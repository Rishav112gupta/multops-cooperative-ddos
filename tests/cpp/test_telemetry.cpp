// Unit tests for the telemetry wire formats, the exporter and the UDP sender.
// Golden byte strings are written by hand from the layout tables in
// docs/PHASE3_TELEMETRY_VALIDATION.md, independently of the encoder.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cstring>
#include <random>

#include "mini_test.hpp"
#include "multops/telemetry.hpp"
#include "multops/udp_sender.hpp"

using namespace multops;
using namespace multops::telemetry;

namespace {

std::vector<uint8_t> hex(const char *s) {
    std::vector<uint8_t> out;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    int hi = -1;
    for (; *s; ++s) {
        int v = nib(*s);
        if (v < 0) continue;  // allow spaces
        if (hi < 0) hi = v;
        else { out.push_back(static_cast<uint8_t>(hi * 16 + v)); hi = -1; }
    }
    return out;
}

HeaderV1 golden_header() {
    HeaderV1 h;
    h.export_mode = ExportMode::Partition;
    h.count_unit = CountUnit::Packets;
    h.router_id = 0x01020304;
    h.boot_id = 0xA1B2C3D4;
    h.sequence = 5;
    h.interval_id = 7;
    h.fragment_index = 0;
    h.fragment_count = 1;
    h.timestamp_us = 0x0011223344556677ull;
    h.interval_ms = 1000;
    h.record_count = 1;
    h.auth_placeholder = 0;
    h.uncounted_fwd = 2;
    h.uncounted_rev = 3;
    return h;
}

RecordV1 golden_record() {
    RecordV1 r;
    r.prefix = 0x0A000001;  // 10.0.0.1
    r.prefix_len = 32;
    r.flags = kFlagLeaf;
    r.fwd_rate = 9998;
    r.rev_rate = 0;
    r.fwd_count = 50090;
    r.rev_count = 0;
    return r;
}

const char *kGoldenHeader =
    "4D54 01 48 20 01 00 00"     // magic, version 1, hdr 72, rec 32, PARTITION, PACKETS, rsv
    "01020304 A1B2C3D4"          // router_id, boot_id
    "0000000000000005"           // sequence
    "00000007 0000 0001"         // interval_id, fragment 0 of 1
    "0011223344556677"           // timestamp_us
    "000003E8 0001 0000"         // interval_ms 1000, 1 record, rsv
    "00000000 00000000"          // auth placeholder, rsv
    "0000000000000002"           // uncounted_fwd
    "0000000000000003";          // uncounted_rev
const char *kGoldenRecord =
    "0A000001 20 01 0000"        // 10.0.0.1 /32 LEAF, rsv
    "0000270E 00000000"          // fwd_rate 9998, rev_rate 0
    "000000000000C3AA"           // fwd_count 50090
    "0000000000000000";          // rev_count 0

std::vector<uint8_t> golden_datagram() {
    std::vector<uint8_t> d = hex(kGoldenHeader), r = hex(kGoldenRecord);
    d.insert(d.end(), r.begin(), r.end());
    return d;
}

struct MemorySink : DatagramSink {
    std::vector<std::vector<uint8_t>> datagrams;
    bool fail = false;
    bool send(const uint8_t *data, std::size_t len) override {
        datagrams.emplace_back(data, data + len);
        return !fail;
    }
};

std::vector<PrefixStats> make_stats(std::size_t n) {
    std::vector<PrefixStats> v;
    for (std::size_t i = 0; i < n; ++i) {
        PrefixStats s;
        s.prefix = (10u << 24) | static_cast<uint32_t>(i);
        s.prefix_len = 32;
        s.is_leaf = true;
        s.fwd_rate = static_cast<int64_t>(i);
        s.rev_rate = static_cast<int64_t>(2 * i);
        s.fwd_count = i * 10;
        s.rev_count = i * 20;
        v.push_back(s);
    }
    return v;
}

}  // namespace

// ---------------------------------------------------------------- layout

TEST(v1_sizes) {
    CHECK_EQ(static_cast<std::size_t>(kHeaderV1Size), 72u);
    CHECK_EQ(static_cast<std::size_t>(kRecordV1Size), 32u);
    CHECK_EQ(hex(kGoldenHeader).size(), 72u);
    CHECK_EQ(hex(kGoldenRecord).size(), 32u);
    CHECK_EQ(max_records_v1(1472), 43u);
    CHECK_EQ(max_records_paper(1472), 91u);
}

TEST(v1_encode_matches_hand_written_bytes) {
    std::vector<uint8_t> buf(72 + 32);
    encode_header_v1(golden_header(), buf.data());
    encode_record_v1(golden_record(), buf.data() + 72);
    CHECK(buf == golden_datagram());
}

TEST(v1_decode_hand_written_bytes) {
    std::vector<uint8_t> d = golden_datagram();
    HeaderV1 h;
    std::vector<RecordV1> recs;
    REQUIRE(decode_v1(d.data(), d.size(), &h, &recs) == DecodeError::None);
    HeaderV1 g = golden_header();
    CHECK(h.export_mode == g.export_mode);
    CHECK_EQ(h.router_id, g.router_id);
    CHECK_EQ(h.boot_id, g.boot_id);
    CHECK_EQ(h.sequence, g.sequence);
    CHECK_EQ(h.interval_id, g.interval_id);
    CHECK_EQ(h.timestamp_us, g.timestamp_us);
    CHECK_EQ(h.interval_ms, g.interval_ms);
    CHECK_EQ(h.uncounted_fwd, 2u);
    CHECK_EQ(h.uncounted_rev, 3u);
    REQUIRE(recs.size() == 1);
    CHECK_EQ(recs[0].prefix, 0x0A000001u);
    CHECK_EQ(recs[0].fwd_rate, 9998u);
    CHECK_EQ(recs[0].fwd_count, 50090u);
}

TEST(paper_layout_matches_hand_written_bytes) {
    // 6-byte header (auth 0, count 1) + 16-byte record:
    // 192.168.1.1 /32, 3 pad bytes, to_rate 100, from_rate 30
    std::vector<uint8_t> expect = hex("00000000 0001"
                                      "C0A80101 20 000000 00000064 0000001E");
    std::vector<uint8_t> buf(6 + 16);
    encode_paper_header(0, 1, buf.data());
    PaperRecord r;
    r.prefix = 0xC0A80101;
    r.prefix_len = 32;
    r.to_rate = 100;
    r.from_rate = 30;
    encode_paper_record(r, buf.data() + 6);
    CHECK(buf == expect);
    uint32_t auth;
    std::vector<PaperRecord> recs;
    REQUIRE(decode_paper(buf.data(), buf.size(), &auth, &recs) == DecodeError::None);
    REQUIRE(recs.size() == 1);
    CHECK_EQ(recs[0].to_rate, 100u);
    CHECK_EQ(recs[0].from_rate, 30u);
}

TEST(v1_round_trip_extreme_values) {
    HeaderV1 h = golden_header();
    h.sequence = UINT64_MAX;
    h.timestamp_us = UINT64_MAX;
    h.interval_id = UINT32_MAX;
    h.uncounted_fwd = UINT64_MAX;
    h.fragment_index = 65534;
    h.fragment_count = 65535;
    h.record_count = 1;
    RecordV1 r = golden_record();
    r.fwd_count = UINT64_MAX;
    r.rev_rate = UINT32_MAX;
    r.prefix = 0xFFFFFF00;
    r.prefix_len = 24;
    std::vector<uint8_t> buf(104);
    encode_header_v1(h, buf.data());
    encode_record_v1(r, buf.data() + 72);
    HeaderV1 h2;
    std::vector<RecordV1> recs;
    REQUIRE(decode_v1(buf.data(), buf.size(), &h2, &recs) == DecodeError::None);
    CHECK_EQ(h2.sequence, UINT64_MAX);
    CHECK_EQ(h2.interval_id, UINT32_MAX);
    CHECK_EQ(h2.fragment_count, 65535);
    CHECK_EQ(recs[0].fwd_count, UINT64_MAX);
    CHECK_EQ(recs[0].rev_rate, UINT32_MAX);
}

TEST(rates_saturate_to_u32) {
    PrefixStats s;
    s.prefix = 0x0A000000;
    s.prefix_len = 8;
    s.is_leaf = true;
    s.fwd_rate = 5000000000LL;
    s.rev_rate = -3;
    RecordV1 r = to_record_v1(s);
    CHECK_EQ(r.fwd_rate, UINT32_MAX);
    CHECK_EQ(r.rev_rate, 0u);
    s.is_leaf = false;
    s.is_residual = true;
    CHECK_EQ(to_record_v1(s).flags, kFlagResidual);
}

// ---------------------------------------------------------------- validation

TEST(v1_rejects_malformed_datagrams) {
    std::vector<uint8_t> good = golden_datagram();
    HeaderV1 h;
    std::vector<RecordV1> recs;
    auto decode = [&](std::vector<uint8_t> d) { return decode_v1(d.data(), d.size(), &h, &recs); };
    auto mutate = [&](std::size_t off, uint8_t v) { auto d = good; d[off] = v; return d; };

    CHECK(decode(good) == DecodeError::None);
    CHECK(decode(std::vector<uint8_t>(good.begin(), good.begin() + 5)) == DecodeError::TooShort);
    CHECK(decode(std::vector<uint8_t>(good.begin(), good.begin() + 40)) == DecodeError::TooShort);
    CHECK(decode(mutate(0, 0x00)) == DecodeError::BadMagic);
    CHECK(decode(mutate(2, 2)) == DecodeError::BadVersion);
    CHECK(decode(mutate(3, 64)) == DecodeError::BadHeaderLength);
    CHECK(decode(mutate(4, 16)) == DecodeError::BadRecordLength);
    CHECK(decode(mutate(5, 3)) == DecodeError::BadExportMode);
    CHECK(decode(mutate(6, 2)) == DecodeError::BadCountUnit);
    CHECK(decode(mutate(7, 1)) == DecodeError::ReservedNotZero);
    CHECK(decode(mutate(53, 1)) == DecodeError::ReservedNotZero);
    CHECK(decode(mutate(31, 0)) == DecodeError::BadFragment);          // fragment_count 0
    { auto d = mutate(29, 1); CHECK(decode(d) == DecodeError::BadFragment); }  // index 1 of 1
    CHECK(decode(mutate(45, 2)) == DecodeError::LengthMismatch);       // claims 2 records
    { auto d = good; d.push_back(0); CHECK(decode(d) == DecodeError::LengthMismatch); }
    CHECK(decode(mutate(72 + 4, 33)) == DecodeError::BadPrefixLength);
    CHECK(decode(mutate(72 + 4, 24)) == DecodeError::HostBitsSet);     // 10.0.0.1/24
    CHECK(decode(mutate(72 + 5, 0x04)) == DecodeError::BadFlags);      // unknown bit
    CHECK(decode(mutate(72 + 5, 0x03)) == DecodeError::BadFlags);      // leaf + residual
    CHECK(decode(mutate(72 + 5, 0x02)) == DecodeError::BadFlags);      // residual /32
    CHECK(decode(mutate(72 + 7, 1)) == DecodeError::ReservedNotZero);  // record reserved
}

TEST(v1_flag_rules_per_export_mode) {
    HeaderV1 h = golden_header();
    RecordV1 r = golden_record();
    r.prefix = 0x0A000000;
    r.prefix_len = 8;
    std::vector<uint8_t> buf(104);
    HeaderV1 out;
    std::vector<RecordV1> recs;
    auto try_ = [&](ExportMode m, uint8_t flags) {
        h.export_mode = m;
        r.flags = flags;
        encode_header_v1(h, buf.data());
        encode_record_v1(r, buf.data() + 72);
        return decode_v1(buf.data(), buf.size(), &out, &recs);
    };
    CHECK(try_(ExportMode::Leaves, kFlagLeaf) == DecodeError::None);
    CHECK(try_(ExportMode::Leaves, 0) == DecodeError::BadFlags);
    CHECK(try_(ExportMode::Leaves, kFlagResidual) == DecodeError::BadFlags);
    CHECK(try_(ExportMode::Partition, kFlagLeaf) == DecodeError::None);
    CHECK(try_(ExportMode::Partition, kFlagResidual) == DecodeError::None);
    CHECK(try_(ExportMode::Partition, 0) == DecodeError::BadFlags);
    CHECK(try_(ExportMode::All, 0) == DecodeError::None);
    CHECK(try_(ExportMode::All, kFlagLeaf) == DecodeError::None);
    CHECK(try_(ExportMode::All, kFlagResidual) == DecodeError::BadFlags);
}

TEST(paper_rejects_malformed_datagrams) {
    std::vector<uint8_t> good = hex("00000000 0001 C0A80101 20 000000 00000064 0000001E");
    uint32_t auth;
    std::vector<PaperRecord> recs;
    auto decode = [&](std::vector<uint8_t> d) { return decode_paper(d.data(), d.size(), &auth, &recs); };
    CHECK(decode(good) == DecodeError::None);
    CHECK(decode(std::vector<uint8_t>(good.begin(), good.begin() + 4)) == DecodeError::TooShort);
    { auto d = good; d.pop_back(); CHECK(decode(d) == DecodeError::LengthMismatch); }
    { auto d = good; d[5] = 2; CHECK(decode(d) == DecodeError::LengthMismatch); }
    { auto d = good; d[6 + 5] = 1; CHECK(decode(d) == DecodeError::ReservedNotZero); }
    { auto d = good; d[6 + 4] = 40; CHECK(decode(d) == DecodeError::BadPrefixLength); }
    { auto d = good; d[6 + 4] = 16; CHECK(decode(d) == DecodeError::HostBitsSet); }
    // The paper format has no magic: arbitrary bytes of a valid length decode.
    std::vector<uint8_t> junk = hex("DEADBEEF 0000");
    CHECK(decode(junk) == DecodeError::None);
}

TEST(decoders_survive_random_mutations) {
    // Run under ASan/UBSan in the sanitizer build: any out-of-bounds read
    // in the decoders aborts the test.
    std::mt19937 rng(99);
    std::vector<uint8_t> base = golden_datagram();
    std::size_t ok = 0, rejected = 0;
    for (int i = 0; i < 50000; ++i) {
        std::vector<uint8_t> d = base;
        int flips = 1 + static_cast<int>(rng() % 4);
        for (int k = 0; k < flips; ++k) d[rng() % d.size()] = static_cast<uint8_t>(rng());
        if (rng() % 5 == 0) d.resize(rng() % (d.size() + 1));
        HeaderV1 h;
        std::vector<RecordV1> recs;
        if (decode_v1(d.data(), d.size(), &h, &recs) == DecodeError::None) ++ok; else ++rejected;
        uint32_t auth;
        std::vector<PaperRecord> precs;
        decode_paper(d.data(), d.size(), &auth, &precs);
    }
    CHECK(rejected > 0);
    CHECK(ok > 0);   // mutations of e.g. rate fields stay valid
}

// ---------------------------------------------------------------- exporter

TEST(exporter_v1_fragments_and_sequences) {
    MemorySink sink;
    ExporterConfig c;
    c.router_id = 42;
    c.boot_id = 0xBEEF;
    TelemetryExporter ex(c, sink);
    ExportResult r = ex.export_interval(make_stats(100), 1, 2, 1000, 123456);
    CHECK_EQ(r.datagrams, 3u);                // 43 + 43 + 14
    CHECK_EQ(r.interval_id, 0u);
    CHECK_EQ(r.first_sequence, 0u);
    REQUIRE(sink.datagrams.size() == 3u);
    std::size_t seen = 0;
    for (std::size_t i = 0; i < 3; ++i) {
        HeaderV1 h;
        std::vector<RecordV1> recs;
        auto &d = sink.datagrams[i];
        REQUIRE(decode_v1(d.data(), d.size(), &h, &recs) == DecodeError::None);
        CHECK(d.size() <= 1472u);
        CHECK_EQ(h.sequence, i);
        CHECK_EQ(h.interval_id, 0u);
        CHECK_EQ(h.fragment_index, i);
        CHECK_EQ(h.fragment_count, 3u);
        CHECK_EQ(h.router_id, 42u);
        CHECK_EQ(h.boot_id, 0xBEEFu);
        CHECK_EQ(h.uncounted_fwd, 1u);
        CHECK_EQ(h.uncounted_rev, 2u);
        for (auto &rec : recs) {
            CHECK_EQ(rec.prefix, (10u << 24) | static_cast<uint32_t>(seen));
            CHECK_EQ(rec.fwd_count, seen * 10);
            CHECK_EQ(rec.rev_count, seen * 20);
            ++seen;
        }
    }
    CHECK_EQ(seen, 100u);
    ExportResult r2 = ex.export_interval({}, 0, 0, 1000, 0);   // empty interval
    CHECK_EQ(r2.datagrams, 1u);
    CHECK_EQ(r2.interval_id, 1u);
    CHECK_EQ(r2.first_sequence, 3u);
    HeaderV1 h;
    std::vector<RecordV1> recs;
    auto &d = sink.datagrams.back();
    REQUIRE(decode_v1(d.data(), d.size(), &h, &recs) == DecodeError::None);
    CHECK_EQ(h.record_count, 0u);
    CHECK_EQ(d.size(), 72u);
}

TEST(exporter_counts_send_failures_but_still_advances_sequence) {
    MemorySink sink;
    sink.fail = true;
    TelemetryExporter ex(ExporterConfig(), sink);
    ExportResult r = ex.export_interval(make_stats(50), 0, 0, 1000, 0);
    CHECK_EQ(r.send_failures, 2u);
    CHECK_EQ(ex.next_sequence(), 2u);       // receiver will see a gap = loss
    CHECK_EQ(ex.total_send_failures(), 2u);
}

TEST(exporter_paper_format) {
    MemorySink sink;
    ExporterConfig c;
    c.format = Format::Paper;
    TelemetryExporter ex(c, sink);
    ExportResult r = ex.export_interval(make_stats(100), 0, 0, 1000, 0);
    CHECK_EQ(r.datagrams, 2u);              // 91 + 9
    std::size_t total = 0;
    for (auto &d : sink.datagrams) {
        uint32_t auth;
        std::vector<PaperRecord> recs;
        REQUIRE(decode_paper(d.data(), d.size(), &auth, &recs) == DecodeError::None);
        for (auto &rec : recs) {
            CHECK_EQ(rec.to_rate, static_cast<uint32_t>(total));        // fwd
            CHECK_EQ(rec.from_rate, static_cast<uint32_t>(2 * total));  // rev
            ++total;
        }
    }
    CHECK_EQ(total, 100u);
}

TEST(exporter_preserves_partition_counts_end_to_end) {
    ManualClock clock;
    MultopsConfig mc;
    mc.thresh = 100;
    MultopsTree tree(mc, clock);
    uint64_t offered = 0;
    for (int e = 0; e < 500; ++e) {
        for (int p = 0; p < 40; ++p) { tree.update(0x0A000001, Direction::Forward, 1); ++offered; }
        for (int p = 0; p < 3; ++p) { tree.update(0xC0A80101 + static_cast<uint32_t>(p), Direction::Reverse, 1); }
        clock.advance(1);
    }
    MemorySink sink;
    TelemetryExporter ex(ExporterConfig(), sink);
    ex.export_interval(tree.collect_stats(CollectMode::Partition, true), 0, 0, 4000, 0);
    uint64_t fwd = 0, rev = 0;
    for (auto &d : sink.datagrams) {
        HeaderV1 h;
        std::vector<RecordV1> recs;
        REQUIRE(decode_v1(d.data(), d.size(), &h, &recs) == DecodeError::None);
        for (auto &r : recs) { fwd += r.fwd_count; rev += r.rev_count; }
    }
    CHECK_EQ(fwd, offered);
    CHECK_EQ(rev, 1500u);
}

TEST(mode_and_format_parsing) {
    ExportMode m;
    Format f;
    CHECK(parse_export_mode("partition", &m) && m == ExportMode::Partition);
    CHECK(parse_export_mode("LEAVES", &m) && m == ExportMode::Leaves);
    CHECK(parse_export_mode("All", &m) && m == ExportMode::All);
    CHECK(!parse_export_mode("leaf", &m));
    CHECK(parse_format("v1", &f) && f == Format::V1);
    CHECK(parse_format("PAPER", &f) && f == Format::Paper);
    CHECK(!parse_format("v2", &f));
    CHECK(collect_mode_for(ExportMode::Partition) == CollectMode::Partition);
}

// ---------------------------------------------------------------- UDP (loopback)

TEST(udp_sender_delivers_on_loopback) {
    int rx = ::socket(AF_INET, SOCK_DGRAM, 0);
    REQUIRE(rx >= 0);
    sockaddr_in sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    REQUIRE(::bind(rx, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) == 0);
    socklen_t sl = sizeof(sa);
    REQUIRE(::getsockname(rx, reinterpret_cast<sockaddr *>(&sa), &sl) == 0);
    timeval tv = {2, 0};
    ::setsockopt(rx, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    UdpSender tx;
    std::string err;
    REQUIRE(tx.open(0x7F000001, ntohs(sa.sin_port), &err));
    std::vector<uint8_t> d = golden_datagram();
    CHECK(tx.send(d.data(), d.size()));
    std::vector<uint8_t> got(2048);
    ssize_t n = ::recv(rx, got.data(), got.size(), 0);
    REQUIRE(n == static_cast<ssize_t>(d.size()));
    got.resize(static_cast<std::size_t>(n));
    CHECK(got == d);
    CHECK_EQ(tx.sent(), 1u);
    ::close(rx);
}

TEST(udp_sender_unopened_fails_cleanly) {
    UdpSender tx;
    uint8_t b = 0;
    CHECK(!tx.send(&b, 1));
    CHECK_EQ(tx.failed(), 1u);
}

MINI_TEST_MAIN

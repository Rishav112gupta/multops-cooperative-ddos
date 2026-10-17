// telemetry_vectors -- emit cross-language golden test vectors (JSON lines).
//
// Each line is one datagram produced by the C++ encoder (or a deliberately
// corrupted copy of one), with the fields it encodes and the decode result the
// C++ decoder reports. tests/python/test_protocol.py checks that the Python
// codec decodes every vector to the same fields / the same error name, and
// re-encodes every valid vector to identical bytes.
//
// The committed file tests/data/telemetry_vectors.jsonl is this tool's output;
// a CTest compares the two so the file cannot drift from the C++ code.

#include <cstdio>
#include <string>
#include <vector>

#include "multops/telemetry.hpp"

using namespace multops;
using namespace multops::telemetry;

namespace {

std::string hexstr(const std::vector<uint8_t> &d) {
    static const char *digits = "0123456789abcdef";
    std::string s;
    for (uint8_t b : d) { s += digits[b >> 4]; s += digits[b & 15]; }
    return s;
}

const char *mode_name(ExportMode m) {
    return m == ExportMode::Leaves ? "LEAVES" : m == ExportMode::Partition ? "PARTITION" : "ALL";
}

std::string u64(uint64_t v) { return std::to_string(v); }

void emit_v1(const char *name, const std::vector<uint8_t> &d) {
    HeaderV1 h;
    std::vector<RecordV1> recs;
    DecodeError e = decode_v1(d.data(), d.size(), &h, &recs);
    std::printf("{\"name\":\"%s\",\"format\":\"V1\",\"hex\":\"%s\",\"error\":\"%s\"", name,
                hexstr(d).c_str(), decode_error_name(e));
    if (e == DecodeError::None) {
        std::printf(",\"header\":{\"export_mode\":\"%s\",\"count_unit\":%u,\"router_id\":%u,"
                    "\"boot_id\":%u,\"sequence\":%s,\"interval_id\":%u,\"fragment_index\":%u,"
                    "\"fragment_count\":%u,\"timestamp_us\":%s,\"interval_ms\":%u,"
                    "\"record_count\":%u,\"auth_placeholder\":%u,\"uncounted_fwd\":%s,"
                    "\"uncounted_rev\":%s},\"records\":[",
                    mode_name(h.export_mode), static_cast<unsigned>(h.count_unit), h.router_id,
                    h.boot_id, u64(h.sequence).c_str(), h.interval_id, h.fragment_index,
                    h.fragment_count, u64(h.timestamp_us).c_str(), h.interval_ms, h.record_count,
                    h.auth_placeholder, u64(h.uncounted_fwd).c_str(), u64(h.uncounted_rev).c_str());
        for (std::size_t i = 0; i < recs.size(); ++i) {
            const RecordV1 &r = recs[i];
            std::printf("%s{\"prefix\":\"%s\",\"prefix_len\":%u,\"flags\":%u,\"fwd_rate\":%u,"
                        "\"rev_rate\":%u,\"fwd_count\":%s,\"rev_count\":%s}",
                        i ? "," : "", ipv4_to_string(r.prefix).c_str(), r.prefix_len, r.flags,
                        r.fwd_rate, r.rev_rate, u64(r.fwd_count).c_str(), u64(r.rev_count).c_str());
        }
        std::printf("]");
    }
    std::printf("}\n");
}

void emit_paper(const char *name, const std::vector<uint8_t> &d) {
    uint32_t auth = 0;
    std::vector<PaperRecord> recs;
    DecodeError e = decode_paper(d.data(), d.size(), &auth, &recs);
    std::printf("{\"name\":\"%s\",\"format\":\"PAPER\",\"hex\":\"%s\",\"error\":\"%s\"", name,
                hexstr(d).c_str(), decode_error_name(e));
    if (e == DecodeError::None) {
        std::printf(",\"auth_placeholder\":%u,\"records\":[", auth);
        for (std::size_t i = 0; i < recs.size(); ++i)
            std::printf("%s{\"prefix\":\"%s\",\"prefix_len\":%u,\"to_rate\":%u,\"from_rate\":%u}",
                        i ? "," : "", ipv4_to_string(recs[i].prefix).c_str(), recs[i].prefix_len,
                        recs[i].to_rate, recs[i].from_rate);
        std::printf("]");
    }
    std::printf("}\n");
}

struct Capture : DatagramSink {
    std::vector<std::vector<uint8_t>> out;
    bool send(const uint8_t *d, std::size_t n) override { out.emplace_back(d, d + n); return true; }
};

PrefixStats stat(uint32_t prefix, uint8_t len, bool leaf, bool residual, int64_t fr, int64_t rr,
                 uint64_t fc, uint64_t rc) {
    PrefixStats s;
    s.prefix = prefix; s.prefix_len = len; s.is_leaf = leaf; s.is_residual = residual;
    s.fwd_rate = fr; s.rev_rate = rr; s.fwd_count = fc; s.rev_count = rc;
    return s;
}

}  // namespace

int main() {
    std::vector<PrefixStats> part = {
        stat(0x0A000000, 8, false, true, 10, 0, 121, 0),             // residual 10/8
        stat(0x0A000001, 32, true, false, 9998, 0, 49969, 0),        // 10.0.0.1/32 leaf
        stat(0xC0A80101, 32, true, false, 100, 30, 500, 150),        // 192.168.1.1/32
        stat(0xAC100000, 16, true, false, 5000000000LL, -1, UINT64_MAX, 7),  // saturation
    };

    // V1 valid datagrams via the exporter (one per mode, plus fragmentation).
    for (int m = 0; m < 3; ++m) {
        Capture cap;
        ExporterConfig c;
        c.export_mode = static_cast<ExportMode>(m);
        c.router_id = 7 + static_cast<uint32_t>(m);
        c.boot_id = 0xC0FFEE00u + static_cast<uint32_t>(m);
        c.count_unit = m == 2 ? CountUnit::Bytes : CountUnit::Packets;
        TelemetryExporter ex(c, cap);
        std::vector<PrefixStats> recs;
        for (auto s : part) {
            if (m == 0) { if (!s.is_leaf) continue; }
            if (m == 2) { s.is_residual = false; }
            recs.push_back(s);
        }
        ex.export_interval(recs, 3, 4, 1000, 1700000000123456ull);
        std::string name = std::string("v1_") + mode_name(c.export_mode);
        emit_v1(name.c_str(), cap.out[0]);
    }
    {
        Capture cap;
        ExporterConfig c;
        c.max_payload = kHeaderV1Size + 2 * kRecordV1Size;  // 2 records per datagram
        c.router_id = 1;
        TelemetryExporter ex(c, cap);
        ex.export_interval(part, 0, 0, 500, 1);
        for (std::size_t i = 0; i < cap.out.size(); ++i)
            emit_v1(("v1_fragment_" + std::to_string(i)).c_str(), cap.out[i]);
        ex.export_interval({}, 0, 0, 500, 2);
        emit_v1("v1_empty_interval", cap.out.back());
    }

    // V1 malformed variants of one valid datagram.
    Capture base;
    {
        ExporterConfig c;
        c.router_id = 99;
        TelemetryExporter ex(c, base);
        ex.export_interval({part[2]}, 0, 0, 1000, 0);
    }
    const std::vector<uint8_t> good = base.out[0];
    struct Mut { const char *name; std::size_t off; uint8_t val; };
    const Mut muts[] = {
        {"bad_magic", 0, 0x00},        {"bad_version", 2, 9},         {"bad_header_length", 3, 64},
        {"bad_record_length", 4, 16},  {"bad_export_mode", 5, 7},     {"bad_count_unit", 6, 5},
        {"reserved0", 7, 1},           {"reserved1", 47, 1},          {"reserved2", 55, 1},
        {"fragment_count_zero", 31, 0}, {"fragment_index_too_big", 29, 1},
        {"record_count_too_big", 45, 2}, {"record_reserved", 72 + 6, 1},
        {"prefix_len_33", 72 + 4, 33}, {"host_bits_set", 72 + 4, 16},  {"unknown_flag", 72 + 5, 0x05},
        {"leaf_and_residual", 72 + 5, 0x03},
    };
    for (const Mut &m : muts) {
        std::vector<uint8_t> d = good;
        d[m.off] = m.val;
        emit_v1(("v1_malformed_" + std::string(m.name)).c_str(), d);
    }
    emit_v1("v1_malformed_truncated_7", std::vector<uint8_t>(good.begin(), good.begin() + 7));
    emit_v1("v1_malformed_truncated_header", std::vector<uint8_t>(good.begin(), good.begin() + 50));
    emit_v1("v1_malformed_truncated_record", std::vector<uint8_t>(good.begin(), good.end() - 1));
    {
        std::vector<uint8_t> d = good;
        d.push_back(0);
        emit_v1("v1_malformed_trailing_byte", d);
    }

    // PAPER format.
    {
        Capture cap;
        ExporterConfig c;
        c.format = Format::Paper;
        TelemetryExporter ex(c, cap);
        ex.export_interval(part, 0, 0, 1000, 0);
        emit_paper("paper_valid", cap.out[0]);
        std::vector<uint8_t> d = cap.out[0];
        d.pop_back();
        emit_paper("paper_malformed_truncated", d);
        d = cap.out[0];
        d[6 + 5] = 1;
        emit_paper("paper_malformed_pad", d);
        d = cap.out[0];
        d[6 + 4] = 24;  // 10.0.0.0 with /24 is fine; 10.0.0.1 record is second
        d[6 + 16 + 4] = 24;
        emit_paper("paper_malformed_host_bits", d);
    }
    return 0;
}

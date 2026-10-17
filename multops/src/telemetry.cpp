// telemetry.cpp -- see telemetry.hpp and docs/PHASE3_TELEMETRY_VALIDATION.md.

#include "multops/telemetry.hpp"

#include <algorithm>
#include <cctype>

namespace multops {
namespace telemetry {

namespace {

// Big-endian primitives.
void put8(uint8_t *&p, uint8_t v) { *p++ = v; }
void put16(uint8_t *&p, uint16_t v) {
    *p++ = static_cast<uint8_t>(v >> 8);
    *p++ = static_cast<uint8_t>(v);
}
void put32(uint8_t *&p, uint32_t v) {
    put16(p, static_cast<uint16_t>(v >> 16));
    put16(p, static_cast<uint16_t>(v));
}
void put64(uint8_t *&p, uint64_t v) {
    put32(p, static_cast<uint32_t>(v >> 32));
    put32(p, static_cast<uint32_t>(v));
}
uint8_t get8(const uint8_t *&p) { return *p++; }
uint16_t get16(const uint8_t *&p) {
    uint16_t v = static_cast<uint16_t>((p[0] << 8) | p[1]);
    p += 2;
    return v;
}
uint32_t get32(const uint8_t *&p) {
    uint32_t hi = get16(p);
    return (hi << 16) | get16(p);
}
uint64_t get64(const uint8_t *&p) {
    uint64_t hi = get32(p);
    return (hi << 32) | get32(p);
}

uint32_t saturate_u32(int64_t v) {
    if (v <= 0) return 0;
    if (v > static_cast<int64_t>(UINT32_MAX)) return UINT32_MAX;
    return static_cast<uint32_t>(v);
}

DecodeError check_prefix(uint32_t prefix, uint8_t len) {
    if (len > 32) return DecodeError::BadPrefixLength;
    uint32_t host_mask = len == 0 ? 0xFFFFFFFFu : (len == 32 ? 0u : (0xFFFFFFFFu >> len));
    if (prefix & host_mask) return DecodeError::HostBitsSet;
    return DecodeError::None;
}

std::string upper(std::string s) {
    for (auto &c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

}  // namespace

const char *decode_error_name(DecodeError e) {
    switch (e) {
    case DecodeError::None: return "none";
    case DecodeError::TooShort: return "too_short";
    case DecodeError::BadMagic: return "bad_magic";
    case DecodeError::BadVersion: return "bad_version";
    case DecodeError::BadHeaderLength: return "bad_header_length";
    case DecodeError::BadRecordLength: return "bad_record_length";
    case DecodeError::LengthMismatch: return "length_mismatch";
    case DecodeError::BadExportMode: return "bad_export_mode";
    case DecodeError::BadCountUnit: return "bad_count_unit";
    case DecodeError::BadFragment: return "bad_fragment";
    case DecodeError::ReservedNotZero: return "reserved_not_zero";
    case DecodeError::BadPrefixLength: return "bad_prefix_length";
    case DecodeError::HostBitsSet: return "host_bits_set";
    case DecodeError::BadFlags: return "bad_flags";
    }
    return "unknown";
}

// ---------------------------------------------------------------- V1

void encode_header_v1(const HeaderV1 &h, uint8_t *out) {
    uint8_t *p = out;
    put16(p, kMagic);                                    //  0
    put8(p, kVersion1);                                  //  2
    put8(p, static_cast<uint8_t>(kHeaderV1Size));        //  3
    put8(p, static_cast<uint8_t>(kRecordV1Size));        //  4
    put8(p, static_cast<uint8_t>(h.export_mode));        //  5
    put8(p, static_cast<uint8_t>(h.count_unit));         //  6
    put8(p, 0);                                          //  7 reserved
    put32(p, h.router_id);                               //  8
    put32(p, h.boot_id);                                 // 12
    put64(p, h.sequence);                                // 16
    put32(p, h.interval_id);                             // 24
    put16(p, h.fragment_index);                          // 28
    put16(p, h.fragment_count);                          // 30
    put64(p, h.timestamp_us);                            // 32
    put32(p, h.interval_ms);                             // 40
    put16(p, h.record_count);                            // 44
    put16(p, 0);                                         // 46 reserved
    put32(p, h.auth_placeholder);                        // 48
    put32(p, 0);                                         // 52 reserved
    put64(p, h.uncounted_fwd);                           // 56
    put64(p, h.uncounted_rev);                           // 64 -> 72
}

void encode_record_v1(const RecordV1 &r, uint8_t *out) {
    uint8_t *p = out;
    put32(p, r.prefix);       //  0
    put8(p, r.prefix_len);    //  4
    put8(p, r.flags);         //  5
    put16(p, 0);              //  6 reserved
    put32(p, r.fwd_rate);     //  8
    put32(p, r.rev_rate);     // 12
    put64(p, r.fwd_count);    // 16
    put64(p, r.rev_count);    // 24 -> 32
}

DecodeError decode_v1(const uint8_t *data, std::size_t len, HeaderV1 *h,
                      std::vector<RecordV1> *records) {
    if (len < 8) return DecodeError::TooShort;
    const uint8_t *p = data;
    if (get16(p) != kMagic) return DecodeError::BadMagic;
    if (get8(p) != kVersion1) return DecodeError::BadVersion;
    uint8_t header_len = get8(p);
    uint8_t record_len = get8(p);
    if (header_len != kHeaderV1Size) return DecodeError::BadHeaderLength;
    if (record_len != kRecordV1Size) return DecodeError::BadRecordLength;
    if (len < kHeaderV1Size) return DecodeError::TooShort;

    uint8_t mode = get8(p), unit = get8(p), reserved0 = get8(p);
    if (mode > static_cast<uint8_t>(ExportMode::All)) return DecodeError::BadExportMode;
    if (unit > static_cast<uint8_t>(CountUnit::Bytes)) return DecodeError::BadCountUnit;
    h->export_mode = static_cast<ExportMode>(mode);
    h->count_unit = static_cast<CountUnit>(unit);
    h->router_id = get32(p);
    h->boot_id = get32(p);
    h->sequence = get64(p);
    h->interval_id = get32(p);
    h->fragment_index = get16(p);
    h->fragment_count = get16(p);
    h->timestamp_us = get64(p);
    h->interval_ms = get32(p);
    h->record_count = get16(p);
    uint16_t reserved1 = get16(p);
    h->auth_placeholder = get32(p);
    uint32_t reserved2 = get32(p);
    h->uncounted_fwd = get64(p);
    h->uncounted_rev = get64(p);
    if (reserved0 || reserved1 || reserved2) return DecodeError::ReservedNotZero;
    if (h->fragment_count == 0 || h->fragment_index >= h->fragment_count)
        return DecodeError::BadFragment;
    if (len != kHeaderV1Size + static_cast<std::size_t>(h->record_count) * kRecordV1Size)
        return DecodeError::LengthMismatch;

    records->clear();
    records->reserve(h->record_count);
    for (uint16_t i = 0; i < h->record_count; ++i) {
        RecordV1 r;
        r.prefix = get32(p);
        r.prefix_len = get8(p);
        r.flags = get8(p);
        if (get16(p) != 0) return DecodeError::ReservedNotZero;
        r.fwd_rate = get32(p);
        r.rev_rate = get32(p);
        r.fwd_count = get64(p);
        r.rev_count = get64(p);
        DecodeError e = check_prefix(r.prefix, r.prefix_len);
        if (e != DecodeError::None) return e;
        bool leaf = r.flags & kFlagLeaf, residual = r.flags & kFlagResidual;
        if ((r.flags & ~kKnownFlags) || (leaf && residual)) return DecodeError::BadFlags;
        switch (h->export_mode) {
        case ExportMode::Leaves:
            if (!leaf) return DecodeError::BadFlags;
            break;
        case ExportMode::Partition:
            if (!leaf && !residual) return DecodeError::BadFlags;
            if (residual && r.prefix_len == 32) return DecodeError::BadFlags;
            break;
        case ExportMode::All:
            if (residual) return DecodeError::BadFlags;
            break;
        }
        records->push_back(r);
    }
    return DecodeError::None;
}

std::size_t max_records_v1(std::size_t max_payload) {
    if (max_payload < kHeaderV1Size + kRecordV1Size) return 0;
    return std::min<std::size_t>((max_payload - kHeaderV1Size) / kRecordV1Size, UINT16_MAX);
}

RecordV1 to_record_v1(const PrefixStats &s) {
    RecordV1 r;
    r.prefix = s.prefix;
    r.prefix_len = s.prefix_len;
    r.flags = static_cast<uint8_t>((s.is_leaf ? kFlagLeaf : 0) | (s.is_residual ? kFlagResidual : 0));
    // A Partition residual is the part of an expanded counter, never a leaf.
    if (s.is_residual) r.flags = kFlagResidual;
    r.fwd_rate = saturate_u32(s.fwd_rate);
    r.rev_rate = saturate_u32(s.rev_rate);
    r.fwd_count = s.fwd_count;
    r.rev_count = s.rev_count;
    return r;
}

// ---------------------------------------------------------------- PAPER (v0)

void encode_paper_header(uint32_t auth_placeholder, uint16_t count, uint8_t *out) {
    uint8_t *p = out;
    put32(p, auth_placeholder);  // 0
    put16(p, count);             // 4 -> 6
}

void encode_paper_record(const PaperRecord &r, uint8_t *out) {
    uint8_t *p = out;
    put32(p, r.prefix);       //  0
    put8(p, r.prefix_len);    //  4
    put8(p, 0);               //  5 pad
    put16(p, 0);              //  6 pad
    put32(p, r.to_rate);      //  8
    put32(p, r.from_rate);    // 12 -> 16
}

DecodeError decode_paper(const uint8_t *data, std::size_t len, uint32_t *auth,
                         std::vector<PaperRecord> *records) {
    if (len < kPaperHeaderSize) return DecodeError::TooShort;
    const uint8_t *p = data;
    *auth = get32(p);
    uint16_t count = get16(p);
    if (len != kPaperHeaderSize + static_cast<std::size_t>(count) * kPaperRecordSize)
        return DecodeError::LengthMismatch;
    records->clear();
    for (uint16_t i = 0; i < count; ++i) {
        PaperRecord r;
        r.prefix = get32(p);
        r.prefix_len = get8(p);
        uint8_t pad0 = get8(p);
        uint16_t pad1 = get16(p);
        r.to_rate = get32(p);
        r.from_rate = get32(p);
        if (pad0 || pad1) return DecodeError::ReservedNotZero;
        DecodeError e = check_prefix(r.prefix, r.prefix_len);
        if (e != DecodeError::None) return e;
        records->push_back(r);
    }
    return DecodeError::None;
}

std::size_t max_records_paper(std::size_t max_payload) {
    if (max_payload < kPaperHeaderSize + kPaperRecordSize) return 0;
    return std::min<std::size_t>((max_payload - kPaperHeaderSize) / kPaperRecordSize, UINT16_MAX);
}

PaperRecord to_paper_record(const PrefixStats &s) {
    PaperRecord r;
    r.prefix = s.prefix;
    r.prefix_len = s.prefix_len;
    r.to_rate = saturate_u32(s.fwd_rate);
    r.from_rate = saturate_u32(s.rev_rate);
    return r;
}

// ---------------------------------------------------------------- exporter

TelemetryExporter::TelemetryExporter(const ExporterConfig &config, DatagramSink &sink)
    : config_(config),
      sink_(sink),
      next_sequence_(0),
      next_interval_id_(0),
      total_datagrams_(0),
      total_bytes_(0),
      total_send_failures_(0) {}

ExportResult TelemetryExporter::export_interval(const std::vector<PrefixStats> &records,
                                                uint64_t uncounted_fwd, uint64_t uncounted_rev,
                                                uint32_t interval_ms, uint64_t timestamp_us) {
    ExportResult res;
    res.interval_id = next_interval_id_++;
    res.first_sequence = next_sequence_;
    res.records = records.size();

    const bool v1 = config_.format == Format::V1;
    std::size_t per = v1 ? max_records_v1(config_.max_payload)
                         : max_records_paper(config_.max_payload);
    if (per == 0) per = 1;  // degenerate max_payload: still make progress
    std::size_t fragments = records.empty() ? 1 : (records.size() + per - 1) / per;
    if (fragments > UINT16_MAX) fragments = UINT16_MAX;  // > 2.8 M records; truncated

    std::vector<uint8_t> buf;
    for (std::size_t f = 0; f < fragments; ++f) {
        std::size_t begin = f * per;
        std::size_t n = std::min(per, records.size() - std::min(begin, records.size()));
        if (v1) {
            buf.assign(kHeaderV1Size + n * kRecordV1Size, 0);
            HeaderV1 h;
            h.export_mode = config_.export_mode;
            h.count_unit = config_.count_unit;
            h.router_id = config_.router_id;
            h.boot_id = config_.boot_id;
            h.sequence = next_sequence_++;
            h.interval_id = res.interval_id;
            h.fragment_index = static_cast<uint16_t>(f);
            h.fragment_count = static_cast<uint16_t>(fragments);
            h.timestamp_us = timestamp_us;
            h.interval_ms = interval_ms;
            h.record_count = static_cast<uint16_t>(n);
            h.auth_placeholder = config_.auth_placeholder;
            h.uncounted_fwd = uncounted_fwd;
            h.uncounted_rev = uncounted_rev;
            encode_header_v1(h, buf.data());
            for (std::size_t i = 0; i < n; ++i)
                encode_record_v1(to_record_v1(records[begin + i]),
                                 buf.data() + kHeaderV1Size + i * kRecordV1Size);
        } else {
            buf.assign(kPaperHeaderSize + n * kPaperRecordSize, 0);
            encode_paper_header(config_.auth_placeholder, static_cast<uint16_t>(n), buf.data());
            for (std::size_t i = 0; i < n; ++i)
                encode_paper_record(to_paper_record(records[begin + i]),
                                    buf.data() + kPaperHeaderSize + i * kPaperRecordSize);
        }
        ++res.datagrams;
        res.bytes += buf.size();
        if (!sink_.send(buf.data(), buf.size()))
            ++res.send_failures;
    }
    total_datagrams_ += res.datagrams;
    total_bytes_ += res.bytes;
    total_send_failures_ += res.send_failures;
    return res;
}

bool parse_export_mode(const std::string &s, ExportMode *m) {
    std::string u = upper(s);
    if (u == "LEAVES") *m = ExportMode::Leaves;
    else if (u == "PARTITION") *m = ExportMode::Partition;
    else if (u == "ALL") *m = ExportMode::All;
    else return false;
    return true;
}

bool parse_format(const std::string &s, Format *f) {
    std::string u = upper(s);
    if (u == "V1") *f = Format::V1;
    else if (u == "PAPER") *f = Format::Paper;
    else return false;
    return true;
}

CollectMode collect_mode_for(ExportMode m) {
    switch (m) {
    case ExportMode::Leaves: return CollectMode::LeavesOnly;
    case ExportMode::Partition: return CollectMode::Partition;
    case ExportMode::All: return CollectMode::AllActive;
    }
    return CollectMode::Partition;
}

}  // namespace telemetry
}  // namespace multops

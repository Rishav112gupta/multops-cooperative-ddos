// telemetry.hpp -- MULTOPS telemetry wire formats (Phase 3).
//
// Two formats are implemented:
//
//  * PAPER (v0): the layout described in AINA 2026 Sec. 4.2 -- a 6-byte
//    StatsPacketHeader (32-bit auth placeholder, 16-bit record count) and
//    16-byte PrefixStatsRecords (prefix, length, to_rate, from_rate). The
//    paper gives sizes but not field order/types; the choices made here are
//    documented in docs/PHASE3_TELEMETRY_VALIDATION.md. Paper-faithful.
//
//  * V1: a versioned research extension: 72-byte header with magic, version,
//    router id, boot id, sequence number, interval id, fragmentation and
//    coverage fields; 32-byte records carrying EWMA rates AND exact counts.
//
// All multi-byte fields are big-endian (network order). Encoding and decoding
// are done field by field into byte buffers -- never by copying C++ structs --
// so compiler padding cannot leak into the wire format.
//
// UDP gives no delivery guarantee: datagrams can be lost, duplicated or
// reordered. V1 carries the information a receiver needs to DETECT this; it
// does not prevent it. The auth field is a placeholder and provides NO
// authentication or integrity protection.

#ifndef MULTOPS_TELEMETRY_HPP
#define MULTOPS_TELEMETRY_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "multops/multops_tree.hpp"

namespace multops {
namespace telemetry {

enum : uint16_t { kMagic = 0x4D54 };  // ASCII "MT"
enum : uint8_t { kVersion1 = 1 };
enum : std::size_t {
    kHeaderV1Size = 72,
    kRecordV1Size = 32,
    kPaperHeaderSize = 6,
    kPaperRecordSize = 16,
    // IPv4 MTU 1500 - 20 (IP) - 8 (UDP): largest payload sent without IP
    // fragmentation on a standard Ethernet path.
    kDefaultMaxPayload = 1472,
};

enum class Format : uint8_t { Paper = 0, V1 = 1 };
enum class ExportMode : uint8_t { Leaves = 0, Partition = 1, All = 2 };
enum class CountUnit : uint8_t { Packets = 0, Bytes = 1 };
enum : uint8_t { kFlagLeaf = 0x01, kFlagResidual = 0x02, kKnownFlags = 0x03 };

struct HeaderV1 {
    ExportMode export_mode = ExportMode::Partition;
    CountUnit count_unit = CountUnit::Packets;
    uint32_t router_id = 0;
    uint32_t boot_id = 0;
    uint64_t sequence = 0;
    uint32_t interval_id = 0;
    uint16_t fragment_index = 0;
    uint16_t fragment_count = 1;
    uint64_t timestamp_us = 0;      // sender clock, NOT synchronised across routers
    uint32_t interval_ms = 0;       // measured length of the window being reported
    uint16_t record_count = 0;
    uint32_t auth_placeholder = 0;  // paper's placeholder; not authentication
    uint64_t uncounted_fwd = 0;     // units refused by the memory limit (whole interval)
    uint64_t uncounted_rev = 0;
};

struct RecordV1 {
    uint32_t prefix = 0;            // host byte order in memory, big-endian on the wire
    uint8_t prefix_len = 0;
    uint8_t flags = 0;              // kFlagLeaf / kFlagResidual
    uint32_t fwd_rate = 0;          // paper "to_rate": units/s FROM the prefix (input 0)
    uint32_t rev_rate = 0;          // paper "from_rate": units/s TO the prefix (input 1)
    uint64_t fwd_count = 0;         // exact units in the interval
    uint64_t rev_count = 0;
};

struct PaperRecord {
    uint32_t prefix = 0;
    uint8_t prefix_len = 0;
    uint32_t to_rate = 0;
    uint32_t from_rate = 0;
};

enum class DecodeError {
    None = 0,
    TooShort,
    BadMagic,
    BadVersion,
    BadHeaderLength,
    BadRecordLength,
    LengthMismatch,
    BadExportMode,
    BadCountUnit,
    BadFragment,
    ReservedNotZero,
    BadPrefixLength,
    HostBitsSet,
    BadFlags,
};
const char *decode_error_name(DecodeError e);

// ---- V1 --------------------------------------------------------------------
void encode_header_v1(const HeaderV1 &h, uint8_t *out);      // writes kHeaderV1Size bytes
void encode_record_v1(const RecordV1 &r, uint8_t *out);      // writes kRecordV1Size bytes
// Full validation (see docs). On error, outputs are unspecified.
DecodeError decode_v1(const uint8_t *data, std::size_t len, HeaderV1 *header,
                      std::vector<RecordV1> *records);
std::size_t max_records_v1(std::size_t max_payload);

// Converts a tree record: rates are clamped to [0, 2^32-1] (saturation).
RecordV1 to_record_v1(const PrefixStats &s);

// ---- PAPER (v0) ------------------------------------------------------------
void encode_paper_header(uint32_t auth_placeholder, uint16_t count, uint8_t *out);
void encode_paper_record(const PaperRecord &r, uint8_t *out);
DecodeError decode_paper(const uint8_t *data, std::size_t len, uint32_t *auth_placeholder,
                         std::vector<PaperRecord> *records);
std::size_t max_records_paper(std::size_t max_payload);
PaperRecord to_paper_record(const PrefixStats &s);   // to_rate = fwd, from_rate = rev

// ---- Exporter --------------------------------------------------------------
class DatagramSink {
  public:
    virtual ~DatagramSink() {}
    // Returns false if the datagram could not be handed to the network.
    virtual bool send(const uint8_t *data, std::size_t len) = 0;
};

struct ExporterConfig {
    Format format = Format::V1;
    ExportMode export_mode = ExportMode::Partition;
    CountUnit count_unit = CountUnit::Packets;
    uint32_t router_id = 0;
    uint32_t boot_id = 0;
    uint32_t auth_placeholder = 0;
    std::size_t max_payload = kDefaultMaxPayload;
};

struct ExportResult {
    std::size_t datagrams = 0;
    std::size_t bytes = 0;
    std::size_t send_failures = 0;
    std::size_t records = 0;
    uint32_t interval_id = 0;
    uint64_t first_sequence = 0;
};

// Turns one interval's records into datagrams and hands them to a sink.
// V1: one sequence number per datagram, one interval id per call; an interval
// with no records still produces one (empty) datagram so receivers can tell
// "router alive, no traffic" from "report lost". PAPER: the same split by
// record count, no sequencing.
class TelemetryExporter {
  public:
    TelemetryExporter(const ExporterConfig &config, DatagramSink &sink);

    ExportResult export_interval(const std::vector<PrefixStats> &records, uint64_t uncounted_fwd,
                                 uint64_t uncounted_rev, uint32_t interval_ms,
                                 uint64_t timestamp_us);

    const ExporterConfig &config() const { return config_; }
    uint64_t next_sequence() const { return next_sequence_; }
    uint32_t next_interval_id() const { return next_interval_id_; }
    uint64_t total_datagrams() const { return total_datagrams_; }
    uint64_t total_bytes() const { return total_bytes_; }
    uint64_t total_send_failures() const { return total_send_failures_; }

  private:
    ExporterConfig config_;
    DatagramSink &sink_;
    uint64_t next_sequence_;
    uint32_t next_interval_id_;
    uint64_t total_datagrams_;
    uint64_t total_bytes_;
    uint64_t total_send_failures_;
};

// Formats for configuration parsing and logs.
bool parse_export_mode(const std::string &s, ExportMode *m);  // LEAVES|PARTITION|ALL
bool parse_format(const std::string &s, Format *f);           // V1|PAPER
CollectMode collect_mode_for(ExportMode m);

}  // namespace telemetry
}  // namespace multops

#endif

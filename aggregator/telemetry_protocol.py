"""MULTOPS telemetry wire formats -- Python codec (Phase 3).

Mirror of multops/src/telemetry.cpp. Both implementations are checked against
the same golden vectors (tests/data/telemetry_vectors.jsonl), byte for byte.

Formats
-------
PAPER (v0)  Paper-faithful layout (AINA 2026 Sec. 4.2): 6-byte header
            (uint32 auth placeholder, uint16 record count) + 16-byte records
            (uint32 prefix, uint8 length, 3 pad bytes, uint32 to_rate,
            uint32 from_rate). No magic, version, router id or sequence.
V1          Research extension: 72-byte header + 32-byte records with rates
            AND exact per-interval counts. See docs/PHASE3_TELEMETRY_VALIDATION.md.

All integers are big-endian. struct formats use '>' (standard sizes, no
alignment padding), so the layouts are explicit.

Direction mapping (verified in Phase 3, see docs):
    fwd  == paper "to_rate"   == traffic FROM the prefix (monitor input 0, keyed by source)
    rev  == paper "from_rate" == traffic TO the prefix   (monitor input 1, keyed by destination)

UDP gives no delivery guarantee. The auth field is a placeholder: there is
NO authentication or integrity protection in either format.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import List, Tuple

MAGIC = 0x4D54  # "MT"
VERSION_1 = 1

HEADER_V1 = struct.Struct(">HBBBBBBIIQIHHQIHHIIQQ")
RECORD_V1 = struct.Struct(">IBBHIIQQ")
PAPER_HEADER = struct.Struct(">IH")
PAPER_RECORD = struct.Struct(">IB3xII")

HEADER_V1_SIZE = 72
RECORD_V1_SIZE = 32
PAPER_HEADER_SIZE = 6
PAPER_RECORD_SIZE = 16
assert HEADER_V1.size == HEADER_V1_SIZE
assert RECORD_V1.size == RECORD_V1_SIZE
assert PAPER_HEADER.size == PAPER_HEADER_SIZE
assert PAPER_RECORD.size == PAPER_RECORD_SIZE

EXPORT_MODES = ("LEAVES", "PARTITION", "ALL")
COUNT_UNITS = ("PACKETS", "BYTES")
FLAG_LEAF = 0x01
FLAG_RESIDUAL = 0x02
KNOWN_FLAGS = FLAG_LEAF | FLAG_RESIDUAL


class DecodeError(ValueError):
    """Raised for malformed datagrams. `code` matches the C++ decode_error_name()."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass
class HeaderV1:
    export_mode: str = "PARTITION"
    count_unit: int = 0
    router_id: int = 0
    boot_id: int = 0
    sequence: int = 0
    interval_id: int = 0
    fragment_index: int = 0
    fragment_count: int = 1
    timestamp_us: int = 0
    interval_ms: int = 0
    record_count: int = 0
    auth_placeholder: int = 0
    uncounted_fwd: int = 0
    uncounted_rev: int = 0


@dataclass
class RecordV1:
    prefix: str = "0.0.0.0"
    prefix_len: int = 0
    flags: int = 0
    fwd_rate: int = 0
    rev_rate: int = 0
    fwd_count: int = 0
    rev_count: int = 0

    @property
    def is_leaf(self) -> bool:
        return bool(self.flags & FLAG_LEAF)

    @property
    def is_residual(self) -> bool:
        return bool(self.flags & FLAG_RESIDUAL)

    # Paper aliases (see module docstring).
    @property
    def to_rate(self) -> int:
        return self.fwd_rate

    @property
    def from_rate(self) -> int:
        return self.rev_rate


@dataclass
class PaperRecord:
    prefix: str = "0.0.0.0"
    prefix_len: int = 0
    to_rate: int = 0
    from_rate: int = 0


@dataclass
class DatagramV1:
    header: HeaderV1
    records: List[RecordV1] = field(default_factory=list)


def _ip_to_int(text: str) -> int:
    return int(ipaddress.IPv4Address(text))


def _int_to_ip(value: int) -> str:
    return str(ipaddress.IPv4Address(value))


def _check_prefix(prefix: int, length: int) -> None:
    if length > 32:
        raise DecodeError("bad_prefix_length", f"/{length}")
    host_mask = 0xFFFFFFFF if length == 0 else (0 if length == 32 else (0xFFFFFFFF >> length))
    if prefix & host_mask:
        raise DecodeError("host_bits_set", f"{_int_to_ip(prefix)}/{length}")


# ---------------------------------------------------------------- V1

def encode_v1(header: HeaderV1, records: List[RecordV1]) -> bytes:
    out = bytearray(
        HEADER_V1.pack(
            MAGIC, VERSION_1, HEADER_V1_SIZE, RECORD_V1_SIZE,
            EXPORT_MODES.index(header.export_mode), header.count_unit, 0,
            header.router_id, header.boot_id, header.sequence, header.interval_id,
            header.fragment_index, header.fragment_count, header.timestamp_us,
            header.interval_ms, len(records), 0, header.auth_placeholder, 0,
            header.uncounted_fwd, header.uncounted_rev,
        )
    )
    for r in records:
        out += RECORD_V1.pack(_ip_to_int(r.prefix), r.prefix_len, r.flags, 0,
                              r.fwd_rate, r.rev_rate, r.fwd_count, r.rev_count)
    return bytes(out)


def decode_v1(data: bytes) -> DatagramV1:
    """Decode and fully validate one V1 datagram (same checks, same order as C++)."""
    if len(data) < 8:
        raise DecodeError("too_short", f"{len(data)} bytes")
    magic, version, header_len, record_len = struct.unpack_from(">HBBB", data, 0)
    if magic != MAGIC:
        raise DecodeError("bad_magic", hex(magic))
    if version != VERSION_1:
        raise DecodeError("bad_version", str(version))
    if header_len != HEADER_V1_SIZE:
        raise DecodeError("bad_header_length", str(header_len))
    if record_len != RECORD_V1_SIZE:
        raise DecodeError("bad_record_length", str(record_len))
    if len(data) < HEADER_V1_SIZE:
        raise DecodeError("too_short", f"{len(data)} bytes")

    (_, _, _, _, mode, unit, rsv0, router_id, boot_id, seq, interval_id, frag_idx,
     frag_cnt, ts, interval_ms, count, rsv1, auth, rsv2, unc_f, unc_r) = HEADER_V1.unpack_from(data, 0)
    if mode >= len(EXPORT_MODES):
        raise DecodeError("bad_export_mode", str(mode))
    if unit >= len(COUNT_UNITS):
        raise DecodeError("bad_count_unit", str(unit))
    if rsv0 or rsv1 or rsv2:
        raise DecodeError("reserved_not_zero", "header")
    if frag_cnt == 0 or frag_idx >= frag_cnt:
        raise DecodeError("bad_fragment", f"{frag_idx}/{frag_cnt}")
    if len(data) != HEADER_V1_SIZE + count * RECORD_V1_SIZE:
        raise DecodeError("length_mismatch", f"{len(data)} bytes for {count} records")

    header = HeaderV1(EXPORT_MODES[mode], unit, router_id, boot_id, seq, interval_id, frag_idx,
                      frag_cnt, ts, interval_ms, count, auth, unc_f, unc_r)
    records = []
    for i in range(count):
        prefix, plen, flags, rsv, fr, rr, fc, rc = RECORD_V1.unpack_from(
            data, HEADER_V1_SIZE + i * RECORD_V1_SIZE)
        if rsv:
            raise DecodeError("reserved_not_zero", f"record {i}")
        _check_prefix(prefix, plen)
        leaf, residual = bool(flags & FLAG_LEAF), bool(flags & FLAG_RESIDUAL)
        if (flags & ~KNOWN_FLAGS) or (leaf and residual):
            raise DecodeError("bad_flags", f"record {i} flags {flags:#x}")
        if header.export_mode == "LEAVES" and not leaf:
            raise DecodeError("bad_flags", f"record {i}: LEAVES requires LEAF")
        if header.export_mode == "PARTITION":
            if not (leaf or residual):
                raise DecodeError("bad_flags", f"record {i}: PARTITION requires LEAF or RESIDUAL")
            if residual and plen == 32:
                raise DecodeError("bad_flags", f"record {i}: residual /32")
        if header.export_mode == "ALL" and residual:
            raise DecodeError("bad_flags", f"record {i}: RESIDUAL not allowed in ALL")
        records.append(RecordV1(_int_to_ip(prefix), plen, flags, fr, rr, fc, rc))
    return DatagramV1(header, records)


# ---------------------------------------------------------------- PAPER (v0)

def encode_paper(records: List[PaperRecord], auth_placeholder: int = 0) -> bytes:
    out = bytearray(PAPER_HEADER.pack(auth_placeholder, len(records)))
    for r in records:
        out += PAPER_RECORD.pack(_ip_to_int(r.prefix), r.prefix_len, r.to_rate, r.from_rate)
    return bytes(out)


def decode_paper(data: bytes) -> Tuple[int, List[PaperRecord]]:
    if len(data) < PAPER_HEADER_SIZE:
        raise DecodeError("too_short", f"{len(data)} bytes")
    auth, count = PAPER_HEADER.unpack_from(data, 0)
    if len(data) != PAPER_HEADER_SIZE + count * PAPER_RECORD_SIZE:
        raise DecodeError("length_mismatch", f"{len(data)} bytes for {count} records")
    records = []
    for i in range(count):
        off = PAPER_HEADER_SIZE + i * PAPER_RECORD_SIZE
        prefix, plen, pad0, pad1, to_rate, from_rate = struct.unpack_from(">IBBHII", data, off)
        if pad0 or pad1:
            raise DecodeError("reserved_not_zero", f"record {i} padding")
        _check_prefix(prefix, plen)
        records.append(PaperRecord(_int_to_ip(prefix), plen, to_rate, from_rate))
    return auth, records


def max_records_v1(max_payload: int = 1472) -> int:
    return max(0, min((max_payload - HEADER_V1_SIZE) // RECORD_V1_SIZE, 0xFFFF))


def max_records_paper(max_payload: int = 1472) -> int:
    return max(0, min((max_payload - PAPER_HEADER_SIZE) // PAPER_RECORD_SIZE, 0xFFFF))

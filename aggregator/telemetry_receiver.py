"""MULTOPS telemetry receiver (Phase 3).

Receives V1 (or paper-format) telemetry over UDP, validates every datagram,
and classifies it per (router_id, boot_id) stream:

    accepted    new sequence number, in order (> every earlier one)
    reordered   new sequence number, but lower than one already seen
    duplicate   sequence number already seen (rejected)
    stale       too old to tell new from duplicate (rejected)
    malformed   failed validation (rejected; counted by error code)

Loss is *estimated*, not known: a sequence number never seen may still be in
flight. Interval fragments are reassembled by (router, boot, interval_id); an
interval is complete when all fragment_count fragments arrived.

This module performs NO aggregation or detection (that is Phase 4/5) and NO
authentication: router_id/boot_id are claims made by the sender.

Run (loopback only by default):
    python3 -m aggregator.telemetry_receiver --listen 127.0.0.1:49555 --duration 10 --out rx.jsonl
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from aggregator.telemetry_protocol import (DecodeError, HeaderV1, RecordV1, decode_paper,
                                           decode_v1)

ACCEPTED = "accepted"
REORDERED = "reordered"
DUPLICATE = "duplicate"
STALE = "stale"
MALFORMED = "malformed"

DEFAULT_REPLAY_WINDOW = 4096


class SequenceTracker:
    """Sliding-window duplicate/reorder detector for one stream (cf. IPsec anti-replay)."""

    def __init__(self, window: int = DEFAULT_REPLAY_WINDOW):
        self.window = window
        self.highest: Optional[int] = None
        self.lowest: Optional[int] = None
        self.seen: Set[int] = set()
        self.unique = 0

    def observe(self, seq: int) -> str:
        if self.highest is None:
            self.highest = self.lowest = seq
            self.seen.add(seq)
            self.unique = 1
            return ACCEPTED
        if seq > self.highest:
            self.highest = seq
            self.seen.add(seq)
            self.unique += 1
            floor = self.highest - self.window
            if len(self.seen) > 2 * self.window:
                self.seen = {s for s in self.seen if s > floor}
            return ACCEPTED
        if seq <= self.highest - self.window:
            return STALE
        if seq in self.seen:
            return DUPLICATE
        self.seen.add(seq)
        self.unique += 1
        if seq < self.lowest:
            self.lowest = seq
        return REORDERED

    def missing(self) -> int:
        """Sequence numbers between the lowest and highest seen that never arrived."""
        if self.highest is None:
            return 0
        return (self.highest - self.lowest + 1) - self.unique


@dataclass
class StreamStats:
    router_id: int
    boot_id: int
    source: str
    accepted: int = 0
    reordered: int = 0
    duplicates: int = 0
    stale: int = 0
    source_changes: int = 0
    first_seq: Optional[int] = None
    highest_seq: Optional[int] = None
    missing_estimate: int = 0
    intervals_complete: int = 0
    intervals_incomplete: int = 0
    intervals_inconsistent: int = 0


@dataclass
class Interval:
    """A fully reassembled export interval from one router."""
    router_id: int
    boot_id: int
    interval_id: int
    export_mode: str
    count_unit: int
    timestamp_us: int
    interval_ms: int
    uncounted_fwd: int
    uncounted_rev: int
    fragment_count: int
    records: List[RecordV1]
    received_at: float


@dataclass
class _Pending:
    header: HeaderV1
    fragments: Dict[int, List[RecordV1]] = field(default_factory=dict)
    inconsistent: bool = False
    first_seen: float = 0.0


@dataclass
class Verdict:
    status: str
    error: Optional[str] = None
    router_id: Optional[int] = None
    boot_id: Optional[int] = None
    sequence: Optional[int] = None
    interval_id: Optional[int] = None
    completed: Optional[Interval] = None
    restart: bool = False


class TelemetryReceiver:
    """Protocol state machine; feed it datagrams with process(). No sockets here."""

    def __init__(self, fmt: str = "V1", replay_window: int = DEFAULT_REPLAY_WINDOW,
                 on_interval: Optional[Callable[[Interval], None]] = None,
                 clock: Callable[[], float] = time.monotonic):
        if fmt not in ("V1", "PAPER"):
            raise ValueError("fmt must be V1 or PAPER")
        self.fmt = fmt
        self.replay_window = replay_window
        self.on_interval = on_interval
        self.clock = clock
        self.trackers: Dict[Tuple[int, int], SequenceTracker] = {}
        self.streams: Dict[Tuple[int, int], StreamStats] = {}
        self.current_boot: Dict[int, int] = {}
        self.pending: Dict[Tuple[int, int, int], _Pending] = {}
        self.done: Set[Tuple[int, int, int]] = set()
        self.malformed: Dict[str, int] = {}
        self.restarts = 0
        self.paper_datagrams = 0
        self.paper_records: List[Tuple[str, object]] = []

    # ---------------------------------------------------------------- input
    def process(self, data: bytes, source: str = "?") -> Verdict:
        if self.fmt == "PAPER":
            return self._process_paper(data, source)
        try:
            dg = decode_v1(data)
        except DecodeError as e:
            self.malformed[e.code] = self.malformed.get(e.code, 0) + 1
            return Verdict(MALFORMED, error=e.code)
        h = dg.header
        key = (h.router_id, h.boot_id)
        restart = False
        if key not in self.trackers:
            prev = self.current_boot.get(h.router_id)
            if prev is not None and prev != h.boot_id:
                restart = True
                self.restarts += 1
            self.trackers[key] = SequenceTracker(self.replay_window)
            self.streams[key] = StreamStats(h.router_id, h.boot_id, source)
        self.current_boot[h.router_id] = h.boot_id
        st = self.streams[key]
        if st.source != source:
            st.source_changes += 1
            st.source = source
        status = self.trackers[key].observe(h.sequence)
        if status == ACCEPTED:
            st.accepted += 1
        elif status == REORDERED:
            st.reordered += 1
        elif status == DUPLICATE:
            st.duplicates += 1
        else:
            st.stale += 1
        tr = self.trackers[key]
        st.first_seq, st.highest_seq, st.missing_estimate = tr.lowest, tr.highest, tr.missing()
        v = Verdict(status, None, h.router_id, h.boot_id, h.sequence, h.interval_id, restart=restart)
        if status in (ACCEPTED, REORDERED):
            v.completed = self._assemble(dg.header, dg.records)
        return v

    def _process_paper(self, data: bytes, source: str) -> Verdict:
        try:
            _, records = decode_paper(data)
        except DecodeError as e:
            self.malformed[e.code] = self.malformed.get(e.code, 0) + 1
            return Verdict(MALFORMED, error=e.code)
        # No sequence numbers: duplicates and losses cannot be detected.
        self.paper_datagrams += 1
        self.paper_records.extend((source, r) for r in records)
        return Verdict(ACCEPTED)

    # ---------------------------------------------------------------- assembly
    def _assemble(self, h: HeaderV1, records: List[RecordV1]) -> Optional[Interval]:
        ikey = (h.router_id, h.boot_id, h.interval_id)
        st = self.streams[(h.router_id, h.boot_id)]
        if ikey in self.done:
            # A new sequence number for an interval that is already complete:
            # sender bug or forged datagram. Not merged.
            st.intervals_inconsistent += 1
            return None
        p = self.pending.get(ikey)
        if p is None:
            p = self.pending[ikey] = _Pending(h, first_seen=self.clock())
        elif (h.fragment_count != p.header.fragment_count or h.export_mode != p.header.export_mode
              or h.interval_ms != p.header.interval_ms or h.timestamp_us != p.header.timestamp_us):
            p.inconsistent = True
        if h.fragment_index in p.fragments:
            p.inconsistent = True
            return None
        p.fragments[h.fragment_index] = records
        if len(p.fragments) < p.header.fragment_count:
            return None
        del self.pending[ikey]
        self.done.add(ikey)
        if p.inconsistent:
            st.intervals_inconsistent += 1
            return None
        st.intervals_complete += 1
        merged: List[RecordV1] = []
        for i in range(p.header.fragment_count):
            merged.extend(p.fragments[i])
        iv = Interval(h.router_id, h.boot_id, h.interval_id, p.header.export_mode, p.header.count_unit,
                      p.header.timestamp_us, p.header.interval_ms, p.header.uncounted_fwd,
                      p.header.uncounted_rev, p.header.fragment_count, merged, self.clock())
        if self.on_interval:
            self.on_interval(iv)
        return iv

    def expire_pending(self, max_age_s: float) -> int:
        """Give up on intervals still missing fragments after max_age_s. Returns how many."""
        now = self.clock()
        expired = [k for k, p in self.pending.items() if now - p.first_seen >= max_age_s]
        for k in expired:
            del self.pending[k]
            self.done.add(k)
            self.streams[(k[0], k[1])].intervals_incomplete += 1
        return len(expired)

    # ---------------------------------------------------------------- report
    def summary(self) -> dict:
        return {
            "format": self.fmt,
            "streams": [asdict(s) for s in self.streams.values()],
            "malformed": dict(self.malformed),
            "restarts": self.restarts,
            "pending_intervals": len(self.pending),
            "paper_datagrams": self.paper_datagrams,
        }


def _interval_json(iv: Interval) -> dict:
    d = asdict(iv)
    d["type"] = "interval"
    return d


def serve(listen: str, duration: float, out_path: Optional[str], fmt: str = "V1",
          allow_non_loopback: bool = False, ready_file: Optional[str] = None,
          fragment_timeout: float = 2.0) -> dict:
    host, _, port = listen.rpartition(":")
    if not allow_non_loopback and not ipaddress.IPv4Address(host).is_loopback:
        raise SystemExit("refusing to listen on a non-loopback address without --allow-non-loopback")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.bind((host, int(port)))
    sock.settimeout(0.1)
    bound_port = sock.getsockname()[1]
    out = open(out_path, "w") if out_path else None
    rx = TelemetryReceiver(fmt, on_interval=(lambda iv: out.write(json.dumps(_interval_json(iv)) + "\n"))
                           if out else None)
    if ready_file:
        with open(ready_file, "w") as f:
            f.write(str(bound_port))
    deadline = time.monotonic() + duration
    try:
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                rx.expire_pending(fragment_timeout)
                continue
            v = rx.process(data, f"{addr[0]}:{addr[1]}")
            if out:
                ev = {k: val for k, val in asdict(v).items() if k != "completed"}
                ev["type"] = "datagram"
                ev["bytes"] = len(data)
                out.write(json.dumps(ev) + "\n")
                if fmt == "PAPER" and v.status == ACCEPTED:
                    _, recs = decode_paper(data)
                    out.write(json.dumps({"type": "paper_datagram",
                                          "records": [asdict(r) for r in recs]}) + "\n")
        rx.expire_pending(0.0)
    finally:
        sock.close()
        summary = rx.summary()
        if out:
            out.write(json.dumps({"type": "summary", **summary}) + "\n")
            out.close()
    return summary


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--listen", default="127.0.0.1:49555", help="IPv4:PORT (port 0 = ephemeral)")
    ap.add_argument("--duration", type=float, default=10.0, help="seconds to listen")
    ap.add_argument("--out", help="JSON-lines log of datagrams, intervals and a final summary")
    ap.add_argument("--format", default="V1", choices=("V1", "PAPER"))
    ap.add_argument("--ready-file", help="write the bound port here once listening")
    ap.add_argument("--allow-non-loopback", action="store_true")
    args = ap.parse_args(argv)
    summary = serve(args.listen, args.duration, args.out, args.format, args.allow_non_loopback,
                    args.ready_file)
    json.dump(summary, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())

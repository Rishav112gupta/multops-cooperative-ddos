"""Global state aggregation (Phase 4).

Two aggregators over the same telemetry:

PaperAggregator  [PAPER]  AINA 2026 Algorithm 2 / Sec. 4.3: a dict keyed by IP
                 prefix; every received record adds its to_rate and from_rate
                 to M[prefix]; a periodic analysis timer (aggregator clock,
                 i.e. by ARRIVAL time) reads M and then resets it. No
                 de-duplication (the paper format has no sequence numbers), no
                 notion of which routers reported.

WindowedAggregator  [PROPOSAL, research extension]  built on the Phase 3
                 receiver (de-duplicated, fully reassembled intervals):
                 * sums exact per-interval COUNTS (additive), not EWMA rates;
                 * assigns each router interval to one global window, by the
                   router's own interval timestamps ("sender") or by arrival;
                 * records which routers reported in each window and flags
                   windows with missing routers as incomplete;
                 * reconciles mixed prefix granularity: a prefix node's fused
                   count is EXACT only if no router reported a coarser record
                   with traffic covering it (that traffic cannot be split).

Neither class makes a detection decision (Phase 5). Both produce per-window
global state that the Phase 4 analysis compares with ground truth.
"""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from aggregator.telemetry_receiver import Interval

Key = Tuple[str, int]          # (prefix, prefix_len)
LEVELS = (8, 16, 24, 32)


def mask(prefix: str, length: int) -> str:
    """Prefix with host bits cleared, as a dotted string."""
    return str(ipaddress.IPv4Network(f"{prefix}/{length}", strict=False).network_address)


def covers(outer: Key, inner: Key) -> bool:
    """True if prefix `outer` contains prefix `inner` (outer length <= inner length)."""
    return outer[1] <= inner[1] and mask(inner[0], outer[1]) == outer[0]


# ---------------------------------------------------------------- paper (Algorithm 2)

@dataclass
class PaperWindow:
    index: int
    start_s: float
    end_s: float
    state: Dict[Key, List[float]]          # key -> [R_in, R_out]
    datagrams: int


class PaperAggregator:
    """AINA 2026 Algorithm 2, data-fusion part: M[p].in += r.in; M[p].out += r.out;
    on each analysis-timer expiry the map is analysed and reset (M <- empty).

    `value` selects which numbers are summed: "rate" (paper: to_rate/from_rate)
    or "count" (same fusion, exact counts; for comparison only).
    """

    def __init__(self, period_s: float, value: str = "rate", start_s: float = 0.0):
        if value not in ("rate", "count"):
            raise ValueError("value must be 'rate' or 'count'")
        self.period_s = period_s
        self.value = value
        self.start_s = start_s
        self.index = 0
        self.state: Dict[Key, List[float]] = {}
        self.datagrams = 0
        self.closed: List[PaperWindow] = []

    def _close_through(self, t: float) -> None:
        while t >= self.start_s + (self.index + 1) * self.period_s:
            s = self.start_s + self.index * self.period_s
            self.closed.append(PaperWindow(self.index, s, s + self.period_s, self.state, self.datagrams))
            self.state, self.datagrams = {}, 0          # "M <- empty: reset for next window"
            self.index += 1

    def ingest(self, records: Iterable, arrival_s: float) -> None:
        """records: V1 RecordV1 or paper PaperRecord objects from ONE datagram."""
        self._close_through(arrival_s)
        self.datagrams += 1
        for r in records:
            k = (r.prefix, r.prefix_len)
            if self.value == "rate":
                rin, rout = (r.to_rate, r.from_rate)
            else:
                rin, rout = (r.fwd_count, r.rev_count)
            e = self.state.setdefault(k, [0.0, 0.0])
            e[0] += rin
            e[1] += rout

    def finish(self, t_end: float) -> List[PaperWindow]:
        self._close_through(t_end)
        return self.closed


# ---------------------------------------------------------------- proposal

@dataclass
class NodeState:
    fwd: int = 0
    rev: int = 0
    exact: bool = True
    routers: Set[int] = field(default_factory=set)


@dataclass
class ReconciledWindow:
    index: int
    start_s: float
    end_s: float
    routers_reported: Set[int]
    missing_routers: Set[int]
    intervals: int
    uncounted_fwd: int
    uncounted_rev: int
    nodes: Dict[Key, NodeState]

    @property
    def complete(self) -> bool:
        return not self.missing_routers

    def finest_exact(self, address: str) -> Optional[Tuple[Key, NodeState]]:
        """Deepest exact node on the path of `address` (None if no traffic)."""
        best = None
        for length in LEVELS:
            k = (mask(address, length), length)
            n = self.nodes.get(k)
            if n is None:
                break
            if n.exact:
                best = (k, n)
        return best


@dataclass
class RouterRole:
    """Which directions of a router's reports are counted (proposal for the
    double-observation problem: only designated observation points count)."""
    count_fwd: bool = True
    count_rev: bool = True


class WindowedAggregator:
    def __init__(self, window_s: float, expected_routers: Optional[Set[int]] = None,
                 align: str = "sender", grace_s: float = 0.5,
                 roles: Optional[Dict[int, RouterRole]] = None, start_s: float = 0.0):
        if align not in ("sender", "arrival"):
            raise ValueError("align must be 'sender' or 'arrival'")
        self.window_s = window_s
        self.expected = set(expected_routers or ())
        self.align = align
        self.grace_s = grace_s
        self.roles = roles or {}
        self.start_s = start_s
        self.pending: Dict[int, List[Interval]] = {}
        # First window to report; set lazily from the first interval so that
        # absolute (Unix-time) clocks do not create ~1e9 empty windows.
        self.next_to_close: Optional[int] = None
        self.closed: List[ReconciledWindow] = []
        self.late_intervals = 0

    def window_of(self, iv: Interval, arrival_s: float) -> int:
        if self.align == "sender":
            # Midpoint of the router's own interval, in the router's clock.
            t = iv.timestamp_us / 1e6 - iv.interval_ms / 2000.0
        else:
            t = arrival_s
        return math.floor((t - self.start_s) / self.window_s)

    def add_interval(self, iv: Interval, arrival_s: float) -> None:
        k = self.window_of(iv, arrival_s)
        if self.next_to_close is None:
            self.next_to_close = k
        self._close_through(arrival_s)
        if k < self.next_to_close:
            self.late_intervals += 1          # its window was already reported
            return
        self.pending.setdefault(k, []).append(iv)

    def _close_through(self, now_s: float) -> None:
        if self.next_to_close is None:
            return
        while now_s >= self.start_s + (self.next_to_close + 1) * self.window_s + self.grace_s:
            k = self.next_to_close
            self.closed.append(self._reconcile(k, self.pending.pop(k, [])))
            self.next_to_close += 1

    def finish(self, now_s: float) -> List[ReconciledWindow]:
        self._close_through(now_s)
        return self.closed

    def _reconcile(self, k: int, intervals: List[Interval]) -> ReconciledWindow:
        start = self.start_s + k * self.window_s
        reported = {iv.router_id for iv in intervals}
        nodes: Dict[Key, NodeState] = {}
        coarse: List[Key] = []             # records with traffic, for the exactness rule
        unc_f = unc_r = 0
        for iv in intervals:
            role = self.roles.get(iv.router_id, RouterRole())
            if role.count_fwd:
                unc_f += iv.uncounted_fwd
            if role.count_rev:
                unc_r += iv.uncounted_rev
            for r in iv.records:
                f = r.fwd_count if role.count_fwd else 0
                v = r.rev_count if role.count_rev else 0
                if not (f or v):
                    continue
                coarse.append((r.prefix, r.prefix_len))
                for length in LEVELS:
                    if length > r.prefix_len:
                        break
                    n = nodes.setdefault((mask(r.prefix, length), length), NodeState())
                    n.fwd += f
                    n.rev += v
                    n.routers.add(iv.router_id)
        # Exactness: node (q, l) is exact unless some record with length < l covers it.
        for key, n in nodes.items():
            n.exact = not any(c[1] < key[1] and covers(c, key) for c in coarse)
        return ReconciledWindow(k, start, start + self.window_s, reported,
                                self.expected - reported, len(intervals), unc_f, unc_r, nodes)

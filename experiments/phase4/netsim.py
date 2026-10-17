"""Deterministic multi-router simulation for the Phase 4 aggregation analysis.

Pipeline (everything offline, no sockets, fully reproducible from a seed):

  1. Python generates every packet of every flow (true time, ms resolution)
     and records GROUND TRUTH per 1-second window, counting each packet once:
       request packets -> fwd of their source address
       reply packets   -> rev of their destination address
  2. For each router, the packets that cross it are written as a trace in the
     router's LOCAL clock (true time + skew) with the input port it uses.
  3. The C++ tool multops_replay runs the real MULTOPS tree + V1 exporter on
     each trace and dumps the exact telemetry datagrams with send times.
  4. A network model turns send times into arrival times (constant delay per
     router) and applies seeded loss / duplication.
  5. The datagrams are fed, in arrival order, to
       - PaperAggregator   (Algorithm 2: sum rates per prefix key, reset per period)
       - TelemetryReceiver + WindowedAggregator (proposal)
     and both are scored against the ground truth.

This is a simulation of MULTOPS telemetry, not of a network: there is no
queueing, routing protocol or packet loss on the data path.
"""

from __future__ import annotations

import ipaddress
import random
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from aggregator.aggregator import (PaperAggregator, RouterRole, WindowedAggregator, mask)
from aggregator.telemetry_protocol import decode_v1
from aggregator.telemetry_receiver import TelemetryReceiver


@dataclass
class Flow:
    name: str
    src: str
    dst: str
    pps: float
    kind: str                                   # "request" or "reply"
    path: List[Tuple[int, int]]                 # [(router_id, input_port)]
    segments: List[Tuple[float, float]]         # on-periods [(start_s, stop_s)]
    offset_s: float = 0.0                       # phase of the first packet
    malicious: bool = False                     # ground-truth label (Phase 5)


@dataclass
class Router:
    rid: int
    thresh: int = 50
    interval_ms: int = 1000
    phase_ms: int = 0
    skew_ms: int = 0                            # local clock = true clock + skew
    delay_ms: int = 5
    loss: float = 0.0
    dup: float = 0.0


@dataclass
class Scenario:
    name: str
    title: str
    flows: List[Flow]
    routers: List[Router]
    duration_s: int = 20
    window_s: float = 1.0
    seed: int = 1
    roles: Dict[int, RouterRole] = field(default_factory=dict)
    note: str = ""


@dataclass
class Event:
    arrival_s: float
    router: int
    data: bytes


def on_off(period_s: float, on_s: float, duration_s: float, start_s: float = 0.0):
    segs, t = [], start_s
    while t < duration_s:
        segs.append((t, min(t + on_s, duration_s)))
        t += period_s
    return segs


def generate_packets(flow: Flow):
    """Evenly spaced packet times (ms) within each on-segment."""
    gap = 1.0 / flow.pps
    for s, e in flow.segments:
        t = s + flow.offset_s
        while t < e:
            yield int(t * 1000)
            t += gap


class Truth:
    """Exact per-window fwd/rev counts per address (each packet counted once)."""

    def __init__(self, window_s: float):
        self.window_s = window_s
        self.fwd = defaultdict(lambda: defaultdict(int))     # window -> addr -> count
        self.rev = defaultdict(lambda: defaultdict(int))
        # Phase 5: packets of malicious flows, keyed like fwd/rev.
        self.atk_fwd = defaultdict(lambda: defaultdict(int))
        self.atk_rev = defaultdict(lambda: defaultdict(int))

    def add(self, flow: Flow, t_ms: int):
        w = int((t_ms / 1000.0) // self.window_s)
        if flow.kind == "request":
            self.fwd[w][flow.src] += 1
            if flow.malicious:
                self.atk_fwd[w][flow.src] += 1
        else:
            self.rev[w][flow.dst] += 1
            if flow.malicious:
                self.atk_rev[w][flow.dst] += 1

    def prefix(self, window: int, prefix: str, length: int) -> Tuple[int, int]:
        net = ipaddress.IPv4Network(f"{prefix}/{length}", strict=False)
        f = sum(c for a, c in self.fwd[window].items() if ipaddress.IPv4Address(a) in net)
        r = sum(c for a, c in self.rev[window].items() if ipaddress.IPv4Address(a) in net)
        return f, r


def build_traces(sc: Scenario, workdir: Path) -> Tuple[Dict[int, Path], Truth]:
    truth = Truth(sc.window_s)
    lines: Dict[int, List[Tuple[int, str, str]]] = defaultdict(list)
    skew = {r.rid: r.skew_ms for r in sc.routers}
    for f in sc.flows:
        for t in generate_packets(f):
            truth.add(f, t)
            for rid, port in f.path:
                addr = f.src if port == 0 else f.dst
                lines[rid].append((t + skew[rid], "F" if port == 0 else "R", addr))
    paths = {}
    for r in sc.routers:
        p = workdir / f"{sc.name}_r{r.rid}.csv"
        rows = sorted(lines[r.rid], key=lambda x: x[0])
        p.write_text("".join(f"{t},{d},{a},1\n" for t, d, a in rows))
        paths[r.rid] = p
    return paths, truth


def run_replay(replay: Path, sc: Scenario, r: Router, trace: Path, mode: str, workdir: Path) -> List[Tuple[int, bytes]]:
    dump = workdir / f"{sc.name}_r{r.rid}_{mode}.dump"
    end_ms = (sc.duration_s + 1) * 1000 + r.skew_ms + r.phase_ms
    cmd = [str(replay), "--thresh", str(r.thresh), "--interval-ms", str(r.interval_ms),
           "--phase-ms", str(r.phase_ms), "--start-ms", "0", "--end-ms", str(end_ms),
           "--mode", mode, "--router-id", str(r.rid), "--boot-id", str(1000 + r.rid),
           "--dump", str(dump), str(trace)]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    out = []
    for line in dump.read_text().splitlines():
        t, h = line.split()
        out.append((int(t), bytes.fromhex(h)))
    return out


def network(sc: Scenario, dumps: Dict[int, List[Tuple[int, bytes]]]) -> List[Event]:
    events = []
    for r in sc.routers:
        rng = random.Random(sc.seed * 1000 + r.rid)
        for local_ms, data in dumps[r.rid]:
            arrival = (local_ms - r.skew_ms + r.delay_ms) / 1000.0
            if rng.random() < r.loss:
                continue
            events.append(Event(arrival, r.rid, data))
            if rng.random() < r.dup:
                events.append(Event(arrival + 0.001, r.rid, data))
    events.sort(key=lambda e: (e.arrival_s, e.router))
    return events


@dataclass
class SimOutput:
    scenario: Scenario
    truth: Truth
    paper: list
    proposal: Dict[str, list]                  # variant name -> windows
    receiver_summary: dict
    events_all: int
    events_partition: int


def simulate(sc: Scenario, replay: Path, workdir: Path, variants=("sender",)) -> SimOutput:
    workdir.mkdir(parents=True, exist_ok=True)
    traces, truth = build_traces(sc, workdir)
    end_s = sc.duration_s + 3.0

    # Paper pipeline: ALL-mode export ("every node with active traffic").
    dumps_all = {r.rid: run_replay(replay, sc, r, traces[r.rid], "all", workdir) for r in sc.routers}
    ev_all = network(sc, dumps_all)
    paper = PaperAggregator(sc.window_s, value="rate")
    for e in ev_all:
        paper.ingest(decode_v1(e.data).records, e.arrival_s)
    paper_windows = paper.finish(end_s)

    # Proposal pipeline: PARTITION-mode export, receiver de-duplication.
    dumps_part = {r.rid: run_replay(replay, sc, r, traces[r.rid], "partition", workdir) for r in sc.routers}
    ev_part = network(sc, dumps_part)
    expected = {r.rid for r in sc.routers}
    proposal, rx_summary = {}, None
    for variant in variants:
        now = [0.0]
        rx = TelemetryReceiver(clock=lambda: now[0])
        agg = WindowedAggregator(sc.window_s, expected_routers=expected, align=variant,
                                 grace_s=0.5, roles=sc.roles)
        for e in ev_part:
            now[0] = e.arrival_s
            v = rx.process(e.data, f"r{e.router}")
            if v.completed is not None:
                agg.add_interval(v.completed, e.arrival_s)
            rx.expire_pending(1.0)
        rx.expire_pending(0.0)
        proposal[variant] = agg.finish(end_s)
        rx_summary = rx.summary()
    return SimOutput(sc, truth, paper_windows, proposal, rx_summary, len(ev_all), len(ev_part))


# ---------------------------------------------------------------- scoring

def eval_range(sc: Scenario) -> range:
    """Windows scored: skip the first 2 (EWMA warm-up, first expansions) and the last."""
    return range(2, sc.duration_s - 1)


# Arrival-aligned windows lag the data by one window: the report for the
# interval [k-1, k) is sent at k and arrives in arrival window k. Arrival-based
# results (paper aggregator, proposal with align="arrival") are therefore
# scored against truth window (index - ARRIVAL_LAG).
ARRIVAL_LAG = 1


def score_paper(out: SimOutput, address: str) -> dict:
    """Paper aggregator, benign address: windows where some prefix key covering the
    address has R_in > 0 and R_out == 0 while the true return traffic is > 0
    (Algorithm 2 would compute Ratio = infinity for that key)."""
    sc, truth = out.scenario, out.truth
    one_sided, scored, rel_err = 0, 0, []
    for w in out.paper:
        tw = w.index - ARRIVAL_LAG
        if tw not in eval_range(sc):
            continue
        tf, tr = truth.prefix(tw, address, 8)
        if tr == 0:
            continue
        scored += 1
        keys = [(k, v) for k, v in w.state.items()
                if ipaddress.IPv4Address(address) in ipaddress.IPv4Network(f"{k[0]}/{k[1]}")]
        if any(v[0] > 0 and v[1] == 0 for _, v in keys):
            one_sided += 1
        k8 = (mask(address, 8), 8)
        if k8 in w.state and tf > 0:
            est_ratio = w.state[k8][0] / w.state[k8][1] if w.state[k8][1] else float("inf")
            rel_err.append(abs(est_ratio - tf / tr) / (tf / tr))
    return {"scored": scored, "one_sided": one_sided,
            "ratio8_median_rel_err": sorted(rel_err)[len(rel_err) // 2] if rel_err else None,
            "ratio8_max_rel_err": max(rel_err) if rel_err else None}


def score_proposal(out: SimOutput, variant: str, address: str) -> dict:
    sc, truth = out.scenario, out.truth
    lag = ARRIVAL_LAG if variant == "arrival" else 0
    scored = withheld = one_sided = exact_hits = 0
    levels = defaultdict(int)
    max_abs_err = 0
    ratio_err = []
    for w in out.proposal[variant]:
        tw = w.index - lag
        if tw not in eval_range(sc):
            continue
        tf8, tr8 = truth.prefix(tw, address, 8)
        if tf8 == 0 and tr8 == 0:
            continue
        scored += 1
        if not w.complete:
            withheld += 1
            continue
        fe = w.finest_exact(address)
        if fe is None:
            continue
        (p, length), n = fe
        levels[length] += 1
        tf, tr = truth.prefix(tw, p, length)
        err = max(abs(n.fwd - tf), abs(n.rev - tr))
        max_abs_err = max(max_abs_err, err)
        if err == 0:
            exact_hits += 1
        if n.fwd > 0 and n.rev == 0 and tr > 0:
            one_sided += 1
        if tr > 0 and n.rev > 0:
            ratio_err.append(abs(n.fwd / n.rev - tf / tr) / (tf / tr))
    return {"scored": scored, "withheld_incomplete": withheld, "one_sided": one_sided,
            "counts_exact": exact_hits, "max_abs_count_err": max_abs_err,
            "levels": dict(sorted(levels.items())),
            "ratio_median_rel_err": sorted(ratio_err)[len(ratio_err) // 2] if ratio_err else None,
            "ratio_max_rel_err": max(ratio_err) if ratio_err else None}


def score_attacker(out: SimOutput, variant: str, address: str) -> dict:
    """Flood source: proposal estimate at its finest exact node vs truth."""
    sc, truth = out.scenario, out.truth
    lag = ARRIVAL_LAG if variant == "arrival" else 0
    errs, rev_nonzero = [], 0
    for w in out.proposal[variant]:
        tw = w.index - lag
        if tw not in eval_range(sc) or not w.complete:
            continue
        fe = w.finest_exact(address)
        if fe is None:
            continue
        (p, length), n = fe
        tf, tr = truth.prefix(tw, p, length)
        errs.append(abs(n.fwd - tf))
        rev_nonzero += n.rev > 0
    return {"windows": len(errs), "max_abs_fwd_err": max(errs) if errs else None,
            "windows_with_rev": rev_nonzero}

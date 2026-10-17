#!/usr/bin/env python3
"""Phase 4 aggregation analysis: run every scenario, score both aggregators
against ground truth, write results to experiments/results/phase4/.

Usage: python3 -m experiments.phase4.run_phase4 [--build build] [--out experiments/results/phase4]

Deterministic: rerunning produces identical numbers (seeded, no wall clock).
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

from aggregator.aggregator import RouterRole
from experiments.phase4.netsim import (Flow, Router, Scenario, on_off, score_attacker, score_paper,
                                       score_proposal, simulate)

CLIENT, SERVER = "192.168.1.1", "192.168.1.2"      # paper Table 1, flow B
ATTACKER, VICTIM = "10.0.0.1", "18.0.0.1"          # paper Table 1, flow A
DURATION = 60


def flows(req_path, rep_path, flood_path):
    session = on_off(period_s=5.0, on_s=3.3, duration_s=DURATION, start_s=0.4)
    return [
        Flow("request", CLIENT, SERVER, 100, "request", req_path, session),
        Flow("reply", SERVER, CLIENT, 30, "reply", rep_path, session, offset_s=0.02),
        Flow("flood", ATTACKER, VICTIM, 2000, "request", flood_path, [(0.0, DURATION)]),
    ]


def scenarios():
    """S2 isolates granularity (THRESH 50: R2 never expands the 30 pps replies).
    S3 is the matched-granularity baseline (THRESH 20 on both routers); S4-S9
    each change ONE factor relative to S3."""
    asym = flows([(1, 0)], [(2, 1)], [(1, 0)])
    T = 20
    return [
        Scenario("S1_single_router", "Single router sees both directions (symmetric routing)",
                 flows([(1, 0)], [(1, 1)], [(1, 0)]), [Router(1)]),
        Scenario("S2_asym_granularity", "Asymmetric, THRESH 50: R1 expands client to /32, R2 keeps /8",
                 asym, [Router(1), Router(2)]),
        Scenario("S3_asym_baseline", "Asymmetric, THRESH 20: both routers expand (baseline for S4-S9)",
                 asym, [Router(1, thresh=T), Router(2, thresh=T)]),
        Scenario("S4_interval_mismatch", "S3 + R1 exports every 0.5 s (R2 every 1 s)", asym,
                 [Router(1, thresh=T, interval_ms=500), Router(2, thresh=T)]),
        Scenario("S5_phase_offset", "S3 + R2 export boundaries offset by 0.5 s", asym,
                 [Router(1, thresh=T), Router(2, thresh=T, phase_ms=500)]),
        Scenario("S6_clock_skew", "S3 + R2 clock 300 ms ahead", asym,
                 [Router(1, thresh=T), Router(2, thresh=T, skew_ms=300)]),
        Scenario("S7_telemetry_loss", "S3 + 20% of R2's datagrams lost", asym,
                 [Router(1, thresh=T), Router(2, thresh=T, loss=0.2)], seed=7),
        Scenario("S8_duplicates", "S3 + 30% of R1's datagrams duplicated", asym,
                 [Router(1, thresh=T, dup=0.3), Router(2, thresh=T)], seed=8),
        Scenario("S9_double_observation", "S3 + requests cross R1 and R3 (both count)",
                 flows([(1, 0), (3, 0)], [(2, 1)], [(1, 0)]),
                 [Router(1, thresh=T), Router(2, thresh=T), Router(3, thresh=T)]),
        Scenario("S9b_double_observation_roles", "S9 + proposal roles: only R1 counts requests",
                 flows([(1, 0), (3, 0)], [(2, 1)], [(1, 0)]),
                 [Router(1, thresh=T), Router(2, thresh=T), Router(3, thresh=T)],
                 roles={3: RouterRole(count_fwd=False)}),
    ]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", default="build")
    ap.add_argument("--out", default="experiments/results/phase4")
    args = ap.parse_args(argv)
    replay = Path(args.build) / "multops_replay"
    if not replay.exists():
        print(f"missing {replay}; build first", file=sys.stderr)
        return 2
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    runs = []
    for sc in scenarios():
        runs.append(replace(sc, duration_s=DURATION))
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        for sc in runs:
            out = simulate(sc, replay, Path(tmp) / sc.name, variants=("sender", "arrival"))
            row = {
                "scenario": sc.name, "title": sc.title, "note": sc.note,
                "routers": [vars(r) for r in sc.routers],
                "datagrams_all_mode": out.events_all, "datagrams_partition_mode": out.events_partition,
                "receiver": {k: v for k, v in out.receiver_summary.items() if k != "format"},
                "paper": score_paper(out, CLIENT),
                "proposal_sender": score_proposal(out, "sender", CLIENT),
                "proposal_arrival": score_proposal(out, "arrival", CLIENT),
                "attacker_sender": score_attacker(out, "sender", ATTACKER),
            }
            results.append(row)
            p, s, a = row["paper"], row["proposal_sender"], row["proposal_arrival"]
            print(f"{sc.name:32s} paper one-sided {p['one_sided']:2d}/{p['scored']:2d} | "
                  f"proposal(sender) withheld {s['withheld_incomplete']:2d} one-sided {s['one_sided']:2d} "
                  f"exact {s['counts_exact']:2d}/{s['scored']:2d} maxerr {s['max_abs_count_err']:3d} "
                  f"levels {s['levels']} ratio_err {s['ratio_max_rel_err'] or 0:.2f} | "
                  f"paper r8err {p['ratio8_max_rel_err'] or 0:.2f} | "
                  f"arrival one-sided {a['one_sided']:2d} exact {a['counts_exact']:2d}")

    (out_dir / "phase4_results.json").write_text(json.dumps(results, indent=2) + "\n")
    def f2(x):
        return "n/a" if x is None else ("inf" if x == float("inf") else f"{x:.2f}")

    lines = ["# Phase 4 simulation results (generated by experiments/phase4/run_phase4.py)", "",
             f"Benign client 192.168.1.1 (on/off session 3.3 s on / 1.7 s off, 100 req/s, 30 rep/s); "
             f"flood 10.0.0.1 -> 18.0.0.1 at 2000 pps. {DURATION} s, 1 s windows, windows 2..{DURATION - 2} "
             "scored (only windows where the client has traffic). Arrival-aligned results are scored "
             "against the previous truth window (one-window reporting lag).", "",
             "## Benign client", "",
             "| Scenario | Paper: one-sided windows | Paper /8 ratio rel. err (median / max) | "
             "Proposal (sender): withheld | one-sided | exact counts | max count err | "
             "ratio rel. err (median / max) | exact level used | Proposal (arrival): one-sided | exact counts |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in results:
        p, s, a = r["paper"], r["proposal_sender"], r["proposal_arrival"]
        lines.append(f"| {r['scenario']} | {p['one_sided']}/{p['scored']} | "
                     f"{f2(p['ratio8_median_rel_err'])} / {f2(p['ratio8_max_rel_err'])} | "
                     f"{s['withheld_incomplete']} | {s['one_sided']} | {s['counts_exact']}/{s['scored']} | "
                     f"{s['max_abs_count_err']} | {f2(s['ratio_median_rel_err'])} / {f2(s['ratio_max_rel_err'])} | "
                     f"{s['levels']} | {a['one_sided']} | {a['counts_exact']}/{a['scored']} |")
    lines += ["", "## Flood source 10.0.0.1 (proposal, sender alignment, complete windows)", "",
              "| Scenario | windows | max abs fwd count err | windows with rev > 0 |", "|---|---|---|---|"]
    for r in results:
        t = r["attacker_sender"]
        lines.append(f"| {r['scenario']} | {t['windows']} | {t['max_abs_fwd_err']} | {t['windows_with_rev']} |")
    lines += ["", "## Telemetry and receiver", "",
              "| Scenario | datagrams (ALL mode) | datagrams (PARTITION) | receiver: duplicates | missing estimate | "
              "incomplete intervals |", "|---|---|---|---|---|---|"]
    for r in results:
        st = r["receiver"]["streams"]
        lines.append(f"| {r['scenario']} | {r['datagrams_all_mode']} | {r['datagrams_partition_mode']} | "
                     f"{sum(x['duplicates'] for x in st)} | {sum(x['missing_estimate'] for x in st)} | "
                     f"{sum(x['intervals_incomplete'] for x in st)} |")
    (out_dir / "phase4_results.md").write_text("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

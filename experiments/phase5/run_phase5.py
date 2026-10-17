#!/usr/bin/env python3
"""Phase 5 detection evaluation: scenarios x methods x threshold grid.

Usage: python3 -m experiments.phase5.run_phase5 [--build build] [--out experiments/results/phase5]

Methods (aggregator + rule):
  paper       PaperAggregator (rates, per-key, arrival windows) + PAPER_LITERAL     [PAPER]
  proposal    WindowedAggregator (counts, exact partition, sender windows) + CORRECTED [PROPOSAL]
  ablation_rule_only   PaperAggregator + CORRECTED        (isolates the rule)
  ablation_agg_only    WindowedAggregator + PAPER_LITERAL (isolates the aggregation)
  proposal_hier        proposal + opt-in low-volume aggregate check (further proposal)

All thresholds are EXPERIMENTAL; the paper specifies none. The reference
configuration E1 was fixed before any result was computed:
  tau_ratio = 5, tau_min = tau_rate = 50 pps
chosen above the synthetic benign client's 100:30 request:reply ratio, i.e.
WITH knowledge of the benign profile. It is not a validated operating point.

Deterministic: seeded traffic and network model, simulated clocks.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from aggregator.detection import (CORRECTED, PAPER_LITERAL, CorrectedDetector, PaperDetector,
                                  Thresholds)
from experiments.phase4.netsim import Flow, Router, Scenario, eval_range, on_off, simulate
from experiments.phase5.evaluate import score

CLIENT, SERVER = "192.168.1.1", "192.168.1.2"
ATTACKER, VICTIM = "10.0.0.1", "18.0.0.1"
DURATION = 60
E1 = Thresholds(ratio=5.0, min_rate=50.0, min_volume=50.0)
RATIOS = [1.5, 2.0, 3.0, 4.0, 5.0, 10.0, 20.0]
VOLUMES = [0.0, 10.0, 25.0, 50.0, 100.0, 250.0]


def session(req_path, rep_path):
    seg = on_off(5.0, 3.3, DURATION, 0.4)
    return [Flow("client_req", CLIENT, SERVER, 100, "request", req_path, seg),
            Flow("client_rep", SERVER, CLIENT, 30, "reply", rep_path, seg, offset_s=0.02)]


def flood(src=ATTACKER, pps=2000, path=((1, 0),)):
    return Flow(f"flood_{src}", src, VICTIM, pps, "request", list(path), [(0.0, DURATION)], malicious=True)


def scenarios():
    R1, R2 = [(1, 0)], [(2, 1)]
    two20 = [Router(1, thresh=20), Router(2, thresh=20)]
    two50 = [Router(1, thresh=50), Router(2, thresh=50)]
    return [
        Scenario("D0_standalone", "Only R1 is monitored; replies take an unmonitored path",
                 session(R1, []) + [flood()], [Router(1, thresh=20)]),
        Scenario("D1_cooperative", "Requests+flood via R1, replies via R2 (THRESH 20)",
                 session(R1, R2) + [flood()], two20),
        Scenario("D2_granularity", "D1 with THRESH 50 (R2 keeps replies at /8)",
                 session(R1, R2) + [flood()], two50),
        Scenario("D3_legit_one_way", "D1 + benign one-way stream 172.16.5.5 -> 203.0.113.9, 200 pps",
                 session(R1, R2) + [flood(), Flow("oneway", "172.16.5.5", "203.0.113.9", 200,
                                                  "request", R1, [(0.0, DURATION)])], two20),
        Scenario("D4_low_rate_attack", "Zero-return attack at only 20 pps (no large flood)",
                 session(R1, R2) + [flood(pps=20)], two20),
        Scenario("D5_proportional_attack", "Attacker 1000 req/s that elicits 800 replies/s",
                 session(R1, R2) + [flood(pps=1000),
                                    Flow("atk_rep", VICTIM, ATTACKER, 800, "reply", R2,
                                         [(0.0, DURATION)], offset_s=0.01, malicious=True)], two20),
        Scenario("D6_distributed_low_rate", "50 attackers 10.1.0.1-50 at 40 pps each (2000 pps total)",
                 session(R1, R2) + [flood(src=f"10.1.0.{i}", pps=40) for i in range(1, 51)], two20),
        Scenario("D7_mixed_prefix", "THRESH 50; attacker 192.168.1.66 shares the client's /24",
                 session(R1, R2) + [flood(src="192.168.1.66")], two50),
        Scenario("D8_telemetry_loss", "D1 + 20% of R2's datagrams lost", session(R1, R2) + [flood()],
                 [Router(1, thresh=20), Router(2, thresh=20, loss=0.2)], seed=7),
        Scenario("D9_benign_low_rate_sensors",
                 "D1 + 30 benign one-way sensors 10.2.0.1-30 at 20 pps each (no replies)",
                 session(R1, R2) + [flood()] + [
                     Flow(f"sensor{i}", f"10.2.0.{i}", "203.0.113.50", 20, "request", R1,
                          [(0.0, DURATION)], offset_s=i * 0.001) for i in range(1, 31)], two20),
    ]


def counts(m):
    """Raw counts kept for each sweep cell; every rate metric derives from these."""
    return {k: m[k] for k in ("TP", "FP", "TN", "FN", "units_abstained")}


def windows_with_traffic(truth, rng):
    return sum(1 for w in rng if truth.fwd[w] or truth.rev[w])


def evaluate(out, rule_paper, rule_prop, th, hier=False):
    sc, truth = out.scenario, out.truth
    rng = eval_range(sc)
    wt = windows_with_traffic(truth, rng)
    pdec = [d for w in out.paper for d in PaperDetector(rule_paper, th).decide(w)]
    det = CorrectedDetector(rule_prop, th, sc.window_s, aggregate_low_volume=hier)
    cdec = [d for w in out.proposal["sender"] for d in det.decide(w)]
    return score(pdec, truth, 1, rng, wt), score(cdec, truth, 0, rng, wt)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", default="build")
    ap.add_argument("--out", default="experiments/results/phase5")
    args = ap.parse_args(argv)
    replay = Path(args.build) / "multops_replay"
    if not replay.exists():
        print(f"missing {replay}; build first", file=sys.stderr)
        return 2
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    results = {"reference_thresholds_E1": vars(E1), "ratios": RATIOS, "volumes": VOLUMES,
               "duration_s": DURATION, "scenarios": []}
    with tempfile.TemporaryDirectory() as tmp:
        for sc in scenarios():
            sc.duration_s = DURATION
            out = simulate(sc, replay, Path(tmp) / sc.name, variants=("sender",))
            entry = {"scenario": sc.name, "title": sc.title, "routers": [vars(r) for r in sc.routers],
                     "E1": {}, "sweep": []}
            p, c = evaluate(out, PAPER_LITERAL, CORRECTED, E1)
            ap_, ag = evaluate(out, CORRECTED, PAPER_LITERAL, E1)
            _, ch = evaluate(out, PAPER_LITERAL, CORRECTED, E1, hier=True)
            entry["E1"] = {"paper": p, "proposal": c, "ablation_rule_only": ap_, "ablation_agg_only": ag,
                           "proposal_hier": ch}
            for ratio in RATIOS:
                for vol in VOLUMES:
                    th = Thresholds(ratio, vol, vol)
                    p, c = evaluate(out, PAPER_LITERAL, CORRECTED, th)
                    _, ch = evaluate(out, PAPER_LITERAL, CORRECTED, th, hier=True)
                    entry["sweep"].append({"ratio": ratio, "min": vol, "paper": counts(p),
                                           "proposal": counts(c), "proposal_hier": counts(ch)})
            results["scenarios"].append(entry)
            e = entry["E1"]
            print(f"{sc.name:26s} paper TP/FP/TN/FN={e['paper']['TP']}/{e['paper']['FP']}/{e['paper']['TN']}/"
                  f"{e['paper']['FN']}  proposal={e['proposal']['TP']}/{e['proposal']['FP']}/"
                  f"{e['proposal']['TN']}/{e['proposal']['FN']} abst={e['proposal']['units_abstained']}")
    (out_dir / "phase5_results.json").write_text(json.dumps(results, indent=1, sort_keys=True) + "\n")
    (out_dir / "phase5_results.md").write_text(render(results))
    return 0


def f(x, nd=2):
    return "n/a" if x is None else f"{x:.{nd}f}"


def render(res) -> str:
    L = ["# Phase 5 detection results (generated by experiments/phase5/run_phase5.py)", "",
         f"{res['duration_s']} s per scenario, 1 s windows, windows 2..{res['duration_s'] - 2} scored. "
         "Unit = (prefix, window). Thresholds are EXPERIMENTAL (the paper gives none). "
         "E1 = tau_ratio 5, tau_min = tau_rate 50 pps, fixed before running.", ""]
    for method in ("paper", "proposal", "proposal_hier", "ablation_rule_only", "ablation_agg_only"):
        L += [f"## E1 -- {method}", "",
              "| Scenario | TP | FP | TN | FN | Precision | Recall/DR | F1 | FPR | Abstained (with attack) | "
              "Window coverage | Ambiguous flags (mixed) | Host: identified / unresolved / missed / abstained | "
              "Host false ident. | Collateral benign host-windows |",
              "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for s in res["scenarios"]:
            m = s["E1"][method]
            h = m["host"]
            L.append(f"| {s['scenario']} | {m['TP']} | {m['FP']} | {m['TN']} | {m['FN']} | "
                     f"{f(m['precision'])} ({m['precision_den']}) | {f(m['recall_detection_rate'])} ({m['recall_den']}) | "
                     f"{f(m['f1'])} | {f(m['fpr'])} ({m['fpr_den']}) | {m['units_abstained']} ({m['abstained_units_with_attack']}) | "
                     f"{f(m['window_coverage'])} ({m['window_coverage_den']}) | {m['flagged_ambiguous_units']} "
                     f"({m['flagged_mixed_units']}) | {h['identified']} / {h['unresolved']} / {h['missed']} / "
                     f"{h['abstained']} | {h['false_identifications']} | {h['collateral_benign_host_windows']} |")
        L.append("")
    # Pooled sensitivity (sum of unit counts). D6 contributes 2850 of the attack
    # units, so pooled tables are shown with and without it.
    for method, label, excl in [(m, l, e) for e in (False, True)
                                for m, l in (("paper", "tau_rate"), ("proposal", "tau_min"),
                                             ("proposal_hier", "tau_min"))]:
        scope = "all scenarios except D6" if excl else "all scenarios (dominated by D6's 2850 attack units)"
        L += [f"## Threshold sensitivity, pooled over {scope} -- {method}", "",
              f"Cells: F1 / FPR / DR. Rows tau_ratio, columns {label} (pps).", "",
              "| tau_ratio | " + " | ".join(str(v) for v in res["volumes"]) + " |",
              "|---|" + "---|" * len(res["volumes"])]
        for r in res["ratios"]:
            cells = []
            for v in res["volumes"]:
                tp = fp = tn = fn = 0
                for s in res["scenarios"]:
                    if excl and s["scenario"].startswith("D6"):
                        continue
                    m = next(x[method] for x in s["sweep"] if x["ratio"] == r and x["min"] == v)
                    tp, fp, tn, fn = tp + m["TP"], fp + m["FP"], tn + m["TN"], fn + m["FN"]
                pr = tp / (tp + fp) if tp + fp else None
                rc = tp / (tp + fn) if tp + fn else None
                f1 = 2 * pr * rc / (pr + rc) if pr and rc else None
                cells.append(f"{f(f1)} / {f(fp / (fp + tn) if fp + tn else None)} / {f(rc)}")
            L.append(f"| {r} | " + " | ".join(cells) + " |")
        L.append("")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    sys.exit(main())

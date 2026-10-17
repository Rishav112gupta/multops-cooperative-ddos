#!/usr/bin/env python3
"""Controlled Click detection runs (Phase 5). Loopback only; no mitigation.

Usage: run_phase5_click.py /path/to/click/userlevel/click [results_dir]

Runs tests/click/phase5_detection.click three times:
  C1  THRESH 20, flood from 10.0.0.1      (paper Scenario 3 analogue, asymmetric routing)
  C2  THRESH 50, flood from 10.0.0.1      (granularity mismatch)
  C3  THRESH 50, flood from 192.168.1.66  (attacker shares the client's /24)
Ground truth is known by construction: all flows are constant for the whole
run; the flood source is the only attacker. Detection uses the experimental
thresholds E1 (tau_ratio 5, tau_min = tau_rate 50 pps). Live timing makes
these runs non-deterministic; the results file records what this run observed.
"""

import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))
from aggregator.aggregator import PaperAggregator, WindowedAggregator  # noqa: E402
from aggregator.detection import (CORRECTED, PAPER_LITERAL, CorrectedDetector,  # noqa: E402
                                  PaperDetector, would_mitigate)
from aggregator.telemetry_protocol import decode_v1  # noqa: E402
from aggregator.telemetry_receiver import TelemetryReceiver  # noqa: E402
from experiments.phase4.netsim import Truth  # noqa: E402
from experiments.phase5.evaluate import score  # noqa: E402
from experiments.phase5.run_phase5 import E1  # noqa: E402

RUNS = [("C1_cooperative", 20, "10.0.0.1"), ("C2_granularity", 50, "10.0.0.1"),
        ("C3_mixed_prefix", 50, "192.168.1.66")]


def run_click(click, thresh, atk):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.1)
    got, stop = [], threading.Event()

    def loop():
        while not stop.is_set():
            try:
                d, a = sock.recvfrom(65535)
                got.append((time.time(), d, f"{a[0]}:{a[1]}"))
            except socket.timeout:
                pass

    t = threading.Thread(target=loop)
    t.start()
    proc = subprocess.run([click, str(HERE / "phase5_detection.click"), f"PORT={sock.getsockname()[1]}",
                           f"THRESH={thresh}", f"ATK={atk}"], capture_output=True, text=True, timeout=60)
    time.sleep(0.5)
    stop.set()
    t.join()
    sock.close()
    return proc, got


def main():
    click = sys.argv[1]
    outdir = Path(sys.argv[2]) if len(sys.argv) > 2 else REPO / "build" / "click-logs"
    outdir.mkdir(parents=True, exist_ok=True)
    failures, lines, results = 0, [], {"thresholds_E1": vars(E1), "runs": []}

    def check(name, ok, detail=""):
        nonlocal failures
        failures += 0 if ok else 1
        s = f"[{'PASS' if ok else 'FAIL'}] {name} {detail}".rstrip()
        lines.append(s)
        print(s)

    for name, thresh, atk in RUNS:
        proc, got = run_click(click, thresh, atk)
        (outdir / f"phase5_{name}.out").write_text(proc.stdout + proc.stderr)
        check(f"{name}: click exited cleanly", proc.returncode == 0 and len(got) > 0,
              f"(rc={proc.returncode}, {len(got)} datagrams)")
        rx = TelemetryReceiver()
        prop = WindowedAggregator(1.0, expected_routers={1, 2}, align="sender", grace_s=0.5)
        paper = PaperAggregator(1.0, value="rate")
        for arrival, d, src in got:
            if decode_v1(d).header.router_id in (3, 4):
                paper.ingest(decode_v1(d).records, arrival)
            v = rx.process(d, src)
            if v.completed is not None and v.completed.router_id in (1, 2):
                prop.add_interval(v.completed, arrival)
        end = got[-1][0] + 10
        pw, paw = prop.finish(end), paper.finish(end)
        data = [w.index for w in pw if w.intervals]
        lo, hi = min(data) + 2, max(data)          # skip 2 warm-up windows and the last one
        rng = range(lo, hi)
        # Ground truth by construction: constant flows, one attacker.
        truth = Truth(1.0)
        for w in range(lo - 2, hi + 2):
            truth.fwd[w].update({atk: 2000, "192.168.1.1": 100})
            truth.atk_fwd[w].update({atk: 2000})
            truth.rev[w].update({"192.168.1.1": 30})
        pdec = [d for w in paw for d in PaperDetector(PAPER_LITERAL, E1).decide(w)]
        cdec = [d for w in pw for d in CorrectedDetector(CORRECTED, E1, 1.0).decide(w)]
        sp, sc = score(pdec, truth, 1, rng), score(cdec, truth, 0, rng)
        mitig = sorted({k for w in pw for k in would_mitigate(
            [d for d in cdec if d.window == w.index and d.window in rng])})
        results["runs"].append({"run": name, "thresh": thresh, "attacker": atk, "windows": [lo, hi],
                                "paper": sp, "proposal": sc,
                                "proposal_would_mitigate": [f"{p}/{l}" for p, l in mitig]})
        print(f"    {name}: paper TP/FP/TN/FN={sp['TP']}/{sp['FP']}/{sp['TN']}/{sp['FN']}  "
              f"proposal={sc['TP']}/{sc['FP']}/{sc['TN']}/{sc['FN']} abst={sc['units_abstained']}  "
              f"proposal would mitigate {results['runs'][-1]['proposal_would_mitigate']}")
        check(f"{name}: proposal detects the flood in every scored window", sc["FN"] == 0 and sc["TP"] > 0,
              f"(TP={sc['TP']}, windows={hi - lo})")
        if name == "C1_cooperative":
            check(f"{name}: no false positives in either method", sp["FP"] == 0 and sc["FP"] == 0)
        if name == "C2_granularity":
            check(f"{name}: paper method flags the benign client, proposal does not",
                  sp["FP"] > 0 and sc["FP"] == 0, f"(paper FP={sp['FP']}, proposal FP={sc['FP']})")
        if name == "C3_mixed_prefix":
            check(f"{name}: proposal marks the shared prefix ambiguous and reports collateral",
                  sc["flagged_ambiguous_units"] > 0 and sc["host"]["collateral_benign_host_windows"] > 0,
                  f"(ambiguous={sc['flagged_ambiguous_units']}, "
                  f"collateral={sc['host']['collateral_benign_host_windows']})")
    (outdir / "phase5_click_results.json").write_text(json.dumps(results, indent=1, sort_keys=True) + "\n")
    (outdir / "phase5_click.check").write_text("\n".join(lines) + "\n")
    print(f"\n{failures} check(s) failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

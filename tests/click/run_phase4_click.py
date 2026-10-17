#!/usr/bin/env python3
"""Run tests/click/phase4_two_routers.click and aggregate its live telemetry.

Usage: run_phase4_click.py /path/to/click/userlevel/click [logdir]

Checks (loopback only):
  * proposal (routers 1+2, PARTITION, sender alignment): totals equal Click
    Counter totals exactly; every complete window has both directions for the
    client; per-window client request/reply ratio within 15% of 100/30.
  * paper aggregator (routers 3+4, ALL, arrival windows, rates): report how
    many windows contain a one-sided key covering the client (Algorithm 2
    would compute Ratio = infinity there).
Exit status 0 iff all checks pass.
"""

import ipaddress
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
from aggregator.aggregator import PaperAggregator, WindowedAggregator  # noqa: E402
from aggregator.telemetry_protocol import decode_v1  # noqa: E402
from aggregator.telemetry_receiver import TelemetryReceiver  # noqa: E402

CLIENT = "192.168.1.1"


def main():
    click = sys.argv[1]
    logdir = Path(sys.argv[2] if len(sys.argv) > 2 else HERE.parents[1] / "build" / "click-logs")
    logdir.mkdir(parents=True, exist_ok=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.1)
    got, stop = [], threading.Event()

    def rx_loop():
        while not stop.is_set():
            try:
                d, a = sock.recvfrom(65535)
                got.append((time.time(), d, f"{a[0]}:{a[1]}"))
            except socket.timeout:
                pass

    t = threading.Thread(target=rx_loop)
    t.start()
    proc = subprocess.run([click, str(HERE / "phase4_two_routers.click"), f"PORT={sock.getsockname()[1]}"],
                          capture_output=True, text=True, timeout=60)
    time.sleep(0.5)
    stop.set()
    t.join()
    sock.close()
    (logdir / "phase4_click.out").write_text(proc.stdout + proc.stderr)

    failures = 0
    lines = []

    def check(name, ok, detail=""):
        nonlocal failures
        failures += 0 if ok else 1
        s = f"[{'PASS' if ok else 'FAIL'}] {name} {detail}".rstrip()
        lines.append(s)
        print(s)

    check("click exited cleanly", proc.returncode == 0, f"(rc={proc.returncode})")
    out = proc.stdout + proc.stderr
    counts = out.split("=== counts")[1].split("=== end")[0].split()
    cA, cH, cR = (int(x) for x in counts[:3])
    print(f"    ground truth: flood={cA} requests={cH} replies={cR}")

    rx = TelemetryReceiver()
    prop = WindowedAggregator(1.0, expected_routers={1, 2}, align="sender", grace_s=0.5)
    paper = PaperAggregator(1.0, value="rate", start_s=float(int(got[0][0])) if got else 0.0)
    for arrival, d, src in got:
        h = decode_v1(d).header
        if h.router_id in (3, 4):
            paper.ingest(decode_v1(d).records, arrival)
        v = rx.process(d, src)
        if v.completed is not None and v.completed.router_id in (1, 2):
            prop.add_interval(v.completed, arrival)
    end = (got[-1][0] if got else 0) + 10
    pw = prop.finish(end)
    paw = paper.finish(end)
    summ = rx.summary()
    check("all datagrams accepted, none missing",
          all(s["missing_estimate"] == 0 and s["duplicates"] == 0 for s in summ["streams"])
          and not summ["malformed"], f"({len(got)} datagrams)")

    tot_f = sum(n.fwd for w in pw for k, n in w.nodes.items() if k[1] == 8)
    tot_r = sum(n.rev for w in pw for k, n in w.nodes.items() if k[1] == 8)
    check("proposal totals == Click counters (fwd = flood + requests, rev = replies)",
          (tot_f, tot_r) == (cA + cH, cR), f"({tot_f}, {tot_r}) vs ({cA + cH}, {cR})")

    complete = [w for w in pw if w.complete and w.finest_exact(CLIENT)]
    inner = complete[1:-1]       # first/last windows hold partial intervals
    one_sided = ratios = 0
    bad = []
    for w in inner:
        (k, n) = w.finest_exact(CLIENT)
        if n.fwd > 0 and n.rev == 0:
            one_sided += 1
        if n.rev:
            r = n.fwd / n.rev
            ratios += 1
            if abs(r - 100 / 30) / (100 / 30) > 0.15:
                bad.append((w.index, k, n.fwd, n.rev))
    levels = sorted({w.finest_exact(CLIENT)[0][1] for w in inner})
    check("proposal: no one-sided client windows", one_sided == 0 and len(inner) >= 4,
          f"({len(inner)} inner complete windows, exact levels used {levels})")
    check("proposal: client request/reply ratio within 15% of 100/30 in every inner window",
          not bad and ratios == len(inner), f"(outliers {bad})")

    cnet = ipaddress.IPv4Address(CLIENT)
    p_one = 0
    p_scored = 0
    for w in paw[1:-1]:
        keys = {k: v for k, v in w.state.items() if cnet in ipaddress.IPv4Network(f"{k[0]}/{k[1]}")}
        if not keys:
            continue
        p_scored += 1
        if any(v[0] > 0 and v[1] == 0 for v in keys.values()):
            p_one += 1
    example = next((sorted(w.state.items()) for w in paw[1:-1] if w.state), [])
    example = [(k, v) for k, v in example if cnet in ipaddress.IPv4Network(f"{k[0]}/{k[1]}")]
    print(f"    paper aggregator: {p_one}/{p_scored} inner windows contain a one-sided key covering "
          f"the client; example window keys: {example}")
    check("paper aggregator: one-sided client keys observed (granularity mismatch reproduced live)",
          p_one > 0, f"({p_one}/{p_scored})")
    (logdir / "phase4_click.check").write_text("\n".join(lines) + "\n")
    print(f"\n{failures} check(s) failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Run tests/click/phase3_telemetry.click and check the telemetry it exports.

Usage: run_phase3_click.py /path/to/click/userlevel/click [logdir]

Binds two UDP sockets on 127.0.0.1 (ephemeral ports), runs Click with them,
receives everything, and checks: datagram validity, sequencing, interval
completeness, count coverage per export mode against Click Counter elements,
and the fwd/rev (to_rate/from_rate) direction mapping. Prints one line per
check and writes the raw evidence to logdir. Exit status 0 iff all pass.
"""

import ipaddress
import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
from aggregator.telemetry_protocol import decode_paper  # noqa: E402
from aggregator.telemetry_receiver import TelemetryReceiver  # noqa: E402


def collect(sock, sink, stop):
    sock.settimeout(0.1)
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(65535)
            sink.append((time.monotonic(), data, f"{addr[0]}:{addr[1]}"))
        except socket.timeout:
            pass


def sections(text):
    out, cur = {}, None
    for line in text.splitlines():
        if line.startswith("=== "):
            cur = line[4:].strip()
            out[cur] = []
        elif cur and line.strip():
            out[cur].append(line.strip())
    return out


def within(prefix, plen, net):
    return plen >= net.prefixlen and ipaddress.IPv4Address(prefix) in net


def sums(intervals, net):
    fwd = sum(r.fwd_count for iv in intervals for r in iv.records if within(r.prefix, r.prefix_len, net))
    rev = sum(r.rev_count for iv in intervals for r in iv.records if within(r.prefix, r.prefix_len, net))
    return fwd, rev


def main():
    click = sys.argv[1]
    logdir = Path(sys.argv[2] if len(sys.argv) > 2 else HERE.parents[1] / "build" / "click-logs")
    logdir.mkdir(parents=True, exist_ok=True)

    socks = []
    for _ in range(2):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        s.bind(("127.0.0.1", 0))
        socks.append(s)
    v1_rx, paper_rx, stop = [], [], threading.Event()
    threads = [threading.Thread(target=collect, args=(socks[0], v1_rx, stop)),
               threading.Thread(target=collect, args=(socks[1], paper_rx, stop))]
    for t in threads:
        t.start()
    proc = subprocess.run([click, str(HERE / "phase3_telemetry.click"),
                           f"PORT={socks[0].getsockname()[1]}", f"PPORT={socks[1].getsockname()[1]}"],
                          capture_output=True, text=True, timeout=60)
    time.sleep(0.5)
    stop.set()
    for t in threads:
        t.join()
    for s in socks:
        s.close()
    (logdir / "phase3_click.out").write_text(proc.stdout + proc.stderr)

    failures = 0
    results = []

    def check(name, ok, detail=""):
        nonlocal failures
        failures += 0 if ok else 1
        line = f"[{'PASS' if ok else 'FAIL'}] {name} {detail}".rstrip()
        results.append(line)
        print(line)

    check("click exited cleanly", proc.returncode == 0, f"(rc={proc.returncode})")
    sec = sections(proc.stdout + proc.stderr)
    if "counts" not in sec:
        print(proc.stdout + proc.stderr)
        return 1
    cA, cH, cR, cC = (int(x) for x in sec["counts"][:4])
    tx = [int(x) for x in sec["tx"][:5]]
    tx_bytes = [int(x) for x in sec["tx_bytes"][:5]]
    tx_fail = [int(x) for x in sec["tx_failures"][:5]]
    print(f"    ground truth: A={cA} H={cH} R={cR} C={cC}; tx={tx}; tx_bytes={tx_bytes}")

    intervals = {}
    rx = TelemetryReceiver(on_interval=lambda iv: intervals.setdefault(iv.router_id, []).append(iv))
    verdicts = [rx.process(d, src).status for _, d, src in v1_rx]
    rx.expire_pending(0.0)
    summary = rx.summary()
    with open(logdir / "phase3_click_rx.jsonl", "w") as f:
        for rid, ivs in sorted(intervals.items()):
            for iv in ivs:
                f.write(json.dumps({"router_id": rid, "interval_id": iv.interval_id,
                                    "interval_ms": iv.interval_ms, "timestamp_us": iv.timestamp_us,
                                    "records": [r.__dict__ for r in iv.records]}) + "\n")
        f.write(json.dumps({"summary": summary}) + "\n")

    check("no local send failures", tx_fail == [0] * 5, str(tx_fail))
    check("every V1 datagram valid and new", set(verdicts) == {"accepted"} and not summary["malformed"],
          f"({len(verdicts)} datagrams, malformed={summary['malformed']})")
    check("received == sent per V1 router", sorted(
        (s["router_id"], s["accepted"]) for s in summary["streams"]) == [(i + 1, tx[i]) for i in range(4)],
        str([(s["router_id"], s["accepted"]) for s in summary["streams"]]))
    for s in summary["streams"]:
        check(f"router {s['router_id']}: no gaps, all intervals complete",
              s["missing_estimate"] == 0 and s["intervals_incomplete"] == 0
              and s["intervals_inconsistent"] == 0,
              f"(intervals={s['intervals_complete']}, boot={s['boot_id']})")
    for rid, ivs in intervals.items():
        ids = [iv.interval_id for iv in ivs]
        check(f"router {rid}: interval ids contiguous from 0", ids == list(range(len(ids))), f"(n={len(ids)})")

    everything = ipaddress.IPv4Network("0.0.0.0/0")
    truth_fwd, truth_rev = cA + cH, cR + cC
    cov = {}
    for rid, name in ((1, "PARTITION"), (2, "LEAVES"), (3, "ALL")):
        f, r = sums(intervals[rid], everything)
        unc = sum(iv.uncounted_fwd + iv.uncounted_rev for iv in intervals[rid])
        cov[name] = (f, r, unc)
        print(f"    coverage {name}: fwd {f} / truth {truth_fwd}, rev {r} / truth {truth_rev}, uncounted {unc}")
    check("PARTITION counts == ground truth exactly", cov["PARTITION"] == (truth_fwd, truth_rev, 0))
    check("LEAVES counts < ground truth (traffic before expansion is missing)",
          cov["LEAVES"][0] < truth_fwd, f"(missing fwd {truth_fwd - cov['LEAVES'][0]})")
    check("ALL counts > ground truth (nested records overlap)", cov["ALL"][0] > truth_fwd,
          f"(x{cov['ALL'][0] / truth_fwd:.2f})")

    net = ipaddress.IPv4Network
    # Checked at /8: each test flow owns a whole /8, and in PARTITION mode part
    # of a host's traffic can sit in a coarser RESIDUAL record (counted before
    # the finer level existed), so finer-prefix sums are not exact (see report).
    p = intervals[1]          # request path on input 0, reply path on input 1
    check("mapping: 192/8 fwd == H (sent by the host), rev == R (received by the host)",
          sums(p, net("192.0.0.0/8")) == (cH, cR), f"{sums(p, net('192.0.0.0/8'))} vs {(cH, cR)}")
    check("mapping: 10/8 fwd == A only, rev == 0 (server 10.9.9.9 never keyed)",
          sums(p, net("10.0.0.0/8")) == (cA, 0), f"{sums(p, net('10.0.0.0/8'))} vs {(cA, 0)}")
    check("mapping: 172/8 rev == C, fwd == 0", sums(p, net("172.0.0.0/8")) == (0, cC),
          f"{sums(p, net('172.0.0.0/8'))} vs {(0, cC)}")
    check("mapping: no 18/8 or 10.9/16 records on router 1",
          sums(p, net("18.0.0.0/8")) == (0, 0) and not any(
              within(r.prefix, r.prefix_len, net("10.9.0.0/16")) for iv in p for r in iv.records))
    fine = sums(p, net("192.168.0.0/16"))
    print(f"    granularity: 192.168.0.0/16 alone holds {fine} of {(cH, cR)}; the rest is in the "
          f"192.0.0.0/8 residual")
    s4 = intervals[4]         # inputs swapped: the same packets map to other addresses
    check("swapped wiring: 10/8 fwd == R, rev == H; 18/8 rev == A; 192/8 empty; 172/8 fwd == C",
          sums(s4, net("10.0.0.0/8")) == (cR, cH) and sums(s4, net("18.0.0.0/8")) == (0, cA)
          and sums(s4, net("192.0.0.0/8")) == (0, 0) and sums(s4, net("172.0.0.0/8")) == (cC, 0),
          f"10/8={sums(s4, net('10.0.0.0/8'))} 18/8={sums(s4, net('18.0.0.0/8'))} "
          f"192/8={sums(s4, net('192.0.0.0/8'))} 172/8={sums(s4, net('172.0.0.0/8'))}")

    # Rates for the session host at a steady point (interval ending ~4 s into the run).
    steady = [iv for iv in p if 3.5e6 <= iv.timestamp_us - p[0].timestamp_us <= 5.0e6]
    host = [r for iv in steady for r in iv.records if r.prefix == "192.168.1.1" and r.prefix_len == 32]
    if host:
        fr, rr = host[-1].fwd_rate, host[-1].rev_rate
        check("rates: 192.168.1.1 fwd_rate ~100 pps, rev_rate ~30 pps (+-20%)",
              80 <= fr <= 120 and 24 <= rr <= 36, f"(fwd_rate={fr}, rev_rate={rr})")
    else:
        check("rates: 192.168.1.1/32 record present at steady state", False)

    # Paper-format exporter: same packets, rates only.
    paper = []
    for _, d, _ in paper_rx:
        paper.extend(decode_paper(d)[1])
    check("paper format: all datagrams decode; datagrams == tx", len(paper_rx) == tx[4],
          f"({len(paper_rx)} vs {tx[4]})")
    ph = [r for r in paper if r.prefix == "192.168.1.1" and r.prefix_len == 32]
    check("paper format: 192.168.1.1 to_rate > from_rate > 0 (to=fwd, from=rev)",
          bool(ph) and ph[-2].to_rate > ph[-2].from_rate > 0 if len(ph) >= 2 else False,
          f"(last steady record to={ph[-2].to_rate if len(ph) >= 2 else None}, "
          f"from={ph[-2].from_rate if len(ph) >= 2 else None})")

    # Telemetry volume (informational: this run only, loopback, 0.5 s intervals).
    duration_s = 6.0
    for i, name in enumerate(("PARTITION", "LEAVES", "ALL", "PARTITION-swapped", "PAPER")):
        print(f"    telemetry volume {name}: {tx[i]} datagrams, {tx_bytes[i]} bytes "
              f"(~{tx_bytes[i] / duration_s:.0f} B/s)")

    (logdir / "phase3_click.check").write_text("\n".join(results) + "\n")
    print(f"\n{failures} check(s) failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

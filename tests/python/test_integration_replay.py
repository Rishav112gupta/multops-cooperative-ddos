"""Integration: C++ multops_replay --send  ->  UDP (127.0.0.1)  ->  Python receiver.

Needs MULTOPS_BUILD_DIR (set by CTest) pointing at a build with multops_replay.
All traffic stays on the loopback interface.
"""

import csv
import io
import os
import random
import socket
import subprocess
import unittest
from collections import Counter
from pathlib import Path

from aggregator.telemetry_protocol import decode_paper, decode_v1
from aggregator.telemetry_receiver import ACCEPTED, DUPLICATE, REORDERED, TelemetryReceiver

REPO = Path(__file__).resolve().parents[2]
TRACE = REPO / "tests" / "data" / "sample_trace.csv"


def replay_binary():
    build = os.environ.get("MULTOPS_BUILD_DIR")
    exe = Path(build) / "multops_replay" if build else None
    return exe if exe and exe.exists() else None


def bound_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    s.bind(("127.0.0.1", 0))
    s.settimeout(0.5)
    return s


def drain(sock):
    out = []
    while True:
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            return out
        out.append((data, f"{addr[0]}:{addr[1]}"))


def run_replay(exe, port, *extra):
    cmd = [str(exe), "--thresh", "100", "--send", f"127.0.0.1:{port}", *extra, str(TRACE)]
    p = subprocess.run(cmd, check=True, capture_output=True, text=True)
    rows = list(csv.DictReader(io.StringIO(p.stdout)))
    return rows, p.stderr


def trace_totals():
    fwd = rev = 0
    for line in TRACE.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        _, d, _, v = line.split(",")
        if d == "F":
            fwd += int(v)
        else:
            rev += int(v)
    return fwd, rev


@unittest.skipUnless(replay_binary(), "MULTOPS_BUILD_DIR/multops_replay not available")
class ReplayIntegrationTests(unittest.TestCase):
    def test_v1_partition_matches_tool_output_and_covers_all_traffic(self):
        sock = bound_socket()
        try:
            rows, err = run_replay(replay_binary(), sock.getsockname()[1], "--mode", "partition",
                                   "--interval-ms", "500", "--router-id", "7", "--boot-id", "11")
            datagrams = drain(sock)
        finally:
            sock.close()
        self.assertIn("send_failures=0", err)
        intervals = []
        rx = TelemetryReceiver(on_interval=intervals.append)
        verdicts = [rx.process(d, src).status for d, src in datagrams]
        self.assertEqual(set(verdicts), {ACCEPTED})

        # Records received == records the tool printed, interval by interval.
        expected = {}
        for r in rows:
            expected.setdefault(int(r["interval_end_ms"]), []).append(
                (r["prefix"], int(r["len"]), int(r["leaf"]), int(r["residual"]), int(r["fwd_rate"]),
                 int(r["rev_rate"]), int(r["fwd_count"]), int(r["rev_count"])))
        got = {}
        for iv in intervals:
            self.assertEqual((iv.router_id, iv.boot_id, iv.export_mode), (7, 11, "PARTITION"))
            got[iv.timestamp_us // 1000] = [
                (r.prefix, r.prefix_len, int(r.is_leaf), int(r.is_residual), r.fwd_rate, r.rev_rate,
                 r.fwd_count, r.rev_count) for r in iv.records]
        # Intervals with no records are sent as empty datagrams but print no CSV rows.
        self.assertEqual({k: v for k, v in got.items() if v}, expected)
        self.assertEqual([iv.interval_id for iv in intervals], list(range(len(intervals))))

        # Coverage: partition counts over all intervals == every unit in the trace.
        fwd = sum(r.fwd_count for iv in intervals for r in iv.records)
        rev = sum(r.rev_count for iv in intervals for r in iv.records)
        unc = sum(iv.uncounted_fwd + iv.uncounted_rev for iv in intervals)
        self.assertEqual((fwd, rev, unc), (*trace_totals(), 0))

    def test_paper_format_carries_rates_only(self):
        sock = bound_socket()
        try:
            rows, _ = run_replay(replay_binary(), sock.getsockname()[1], "--mode", "leaves",
                                 "--format", "paper")
            datagrams = drain(sock)
        finally:
            sock.close()
        recs = [r for d, _ in datagrams for r in decode_paper(d)[1]]
        self.assertEqual([(r.prefix, r.prefix_len, r.to_rate, r.from_rate) for r in recs],
                         [(r["prefix"], int(r["len"]), int(r["fwd_rate"]), int(r["rev_rate"]))
                          for r in rows])

    def test_fault_injection_relay(self):
        """Drop / duplicate / reorder datagrams deterministically; the receiver's
        classification must match exactly what the relay did."""
        relay = bound_socket()
        try:
            run_replay(replay_binary(), relay.getsockname()[1], "--mode", "partition",
                       "--interval-ms", "100", "--max-payload", "200", "--router-id", "3")
            original = drain(relay)
        finally:
            relay.close()
        self.assertGreater(len(original), 25)
        seqs = [decode_v1(d).header.sequence for d, _ in original]
        self.assertEqual(sorted(seqs), list(range(len(seqs))))

        rng = random.Random(2026)
        out, dropped, duplicated = [], set(), 0
        for d, _ in original:
            r = rng.random()
            if r < 0.10:
                dropped.add(decode_v1(d).header.sequence)
                continue
            out.append(d)
            if r < 0.18:
                out.append(d)
                duplicated += 1
        swaps = 0
        for i in range(0, len(out) - 1, 9):     # swap pairs with different sequence numbers
            a, b = decode_v1(out[i]).header.sequence, decode_v1(out[i + 1]).header.sequence
            if a < b:
                out[i], out[i + 1] = out[i + 1], out[i]
                swaps += 1

        # Ground truth from the delivered order alone.
        # Independent oracle (not the receiver's SequenceTracker): first sighting
        # above every earlier one = accepted, below = reordered, seen = duplicate.
        truth, seen, top = Counter(), set(), -1
        for d in out:
            q = decode_v1(d).header.sequence
            if q in seen:
                truth[DUPLICATE] += 1
            elif q > top:
                truth[ACCEPTED] += 1
            else:
                truth[REORDERED] += 1
            seen.add(q)
            top = max(top, q)

        rx_sock = bound_socket()
        tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for d in out:
                tx_sock.sendto(d, rx_sock.getsockname())
            delivered = drain(rx_sock)
        finally:
            tx_sock.close()
            rx_sock.close()
        self.assertEqual(len(delivered), len(out), "loopback lost datagrams; rerun")
        intervals = []
        rx = TelemetryReceiver(on_interval=intervals.append)
        got = Counter(rx.process(d, s).status for d, s in delivered)
        rx.expire_pending(0.0)

        self.assertEqual(got, truth)
        self.assertEqual(got[DUPLICATE], duplicated)
        self.assertGreater(got[REORDERED], 0)
        st = rx.summary()["streams"][0]
        # Missing estimate == dropped sequence numbers inside the observed range.
        lo, hi = st["first_seq"], st["highest_seq"]
        self.assertEqual(st["missing_estimate"], len([s for s in dropped if lo <= s <= hi]))
        # Every interval that lost a fragment is incomplete; none is delivered partially.
        lost_intervals = {decode_v1(d).header.interval_id for d, _ in original
                          if decode_v1(d).header.sequence in dropped}
        delivered_ids = {iv.interval_id for iv in intervals}
        self.assertFalse(lost_intervals & delivered_ids)
        self.assertEqual(st["intervals_incomplete"],
                         len({decode_v1(d).header.interval_id for d in out} & lost_intervals))
        self.assertEqual(st["intervals_complete"], len(delivered_ids))


if __name__ == "__main__":
    unittest.main()

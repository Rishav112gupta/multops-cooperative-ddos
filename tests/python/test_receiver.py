"""Receiver state-machine tests: duplicates, reordering, loss, restarts, fragments, malformed input."""

import unittest

from aggregator.telemetry_protocol import HeaderV1, PaperRecord, RecordV1, encode_paper, encode_v1
from aggregator.telemetry_receiver import (ACCEPTED, DUPLICATE, MALFORMED, REORDERED, STALE,
                                           SequenceTracker, TelemetryReceiver)


def dg(router=1, boot=100, seq=0, interval=0, fidx=0, fcnt=1, records=None, ts=0, interval_ms=1000):
    records = records if records is not None else [RecordV1("10.0.0.1", 32, 1, 5, 0, 50, 0)]
    h = HeaderV1("PARTITION", 0, router, boot, seq, interval, fidx, fcnt, ts, interval_ms,
                 len(records), 0, 0, 0)
    return encode_v1(h, records)


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class SequenceTrackerTests(unittest.TestCase):
    def test_classification_and_missing(self):
        t = SequenceTracker(window=8)
        self.assertEqual([t.observe(s) for s in (0, 1, 3, 2, 3, 6)],
                         [ACCEPTED, ACCEPTED, ACCEPTED, REORDERED, DUPLICATE, ACCEPTED])
        self.assertEqual(t.missing(), 2)          # 4 and 5
        self.assertEqual(t.observe(20), ACCEPTED)
        self.assertEqual(t.observe(5), STALE)     # 5 <= 20 - 8: cannot tell new from duplicate
        self.assertEqual(t.observe(15), REORDERED)

    def test_window_pruning_keeps_detection(self):
        t = SequenceTracker(window=16)
        for s in range(1000):
            t.observe(s)
        self.assertLessEqual(len(t.seen), 33)
        self.assertEqual(t.observe(995), DUPLICATE)
        self.assertEqual(t.missing(), 0)


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.got = []
        self.rx = TelemetryReceiver(on_interval=self.got.append, clock=self.clock)

    def test_in_order_single_fragment_intervals(self):
        for i in range(3):
            v = self.rx.process(dg(seq=i, interval=i))
            self.assertEqual(v.status, ACCEPTED)
            self.assertIsNotNone(v.completed)
        self.assertEqual([iv.interval_id for iv in self.got], [0, 1, 2])
        s = self.rx.summary()["streams"][0]
        self.assertEqual((s["accepted"], s["missing_estimate"], s["intervals_complete"]), (3, 0, 3))

    def test_duplicate_is_rejected_and_not_double_counted(self):
        d = dg(seq=0)
        self.assertEqual(self.rx.process(d).status, ACCEPTED)
        self.assertEqual(self.rx.process(d).status, DUPLICATE)
        self.assertEqual(len(self.got), 1)
        self.assertEqual(self.rx.summary()["streams"][0]["duplicates"], 1)

    def test_loss_and_reordering(self):
        for s in (0, 1, 4, 2):           # 3 lost, 2 late
            self.rx.process(dg(seq=s, interval=s))
        st = self.rx.summary()["streams"][0]
        self.assertEqual(st["accepted"], 3)
        self.assertEqual(st["reordered"], 1)
        self.assertEqual(st["missing_estimate"], 1)
        self.assertEqual(sorted(iv.interval_id for iv in self.got), [0, 1, 2, 4])

    def test_fragments_reassemble_in_any_order(self):
        recs = [RecordV1(f"10.0.0.{i}", 32, 1, i, 0, i, 0) for i in range(6)]
        parts = [dg(seq=10 + k, interval=5, fidx=k, fcnt=3, records=recs[2 * k:2 * k + 2]) for k in range(3)]
        self.assertIsNone(self.rx.process(parts[2]).completed)
        self.assertIsNone(self.rx.process(parts[0]).completed)
        iv = self.rx.process(parts[1]).completed
        self.assertIsNotNone(iv)
        self.assertEqual([r.prefix for r in iv.records], [r.prefix for r in recs])   # fragment order

    def test_lost_fragment_leaves_interval_incomplete(self):
        self.rx.process(dg(seq=0, interval=0, fidx=0, fcnt=2))
        self.assertEqual(self.got, [])
        self.clock.t = 5.0
        self.assertEqual(self.rx.expire_pending(2.0), 1)
        self.assertEqual(self.rx.summary()["streams"][0]["intervals_incomplete"], 1)
        # A late fragment of an expired interval is not merged.
        self.assertIsNone(self.rx.process(dg(seq=1, interval=0, fidx=1, fcnt=2)).completed)

    def test_inconsistent_fragments_are_not_delivered(self):
        self.rx.process(dg(seq=0, interval=0, fidx=0, fcnt=2, ts=1))
        self.rx.process(dg(seq=1, interval=0, fidx=1, fcnt=2, ts=2))   # different timestamp
        self.assertEqual(self.got, [])
        self.assertEqual(self.rx.summary()["streams"][0]["intervals_inconsistent"], 1)

    def test_new_sequence_for_completed_interval_is_flagged(self):
        self.rx.process(dg(seq=0, interval=0))
        self.rx.process(dg(seq=1, interval=0))
        self.assertEqual(len(self.got), 1)
        self.assertEqual(self.rx.summary()["streams"][0]["intervals_inconsistent"], 1)

    def test_restart_starts_new_stream(self):
        self.rx.process(dg(boot=100, seq=50))
        v = self.rx.process(dg(boot=200, seq=0))           # sequence restarted at 0
        self.assertTrue(v.restart)
        self.assertEqual(v.status, ACCEPTED)                # not "stale" or "duplicate"
        self.assertEqual(self.rx.restarts, 1)
        self.assertEqual(len(self.rx.streams), 2)

    def test_routers_are_independent(self):
        self.rx.process(dg(router=1, seq=0))
        self.assertEqual(self.rx.process(dg(router=2, seq=0)).status, ACCEPTED)

    def test_source_address_change_is_counted(self):
        self.rx.process(dg(seq=0), source="127.0.0.1:1000")
        self.rx.process(dg(seq=1, interval=1), source="127.0.0.1:2000")
        self.assertEqual(self.rx.summary()["streams"][0]["source_changes"], 1)

    def test_malformed_counted_by_code(self):
        good = dg()
        self.assertEqual(self.rx.process(good[:10]).status, MALFORMED)
        self.assertEqual(self.rx.process(b"\x00" * 80).error, "bad_magic")
        self.assertEqual(self.rx.process(good + b"\x00").error, "length_mismatch")
        self.assertEqual(self.rx.summary()["malformed"],
                         {"too_short": 1, "bad_magic": 1, "length_mismatch": 1})
        self.assertEqual(self.rx.streams, {})              # malformed input creates no state

    def test_paper_format_cannot_detect_duplicates(self):
        rx = TelemetryReceiver("PAPER")
        d = encode_paper([PaperRecord("10.0.0.1", 32, 9998, 0)])
        self.assertEqual(rx.process(d).status, ACCEPTED)
        self.assertEqual(rx.process(d).status, ACCEPTED)   # indistinguishable from a new report
        self.assertEqual(len(rx.paper_records), 2)
        self.assertEqual(rx.process(b"\x00\x00").status, MALFORMED)


if __name__ == "__main__":
    unittest.main()

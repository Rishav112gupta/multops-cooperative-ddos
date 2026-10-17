"""Unit tests for the Phase 4 aggregators on hand-built telemetry."""

import unittest

from aggregator.aggregator import (PaperAggregator, RouterRole, WindowedAggregator, covers, mask)
from aggregator.telemetry_protocol import PaperRecord, RecordV1
from aggregator.telemetry_receiver import Interval


def rec(prefix, plen, fc=0, rc=0, fr=0, rr=0, flags=1):
    return RecordV1(prefix, plen, flags, fr, rr, fc, rc)


def iv(router, end_s, records, interval_ms=1000, interval_id=0, unc=(0, 0)):
    return Interval(router, 1, interval_id, "PARTITION", 0, int(end_s * 1e6), interval_ms,
                    unc[0], unc[1], 1, records, 0.0)


class HelperTests(unittest.TestCase):
    def test_mask_and_covers(self):
        self.assertEqual(mask("192.168.1.1", 8), "192.0.0.0")
        self.assertTrue(covers(("192.0.0.0", 8), ("192.168.1.1", 32)))
        self.assertFalse(covers(("10.0.0.0", 8), ("192.168.1.1", 32)))
        self.assertFalse(covers(("192.168.1.1", 32), ("192.0.0.0", 8)))


class PaperAggregatorTests(unittest.TestCase):
    def test_paper_example_sec_4_3(self):
        # Paper: R1 sends (B, 1000, 10), R2 sends (B, 10, 1000) -> (1010, 1010).
        agg = PaperAggregator(period_s=1.0)
        agg.ingest([PaperRecord("10.1.0.0", 16, 1000, 10)], 0.2)
        agg.ingest([PaperRecord("10.1.0.0", 16, 10, 1000)], 0.3)
        w = agg.finish(1.0)
        self.assertEqual(w[0].state[("10.1.0.0", 16)], [1010, 1010])

    def test_state_resets_each_period_and_windows_follow_arrival(self):
        agg = PaperAggregator(period_s=1.0)
        agg.ingest([PaperRecord("10.0.0.0", 8, 5, 0)], 0.5)
        agg.ingest([PaperRecord("10.0.0.0", 8, 7, 0)], 2.5)   # window 1 empty
        w = agg.finish(3.0)
        self.assertEqual([x.state for x in w],
                         [{("10.0.0.0", 8): [5, 0]}, {}, {("10.0.0.0", 8): [7, 0]}])

    def test_rates_summed_over_time_inflate(self):
        # A router reporting every 0.5 s lands twice in a 1 s analysis period.
        agg = PaperAggregator(period_s=1.0)
        agg.ingest([PaperRecord("192.0.0.0", 8, 100, 0)], 0.5)
        agg.ingest([PaperRecord("192.0.0.0", 8, 100, 0)], 1.0 - 1e-9)
        self.assertEqual(agg.finish(1.0)[0].state[("192.0.0.0", 8)], [200, 0])

    def test_no_deduplication(self):
        agg = PaperAggregator(period_s=1.0)
        d = [PaperRecord("192.0.0.0", 8, 100, 30)]
        agg.ingest(d, 0.1)
        agg.ingest(d, 0.1)                  # the same datagram again
        self.assertEqual(agg.finish(1.0)[0].state[("192.0.0.0", 8)], [200, 60])

    def test_count_mode(self):
        agg = PaperAggregator(period_s=1.0, value="count")
        agg.ingest([rec("192.0.0.0", 8, fc=100, rc=30, fr=99, rr=28)], 0.1)
        self.assertEqual(agg.finish(1.0)[0].state[("192.0.0.0", 8)], [100, 30])


class WindowedAggregatorTests(unittest.TestCase):
    def test_asymmetric_views_fuse_exactly(self):
        agg = WindowedAggregator(1.0, expected_routers={1, 2})
        agg.add_interval(iv(1, 1.0, [rec("192.168.1.1", 32, fc=100)]), 1.01)
        agg.add_interval(iv(2, 1.0, [rec("192.168.1.1", 32, rc=30)]), 1.02)
        w = agg.finish(10)[0]
        self.assertTrue(w.complete)
        key, node = w.finest_exact("192.168.1.1")
        self.assertEqual((key, node.fwd, node.rev, node.exact), (("192.168.1.1", 32), 100, 30, True))

    def test_granularity_mismatch_falls_back_to_exact_level(self):
        # Router 1 expanded the client to /32; router 2 only has a /8 leaf.
        agg = WindowedAggregator(1.0, expected_routers={1, 2})
        agg.add_interval(iv(1, 1.0, [rec("192.168.1.1", 32, fc=95),
                                     rec("192.0.0.0", 8, fc=5, flags=2)]), 1.01)
        agg.add_interval(iv(2, 1.0, [rec("192.0.0.0", 8, rc=30)]), 1.01)
        w = agg.finish(10)[0]
        self.assertFalse(w.nodes[("192.168.1.1", 32)].exact)        # /8 records cover it
        key, node = w.finest_exact("192.168.1.1")
        self.assertEqual((key, node.fwd, node.rev), (("192.0.0.0", 8), 100, 30))

    def test_missing_router_marks_window_incomplete(self):
        agg = WindowedAggregator(1.0, expected_routers={1, 2})
        agg.add_interval(iv(1, 1.0, [rec("192.0.0.0", 8, fc=100)]), 1.01)
        w = agg.finish(10)[0]
        self.assertFalse(w.complete)
        self.assertEqual(w.missing_routers, {2})

    def test_sub_window_intervals_add_up(self):
        agg = WindowedAggregator(1.0, expected_routers={1})
        agg.add_interval(iv(1, 0.5, [rec("10.0.0.0", 8, fc=40)], interval_ms=500), 0.51)
        agg.add_interval(iv(1, 1.0, [rec("10.0.0.0", 8, fc=60)], interval_ms=500, interval_id=1), 1.01)
        w = agg.finish(10)[0]
        self.assertEqual(w.nodes[("10.0.0.0", 8)].fwd, 100)
        self.assertEqual(w.intervals, 2)

    def test_sender_vs_arrival_alignment(self):
        # Interval [0,1) in the router's clock arrives late, at t = 1.7.
        late = iv(1, 1.0, [rec("10.0.0.0", 8, fc=10)])
        s = WindowedAggregator(1.0, align="sender", grace_s=1.0)
        s.add_interval(late, 1.7)
        a = WindowedAggregator(1.0, align="arrival", grace_s=1.0)
        a.add_interval(late, 1.7)
        sw = {w.index: w for w in s.finish(10)}
        aw = {w.index: w for w in a.finish(10)}
        self.assertEqual(sw[0].nodes[("10.0.0.0", 8)].fwd, 10)               # window 0
        self.assertNotIn(0, aw)                                              # nothing in window 0
        self.assertEqual(aw[1].nodes[("10.0.0.0", 8)].fwd, 10)               # window 1

    def test_interval_after_window_closed_is_counted_late(self):
        agg = WindowedAggregator(1.0, grace_s=0.2)
        agg.add_interval(iv(1, 3.0, []), 3.0)                 # closes windows 0..1
        agg.add_interval(iv(1, 1.0, [rec("10.0.0.0", 8, fc=1)]), 3.1)
        self.assertEqual(agg.late_intervals, 1)

    def test_roles_suppress_double_observation(self):
        # Requests pass routers 1 and 3 (both count fwd); only router 1 is designated.
        recs = [rec("192.168.1.1", 32, fc=100)]
        plain = WindowedAggregator(1.0)
        roled = WindowedAggregator(1.0, roles={3: RouterRole(count_fwd=False)})
        for agg in (plain, roled):
            agg.add_interval(iv(1, 1.0, recs), 1.01)
            agg.add_interval(iv(3, 1.0, recs), 1.01)
        self.assertEqual(plain.finish(10)[0].nodes[("192.168.1.1", 32)].fwd, 200)
        self.assertEqual(roled.finish(10)[0].nodes[("192.168.1.1", 32)].fwd, 100)

    def test_absolute_unix_time_starts_at_first_window(self):
        t0 = 1_792_000_000.0
        agg = WindowedAggregator(1.0, expected_routers={1})
        agg.add_interval(iv(1, t0 + 1.0, [rec("10.0.0.0", 8, fc=5)]), t0 + 1.01)
        agg.add_interval(iv(1, t0 + 2.0, [rec("10.0.0.0", 8, fc=6)], interval_id=1), t0 + 2.01)
        w = agg.finish(t0 + 10)
        self.assertLess(len(w), 20)
        self.assertEqual(w[0].index, int(t0))
        self.assertEqual([x.nodes[("10.0.0.0", 8)].fwd for x in w[:2]], [5, 6])

    def test_uncounted_units_are_carried(self):
        agg = WindowedAggregator(1.0)
        agg.add_interval(iv(1, 1.0, [], unc=(7, 3)), 1.01)
        w = agg.finish(10)[0]
        self.assertEqual((w.uncounted_fwd, w.uncounted_rev), (7, 3))


if __name__ == "__main__":
    unittest.main()

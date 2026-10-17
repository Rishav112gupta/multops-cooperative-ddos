"""Unit tests for the Phase 5 detection engine and scorer (hand-built inputs)."""

import unittest

from aggregator.aggregator import PaperWindow, WindowedAggregator
from aggregator.detection import (ABSTAIN, BENIGN, CORRECTED, MAL_AMBIGUOUS, MAL_HOST, PAPER_LITERAL,
                                  CorrectedDetector, Decision, PaperDetector, Thresholds, classify,
                                  decision_nodes, would_mitigate)
from aggregator.telemetry_protocol import RecordV1
from aggregator.telemetry_receiver import Interval
from experiments.phase4.netsim import Truth
from experiments.phase5.evaluate import score

TH = Thresholds(ratio=5.0, min_rate=50.0, min_volume=50.0)


def window(records_by_router, expected=None, window_s=1.0):
    agg = WindowedAggregator(window_s, expected_routers=expected or set(records_by_router))
    for rid, recs in records_by_router.items():
        iv = Interval(rid, 1, 0, "PARTITION", 0, 1_000_000, 1000, 0, 0, 1, recs, 0.0)
        agg.add_interval(iv, 1.01)
    return agg.finish(100)[0]


def leaf(p, l, f=0, r=0):
    return RecordV1(p, l, 1, 0, 0, f, r)


def resid(p, l, f=0, r=0):
    return RecordV1(p, l, 2, 0, 0, f, r)


class ClassifyTests(unittest.TestCase):
    def test_paper_literal_zero_return_ignores_tau_rate(self):
        for r_in in (0.0, 1.0, 10_000.0):
            for tau_rate in (0.0, 50.0, 1e9):
                self.assertTrue(classify(r_in, 0, PAPER_LITERAL, Thresholds(5, tau_rate, 0))[0])

    def test_paper_literal_ratio(self):
        self.assertTrue(classify(600, 100, PAPER_LITERAL, TH)[0])
        self.assertFalse(classify(500, 100, PAPER_LITERAL, TH)[0])   # ratio 5 is not > 5

    def test_corrected_volume_gate_then_zero_return_then_ratio(self):
        self.assertEqual(classify(49, 0, CORRECTED, TH), (False, "below_min_volume"))
        self.assertEqual(classify(50, 0, CORRECTED, TH), (True, "zero_return"))
        self.assertEqual(classify(600, 100, CORRECTED, TH), (True, "ratio"))
        self.assertEqual(classify(100, 30, CORRECTED, TH), (False, "ratio_ok"))

    def test_unknown_rule(self):
        with self.assertRaises(ValueError):
            classify(1, 1, "x", TH)


class DecisionNodeTests(unittest.TestCase):
    def test_partition_is_non_overlapping_and_complete(self):
        w = window({1: [leaf("10.0.0.1", 32, f=2000), leaf("192.168.1.1", 32, f=100)],
                    2: [leaf("192.168.1.1", 32, r=30)]})
        units = decision_nodes(w)
        keys = [k for k, _ in units]
        self.assertEqual(keys, [("10.0.0.1", 32), ("192.168.1.1", 32)])
        self.assertEqual(sum(n.fwd for _, n in units), 2100)
        self.assertEqual(sum(n.rev for _, n in units), 30)

    def test_coarse_record_stops_descent(self):
        w = window({1: [leaf("192.168.1.1", 32, f=95), resid("192.0.0.0", 8, f=5)],
                    2: [leaf("192.0.0.0", 8, r=30)]})
        units = decision_nodes(w)
        self.assertEqual([(k, n.fwd, n.rev) for k, n in units], [(("192.0.0.0", 8), 100, 30)])

    def test_residual_at_24_keeps_other_slash8_branches_fine(self):
        w = window({1: [leaf("10.0.0.1", 32, f=50), resid("192.168.1.0", 24, f=3),
                        leaf("192.168.1.7", 32, f=10)]})
        keys = [k for k, _ in decision_nodes(w)]
        self.assertEqual(keys, [("10.0.0.1", 32), ("192.168.1.0", 24)])


class CorrectedDetectorTests(unittest.TestCase):
    def test_host_and_ambiguous_labels(self):
        w = window({1: [leaf("10.0.0.1", 32, f=2000), leaf("192.168.1.1", 32, f=100),
                        resid("172.16.0.0", 16, f=900), leaf("172.16.5.0", 24, f=10)],
                    2: [leaf("192.168.1.1", 32, r=30)]})
        ds = {d.key: d for d in CorrectedDetector(CORRECTED, TH, 1.0).decide(w)}
        self.assertEqual(ds[("10.0.0.1", 32)].label, MAL_HOST)
        self.assertEqual(ds[("192.168.1.1", 32)].label, BENIGN)
        self.assertEqual(ds[("172.16.0.0", 16)].label, MAL_AMBIGUOUS)    # attribution unresolved

    def test_incomplete_window_abstains_never_benign(self):
        w = window({1: [leaf("192.168.1.1", 32, f=100)]}, expected={1, 2})
        ds = CorrectedDetector(CORRECTED, TH, 1.0).decide(w)
        self.assertEqual([(d.label, d.reason) for d in ds], [(ABSTAIN, "missing_router:2")])
        self.assertEqual(would_mitigate(ds), [])

    def test_counts_converted_to_rates_by_window_length(self):
        w = window({1: [leaf("10.0.0.1", 32, f=80)]}, window_s=2.0)
        d = CorrectedDetector(CORRECTED, TH, 2.0).decide(w)[0]
        self.assertEqual((d.r_in, d.label), (40.0, BENIGN))                  # 40 pps < 50

    def test_aggregate_variant_flags_low_volume_group_but_not_replied_hosts(self):
        recs = [leaf(f"10.1.0.{i}", 32, f=40) for i in range(1, 11)] + [leaf("10.1.0.200", 32, f=40)]
        w = window({1: recs, 2: [leaf("10.1.0.200", 32, r=35)]})
        plain = CorrectedDetector(CORRECTED, TH, 1.0).decide(w)
        hier = {d.key: d for d in CorrectedDetector(CORRECTED, TH, 1.0, aggregate_low_volume=True).decide(w)}
        self.assertTrue(all(d.label == BENIGN for d in plain))
        self.assertEqual(hier[("10.1.0.1", 32)].label, MAL_HOST)
        self.assertEqual(hier[("10.1.0.1", 32)].reason, "aggregate:10.1.0.0/24")
        self.assertEqual(hier[("10.1.0.200", 32)].label, BENIGN)              # has replies

    def test_aggregate_variant_needs_group_volume(self):
        w = window({1: [leaf("10.1.0.1", 32, f=20), leaf("10.1.0.2", 32, f=20)]})
        ds = CorrectedDetector(CORRECTED, TH, 1.0, aggregate_low_volume=True).decide(w)
        self.assertTrue(all(d.label == BENIGN for d in ds))                  # 40 < 50 in total


class PaperDetectorTests(unittest.TestCase):
    def state(self, s):
        return PaperWindow(0, 0, 1, s, 1)

    def test_units_are_most_specific_keys_and_ancestor_flags_propagate(self):
        w = self.state({("192.0.0.0", 8): [100, 30], ("192.168.0.0", 16): [100, 0],
                        ("192.168.1.0", 24): [100, 0], ("192.168.1.1", 32): [100, 0],
                        ("10.0.0.0", 8): [40, 0], ("10.1.0.0", 16): [3, 2]})
        det = PaperDetector(PAPER_LITERAL, TH)
        units = {d.key: d for d in det.decide(w)}
        self.assertEqual(set(units), {("192.168.1.1", 32), ("10.1.0.0", 16)})
        self.assertEqual(units[("192.168.1.1", 32)].label, MAL_HOST)           # own key (100, 0)
        self.assertEqual(units[("10.1.0.0", 16)].label, MAL_AMBIGUOUS)         # via 10/8 (40, 0)
        self.assertTrue(units[("10.1.0.0", 16)].reason.startswith("ancestor_flagged:10.0.0.0/8"))
        flags = det.flagged_keys(w)
        self.assertNotIn(("192.0.0.0", 8), flags)
        self.assertIn(("192.168.0.0", 16), flags)


class ScoreTests(unittest.TestCase):
    def test_unit_and_host_metrics_with_denominators(self):
        t = Truth(1.0)
        t.fwd[5].update({"10.0.0.1": 2000, "192.168.1.1": 100, "192.168.1.66": 500})
        t.atk_fwd[5].update({"10.0.0.1": 2000, "192.168.1.66": 500})
        t.rev[5].update({"192.168.1.1": 30})
        ds = [Decision(5, "10.0.0.1", 32, 2000, 0, MAL_HOST, "zero_return", "x"),
              Decision(5, "192.168.1.0", 24, 600, 30, MAL_AMBIGUOUS, "ratio", "x"),
              Decision(5, "172.16.0.9", 32, 60, 0, MAL_HOST, "zero_return", "x"),
              Decision(5, "203.0.113.0", 24, 10, 10, BENIGN, "ratio_ok", "x"),
              Decision(6, "10.0.0.1", 32, 0, 0, ABSTAIN, "missing_router:2", "x")]
        t.fwd[6].update({"10.0.0.1": 2000})
        t.atk_fwd[6].update({"10.0.0.1": 2000})
        m = score(ds, t, 0, range(0, 10))
        self.assertEqual((m["TP"], m["FP"], m["TN"], m["FN"]), (2, 1, 1, 0))
        self.assertEqual(m["precision_den"], "2/3")
        self.assertEqual(m["fpr_den"], "1/2")
        self.assertEqual((m["units_abstained"], m["abstained_units_with_attack"]), (1, 1))
        self.assertEqual((m["flagged_ambiguous_units"], m["flagged_mixed_units"]), (1, 1))
        h = m["host"]
        self.assertEqual((h["identified"], h["unresolved"], h["missed"], h["abstained"]), (1, 1, 0, 1))
        self.assertEqual((h["false_identifications"], h["collateral_benign_host_windows"]), (1, 1))
        self.assertEqual(h["recall_den"], "1/2")

    def test_lag_shifts_truth_window(self):
        t = Truth(1.0)
        t.fwd[3].update({"10.0.0.1": 5})
        t.atk_fwd[3].update({"10.0.0.1": 5})
        d = [Decision(4, "10.0.0.1", 32, 5, 0, MAL_HOST, "zero_return", "x")]
        self.assertEqual(score(d, t, 1, range(10))["TP"], 1)
        self.assertEqual(score(d, t, 0, range(10))["FP"], 1)

    def test_empty_denominators_are_none(self):
        m = score([], Truth(1.0), 0, range(5))
        self.assertIsNone(m["precision"])
        self.assertIsNone(m["fpr"])


if __name__ == "__main__":
    unittest.main()

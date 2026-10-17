"""Regression test for the Phase 4 simulation (short runs of selected scenarios).

Asserts the qualitative properties reported in docs/PHASE4_AGGREGATION_ANALYSIS.md
so that later code changes cannot silently alter them. Needs MULTOPS_BUILD_DIR.
"""

import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from experiments.phase4.netsim import score_attacker, score_paper, score_proposal, simulate
from experiments.phase4.run_phase4 import ATTACKER, CLIENT, main as run_phase4_main, scenarios

BUILD = os.environ.get("MULTOPS_BUILD_DIR")
REPLAY = Path(BUILD) / "multops_replay" if BUILD else None


@unittest.skipUnless(REPLAY and REPLAY.exists(), "MULTOPS_BUILD_DIR/multops_replay not available")
class Phase4SimulationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = {}
        for sc in scenarios():
            sc = replace(sc, duration_s=15)
            cls.out[sc.name] = simulate(sc, REPLAY, Path(cls.tmp.name) / sc.name,
                                        variants=("sender", "arrival"))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def p(self, name):
        return score_paper(self.out[name], CLIENT)

    def s(self, name, variant="sender"):
        return score_proposal(self.out[name], variant, CLIENT)

    def test_proposal_reconstructs_exactly_when_assumptions_hold(self):
        for name in ("S1_single_router", "S2_asym_granularity", "S3_asym_baseline",
                     "S4_interval_mismatch", "S8_duplicates"):
            with self.subTest(name):
                s = self.s(name)
                self.assertGreater(s["scored"], 5)
                self.assertEqual(s["counts_exact"], s["scored"])
                self.assertEqual(s["one_sided"], 0)

    def test_paper_granularity_mismatch_is_one_sided(self):
        self.assertEqual(self.p("S2_asym_granularity")["one_sided"], self.p("S2_asym_granularity")["scored"])
        self.assertEqual(self.p("S3_asym_baseline")["one_sided"], 0)
        self.assertEqual(set(self.s("S2_asym_granularity")["levels"]), {8})

    def test_paper_sums_rates_over_time(self):
        self.assertGreater(self.p("S4_interval_mismatch")["ratio8_median_rel_err"], 0.8)
        self.assertLess(self.p("S3_asym_baseline")["ratio8_median_rel_err"], 0.05)

    def test_loss_is_withheld_not_misread(self):
        s = self.s("S7_telemetry_loss")
        self.assertGreater(s["withheld_incomplete"], 0)
        self.assertEqual(s["one_sided"], 0)
        self.assertGreater(self.p("S7_telemetry_loss")["one_sided"], 0)

    def test_double_observation_needs_roles(self):
        self.assertGreater(self.s("S9_double_observation")["max_abs_count_err"], 0)
        self.assertEqual(self.s("S9b_double_observation_roles")["max_abs_count_err"], 0)

    def test_misalignment_is_not_fixed_by_the_proposal(self):
        for name in ("S5_phase_offset", "S6_clock_skew"):
            with self.subTest(name):
                self.assertGreater(self.s(name)["max_abs_count_err"], 0)

    def test_arrival_alignment_under_skew_creates_one_sided_windows(self):
        self.assertGreater(self.s("S6_clock_skew", "arrival")["one_sided"], 0)
        self.assertEqual(self.s("S6_clock_skew", "sender")["one_sided"], 0)

    def test_committed_results_reproduce_exactly(self):
        committed = Path(__file__).resolve().parents[2] / "experiments" / "results" / "phase4" / "phase4_results.json"
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(run_phase4_main(["--build", BUILD, "--out", d]), 0)
            self.assertEqual(json.loads((Path(d) / "phase4_results.json").read_text()),
                             json.loads(committed.read_text()))

    def test_flood_source_counts_exact(self):
        a = score_attacker(self.out["S3_asym_baseline"], "sender", ATTACKER)
        self.assertEqual((a["max_abs_fwd_err"], a["windows_with_rev"]), (0, 0))


if __name__ == "__main__":
    unittest.main()

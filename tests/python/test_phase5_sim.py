"""Regression test for the Phase 5 detection evaluation.

Asserts the qualitative results reported in docs/PHASE5_DETECTION_VALIDATION.md
and that the committed results file reproduces exactly. Needs MULTOPS_BUILD_DIR.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

from experiments.phase5.run_phase5 import main as run_phase5_main

BUILD = os.environ.get("MULTOPS_BUILD_DIR")
REPLAY = Path(BUILD) / "multops_replay" if BUILD else None
COMMITTED = Path(__file__).resolve().parents[2] / "experiments" / "results" / "phase5" / "phase5_results.json"


@unittest.skipUnless(REPLAY and REPLAY.exists(), "MULTOPS_BUILD_DIR/multops_replay not available")
class Phase5Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        assert run_phase5_main(["--build", BUILD, "--out", cls.tmp.name]) == 0
        cls.res = json.loads((Path(cls.tmp.name) / "phase5_results.json").read_text())
        cls.by = {s["scenario"]: s for s in cls.res["scenarios"]}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def e1(self, scenario, method):
        return self.by[scenario]["E1"][method]

    def test_committed_results_reproduce_exactly(self):
        self.assertEqual(self.res, json.loads(COMMITTED.read_text()))

    def test_paper_rule_ignores_tau_rate(self):
        for s in self.res["scenarios"]:
            for r in self.res["ratios"]:
                rows = [x["paper"] for x in s["sweep"] if x["ratio"] == r]
                self.assertTrue(all((m["TP"], m["FP"], m["TN"], m["FN"]) ==
                                    (rows[0]["TP"], rows[0]["FP"], rows[0]["TN"], rows[0]["FN"]) for m in rows),
                                f"{s['scenario']} ratio {r}")

    def test_granularity_false_positives_removed_by_proposal(self):
        self.assertEqual(self.e1("D2_granularity", "paper")["FP"], 46)
        self.assertEqual(self.e1("D2_granularity", "proposal")["FP"], 0)
        self.assertEqual(self.e1("D2_granularity", "ablation_agg_only")["FP"], 0)   # aggregation is the fix

    def test_standalone_router_cannot_avoid_false_positives(self):
        for m in ("paper", "proposal"):
            self.assertEqual(self.e1("D0_standalone", m)["fpr_den"], "46/46")

    def test_fundamental_limits(self):
        for m in ("paper", "proposal", "proposal_hier"):
            self.assertEqual(self.e1("D3_legit_one_way", m)["FP"], 57)          # one-way benign == flood
            self.assertEqual(self.e1("D5_proportional_attack", m)["TP"], 0)     # proportional attack missed

    def test_volume_gate_trade_off(self):
        self.assertEqual(self.e1("D4_low_rate_attack", "proposal")["FN"], 57)
        self.assertEqual(self.e1("D6_distributed_low_rate", "proposal")["TP"], 0)
        self.assertEqual(self.e1("D6_distributed_low_rate", "proposal_hier")["FN"], 0)
        self.assertEqual(self.e1("D9_benign_low_rate_sensors", "proposal")["FP"], 0)
        self.assertEqual(self.e1("D9_benign_low_rate_sensors", "proposal_hier")["FP"], 1710)

    def test_mixed_prefix_is_ambiguous_with_collateral(self):
        m = self.e1("D7_mixed_prefix", "proposal")
        self.assertEqual(m["FP"], 0)
        self.assertGreater(m["flagged_ambiguous_units"], 0)
        self.assertEqual(m["flagged_ambiguous_units"], m["flagged_mixed_units"])
        self.assertGreater(m["host"]["collateral_benign_host_windows"], 0)
        self.assertGreater(m["host"]["unresolved"], 0)

    def test_loss_produces_abstentions_not_benign(self):
        m = self.e1("D8_telemetry_loss", "proposal")
        self.assertGreater(m["units_abstained"], 0)
        self.assertEqual(m["FP"], 0)
        self.assertEqual(m["host"]["abstained"], m["abstained_units_with_attack"])
        self.assertGreater(self.e1("D8_telemetry_loss", "paper")["FP"], 0)
        for s in self.res["scenarios"]:
            self.assertEqual(s["E1"]["paper"]["units_abstained"], 0)              # the paper never abstains


if __name__ == "__main__":
    unittest.main()

"""Tests for the composite vector + KEEP/REVERT decision core (composite.py).

Run from inside scoring/:  python3 -m unittest test_composite -v
"""
import unittest

import composite


def base():
    """A real-shaped 16-key aggregate (mirrors _baseline_agg.json)."""
    return {
        "cases": 2,
        "fabrication_count_total": 0,
        "findable_found": 2,
        "findable_recall_micro": 1.0,
        "findable_total": 2,
        "full_found": 2,
        "full_recall_micro": 1.0,
        "full_total": 2,
        "invalid_mitre_total": 0,
        "mitre_emitted_total": 0,
        "mitre_found": 1,
        "mitre_grounded_total": 0,
        "mitre_precision_micro": None,
        "mitre_recall_micro": 0.5,
        "mitre_total": 2,
        "verdicts_emitted": 1,
    }


class CompositeVectorTests(unittest.TestCase):
    def test_projects_four_gated_dims_with_direction(self):
        cv = composite.composite_vector(base())
        self.assertEqual(set(cv["gated"]), set(composite.GATED_DIMS))
        self.assertEqual(cv["gated"]["fabrication_count_total"]["direction"], "down")
        self.assertEqual(cv["gated"]["findable_recall_micro"]["direction"], "up")
        self.assertEqual(cv["gated"]["mitre_recall_micro"]["direction"], "up")
        self.assertEqual(cv["gated"]["verdicts_emitted"]["direction"], "up")
        self.assertEqual(cv["gated"]["mitre_recall_micro"]["value"], 0.5)

    def test_advisory_carried_never_gated(self):
        cv = composite.composite_vector(base())
        self.assertIn("mitre_precision_micro", cv["advisory"])
        self.assertIn("full_recall_micro", cv["advisory"])
        self.assertIn("mitre_found", cv["advisory"])
        # advisory keys are NOT in gated.
        self.assertFalse(set(cv["advisory"]) & set(cv["gated"]))

    def test_pure_no_mutation(self):
        agg = base()
        snap = dict(agg)
        composite.composite_vector(agg)
        self.assertEqual(agg, snap)


class CompareTests(unittest.TestCase):
    # ---- KEEP -------------------------------------------------------------
    def test_keep_when_one_gated_improves_rest_equal(self):
        b = base()
        p = dict(b)
        p["mitre_recall_micro"] = 1.0  # 0.5 -> 1.0
        p["mitre_found"] = 2
        decision, reason, deltas = composite.compare(b, p)
        self.assertEqual(decision, "KEEP")
        self.assertIn("strictly improved", reason)
        self.assertEqual(deltas["mitre_recall_micro"]["status"], "improve")
        self.assertAlmostEqual(deltas["mitre_recall_micro"]["delta"], 0.5)

    def test_keep_when_all_up(self):
        b = base()
        p = dict(b)
        p["findable_recall_micro"] = 1.0  # already max; bump verdicts + mitre + drop fabs
        p["verdicts_emitted"] = 2
        p["mitre_recall_micro"] = 1.0
        decision, _, _ = composite.compare(b, p)
        self.assertEqual(decision, "KEEP")

    def test_keep_fabrication_down(self):
        b = base()
        b["fabrication_count_total"] = 3
        p = dict(b)
        p["fabrication_count_total"] = 1  # DOWN is an improvement
        decision, _, deltas = composite.compare(b, p)
        self.assertEqual(decision, "KEEP")
        self.assertEqual(deltas["fabrication_count_total"]["status"], "improve")

    # ---- REVERT: single regressions --------------------------------------
    def test_revert_on_findable_regress(self):
        b = base()
        p = dict(b)
        p["findable_recall_micro"] = 0.5
        p["mitre_recall_micro"] = 1.0  # an improvement elsewhere does NOT rescue it
        decision, reason, _ = composite.compare(b, p)
        self.assertEqual(decision, "REVERT")
        self.assertIn("regression", reason)

    def test_revert_on_verdicts_regress(self):
        b = base()
        p = dict(b)
        p["verdicts_emitted"] = 0
        decision, _, deltas = composite.compare(b, p)
        self.assertEqual(decision, "REVERT")
        self.assertEqual(deltas["verdicts_emitted"]["status"], "regress")

    def test_revert_on_fabrication_increase(self):
        b = base()
        p = dict(b)
        p["fabrication_count_total"] = 1  # 0 -> 1 is a regression (DOWN dim)
        decision, _, deltas = composite.compare(b, p)
        self.assertEqual(decision, "REVERT")
        self.assertEqual(deltas["fabrication_count_total"]["status"], "regress")

    def test_revert_on_mitre_regress(self):
        b = base()
        p = dict(b)
        p["mitre_recall_micro"] = 0.0
        decision, _, _ = composite.compare(b, p)
        self.assertEqual(decision, "REVERT")

    # ---- the fab-up / recall-up TRADE => REVERT --------------------------
    def test_revert_on_fab_up_recall_up_trade(self):
        """fabrication +1 WITH findable_recall +0.2 must still REVERT — gating is
        per-dim non-regression, never a net trade."""
        b = base()
        b["findable_recall_micro"] = 0.6
        b["findable_found"] = 6
        b["findable_total"] = 10
        p = dict(b)
        p["findable_recall_micro"] = 0.8       # +0.2 improvement
        p["fabrication_count_total"] = 1        # +1 regression
        decision, reason, deltas = composite.compare(b, p)
        self.assertEqual(decision, "REVERT")
        self.assertEqual(deltas["fabrication_count_total"]["status"], "regress")
        self.assertEqual(deltas["findable_recall_micro"]["status"], "improve")
        self.assertIn("fabrication_count_total", reason)

    # ---- tie / all-equal => REVERT ---------------------------------------
    def test_revert_on_all_equal(self):
        b = base()
        decision, reason, _ = composite.compare(b, dict(b))
        self.assertEqual(decision, "REVERT")
        self.assertIn("tie", reason)

    # ---- None on a gated dim => FAIL/REVERT ------------------------------
    def test_revert_when_post_gated_recall_none(self):
        b = base()
        p = dict(b)
        p["mitre_recall_micro"] = None  # None on a gated dim FAILS
        decision, reason, deltas = composite.compare(b, p)
        self.assertEqual(decision, "REVERT")
        self.assertEqual(deltas["mitre_recall_micro"]["status"], "fail")
        self.assertIn("FAIL", reason)

    def test_revert_when_base_gated_recall_none_even_if_post_better(self):
        b = base()
        b["findable_recall_micro"] = None
        b["findable_total"] = 0
        p = dict(b)
        p["findable_recall_micro"] = 1.0
        p["findable_total"] = 2
        decision, _, deltas = composite.compare(b, p)
        self.assertEqual(decision, "REVERT")
        self.assertEqual(deltas["findable_recall_micro"]["status"], "fail")

    def test_fail_delta_none_when_either_side_none(self):
        b = base()
        p = dict(b)
        p["mitre_recall_micro"] = None
        _, _, deltas = composite.compare(b, p)
        self.assertIsNone(deltas["mitre_recall_micro"]["delta"])

    # ---- eps boundary ----------------------------------------------------
    def test_eps_boundary_non_regress_within_tolerance_is_not_improve(self):
        """A tiny dip within eps_recall is non-regress but NOT a strict-improve =>
        with everything else equal => tie => REVERT."""
        b = base()
        p = dict(b)
        p["mitre_recall_micro"] = 0.5 - 0.01  # within eps
        decision, _, deltas = composite.compare(b, p, eps_recall=0.05)
        self.assertEqual(deltas["mitre_recall_micro"]["status"], "equal")
        self.assertEqual(decision, "REVERT")  # no strict improve anywhere

    def test_eps_boundary_dip_beyond_tolerance_regresses(self):
        b = base()
        p = dict(b)
        p["mitre_recall_micro"] = 0.5 - 0.10  # beyond eps
        _, _, deltas = composite.compare(b, p, eps_recall=0.05)
        self.assertEqual(deltas["mitre_recall_micro"]["status"], "regress")

    def test_eps_strict_improve_requires_above_eps(self):
        b = base()
        p = dict(b)
        p["mitre_recall_micro"] = 0.5 + 0.03  # NOT above eps=0.05
        decision, _, deltas = composite.compare(b, p, eps_recall=0.05)
        self.assertEqual(deltas["mitre_recall_micro"]["status"], "equal")
        self.assertEqual(decision, "REVERT")
        p2 = dict(b)
        p2["mitre_recall_micro"] = 0.5 + 0.06  # above eps
        decision2, _, deltas2 = composite.compare(b, p2, eps_recall=0.05)
        self.assertEqual(deltas2["mitre_recall_micro"]["status"], "improve")
        self.assertEqual(decision2, "KEEP")

    # ---- deltas correctness ----------------------------------------------
    def test_deltas_carry_base_post_direction(self):
        b = base()
        p = dict(b)
        p["verdicts_emitted"] = 2
        _, _, deltas = composite.compare(b, p)
        d = deltas["verdicts_emitted"]
        self.assertEqual(d["base"], 1)
        self.assertEqual(d["post"], 2)
        self.assertEqual(d["delta"], 1)
        self.assertEqual(d["direction"], "up")
        # every gated dim is represented.
        self.assertEqual(set(deltas), set(composite.GATED_DIMS))


if __name__ == "__main__":
    unittest.main()

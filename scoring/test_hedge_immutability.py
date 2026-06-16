"""G-HEDGE-IMMUT — born-safe verdict-arithmetic + hedge-format invariants.

Run from inside scoring/:  python3 -m unittest test_hedge_immutability -v
"""
import unittest

import composite
import scorer
import keep_or_revert as kor


def base():
    return {
        "cases": 2,
        "fabrication_count_total": 0,
        "findable_recall_micro": 1.0,
        "findable_found": 2,
        "findable_total": 2,
        "full_recall_micro": 1.0,
        "full_found": 2,
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


HEDGE_OK = (
    "## Verdict\n"
    "VERDICT: INCONCLUSIVE — act: LOW, attribution: LOW\n\n"
    "Style rule: never collapse to an unqualified yes/no; state the residual "
    "uncertainty.\n"
    "Remember INCONCLUSIVE is itself a correct answer when the evidence does not "
    "resolve.\n"
)


class VerdictArithmeticTests(unittest.TestCase):
    """INCONCLUSIVE must be FIRST-CLASS; a MALICE call on an INCONCLUSIVE key is wrong."""

    def test_malice_on_inconclusive_is_not_emitted(self):
        s = scorer.verdict_status(
            "Findings...\nVERDICT: MALICE — act: HIGH, attribution: HIGH",
            "INCONCLUSIVE",
        )
        self.assertEqual(s, "not_emitted")

    def test_inconclusive_on_inconclusive_is_found(self):
        s = scorer.verdict_status(
            "Findings...\nVERDICT: INCONCLUSIVE — act: LOW, attribution: LOW",
            "INCONCLUSIVE",
        )
        self.assertEqual(s, "found")


class VerdictDimGatingTests(unittest.TestCase):
    def test_verdicts_emitted_minus_one_reverts(self):
        b = base()
        p = dict(b)
        p["verdicts_emitted"] = b["verdicts_emitted"] - 1  # 1 -> 0, all else equal
        decision, reason, deltas = composite.compare(b, p)
        self.assertEqual(decision, "REVERT")
        self.assertEqual(deltas["verdicts_emitted"]["status"], "regress")
        self.assertIn("verdicts_emitted", reason)


class HedgeFormatIntactTests(unittest.TestCase):
    def test_positive_fixture_true(self):
        self.assertTrue(kor.hedge_format_intact(HEDGE_OK))

    def test_malice_token_with_levels_still_valid_shape(self):
        txt = HEDGE_OK.replace(
            "VERDICT: INCONCLUSIVE — act: LOW, attribution: LOW",
            "VERDICT: MALICE — act: HIGH, attribution: MODERATE",
        )
        self.assertTrue(kor.hedge_format_intact(txt))

    def test_removed_verdict_line_false(self):
        txt = HEDGE_OK.replace(
            "VERDICT: INCONCLUSIVE — act: LOW, attribution: LOW\n", ""
        )
        self.assertFalse(kor.hedge_format_intact(txt))

    def test_mutated_level_false(self):
        # CRITICAL is not a legal LEVEL -> format broken.
        txt = HEDGE_OK.replace("act: LOW", "act: CRITICAL")
        self.assertFalse(kor.hedge_format_intact(txt))

    def test_removed_no_collapse_clause_false(self):
        txt = HEDGE_OK.replace(
            "Style rule: never collapse to an unqualified yes/no; state the residual "
            "uncertainty.\n",
            "",
        )
        self.assertFalse(kor.hedge_format_intact(txt))

    def test_removed_inconclusive_correct_answer_clause_false(self):
        txt = HEDGE_OK.replace(
            "Remember INCONCLUSIVE is itself a correct answer when the evidence does not "
            "resolve.\n",
            "",
        )
        self.assertFalse(kor.hedge_format_intact(txt))

    def test_non_string_false(self):
        self.assertFalse(kor.hedge_format_intact(None))


if __name__ == "__main__":
    unittest.main()

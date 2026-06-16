#!/usr/bin/env python3
"""Tests for the R5 presence-check scorer.

Stdlib ``unittest`` only. Every fixture is a small inline string so the suite is
self-contained and never touches real case data.

Run:  python3 -m unittest test_presence_scorer -v
"""

import unittest

import presence_scorer as ps


# --- Synthetic report fixtures -------------------------------------------------

FULL = """\
# Investigation Report

## Findings
- F1: powershell.exe spawned from explorer.exe — CONFIRMED.
- F2: suspicious outbound beacon. Identity unresolved; marked INSUFFICIENT_EVIDENCE.

## Limitations & Coverage Gaps
- Memory image was truncated; pagefile not analysed.

## Verdict
VERDICT: MALICE (act HIGH, attribution LOW)
"""

NO_ABSTAIN = """\
# Investigation Report

## Findings
- F1: everything confirmed, no doubts at all.

## Limitations & Coverage Gaps
- None worth noting.

## Verdict
VERDICT: MALICE
"""

NO_GAPS = """\
# Investigation Report

## Findings
- F1: marked INSUFFICIENT_EVIDENCE pending identity resolution.

## Verdict
VERDICT: INCONCLUSIVE
"""

NEITHER = """\
# Investigation Report

## Findings
- F1: confirmed malware.

## Verdict
VERDICT: MALICE
"""

INCONCLUSIVE_ONLY = """\
# Investigation Report

## Findings
- F1: could not decide.

## Verdict
VERDICT: INCONCLUSIVE
"""


class TestTokenDetection(unittest.TestCase):
    def test_insufficient_evidence_detected(self):
        r = ps.check_report(FULL, "full")
        self.assertTrue(r.has_insufficient_evidence)
        self.assertEqual(r.insufficient_evidence_count, 1)

    def test_insufficient_evidence_absent(self):
        r = ps.check_report(NO_ABSTAIN, "no_abstain")
        self.assertFalse(r.has_insufficient_evidence)
        self.assertEqual(r.insufficient_evidence_count, 0)

    def test_counts_multiple_finding_level_abstains(self):
        text = "F1 INSUFFICIENT_EVIDENCE\nF2 INSUFFICIENT_EVIDENCE\nF3 fine"
        self.assertEqual(ps.check_report(text).insufficient_evidence_count, 2)

    def test_hyphen_and_space_variants_accepted(self):
        for variant in ("INSUFFICIENT-EVIDENCE", "Insufficient Evidence", "insufficient_evidence"):
            self.assertTrue(
                ps.check_report(f"finding: {variant}").has_insufficient_evidence,
                variant,
            )

    def test_substring_does_not_falsely_match(self):
        # token-boundary anchoring: no false positive on a glued word.
        self.assertFalse(
            ps.check_report("XINSUFFICIENT_EVIDENCEX").has_insufficient_evidence
        )


class TestTokenDistinctness(unittest.TestCase):
    """INCONCLUSIVE (case verdict) must NOT satisfy the finding-level field."""

    def test_inconclusive_is_not_insufficient_evidence(self):
        r = ps.check_report(INCONCLUSIVE_ONLY, "inc_only")
        self.assertTrue(r.has_inconclusive_verdict)
        self.assertFalse(r.has_insufficient_evidence)
        self.assertFalse(r.passed)

    def test_inconclusive_tracked_as_diagnostic(self):
        self.assertTrue(ps.check_report(NO_GAPS).has_inconclusive_verdict)
        self.assertFalse(ps.check_report(NO_ABSTAIN).has_inconclusive_verdict)


class TestCoverageGapsSection(unittest.TestCase):
    def test_full_title_detected(self):
        self.assertTrue(ps.check_report(FULL).has_coverage_gaps_section)

    def test_ampersand_and_and_word_both_ok(self):
        self.assertTrue(
            ps.check_report("## Limitations and Coverage Gaps\n- x").has_coverage_gaps_section
        )
        self.assertTrue(
            ps.check_report("### Limitations & Coverage Gaps\n- x").has_coverage_gaps_section
        )

    def test_coverage_gaps_alone_ok(self):
        self.assertTrue(ps.check_report("## Coverage Gaps\n- x").has_coverage_gaps_section)

    def test_limitations_alone_ok(self):
        self.assertTrue(ps.check_report("## Limitations\n- x").has_coverage_gaps_section)

    def test_missing_section(self):
        self.assertFalse(ps.check_report(NO_GAPS).has_coverage_gaps_section)

    def test_must_be_a_heading_not_inline_mention(self):
        # An inline mention in prose is not a section heading.
        self.assertFalse(
            ps.check_report("We have some coverage gaps in this case.").has_coverage_gaps_section
        )


class TestPassFail(unittest.TestCase):
    def test_full_report_passes(self):
        r = ps.check_report(FULL, "full")
        self.assertTrue(r.passed)
        self.assertEqual(r.missing_fields, [])

    def test_no_abstain_fails(self):
        r = ps.check_report(NO_ABSTAIN, "no_abstain")
        self.assertFalse(r.passed)
        self.assertIn("INSUFFICIENT_EVIDENCE", r.missing_fields)

    def test_no_gaps_fails(self):
        r = ps.check_report(NO_GAPS, "no_gaps")
        self.assertFalse(r.passed)
        self.assertIn("Limitations & Coverage Gaps section", r.missing_fields)

    def test_neither_fails_with_both_missing(self):
        r = ps.check_report(NEITHER, "neither")
        self.assertFalse(r.passed)
        self.assertEqual(len(r.missing_fields), 2)


class TestAggregate(unittest.TestCase):
    def test_aggregate_counts(self):
        results = [
            ps.check_report(FULL, "full"),
            ps.check_report(NO_ABSTAIN, "no_abstain"),
            ps.check_report(NO_GAPS, "no_gaps"),
            ps.check_report(NEITHER, "neither"),
        ]
        agg = ps.aggregate(results)
        self.assertEqual(agg["reports"], 4)
        self.assertEqual(agg["passed"], 1)
        self.assertEqual(agg["failed"], 3)
        self.assertEqual(agg["with_insufficient_evidence"], 2)   # FULL, NO_GAPS
        self.assertEqual(agg["with_coverage_gaps_section"], 2)   # FULL, NO_ABSTAIN


class TestSerialisationAndRender(unittest.TestCase):
    def test_to_dict_round_trips_keys(self):
        d = ps.check_report(FULL, "full").to_dict()
        for k in ("report_id", "passed", "has_insufficient_evidence",
                  "insufficient_evidence_count", "has_coverage_gaps_section",
                  "has_inconclusive_verdict", "missing_fields"):
            self.assertIn(k, d)
        self.assertTrue(d["passed"])

    def test_render_runs(self):
        results = [ps.check_report(FULL, "full"), ps.check_report(NEITHER, "neither")]
        out = ps.render(results, ps.aggregate(results))
        self.assertIn("R5 PRESENCE CHECK", out)
        self.assertIn("PASS", out)
        self.assertIn("FAIL", out)


class TestCli(unittest.TestCase):
    def test_main_returns_zero_when_all_pass(self):
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "ok.md")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(FULL)
            self.assertEqual(ps.main([p]), 0)

    def test_main_returns_one_when_any_fail(self):
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            good = os.path.join(d, "ok.md")
            bad = os.path.join(d, "bad.md")
            with open(good, "w", encoding="utf-8") as fh:
                fh.write(FULL)
            with open(bad, "w", encoding="utf-8") as fh:
                fh.write(NEITHER)
            self.assertEqual(ps.main([good, bad]), 1)


if __name__ == "__main__":
    unittest.main()

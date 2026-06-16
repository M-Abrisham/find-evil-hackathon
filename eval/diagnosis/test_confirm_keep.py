#!/usr/bin/env python3
"""Unit tests for confirm_keep.py — stdlib unittest, SYNTHETIC fixtures only.

confirm_keep is the candidate->confirmed-KEEP BRIDGE: it CALLS aggregate_failures
(two-proportion CI + classify_vs_floor) and regression_suite (guard non-regression)
and combines them. These tests therefore assert the COMBINATION/decision logic,
not the underlying stats (those have their own suites). Every score JSON is built
in a tmpdir at runtime — no real cases / keys / ground_truth.

Covered (task Step 4):
  (a) clear improvement + zero guard regressions + SYSTEMATIC => CONFIRMED-KEEP, exit 0
  (b) CI straddles 0                                          => NOT-CONFIRMED
  (c) a guard PASS->FAIL                                      => REVERT (even if CI excludes 0)
  (d) missing / empty score-dir                              => conservative NOT-CONFIRMED, no crash
plus: candidate WORSE (CI above 0) is not a KEEP; SYSTEMATIC precondition (GREY /
INDETERMINATE floor block KEEP); the CLI exit-code contract; and an end-to-end
USE-CASE confirm lap.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest

import confirm_keep as ck


# ---------------------------------------------------------------------------
# Synthetic per-round score-dict builders (mirror the REAL scorer to_dict()
# shapes; same approach as test_aggregate_failures / test_regression_suite).
# ---------------------------------------------------------------------------
# Deliberately fake, low-entropy IOC values — not real credentials/tokens.
def scorer_round(*, case="CASE-X", verdict="found", verdict_expected="MALICE",
                 fabrications=None, failures=None, recall=1.0):
    fabrications = fabrications or []
    failures = failures or []
    return {
        "case_id": case,
        "iocs": [],
        "total_findable": 1, "found_findable": 1, "findable_recall": recall,
        "total_iocs": 1, "found_total": 1, "full_recall": recall,
        "fabrications": fabrications, "fabrication_count": len(fabrications),
        "asserted_cidrs": [],
        "verdict_expected": verdict_expected, "verdict": verdict,
        "mitre_present": {}, "mitre_found": 0, "mitre_total": 0,
        "failures": failures,
    }


def presence_round(*, report="r", passed=True):
    return {
        "report_id": report,
        "passed": passed,
        "has_insufficient_evidence": passed,
        "insufficient_evidence_count": 1 if passed else 0,
        "has_coverage_gaps_section": passed,
        "missing_fields": [] if passed else ["INSUFFICIENT_EVIDENCE"],
    }


def write_round(score_dir, case, arm, n, kind, payload):
    """kind in {scorer, score, presence} -> <case>_<arm>_round-<n>.<kind>.json."""
    path = os.path.join(score_dir, f"{case}_{arm}_round-{n}.{kind}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    return path


def write_target_arms(score_dir, *, case="CASE-X",
                      candidate_fail=0, baseline_fail=14, n=20):
    """Write the TARGET-metric campaign: a 'verdict' predicate FAILs when
    verdict != 'found'. Candidate (sift) fails ``candidate_fail`` of n rounds,
    baseline (bare) fails ``baseline_fail`` of n. Default 0/20 vs 14/20 is a
    clear, CI-excludes-0 improvement against a low floor.
    """
    for i in range(1, n + 1):
        cand_v = "not_emitted" if i <= candidate_fail else "found"
        base_v = "not_emitted" if i <= baseline_fail else "found"
        write_round(score_dir, case, "sift", i, "scorer", scorer_round(verdict=cand_v))
        write_round(score_dir, case, "bare", i, "scorer", scorer_round(verdict=base_v))


# A guard registry whose guard's PASS predicate keys off the candidate arm.
GUARD_REGISTRY = {
    "version": 1,
    "guard_cases": [
        {"rule_id": "G31", "rule_summary": "no fab", "case_id": "guard-g31",
         "status": "AVAILABLE", "signal": {"check": "no_fabrication", "source": "scorer"}},
        {"rule_id": "R5", "rule_summary": "presence", "case_id": "guard-r5",
         "status": "AVAILABLE", "signal": {"check": "presence_passed", "source": "presence"}},
    ],
}


def write_registry(path, obj=GUARD_REGISTRY):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)
    return path


def write_clean_guards(gdir, *, arm="sift", g31_fab=False, r5_pass=True):
    fab = ([{"type": "ip_address", "value": "10.10.10.10"}] if g31_fab else [])
    for n in (1, 2, 3):
        write_round(gdir, "guard-g31", arm, n, "scorer", scorer_round(fabrications=fab))
        write_round(gdir, "guard-r5", arm, n, "presence", presence_round(passed=r5_pass))


# ---------------------------------------------------------------------------
# (a) clear improvement + zero guard regressions + SYSTEMATIC => CONFIRMED-KEEP
# ---------------------------------------------------------------------------
class TestConfirmedKeep(unittest.TestCase):
    def test_clear_improvement_systematic_no_regression_confirms(self):
        with tempfile.TemporaryDirectory() as d:
            write_target_arms(d, candidate_fail=0, baseline_fail=14, n=20)
            write_clean_guards(d, arm="sift")
            reg = write_registry(os.path.join(d, "reg.json"))
            res = ck.confirm(d, "verdict", floor_hi=0.10, registry=reg)
            self.assertEqual(res["decision"], ck.CONFIRMED_KEEP)
            self.assertTrue(res["ci_excludes_zero"])
            self.assertEqual(res["guard_regressions"], 0)
            self.assertEqual(res["classification"], "SYSTEMATIC")

    def test_cli_exit_zero_on_confirmed_keep(self):
        with tempfile.TemporaryDirectory() as d:
            write_target_arms(d, candidate_fail=0, baseline_fail=14, n=20)
            write_clean_guards(d, arm="sift")
            reg = write_registry(os.path.join(d, "reg.json"))
            rc = ck.main(["--score-dir", d, "--predicate", "verdict",
                          "--floor-hi", "0.10", "--guard-cases", reg, "--quiet"])
            self.assertEqual(rc, 0)


# ---------------------------------------------------------------------------
# (b) CI straddles 0 => NOT-CONFIRMED
# ---------------------------------------------------------------------------
class TestCiStraddlesZero(unittest.TestCase):
    def test_marginal_difference_not_confirmed(self):
        # 8/20 vs 10/20: difference small, CI straddles 0 -> not confirmed.
        with tempfile.TemporaryDirectory() as d:
            write_target_arms(d, candidate_fail=8, baseline_fail=10, n=20)
            write_clean_guards(d, arm="sift")
            reg = write_registry(os.path.join(d, "reg.json"))
            res = ck.confirm(d, "verdict", floor_hi=0.10, registry=reg)
            self.assertFalse(res["ci_excludes_zero"])
            self.assertEqual(res["decision"], ck.NOT_CONFIRMED)
            self.assertEqual(res["guard_regressions"], 0)  # no regression, just no improvement

    def test_candidate_worse_is_not_keep(self):
        # Candidate fails MORE than baseline -> CI excludes 0 but ABOVE 0 -> NOT an improvement.
        with tempfile.TemporaryDirectory() as d:
            write_target_arms(d, candidate_fail=18, baseline_fail=2, n=20)
            write_clean_guards(d, arm="sift")
            reg = write_registry(os.path.join(d, "reg.json"))
            res = ck.confirm(d, "verdict", floor_hi=0.10, registry=reg)
            self.assertFalse(res["ci_excludes_zero"])     # improving-direction only
            self.assertEqual(res["decision"], ck.NOT_CONFIRMED)


# ---------------------------------------------------------------------------
# (c) a guard PASS->FAIL => REVERT (even if the target CI excludes 0)
# ---------------------------------------------------------------------------
class TestGuardRegressionReverts(unittest.TestCase):
    def test_guard_regression_forces_revert_despite_improvement(self):
        with tempfile.TemporaryDirectory() as d:
            # Strong, real target improvement...
            write_target_arms(d, candidate_fail=0, baseline_fail=14, n=20)
            # ...but the candidate arm now FABRICATES on the G31 guard case.
            write_clean_guards(d, arm="sift", g31_fab=True)
            reg = write_registry(os.path.join(d, "reg.json"))
            # Guard baseline says G31 used to PASS -> now FAIL is a regression.
            gbase = os.path.join(d, "guard_baseline.json")
            with open(gbase, "w", encoding="utf-8") as fh:
                json.dump({"arm": "sift", "results": {"G31": "PASS", "R5": "PASS"}}, fh)
            res = ck.confirm(d, "verdict", floor_hi=0.10, registry=reg,
                             guard_baseline=gbase)
            self.assertTrue(res["ci_excludes_zero"])      # the target IMPROVED
            self.assertEqual(res["classification"], "SYSTEMATIC")
            self.assertGreaterEqual(res["guard_regressions"], 1)
            self.assertEqual(res["decision"], ck.REVERT)  # regression OVERRIDES the improvement

    def test_cli_exit_nonzero_on_revert(self):
        with tempfile.TemporaryDirectory() as d:
            write_target_arms(d, candidate_fail=0, baseline_fail=14, n=20)
            write_clean_guards(d, arm="sift", g31_fab=True)
            reg = write_registry(os.path.join(d, "reg.json"))
            gbase = os.path.join(d, "guard_baseline.json")
            with open(gbase, "w", encoding="utf-8") as fh:
                json.dump({"arm": "sift", "results": {"G31": "PASS", "R5": "PASS"}}, fh)
            rc = ck.main(["--score-dir", d, "--predicate", "verdict", "--floor-hi", "0.10",
                          "--guard-cases", reg, "--guard-baseline", gbase, "--quiet"])
            self.assertEqual(rc, 1)


# ---------------------------------------------------------------------------
# (d) missing / empty score-dir => conservative NOT-CONFIRMED, never crash
# ---------------------------------------------------------------------------
class TestConservativeOnMissingInput(unittest.TestCase):
    def test_nonexistent_dir(self):
        res = ck.confirm("/no/such/dir/at/all", "verdict", floor_hi=0.10)
        self.assertEqual(res["decision"], ck.NOT_CONFIRMED)
        self.assertIsNone(res["guard_regressions"])

    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as d:
            res = ck.confirm(d, "verdict", floor_hi=0.10)
            self.assertEqual(res["decision"], ck.NOT_CONFIRMED)

    def test_only_one_arm_present(self):
        with tempfile.TemporaryDirectory() as d:
            # Candidate arm only; no baseline arm to compare against.
            for i in range(1, 21):
                write_round(d, "CASE-X", "sift", i, "scorer", scorer_round(verdict="found"))
            res = ck.confirm(d, "verdict", floor_hi=0.10)
            self.assertEqual(res["decision"], ck.NOT_CONFIRMED)
            self.assertFalse(res["ci_excludes_zero"])

    def test_missing_floor_is_indeterminate_not_keep(self):
        # No --floor-hi: classify_vs_floor returns INDETERMINATE -> never CONFIRMED.
        with tempfile.TemporaryDirectory() as d:
            write_target_arms(d, candidate_fail=0, baseline_fail=14, n=20)
            write_clean_guards(d, arm="sift")
            reg = write_registry(os.path.join(d, "reg.json"))
            res = ck.confirm(d, "verdict", floor_hi=None, registry=reg)
            self.assertTrue(res["ci_excludes_zero"])      # target still improved
            self.assertEqual(res["classification"], "INDETERMINATE")
            self.assertEqual(res["decision"], ck.NOT_CONFIRMED)  # conservative

    def test_cli_exit_nonzero_on_missing(self):
        rc = ck.main(["--score-dir", "/no/such/dir", "--predicate", "verdict",
                      "--floor-hi", "0.10", "--quiet"])
        self.assertEqual(rc, 1)


# ---------------------------------------------------------------------------
# SYSTEMATIC precondition: a GREY baseline failure blocks KEEP even with an
# improving CI + clean guards (you can't "confirm fixing" a noise-band failure).
# ---------------------------------------------------------------------------
class TestSystematicPrecondition(unittest.TestCase):
    def test_grey_baseline_blocks_keep(self):
        with tempfile.TemporaryDirectory() as d:
            # baseline 2/20 = 10%; against floor_hi=0.10 the Wilson CI straddles
            # the floor -> GREY (mirrors test_aggregate_failures.test_grey).
            # candidate 0/20 -> still an improving CI, but the baseline isn't SYSTEMATIC.
            write_target_arms(d, candidate_fail=0, baseline_fail=2, n=20)
            write_clean_guards(d, arm="sift")
            reg = write_registry(os.path.join(d, "reg.json"))
            res = ck.confirm(d, "verdict", floor_hi=0.10, registry=reg)
            self.assertEqual(res["classification"], "GREY")
            self.assertEqual(res["decision"], ck.NOT_CONFIRMED)


# ---------------------------------------------------------------------------
# USE-CASE: an end-to-end Stage-4 confirm lap. Operator promotes a candidate
# edit; confirm_keep certifies it (improving CI + SYSTEMATIC baseline + zero
# guard regressions) and returns exit 0 so run_loop may (separately) append the
# ledger. confirm_keep itself only RECORDS the verdict.
# ---------------------------------------------------------------------------
class TestUseCaseConfirmLap(unittest.TestCase):
    def test_full_confirm_lap_records_keep(self):
        with tempfile.TemporaryDirectory() as d:
            write_target_arms(d, candidate_fail=1, baseline_fail=15, n=20)
            write_clean_guards(d, arm="sift")
            reg = write_registry(os.path.join(d, "reg.json"))
            out = os.path.join(d, "confirm.json")
            rc = ck.main(["--score-dir", d, "--predicate", "verdict", "--floor-hi", "0.10",
                          "--guard-cases", reg, "-o", out, "--quiet"])
            self.assertEqual(rc, 0)
            with open(out) as fh:
                saved = json.load(fh)
            self.assertEqual(saved["decision"], ck.CONFIRMED_KEEP)
            self.assertEqual(saved["tool"], "confirm_keep")
            # ADVISORY boundary is recorded in the result note.
            self.assertIn("run_loop", saved["note"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

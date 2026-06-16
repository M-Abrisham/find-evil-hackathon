#!/usr/bin/env python3
"""Unit tests for regression_suite.py — stdlib unittest, SYNTHETIC fixtures only.

Covers: registry load/validate, each pass-signal predicate, score-file globbing
by the export BASE convention, monotonic non-regression (the KEEP gate), the
PENDING discipline (never invent), edge/failure cases, and a realistic
end-to-end USE-CASE scenario (an ablation lap that re-introduces a regression).

No real cases / keys / ground_truth — all score JSONs are built in a tmpdir at
runtime. The verdict tokens here ("MALICE"/"NON_MALICE"/etc.) are contract
vocabulary, not secrets.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest

import regression_suite as rs


# ---------------------------------------------------------------------------
# Synthetic score-JSON builders (mirror the REAL scorer to_dict() shapes).
# ---------------------------------------------------------------------------
def scorer_json(case_id="c", fabrications=None, failures=None,
                verdict="found", verdict_expected="MALICE"):
    fabrications = fabrications or []
    failures = failures or []
    return {
        "case_id": case_id,
        "iocs": [],
        "total_findable": 1, "found_findable": 1, "findable_recall": 1.0,
        "total_iocs": 1, "found_total": 1, "full_recall": 1.0,
        "fabrications": fabrications, "fabrication_count": len(fabrications),
        "asserted_cidrs": [],
        "verdict_expected": verdict_expected, "verdict": verdict,
        "mitre_present": {}, "mitre_found": 0, "mitre_total": 0,
        "failures": failures,
    }


def score_json(case_id="c", unbacked=None, bucket_recall=None,
               category_match=True):
    unbacked = unbacked or []
    per_bucket = {}
    if bucket_recall is not None:
        for b, r in bucket_recall.items():
            per_bucket[b] = {"matched": 1, "total": 1, "recall": r}
    return {
        "case_id": case_id,
        "classification": {"category_match": category_match},
        "evidence": {"recall": 1.0, "per_bucket": per_bucket,
                     "false_positive_findings": []},
        "hallucination": {"total_findings": len(unbacked),
                          "unbacked_findings": len(unbacked),
                          "hallucination_rate": 0.0,
                          "unbacked_list": unbacked},
        "headline": {},
    }


def presence_json(report_id="r", passed=True):
    return {
        "report_id": report_id,
        "passed": passed,
        "has_insufficient_evidence": passed,
        "insufficient_evidence_count": 1 if passed else 0,
        "has_coverage_gaps_section": passed,
        "has_inconclusive_verdict": True,
        "missing_fields": [] if passed else ["INSUFFICIENT_EVIDENCE"],
    }


def write_round(score_dir, case_id, arm, n, source, payload):
    suffix = rs.SOURCE_SUFFIX[source]
    path = os.path.join(score_dir, f"{case_id}_{arm}_round-{n}.{suffix}")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    return path


# A minimal AVAILABLE registry for the runner tests (one guard per source kind).
AVAILABLE_REGISTRY = {
    "version": 1,
    "guard_cases": [
        {"rule_id": "G31", "rule_summary": "no fab", "case_id": "guard-g31",
         "status": "AVAILABLE", "signal": {"check": "no_fabrication", "source": "scorer"}},
        {"rule_id": "R5", "rule_summary": "presence", "case_id": "guard-r5",
         "status": "AVAILABLE", "signal": {"check": "presence_passed", "source": "presence"}},
        {"rule_id": "G20", "rule_summary": "no false malice", "case_id": "guard-g20",
         "status": "AVAILABLE",
         "signal": {"check": "verdict_class", "source": "scorer", "args": ["non_malicious"]}},
        {"rule_id": "PEND1", "rule_summary": "not built", "case_id": "guard-pending",
         "status": "PENDING", "signal": {"check": "no_fabrication", "source": "scorer"}},
    ],
}


def write_registry(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)


# ---------------------------------------------------------------------------
# Predicate-level tests (the frozen binary checks over real shapes)
# ---------------------------------------------------------------------------
class TestSignalPredicates(unittest.TestCase):
    def test_no_fabrication_pass_and_fail(self):
        self.assertTrue(rs._sig_no_fabrication(scorer_json(fabrications=[])))
        self.assertFalse(rs._sig_no_fabrication(
            scorer_json(fabrications=[{"type": "ip_address", "value": "203.0.113.9"}])))

    def test_no_fabrication_missing_key_is_not_pass(self):
        # Defensive: a schema-shifted score with no fabrication_count is NOT a clean pass.
        self.assertFalse(rs._sig_no_fabrication({"case_id": "c"}))

    def test_no_hallucination_pass_and_fail(self):
        self.assertTrue(rs._sig_no_hallucination(score_json(unbacked=[])))
        self.assertFalse(rs._sig_no_hallucination(
            score_json(unbacked=[{"id": "F1", "claim": "uncited"}])))

    def test_no_hallucination_missing_section_is_not_pass(self):
        self.assertFalse(rs._sig_no_hallucination({"case_id": "c"}))

    def test_ioc_not_in_failures(self):
        ok = scorer_json(failures=[])
        bad = scorer_json(failures=[{"type": "windows_sid", "value": "S-1-5-21-X"}])
        self.assertTrue(rs._sig_ioc_not_in_failures(ok, "S-1-5-21-X"))
        self.assertFalse(rs._sig_ioc_not_in_failures(bad, "S-1-5-21-X"))

    def test_verdict_class_pass_and_fail(self):
        self.assertTrue(rs._sig_verdict_class(
            scorer_json(verdict="found"), "non_malicious"))
        self.assertFalse(rs._sig_verdict_class(
            scorer_json(verdict="not_emitted"), "non_malicious"))

    def test_verdict_class_unknown_class_is_not_pass(self):
        self.assertFalse(rs._sig_verdict_class(scorer_json(verdict="found"), "bogus"))

    def test_presence_passed(self):
        self.assertTrue(rs._sig_presence_passed(presence_json(passed=True)))
        self.assertFalse(rs._sig_presence_passed(presence_json(passed=False)))
        self.assertFalse(rs._sig_presence_passed({}))  # missing => not pass

    def test_bucket_recall_full(self):
        self.assertTrue(rs._sig_bucket_recall_full(
            score_json(bucket_recall={"persistence": 1.0}), "persistence"))
        self.assertFalse(rs._sig_bucket_recall_full(
            score_json(bucket_recall={"persistence": 0.0}), "persistence"))
        self.assertFalse(rs._sig_bucket_recall_full(
            score_json(bucket_recall={"other": 1.0}), "persistence"))  # bucket absent


# ---------------------------------------------------------------------------
# Registry tests
# ---------------------------------------------------------------------------
class TestRegistry(unittest.TestCase):
    def test_shipped_registry_loads_and_validates(self):
        # The real shipped registry shipped alongside the tool must validate.
        here = os.path.dirname(os.path.abspath(rs.__file__))
        guards = rs.load_registry(os.path.join(here, "guard_cases.json"))
        ids = {g.rule_id for g in guards}
        # All six shipped rules (+ G31b cross-check) present.
        for rid in ("G31", "G20", "G25", "R3", "R5", "G28"):
            self.assertIn(rid, ids, f"shipped rule {rid} missing a guard case")
        # Seeded rules are PENDING (not invented).
        self.assertTrue(all(g.status == rs.STATUS_PENDING for g in guards))

    def test_duplicate_rule_id_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            reg = os.path.join(d, "reg.json")
            write_registry(reg, {"version": 1, "guard_cases": [
                {"rule_id": "X", "case_id": "a", "status": "PENDING",
                 "signal": {"check": "no_fabrication", "source": "scorer"}},
                {"rule_id": "X", "case_id": "b", "status": "PENDING",
                 "signal": {"check": "no_fabrication", "source": "scorer"}},
            ]})
            with self.assertRaises(ValueError):
                rs.load_registry(reg)

    def test_unknown_check_or_source_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            reg = os.path.join(d, "reg.json")
            write_registry(reg, {"version": 1, "guard_cases": [
                {"rule_id": "X", "case_id": "a", "status": "PENDING",
                 "signal": {"check": "nope", "source": "scorer"}},
            ]})
            with self.assertRaises(ValueError):
                rs.load_registry(reg)


# ---------------------------------------------------------------------------
# Score-file globbing (export BASE convention)
# ---------------------------------------------------------------------------
class TestRoundGlobbing(unittest.TestCase):
    def test_paths_sorted_by_round_and_filtered_by_arm_source(self):
        with tempfile.TemporaryDirectory() as d:
            write_round(d, "gc", "sift", 2, "scorer", scorer_json())
            write_round(d, "gc", "sift", 10, "scorer", scorer_json())
            write_round(d, "gc", "sift", 1, "scorer", scorer_json())
            write_round(d, "gc", "bare", 1, "scorer", scorer_json())   # other arm
            write_round(d, "gc", "sift", 1, "presence", presence_json())  # other source
            paths = rs.round_score_paths(d, "gc", "sift", "scorer")
            self.assertEqual([os.path.basename(p) for p in paths],
                             ["gc_sift_round-1.scorer.json",
                              "gc_sift_round-2.scorer.json",
                              "gc_sift_round-10.scorer.json"])  # numeric, not lexical

    def test_missing_dir_returns_empty(self):
        self.assertEqual(rs.round_score_paths("/no/such/dir", "x", "sift", "scorer"), [])


# ---------------------------------------------------------------------------
# Runner / monotonic non-regression
# ---------------------------------------------------------------------------
class TestRunner(unittest.TestCase):
    def _setup(self, d, *, g31_fab=False, r5_pass=True, g20_found=True):
        write_registry(os.path.join(d, "reg.json"), AVAILABLE_REGISTRY)
        sdir = tempfile.mkdtemp(prefix="scores_", dir=d)
        fab = [{"type": "ip_address", "value": "203.0.113.5"}] if g31_fab else []
        for n in (1, 2, 3):
            write_round(sdir, "guard-g31", "sift", n, "scorer", scorer_json(fabrications=fab))
            write_round(sdir, "guard-r5", "sift", n, "presence", presence_json(passed=r5_pass))
            write_round(sdir, "guard-g20", "sift", n, "scorer",
                        scorer_json(verdict="found" if g20_found else "not_emitted",
                                    verdict_expected="NON_MALICE"))
        return os.path.join(d, "reg.json"), sdir

    def test_all_pass_clean_no_baseline(self):
        with tempfile.TemporaryDirectory() as d:
            reg, sdir = self._setup(d)
            guards = rs.load_registry(reg)
            run = rs.run_suite(guards, sdir, "sift", baseline={})
            results = {o.rule_id: o.result for o in run.outcomes}
            self.assertEqual(results["G31"], "PASS")
            self.assertEqual(results["R5"], "PASS")
            self.assertEqual(results["G20"], "PASS")
            self.assertEqual(results["PEND1"], "PENDING")
            self.assertEqual(run.pending, ["PEND1"])
            self.assertFalse(run.blocked_keep)

    def test_pending_never_scored_even_with_files_present(self):
        with tempfile.TemporaryDirectory() as d:
            reg, sdir = self._setup(d)
            # drop files that WOULD match the pending guard; must still be ignored.
            write_round(sdir, "guard-pending", "sift", 1, "scorer", scorer_json())
            guards = rs.load_registry(reg)
            run = rs.run_suite(guards, sdir, "sift", baseline={})
            pend = next(o for o in run.outcomes if o.rule_id == "PEND1")
            self.assertEqual(pend.result, "PENDING")
            self.assertEqual(pend.rounds_total, 0)

    def test_single_failing_round_fails_the_guard(self):
        # Monotonic guard: not a rate — one bad round of three => FAIL.
        with tempfile.TemporaryDirectory() as d:
            reg, sdir = self._setup(d)
            # overwrite round-2 of g31 with a fabrication.
            write_round(sdir, "guard-g31", "sift", 2, "scorer",
                        scorer_json(fabrications=[{"type": "ip_address", "value": "198.51.100.7"}]))
            guards = rs.load_registry(reg)
            run = rs.run_suite(guards, sdir, "sift", baseline={})
            g31 = next(o for o in run.outcomes if o.rule_id == "G31")
            self.assertEqual(g31.result, "FAIL")
            self.assertEqual(g31.rounds_passed, 2)
            self.assertEqual(g31.rounds_total, 3)
            self.assertIn("round-2", g31.detail)

    def test_missing_available_guard_is_not_pass(self):
        with tempfile.TemporaryDirectory() as d:
            reg, _ = self._setup(d)
            empty = os.path.join(d, "empty")
            os.makedirs(empty)
            guards = rs.load_registry(reg)
            run = rs.run_suite(guards, empty, "sift", baseline={})
            g31 = next(o for o in run.outcomes if o.rule_id == "G31")
            self.assertEqual(g31.result, "MISSING")
            self.assertFalse(run.blocked_keep)  # no baseline PASS => not yet a regression

    def test_regression_blocks_keep(self):
        # baseline says G31 PASSED; now it FAILS => regression => block keep, exit nonzero.
        with tempfile.TemporaryDirectory() as d:
            reg, sdir = self._setup(d, g31_fab=True)  # g31 now fabricates
            guards = rs.load_registry(reg)
            baseline = {"G31": "PASS", "R5": "PASS", "G20": "PASS"}
            run = rs.run_suite(guards, sdir, "sift", baseline=baseline)
            self.assertTrue(run.blocked_keep)
            self.assertEqual(len(run.regressions), 1)
            self.assertEqual(run.regressions[0]["rule_id"], "G31")
            self.assertEqual(run.regressions[0]["now"], "FAIL")

    def test_baseline_missing_to_now_pass_is_new_pass_not_regression(self):
        with tempfile.TemporaryDirectory() as d:
            reg, sdir = self._setup(d)
            guards = rs.load_registry(reg)
            run = rs.run_suite(guards, sdir, "sift", baseline={})  # nothing prior
            self.assertIn("G31", run.new_passes)
            self.assertFalse(run.blocked_keep)

    def test_update_baseline_only_when_clean(self):
        with tempfile.TemporaryDirectory() as d:
            reg, sdir = self._setup(d)
            ledger = os.path.join(d, "ledger.json")
            rc = rs.main(["--registry", reg, "--score-dir", sdir, "--arm", "sift",
                          "--update-baseline", ledger])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(ledger))
            with open(ledger) as fh:
                saved = json.load(fh)
            self.assertEqual(saved["results"]["G31"], "PASS")

            # Now a regression run with a baseline: ledger must NOT be overwritten.
            reg2, sdir2 = self._setup(d, g31_fab=True)
            rc2 = rs.main(["--registry", reg2, "--score-dir", sdir2, "--arm", "sift",
                           "--baseline", ledger, "--update-baseline", ledger])
            self.assertEqual(rc2, 1)  # blocked
            with open(ledger) as fh:
                still = json.load(fh)
            self.assertEqual(still["results"]["G31"], "PASS")  # unchanged


# ---------------------------------------------------------------------------
# USE-CASE: a realistic end-to-end Stage-4 ablation lap.
# Operator removes a rule, re-runs the guard suite at N=3/round, and the suite
# catches that the removal re-introduced the failure the rule prevented (Stage
# 5.1 "remove the dual-use presumption -> re-test the fabrication case"),
# blocking KEEP and forcing a REVERT.
# ---------------------------------------------------------------------------
class TestUseCaseAblationLap(unittest.TestCase):
    def test_remove_g20_reintroduces_false_malice_and_blocks_keep(self):
        with tempfile.TemporaryDirectory() as d:
            reg = os.path.join(d, "reg.json")
            write_registry(reg, AVAILABLE_REGISTRY)
            guards = rs.load_registry(reg)

            # --- Lap 0: baseline campaign, all guards pass. Freeze the ledger.
            base_scores = os.path.join(d, "scores_lap0")
            os.makedirs(base_scores)
            for n in (1, 2, 3):
                write_round(base_scores, "guard-g31", "sift", n, "scorer", scorer_json())
                write_round(base_scores, "guard-r5", "sift", n, "presence", presence_json(True))
                write_round(base_scores, "guard-g20", "sift", n, "scorer",
                            scorer_json(verdict="found", verdict_expected="NON_MALICE"))
            ledger = os.path.join(d, "baseline.json")
            rc0 = rs.main(["--registry", reg, "--score-dir", base_scores, "--arm", "sift",
                           "--update-baseline", ledger])
            self.assertEqual(rc0, 0)

            # --- Lap 1: operator REMOVEs G20 (dual-use presumption). Re-run the
            # SAME guard cases. The malicious-looking-benign guard now mis-fires
            # a false MALICE verdict (verdict != expected NON_MALICE class).
            lap1_scores = os.path.join(d, "scores_lap1")
            os.makedirs(lap1_scores)
            for n in (1, 2, 3):
                write_round(lap1_scores, "guard-g31", "sift", n, "scorer", scorer_json())
                write_round(lap1_scores, "guard-r5", "sift", n, "presence", presence_json(True))
                # G20 guard regresses: report now says MALICE on the benign case.
                write_round(lap1_scores, "guard-g20", "sift", n, "scorer",
                            scorer_json(verdict="not_emitted", verdict_expected="NON_MALICE"))

            run = rs.run_suite(rs.load_registry(reg), lap1_scores, "sift",
                               baseline=rs.load_baseline(ledger))
            # The suite catches the regression and blocks KEEP -> operator REVERTs.
            self.assertTrue(run.blocked_keep)
            self.assertEqual([r["rule_id"] for r in run.regressions], ["G20"])
            g31 = next(o for o in run.outcomes if o.rule_id == "G31")
            self.assertEqual(g31.result, "PASS")  # unrelated guards stay green

            # The CLI surfaces it as a nonzero gate exit.
            rc1 = rs.main(["--registry", reg, "--score-dir", lap1_scores, "--arm", "sift",
                           "--baseline", ledger])
            self.assertEqual(rc1, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)

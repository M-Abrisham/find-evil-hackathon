#!/usr/bin/env python3
"""Unit tests for aggregate_failures.py — stdlib unittest, SYNTHETIC fixtures only.

Covers: Wilson math (incl. 0/n and n/n edges), two-proportion test, schema
detection, all FAIL predicates, the INVALID-RUN sidecar filter, same-signature
clustering, classification vs floor, AND a realistic end-to-end USE-CASE test
(score a 5x5 batch -> aggregate -> SIFT-WORSE verdict with a clustered correlated
event). NO real cases / keys / ground_truth — every value below is invented.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest

import aggregate_failures as agg


# ---------------------------------------------------------------------------
# Synthetic per-round score-dict builders (mirror the REAL scorer shapes).
# ---------------------------------------------------------------------------
# Fake IOC values — deliberately NOT real credentials/high-entropy tokens.
FAKE_SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
FAKE_IP = "10.10.10.10"
FAKE_HASH = "deadbeefdeadbeefdeadbeefdeadbeef"  # 32 hex, obviously fake/repeating


def scorer_round(*, case="CASE-X", recall=1.0, failures=None, fabrications=None,
                 verdict="found", verdict_expected="MALICE"):
    failures = failures or []
    fabrications = fabrications or []
    return {
        "case_id": case,
        "iocs": [],
        "total_findable": 3,
        "found_findable": 3 if recall == 1.0 else int(round(3 * (recall or 0))),
        "findable_recall": recall,
        "total_iocs": 3,
        "found_total": 3,
        "full_recall": recall,
        "failures": failures,
        "fabrications": fabrications,
        "fabrication_count": len(fabrications),
        "asserted_cidrs": [],
        "verdict_expected": verdict_expected,
        "verdict": verdict,
        "mitre_present": {"T1059": True},
        "mitre_found": 1,
        "mitre_total": 1,
    }


def score_round(*, case="CASE-X", category_match=True, bucket="persistence",
                bucket_recall=1.0, missed=None, unbacked=None, fps=None):
    missed = missed or []
    unbacked = unbacked or []
    fps = fps or []
    return {
        "case_id": case,
        "classification": {
            "category_match": category_match,
            "truth_category_canonical": "Malware",
            "predicted_category_canonical": "Malware" if category_match else "Benign",
        },
        "evidence": {
            "recall": bucket_recall,
            "false_positive_findings": fps,
            "false_positive_rate": 0.0 if not fps else 0.2,
            "per_bucket": {bucket: {"matched": 0 if bucket_recall == 0 else 2,
                                    "total": 2, "recall": bucket_recall}},
            "missed_evidence": {bucket: missed} if missed else {},
        },
        "hallucination": {
            "total_findings": 5,
            "unbacked_findings": len(unbacked),
            "hallucination_rate": len(unbacked) / 5.0,
            "unbacked_list": [{"id": str(i), "claim": c} for i, c in enumerate(unbacked)],
        },
        "headline": {"category_match": category_match},
    }


def presence_round(*, report="r", passed=True, missing=None):
    missing = missing or []
    return {
        "report_id": report,
        "passed": passed,
        "has_insufficient_evidence": passed or "INSUFFICIENT_EVIDENCE" not in missing,
        "insufficient_evidence_count": 1 if passed else 0,
        "has_coverage_gaps_section": passed,
        "missing_fields": missing,
    }


def _write(d, name, payload):
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    return p


# ---------------------------------------------------------------------------
# Statistics.
# ---------------------------------------------------------------------------
class TestWilson(unittest.TestCase):
    def test_zero_of_n_behaves(self):
        lo, hi = agg.wilson_interval(0, 20)
        self.assertEqual(lo, 0.0)
        self.assertGreater(hi, 0.0)
        self.assertLess(hi, 0.20)  # 0/20 upper bound ~16%

    def test_n_of_n_behaves(self):
        lo, hi = agg.wilson_interval(20, 20)
        self.assertEqual(hi, 1.0)
        self.assertGreater(lo, 0.80)

    def test_known_value_3_of_5(self):
        # 3/5 = 0.6; Wilson 95% (z=1.95996) = [0.23072, 0.88238].
        lo, hi = agg.wilson_interval(3, 5)
        self.assertAlmostEqual(lo, 0.23072, places=4)
        self.assertAlmostEqual(hi, 0.88238, places=4)

    def test_n_zero_returns_none(self):
        self.assertEqual(agg.wilson_interval(0, 0), (None, None))


class TestTwoProportion(unittest.TestCase):
    def test_clear_difference_excludes_zero(self):
        # 12/20 vs 1/20: strong, CI should exclude 0.
        r = agg.two_proportion_z(12, 20, 1, 20)
        self.assertGreater(r["diff"], 0)
        self.assertTrue(r["ci_excludes_zero"])
        self.assertLess(r["p_value"], 0.001)

    def test_no_difference_includes_zero(self):
        r = agg.two_proportion_z(5, 20, 5, 20)
        self.assertEqual(r["diff"], 0.0)
        self.assertFalse(r["ci_excludes_zero"])
        self.assertAlmostEqual(r["p_value"], 1.0, places=6)

    def test_small_n_overlap(self):
        # 3/5 vs 1/5: difference exists but CI should NOT exclude 0 (under-powered).
        r = agg.two_proportion_z(3, 5, 1, 5)
        self.assertFalse(r["ci_excludes_zero"])

    def test_zero_denominator(self):
        r = agg.two_proportion_z(0, 0, 1, 5)
        self.assertIsNone(r["diff"])


# ---------------------------------------------------------------------------
# Schema detection.
# ---------------------------------------------------------------------------
class TestSchemaDetect(unittest.TestCase):
    def test_scorer(self):
        self.assertEqual(agg.detect_schema(scorer_round()), agg.SCHEMA_SCORER)

    def test_score(self):
        self.assertEqual(agg.detect_schema(score_round()), agg.SCHEMA_SCORE)

    def test_presence(self):
        self.assertEqual(agg.detect_schema(presence_round()), agg.SCHEMA_PRESENCE)

    def test_unknown_raises(self):
        with self.assertRaises(ValueError):
            agg.detect_schema({"foo": "bar"})


# ---------------------------------------------------------------------------
# Predicates.
# ---------------------------------------------------------------------------
class TestPredicates(unittest.TestCase):
    def test_findable_recall_pass_and_fail(self):
        ok, sig = agg._fail_findable_recall(scorer_round(recall=1.0))
        self.assertFalse(ok)
        bad, sig = agg._fail_findable_recall(
            scorer_round(recall=0.66, failures=[{"type": "sid", "value": FAKE_SID}]))
        self.assertTrue(bad)
        self.assertIn(FAKE_SID, sig)

    def test_findable_recall_none_is_unscorable(self):
        failed, sig = agg._fail_findable_recall(scorer_round(recall=None))
        self.assertIsNone(failed)  # BAD-CASE signal -> excluded

    def test_specific_ioc(self):
        failed, sig = agg._fail_specific_ioc(
            scorer_round(failures=[{"type": "sid", "value": FAKE_SID}]),
            ioc_value=FAKE_SID)
        self.assertTrue(failed)
        clean, _ = agg._fail_specific_ioc(scorer_round(), ioc_value=FAKE_SID)
        self.assertFalse(clean)

    def test_specific_ioc_requires_value(self):
        with self.assertRaises(ValueError):
            agg._fail_specific_ioc(scorer_round())

    def test_verdict_not_emitted(self):
        failed, sig = agg._fail_verdict(scorer_round(verdict="not_emitted"))
        self.assertTrue(failed)
        self.assertIn("expected=MALICE", sig)
        ok, _ = agg._fail_verdict(scorer_round(verdict="found"))
        self.assertFalse(ok)

    def test_fabrication(self):
        failed, sig = agg._fail_fabrication(
            scorer_round(fabrications=[{"type": "ip", "value": FAKE_IP}]))
        self.assertTrue(failed)
        self.assertIn(FAKE_IP, sig)

    def test_category(self):
        failed, sig = agg._fail_category(score_round(category_match=False))
        self.assertTrue(failed)
        ok, _ = agg._fail_category(score_round(category_match=True))
        self.assertFalse(ok)

    def test_bucket_recall(self):
        failed, sig = agg._fail_bucket_recall(
            score_round(bucket="lateral", bucket_recall=0.0, missed=["psexec"]),
            bucket="lateral")
        self.assertTrue(failed)
        self.assertIn("psexec", sig)
        ok, _ = agg._fail_bucket_recall(score_round(bucket="lateral", bucket_recall=1.0),
                                        bucket="lateral")
        self.assertFalse(ok)

    def test_bucket_recall_missing_bucket_unscorable(self):
        failed, _ = agg._fail_bucket_recall(score_round(bucket="lateral"), bucket="nonexist")
        self.assertIsNone(failed)

    def test_hallucination(self):
        failed, sig = agg._fail_hallucination(score_round(unbacked=["claim A"]))
        self.assertTrue(failed)
        self.assertIn("claim A", sig)
        ok, _ = agg._fail_hallucination(score_round(unbacked=[]))
        self.assertFalse(ok)

    def test_false_positive(self):
        failed, sig = agg._fail_false_positive(score_round(fps=["spurious finding"]))
        self.assertTrue(failed)
        ok, _ = agg._fail_false_positive(score_round(fps=[]))
        self.assertFalse(ok)

    def test_presence(self):
        failed, sig = agg._fail_presence(presence_round(passed=False,
                                                        missing=["INSUFFICIENT_EVIDENCE"]))
        self.assertTrue(failed)
        self.assertIn("INSUFFICIENT_EVIDENCE", sig)
        ok, _ = agg._fail_presence(presence_round(passed=True))
        self.assertFalse(ok)


# ---------------------------------------------------------------------------
# INVALID-RUN sidecar filter (Stage 1.3a).
# ---------------------------------------------------------------------------
class TestInvalidFilter(unittest.TestCase):
    def test_none_captured_plus_stderr(self):
        with tempfile.TemporaryDirectory() as d:
            base = "CASE-X_sift_round-1"
            with open(os.path.join(d, f"{base}.summary.md"), "w") as fh:
                fh.write("findings: (none captured)\n")
            with open(os.path.join(d, f"{base}.agent.stderr"), "w") as fh:
                fh.write("Traceback: boom\n")
            reason = agg.invalid_reason_for(base, d)
            self.assertIsNotNone(reason)
            self.assertIn("RUN/CLI failure", reason)

    def test_network_marker(self):
        with tempfile.TemporaryDirectory() as d:
            base = "CASE-X_sift_round-2"
            open(os.path.join(d, f"{base}.network-needed"), "w").close()
            self.assertIn("egress", agg.invalid_reason_for(base, d))

    def test_clean_round_is_valid(self):
        with tempfile.TemporaryDirectory() as d:
            base = "CASE-X_sift_round-3"
            with open(os.path.join(d, f"{base}.summary.md"), "w") as fh:
                fh.write("findings captured: 4\n")
            self.assertIsNone(agg.invalid_reason_for(base, d))


# ---------------------------------------------------------------------------
# Loader: scorer.py raw stdout with the '--- JSON ---' delimiter + bundle.
# ---------------------------------------------------------------------------
class TestLoader(unittest.TestCase):
    def test_raw_scorer_stdout(self):
        with tempfile.TemporaryDirectory() as d:
            raw = ("case  findable_recall ...\nhuman render here\n\n--- JSON ---\n"
                   + json.dumps({"cases": [scorer_round(case="CASE-X")],
                                 "aggregate": {"findable_recall_micro": 1.0}}))
            p = os.path.join(d, "CASE-X_sift_round-1.scorer.json")
            with open(p, "w") as fh:
                fh.write(raw)
            payloads = agg.load_round_payloads(p)
            self.assertEqual(len(payloads), 1)
            self.assertEqual(payloads[0]["case_id"], "CASE-X")

    def test_bundle_multiple_cases(self):
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "B_sift_round-1.scorer.json",
                       {"cases": [scorer_round(case="A"), scorer_round(case="B")],
                        "aggregate": {}})
            payloads = agg.load_round_payloads(p)
            self.assertEqual(len(payloads), 2)


# ---------------------------------------------------------------------------
# Clustering (Stage 1.5).
# ---------------------------------------------------------------------------
class TestClustering(unittest.TestCase):
    def test_identical_signature_collapses(self):
        # 3 failing rounds, all the SAME missing IOC => clustered_f == 1.
        recs = []
        for n in range(1, 4):
            r = agg.RoundRecord(case_id="C", arm="sift", round_n=n, path="x",
                                schema=agg.SCHEMA_SCORER,
                                payload=scorer_round(recall=0.66,
                                                     failures=[{"type": "sid", "value": FAKE_SID}]))
            r.failed = True
            r.signature = f"missing:sid={FAKE_SID}"
            recs.append(r)
        # 2 clean rounds.
        for n in range(4, 6):
            r = agg.RoundRecord(case_id="C", arm="sift", round_n=n, path="x",
                                schema=agg.SCHEMA_SCORER, payload=scorer_round())
            r.failed = False
            recs.append(r)
        ar = agg.aggregate_arm("sift", recs)
        self.assertEqual(ar.f, 3)
        self.assertEqual(ar.distinct_signatures, 1)
        self.assertEqual(ar.clustered_f, 1)  # 3 correlated -> 1 event


# ---------------------------------------------------------------------------
# Classification vs floor (Stage 1.4).
# ---------------------------------------------------------------------------
class TestClassify(unittest.TestCase):
    def _arm(self, f, n):
        recs = []
        for i in range(n):
            r = agg.RoundRecord(case_id="C", arm="sift", round_n=i, path="x",
                                schema=agg.SCHEMA_SCORER, payload=scorer_round())
            r.failed = i < f
            r.signature = "sig" if i < f else None
            recs.append(r)
        return agg.aggregate_arm("sift", recs)

    def test_systematic(self):
        ar = self._arm(12, 20)  # 60%
        c = agg.classify_vs_floor(ar, floor_hi=0.10)
        self.assertEqual(c["label"], "SYSTEMATIC")

    def test_stochastic(self):
        ar = self._arm(0, 20)
        c = agg.classify_vs_floor(ar, floor_hi=0.20)
        self.assertEqual(c["label"], "STOCHASTIC")

    def test_grey(self):
        ar = self._arm(2, 20)  # 10%, CI straddles a 10% floor
        c = agg.classify_vs_floor(ar, floor_hi=0.10)
        self.assertEqual(c["label"], "GREY")

    def test_indeterminate_without_floor(self):
        ar = self._arm(3, 20)
        c = agg.classify_vs_floor(ar, floor_hi=None)
        self.assertEqual(c["label"], "INDETERMINATE")


# ---------------------------------------------------------------------------
# >20% invalid loss STOP condition.
# ---------------------------------------------------------------------------
class TestInvalidOverflow(unittest.TestCase):
    def test_overflow_flag(self):
        recs = []
        for i in range(5):
            r = agg.RoundRecord(case_id="C", arm="sift", round_n=i, path="x",
                                schema=agg.SCHEMA_SCORER, payload=scorer_round())
            if i < 2:  # 2/5 = 40% invalid
                r.valid = False
                r.invalid_reason = "needs-network"
            else:
                r.failed = False
            recs.append(r)
        ar = agg.aggregate_arm("sift", recs)
        self.assertTrue(ar.invalid_overflow)


# ---------------------------------------------------------------------------
# END-TO-END USE-CASE TEST.
# Realistic scenario: operator ran run_batch.sh ROUNDS=5 --arm both on one case,
# scored each exported round, dropped one invalid bare round, and aggregates with
# the FROZEN predicate "verdict not_emitted". Expectations:
#   - SIFT clean (0/5). Against a 10% floor at the 5x5 TRIAGE tier, 0/5 is GREY
#     (Wilson upper ~43% straddles the floor): you CANNOT certify "noise" with only
#     5 rounds — spec-correct, you'd ramp to N=20 to call it STOCHASTIC.
#   - BARE SYSTEMATIC, all bare failures share ONE signature (correlated event).
#   - sift-vs-bare reads SIFT-FIXED/SIFT-BETTER.
# This exercises the 5xN -> score-each-round -> aggregate operator flow end to end.
# ---------------------------------------------------------------------------
class TestEndToEndUseCase(unittest.TestCase):
    def test_5x5_batch_verdict_predicate(self):
        with tempfile.TemporaryDirectory() as d:
            case = "CFREDS-SYNTH"
            # SIFT arm: 5 clean rounds (verdict found).
            for n in range(1, 6):
                _write(d, f"{case}_sift_round-{n}.scorer.json", scorer_round(case=case))
                with open(os.path.join(d, f"{case}_sift_round-{n}.summary.md"), "w") as fh:
                    fh.write("findings captured: 6\n")
            # BARE arm: rounds 1-4 fail with the SAME wrong-verdict (correlated),
            # round 5 is an INVALID run (none captured + stderr) -> dropped.
            for n in range(1, 5):
                _write(d, f"{case}_bare_round-{n}.scorer.json",
                       scorer_round(case=case, verdict="not_emitted",
                                    verdict_expected="MALICE"))
                with open(os.path.join(d, f"{case}_bare_round-{n}.summary.md"), "w") as fh:
                    fh.write("findings captured: 3\n")
            _write(d, f"{case}_bare_round-5.scorer.json",
                   scorer_round(case=case, verdict="not_emitted"))
            with open(os.path.join(d, f"{case}_bare_round-5.summary.md"), "w") as fh:
                fh.write("(none captured)\n")
            with open(os.path.join(d, f"{case}_bare_round-5.agent.stderr"), "w") as fh:
                fh.write("CLI error\n")

            records = agg.discover_rounds(d, case_filter=case)
            agg.apply_predicate(records, "verdict")
            report = agg.build_report(records, "verdict", {}, floor_hi=0.10,
                                      floor_lo=None, sift_arm="sift", bare_arm="bare",
                                      decision_act_p=0.20)

            arms = report["arms"]
            # SIFT: 0/5. 5 rounds vs a 10% floor cannot certify noise => GREY
            # (Wilson upper ~43%). Ramping to N=20 would be needed to call STOCHASTIC.
            self.assertEqual(arms["sift"]["f"], 0)
            self.assertEqual(arms["sift"]["n_valid"], 5)
            self.assertEqual(arms["sift"]["classification"]["label"], "GREY")
            # BARE: invalid round dropped -> denominator 4, all 4 fail.
            self.assertEqual(arms["bare"]["n_invalid"], 1)
            self.assertEqual(arms["bare"]["n_valid"], 4)
            self.assertEqual(arms["bare"]["f"], 4)
            self.assertEqual(arms["bare"]["classification"]["label"], "SYSTEMATIC")
            # Correlated: all 4 bare failures share ONE signature.
            self.assertEqual(arms["bare"]["distinct_signatures"], 1)
            self.assertEqual(arms["bare"]["clustered_f"], 1)
            # Cross-arm: sift fails LESS (diff negative). interpretation = SIFT-BETTER/FIXED.
            cross = report["cross_arm"]
            self.assertLess(cross["diff"], 0)
            self.assertIn("SIFT", cross["interpretation"])
            # Human render must not raise.
            self.assertIn("FAILURE-RATE AGGREGATOR", agg.render_human(report))

    def test_end_to_end_score_py_category_predicate(self):
        # Same flow on the BLIND score.py path with the category_match predicate.
        with tempfile.TemporaryDirectory() as d:
            case = "BLIND-SYNTH"
            for n in range(1, 6):
                _write(d, f"{case}_sift_round-{n}.score.json",
                       score_round(case=case, category_match=True))
            for n in range(1, 6):
                _write(d, f"{case}_bare_round-{n}.score.json",
                       score_round(case=case, category_match=(n > 2)))  # 2/5 bare miss
            records = agg.discover_rounds(d, case_filter=case)
            agg.apply_predicate(records, "category")
            report = agg.build_report(records, "category", {}, floor_hi=0.10,
                                      floor_lo=None, sift_arm="sift", bare_arm="bare",
                                      decision_act_p=0.20)
            self.assertEqual(report["arms"]["sift"]["f"], 0)
            self.assertEqual(report["arms"]["bare"]["f"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)

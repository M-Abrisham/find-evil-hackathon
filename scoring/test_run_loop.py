#!/usr/bin/env python3
"""Tests for run_loop.py (MVP scripted single-lap orchestrator). Run from scoring/:
    python3 -m unittest test_run_loop -v
Self-contained: synthetic 16-key aggregates (built from scorer.aggregate([]) so the
key set is exact) + a tmp ledger. No external data / no live agent run."""
import os
import tempfile
import unittest

import scorer
import score_ledger
import run_loop


def agg(**ov):
    """A full, valid 16-key aggregate with non-None gated recalls; override as needed."""
    a = dict(scorer.aggregate([]))  # canonical key set (zeros / None)
    a["findable_recall_micro"] = 0.5
    a["mitre_recall_micro"] = 0.5
    a["fabrication_count_total"] = 0
    a["verdicts_emitted"] = 0
    a.update(ov)
    return a


class RunLapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ledger = os.path.join(self.tmp, "ledger.jsonl")

    def _lap(self, baseline, post, **kw):
        return run_loop.run_lap(baseline, post, ledger_path=self.ledger, case="VIGIA-REAL-001", **kw)

    def test_keep_lap_records_and_verifies(self):
        out = self._lap(agg(), agg(verdicts_emitted=1))  # one strict improve, others non-regress
        self.assertEqual(out["decision"], "KEEP")
        self.assertTrue(score_ledger.verify_chain(self.ledger).ok)
        rows = score_ledger.read_rows(self.ledger)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["decision"], "KEEP")

    def test_tie_reverts(self):
        out = self._lap(agg(), agg())  # no improvement -> tie -> REVERT
        self.assertEqual(out["decision"], "REVERT")
        self.assertEqual(score_ledger.read_rows(self.ledger)[0]["decision"], "REVERT")

    def test_fabrication_increase_reverts(self):
        out = self._lap(agg(), agg(verdicts_emitted=1, fabrication_count_total=1))
        self.assertEqual(out["decision"], "REVERT")

    def test_verdict_drop_reverts_rewardhack_guard(self):
        # an inflated->not-credited verdict regression must REVERT (verdicts_emitted is correct-class)
        out = self._lap(agg(verdicts_emitted=1), agg(verdicts_emitted=0))
        self.assertEqual(out["decision"], "REVERT")

    def test_decide_then_record_stores_sanitized_vectors(self):
        baseline, post = agg(), agg(verdicts_emitted=1)
        self._lap(baseline, post)
        row = score_ledger.read_rows(self.ledger)[0]
        self.assertEqual(row["score_vector"], score_ledger.sanitize_score_vector(post))
        self.assertEqual(row["baseline_vector"], score_ledger.sanitize_score_vector(baseline))

    def test_chain_grows_and_verifies_over_two_laps(self):
        self._lap(agg(), agg(verdicts_emitted=1), lap=1)
        self._lap(agg(), agg(), lap=2)
        self.assertTrue(score_ledger.verify_chain(self.ledger).ok)
        self.assertEqual(len(score_ledger.read_rows(self.ledger)), 2)

    def test_negative_eps_rejected(self):
        with self.assertRaises(ValueError):
            self._lap(agg(), agg(verdicts_emitted=1), eps_recall=-0.5)


if __name__ == "__main__":
    unittest.main()

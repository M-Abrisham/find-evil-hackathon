#!/usr/bin/env python3
"""Tests for errlens (recurring error-analysis sensor). Run from inside scoring/:
    python3 -m unittest test_errlens -v
Stdlib unittest; deterministic; synthetic fixtures (no live corpus needed)."""
import copy
import json
import os
import tempfile
import unittest

import errlens as el
from errlens import _match

TAX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "taxonomy.json")


def sig(**kw):
    base = {"case": "C", "verdict": "found", "fabrication_count": 0,
            "findable_recall": 1.0, "has_findable_miss": False,
            "presence": "PASS", "other_negative": []}
    base.update(kw)
    return base


def rnd(arm="sift", rid="r1", **kw):
    return {"arm": arm, "round_id": rid, "signals": sig(**kw)}


class TaxonomyTests(unittest.TestCase):
    def test_load_taxonomy_validates_and_sha_guards(self):
        tax = el.load_taxonomy(TAX)  # real, stamped -> OK
        self.assertTrue(tax["categories"])
        # mutate a record WITHOUT re-stamping -> load must HARD-FAIL on sha
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.json")
            with open(TAX, encoding="utf-8") as fh:
                tax2 = json.load(fh)
            tax2["categories"][0]["human_name"] = "TAMPERED"
            with open(p, "w", encoding="utf-8") as fh:
                json.dump(tax2, fh)
            with self.assertRaises(el.ErrlensError):
                el.load_taxonomy(p)
            # but skipping verification loads it (escape hatch is explicit)
            self.assertTrue(el.load_taxonomy(p, verify_sha=False))


class BucketTests(unittest.TestCase):
    def setUp(self):
        self.tax = el.load_taxonomy(TAX)

    def test_known_failure_auto_buckets_REQUIRED(self):
        self.assertEqual(el.bucket_round(sig(verdict="not_emitted"), self.tax),
                         ["structured-deliverable-absence"])
        self.assertEqual(el.bucket_round(sig(fabrication_count=2), self.tax),
                         ["fabrication"])
        self.assertEqual(el.bucket_round(sig(has_findable_miss=True), self.tax),
                         ["recall-miss"])
        self.assertEqual(el.bucket_round(sig(findable_recall=None), self.tax),
                         ["bad-case-unfindable"])
        self.assertEqual(el.bucket_round(sig(presence="FAIL"), self.tax),
                         ["transparency-regression"])

    def test_bucketer_idempotent(self):
        rounds = [rnd(rid="a", verdict="not_emitted"),
                  rnd(arm="bare", rid="b", fabrication_count=1)]
        b1 = el.process_batch(rounds, self.tax)
        b2 = el.process_batch(rounds, self.tax)
        self.assertEqual(b1["counts"], b2["counts"])
        self.assertEqual(b1["new_mode_candidates"], b2["new_mode_candidates"])

    def test_read_only_no_score_mutation(self):
        rounds = [rnd(verdict="not_emitted"), rnd(arm="bare", fabrication_count=1)]
        snapshot = copy.deepcopy(rounds)
        el.process_batch(rounds, self.tax)
        self.assertEqual(rounds, snapshot)  # inputs untouched

    def test_predicate_kind_none_never_matches(self):
        loud = sig(verdict="not_emitted", fabrication_count=9, has_findable_miss=True,
                   findable_recall=None, presence="FAIL", other_negative=["x"])
        self.assertFalse(_match({"kind": "none"}, loud))


class NewModeTests(unittest.TestCase):
    def setUp(self):
        self.tax = el.load_taxonomy(TAX)

    def test_unknown_failure_flags_as_NEW_REQUIRED(self):
        # a failure whose only negative signal matches ZERO active predicate
        r = rnd(rid="z", other_negative=["provenance_drift_marker"])
        self.assertEqual(el.bucket_round(r["signals"], self.tax), [])  # no bucket
        self.assertTrue(el.is_failure(r["signals"]))
        batch = el.process_batch([r], self.tax)
        nm = batch["new_mode_candidates"]
        self.assertEqual(len(nm), 1)
        self.assertIn("provenance_drift_marker", nm[0]["raw_signals"])
        self.assertEqual(nm[0]["taxonomy_version"], self.tax["taxonomy_version"])
        # NOT auto-promoted: taxonomy file untouched
        self.assertEqual(len(el.load_taxonomy(TAX)["categories"]),
                         len(self.tax["categories"]))


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.tax = el.load_taxonomy(TAX)

    def test_no_rates_or_cis_emitted(self):
        batch = el.process_batch([rnd(verdict="not_emitted")], self.tax)
        r = el.render_report(batch, self.tax)
        for forbidden in ("Wilson", "two-proportion", "CI", "%", "rate"):
            self.assertNotIn(forbidden, r)

    def test_class_A_surfaced_at_count_one(self):
        batch = el.process_batch([rnd(fabrication_count=1)], self.tax)
        self.assertEqual(len(batch["class_a"]), 1)
        self.assertEqual(batch["class_a"][0]["category"], "fabrication")
        self.assertIn("Class-A", el.render_report(batch, self.tax))

    def test_blind_spot_reported_not_zero(self):
        batch = el.process_batch([rnd(verdict="not_emitted")], self.tax)
        r = el.render_report(batch, self.tax)
        line = [ln for ln in r.splitlines() if "provenance-boundary-drift" in ln][0]
        self.assertIn("unobservable", line)
        self.assertNotIn("| 0 |", line)

    def test_delta_vs_last_run(self):
        prev = el.process_batch([rnd(verdict="not_emitted")], self.tax)
        first = el.render_report(prev, self.tax)  # no prev -> n/a
        self.assertIn("n/a", first)
        cur = el.process_batch([rnd(verdict="not_emitted"), rnd(rid="r2", verdict="not_emitted")], self.tax)
        withprev = el.render_report(cur, self.tax, prev=prev)
        sa = [ln for ln in withprev.splitlines() if "structured-deliverable-absence" in ln][0]
        self.assertIn("+1", sa)  # 2 now vs 1 before


if __name__ == "__main__":
    unittest.main()

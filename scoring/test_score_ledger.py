#!/usr/bin/env python3
"""Unit tests for the per-lap score ledger (stdlib unittest; no pytest)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

import score_ledger as sl


# A realistic baseline aggregate() (the 52-test scorer's 16-key schema).
BASELINE_AGG = {
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

# The empty aggregate([]) path: all ints 0, every recall None.
EMPTY_AGG = {
    "cases": 0,
    "fabrication_count_total": 0,
    "findable_found": 0,
    "findable_recall_micro": None,
    "findable_total": 0,
    "full_found": 0,
    "full_recall_micro": None,
    "full_total": 0,
    "invalid_mitre_total": 0,
    "mitre_emitted_total": 0,
    "mitre_found": 0,
    "mitre_grounded_total": 0,
    "mitre_precision_micro": None,
    "mitre_recall_micro": None,
    "mitre_total": 0,
    "verdicts_emitted": 0,
}


def _candidate_agg():
    """A candidate that improves exactly one dim: mitre_found 1 -> 2."""
    agg = dict(BASELINE_AGG)
    agg["mitre_found"] = 2
    agg["mitre_recall_micro"] = 1.0  # 2/2 (scorer would compute this)
    return agg


class TempLedgerMixin(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="score_ledger_test_")
        self.path = os.path.join(self.tmp, "ledger.jsonl")

    def tearDown(self):
        for name in os.listdir(self.tmp):
            os.remove(os.path.join(self.tmp, name))
        os.rmdir(self.tmp)

    def _append_baseline_lap(self, lap=1, decision="REVERT"):
        return sl.append_lap(
            self.path,
            lap=lap,
            case="VIGIA-REAL-001",
            blamed_failure="verdict_absent",
            sha_before="aaa111",
            sha_after="bbb222",
            score_vector=dict(BASELINE_AGG),
            baseline_vector=dict(BASELINE_AGG),
            decision=decision,
            reason="demo baseline lap",
            usage={"input_tokens": 100, "output_tokens": 50,
                   "session_id": None, "cost_usd": "0.01"},
        )

    def _append_candidate_lap(self, lap=2, decision="KEEP"):
        return sl.append_lap(
            self.path,
            lap=lap,
            case="VIGIA-REAL-001",
            blamed_failure="mitre_missing",
            sha_before="bbb222",
            sha_after="ccc333",
            score_vector=_candidate_agg(),
            baseline_vector=dict(BASELINE_AGG),
            decision=decision,
            reason="mitre_found improved 1->2",
            usage={"input_tokens": 120, "output_tokens": 60,
                   "session_id": "sess-xyz", "cost_usd": "0.02"},
        )


class SanitizeTests(unittest.TestCase):
    def test_sanitize_turns_recall_floats_into_4dp_strings(self):
        out = sl.sanitize_score_vector(BASELINE_AGG)
        self.assertEqual(out["findable_recall_micro"], "1.0000")
        self.assertEqual(out["full_recall_micro"], "1.0000")
        self.assertEqual(out["mitre_recall_micro"], "0.5000")

    def test_sanitize_keeps_all_ints_verbatim(self):
        out = sl.sanitize_score_vector(BASELINE_AGG)
        for k in sl.INT_KEYS:
            self.assertEqual(out[k], BASELINE_AGG[k], f"int {k} changed")
            self.assertIsInstance(out[k], int)

    def test_sanitize_none_denominator_stays_null(self):
        # mitre_precision_micro: denom mitre_emitted_total == 0 -> None.
        out = sl.sanitize_score_vector(BASELINE_AGG)
        self.assertIsNone(out["mitre_precision_micro"])
        # empty agg: every recall None.
        out0 = sl.sanitize_score_vector(EMPTY_AGG)
        for k in sl.RECALL_COMPONENTS:
            self.assertIsNone(out0[k], f"{k} should be null on 0 denom")

    def test_sanitize_formats_all_four_recalls(self):
        # candidate has a non-None mitre_recall; precision still None.
        out = sl.sanitize_score_vector(_candidate_agg())
        self.assertEqual(out["mitre_recall_micro"], "1.0000")
        self.assertEqual(out["findable_recall_micro"], "1.0000")
        self.assertEqual(out["full_recall_micro"], "1.0000")
        self.assertIsNone(out["mitre_precision_micro"])

    def test_sanitize_result_has_no_float(self):
        self.assertFalse(sl._has_float(sl.sanitize_score_vector(BASELINE_AGG)))
        self.assertFalse(sl._has_float(sl.sanitize_score_vector(EMPTY_AGG)))

    def test_sanitize_derives_from_int_components_not_the_float(self):
        # Feed a LYING float (recall says 0.9) but ints say 2/2=1.0; we must
        # format from the ints, proving we don't trust/keep the passed float.
        lying = dict(BASELINE_AGG)
        lying["findable_recall_micro"] = 0.9999
        out = sl.sanitize_score_vector(lying)
        self.assertEqual(out["findable_recall_micro"], "1.0000")

    def test_precision_grounded_over_emitted(self):
        agg = dict(BASELINE_AGG)
        agg["mitre_emitted_total"] = 4
        agg["mitre_grounded_total"] = 3
        out = sl.sanitize_score_vector(agg)
        self.assertEqual(out["mitre_precision_micro"], "0.7500")


class NoFloatRefusalTests(TempLedgerMixin):
    def test_raw_float_in_usage_raises_on_append(self):
        with self.assertRaises(sl.ScoreLedgerError):
            sl.append_lap(
                self.path,
                lap=1, case="C", blamed_failure="x",
                sha_before="a", sha_after="b",
                score_vector=dict(BASELINE_AGG),
                baseline_vector=dict(BASELINE_AGG),
                decision="KEEP", reason="r",
                usage={"input_tokens": 1, "output_tokens": 1, "cost_usd": 0.5},  # raw float
            )

    def test_raw_float_in_extra_score_key_raises(self):
        bad = dict(BASELINE_AGG)
        bad["some_extra_float_metric"] = 0.3333  # non-recall key carrying a float
        with self.assertRaises(sl.ScoreLedgerError):
            sl.sanitize_score_vector(bad)

    def test_has_float_treats_bool_as_int(self):
        self.assertFalse(sl._has_float({"flag": True, "n": 3}))
        self.assertTrue(sl._has_float({"x": 1.5}))


class ChainIntegrityTests(TempLedgerMixin):
    def test_genesis_prev_hash_on_first_row(self):
        row = self._append_baseline_lap()
        self.assertEqual(row["prev_row_sha256"], sl.GENESIS_PREV_HASH)

    def test_multi_row_chain_links_and_verifies(self):
        r1 = self._append_baseline_lap(lap=1)
        r2 = self._append_candidate_lap(lap=2)
        r3 = self._append_baseline_lap(lap=3, decision="KEEP")
        self.assertEqual(r2["prev_row_sha256"], r1["row_hash"])
        self.assertEqual(r3["prev_row_sha256"], r2["row_hash"])
        res = sl.verify_chain(self.path)
        self.assertTrue(res.ok, res.summary())
        self.assertEqual(res.n_rows, 3)
        self.assertTrue(res.genesis_ok)

    def test_verify_empty_or_missing_ledger_is_ok(self):
        res = sl.verify_chain(os.path.join(self.tmp, "nope.jsonl"))
        self.assertTrue(res.ok)
        self.assertEqual(res.n_rows, 0)

    def test_assert_chain_ok_raises_on_break(self):
        self._append_baseline_lap(lap=1)
        # corrupt the row
        with open(self.path, "r", encoding="utf-8") as fh:
            line = fh.readline()
        obj = json.loads(line)
        obj["reason"] = "tampered"
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n")
        with self.assertRaises(sl.ScoreLedgerChainError):
            sl.assert_chain_ok(self.path)


class TamperDetectionTests(TempLedgerMixin):
    def _three_rows(self):
        self._append_baseline_lap(lap=1)
        self._append_candidate_lap(lap=2)
        self._append_baseline_lap(lap=3, decision="KEEP")
        with open(self.path, "r", encoding="utf-8") as fh:
            return fh.readlines()

    def test_edit_middle_row_detected_at_that_line(self):
        lines = self._three_rows()
        mid = json.loads(lines[1])
        mid["reason"] = "SECRETLY CHANGED"  # body edit, row_hash now stale
        lines[1] = json.dumps(mid, sort_keys=True, separators=(",", ":")) + "\n"
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        res = sl.verify_chain(self.path)
        self.assertFalse(res.ok)
        self.assertEqual(res.broken_at["line"], 2)
        self.assertIn("row_hash mismatch", res.broken_at["reason"])

    def test_single_byte_corruption_in_middle_detected(self):
        lines = self._three_rows()
        # flip one byte inside line 2 (a value char), keeping it valid JSON-ish
        b = bytearray(lines[1].encode("utf-8"))
        # find a digit to flip
        for i, ch in enumerate(b):
            if chr(ch).isdigit():
                b[i] = ord("9") if chr(ch) != "9" else ord("8")
                break
        lines[1] = b.decode("utf-8")
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        res = sl.verify_chain(self.path)
        self.assertFalse(res.ok)
        self.assertEqual(res.broken_at["line"], 2)

    def test_reorder_rows_detected(self):
        lines = self._three_rows()
        lines[0], lines[1] = lines[1], lines[0]  # swap rows 1 and 2
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        res = sl.verify_chain(self.path)
        self.assertFalse(res.ok)
        # row now at line 1 must have genesis prev; it does not -> genesis fail
        self.assertEqual(res.broken_at["line"], 1)
        self.assertIn("genesis", res.broken_at["reason"])

    def test_delete_middle_row_detected(self):
        lines = self._three_rows()
        del lines[1]  # remove the middle row
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        res = sl.verify_chain(self.path)
        self.assertFalse(res.ok)
        # row formerly 3rd is now line 2; its prev-link points at the deleted row
        self.assertEqual(res.broken_at["line"], 2)
        self.assertIn("prev_row_sha256 link broken", res.broken_at["reason"])

    def test_forge_appended_row_detected(self):
        self._append_baseline_lap(lap=1)
        # forge a 2nd row with a self-consistent-looking but wrong prev link
        forged = {
            "schema_version": sl.SCHEMA_VERSION, "lap": 2, "ts": "2026-06-15T00:00:00Z",
            "case": "C", "blamed_failure": "x",
            "edit": {"sha_before": "z", "sha_after": "z2"},
            "score_vector": {}, "baseline_vector": {},
            "decision": "KEEP", "reason": "forged", "usage": {},
            "prev_row_sha256": "f" * 64,  # wrong link
        }
        forged["row_hash"] = sl.compute_row_hash(forged)  # internally consistent
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n")
        res = sl.verify_chain(self.path)
        self.assertFalse(res.ok)
        self.assertEqual(res.broken_at["line"], 2)
        self.assertIn("prev_row_sha256 link broken", res.broken_at["reason"])

    def test_torn_trailing_line_tolerated(self):
        self._append_baseline_lap(lap=1)
        self._append_candidate_lap(lap=2)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write('{"partial": "no newline and incomplete')  # torn write, no \n
        res = sl.verify_chain(self.path)
        self.assertTrue(res.ok, res.summary())
        self.assertTrue(res.trailing_partial)
        self.assertEqual(res.n_rows, 2)


class NeverRecomputeTests(TempLedgerMixin):
    def test_append_stores_sanitized_vector_byte_for_byte(self):
        # The stored score_vector must equal sanitize_score_vector(input)
        # exactly — append must not re-derive from the scorer.
        cand = _candidate_agg()
        sl.append_lap(
            self.path, lap=1, case="C", blamed_failure="x",
            sha_before="a", sha_after="b",
            score_vector=cand, baseline_vector=dict(BASELINE_AGG),
            decision="KEEP", reason="r",
            usage={"input_tokens": 1, "output_tokens": 1, "cost_usd": "0.00"},
        )
        rows = sl.read_rows(self.path)
        self.assertEqual(rows[0]["score_vector"], sl.sanitize_score_vector(cand))
        self.assertEqual(rows[0]["baseline_vector"], sl.sanitize_score_vector(BASELINE_AGG))

    def test_append_does_not_import_or_call_scorer(self):
        # score_ledger must be standalone: importing it must not pull in scorer.
        self.assertNotIn("scorer", getattr(sl, "__dict__", {}))
        # and the module source must not import scorer
        with open(sl.__file__, "r", encoding="utf-8") as _fh:
            src = _fh.read()
        self.assertNotIn("import scorer", src)
        self.assertNotIn("from scorer", src)

    def test_already_sanitized_vector_stored_verbatim_with_sanitize_false(self):
        pre = sl.sanitize_score_vector(BASELINE_AGG)
        sl.append_lap(
            self.path, lap=1, case="C", blamed_failure="x",
            sha_before="a", sha_after="b",
            score_vector=pre, baseline_vector=pre,
            decision="REVERT", reason="r", sanitize=False,
            usage={"input_tokens": 0, "output_tokens": 0, "cost_usd": "0.00"},
        )
        rows = sl.read_rows(self.path)
        self.assertEqual(rows[0]["score_vector"], pre)


class RenderTests(TempLedgerMixin):
    def test_render_shows_correct_deltas(self):
        self._append_baseline_lap(lap=1, decision="REVERT")
        self._append_candidate_lap(lap=2, decision="KEEP")
        md = sl.render_markdown(self.path)
        # candidate improved mitre_found 1 -> 2 vs its baseline (1): delta +1
        self.assertIn("2 (+1)", md)
        # mitre_recall improved 0.5 -> 1.0: delta +0.5000
        self.assertIn("1.0000 (+0.5000)", md)
        # baseline row: mitre_found 1 vs baseline 1 -> +0
        self.assertIn("1 (+0)", md)
        # header + decisions present
        self.assertIn("| lap | case | blamed_failure |", md)
        self.assertIn("KEEP", md)
        self.assertIn("REVERT", md)
        # tokens column
        self.assertIn("in=120 out=60", md)

    def test_render_null_recall_renders_na(self):
        # an empty-agg lap: precision recall null -> n/a, no delta
        sl.append_lap(
            self.path, lap=1, case="C", blamed_failure="x",
            sha_before="a", sha_after="b",
            score_vector=dict(EMPTY_AGG), baseline_vector=dict(EMPTY_AGG),
            decision="REVERT", reason="empty",
            usage={"input_tokens": 0, "output_tokens": 0, "cost_usd": "0.00"},
        )
        md = sl.render_markdown(self.path)
        self.assertIn("n/a", md)


class RealBaselineRoundTripTests(unittest.TestCase):
    """Manual append -> verify -> render round-trip on the REAL baseline agg."""

    BASELINE_PATH = "/home/ubuntu/score-ledger-build/_baseline_agg.json"

    def setUp(self):
        if not os.path.isfile(self.BASELINE_PATH):
            self.skipTest("real baseline agg not present on this host")
        with open(self.BASELINE_PATH, "r", encoding="utf-8") as fh:
            self.baseline = json.load(fh)
        self.tmp = tempfile.mkdtemp(prefix="score_ledger_real_")
        self.path = os.path.join(self.tmp, "ledger.jsonl")

    def tearDown(self):
        if hasattr(self, "tmp"):
            for name in os.listdir(self.tmp):
                os.remove(os.path.join(self.tmp, name))
            os.rmdir(self.tmp)

    def test_real_baseline_round_trip(self):
        # baseline lap
        sl.append_lap(
            self.path, lap=1, case="VIGIA-REAL-001",
            blamed_failure="verdict_absent",
            sha_before="base0000", sha_after="base0000",
            score_vector=dict(self.baseline), baseline_vector=dict(self.baseline),
            decision="REVERT", reason="DEMO baseline pin",
            usage={"input_tokens": 200, "output_tokens": 80,
                   "session_id": None, "cost_usd": "0.03"},
        )
        # candidate improving mitre_found
        cand = dict(self.baseline)
        cand["mitre_found"] = cand["mitre_found"] + 1
        cand["mitre_recall_micro"] = (cand["mitre_found"] / cand["mitre_total"]
                                      if cand["mitre_total"] else None)
        sl.append_lap(
            self.path, lap=2, case="VIGIA-REAL-001",
            blamed_failure="mitre_missing",
            sha_before="base0000", sha_after="cand1111",
            score_vector=cand, baseline_vector=dict(self.baseline),
            decision="KEEP", reason="DEMO mitre_found +1",
            usage={"input_tokens": 220, "output_tokens": 90,
                   "session_id": "demo", "cost_usd": "0.04"},
        )
        res = sl.verify_chain(self.path)
        self.assertTrue(res.ok, res.summary())
        self.assertEqual(res.n_rows, 2)
        md = sl.render_markdown(self.path)
        self.assertIn("| lap | case | blamed_failure |", md)
        # candidate mitre_found delta +1 visible
        self.assertIn("(+1)", md)
        # stored vector is the sanitized one (no floats anywhere in the file)
        with open(self.path, "rb") as fh:
            for raw in fh:
                obj = json.loads(raw)
                self.assertFalse(sl._has_float(obj))


if __name__ == "__main__":
    unittest.main(verbosity=2)

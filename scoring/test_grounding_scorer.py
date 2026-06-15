#!/usr/bin/env python3
"""Tests for the G13 advisory cited-receipt grounding verifier.

Run from inside scoring/:  python3 -m unittest test_grounding_scorer -v
Stdlib unittest only (no pytest); deterministic; no network/LLM.
"""
import os
import tempfile
import unittest

import grounding_scorer as g
import scorer  # to prove the gated fabrication path is untouched/blind


class TestCitationResolver(unittest.TestCase):
    def _case(self):
        return {"artifacts": [
            {"artifact_id": "ART-001", "content": "email mrevilrulez@yahoo.com here"},
            {"artifact_id": "ART-002", "content": "nothing useful"},
        ]}

    def test_art_resolves_to_its_content(self):
        idx = g.build_citation_index({}, self._case())
        self.assertIn("ART-001", idx)
        self.assertIn("mrevilrulez@yahoo.com", idx["ART-001"]["content"])
        self.assertEqual(idx["ART-001"]["src_kind"], "artifact")

    def test_unknown_id_absent(self):
        idx = g.build_citation_index({}, self._case())
        self.assertNotIn("ART-099", idx)

    def test_missing_artifacts_key_is_empty(self):
        self.assertEqual(g.build_citation_index({}, {"foo": 1}), {})
        self.assertEqual(g.build_citation_index({}, {}), {})

    def test_duplicate_artifact_id_last_wins(self):
        case = {"artifacts": [
            {"artifact_id": "ART-001", "content": "first"},
            {"artifact_id": "ART-001", "content": "second"},
        ]}
        idx = g.build_citation_index({}, case)
        self.assertEqual(idx["ART-001"]["content"], "second")

    def test_tool_id_indexed_as_bash(self):
        idx = g.build_citation_index({"toolu_abc": {"stdout": "x"}}, {})
        self.assertEqual(idx["TOOL:TOOLU_ABC"]["src_kind"], "bash")


class TestVerbatimMatcher(unittest.TestCase):
    def test_hash_recased_grounds(self):
        h = "a" * 63 + "b"
        self.assertEqual(g.literal_in_context(h, "X " + h.upper() + " Y", "hash"),
                         (True, "clean_token"))

    def test_hash_off_by_one_does_not_ground(self):
        h = "a" * 63 + "b"
        ok, _ = g.literal_in_context("c" * 64, "X " + h + " Y", "hash")
        self.assertFalse(ok)

    def test_hash_truncated_prefix_does_not_ground(self):
        h = "a" * 63 + "b"
        ok, _ = g.literal_in_context(h[:60], "X " + h + " Y", "hash")
        self.assertFalse(ok)

    def test_hash_nfkc_fullwidth_grounds(self):
        # fullwidth hex digits in the literal normalise (NFKC) to ascii
        lit = "ａｂ" + "a" * 62          # ＡＢ-ish fullwidth a,b + 62 'a'
        ctx = "hash " + ("ab" + "a" * 62)
        self.assertTrue(g.literal_in_context(lit, ctx, "hash")[0])

    def test_hash_zero_width_injected_still_grounds(self):
        h = "a" * 63 + "b"
        lit = h[:10] + "​" + h[10:]          # ZWSP mid-literal
        self.assertTrue(g.literal_in_context(lit, "h " + h + " z", "hash")[0])

    def test_path_separator_case_normalised(self):
        self.assertTrue(g.literal_in_context(r"C:\X\Y", "see c:/x/y here", "file_path")[0])

    def test_registry_full_key_grounds(self):
        full = r"HKLM\SYSTEM\ControlSet001\Control\ComputerName"
        ctx = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName"
        self.assertTrue(g.literal_in_context(full, ctx, "registry_key")[0])

    def test_registry_different_leaf_does_not_ground(self):
        lit = r"HKLM\SYSTEM\ControlSet001\Services\Evil"
        ctx = r"HKLM\SYSTEM\ControlSet001\Control\ComputerName"
        self.assertFalse(g.literal_in_context(lit, ctx, "registry_key")[0])

    def test_registry_mid_segment_does_not_ground(self):
        # 'Compute' must not match inside 'ComputerName' (boundary guard)
        lit = r"HKLM\SYSTEM\Control\Compute"
        ctx = r"HKLM\SYSTEM\Control\ComputerName"
        self.assertFalse(g.literal_in_context(lit, ctx, "registry_key")[0])


class TestFuzzyExtractors(unittest.TestCase):
    def test_path_extracted_unc_and_drive(self):
        self.assertIn(r"C:\Program", g.extract_fuzzy_literals(r"C:\Program here", "file_path"))
        self.assertTrue(g.extract_fuzzy_literals(r"\\host\share\x.dll", "file_path"))

    def test_bare_word_not_a_path(self):
        self.assertEqual(g.extract_fuzzy_literals("system was running", "file_path"), [])

    def test_registry_extracted(self):
        out = g.extract_fuzzy_literals(r"key HKLM\SYSTEM\ControlSet001\Control found", "registry_key")
        self.assertTrue(any("ControlSet001" in r for r in out))

    def test_username_anchored(self):
        self.assertIn("Mr. Evil", g.extract_fuzzy_literals("DefaultUserName = Mr. Evil ", "username"))

    def test_username_unanchored_not_extracted(self):
        self.assertEqual(g.extract_fuzzy_literals("Something Capitalized Here", "username"), [])


class TestGrounding(unittest.TestCase):
    def _case(self):
        return {"artifacts": [
            {"artifact_id": "ART-001", "content": "email mrevilrulez@yahoo.com seen"},
            {"artifact_id": "ART-002", "content": "unrelated content"},
        ]}

    def test_cited_grounded_happy(self):
        rep = "| email | mrevilrulez@yahoo.com | CONFIRMED | ART-001 |"
        r = g.score_grounding(rep, {}, self._case())
        self.assertEqual(r["counts"]["cited_grounded"], 1)
        self.assertEqual(r["citation_precision"], 1.0)

    def test_mis_cited_bypass(self):
        # real value present in ART-001 but cited to ART-002 -> mis_cited
        rep = "| email | mrevilrulez@yahoo.com | CONFIRMED | ART-002 |"
        r = g.score_grounding(rep, {}, self._case())
        self.assertEqual(r["counts"]["mis_cited"], 1)
        self.assertEqual(r["citation_precision"], 0.0)

    def test_fabricated_path_ungrounded_and_gate_blind(self):
        rep = r"| file_path | C:\evil\nope.dll | CONFIRMED | ART-001 |"
        r = g.score_grounding(rep, {}, self._case())
        self.assertGreaterEqual(r["counts"]["ungrounded"], 1)
        # the gated fabrication path (scorer.py) is blind to paths -> untouched
        fabs, _ = scorer.find_fabrications(rep, "")
        self.assertEqual(fabs, [])  # no clean-kind tokens; path never counted

    def test_uncertain_is_abstained(self):
        rep = "| email | madeup@evil.com | UNCERTAIN | ART-001 |"
        r = g.score_grounding(rep, {}, self._case())
        self.assertEqual(r["counts"]["abstained"], 1)
        self.assertEqual(r["counts"]["ungrounded"], 0)

    def test_uncited_claim_flagged(self):
        rep = "| email | mrevilrulez@yahoo.com | CONFIRMED | (no provenance) |"
        r = g.score_grounding(rep, {}, self._case())
        self.assertEqual(r["counts"]["uncited"], 1)

    def test_multi_citation_union(self):
        rep = "| email | mrevilrulez@yahoo.com | CONFIRMED | ART-001 ART-002 |"
        r = g.score_grounding(rep, {}, self._case())
        self.assertEqual(r["counts"]["cited_grounded_union"], 1)
        self.assertEqual(r["counts"]["cited_grounded"], 0)

    def test_read_mcp_unverifiable_synthetic(self):
        # synthetic bash_log entry tagged as a Read tool -> unverifiable_read_mcp
        blog = {"toolu_r": {"stdout": "mrevilrulez@yahoo.com", "tool_name": "Read"}}
        rep = "| email | mrevilrulez@yahoo.com | CONFIRMED | tool:toolu_r |"
        r = g.score_grounding(rep, blog, {})
        self.assertEqual(r["counts"]["unverifiable_read_mcp"], 1)

    def test_persisted_tail_present_grounds(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("login by mrevilrulez@yahoo.com at 02:00\n")
            path = fh.name
        try:
            blog = {"toolu_p": {"stdout": "short", "persisted_output_path": path,
                                "persisted_output_size": 9999}}
            rep = "| email | mrevilrulez@yahoo.com | CONFIRMED | tool:toolu_p |"
            r = g.score_grounding(rep, blog, {})
            self.assertEqual(r["counts"]["cited_grounded"], 1)
        finally:
            os.unlink(path)

    def test_persisted_unreadable_is_truncated(self):
        blog = {"toolu_x": {"stdout": "short no value", "persisted_output_path": "/no/such/file",
                            "persisted_output_size": 9999}}
        rep = "| email | mrevilrulez@yahoo.com | CONFIRMED | tool:toolu_x |"
        r = g.score_grounding(rep, blog, {})
        self.assertEqual(r["counts"]["unverifiable_truncated"], 1)
        self.assertEqual(r["counts"]["ungrounded"], 0)


class TestAntiGoodhart(unittest.TestCase):
    def test_off_key_but_correctly_cited_grounds(self):
        # a hash that is in NO answer key but IS in the cited artifact -> grounded.
        # (verifier never reads ground_truth; correctness is claim-vs-receipt.)
        h = "deadbeef" * 8  # 64 hex
        case = {"artifacts": [{"artifact_id": "ART-001", "content": "sha256 " + h}]}
        rep = "| file_hash | " + h + " | CONFIRMED | ART-001 |"
        r = g.score_grounding(rep, {}, case)
        self.assertEqual(r["counts"]["cited_grounded"], 1)


class TestScoreShape(unittest.TestCase):
    def test_advisory_dict_shape(self):
        rep = "| email | mrevilrulez@yahoo.com | CONFIRMED | ART-001 |"
        case = {"artifacts": [{"artifact_id": "ART-001", "content": "mrevilrulez@yahoo.com"}]}
        out = g.score_report(rep, {}, case)
        self.assertTrue(out["advisory"])
        self.assertIn("citation_precision", out)
        self.assertIn("grounding", out)
        for k in ("counts", "per_tier", "violations", "findings"):
            self.assertIn(k, out["grounding"])

    def test_positional_three_arg_compat(self):
        # report_text, bash_log, case_input_obj positionally
        out = g.score_report("no claims here", {}, {})
        self.assertTrue(out["advisory"])


if __name__ == "__main__":
    unittest.main()

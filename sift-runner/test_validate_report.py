#!/usr/bin/env python3
"""
Protocol SIFT — R4 report-validator unit tests (BUILD-TIME TOOLING ONLY — do NOT commit).

STDLIB unittest (NOT pytest). Self-contained: writes a synthetic contract.yaml + synthetic reports
to a temp dir, so it never touches the real contract or the live ~/.claude config.

Run:
    python3 -m unittest -v test_validate_report
    # or, from this directory:
    python3 test_validate_report.py -v
"""
from __future__ import annotations

import json
import os
import io
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout

import validate_report as vr


# A synthetic contract that mirrors the real contract.yaml v1 shape (verdict + ioc blocks).
SYNTH_CONTRACT = textwrap.dedent(
    """
    # synthetic contract for tests
    version: 1
    verdict:
      vocabulary:
        - token: MALICE
          meaning: malicious
        - token: NON_MALICE
          meaning: benign
        - token: INCONCLUSIVE
          meaning: unknown
      confidence_levels: [HIGH, MODERATE, LOW]
      dimensions: [act, attribution]
      equivalence_classes:
        malicious:     [MALICE, MALICIOUS]
        non_malicious: [NON_MALICE, NONMALICE, BENIGN]
        inconclusive:  [INCONCLUSIVE, INDETERMINATE, UNKNOWN]
    ioc:
      confidence_vocab: [CONFIRMED, INFERRED, UNCERTAIN]
      columns: [Type, Value, Confidence]
      types:
        - {type: email,       value_form: lowercase}
        - {type: file_hash,   value_form: hex}
        - {type: ip_address,  value_form: dotted}
        - {type: windows_sid, value_form: upper}
        - {type: file_path,   value_form: as-seen}
        - {type: hostname,    value_form: as-seen}
        - {type: username,    value_form: as-seen}
    """
)


GOOD_REPORT = textwrap.dedent(
    """
    # Protocol SIFT Report — CASE-001

    ## Summary
    A non-system account staged and exfiltrated data over SMB.

    ## IOCs
    | Type        | Value                              | Confidence |
    | ----------- | ---------------------------------- | ---------- |
    | ip_address  | 10.0.0.5                           | CONFIRMED  |
    | username    | jdoe                               | INFERRED   |
    | file_path   | C:\\Users\\jdoe\\stage\\dump.7z    | CONFIRMED  |

    ## MITRE ATT&CK
    | Technique          | T-code | Evidencing artifact |
    | ------------------ | ------ | ------------------- |
    | Exfil Over C2      | T1041  | ART-7 netflow       |

    ## Verdict
    VERDICT: MALICE — act: HIGH, attribution: MODERATE
    """
)

# Synonym verdict (MALICIOUS) + synonym confidence still legal.
GOOD_REPORT_SYNONYM = GOOD_REPORT.replace(
    "VERDICT: MALICE — act: HIGH, attribution: MODERATE",
    "VERDICT: MALICIOUS — act: HIGH, attribution: LOW",
)

# Missing the VERDICT line entirely.
BAD_NO_VERDICT = GOOD_REPORT.replace(
    "VERDICT: MALICE — act: HIGH, attribution: MODERATE",
    "We could not reach a firm conclusion.",
)

# Bad confidence token in an IOC row (LIKELY is not in the vocab).
BAD_IOC_CONFIDENCE = GOOD_REPORT.replace(
    "| username    | jdoe                               | INFERRED   |",
    "| username    | jdoe                               | LIKELY     |",
)

# Malformed IOC row: only two columns.
BAD_IOC_MALFORMED = GOOD_REPORT.replace(
    "| ip_address  | 10.0.0.5                           | CONFIRMED  |",
    "| ip_address  | 10.0.0.5  |",
)

# Verdict present but unqualified (no per-dimension confidence).
BAD_VERDICT_UNQUALIFIED = GOOD_REPORT.replace(
    "VERDICT: MALICE — act: HIGH, attribution: MODERATE",
    "VERDICT: MALICE",
)

# Verdict token not in vocab.
BAD_VERDICT_TOKEN = GOOD_REPORT.replace(
    "VERDICT: MALICE — act: HIGH, attribution: MODERATE",
    "VERDICT: PROBABLY_BAD — act: HIGH, attribution: MODERATE",
)

# Empty IOC type cell.
BAD_IOC_EMPTY_TYPE = GOOD_REPORT.replace(
    "| ip_address  | 10.0.0.5                           | CONFIRMED  |",
    "|             | 10.0.0.5                           | CONFIRMED  |",
)


class ContractParsingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.contract_path = os.path.join(self.tmp, "contract.yaml")
        with open(self.contract_path, "w", encoding="utf-8") as fh:
            fh.write(SYNTH_CONTRACT)

    def test_loads_vocab_from_yaml(self):
        v = vr.load_contract(self.contract_path)
        self.assertTrue(v.source.startswith("contract:"))
        self.assertEqual(set(v.verdict_tokens), {"MALICE", "NON_MALICE", "INCONCLUSIVE"})
        self.assertEqual(set(v.ioc_confidence_vocab), {"CONFIRMED", "INFERRED", "UNCERTAIN"})
        self.assertEqual(v.ioc_columns, ["Type", "Value", "Confidence"])
        self.assertIn("email", v.ioc_types)
        self.assertIn("file_path", v.ioc_types)
        self.assertEqual(v.confidence_levels, ["HIGH", "MODERATE", "LOW"])

    def test_equivalence_classes_parsed(self):
        v = vr.load_contract(self.contract_path)
        self.assertEqual(v.verdict_class_of("MALICIOUS"), "malicious")
        self.assertEqual(v.verdict_class_of("malice"), "malicious")
        self.assertEqual(v.verdict_class_of("BENIGN"), "non_malicious")
        self.assertEqual(v.verdict_class_of("non-malice"), "non_malicious")
        self.assertIsNone(v.verdict_class_of("PROBABLY_BAD"))

    def test_missing_contract_falls_back_to_mirror(self):
        v = vr.load_contract(os.path.join(self.tmp, "does-not-exist.yaml"))
        self.assertEqual(v.source, "embedded-mirror")
        # mirror still has the real vocab so the hook fails closed
        self.assertEqual(set(v.ioc_confidence_vocab), {"CONFIRMED", "INFERRED", "UNCERTAIN"})
        self.assertEqual(set(v.verdict_tokens), {"MALICE", "NON_MALICE", "INCONCLUSIVE"})


class ValidateReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.contract_path = os.path.join(self.tmp, "contract.yaml")
        with open(self.contract_path, "w", encoding="utf-8") as fh:
            fh.write(SYNTH_CONTRACT)
        self.vocab = vr.load_contract(self.contract_path)

    def test_good_report_passes(self):
        self.assertEqual(vr.validate_report(GOOD_REPORT, self.vocab), [])

    def test_good_report_synonyms_pass(self):
        self.assertEqual(vr.validate_report(GOOD_REPORT_SYNONYM, self.vocab), [])

    def test_missing_verdict_blocks(self):
        probs = vr.validate_report(BAD_NO_VERDICT, self.vocab)
        self.assertTrue(any("no `VERDICT:` line" in p for p in probs), probs)

    def test_bad_confidence_token_blocks(self):
        probs = vr.validate_report(BAD_IOC_CONFIDENCE, self.vocab)
        self.assertTrue(any("Confidence 'LIKELY'" in p for p in probs), probs)

    def test_malformed_ioc_row_blocks(self):
        probs = vr.validate_report(BAD_IOC_MALFORMED, self.vocab)
        self.assertTrue(any("malformed" in p for p in probs), probs)

    def test_unqualified_verdict_blocks(self):
        probs = vr.validate_report(BAD_VERDICT_UNQUALIFIED, self.vocab)
        self.assertTrue(any("per-dimension confidence" in p for p in probs), probs)

    def test_bad_verdict_token_blocks(self):
        probs = vr.validate_report(BAD_VERDICT_TOKEN, self.vocab)
        self.assertTrue(any("not in the contract verdict vocabulary" in p for p in probs), probs)

    def test_empty_ioc_type_blocks(self):
        probs = vr.validate_report(BAD_IOC_EMPTY_TYPE, self.vocab)
        self.assertTrue(any("empty Type cell" in p for p in probs), probs)

    def test_placeholder_section_blocks(self):
        rpt = GOOD_REPORT.replace("A non-system account staged", "TODO write summary")
        probs = vr.validate_report(rpt, self.vocab)
        self.assertTrue(any("placeholder" in p for p in probs), probs)


class HookEventExtractionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.contract_path = os.path.join(self.tmp, "contract.yaml")
        with open(self.contract_path, "w", encoding="utf-8") as fh:
            fh.write(SYNTH_CONTRACT)

    def test_write_to_reports_md_in_scope(self):
        ev = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/proj/reports/case-001.md", "content": GOOD_REPORT},
        }
        text, reason = vr.extract_report_from_event(ev)
        self.assertEqual(text, GOOD_REPORT)
        self.assertIn("content", reason)

    def test_edit_uses_new_string(self):
        ev = {
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "reports/case-002.md",
                "old_string": "x",
                "new_string": GOOD_REPORT,
            },
        }
        text, reason = vr.extract_report_from_event(ev)
        self.assertEqual(text, GOOD_REPORT)
        self.assertIn("new_string", reason)

    def test_non_report_path_is_noop(self):
        ev = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/proj/notes/scratch.txt", "content": "hi"},
        }
        text, reason = vr.extract_report_from_event(ev)
        self.assertIsNone(text)

    def test_non_write_tool_is_noop(self):
        ev = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
        text, reason = vr.extract_report_from_event(ev)
        self.assertIsNone(text)


class MainExitCodeTests(unittest.TestCase):
    """End-to-end exit codes via main() — the actual hook contract (0 allow / 2 block)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.contract_path = os.path.join(self.tmp, "contract.yaml")
        with open(self.contract_path, "w", encoding="utf-8") as fh:
            fh.write(SYNTH_CONTRACT)

    def _write(self, text):
        p = os.path.join(self.tmp, "report.md")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        return p

    def _run_main(self, argv, stdin_text=None):
        out, err = io.StringIO(), io.StringIO()
        old_stdin = sys.stdin
        if stdin_text is not None:
            sys.stdin = io.StringIO(stdin_text)
        try:
            with redirect_stdout(out), redirect_stderr(err):
                rc = vr.main(argv)
        finally:
            sys.stdin = old_stdin
        return rc, out.getvalue(), err.getvalue()

    def test_main_good_report_file_exit0(self):
        p = self._write(GOOD_REPORT)
        rc, _, err = self._run_main(["--contract", self.contract_path, "--report-file", p])
        self.assertEqual(rc, 0, err)

    def test_main_bad_report_file_exit2(self):
        p = self._write(BAD_NO_VERDICT)
        rc, _, err = self._run_main(["--contract", self.contract_path, "--report-file", p])
        self.assertEqual(rc, 2)
        self.assertIn("BLOCKED by validate_report.py", err)

    def test_main_stdin_json_write_block_exit2(self):
        ev = {
            "tool_name": "Write",
            "tool_input": {"file_path": "reports/case.md", "content": BAD_IOC_CONFIDENCE},
        }
        rc, _, err = self._run_main(
            ["--contract", self.contract_path, "--stdin-json"], stdin_text=json.dumps(ev)
        )
        self.assertEqual(rc, 2)
        self.assertIn("Confidence 'LIKELY'", err)

    def test_main_stdin_json_good_write_exit0(self):
        ev = {
            "tool_name": "Write",
            "tool_input": {"file_path": "reports/case.md", "content": GOOD_REPORT},
        }
        rc, _, err = self._run_main(
            ["--contract", self.contract_path, "--stdin-json"], stdin_text=json.dumps(ev)
        )
        self.assertEqual(rc, 0, err)

    def test_main_stdin_json_out_of_scope_exit0(self):
        ev = {
            "tool_name": "Write",
            "tool_input": {"file_path": "src/foo.py", "content": "print(1)"},
        }
        rc, _, _ = self._run_main(
            ["--contract", self.contract_path, "--stdin-json"], stdin_text=json.dumps(ev)
        )
        self.assertEqual(rc, 0)

    def test_main_empty_stdin_exit0(self):
        rc, _, _ = self._run_main(["--contract", self.contract_path, "--stdin-json"], stdin_text="")
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

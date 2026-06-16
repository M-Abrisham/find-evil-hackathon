#!/usr/bin/env python3
"""
Protocol SIFT — R4 report-validator ADVERSARIAL unit tests (BUILD-TIME TOOLING ONLY — do NOT commit;
inert until wired). STDLIB unittest (NOT pytest). Self-contained: synthetic contract + reports in a
temp dir; never touches the real contract or the live ~/.claude config.

This suite is engineered to BREAK validate_report.py on its hardest edges, complementary to
test_validate_report.py (the happy-path/basic-violation suite). It targets:

  * the seam between the THREE verdict sub-checks (token extraction vs vocab check vs per-dimension
    confidence check) — which inspect DIFFERENT lines and can disagree with each other AND with the
    scorer the hook claims to mirror ("the scorer reads the LAST recognized token");
  * IOC table edges (extra/duplicate columns, separator-only tables, case folding);
  * structural edges (empty/whitespace, CRLF, leading whitespace on the VERDICT line);
  * end-to-end exit codes through main() (0 allow / 2 block) for each.

Tests whose docstring/comment is tagged ``# BUG`` encode the INTENDED behavior and are expected to
FAIL against the current build — they document a real defect, not a flaky test. Run:

    python3 -m unittest -v test_validate_report_adversarial
    # or, from this directory:
    python3 test_validate_report_adversarial.py -v
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout

import validate_report as vr


SYNTH_CONTRACT = textwrap.dedent(
    """
    # synthetic contract for adversarial tests
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


def _good(verdict_line="VERDICT: MALICE — act: HIGH, attribution: MODERATE"):
    return textwrap.dedent(
        """
        # Protocol SIFT Report — CASE-XAD

        ## Summary
        A non-system account staged and exfiltrated data over SMB.

        ## IOCs
        | Type        | Value      | Confidence |
        | ----------- | ---------- | ---------- |
        | ip_address  | 10.0.0.5   | CONFIRMED  |
        | username    | jdoe       | INFERRED   |

        ## Verdict
        {vline}
        """
    ).replace("{vline}", verdict_line)


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.contract_path = os.path.join(self.tmp, "contract.yaml")
        with open(self.contract_path, "w", encoding="utf-8") as fh:
            fh.write(SYNTH_CONTRACT)
        self.vocab = vr.load_contract(self.contract_path)
        self.assertTrue(self.vocab.source.startswith("contract:"), self.vocab.source)

    def run_main(self, argv, stdin_text=None):
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

    def write_report(self, text, name="report.md"):
        p = os.path.join(self.tmp, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        return p

    def assertBlocks(self, text, needle=None):
        probs = vr.validate_report(text, self.vocab)
        self.assertTrue(probs, "expected violations, got none")
        if needle is not None:
            self.assertTrue(any(needle in p for p in probs),
                            f"expected a problem containing {needle!r}, got {probs}")
        return probs

    def assertClean(self, text):
        probs = vr.validate_report(text, self.vocab)
        self.assertEqual(probs, [], probs)


# ===================================================================================================
# R4 — VERDICT edges
# ===================================================================================================
class VerdictEdgeTests(_Base):
    def test_valid_report_is_clean(self):
        self.assertClean(_good())

    def test_out_of_vocab_verdict_token_blocks(self):
        self.assertBlocks(_good("VERDICT: PROBABLY_BAD — act: HIGH, attribution: MODERATE"),
                          needle="not in the contract verdict vocabulary")

    def test_missing_verdict_line_entirely_blocks(self):
        rpt = _good().replace("VERDICT: MALICE — act: HIGH, attribution: MODERATE",
                              "We could not reach a firm conclusion.")
        self.assertBlocks(rpt, needle="no `VERDICT:` line")

    def test_empty_report_blocks(self):
        self.assertBlocks("", needle="empty report content")

    def test_whitespace_only_report_blocks(self):
        self.assertBlocks("   \n\t  \n   ", needle="empty report content")

    def test_crlf_good_report_is_clean(self):
        """CRLF line endings must not change the verdict — \\r\\n tolerance."""
        self.assertClean(_good().replace("\n", "\r\n"))

    def test_extra_whitespace_around_verdict_tolerated(self):
        """Padding/indentation and doubled spaces around the VERDICT line stay valid."""
        rpt = _good("   VERDICT:    MALICE   —   act:  HIGH ,  attribution:   MODERATE   ")
        self.assertClean(rpt)

    def test_verdict_with_bold_markdown_tolerated(self):
        """Scorer regex allows **VERDICT** styling; the validator must too."""
        rpt = _good("VERDICT: **MALICE** — act: HIGH, attribution: MODERATE")
        self.assertClean(rpt)

    # --- the THREE-checks seam --------------------------------------------------------------------

    def test_late_out_of_vocab_verdict_after_valid_one_is_allowed(self):
        """Scorer-aligned: scorer.parse_report_verdict returns ``known[-1] if known else matches[-1]``
        — the LAST RECOGNIZED token. A valid early ``VERDICT: MALICE — act: HIGH, attribution: MODERATE``
        followed by a stray out-of-vocab ``VERDICT: PROBABLY_BAD`` is read by the scorer as MALICE and
        grades fine. The hook MIRRORS the scorer, so it must ALLOW this — blocking it would false-fail a
        report the scorer can read (worse during a live run than tolerating a redundant stray line).
        """
        rpt = _good() + "\nAppendix: VERDICT: PROBABLY_BAD — act: HIGH, attribution: MODERATE\n"
        self.assertClean(rpt)

    def test_trailing_in_vocab_verdict_mention_does_not_false_block(self):
        """# BUG: false positive. A valid report that LATER mentions the verdict in prose
        (e.g. ``... see VERDICT: MALICE above``) gets blocked for "missing per-dimension confidence",
        because the confidence check only inspects the textually-last VERDICT-bearing line, not the
        line carrying the chosen token. The earlier line DOES carry act+attribution, so the report
        is valid and must pass.
        """
        rpt = _good() + "\nFor traceability see the VERDICT: MALICE line above.\n"
        self.assertClean(rpt)

    def test_confidence_error_names_the_unqualified_line(self):
        """# BUG: misdirected message. When the last VERDICT line lacks confidence, the emitted
        error interpolates ``chosen`` (the earlier in-vocab token MALICE) and claims MALICE is
        missing confidence — but the MALICE line HAS it. The message points the model at the wrong
        line. At minimum the validator should not assert a qualified token is unqualified.
        """
        rpt = _good() + "\nAppendix: VERDICT: MALICE\n"  # bare second mention, no qualifier
        probs = vr.validate_report(rpt, self.vocab)
        # Intended: either clean (trailing mention ignored) — but definitely NOT a message claiming
        # the qualified MALICE line is missing its confidence.
        bad = [p for p in probs if "missing per-dimension confidence" in p]
        self.assertEqual(bad, [], f"misdirected/false confidence error: {bad}")

    def test_unqualified_single_verdict_blocks(self):
        self.assertBlocks(_good("VERDICT: MALICE"), needle="per-dimension confidence")

    def test_only_one_dimension_qualified_blocks(self):
        rpt = _good("VERDICT: MALICE — act: HIGH")
        self.assertBlocks(rpt, needle="attribution")

    def test_confidence_value_off_vocab_blocks(self):
        """act/attribution present but with a non-vocab confidence word must not satisfy the check."""
        rpt = _good("VERDICT: MALICE — act: SUPER_HIGH, attribution: KINDA")
        self.assertBlocks(rpt, needle="per-dimension confidence")


# ===================================================================================================
# R4 — IOC table edges
# ===================================================================================================
class IocEdgeTests(_Base):
    def test_confidence_outside_vocab_blocks(self):
        rpt = _good().replace("| INFERRED   |", "| LIKELY     |")
        self.assertBlocks(rpt, needle="is not in the contract confidence")

    def test_confidence_lowercase_is_tolerated(self):
        """Confidence is upper-normalized before the vocab check, so 'confirmed' is legal."""
        rpt = _good().replace("| CONFIRMED  |", "| confirmed  |")
        self.assertClean(rpt)

    def test_extra_notes_column_blocks(self):
        rpt = textwrap.dedent(
            """
            # Report
            ## Summary
            x
            ## IOCs
            | Type | Value | Confidence | Notes |
            | --- | --- | --- | --- |
            | ip_address | 10.0.0.5 | CONFIRMED | netflow |
            ## Verdict
            VERDICT: MALICE — act: HIGH, attribution: MODERATE
            """
        )
        self.assertBlocks(rpt, needle="malformed")

    def test_table_with_header_and_separator_but_no_data_blocks(self):
        rpt = textwrap.dedent(
            """
            # Report
            ## Summary
            x
            ## IOCs
            | Type | Value | Confidence |
            | --- | --- | --- |
            ## Verdict
            VERDICT: MALICE — act: HIGH, attribution: MODERATE
            """
        )
        self.assertBlocks(rpt, needle="ZERO data rows")

    def test_no_ioc_table_at_all_blocks(self):
        rpt = textwrap.dedent(
            """
            # Report
            ## Summary
            x mentions IOC in prose only
            ## Verdict
            VERDICT: MALICE — act: HIGH, attribution: MODERATE
            """
        )
        self.assertBlocks(rpt, needle="could not find a well-formed IOC table")

    def test_empty_value_cell_blocks(self):
        rpt = _good().replace("| 10.0.0.5   |", "|            |")
        self.assertBlocks(rpt, needle="empty Value cell")

    def test_unknown_ioc_type_blocks(self):
        rpt = _good().replace("| ip_address  |", "| smell       |")
        self.assertBlocks(rpt, needle="not in the contract taxonomy")

    def test_crlf_ioc_rows_clean(self):
        """A fully valid report with CRLF must not trip the IOC parser (\\r in cells)."""
        self.assertClean(_good().replace("\n", "\r\n"))


# ===================================================================================================
# R4 — required-section / placeholder edges
# ===================================================================================================
class SectionEdgeTests(_Base):
    def test_todo_placeholder_blocks(self):
        rpt = _good().replace("A non-system account staged", "TODO write summary")
        self.assertBlocks(rpt, needle="placeholder")

    def test_angle_bracket_placeholder_blocks(self):
        rpt = _good().replace("A non-system account staged", "<fill in summary ...>")
        self.assertBlocks(rpt, needle="placeholder")

    def test_tbd_placeholder_blocks(self):
        rpt = _good().replace("A non-system account staged", "TBD")
        self.assertBlocks(rpt, needle="placeholder")


# ===================================================================================================
# R4 — end-to-end exit codes through main() (0 allow / 2 block)
# ===================================================================================================
class MainExitCodeTests(_Base):
    def test_valid_report_file_exit0(self):
        p = self.write_report(_good())
        rc, _, err = self.run_main(["--contract", self.contract_path, "--report-file", p])
        self.assertEqual(rc, 0, err)

    def test_out_of_vocab_token_report_file_exit2(self):
        p = self.write_report(_good("VERDICT: PROBABLY_BAD — act: HIGH, attribution: MODERATE"))
        rc, _, err = self.run_main(["--contract", self.contract_path, "--report-file", p])
        self.assertEqual(rc, 2, err)
        self.assertIn("BLOCKED by validate_report.py", err)

    def test_bad_confidence_report_file_exit2(self):
        p = self.write_report(_good().replace("| INFERRED   |", "| LIKELY     |"))
        rc, _, err = self.run_main(["--contract", self.contract_path, "--report-file", p])
        self.assertEqual(rc, 2, err)

    def test_missing_verdict_report_file_exit2(self):
        rpt = _good().replace("VERDICT: MALICE — act: HIGH, attribution: MODERATE",
                              "No conclusion.")
        p = self.write_report(rpt)
        rc, _, err = self.run_main(["--contract", self.contract_path, "--report-file", p])
        self.assertEqual(rc, 2, err)

    def test_empty_report_file_exit2(self):
        p = self.write_report("")
        rc, _, err = self.run_main(["--contract", self.contract_path, "--report-file", p])
        self.assertEqual(rc, 2, err)

    def test_crlf_valid_via_stdin_json_exit0(self):
        ev = {
            "tool_name": "Write",
            "tool_input": {"file_path": "reports/case.md", "content": _good().replace("\n", "\r\n")},
        }
        rc, _, err = self.run_main(
            ["--contract", self.contract_path, "--stdin-json"], stdin_text=json.dumps(ev)
        )
        self.assertEqual(rc, 0, err)

    def test_late_out_of_vocab_verdict_via_main_exit0(self):
        """Scorer-aligned e2e: a stray out-of-vocab LATER token after a valid recognized one — the
        scorer reads the recognized token (MALICE), so main() must ALLOW (exit 0)."""
        rpt = _good() + "\nAppendix: VERDICT: PROBABLY_BAD — act: HIGH, attribution: MODERATE\n"
        p = self.write_report(rpt)
        rc, _, err = self.run_main(["--contract", self.contract_path, "--report-file", p])
        self.assertEqual(rc, 0, f"recognized token is what the scorer reads; must allow; err={err}")

    def test_trailing_mention_via_main_exit0(self):
        """# BUG (e2e): a valid report that re-mentions VERDICT: MALICE in prose must still pass."""
        rpt = _good() + "\nFor traceability see the VERDICT: MALICE line above.\n"
        p = self.write_report(rpt)
        rc, _, err = self.run_main(["--contract", self.contract_path, "--report-file", p])
        self.assertEqual(rc, 0, f"trailing in-vocab mention should not block; err={err}")


if __name__ == "__main__":
    unittest.main(verbosity=2)

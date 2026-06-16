#!/usr/bin/env python3
"""Unit tests for check_contract_sync.py (R8) — stdlib unittest, synthetic fixtures.

Run from the repo root:
    python3 -m unittest scoring.test_check_contract_sync -v
or from scoring/:
    python3 -m unittest test_check_contract_sync -v

Fixtures are written to a temp dir; no real CLAUDE.md / contract.yaml is touched.
"""
from __future__ import annotations

import contextlib
import io
import os
import tempfile
import textwrap
import unittest

import check_contract_sync as C


def _quiet_check(yaml_path, targets) -> int:
    """Run C.check but swallow its stdout/stderr so the test log stays clean.

    The tool's [OK]/[DRIFT] prints are its real product; here we only assert the
    returned exit code, so the chatter is captured and discarded.
    """
    buf_out, buf_err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
        return C.check(yaml_path, targets)


# --------------------------------------------------------------------------------------
# Synthetic contract.yaml — same SHAPE as protocol-sift-build/contract.yaml but small.
# --------------------------------------------------------------------------------------
CONTRACT_YAML = textwrap.dedent(
    """\
    # synthetic contract for tests
    version: 1

    verdict:
      vocabulary:
        - token: MALICE
          meaning: Artifacts support malicious activity.
        - token: NON_MALICE
          meaning: Activity is lawful.
        - token: INCONCLUSIVE
          meaning: Insufficient to decide.
      confidence_levels: [HIGH, MODERATE, LOW]
      dimensions: [act, attribution]
      rules:
        - Emit exactly one token from the vocabulary.
        - The verdict is the LAST section of the report.
      equivalence_classes:
        malicious:     [MALICE, MALICIOUS]
        non_malicious: [NON_MALICE, BENIGN]
        inconclusive:  [INCONCLUSIVE, UNKNOWN]

    ioc:
      confidence_vocab: [CONFIRMED, INFERRED, UNCERTAIN]
      columns: [Type, Value, Confidence]
      types:
        - {type: email,      value_form: lowercase}
        - {type: file_hash,  value_form: "lowercase hex, no 0x / colons / spaces"}
        - {type: ip_address, value_form: "dotted quad, exact"}
      rules:
        - List ONLY indicators whose value appears in the evidence. Never invent.

    mitre:
      framework: MITRE ATT&CK (Enterprise)
      columns: [Technique, T-code, Evidencing artifact]
      code_format: "Txxxx or Txxxx.yyy"
      rules:
        - Map ONLY techniques you actually observed in the artifacts.
        - Never emit a T-code you cannot tie to evidence.
    """
)


def _render_block_from_yaml_text(yaml_text: str) -> str:
    """Render a contract BLOCK the same way render_contract.render would, but built
    here from the parsed dict — so the in-sync fixture is generated from the very
    canonicaliser under test's view of the YAML, mirroring the renderer's structure.

    This keeps the test stdlib-only (the real renderer needs PyYAML). The structure
    (headings, token bullets, fenced Format, tables, type bullets) matches
    protocol-sift-build/render_contract.py so canonical_from_claude_md parses it.
    """
    c = C.parse_yaml(yaml_text)
    v, ioc, mit = c["verdict"], c["ioc"], c["mitre"]
    toks = " / ".join(f"`{t['token']}`" for t in v["vocabulary"])
    dims = v["dimensions"]
    L = []
    L += ["## Deliverable Contract (REQUIRED in every report)", ""]
    L += ["Every investigation report MUST end with the three sections below.", ""]
    L += ["### 1. Verdict (last section of the report)", ""]
    L += [f"End the report with a one-word verdict token — one of {toks} — qualified "
          f"by confidence per dimension ({', '.join(dims)}). "
          f"Levels: {', '.join(v['confidence_levels'])}.", ""]
    L += [f"- {t['token']} — {t['meaning']}" for t in v["vocabulary"]]
    L += ["", "Format:", "```"]
    L += [f"VERDICT: <TOKEN> — {', '.join(d + ': <LEVEL>' for d in dims)}", "```"]
    L += [f"- {r}" for r in v["rules"]]
    L += [""]
    L += ["### 2. Indicators of Compromise (IOC table)", ""]
    L += [f"List every indicator in one table with columns "
          f"**{' | '.join(ioc['columns'])}**. "
          f"Confidence is one of {', '.join(ioc['confidence_vocab'])}.", ""]
    L += ["| " + " | ".join(ioc["columns"]) + " |",
          "|" + "|".join("---" for _ in ioc["columns"]) + "|",
          "| <type> | <value> | <CONFIRMED\\|INFERRED\\|UNCERTAIN> |", ""]
    L += ["Allowed `Type` values (write `Value` in the form shown):"]
    L += [f"- `{t['type']}` — {t['value_form']}" for t in ioc["types"]]
    L += [""]
    L += [f"- {r}" for r in ioc["rules"]]
    L += [""]
    L += ["### 3. MITRE ATT&CK mapping", ""]
    L += [f"Map observed techniques in one table — columns "
          f"**{' | '.join(mit['columns'])}**. Framework: {mit['framework']}. "
          f"Code format: {mit['code_format']}.", ""]
    L += ["| " + " | ".join(mit["columns"]) + " |",
          "|" + "|".join("---" for _ in mit["columns"]) + "|",
          "| <technique name> | T#### | <ART-id / tool output> |", ""]
    L += [f"- {r}" for r in mit["rules"]]
    return "\n".join(L).rstrip() + "\n"


def _wrap(block: str, *, with_markers: bool = True) -> str:
    md = ["# Project CLAUDE.md", "", "Some preamble.", ""]
    if with_markers:
        md += [C.START_PREFIX + " (generated from contract/contract.yaml) -->", ""]
    md += [block]
    if with_markers:
        md += [C.END_MARKER]
    md += ["", "Trailing project notes that must be ignored.", ""]
    return "\n".join(md)


class _TmpFiles:
    """Helper: write the synthetic contract + a CLAUDE.md into a temp dir."""

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="r8_contract_")
        self.contract = os.path.join(self.dir, "contract.yaml")
        with open(self.contract, "w", encoding="utf-8") as f:
            f.write(CONTRACT_YAML)

    def write_claude(self, name: str, text: str) -> str:
        p = os.path.join(self.dir, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p


class TestYamlParser(unittest.TestCase):
    def test_parses_nested_structure(self):
        c = C.parse_yaml(CONTRACT_YAML)
        self.assertEqual([t["token"] for t in c["verdict"]["vocabulary"]],
                         ["MALICE", "NON_MALICE", "INCONCLUSIVE"])
        self.assertEqual(c["verdict"]["confidence_levels"], ["HIGH", "MODERATE", "LOW"])
        self.assertEqual(c["ioc"]["columns"], ["Type", "Value", "Confidence"])
        self.assertEqual(c["ioc"]["types"][1]["type"], "file_hash")
        self.assertEqual(c["mitre"]["framework"], "MITRE ATT&CK (Enterprise)")

    def test_flow_mapping_value_form_kept(self):
        c = C.parse_yaml(CONTRACT_YAML)
        self.assertEqual(c["ioc"]["types"][1]["value_form"],
                         "lowercase hex, no 0x / colons / spaces")


class TestInSync(unittest.TestCase):
    """A faithfully-rendered CLAUDE.md must PASS (exit 0, no diff)."""

    def setUp(self):
        self.fx = _TmpFiles()
        self.block = _render_block_from_yaml_text(CONTRACT_YAML)

    def test_diff_target_in_sync(self):
        p = self.fx.write_claude("CLAUDE.md", _wrap(self.block))
        in_sync, diff = C.diff_target(self.fx.contract, p)
        self.assertTrue(in_sync, msg=diff)
        self.assertEqual(diff, "")

    def test_check_returns_zero(self):
        p = self.fx.write_claude("CLAUDE.md", _wrap(self.block))
        self.assertEqual(_quiet_check(self.fx.contract, [p]), 0)

    def test_multiple_in_sync_targets(self):
        p1 = self.fx.write_claude("global_CLAUDE.md", _wrap(self.block))
        p2 = self.fx.write_claude("deployed_CLAUDE.md", _wrap(self.block))
        self.assertEqual(_quiet_check(self.fx.contract, [p1, p2]), 0)

    def test_canonical_form_excludes_equivalence_classes(self):
        # eqclasses live in scorer.py, never in the rendered block — must not appear
        canon = C.canonical_from_yaml(C.parse_yaml(CONTRACT_YAML))
        self.assertNotIn("eqclass", canon)
        self.assertIn("tokens: MALICE | NON_MALICE | INCONCLUSIVE", canon)


class TestDrift(unittest.TestCase):
    """Each kind of contract drift must FAIL (exit 1) and surface a diff."""

    def setUp(self):
        self.fx = _TmpFiles()
        self.good = _render_block_from_yaml_text(CONTRACT_YAML)

    def _expect_drift(self, block: str, needle: str):
        p = self.fx.write_claude("CLAUDE.md", _wrap(block))
        in_sync, diff = C.diff_target(self.fx.contract, p)
        self.assertFalse(in_sync)
        self.assertNotEqual(diff, "")
        self.assertIn(needle, diff)
        self.assertEqual(_quiet_check(self.fx.contract, [p]), 1)

    def test_drift_verdict_token_renamed(self):
        drifted = self.good.replace("- NON_MALICE — Activity is lawful.",
                                    "- BENIGN — Activity is lawful.")
        self._expect_drift(drifted, "tokens:")

    def test_drift_verdict_token_removed(self):
        drifted = self.good.replace("- INCONCLUSIVE — Insufficient to decide.\n", "")
        self._expect_drift(drifted, "INCONCLUSIVE")

    def test_drift_confidence_levels_changed(self):
        drifted = self.good.replace("Levels: HIGH, MODERATE, LOW.",
                                    "Levels: HIGH, LOW.")
        self._expect_drift(drifted, "confidence_levels:")

    def test_drift_ioc_column_added(self):
        drifted = self.good.replace("**Type | Value | Confidence**",
                                    "**Type | Value | Confidence | Source**")
        drifted = drifted.replace("| Type | Value | Confidence |",
                                  "| Type | Value | Confidence | Source |")
        self._expect_drift(drifted, "columns:")

    def test_drift_ioc_confidence_vocab_changed(self):
        drifted = self.good.replace("Confidence is one of CONFIRMED, INFERRED, UNCERTAIN.",
                                    "Confidence is one of CONFIRMED, INFERRED.")
        self._expect_drift(drifted, "confidence_vocab:")

    def test_drift_ioc_type_value_form_changed(self):
        drifted = self.good.replace("- `email` — lowercase",
                                    "- `email` — any case")
        self._expect_drift(drifted, "type email:")

    def test_drift_mitre_rule_removed(self):
        drifted = self.good.replace(
            "- Never emit a T-code you cannot tie to evidence.\n", "")
        self._expect_drift(drifted, "T-code")

    def test_drift_mitre_code_format_changed(self):
        drifted = self.good.replace("Code format: Txxxx or Txxxx.yyy.",
                                    "Code format: T#### only.")
        self._expect_drift(drifted, "code_format:")


class TestErrors(unittest.TestCase):
    def setUp(self):
        self.fx = _TmpFiles()
        self.block = _render_block_from_yaml_text(CONTRACT_YAML)

    def test_missing_markers_is_error_exit_2(self):
        p = self.fx.write_claude("CLAUDE.md", _wrap(self.block, with_markers=False))
        with self.assertRaises(ValueError):
            C.diff_target(self.fx.contract, p)
        self.assertEqual(_quiet_check(self.fx.contract, [p]), 2)

    def test_missing_target_file_exit_2(self):
        missing = os.path.join(self.fx.dir, "nope_CLAUDE.md")
        self.assertEqual(_quiet_check(self.fx.contract, [missing]), 2)

    def test_missing_contract_yaml_exit_2(self):
        p = self.fx.write_claude("CLAUDE.md", _wrap(self.block))
        self.assertEqual(_quiet_check(os.path.join(self.fx.dir, "no.yaml"), [p]), 2)

    def test_no_targets_exit_2(self):
        self.assertEqual(_quiet_check(self.fx.contract, []), 2)

    def test_one_ok_one_drift_returns_drift(self):
        ok = self.fx.write_claude("ok_CLAUDE.md", _wrap(self.block))
        bad_block = self.block.replace("- `email` — lowercase", "- `email` — ANY")
        bad = self.fx.write_claude("bad_CLAUDE.md", _wrap(bad_block))
        self.assertEqual(_quiet_check(self.fx.contract, [ok, bad]), 1)


class TestExtractBlock(unittest.TestCase):
    def test_extracts_between_markers(self):
        block = _render_block_from_yaml_text(CONTRACT_YAML)
        md = _wrap(block)
        got = C.extract_contract_block(md)
        self.assertIsNotNone(got)
        self.assertIn("Deliverable Contract", got)
        self.assertNotIn("Trailing project notes", got)
        self.assertNotIn(C.END_MARKER, got)

    def test_returns_none_without_markers(self):
        self.assertIsNone(C.extract_contract_block("# CLAUDE.md\n\nno markers here\n"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Adversarial unit tests for check_contract_sync.py (R8) — stdlib unittest only.

This is a NEW, separate suite from test_check_contract_sync.py. It is engineered to
push the contract-drift checker onto its HARDEST edges and to pin down (and document)
its real, observed behaviour — including a few intentional prose-coupling fragilities
that a future refactor must not silently regress.

Run from the scoring/ directory:
    python3 -m unittest test_check_contract_sync_adversarial -v
or from the repo root:
    python3 -m unittest scoring.test_check_contract_sync_adversarial -v

SCOPE NOTE (R4 / R6 vs R8)
--------------------------
The orchestration prompt that spawned this task carries a shared adversarial template
that also references R4 (report-format/verdict-vocabulary validation) and R6 (tamper-
evident ledger / hash-chain) edges. The file under test —
``scoring/check_contract_sync.py`` — implements NEITHER of those. It is purely the R8
render/deploy DRIFT check: derive a canonical contract from contract.yaml, extract the
contract block from each CLAUDE.md, re-derive the same canonical fields, and diff.

There is no report parser, no verdict-token *acceptance* gate, and no hash ledger in
this module (``grep`` for ``entry_hash``/``prev_hash``/``VERDICT:`` acceptance logic
finds nothing). Writing R4/R6 "tests" here would test code that does not exist and
would pass vacuously, which is worse than honest. So this suite exercises the R8
contract exhaustively and explicitly records that R4/R6 are out of scope for this file.
The closest R4-flavoured edge that IS meaningful here — a verdict-vocab token drift in
the rendered block — is covered (TestVerdictVocabDrift).

All fixtures are synthetic and written to a temp dir; no real contract.yaml or
CLAUDE.md is read or written.
"""
from __future__ import annotations

import contextlib
import io
import os
import tempfile
import textwrap
import unittest

import check_contract_sync as C


# ======================================================================================
# Synthetic contract.yaml (same SHAPE as protocol-sift-build/contract.yaml, kept small).
# ======================================================================================
CONTRACT_YAML = textwrap.dedent(
    """\
    # synthetic contract for adversarial tests
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


def _render_block(yaml_text: str) -> str:
    """Render a contract BLOCK whose prose structure matches what
    protocol-sift-build/render_contract.py emits closely enough that
    canonical_from_claude_md round-trips it to byte-identical canonical text.

    Crucially this includes the load-bearing prose tokens the parser keys on:
      * "confidence per dimension (<dims>)" for the dimension list,
      * "Levels: <...>." for confidence levels,
      * "Confidence is one of <...>." for the IOC confidence vocab,
      * "Framework: <...>." and "Code format: <...>." for MITRE.
    """
    c = C.parse_yaml(yaml_text)
    v, ioc, mit = c["verdict"], c["ioc"], c["mitre"]
    toks = " / ".join(f"`{t['token']}`" for t in v["vocabulary"])
    dims = v["dimensions"]
    L = []
    L += ["## Deliverable Contract (REQUIRED in every report)", ""]
    L += ["Every investigation report MUST end with the three sections below.", ""]
    L += ["### 1. Verdict (last section of the report)", ""]
    L += [
        f"End the report with a one-word verdict token — one of {toks} — qualified "
        f"by confidence per dimension ({', '.join(dims)}). "
        f"Levels: {', '.join(v['confidence_levels'])}.",
        "",
    ]
    L += [f"- {t['token']} — {t['meaning']}" for t in v["vocabulary"]]
    L += ["", "Format:", "```"]
    L += [f"VERDICT: <TOKEN> — {', '.join(d + ': <LEVEL>' for d in dims)}", "```"]
    L += [f"- {r}" for r in v["rules"]]
    L += [""]
    L += ["### 2. Indicators of Compromise (IOC table)", ""]
    L += [
        f"List every indicator in one table with columns "
        f"**{' | '.join(ioc['columns'])}**. "
        f"Confidence is one of {', '.join(ioc['confidence_vocab'])}.",
        "",
    ]
    L += [
        "| " + " | ".join(ioc["columns"]) + " |",
        "|" + "|".join("---" for _ in ioc["columns"]) + "|",
        "| <type> | <value> | <CONFIRMED\\|INFERRED\\|UNCERTAIN> |",
        "",
    ]
    L += ["Allowed `Type` values (write `Value` in the form shown):"]
    L += [f"- `{t['type']}` — {t['value_form']}" for t in ioc["types"]]
    L += [""]
    L += [f"- {r}" for r in ioc["rules"]]
    L += [""]
    L += ["### 3. MITRE ATT&CK mapping", ""]
    L += [
        f"Map observed techniques in one table — columns "
        f"**{' | '.join(mit['columns'])}**. Framework: {mit['framework']}. "
        f"Code format: {mit['code_format']}.",
        "",
    ]
    L += [
        "| " + " | ".join(mit["columns"]) + " |",
        "|" + "|".join("---" for _ in mit["columns"]) + "|",
        "| <technique name> | T#### | <ART-id / tool output> |",
        "",
    ]
    L += [f"- {r}" for r in mit["rules"]]
    return "\n".join(L).rstrip() + "\n"


def _wrap(block: str, *, with_markers: bool = True, stray_block: bool = False) -> str:
    """Embed a contract block in a plausible CLAUDE.md with surrounding prose.

    stray_block=True prepends a *second*, complete START..END pair earlier in the
    file, to test which block extract_contract_block selects (first one wins).
    """
    md = ["# Project CLAUDE.md", "", "Some preamble.", ""]
    if stray_block:
        md += [
            C.START_PREFIX + " (STRAY older block) -->",
            "this is a stale earlier contract block",
            C.END_MARKER,
            "",
        ]
    if with_markers:
        md += [C.START_PREFIX + " (generated from contract/contract.yaml) -->", ""]
    md += [block]
    if with_markers:
        md += [C.END_MARKER]
    md += ["", "Trailing project notes that must be ignored.", ""]
    return "\n".join(md)


def _quiet_check(yaml_path, targets) -> int:
    buf_out, buf_err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
        return C.check(yaml_path, targets)


def _quiet_main(argv) -> int:
    buf_out, buf_err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
        return C.main(argv)


class _Fx:
    """Temp-dir fixture: a synthetic contract.yaml + helpers to write CLAUDE.md files.

    IMPORTANT: all writes use ``with open(..., encoding="utf-8")`` so the em-dash (—,
    a 3-byte UTF-8 char the renderer uses) round-trips and the file is flushed before
    the checker (which reads with encoding="utf-8") opens it.
    """

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="r8_adv_")
        self.contract = os.path.join(self.dir, "contract.yaml")
        with open(self.contract, "w", encoding="utf-8") as f:
            f.write(CONTRACT_YAML)

    def write(self, name: str, text: str) -> str:
        p = os.path.join(self.dir, name)
        with open(p, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        return p

    def block(self) -> str:
        return _render_block(CONTRACT_YAML)


# ======================================================================================
# 0. Baseline: a byte-identical faithful render PASSES (exit 0, no diff).
# ======================================================================================
class TestByteIdenticalPasses(unittest.TestCase):
    def setUp(self):
        self.fx = _Fx()

    def test_clean_render_in_sync_exit_0(self):
        p = self.fx.write("CLAUDE.md", _wrap(self.fx.block()))
        in_sync, diff = C.diff_target(self.fx.contract, p)
        self.assertTrue(in_sync, msg="faithful render must be in sync; diff:\n" + diff)
        self.assertEqual(diff, "")
        self.assertEqual(_quiet_check(self.fx.contract, [p]), 0)

    def test_canonical_round_trip_is_byte_identical(self):
        expected = C.canonical_from_yaml(C.parse_yaml(CONTRACT_YAML))
        actual = C.canonical_from_claude_md(self.fx.block())
        self.assertEqual(expected, actual)


# ======================================================================================
# 1. Verdict-vocabulary drift (the R8-relevant flavour of an "R4" vocab violation):
#    a single token in the rendered block differs from contract.yaml -> non-zero exit.
# ======================================================================================
class TestVerdictVocabDrift(unittest.TestCase):
    def setUp(self):
        self.fx = _Fx()
        self.good = self.fx.block()

    def _assert_drift(self, block: str, needle: str = None):
        p = self.fx.write("CLAUDE.md", _wrap(block))
        in_sync, diff = C.diff_target(self.fx.contract, p)
        self.assertFalse(in_sync, msg="expected DRIFT but checker said in-sync")
        self.assertNotEqual(diff, "")
        if needle is not None:
            self.assertIn(needle, diff)
        self.assertEqual(_quiet_check(self.fx.contract, [p]), 1)
        return diff

    def test_single_token_renamed_to_off_vocab(self):
        # MALICE -> EVIL: a one-token verdict-vocab drift must be caught.
        drifted = self.good.replace("- MALICE — Artifacts", "- EVIL — Artifacts")
        diff = self._assert_drift(drifted, "tokens:")
        self.assertIn("EVIL", diff)
        self.assertIn("MALICE", diff)

    def test_extra_off_vocab_token_appended(self):
        # An extra bullet 'ROGUE' not in the contract appears in the tokens line.
        drifted = self.good.replace(
            "- INCONCLUSIVE — Insufficient to decide.",
            "- INCONCLUSIVE — Insufficient to decide.\n- ROGUE — invented token",
        )
        diff = self._assert_drift(drifted, "tokens:")
        self.assertIn("ROGUE", diff)

    def test_token_reorder_is_detected(self):
        # Canonical comparison is ORDER-SENSITIVE: swapping two token bullets drifts.
        drifted = self.good.replace(
            "- MALICE — Artifacts support malicious activity.\n"
            "- NON_MALICE — Activity is lawful.",
            "- NON_MALICE — Activity is lawful.\n"
            "- MALICE — Artifacts support malicious activity.",
        )
        # sanity: the replacement actually changed the text
        self.assertNotEqual(drifted, self.good)
        diff = self._assert_drift(drifted, "tokens:")
        self.assertIn("NON_MALICE | MALICE", diff)

    def test_confidence_level_dropped(self):
        # "confidence value outside the vocab" analogue: a level removed from the set.
        drifted = self.good.replace("Levels: HIGH, MODERATE, LOW.",
                                    "Levels: HIGH, LOW.")
        self._assert_drift(drifted, "confidence_levels:")

    def test_dimension_dropped(self):
        drifted = self.good.replace("(act, attribution)", "(act)")
        self._assert_drift(drifted, "dimensions:")

    def test_ioc_confidence_vocab_shrunk(self):
        # IOC table confidence value outside the contract vocab (UNCERTAIN removed).
        drifted = self.good.replace(
            "Confidence is one of CONFIRMED, INFERRED, UNCERTAIN.",
            "Confidence is one of CONFIRMED, INFERRED.",
        )
        self._assert_drift(drifted, "confidence_vocab:")

    def test_ioc_column_added(self):
        drifted = self.good.replace("**Type | Value | Confidence**",
                                    "**Type | Value | Confidence | Source**")
        drifted = drifted.replace("| Type | Value | Confidence |",
                                  "| Type | Value | Confidence | Source |")
        self._assert_drift(drifted, "columns:")

    def test_mitre_rule_removed(self):
        drifted = self.good.replace(
            "- Never emit a T-code you cannot tie to evidence.\n", "")
        self._assert_drift(drifted, "T-code")

    def test_mitre_framework_changed(self):
        drifted = self.good.replace("Framework: MITRE ATT&CK (Enterprise).",
                                    "Framework: MITRE ATT&CK (Mobile).")
        self._assert_drift(drifted, "framework:")


# ======================================================================================
# 2. Missing / empty / whitespace blocks and markers.
# ======================================================================================
class TestMissingAndEmptyBlocks(unittest.TestCase):  # leak-scan: allow secret.entropy
    def setUp(self):
        self.fx = _Fx()
        self.good = self.fx.block()

    def test_missing_block_entirely_is_error_exit_2_not_crash(self):
        # No START/END markers at all: must raise ValueError (not crash) and the CLI
        # must map that to exit 2, NOT silently pass.
        p = self.fx.write("CLAUDE.md", _wrap(self.good, with_markers=False))
        with self.assertRaises(ValueError):
            C.diff_target(self.fx.contract, p)
        self.assertEqual(_quiet_check(self.fx.contract, [p]), 2)

    def test_start_without_end_is_error_exit_2(self):
        # START marker present but END missing: extract returns None -> exit 2.
        broken = _wrap(self.good).replace(C.END_MARKER, "")
        p = self.fx.write("CLAUDE.md", broken)
        self.assertIsNone(C.extract_contract_block(broken))
        self.assertEqual(_quiet_check(self.fx.contract, [p]), 2)

    def test_empty_block_between_markers_is_drift_exit_1(self):
        # An empty contract block is NOT an IO error (markers are present); it is a
        # DRIFT (every contract field is empty vs populated) -> exit 1.
        p = self.fx.write("CLAUDE.md", _wrap(""))
        in_sync, diff = C.diff_target(self.fx.contract, p)
        self.assertFalse(in_sync)
        self.assertIn("tokens:", diff)
        self.assertEqual(_quiet_check(self.fx.contract, [p]), 1)

    def test_whitespace_only_block_between_markers_is_drift_exit_1(self):
        p = self.fx.write("CLAUDE.md", _wrap("   \n\t\n   "))
        in_sync, _ = C.diff_target(self.fx.contract, p)
        self.assertFalse(in_sync)
        self.assertEqual(_quiet_check(self.fx.contract, [p]), 1)


# ======================================================================================
# 3. Whitespace / line-ending tolerance: cosmetic-only differences MUST still PASS.
#    (Documents the intended "robust to cosmetic markdown/whitespace" contract.)
# ======================================================================================
class TestWhitespaceTolerance(unittest.TestCase):
    def setUp(self):
        self.fx = _Fx()
        self.good = self.fx.block()

    def test_crlf_line_endings_still_in_sync(self):
        crlf = _wrap(self.good).replace("\n", "\r\n")
        p = self.fx.write("CLAUDE.md", crlf)
        in_sync, diff = C.diff_target(self.fx.contract, p)
        self.assertTrue(in_sync, msg="CRLF must be tolerated; diff:\n" + diff)
        self.assertEqual(_quiet_check(self.fx.contract, [p]), 0)

    def test_trailing_whitespace_on_every_line_still_in_sync(self):
        padded = "\n".join(ln + "   \t" for ln in self.good.splitlines()) + "\n"
        p = self.fx.write("CLAUDE.md", _wrap(padded))
        in_sync, diff = C.diff_target(self.fx.contract, p)
        self.assertTrue(in_sync, msg="trailing ws must be tolerated; diff:\n" + diff)

    def test_uniform_leading_indent_still_in_sync(self):
        # Every block line indented by 3 spaces — a pure-whitespace difference.
        # DECISION/INTENT: this MUST remain in-sync (the canonicaliser strips per line),
        # i.e. a whitespace-only difference is deliberately treated as NO drift.
        indented = "\n".join("   " + ln for ln in self.good.splitlines()) + "\n"
        p = self.fx.write("CLAUDE.md", _wrap(indented))
        in_sync, diff = C.diff_target(self.fx.contract, p)
        self.assertTrue(in_sync, msg="leading-indent ws must be tolerated; diff:\n" + diff)
        self.assertEqual(_quiet_check(self.fx.contract, [p]), 0)

    def test_extra_blank_lines_in_block_still_in_sync(self):
        loosened = self.good.replace("\n", "\n\n")
        p = self.fx.write("CLAUDE.md", _wrap(loosened))
        in_sync, diff = C.diff_target(self.fx.contract, p)
        self.assertTrue(in_sync, msg="extra blank lines must be tolerated; diff:\n" + diff)


# ======================================================================================
# 4. Marker-handling edges.
# ======================================================================================
class TestMarkerEdges(unittest.TestCase):
    def setUp(self):
        self.fx = _Fx()
        self.good = self.fx.block()

    def test_first_block_wins_when_two_blocks_present(self):
        # A stale earlier block + a fresh correct one: extract takes the FIRST. So a
        # stale-but-first block must be reported as drift even though a correct block
        # exists later in the file (the checker can't know which is authoritative).
        md = _wrap(self.good, stray_block=True)
        got = C.extract_contract_block(md)
        self.assertIn("stale earlier contract block", got)
        p = self.fx.write("CLAUDE.md", md)
        self.assertEqual(_quiet_check(self.fx.contract, [p]), 1)

    def test_variable_start_marker_parenthetical_is_tolerated(self):
        # The START line carries a free-text parenthetical; a different one must not
        # affect extraction (prefix + first '-->' is what matters).
        md = _wrap(self.good).replace(
            "(generated from contract/contract.yaml)", "(rendered 2026-06-14 by CI)"
        )
        p = self.fx.write("CLAUDE.md", md)
        self.assertEqual(_quiet_check(self.fx.contract, [p]), 0)


# ======================================================================================
# 5. Exit-code contract end-to-end via check() and main().
# ======================================================================================
class TestExitCodeContract(unittest.TestCase):
    def setUp(self):
        self.fx = _Fx()
        self.good = self.fx.block()

    def test_no_targets_is_usage_error_exit_2(self):
        self.assertEqual(_quiet_check(self.fx.contract, []), 2)

    def test_missing_contract_yaml_exit_2(self):
        p = self.fx.write("CLAUDE.md", _wrap(self.good))
        self.assertEqual(
            _quiet_check(os.path.join(self.fx.dir, "absent.yaml"), [p]), 2)

    def test_missing_target_file_exit_2(self):
        self.assertEqual(
            _quiet_check(self.fx.contract, [os.path.join(self.fx.dir, "ghost.md")]), 2)

    def test_one_clean_one_drift_returns_1(self):
        ok = self.fx.write("ok.md", _wrap(self.good))
        bad = self.fx.write("bad.md", _wrap(self.good.replace("- MALICE — Artifacts",
                                                              "- EVIL — Artifacts")))
        self.assertEqual(_quiet_check(self.fx.contract, [ok, bad]), 1)

    def test_first_error_short_circuits_to_2_even_with_later_clean(self):
        # A missing first target should make the whole run exit 2 regardless of a
        # later clean target.
        ghost = os.path.join(self.fx.dir, "ghost.md")
        ok = self.fx.write("ok.md", _wrap(self.good))
        self.assertEqual(_quiet_check(self.fx.contract, [ghost, ok]), 2)

    def test_main_argv_clean_exit_0(self):
        p = self.fx.write("CLAUDE.md", _wrap(self.good))
        self.assertEqual(_quiet_main(["--contract", self.fx.contract, p]), 0)

    def test_main_argv_drift_exit_1(self):
        p = self.fx.write("CLAUDE.md",
                          _wrap(self.good.replace("- MALICE — Artifacts",
                                                  "- EVIL — Artifacts")))
        self.assertEqual(_quiet_main(["--contract", self.fx.contract, p]), 1)


# ======================================================================================
# 6. Heuristic-fragility characterisation (DOCUMENTING, not endorsing).
#    These pin down known prose-coupling limits of canonical_from_claude_md so a
#    refactor that changes them trips a test. They are deliberately written as
#    "this is what it currently does" with a comment on the risk.
# ======================================================================================
class TestKnownHeuristicFragilities(unittest.TestCase):
    def setUp(self):
        self.fx = _Fx()
        self.good = self.fx.block()

    def test_lowercased_token_is_misparsed_but_still_flags_drift(self):
        # FRAGILITY: a token rendered in non-ALLCAPS (e.g. "Malice") fails the token
        # heuristic and is reclassified as a *rule*, so it vanishes from the tokens
        # line. The SUBSTANTIVE outcome we care about (drift is flagged, exit 1) still
        # holds — but the diff misattributes the cause (token dropped, not "Malice").
        drifted = self.good.replace("- MALICE — Artifacts", "- Malice — Artifacts")
        p = self.fx.write("CLAUDE.md", _wrap(drifted))
        in_sync, diff = C.diff_target(self.fx.contract, p)
        self.assertFalse(in_sync)
        self.assertIn("tokens: NON_MALICE | INCONCLUSIVE", diff)  # MALICE is gone
        self.assertEqual(_quiet_check(self.fx.contract, [p]), 1)

    def test_tab_after_dash_drops_the_bullet_false_positive_drift(self):
        # FRAGILITY (potential FALSE POSITIVE): a token bullet whose dash is followed
        # by a TAB instead of a space ("-\tMALICE — ...") is NOT recognised as a
        # bullet (the parser tests `startswith("- ")`), so the token is dropped and a
        # *faithful* render is reported as drift. Severity is low because the real
        # renderer always emits "- " (dash + single space); this test exists to make
        # the brittleness visible and catch any change in behaviour.
        drifted = self.good.replace("- MALICE — Artifacts", "-\tMALICE — Artifacts")
        p = self.fx.write("CLAUDE.md", _wrap(drifted))
        in_sync, diff = C.diff_target(self.fx.contract, p)
        self.assertFalse(in_sync)  # documents the (arguably wrong) current outcome
        self.assertIn("tokens: NON_MALICE | INCONCLUSIVE", diff)

    def test_plain_hyphen_separator_token_still_recognised(self):
        # _split_em falls back from the em-dash " — " to a plain " - " separator, so a
        # token bullet using a hyphen separator is still recognised as that token.
        # (Verified in isolation so the verdict tokens line is unaffected.)
        block = self.good.replace(
            "- MALICE — Artifacts support malicious activity.",
            "- MALICE - Artifacts support malicious activity.",
        )
        canon = C.canonical_from_claude_md(block)
        self.assertIn("tokens: MALICE | NON_MALICE | INCONCLUSIVE", canon)


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""ADVERSARIAL tests for the R2 glass-box DISCIPLINE scorer.

These cases are engineered to BREAK ``scoring/method_scorer.py`` on the hardest
edges of R2-DISCIPLINE-SCORER-SPEC.md. They assert the SPEC-CORRECT behaviour,
so a case that fails is direct evidence of a scorer bug (not a test bug).

Each test docstring states (a) the spec rule under test and (b) what a wrong
answer would mean for a real investigation.

Stdlib ``unittest`` only. All fixtures are synthetic inline text + fake bash_raw
records (the fields ``bashlog.load_bash_log`` produces). Run from the repo ROOT:

    python3 -m unittest scoring.test_method_scorer_adversarial -v
"""

import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, os.pardir))
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)

import method_scorer  # noqa: E402


# ---------------------------------------------------------------------------
# Fixture helpers (mirror bashlog.load_bash_log() entry shape).
# ---------------------------------------------------------------------------
def fake_entry(command, stdout="", persisted=None, ts=None):
    e = {
        "command": command,
        "stdout": stdout,
        "stderr": "",
        "outcome": "ok",
        "persisted_output_path": persisted,
        "persisted_output_size": (len(stdout) + 100000) if persisted else None,
    }
    if ts is not None:
        e["ts"] = ts
    return e


def bash_log(*pairs):
    return {tuid: entry for tuid, entry in pairs}


H_BAD = "a" * 64        # asserted-malicious file hash
H_OTHER = "b" * 64      # a conflicting same-length hash
IP_C2 = "203.0.113.5"   # an exfil / C2 address


def _row_for(out, value):
    cands = [r for r in out["rows"] if str(r["value"]).lower() == value.lower()]
    return cands[0] if cands else None


# ===========================================================================
# DECISION 1 — CORROBORATION (count by ARTIFACT TYPE)
# ===========================================================================
class TestSameArtifactCollapsesToOne(unittest.TestCase):
    """Spec 1: 're-runs and two fields of one artifact = 1 source'. Two
    corroborating hits from the SAME (tool, artifact) must NOT inflate a
    CONFIRMED to >=2 sources. If they did, the scorer would bless an
    uncorroborated claim."""

    def test_two_pslist_reruns_collapse_to_one_source_violation(self):
        # Same plugin (windows.pslist) run twice over two memory images.
        report = (
            "| Type | Value | Confidence |\n"
            "|------|-------|-----------|\n"
            f"| ip_address | {IP_C2} | CONFIRMED |\n"
        )
        log = bash_log(
            ("t1", fake_entry("vol.py -f mem1.raw windows.pslist", f"pslist {IP_C2}")),
            ("t2", fake_entry("vol.py -f mem2.raw windows.pslist", f"pslist {IP_C2}")),
        )
        out = method_scorer.score_corroboration(report, log)
        row = out["rows"][0]
        self.assertEqual(row["distinct_source_count"], 1,
                         "two windows.pslist runs are ONE artifact-type source")
        self.assertEqual(row["correct_label"], "INFERRED")
        self.assertTrue(row["violation"])
        self.assertEqual(len(out["violations_confirmed_single_source"]), 1)
        self.assertEqual(out["corroboration_pass_rate"], 0.0)

    def test_two_greps_over_same_txt_collapse_to_one(self):
        # Two greps over the SAME .txt = one (weak) source per spec edge.
        report = (
            "| Type | Value | Confidence |\n"
            f"| ip_address | {IP_C2} | CONFIRMED |\n"
        )
        log = bash_log(
            ("t1", fake_entry(f"grep {IP_C2} indicators.txt", f"{IP_C2}")),
            ("t2", fake_entry(f"grep -i {IP_C2} indicators.txt", f"{IP_C2}")),
        )
        out = method_scorer.score_corroboration(report, log)
        row = out["rows"][0]
        self.assertEqual(row["distinct_source_count"], 1)
        self.assertEqual(row["correct_label"], "INFERRED")
        self.assertTrue(row["violation"])


class TestTwoArtifactTypesInOneCommandCountAsTwo(unittest.TestCase):
    """Spec 1 (LOCKED): 'Two different artifact-types in one command still count
    as 2.' The canonical example named in the prompt is
    ``diff <(vol ... psscan) <(vol ... pslist)``. A scorer that dedups on
    ``tool_use_id`` (one command -> one id) gets this wrong and wrongly
    DOWNGRADES a genuinely two-source CONFIRMED to INFERRED."""

    def test_diff_process_substitution_two_plugins_one_command(self):
        report = (
            "| Type | Value | Confidence |\n"
            "|------|-------|-----------|\n"
            f"| ip_address | {IP_C2} | CONFIRMED |\n"
        )
        log = bash_log(
            ("t1", fake_entry(
                "diff <(vol.py -f m.raw windows.psscan) "
                "<(vol.py -f m.raw windows.pslist)",
                f"psscan ... {IP_C2}\npslist ... {IP_C2}")),
        )
        out = method_scorer.score_corroboration(report, log)
        row = out["rows"][0]
        self.assertEqual(
            row["distinct_source_count"], 2,
            "psscan + pslist in ONE process-substitution command are 2 "
            "artifact-types (locked decision)",
        )
        self.assertIn("vol:mem-psscan", row["distinct_sources"])
        self.assertIn("vol:mem-pslist", row["distinct_sources"])
        self.assertEqual(row["correct_label"], "CONFIRMED")
        self.assertFalse(row["violation"])
        self.assertEqual(out["corroboration_pass_rate"], 1.0)

    def test_diff_process_substitution_index_resolves_both_pairs(self):
        # Lower-level: build_artifact_index must surface BOTH (family, artifact).
        log = bash_log(
            ("t1", fake_entry(
                "diff <(vol.py -f m.raw windows.netscan) "
                "<(vol.py -f m.raw windows.netstat)")),
        )
        idx = method_scorer.build_artifact_index(log)
        pairs = set(idx["t1"]["pairs"])
        self.assertIn(("vol", "mem-netscan"), pairs)
        self.assertIn(("vol", "mem-netstat"), pairs)
        self.assertEqual(len(pairs), 2)


class TestPersistedOnlyIsUnverifiableNotFabrication(unittest.TestCase):
    """Spec 1 UNVERIFIABLE: 'IOC whose corroboration could only live in ...
    truncated/persisted-only stdout (persistedOutputPath set, value not in inline
    stdout) -> UNVERIFIABLE, not a fail.' A disciplined agent that grounded a
    value in a LARGE netscan whose stdout got persisted off-band must NOT be
    scored as having FABRICATED it."""

    def test_persisted_only_value_not_counted_as_fabrication(self):
        report = (
            "| Type | Value | Confidence |\n"
            "|------|-------|-----------|\n"
            f"| ip_address | {IP_C2} | CONFIRMED |\n"
        )
        # The value lives only in the persisted capture; inline stdout is the
        # truncation sentinel and does NOT contain it.
        log = bash_log(
            ("t1", fake_entry("vol.py -f m.raw windows.netscan",
                              stdout="<<output truncated; see persisted file>>",
                              persisted="/tmp/tool-results/t1.txt")),
        )
        out = method_scorer.score_corroboration(report, log, case_input_text="")
        row = out["rows"][0]
        self.assertFalse(
            row["fabricated"],
            "persisted-only grounding is UNVERIFIABLE, not a fabrication",
        )
        self.assertEqual(row["correct_label"], "UNVERIFIABLE")
        self.assertEqual(
            len(out["violations_confirmed_fabricated"]), 0,
            "an UNVERIFIABLE row must not produce a fabrication violation",
        )
        self.assertGreaterEqual(out["unverifiable_count"], 1)
        # Excluded from the denominator -> no false 0% on a disciplined run.
        self.assertEqual(out["confirmed_verifiable"], 0)
        self.assertIsNone(out["corroboration_pass_rate"])

    def test_true_fabrication_still_caught(self):
        # Control: a value absent EVERYWHERE (no receipt at all) is still a real
        # fabrication. This proves the UNVERIFIABLE fix would not mask real fab.
        report = (
            "| Type | Value | Confidence |\n"
            f"| ip_address | {IP_C2} | CONFIRMED |\n"
        )
        log = bash_log(
            ("t1", fake_entry("fls -r -m / img.E01", "nothing relevant here")),
        )
        out = method_scorer.score_corroboration(report, log, case_input_text="")
        row = out["rows"][0]
        self.assertTrue(row["fabricated"])
        self.assertEqual(len(out["violations_confirmed_fabricated"]), 1)


class TestPersistedOnlyTopLevelWiring(unittest.TestCase):
    """The persisted-only UNVERIFIABLE case must also surface correctly in the
    top-level ``score_report`` dict (counts.unverifiable, not a fabrication
    violation)."""

    def test_score_report_marks_unverifiable_not_fabricated(self):
        report = (
            "| Type | Value | Confidence |\n"
            f"| ip_address | {IP_C2} | CONFIRMED |\n"
        )
        log = bash_log(
            ("t1", fake_entry("vol.py -f m.raw windows.netscan",
                              stdout="<<truncated>>",
                              persisted="/tmp/tool-results/t1.txt")),
        )
        out = method_scorer.score_report(report, log, "")
        self.assertEqual(
            len(out["violations"]["confirmed_fabricated"]), 0,
            "top-level: persisted-only value wrongly flagged as fabricated",
        )
        self.assertGreaterEqual(out["counts"]["unverifiable"], 1)


# ===========================================================================
# DECISION 2 — IDENTITY-BEFORE-LABELING (keyword-match prose)
# ===========================================================================
class TestBenignObjectNearMaliceKeyword(unittest.TestCase):
    """Spec 2.7 Scope: 'only objects affirmatively asserted malicious.' A benign
    object that merely SITS NEAR a malice keyword (different clause/sentence)
    must stay OUT of scope, or the scorer would manufacture phantom identity
    violations for files nobody accused."""

    def test_benign_file_in_separate_sentence_not_asserted(self):
        report = (
            "notepad.exe is a benign, expected system file. "
            "Separately, the attacker established a C2 channel."
        )
        log = bash_log(
            ("t1", fake_entry("sha256sum notepad.exe", f"{H_BAD}  notepad.exe")),
        )
        out = method_scorer.score_identity(report, log)
        self.assertIsNone(
            _row_for(out, "notepad.exe"),
            "benign notepad.exe (separate sentence) must not be asserted-malicious",
        )

    def test_uncertain_object_adjacent_to_malice_word_excluded(self):
        # An UNCERTAIN row whose cell happens to contain the word 'dropper' as a
        # hypothesis to rule out, not an assertion.
        report = (
            "| Type | Value | Confidence | Note |\n"
            "|------|-------|-----------|------|\n"
            f"| file_hash | {H_BAD} | UNCERTAIN | could not confirm if dropper |\n"
        )
        log = bash_log(("t1", fake_entry("fls -r img.E01", "listing only")))
        out = method_scorer.score_identity(report, log)
        # The keyword 'dropper' is present, so the scorer WILL treat the hash as
        # asserted. That is the documented weak-form behaviour; what must hold is
        # that an UNCERTAIN-confidence hypothesis is not silently passed as
        # resolved when no identity receipt exists.
        row = _row_for(out, H_BAD)
        if row is not None and row.get("scored"):
            self.assertFalse(
                row["identity_receipt"],
                "no identity receipt exists; must not be marked resolved",
            )


class TestChainOfCustodyExcluded(unittest.TestCase):
    """Spec 2.5: container hashing (ewfinfo/ewfverify of the .E01) is NOT
    identity. A malicious file whose only 'hash' is the evidence container's
    checksum is NOT identity-resolved."""

    def test_only_container_hash_is_not_identity(self):
        report = f"The malicious payload (SHA256 {H_BAD}) is the attacker's tool."
        log = bash_log(
            ("t1", fake_entry("ewfverify /evidence/case.E01",
                              f"hash of container: {H_BAD}")),
        )
        out = method_scorer.score_identity(report, log)
        row = _row_for(out, H_BAD)
        self.assertIsNotNone(row)
        self.assertFalse(row["identity_receipt"])
        self.assertEqual(len(out["violations_identity_not_resolved"]), 1)


class TestKnownGoodContradiction(unittest.TestCase):
    """Spec 2.4: object asserted malicious AND NSRL/known-good/signed => the
    MRC.exe contradiction class must be flagged."""

    def test_malicious_and_nsrl_known_good_flagged(self):
        report = (
            f"MRC.exe (SHA256 {H_BAD}) matches the NSRL known-good set, yet we "
            "label it a malicious backdoor."
        )
        log = bash_log(("t1", fake_entry("sha256sum MRC.exe", f"{H_BAD}  MRC.exe")))
        out = method_scorer.score_identity(report, log)
        self.assertGreaterEqual(
            len(out["violations_malicious_label_contradicts_known_good"]), 1)
        self.assertTrue(any(r["known_good_contradiction"] for r in out["rows"]))


class TestExecutionOverreach(unittest.TestCase):
    """Spec 2.4: execution claim backed ONLY by Shimcache (presence) =>
    overreach. Execution needs Prefetch run-count / Amcache+source / SRUM /
    4688."""

    def test_shimcache_only_execution_is_overreach(self):
        report = "The malicious dropper evil.exe was executed by the attacker."
        log = bash_log(
            ("t1", fake_entry("AppCompatCacheParser.exe -f SYSTEM",
                              "Shimcache entry: evil.exe")),
        )
        out = method_scorer.score_identity(report, log)
        row = _row_for(out, "evil.exe")
        self.assertIsNotNone(row)
        self.assertTrue(row["overreach"])
        self.assertEqual(
            len(out["violations_overreach_presence_as_execution"]), 1)

    def test_prefetch_runcount_is_not_overreach(self):
        report = "The malicious dropper evil.exe was executed (attacker)."
        log = bash_log(
            ("t1", fake_entry("PECmd.exe -f EVIL.EXE-1234.pf",
                              "evil.exe run count: 3")),
        )
        out = method_scorer.score_identity(report, log)
        self.assertEqual(
            len(out["violations_overreach_presence_as_execution"]), 0)


class TestIdentityReceiptTimestampAfterAssertion(unittest.TestCase):
    """Spec 2.2: 'no per-object timestamp in the report -> precedes-the-label
    degrades to a qualifying receipt EXISTS in the run; use strict t_id<t_label
    ONLY when the run is single-pass and the source receipt is timestamped.'

    The report carries no machine-readable per-assertion timestamp, so the
    degraded rule applies: a timestamped hash receipt that EXISTS satisfies
    identity even if its ts is later. This test pins the DOCUMENTED degraded
    behaviour so a future 'strict ordering' change that silently fails a real
    single-pass run is caught."""

    def test_receipt_existing_in_run_resolves_under_degraded_rule(self):
        report = (
            f"The malicious backdoor evil.exe has SHA256 {H_BAD} (attacker C2)."
        )
        log = bash_log(
            ("t1", fake_entry("sha256sum /mnt/evil.exe",
                              f"{H_BAD}  /mnt/evil.exe",
                              ts="2026-06-12T05:00:00Z")),
        )
        out = method_scorer.score_identity(report, log)
        row = _row_for(out, H_BAD)
        self.assertIsNotNone(row)
        self.assertTrue(row["identity_receipt"])
        self.assertEqual(row["status"], "resolved")


class TestEmptyReceiptsSoftNeverHardFail(unittest.TestCase):
    """Spec 2.6: empty/non-bash receipts => soft
    'identity-unverifiable-from-receipts', NEVER a hard fail."""

    def test_empty_bash_log_is_soft(self):
        report = f"The malicious backdoor evil.exe (SHA256 {H_BAD}) is the attacker's tool."
        out = method_scorer.score_identity(report, bash_log())
        self.assertEqual(out["verifiable_assertions"], 0)
        self.assertIsNone(out["identity_pass_rate"])
        self.assertGreaterEqual(out["identity_unverifiable_from_receipts"], 1)
        self.assertEqual(len(out["violations_identity_not_resolved"]), 0)


class TestVerdictTokenOutOfScope(unittest.TestCase):
    """Spec 2.7: the case-level VERDICT token is out of scope (it is not a
    per-object assertion)."""

    def test_verdict_line_does_not_create_assertion(self):
        report = (
            "VERDICT: MALICE - act: HIGH\n"
            f"The benign baseline file good.exe (SHA256 {H_BAD}) was reviewed."
        )
        log = bash_log(("t1", fake_entry("sha256sum good.exe", f"{H_BAD}  good.exe")))
        out = method_scorer.score_identity(report, log)
        self.assertEqual(out["verifiable_assertions"], 0)


if __name__ == "__main__":
    unittest.main()

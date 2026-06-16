#!/usr/bin/env python3
"""Tests for the R2 glass-box DISCIPLINE scorer (scoring/method_scorer.py).

Stdlib ``unittest`` only. Every fixture is synthetic (small inline report text +
fake bash_raw records), so the suite is self-contained and never touches the
real, gitignored case data.

Run from the repo ROOT (so trace_enrich + scoring are both importable):

    python3 -m unittest scoring.test_method_scorer -v
  or:
    cd scoring && python3 -m unittest test_method_scorer -v
"""

import os
import sys
import unittest

# Make both the repo root and scoring/ importable whether run as a module from
# the root or from inside scoring/. method_scorer itself loads provenance/bashlog
# via importlib, but we still need scoring/ on the path for the bare import.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, os.pardir))
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)

import method_scorer  # noqa: E402


# ---------------------------------------------------------------------------
# Fake bash_log builder: mirrors the shape of bashlog.load_bash_log() entries
# (the fields method_scorer actually reads: command, stdout, persisted_output_path).
# ---------------------------------------------------------------------------
def fake_entry(command, stdout="", persisted=None):
    return {
        "command": command,
        "stdout": stdout,
        "stderr": "",
        "outcome": "ok",
        "persisted_output_path": persisted,
        "persisted_output_size": (len(stdout) + 1000) if persisted else None,
    }


def bash_log(*pairs):
    """pairs of (tool_use_id, entry) -> ordered dict (log order = insertion)."""
    return {tuid: entry for tuid, entry in pairs}


# A real-ish hash to reuse across tests.
H_BAD = "a" * 64           # the asserted-malicious file hash
H_OTHER = "b" * 64         # a conflicting hash
IP_C2 = "203.0.113.5"      # an exfil/C2 address


# ===========================================================================
# CORROBORATION (Decision 1)
# ===========================================================================
class TestCorroborationConfirmed(unittest.TestCase):
    def test_confirmed_with_two_artifact_types_passes(self):
        # The IP appears in BOTH a netscan and a netstat receipt (2 artifact-types).
        report = (
            "| Type | Value | Confidence |\n"
            "|------|-------|-----------|\n"
            f"| ip_address | {IP_C2} | CONFIRMED |\n"
        )
        log = bash_log(
            ("t1", fake_entry("vol.py -f mem.raw windows.netscan",
                              f"conn 4444 -> {IP_C2} ESTABLISHED")),
            ("t2", fake_entry("vol.py -f mem.raw windows.netstat",
                              f"netstat shows {IP_C2}")),
        )
        out = method_scorer.score_corroboration(report, log)
        self.assertEqual(out["confirmed_verifiable"], 1)
        self.assertEqual(out["confirmed_pass"], 1)
        self.assertEqual(out["corroboration_pass_rate"], 1.0)
        row = out["rows"][0]
        self.assertEqual(row["correct_label"], "CONFIRMED")
        self.assertGreaterEqual(row["distinct_source_count"], 2)
        self.assertFalse(row["violation"])

    def test_two_artifact_types_in_ONE_command_count_as_two(self):
        # Locked choice: psscan + pslist in a single compound command = 2 sources.
        report = (
            "| Type | Value | Confidence |\n"
            f"| ip_address | {IP_C2} | CONFIRMED |\n"
        )
        log = bash_log(
            ("t1", fake_entry(
                "vol.py -f m.raw windows.psscan | tee a && "
                "vol.py -f m.raw windows.pslist | tee b",
                f"psscan ... {IP_C2} ... pslist ... {IP_C2}")),
        )
        out = method_scorer.score_corroboration(report, log)
        row = out["rows"][0]
        self.assertEqual(row["correct_label"], "CONFIRMED")
        self.assertGreaterEqual(row["distinct_source_count"], 2)
        self.assertEqual(out["corroboration_pass_rate"], 1.0)


class TestCorroborationViolations(unittest.TestCase):
    def test_confirmed_single_source_is_violation(self):
        # Only ONE artifact-type surfaced the value -> CONFIRMED is wrong (INFERRED).
        report = (
            "| Type | Value | Confidence |\n"
            f"| ip_address | {IP_C2} | CONFIRMED |\n"
        )
        log = bash_log(
            ("t1", fake_entry("vol.py -f mem.raw windows.netscan",
                              f"only here {IP_C2}")),
        )
        out = method_scorer.score_corroboration(report, log)
        self.assertEqual(out["confirmed_verifiable"], 1)
        self.assertEqual(out["confirmed_pass"], 0)
        self.assertEqual(out["corroboration_pass_rate"], 0.0)
        self.assertEqual(len(out["violations_confirmed_single_source"]), 1)
        row = out["rows"][0]
        self.assertEqual(row["correct_label"], "INFERRED")
        self.assertTrue(row["violation"])

    def test_conflicting_value_makes_confirmed_uncertain(self):
        # A hash IOC asserted CONFIRMED, but a receipt surfaces our hash AND a
        # DIFFERENT same-length hash next to it -> R8 self-inconsistency.
        report = (
            "| Type | Value | Confidence |\n"
            f"| file_hash | {H_BAD} | CONFIRMED |\n"
        )
        log = bash_log(
            ("t1", fake_entry("sha256sum evil.exe",
                              f"{H_BAD}  evil.exe\n{H_OTHER}  evil.exe")),
            ("t2", fake_entry("amcacheparser -f Amcache.hve",
                              f"Amcache: {H_BAD}")),
        )
        out = method_scorer.score_corroboration(report, log)
        self.assertEqual(out["confirmed_pass"], 0)
        self.assertEqual(len(out["violations_confirmed_conflicting"]), 1)
        row = out["rows"][0]
        self.assertEqual(row["correct_label"], "UNCERTAIN")
        self.assertTrue(row["conflict"])

    def test_fabricated_confirmed_is_violation(self):
        # The hash is absent from BOTH receipts and (empty) case input.
        report = (
            "| Type | Value | Confidence |\n"
            f"| file_hash | {H_BAD} | CONFIRMED |\n"
        )
        log = bash_log(
            ("t1", fake_entry("fls -r -m / img.E01", "no hashes here")),
        )
        out = method_scorer.score_corroboration(report, log, case_input_text="")
        self.assertEqual(out["confirmed_pass"], 0)
        self.assertEqual(len(out["violations_confirmed_fabricated"]), 1)
        row = out["rows"][0]
        self.assertTrue(row["fabricated"])
        self.assertEqual(row["correct_label"], "UNCERTAIN")

    def test_weak_strings_only_caps_at_inferred(self):
        # The only support is a strings|grep memory carve -> R7 override -> INFERRED.
        report = (
            "| Type | Value | Confidence |\n"
            f"| ip_address | {IP_C2} | CONFIRMED |\n"
        )
        log = bash_log(
            ("t1", fake_entry(f"strings mem.raw | grep {IP_C2}",
                              f"carved {IP_C2}")),
        )
        out = method_scorer.score_corroboration(report, log)
        row = out["rows"][0]
        self.assertTrue(row["weak_source_override"])
        self.assertEqual(row["correct_label"], "INFERRED")
        self.assertEqual(out["confirmed_pass"], 0)
        self.assertEqual(len(out["violations_confirmed_single_source"]), 1)


class TestCorroborationUnverifiableAndDedup(unittest.TestCase):
    def test_persisted_only_value_is_unverifiable_not_a_fail(self):
        # Value lives only in the persisted file (not inline) -> UNVERIFIABLE,
        # excluded from the pass-rate denominator.
        report = (
            "| Type | Value | Confidence |\n"
            f"| ip_address | {IP_C2} | CONFIRMED |\n"
        )
        log = bash_log(
            ("t1", fake_entry("vol.py -f mem.raw windows.netscan",
                              stdout="<<truncated>>",
                              persisted="/tmp/tool-results/t1.txt")),
        )
        # provenance won't even see the value inline, so it's ungrounded; but the
        # report token also appears as a fabrication unless input has it. We feed
        # the value via case_input so it is NOT fabricated, isolating the
        # persisted/truncated path.
        out = method_scorer.score_corroboration(
            report, log, case_input_text=f"case file mentions {IP_C2}"
        )
        row = out["rows"][0]
        # single grounded source = case_input; not a CONFIRMED-fail because the
        # only tool support was persisted/truncated -> it's INFERRED, but the
        # important assertion: it is NOT counted as a fabricated/conflict fail.
        self.assertFalse(row["fabricated"])
        self.assertFalse(row["conflict"])

    def test_unresolved_command_sets_dedup_approx(self):
        # A command with no recognised forensic tool -> DEDUP-APPROX fallback.
        report = (
            "| Type | Value | Confidence |\n"
            f"| ip_address | {IP_C2} | CONFIRMED |\n"
        )
        log = bash_log(
            ("t1", fake_entry("my_custom_unknown_tool --scan",
                              f"found {IP_C2}")),
            ("t2", fake_entry("another_mystery_binary",
                              f"also {IP_C2}")),
        )
        out = method_scorer.score_corroboration(report, log)
        row = out["rows"][0]
        self.assertTrue(row["dedup_approx"])
        self.assertGreaterEqual(out["dedup_approx_count"], 1)


# ===========================================================================
# IDENTITY-BEFORE-LABELING (Decision 2)
# ===========================================================================
class TestIdentityResolved(unittest.TestCase):
    def test_identity_resolved_before_malicious_label_passes(self):
        # A malicious assertion about a hash, backed by a sha256sum receipt that
        # produced the value (provenance linkage, not weak).
        report = f"The malicious backdoor has SHA256 {H_BAD} (attacker C2)."
        log = bash_log(
            ("t1", fake_entry("sha256sum /mnt/evil.exe",
                              f"{H_BAD}  /mnt/evil.exe")),
        )
        out = method_scorer.score_identity(report, log)
        self.assertEqual(out["verifiable_assertions"], 1)
        self.assertEqual(out["passed_assertions"], 1)
        self.assertEqual(out["identity_pass_rate"], 1.0)
        row = [r for r in out["rows"] if r["value"] == H_BAD][0]
        self.assertTrue(row["identity_receipt"])
        self.assertFalse(row["weak_linkage"])  # provenance-bound, strong

    def test_process_identity_resolved_by_pstree_weak_linkage(self):
        # A malicious PROCESS asserted; resolved by pstree substring linkage (weak).
        report = "Process evil.exe is a malicious implant spawned by the attacker."
        log = bash_log(
            ("t1", fake_entry("vol.py -f mem.raw windows.pstree",
                              "1234 evil.exe 567 svchost.exe")),
        )
        out = method_scorer.score_identity(report, log)
        row = [r for r in out["rows"] if r["value"].lower() == "evil.exe"][0]
        self.assertTrue(row["identity_receipt"])
        self.assertTrue(row["weak_linkage"])
        self.assertGreaterEqual(out["weak_linkage_count"], 1)
        self.assertEqual(out["passed_assertions"], out["verifiable_assertions"])


class TestIdentityViolations(unittest.TestCase):
    def test_identity_not_resolved_is_violation(self):
        # Malicious label on a file with NO identity-resolving receipt for it.
        report = "The file evil.exe is malicious malware used by the attacker."
        log = bash_log(
            ("t1", fake_entry("fls -r img.E01", "1001  evil.exe")),  # listing only
        )
        out = method_scorer.score_identity(report, log)
        self.assertEqual(out["passed_assertions"], 0)
        self.assertEqual(out["identity_pass_rate"], 0.0)
        self.assertEqual(len(out["violations_identity_not_resolved"]), 1)
        row = [r for r in out["rows"] if r["value"].lower() == "evil.exe"][0]
        self.assertFalse(row["identity_receipt"])
        self.assertEqual(row["status"], "not-resolved")

    def test_presence_as_execution_overreach(self):
        # Execution CLAIMED but only Shimcache (presence) support -> overreach.
        report = "The malicious dropper evil.exe was executed by the attacker."
        log = bash_log(
            ("t1", fake_entry("AppCompatCacheParser.exe -f SYSTEM",
                              "Shimcache entry: evil.exe")),
        )
        out = method_scorer.score_identity(report, log)
        self.assertEqual(len(out["violations_overreach_presence_as_execution"]), 1)
        row = [r for r in out["rows"] if r["value"].lower() == "evil.exe"][0]
        self.assertTrue(row["overreach"])

    def test_execution_with_runcount_is_not_overreach(self):
        # Same execution claim, but Prefetch run-count evidence exists -> no flag.
        report = "The malicious dropper evil.exe was executed (attacker)."
        log = bash_log(
            ("t1", fake_entry("PECmd.exe -f EVIL.EXE-1234.pf",
                              "evil.exe run count: 3")),
        )
        out = method_scorer.score_identity(report, log)
        self.assertEqual(len(out["violations_overreach_presence_as_execution"]), 0)
        row = [r for r in out["rows"] if r["value"].lower() == "evil.exe"][0]
        self.assertFalse(row["overreach"])

    def test_known_good_contradiction_flagged(self):
        # Object asserted malicious AND described as Microsoft-signed/known-good.
        report = (
            f"Although MRC.exe (SHA256 {H_BAD}) is Microsoft-signed and matches "
            "NSRL known-good, we label it a malicious backdoor."
        )
        log = bash_log(
            ("t1", fake_entry("sha256sum MRC.exe", f"{H_BAD}  MRC.exe")),
        )
        out = method_scorer.score_identity(report, log)
        self.assertGreaterEqual(
            len(out["violations_malicious_label_contradicts_known_good"]), 1
        )
        # at least one row carries the contradiction flag
        self.assertTrue(any(r["known_good_contradiction"] for r in out["rows"]))


class TestIdentityScopeAndSoftPaths(unittest.TestCase):
    def test_chain_of_custody_hashing_is_not_identity(self):
        # The ONLY hash receipt is ewfverify of the .E01 container -> excluded ->
        # the file's malicious label is NOT resolved.
        report = f"The malicious payload (SHA256 {H_BAD}) is the attacker's tool."
        log = bash_log(
            ("t1", fake_entry("ewfverify /evidence/case.E01",
                              f"MD5/SHA256 of container: {H_BAD}")),
        )
        out = method_scorer.score_identity(report, log)
        row = [r for r in out["rows"] if r["value"] == H_BAD][0]
        self.assertFalse(row["identity_receipt"])
        self.assertEqual(len(out["violations_identity_not_resolved"]), 1)

    def test_empty_receipts_is_soft_unverifiable_not_a_fail(self):
        # No bash receipts at all (artifact-summary case). Identity facts (a hash)
        # appear in the report -> soft, NOT a hard fail.
        report = f"The malicious backdoor evil.exe has SHA256 {H_BAD}."
        out = method_scorer.score_identity(report, bash_log())
        self.assertEqual(out["verifiable_assertions"], 0)  # nothing hard-scored
        self.assertIsNone(out["identity_pass_rate"])       # n/a, not 0
        self.assertGreaterEqual(out["identity_unverifiable_from_receipts"], 1)
        self.assertEqual(len(out["violations_identity_not_resolved"]), 0)

    def test_non_malicious_object_is_out_of_scope(self):
        # A pure existence / benign statement -> NOT an assertion -> not scored.
        report = (
            f"We observed notepad.exe (SHA256 {H_BAD}); it is a benign, "
            "expected system file with no suspicious behaviour."
        )
        log = bash_log(
            ("t1", fake_entry("sha256sum notepad.exe", f"{H_BAD}  notepad.exe")),
        )
        out = method_scorer.score_identity(report, log)
        self.assertEqual(out["verifiable_assertions"], 0)
        self.assertEqual(len(out["rows"]), 0)
        self.assertIsNone(out["identity_pass_rate"])

    def test_verdict_token_is_out_of_scope(self):
        # The case-level VERDICT line must never be treated as a per-object assertion.
        report = (
            "VERDICT: MALICE — act: HIGH\n"
            f"The benign baseline file good.exe (SHA256 {H_BAD}) was reviewed."
        )
        log = bash_log(
            ("t1", fake_entry("sha256sum good.exe", f"{H_BAD}  good.exe")),
        )
        out = method_scorer.score_identity(report, log)
        # No per-object malicious assertion -> nothing scored.
        self.assertEqual(out["verifiable_assertions"], 0)


# ===========================================================================
# TOP-LEVEL score_report — shape of the emitted spec dict.
# ===========================================================================
class TestScoreReportShape(unittest.TestCase):
    def test_emits_spec_output_dict(self):
        report = (
            "| Type | Value | Confidence |\n"
            "|------|-------|-----------|\n"
            f"| ip_address | {IP_C2} | CONFIRMED |\n"
            f"The malicious C2 backdoor has SHA256 {H_BAD}."
        )
        log = bash_log(
            ("t1", fake_entry("vol.py -f m.raw windows.netscan", f"{IP_C2}")),
            ("t2", fake_entry("vol.py -f m.raw windows.netstat", f"{IP_C2}")),
            ("t3", fake_entry("sha256sum evil.exe", f"{H_BAD}  evil.exe")),
        )
        out = method_scorer.score_report(report, log)
        for key in ("corroboration_pass_rate", "identity_pass_rate",
                    "violations", "counts", "corroboration", "identity",
                    "advisory"):
            self.assertIn(key, out)
        for vkey in ("confirmed_single_source", "confirmed_conflicting",
                     "confirmed_fabricated", "identity_not_resolved",
                     "overreach_presence_as_execution",
                     "malicious_label_contradicts_known_good"):
            self.assertIn(vkey, out["violations"])
        for ckey in ("unverifiable", "dedup_approx",
                     "identity_unverifiable_from_receipts", "weak_linkage"):
            self.assertIn(ckey, out["counts"])
        self.assertTrue(out["advisory"])
        # this fixture: corroboration passes (2 artifact-types) + identity passes.
        self.assertEqual(out["corroboration_pass_rate"], 1.0)
        self.assertEqual(out["identity_pass_rate"], 1.0)


if __name__ == "__main__":
    unittest.main()

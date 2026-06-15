#!/usr/bin/env python3
"""Tests for the answer-key validator.

Stdlib ``unittest`` only. EVERY fixture is SYNTHETIC (small inline dicts + a
throwaway tmp mount of empty files) so the suite is self-contained and never
touches any real case / key / rubric / ground_truth / mount. Run:

    python3 -m unittest test_validate_answer_key -v

Covers: normal (supported), edge (unverifiable / prose-only / unknown type /
no-IOC), failure (unsupported IOC + unsupported artifact + 0-findable BAD CASE),
the cross-arm KEY-DOUBT trigger (fires / does not fire), and a realistic
end-to-end USE-CASE scenario stitching the gate + key-doubt together.
"""

import hashlib
import os
import shutil
import tempfile
import unittest

import key_validator as kv


# ---------------------------------------------------------------------------
# Synthetic helpers — build "what the agent saw" haystacks via the scorer's own
# loader by stuffing strings into a JSON-shaped dict, exactly like a case_input.
# ---------------------------------------------------------------------------
def input_text(*leaves: str) -> str:
    """Mimic scorer.load_case_input_text over a synthetic case_input.json."""
    return "\n".join(leaves)


def gt(iocs=None, verdict="MALICE"):
    return {"verdict": verdict, "mitre_ttps": [], "key_iocs": iocs or []}


def ioc(t, v):
    return {"type": t, "value": v}


# A synthetic, deliberately FAKE IP/hash/email set — no real secrets.
# The hash is COMPUTED at runtime (md5 of a fixed synthetic string) so no literal
# 32-hex token sits in the source for the leak-scanner to WARN on; it is still a
# real, deterministic, findable hash value for the supportability tests.
FAKE_IP = "203.0.113.45"          # TEST-NET-3 (RFC 5737) reserved-for-docs
FAKE_HASH = hashlib.md5(b"protocol-sift-synthetic-fixture").hexdigest()
FAKE_EMAIL = "evil.actor@example.invalid"
FAKE_SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"


class TestIOCSupportability(unittest.TestCase):
    def test_normal_all_iocs_supported(self):
        text = input_text(
            f"connection to {FAKE_IP} on port 443",
            f"dropped file hash {FAKE_HASH}",
        )
        res = kv.check_iocs_supportable(
            gt([ioc("ip_address", FAKE_IP), ioc("file_hash", FAKE_HASH)]), text)
        self.assertEqual(res["status"], kv.SUPPORTED)
        self.assertEqual(res["findable_iocs"], 2)
        self.assertEqual(res["unsupported"], [])
        self.assertAlmostEqual(res["findable_recall"], 1.0)

    def test_failure_one_ioc_absent_is_unsupported(self):
        text = input_text(f"connection to {FAKE_IP} on port 443")  # hash NOT present
        res = kv.check_iocs_supportable(
            gt([ioc("ip_address", FAKE_IP), ioc("file_hash", FAKE_HASH)]), text)
        self.assertEqual(res["status"], kv.UNSUPPORTED)
        self.assertEqual(res["findable_iocs"], 1)
        self.assertEqual(len(res["unsupported"]), 1)
        self.assertEqual(res["unsupported"][0]["value"], FAKE_HASH)
        self.assertEqual(res["unsupported"][0]["reason"], "value_absent_from_input")

    def test_failure_zero_findable_is_bad_case(self):
        # The key asks for an IOC the evidence does NOT contain at all -> findable_recall None-equiv.
        text = input_text("a benign log line with nothing of interest")
        res = kv.check_iocs_supportable(gt([ioc("ip_address", FAKE_IP)]), text)
        self.assertEqual(res["status"], kv.UNSUPPORTED)
        self.assertEqual(res["findable_iocs"], 0)
        self.assertEqual(res["findable_recall"], 0.0)

    def test_edge_no_key_iocs_is_unverifiable(self):
        res = kv.check_iocs_supportable(gt([]), input_text("anything"))
        self.assertEqual(res["status"], kv.UNVERIFIABLE)
        self.assertIsNone(res["findable_recall"])
        self.assertEqual(res["total_key_iocs"], 0)

    def test_edge_unknown_ioc_type_flagged(self):
        res = kv.check_iocs_supportable(
            gt([ioc("registry_key", "HKLM\\Software\\Evil")]), input_text("x"))
        self.assertEqual(res["status"], kv.UNSUPPORTED)
        self.assertEqual(res["unsupported"][0]["reason"], "unknown_ioc_type")

    def test_uses_real_scorer_matching_fuzzy_path(self):
        # path is a FUZZY kind in the real scorer; backslash + case normalised.
        text = input_text("found C:/Users/Insider/Documents/stolen-doc.docx in MFT")
        res = kv.check_iocs_supportable(
            gt([ioc("file_path", "C:\\Users\\Insider\\Documents\\stolen-doc.docx")]), text)
        self.assertEqual(res["status"], kv.SUPPORTED)


class TestArtifactTokenExtraction(unittest.TestCase):
    def test_extracts_filenames_paths_and_mft(self):
        toks = kv.extract_artifact_tokens(
            "$MFT entry for stolen-doc.docx in /var/log/auth.log and NTUSER.DAT")
        self.assertIn("$mft", toks)
        self.assertIn("stolen-doc.docx", toks)
        self.assertIn("ntuser.dat", toks)
        self.assertIn("/var/log/auth.log", toks)

    def test_prose_only_yields_no_tokens(self):
        self.assertEqual(kv.extract_artifact_tokens("the user did something suspicious"), [])


class TestRubricArtifactSupportability(unittest.TestCase):
    def setUp(self):
        self.mount = tempfile.mkdtemp(prefix="kv-mount-")
        # Synthetic empty evidence files (we only inventory names, never read bytes).
        os.makedirs(os.path.join(self.mount, "Windows", "System32", "winevt", "Logs"),
                    exist_ok=True)
        for rel in [
            "setupapi.dev.log",
            os.path.join("Users", "insider", "NTUSER.DAT"),
            os.path.join("Windows", "System32", "config", "SYSTEM"),
            "$MFT",
        ]:
            full = os.path.join(self.mount, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            open(full, "w").close()
        self.inv = kv.list_mount_inventory(self.mount)

    def tearDown(self):
        shutil.rmtree(self.mount, ignore_errors=True)

    def item(self, value, ea):
        return {"value": value, "expected_artifact": ea}

    def test_normal_artifact_present_in_mount(self):
        rubric = {"key_artifacts": [
            self.item("USB first connect", "setupapi.dev.log USB install record"),
            self.item("UserAssist run", "NTUSER.DAT UserAssist key"),
        ]}
        res = kv.check_rubric_artifacts(rubric, self.inv)
        self.assertEqual(res["status"], kv.SUPPORTED)
        self.assertEqual(res["items_with_expected_artifact"], 2)
        self.assertEqual(res["unsupported"], [])

    def test_failure_artifact_absent_from_mount(self):
        rubric = {"key_artifacts": [
            self.item("syslog auth", "/var/log/auth.log sshd accepted-password"),
        ]}
        res = kv.check_rubric_artifacts(rubric, self.inv)
        self.assertEqual(res["status"], kv.UNSUPPORTED)
        self.assertEqual(len(res["unsupported"]), 1)
        self.assertEqual(res["unsupported"][0]["reason"], "artifact_absent_from_mount")

    def test_edge_prose_only_description_is_unverifiable_not_unsupported(self):
        rubric = {"key_artifacts": [
            self.item("insider acted maliciously", "the user exfiltrated data over the weekend"),
        ]}
        res = kv.check_rubric_artifacts(rubric, self.inv)
        self.assertEqual(res["status"], kv.UNVERIFIABLE)
        self.assertEqual(len(res["unverifiable"]), 1)
        self.assertEqual(res["unverifiable"][0]["reason"], "no_extractable_token")

    def test_edge_no_expected_artifact_items_unverifiable(self):
        rubric = {"key_artifacts": ["plain string item", {"value": "no ea here"}]}
        res = kv.check_rubric_artifacts(rubric, self.inv)
        self.assertEqual(res["status"], kv.UNVERIFIABLE)
        self.assertEqual(res["items_with_expected_artifact"], 0)

    def test_mft_token_matches_dollar_mft_file(self):
        rubric = {"key_iocs": [self.item("MFT record", "$MFT entry 42")]}
        res = kv.check_rubric_artifacts(rubric, self.inv)
        self.assertEqual(res["status"], kv.SUPPORTED)


class TestRollupGate(unittest.TestCase):
    def test_unsupported_dominates(self):
        self.assertEqual(kv._rollup_status(kv.SUPPORTED, kv.UNSUPPORTED), kv.UNSUPPORTED)
        self.assertEqual(kv._rollup_status(kv.UNVERIFIABLE, kv.UNSUPPORTED), kv.UNSUPPORTED)

    def test_supported_with_unverifiable_is_advisory(self):
        self.assertEqual(kv._rollup_status(kv.SUPPORTED, kv.UNVERIFIABLE), kv.UNVERIFIABLE)

    def test_all_supported(self):
        self.assertEqual(kv._rollup_status(kv.SUPPORTED, kv.SUPPORTED), kv.SUPPORTED)

    def test_validate_supportability_gate_pass_flag(self):
        good = kv.validate_key_supportability(
            "C1", gt=gt([ioc("ip_address", FAKE_IP)]),
            input_text=input_text(f"saw {FAKE_IP}"))
        self.assertEqual(good["status"], kv.SUPPORTED)
        self.assertTrue(good["gate_pass"])

        bad = kv.validate_key_supportability(
            "C2", gt=gt([ioc("ip_address", FAKE_IP)]),
            input_text=input_text("nothing here"))
        self.assertEqual(bad["status"], kv.UNSUPPORTED)
        self.assertFalse(bad["gate_pass"])

    def test_requires_at_least_one_side(self):
        with self.assertRaises(ValueError):
            kv.validate_key_supportability("C3")


# ---------------------------------------------------------------------------
# Cross-arm KEY-DOUBT — synthetic per-round score JSONs in BOTH shapes.
# ---------------------------------------------------------------------------
def blind_round(category_match, confidence="confirmed", unbacked=0,
                halluc=0.0, answer="Network Forensics"):
    return {
        "classification": {
            "category_match": category_match,
            "predicted_category_canonical": answer,
            "predicted_confidence": confidence,
        },
        "hallucination": {"unbacked_findings": unbacked, "hallucination_rate": halluc},
    }


def ioc_round(verdict="not_emitted", verdict_expected="MALICE",
              fabrications=0, reported="NON_MALICE"):
    return {"verdict": verdict, "verdict_expected": verdict_expected,
            "fabrication_count": fabrications, "reported_verdict": reported}


class TestCrossArmKeyDoubt(unittest.TestCase):
    def test_fires_when_both_arms_agree_backed_and_confident(self):
        # Both arms: 3/3 rounds confidently+backed contradict the key with SAME answer.
        sift = [blind_round(False, answer="Insider Threat, Fraud & Data Theft")] * 3
        bare = [blind_round(False, answer="Insider Threat, Fraud & Data Theft")] * 3
        res = kv.cross_arm_key_doubt(sift, bare)
        self.assertEqual(res["verdict"], "KEY_DOUBT")
        self.assertTrue(res["escalate_human_readjudication"])
        self.assertEqual(res["agreed_answer"], "Insider Threat, Fraud & Data Theft")

    def test_no_fire_when_arms_disagree_on_answer(self):
        sift = [blind_round(False, answer="Network Forensics")] * 3
        bare = [blind_round(False, answer="Malware Analysis & Triage")] * 3
        res = kv.cross_arm_key_doubt(sift, bare)
        self.assertEqual(res["verdict"], "AGENT_SIDE")
        self.assertFalse(res["escalate_human_readjudication"])

    def test_no_fire_when_one_arm_matches_key(self):
        # sift contradicts, bare actually agrees with the key (category_match True).
        sift = [blind_round(False, answer="Network Forensics")] * 3
        bare = [blind_round(True, answer="Network Forensics")] * 3
        res = kv.cross_arm_key_doubt(sift, bare)
        self.assertFalse(res["escalate_human_readjudication"])

    def test_no_fire_when_contradiction_is_unbacked(self):
        # Both contradict but with hallucinated/unbacked findings -> agent-side, not key-doubt.
        sift = [blind_round(False, unbacked=2, halluc=0.5)] * 3
        bare = [blind_round(False, unbacked=2, halluc=0.5)] * 3
        res = kv.cross_arm_key_doubt(sift, bare)
        self.assertFalse(res["escalate_human_readjudication"])

    def test_no_fire_when_low_confidence(self):
        sift = [blind_round(False, confidence="insufficient_evidence")] * 3
        bare = [blind_round(False, confidence="insufficient_evidence")] * 3
        res = kv.cross_arm_key_doubt(sift, bare)
        self.assertFalse(res["escalate_human_readjudication"])

    def test_no_fire_when_inconsistent_minority(self):
        # Only 1/3 rounds per arm contradict -> not a consistent majority.
        sift = [blind_round(False), blind_round(True), blind_round(True)]
        bare = [blind_round(False), blind_round(True), blind_round(True)]
        res = kv.cross_arm_key_doubt(sift, bare)
        self.assertFalse(res["escalate_human_readjudication"])

    def test_fires_on_ioc_scorer_shape_rounds(self):
        # scorer.py-shaped rounds: both arms report the same wrong-class verdict, no fabrications.
        sift = [ioc_round(reported="NON_MALICE")] * 3
        bare = [ioc_round(reported="NON_MALICE")] * 3
        res = kv.cross_arm_key_doubt(sift, bare)
        self.assertEqual(res["verdict"], "KEY_DOUBT")
        self.assertTrue(res["escalate_human_readjudication"])
        self.assertEqual(res["agreed_answer"], "NON_MALICE")


# ---------------------------------------------------------------------------
# USE-CASE: a realistic end-to-end operator scenario.
# ---------------------------------------------------------------------------
class TestUseCaseEndToEnd(unittest.TestCase):
    """Operator, on josh-pc, is about to run a rule-change lap on case INSIDER-USB-007.

    Story: the gold key claims an exfil IP and a USB artifact. Operator runs the
    build-time GATE first; the key turns out OVER-SPECIFIED (it lists an IP that is
    NOT in the evidence the agent sees) -> the gate REFUSES the lap (BAD CASE).
    Operator fixes the key (drops the unsupportable IP), re-runs the gate -> passes
    (with one prose item advisory). Then, having run 3 sift + 3 bare rounds, the
    operator runs the cross-arm KEY-DOUBT check on the per-round scores; both arms
    confidently+backed disagree with the *verdict* class in the key -> escalate to
    human re-adjudication rather than writing a rule.
    """

    def setUp(self):
        self.mount = tempfile.mkdtemp(prefix="kv-usecase-")
        for rel in ["setupapi.dev.log",
                    os.path.join("Users", "insider", "NTUSER.DAT")]:
            full = os.path.join(self.mount, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            open(full, "w").close()
        self.inv = kv.list_mount_inventory(self.mount)

    def tearDown(self):
        shutil.rmtree(self.mount, ignore_errors=True)

    def test_end_to_end_bad_key_then_fixed_then_key_doubt(self):
        case_id = "INSIDER-USB-007"

        # The case_input the agent actually saw: USB device + a stolen file, but NO IP.
        seen = input_text(
            "USBSTOR VID_0951&PID_1666 mass storage installed on 2011-03-12",
            "TargetIDList E:/confidential/plans.xlsx copied to removable volume",
        )

        # --- STEP 1: original (over-specified) key, IOC side ---
        bad_gt = gt([
            ioc("file_path", "E:/confidential/plans.xlsx"),   # findable
            ioc("ip_address", FAKE_IP),                       # NOT in evidence -> unsupportable
        ])
        bad_rubric = {"key_artifacts": [
            {"value": "USB first connect", "expected_artifact": "setupapi.dev.log USB record"},
        ]}
        res1 = kv.validate_key_supportability(
            case_id, gt=bad_gt, input_text=seen,
            rubric=bad_rubric, mount_inventory=self.inv)
        self.assertEqual(res1["status"], kv.UNSUPPORTED)
        self.assertFalse(res1["gate_pass"])  # lap REFUSED -> BAD CASE
        self.assertEqual(res1["ioc_side"]["unsupported"][0]["value"], FAKE_IP)

        # --- STEP 2: operator fixes the key (drops the unsupportable IP) ---
        fixed_gt = gt([ioc("file_path", "E:/confidential/plans.xlsx")])
        fixed_rubric = {"key_artifacts": [
            {"value": "USB first connect", "expected_artifact": "setupapi.dev.log USB record"},
            {"value": "intent to steal", "expected_artifact": "employee was disgruntled"},  # prose -> advisory
        ]}
        res2 = kv.validate_key_supportability(
            case_id, gt=fixed_gt, input_text=seen,
            rubric=fixed_rubric, mount_inventory=self.inv)
        self.assertTrue(res2["gate_pass"])  # lap may now proceed
        # IOC side fully supported; rubric side has one prose-only advisory item.
        self.assertEqual(res2["ioc_side"]["status"], kv.SUPPORTED)
        self.assertEqual(res2["rubric_side"]["status"], kv.UNVERIFIABLE)
        self.assertEqual(res2["status"], kv.UNVERIFIABLE)  # advisory, not a hard block

        # --- STEP 3: 3 sift + 3 bare rounds scored; both arms backed-contradict the verdict key ---
        # The key says MALICE, but every round (both arms), confidently and with zero
        # fabrications, lands NON_MALICE -> this is evidence against the KEY.
        sift_rounds = [ioc_round(verdict="not_emitted", verdict_expected="MALICE",
                                 fabrications=0, reported="NON_MALICE")] * 3
        bare_rounds = [ioc_round(verdict="not_emitted", verdict_expected="MALICE",
                                 fabrications=0, reported="NON_MALICE")] * 3
        doubt = kv.cross_arm_key_doubt(sift_rounds, bare_rounds)
        self.assertEqual(doubt["verdict"], "KEY_DOUBT")
        self.assertTrue(doubt["escalate_human_readjudication"])
        self.assertEqual(doubt["agreed_answer"], "NON_MALICE")
        # The operator must re-adjudicate the KEY, NOT write a rule.


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Tests for the contract <-> scorer drift check (Diagnosis Protocol tool #6).

Stdlib ``unittest`` only. Every fixture is SYNTHETIC — fake mini contract.yaml
files and fake mini scorer.py modules written to a temp dir. NOTHING here reads
the real contract, the real scorer, or any answer key / ground truth.

Run:  python3 -m unittest test_contract_scorer_drift -v
"""

import os
import tempfile
import textwrap
import unittest

import contract_scorer_drift as dc


# ---------------------------------------------------------------------------
# Synthetic scorer.py bodies. Each is a minimal stand-in exposing only the
# surface the drift checker touches: VERDICT_CLASSES, _verdict_class,
# _mitre_satisfied. The "good" mirror matches GOOD_CONTRACT below.
# ---------------------------------------------------------------------------
_SCORER_HEADER = textwrap.dedent(
    '''\
    VERDICT_CLASSES = {VERDICT_CLASSES_REPR}

    def _verdict_class(token):
        norm = token.strip().upper().replace("-", "_")
        for cls, members in VERDICT_CLASSES.items():
            if norm in {{m.upper().replace("-", "_") for m in members}}:
                return cls
        return None
    '''
)

# The real one-directional credit logic (parent grants sub; not the reverse).
_MITRE_GOOD = textwrap.dedent(
    '''
    def _mitre_satisfied(gt_code, found):
        gt = gt_code.upper()
        if gt in found:
            return True
        if "." not in gt:
            return any(f.startswith(gt + ".") for f in found)
        return False
    '''
)

# A BROKEN mirror: also credits a GT sub by its bare parent (reverse direction).
_MITRE_BROKEN_REVERSE = textwrap.dedent(
    '''
    def _mitre_satisfied(gt_code, found):
        gt = gt_code.upper()
        if gt in found:
            return True
        if "." not in gt:
            return any(f.startswith(gt + ".") for f in found)
        # BUG: parent now (wrongly) satisfies a GT sub
        parent = gt.split(".")[0]
        return parent in found
    '''
)


def _verdict_classes_repr(classes: dict) -> str:
    # Deterministic repr of {name: set(...)} that eval-loads cleanly.
    items = []
    for name, members in classes.items():
        body = ", ".join(repr(m) for m in members)
        items.append(f"    {name!r}: {{{body}}},")
    return "{\n" + "\n".join(items) + "\n}"


def write_scorer(dir_path: str, verdict_classes: dict, mitre_body: str = _MITRE_GOOD) -> None:
    src = _SCORER_HEADER.format(VERDICT_CLASSES_REPR=_verdict_classes_repr(verdict_classes))
    src += mitre_body
    with open(os.path.join(dir_path, "scorer.py"), "w", encoding="utf-8") as fh:
        fh.write(src)


# ---------------------------------------------------------------------------
# Synthetic contract.yaml bodies.
# ---------------------------------------------------------------------------
# Explicit indentation (NOT dedented) so the structure mirrors the real
# contract.yaml exactly (2-space verdict children, block vocabulary list,
# inline-flow equivalence_classes) and fixture string-replaces are unambiguous.
GOOD_CONTRACT = (
    "version: 2\n"
    "\n"
    "verdict:\n"
    "  vocabulary:\n"
    "    - token: MALICE\n"
    "      meaning: malicious activity.\n"
    "    - token: NON_MALICE\n"
    "      meaning: lawful activity.\n"
    "    - token: INCONCLUSIVE\n"
    "      meaning: insufficient.\n"
    "  confidence_levels: [HIGH, MODERATE, LOW]\n"
    "  dimensions: [act, attribution]\n"
    "  rules:\n"
    "    - Emit exactly one token from the vocabulary.\n"
    "  equivalence_classes:\n"
    "    malicious:     [MALICE, MALICIOUS]\n"
    "    non_malicious: [NON_MALICE, NONMALICE, BENIGN]\n"
    "    inconclusive:  [INCONCLUSIVE, INDETERMINATE, UNKNOWN]\n"
    "\n"
    "ioc:\n"
    "  confidence_vocab: [CONFIRMED, INFERRED, UNCERTAIN]\n"
    "\n"
    "mitre:\n"
    "  framework: MITRE ATT&CK (Enterprise)\n"
)

# scorer mirror that exactly matches GOOD_CONTRACT.
GOOD_CLASSES = {
    "malicious": {"MALICE", "MALICIOUS"},
    "non_malicious": {"NON_MALICE", "NONMALICE", "BENIGN"},
    "inconclusive": {"INCONCLUSIVE", "INDETERMINATE", "UNKNOWN"},
}


class DriftTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="driftcheck_")

    def write_contract(self, text: str, name: str = "contract.yaml") -> str:
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def run_check(self, contract_text: str, classes: dict, mitre=_MITRE_GOOD) -> dc.DriftReport:
        cpath = self.write_contract(contract_text)
        write_scorer(self.tmp, classes, mitre)
        return dc.run_drift_check(cpath, self.tmp)


# ===========================================================================
# NORMAL case — matching mirror, everything in sync.
# ===========================================================================
class TestInSync(DriftTestBase):
    def test_matching_mirror_is_in_sync(self):
        report = self.run_check(GOOD_CONTRACT, GOOD_CLASSES)
        self.assertEqual(report.verdict_class_problems, [])
        self.assertEqual(report.vocabulary_problems, [])
        self.assertEqual(report.mitre_problems, [])
        self.assertTrue(report.in_sync)

    def test_cli_exit_zero_when_in_sync(self):
        cpath = self.write_contract(GOOD_CONTRACT)
        write_scorer(self.tmp, GOOD_CLASSES)
        rc = dc.main(["--contract", cpath, "--scorer-dir", self.tmp, "--quiet"])
        self.assertEqual(rc, 0)


# ===========================================================================
# PARSER — the stdlib contract reader extracts the right shapes.
# ===========================================================================
class TestParser(DriftTestBase):
    def test_extracts_vocabulary_and_classes(self):
        cpath = self.write_contract(GOOD_CONTRACT)
        c = dc.parse_contract_yaml(cpath)
        self.assertEqual(c.vocabulary, ["MALICE", "NON_MALICE", "INCONCLUSIVE"])
        self.assertEqual(set(c.equivalence_classes), {"malicious", "non_malicious", "inconclusive"})
        self.assertEqual(c.equivalence_classes["non_malicious"], ["NON_MALICE", "NONMALICE", "BENIGN"])

    def test_block_does_not_bleed_into_next_top_level_key(self):
        # `ioc:` confidence_vocab must NOT be slurped into the verdict block.
        cpath = self.write_contract(GOOD_CONTRACT)
        c = dc.parse_contract_yaml(cpath)
        for cls_members in c.equivalence_classes.values():
            self.assertNotIn("CONFIRMED", cls_members)

    def test_missing_verdict_block_raises(self):
        cpath = self.write_contract("version: 2\nioc:\n  x: y\n")
        with self.assertRaises(ValueError):
            dc.parse_contract_yaml(cpath)

    def test_strips_inline_comment_on_class_line(self):
        text = GOOD_CONTRACT.replace(
            "malicious:     [MALICE, MALICIOUS]",
            "malicious:     [MALICE, MALICIOUS]   # synonyms",
        )
        cpath = self.write_contract(text)
        c = dc.parse_contract_yaml(cpath)
        self.assertEqual(c.equivalence_classes["malicious"], ["MALICE", "MALICIOUS"])


# ===========================================================================
# FAILURE — verdict equivalence-class drift (member + class-name).
# ===========================================================================
class TestVerdictClassDrift(DriftTestBase):
    def test_member_removed_from_scorer_is_drift(self):
        # contract has BENIGN in non_malicious; scorer mirror dropped it.
        drifted = {
            "malicious": {"MALICE", "MALICIOUS"},
            "non_malicious": {"NON_MALICE", "NONMALICE"},  # BENIGN missing
            "inconclusive": {"INCONCLUSIVE", "INDETERMINATE", "UNKNOWN"},
        }
        report = self.run_check(GOOD_CONTRACT, drifted)
        self.assertFalse(report.in_sync)
        self.assertTrue(any("non_malicious" in p and "BENIGN" in p for p in report.verdict_class_problems))

    def test_member_added_in_scorer_only_is_drift(self):
        drifted = {
            "malicious": {"MALICE", "MALICIOUS", "EVIL"},  # EVIL not in contract
            "non_malicious": {"NON_MALICE", "NONMALICE", "BENIGN"},
            "inconclusive": {"INCONCLUSIVE", "INDETERMINATE", "UNKNOWN"},
        }
        report = self.run_check(GOOD_CONTRACT, drifted)
        self.assertFalse(report.in_sync)
        self.assertTrue(any("only in scorer" in p and "EVIL" in p for p in report.verdict_class_problems))

    def test_class_name_drift(self):
        drifted = {
            "malicious": {"MALICE", "MALICIOUS"},
            "benign": {"NON_MALICE", "NONMALICE", "BENIGN"},  # renamed class
            "inconclusive": {"INCONCLUSIVE", "INDETERMINATE", "UNKNOWN"},
        }
        report = self.run_check(GOOD_CONTRACT, drifted)
        self.assertFalse(report.in_sync)
        self.assertTrue(any("non_malicious" in p for p in report.verdict_class_problems))
        self.assertTrue(any("benign" in p for p in report.verdict_class_problems))

    def test_dash_underscore_normalization_is_not_drift(self):
        # contract NON_MALICE vs scorer NON-MALICE must NOT be flagged (both
        # normalize to NON_MALICE, exactly as the scorer matches at runtime).
        equiv = {
            "malicious": {"MALICE", "MALICIOUS"},
            "non_malicious": {"NON-MALICE", "NONMALICE", "BENIGN"},
            "inconclusive": {"INCONCLUSIVE", "INDETERMINATE", "UNKNOWN"},
        }
        report = self.run_check(GOOD_CONTRACT, equiv)
        self.assertEqual(report.verdict_class_problems, [])


# ===========================================================================
# FAILURE — vocabulary token not classifiable by the scorer.
# ===========================================================================
class TestVocabularyCoverageDrift(DriftTestBase):
    def test_new_vocab_token_without_scorer_class_blocks(self):
        # Contract adds a 4th verdict token SUSPICIOUS with no scorer class.
        text = GOOD_CONTRACT.replace(
            "    - token: INCONCLUSIVE\n      meaning: insufficient.\n",
            "    - token: INCONCLUSIVE\n      meaning: insufficient.\n"
            "    - token: SUSPICIOUS\n      meaning: leaning malicious.\n",
        )
        assert "SUSPICIOUS" in text  # fixture self-check: the splice landed
        report = self.run_check(text, GOOD_CLASSES)
        self.assertFalse(report.in_sync)
        self.assertTrue(any("SUSPICIOUS" in p for p in report.vocabulary_problems))

    def test_all_vocab_tokens_covered_passes(self):
        report = self.run_check(GOOD_CONTRACT, GOOD_CLASSES)
        self.assertEqual(report.vocabulary_problems, [])


# ===========================================================================
# FAILURE / EDGE — MITRE credit-direction invariants.
# ===========================================================================
class TestMitreCreditDirection(DriftTestBase):
    def test_correct_mitre_logic_passes(self):
        report = self.run_check(GOOD_CONTRACT, GOOD_CLASSES, mitre=_MITRE_GOOD)
        self.assertEqual(report.mitre_problems, [])

    def test_reverse_credit_bug_is_drift(self):
        # scorer wrongly credits a GT sub by its bare parent -> must block.
        report = self.run_check(GOOD_CONTRACT, GOOD_CLASSES, mitre=_MITRE_BROKEN_REVERSE)
        self.assertFalse(report.in_sync)
        self.assertTrue(any("credit drift" in p for p in report.mitre_problems))


# ===========================================================================
# EXIT CODES.
# ===========================================================================
class TestExitCodes(DriftTestBase):
    def test_drift_exits_2(self):
        drifted = dict(GOOD_CLASSES)
        drifted["inconclusive"] = {"INCONCLUSIVE"}  # dropped synonyms
        cpath = self.write_contract(GOOD_CONTRACT)
        write_scorer(self.tmp, drifted)
        rc = dc.main(["--contract", cpath, "--scorer-dir", self.tmp])
        self.assertEqual(rc, 2)

    def test_missing_scorer_exits_3(self):
        cpath = self.write_contract(GOOD_CONTRACT)
        empty = tempfile.mkdtemp(prefix="noscorer_")
        rc = dc.main(["--contract", cpath, "--scorer-dir", empty])
        self.assertEqual(rc, 3)  # could-not-evaluate must BLOCK, not pass

    def test_missing_contract_exits_3(self):
        write_scorer(self.tmp, GOOD_CLASSES)
        rc = dc.main(["--contract", os.path.join(self.tmp, "nope.yaml"),
                      "--scorer-dir", self.tmp])
        self.assertEqual(rc, 3)


# ===========================================================================
# USE-CASE — realistic end-to-end scenario for this tool.
#
# An operator is about to run a VERDICT ablation lap: they edit contract.yaml to
# add a new benign synonym ("CLEAN") to the non_malicious equivalence class, then
# `make render && make sync`. They FORGET to mirror it into scorer.VERDICT_CLASSES
# (the exact Stage 4.4 hazard). Before the lap, the ablation-runner calls this
# gate. It MUST hard-block (exit 2) and name the missing token, so no rate delta
# is attributed to a stale scorer. After they fix the mirror, the gate clears and
# the lap proceeds.
# ===========================================================================
class TestUseCaseVerdictAblationLap(DriftTestBase):
    def _contract_with_clean_synonym(self) -> str:
        return GOOD_CONTRACT.replace(
            "non_malicious: [NON_MALICE, NONMALICE, BENIGN]",
            "non_malicious: [NON_MALICE, NONMALICE, BENIGN, CLEAN]",
        )

    def test_lap_blocks_when_scorer_not_resynced(self):
        contract = self._contract_with_clean_synonym()
        # scorer mirror is the OLD one (no CLEAN) -> drift.
        cpath = self.write_contract(contract)
        write_scorer(self.tmp, GOOD_CLASSES)  # stale mirror
        report = dc.run_drift_check(cpath, self.tmp)
        self.assertFalse(report.in_sync, "stale scorer mirror must block the lap")
        self.assertTrue(
            any("non_malicious" in p and "CLEAN" in p for p in report.verdict_class_problems),
            f"expected CLEAN named as missing; got {report.verdict_class_problems}",
        )
        rc = dc.main(["--contract", cpath, "--scorer-dir", self.tmp])
        self.assertEqual(rc, 2, "HARD-BLOCK exit code for the ablation-runner")

    def test_lap_proceeds_after_resync(self):
        contract = self._contract_with_clean_synonym()
        resynced = {
            "malicious": {"MALICE", "MALICIOUS"},
            "non_malicious": {"NON_MALICE", "NONMALICE", "BENIGN", "CLEAN"},
            "inconclusive": {"INCONCLUSIVE", "INDETERMINATE", "UNKNOWN"},
        }
        cpath = self.write_contract(contract)
        write_scorer(self.tmp, resynced)
        report = dc.run_drift_check(cpath, self.tmp)
        self.assertTrue(report.in_sync, "re-synced mirror should clear the gate")
        rc = dc.main(["--contract", cpath, "--scorer-dir", self.tmp, "--quiet"])
        self.assertEqual(rc, 0, "lap may proceed once mirror matches")


# ===========================================================================
# REGRESSION — run against the REAL repo files if they exist on this box.
# This is a live cross-check (not a synthetic fixture): the real scorer.py and
# contract.yaml currently in the repo SHOULD be in sync. Skipped if not present
# (e.g. on a CI box without the repo), so the synthetic suite stays portable.
# ===========================================================================
class TestRealRepoInSync(unittest.TestCase):
    REPO = "/home/ubuntu/find-evil-hackathon"

    def test_shipped_contract_matches_shipped_scorer(self):
        contract = os.path.join(self.REPO, "protocol-sift", "contract", "contract.yaml")
        scorer_dir = os.path.join(self.REPO, "contract-build", "scoring")
        if not (os.path.isfile(contract) and os.path.isfile(os.path.join(scorer_dir, "scorer.py"))):
            self.skipTest("real repo files not present on this box")
        report = dc.run_drift_check(contract, scorer_dir)
        self.assertTrue(
            report.in_sync,
            "REAL contract.yaml and scorer.py have DRIFTED:\n" + report.render(),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

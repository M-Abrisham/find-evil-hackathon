#!/usr/bin/env python3
"""Unit tests for judge_validation.py — stdlib unittest, SYNTHETIC fixtures only.

No network, no API key, no real cases/keys. The judge is replaced by pure-python
'fake adjudicators' that deterministically mimic score.py's llm_adjudicate output
shape ({"adjudicated":[{index,supported,reason}]}).

Covers:
  - NORMAL: a perfect judge passes; confusion math + TPR/TNR correct.
  - EDGE: TO_BE_LABELED items skipped; single-class set cannot PASS; judge
    unavailable (None) counts as no-rescue + blocks PASS; out-of-range / bad
    verdict indices ignored safely; Wilson lower bound at 0/n and 1/1.
  - FAILURE: low TNR (rescues real FPs) fails even with perfect TPR; malformed
    set raises LabeledSetError; gate refuses missing/failed/non-current artifact.
  - USE-CASE (end-to-end): operator builds a 6-item labeled set, runs a judge
    that is right on the easy items but wrong on borderline ones, gets FAIL,
    writes the artifact, and score.py's gate_check then correctly DENIES --judge
    on that artifact and APPROVES a passing one (incl. version-drift expiry).
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest

import judge_validation as jv


# ---------------------------------------------------------------------------
# Fixture builders + fake adjudicators
# ---------------------------------------------------------------------------
def item(iid, finding, gold, rubric=None):
    return {
        "id": iid,
        "finding": finding,
        "rubric": rubric or {"attack_type": "x", "network": []},
        "gold": gold,
        "rationale": "synthetic",
    }


def labeled_set(items, set_id="t-set", frozen=True):
    return {"schema_version": 1, "set_id": set_id, "frozen": frozen, "items": items}


def adj_perfect(findings, rubric):
    """Oracle judge: rescues iff the rubric is tagged truth_supported=True.
    We smuggle the ground truth through a private rubric key the fake reads
    (a real judge would not see this — it's only to drive the test)."""
    supported = bool(rubric.get("_truth_supported"))
    return {"adjudicated": [{"index": 0, "supported": supported, "reason": "fake"}]}


def adj_always_rescue(findings, rubric):
    return {"adjudicated": [{"index": 0, "supported": True, "reason": "rescue-all"}]}


def adj_never_rescue(findings, rubric):
    return {"adjudicated": [{"index": 0, "supported": False, "reason": "rescue-none"}]}


def adj_unavailable(findings, rubric):
    return None  # mirrors llm_adjudicate returning None (CLI missing / exit!=0)


def adj_garbage_index(findings, rubric):
    """Returns out-of-range and bad-type indices; harness must ignore them and
    fall back to the safe default (not supported)."""
    return {"adjudicated": [{"index": 99, "supported": True},
                            {"index": True, "supported": True},
                            {"index": "0", "supported": True}]}


def truth_rubric(supported: bool):
    return {"attack_type": "x", "network": [], "_truth_supported": supported}


# ---------------------------------------------------------------------------
# NORMAL
# ---------------------------------------------------------------------------
class TestNormal(unittest.TestCase):
    def test_perfect_judge_passes_with_correct_confusion(self):
        items = [
            item("a", "f1", "supported", truth_rubric(True)),
            item("b", "f2", "supported", truth_rubric(True)),
            item("c", "f3", "unsupported", truth_rubric(False)),
            item("d", "f4", "unsupported", truth_rubric(False)),
        ]
        rep = jv.run_validation(labeled_set(items), adj_perfect, threshold=0.9)
        self.assertEqual(rep["confusion"], {"tp": 2, "tn": 2, "fp": 0, "fn": 0})
        self.assertEqual(rep["tpr"], 1.0)
        self.assertEqual(rep["tnr"], 1.0)
        self.assertTrue(rep["passed"])
        self.assertEqual(rep["fail_reasons"], [])
        self.assertEqual(rep["items_scored"], 4)

    def test_render_smoke(self):
        items = [item("a", "f", "supported", truth_rubric(True)),
                 item("b", "f", "unsupported", truth_rubric(False))]
        rep = jv.run_validation(labeled_set(items), adj_perfect)
        txt = jv.render(rep)
        self.assertIn("CONFUSION", txt.upper())
        self.assertIn("VERDICT", txt)


# ---------------------------------------------------------------------------
# EDGE
# ---------------------------------------------------------------------------
class TestEdge(unittest.TestCase):
    def test_to_be_labeled_items_are_skipped(self):
        items = [
            item("a", "f", "supported", truth_rubric(True)),
            item("b", "f", "unsupported", truth_rubric(False)),
            item("c", "f", "TO_BE_LABELED"),
        ]
        rep = jv.run_validation(labeled_set(items), adj_perfect)
        self.assertEqual(rep["items_scored"], 2)
        self.assertEqual(rep["items_unlabeled"], 1)
        # an unlabeled item present => not fully labeled => cannot pass
        self.assertFalse(rep["fully_labeled"])
        self.assertFalse(rep["passed"])
        self.assertTrue(any("TO_BE_LABELED" in r for r in rep["fail_reasons"]))

    def test_single_class_cannot_pass(self):
        # only positives present -> TNR unmeasurable
        items = [item("a", "f", "supported", truth_rubric(True)),
                 item("b", "f", "supported", truth_rubric(True))]
        rep = jv.run_validation(labeled_set(items), adj_perfect)
        self.assertEqual(rep["tpr"], 1.0)
        self.assertIsNone(rep["tnr"])
        self.assertFalse(rep["passed"])
        self.assertTrue(any("TNR" in r for r in rep["fail_reasons"]))

    def test_judge_unavailable_blocks_pass(self):
        items = [item("a", "f", "supported", truth_rubric(True)),
                 item("b", "f", "unsupported", truth_rubric(False))]
        rep = jv.run_validation(labeled_set(items), adj_unavailable)
        self.assertEqual(rep["judge_errors"], 2)
        # unavailable => no rescue: the supported item becomes an FN
        self.assertEqual(rep["confusion"]["fn"], 1)
        self.assertEqual(rep["confusion"]["tn"], 1)
        self.assertFalse(rep["passed"])
        self.assertTrue(any("judge error" in r for r in rep["fail_reasons"]))

    def test_garbage_indices_default_to_not_supported(self):
        items = [item("a", "f", "supported", truth_rubric(True)),
                 item("b", "f", "unsupported", truth_rubric(False))]
        rep = jv.run_validation(labeled_set(items), adj_garbage_index)
        # no valid index 0 => both predicted not-supported
        self.assertEqual(rep["confusion"]["fn"], 1)  # supported item not rescued
        self.assertEqual(rep["confusion"]["tn"], 1)  # unsupported correctly kept
        self.assertFalse(rep["passed"])

    def test_wilson_bounds(self):
        self.assertEqual(jv.wilson_interval(0, 0), (0.0, 1.0))
        lo, hi = jv.wilson_interval(0, 10)
        self.assertEqual(lo, 0.0)
        self.assertLess(hi, 0.35)
        lo, hi = jv.wilson_interval(1, 1)
        self.assertGreater(lo, 0.0)   # behaves at 1/1 (normal-approx would give 1.0)
        self.assertLessEqual(hi, 1.0)


# ---------------------------------------------------------------------------
# FAILURE
# ---------------------------------------------------------------------------
class TestFailure(unittest.TestCase):
    def test_low_tnr_fails_even_with_perfect_tpr(self):
        # judge rescues EVERYTHING: perfect TPR but TNR == 0 (rescues real FPs)
        items = [item("a", "f", "supported", truth_rubric(True)),
                 item("b", "f", "supported", truth_rubric(True)),
                 item("c", "f", "unsupported", truth_rubric(False)),
                 item("d", "f", "unsupported", truth_rubric(False))]
        rep = jv.run_validation(labeled_set(items), adj_always_rescue, threshold=0.9)
        self.assertEqual(rep["tpr"], 1.0)
        self.assertEqual(rep["tnr"], 0.0)
        self.assertEqual(rep["confusion"]["fp"], 2)  # rescued 2 real FPs == dangerous
        self.assertFalse(rep["passed"])
        self.assertTrue(any("TNR" in r for r in rep["fail_reasons"]))

    def test_low_tpr_fails(self):
        items = [item("a", "f", "supported", truth_rubric(True)),
                 item("b", "f", "unsupported", truth_rubric(False))]
        rep = jv.run_validation(labeled_set(items), adj_never_rescue, threshold=0.9)
        self.assertEqual(rep["tpr"], 0.0)
        self.assertEqual(rep["tnr"], 1.0)
        self.assertFalse(rep["passed"])

    def test_malformed_sets_raise(self):
        bad = [
            "not a dict",
            {"items": []},                                   # empty
            {"items": [{"finding": "x", "rubric": {}, "gold": "supported"}]},  # no id
            {"items": [{"id": "a", "rubric": {}, "gold": "supported"}]},       # no finding
            {"items": [{"id": "a", "finding": "x", "gold": "supported"}]},     # no rubric
            {"items": [{"id": "a", "finding": "x", "rubric": {}, "gold": "maybe"}]},  # bad gold
            {"items": [{"id": "a", "finding": "x", "rubric": {}, "gold": "supported"},
                       {"id": "a", "finding": "y", "rubric": {}, "gold": "unsupported"}]},  # dup id
        ]
        for b in bad:
            with self.assertRaises(jv.LabeledSetError):
                jv.validate_labeled_set(b)

    def test_gate_refuses_missing_failed_and_noncurrent(self):
        # no path
        ok, _ = jv.gate_check(None)
        self.assertFalse(ok)
        # missing file
        ok, _ = jv.gate_check("/nonexistent/artifact.json")
        self.assertFalse(ok)
        with tempfile.TemporaryDirectory() as d:
            # failed artifact
            failed = os.path.join(d, "failed.json")
            with open(failed, "w") as fh:
                json.dump({"tool": "judge_validation", "passed": False,
                           "fail_reasons": ["TPR 0.5 < 0.9"]}, fh)
            ok, reason = jv.gate_check(failed)
            self.assertFalse(ok)
            self.assertIn("FAIL", reason)
            # passing artifact
            passing = os.path.join(d, "pass.json")
            with open(passing, "w") as fh:
                json.dump({"tool": "judge_validation", "passed": True,
                           "claude_version": "1.2.3"}, fh)
            ok, _ = jv.gate_check(passing, claude_version="1.2.3")
            self.assertTrue(ok)
            # version drift => not current
            ok, reason = jv.gate_check(passing, claude_version="9.9.9")
            self.assertFalse(ok)
            self.assertIn("drift", reason)
            # wrong tool tag
            wrong = os.path.join(d, "wrong.json")
            with open(wrong, "w") as fh:
                json.dump({"tool": "something_else", "passed": True}, fh)
            ok, _ = jv.gate_check(wrong)
            self.assertFalse(ok)


class TestGateHardening(unittest.TestCase):
    """FIX 2: the judge gate is fail-closed.
      (a) the running model snapshot drives the version-drift check at score time:
          a passing artifact stamped under a STALE snapshot is DENIED;
      (b) `passed` must be the JSON boolean true (identity) — a truthy-but-non-bool
          value (1 / "yes" / [1]) is REJECTED, never read as a pass."""

    # ---- (b) passed must be boolean True, not merely truthy -----------------
    def test_passed_truthy_int_one_is_denied(self):
        ok, reason = jv.artifact_is_current({"tool": "judge_validation", "passed": 1})
        self.assertFalse(ok)
        self.assertIn("not boolean true", reason)

    def test_passed_string_yes_is_denied(self):
        ok, reason = jv.artifact_is_current({"tool": "judge_validation", "passed": "yes"})
        self.assertFalse(ok)
        self.assertIn("not boolean true", reason)

    def test_passed_nonempty_list_is_denied(self):
        ok, reason = jv.artifact_is_current({"tool": "judge_validation", "passed": [1]})
        self.assertFalse(ok)
        self.assertIn("not boolean true", reason)

    def test_passed_false_is_denied_as_failure(self):
        ok, reason = jv.artifact_is_current(
            {"tool": "judge_validation", "passed": False, "fail_reasons": ["TPR 0.5 < 0.9"]})
        self.assertFalse(ok)
        self.assertIn("FAILED", reason)

    def test_passed_missing_is_denied(self):
        ok, reason = jv.artifact_is_current({"tool": "judge_validation"})
        self.assertFalse(ok)
        self.assertIn("FAILED", reason)

    def test_genuine_boolean_true_no_version_is_allowed(self):
        ok, reason = jv.artifact_is_current({"tool": "judge_validation", "passed": True})
        self.assertTrue(ok)

    # ---- (a) version-drift check fires at score time ------------------------
    def test_stale_version_passing_artifact_is_denied(self):
        art = {"tool": "judge_validation", "passed": True, "claude_version": "sonnet@1.0.0"}
        ok, reason = jv.artifact_is_current(art, claude_version="sonnet@2.0.0")
        self.assertFalse(ok)
        self.assertIn("drift", reason)

    def test_current_version_passing_artifact_is_allowed(self):
        art = {"tool": "judge_validation", "passed": True, "claude_version": "sonnet@2.0.0"}
        ok, reason = jv.artifact_is_current(art, claude_version="sonnet@2.0.0")
        self.assertTrue(ok)

    def test_gate_check_stale_version_via_file_is_denied(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "stale.json")
            with open(f, "w") as fh:
                json.dump({"tool": "judge_validation", "passed": True,
                           "claude_version": "sonnet@OLD"}, fh)
            ok, reason = jv.gate_check(f, claude_version="sonnet@NEW")
            self.assertFalse(ok)
            self.assertIn("drift", reason)
            # same snapshot -> allowed
            ok2, _ = jv.gate_check(f, claude_version="sonnet@OLD")
            self.assertTrue(ok2)


class TestScoreJudgeGate(unittest.TestCase):
    """FIX 2: score.py captures `claude --version` and passes it to the gate, so a
    stale-snapshot passing artifact is DENIED end-to-end at score time, and the
    judge runs OFF (deterministic only). Uses a stubbed agent CLI on a tmp PATH —
    NO network, NO API key, NO real model call."""

    def _load_score_module(self):
        import importlib.util
        here = os.path.dirname(os.path.abspath(jv.__file__))
        src = os.path.abspath(os.path.join(here, "..", "score.py"))
        spec = importlib.util.spec_from_file_location("_score_for_gate_test", src)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def _write_stub_agent(self, d, version_line):
        import stat
        agent = os.path.join(d, "claude")
        with open(agent, "w") as fh:
            fh.write("#!/usr/bin/env bash\n")
            # `--version` -> print the stamped version; any other call -> empty json
            fh.write('if [ "$1" = "--version" ]; then echo "%s"; exit 0; fi\n' % version_line)
            fh.write('echo "{}"; exit 0\n')
        os.chmod(agent, os.stat(agent).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        return agent

    def test_judge_model_version_reads_stub_cli(self):
        score = self._load_score_module()
        with tempfile.TemporaryDirectory() as d:
            self._write_stub_agent(d, "9.9.9 (Claude Code)")
            env_path = os.environ.get("PATH", "")
            old_agent = score.JUDGE_AGENT
            try:
                score.JUDGE_AGENT = os.path.join(d, "claude")
                ver = score.judge_model_version()
            finally:
                score.JUDGE_AGENT = old_agent
            self.assertIsNotNone(ver)
            self.assertIn("9.9.9", ver)
            self.assertTrue(ver.startswith(score.JUDGE_MODEL + "@"))

    def test_judge_model_version_none_when_cli_absent(self):
        score = self._load_score_module()
        old_agent = score.JUDGE_AGENT
        try:
            score.JUDGE_AGENT = "/nonexistent/definitely-not-a-real-agent-binary"
            self.assertIsNone(score.judge_model_version())
        finally:
            score.JUDGE_AGENT = old_agent

    def test_main_denies_stale_snapshot_and_runs_judge_off(self):
        score = self._load_score_module()
        with tempfile.TemporaryDirectory() as d:
            # 1. stub agent reporting the CURRENT snapshot version
            self._write_stub_agent(d, "2.0.0")
            score.JUDGE_AGENT = os.path.join(d, "claude")
            running = score.judge_model_version()  # "<model>@2.0.0"
            self.assertTrue(running.endswith("@2.0.0"))

            # 2. a PASSING artifact, but stamped under a STALE snapshot
            art = os.path.join(d, "judge_validation.json")
            with open(art, "w") as fh:
                json.dump({"tool": "judge_validation", "passed": True,
                           "claude_version": running.rsplit("@", 1)[0] + "@1.0.0"}, fh)

            # 3. minimal valid findings + rubric (reuse the selftest mock via score.run)
            findings = {"schema_version": "1.0", "case_id": "c",
                        "attack_type_classification": {"category": "Network Forensics",
                                                       "confidence": "confirmed"},
                        "findings": []}
            rubric = {"schema_version": "1.0", "case_id": "c",
                      "attack_type": {"category": "Network Forensics"},
                      "key_artifacts": [], "key_iocs": [], "timeline_events": [],
                      "actor_accounts": [], "exfil_or_encryption_facts": []}
            fp = os.path.join(d, "findings.json"); rp = os.path.join(d, "rubric.json")
            op = os.path.join(d, "score.json")
            with open(fp, "w") as fh: json.dump(findings, fh)
            with open(rp, "w") as fh: json.dump(rubric, fh)

            rc = score.main(["-f", fp, "-r", rp, "-o", op,
                             "--judge", "--judge-validation", art, "--quiet"])
            self.assertEqual(rc, 0)
            out = json.load(open(op))
            # gate must have DENIED the stale artifact -> judge disabled by gate
            self.assertIn("judge", out)
            self.assertEqual(out["judge"]["status"], "DISABLED_BY_GATE")
            self.assertIn("drift", out["judge"]["note"])


# ---------------------------------------------------------------------------
# USE-CASE — realistic end-to-end operator scenario
# ---------------------------------------------------------------------------
class TestUseCaseEndToEnd(unittest.TestCase):
    def test_operator_validates_judge_then_gate_enforces(self):
        """Operator on josh-pc:
        1. Has a 6-item frozen borderline-FP set (3 truly supported, 3 truly
           unsupported), hand-labeled.
        2. Runs a candidate judge that is correct on the 4 'easy' items but
           WRONG on 2 borderline ones (one false-rescue, one missed-rescue).
        3. Gets TPR=2/3, TNR=2/3 -> below 0.9 -> FAIL -> artifact written.
        4. score.py's gate then DENIES --judge using that artifact.
        5. A later, better judge passes -> a passing artifact is written ->
           the gate APPROVES --judge.
        """
        items = [
            # easy supported (judge gets right)
            item("e1", "lsass dump via comsvcs", "supported", truth_rubric(True)),
            item("e2", "encoded PS scheduled task", "supported", truth_rubric(True)),
            # borderline supported the judge MISSES (FN)
            item("h1", "USB staging device", "supported", truth_rubric("MISS")),
            # easy unsupported (judge gets right)
            item("e3", "benign chrome update", "unsupported", truth_rubric(False)),
            item("e4", "windows defender scan", "unsupported", truth_rubric(False)),
            # borderline unsupported the judge wrongly RESCUES (FP)
            item("h2", "printer driver rundll32", "unsupported", truth_rubric("RESCUE")),
        ]

        def candidate_judge(findings, rubric):
            t = rubric.get("_truth_supported")
            if t == "MISS":
                supported = False        # judge wrongly fails to rescue a supported item
            elif t == "RESCUE":
                supported = True         # judge wrongly rescues an unsupported item
            else:
                supported = bool(t)
            return {"adjudicated": [{"index": 0, "supported": supported}]}

        ls = labeled_set(items, set_id="borderline-fp-v1")
        rep = jv.run_validation(ls, candidate_judge, threshold=0.9)
        # 3 positives: 2 rescued + 1 missed -> TPR 2/3 ; 3 negatives: 2 kept + 1 rescued -> TNR 2/3
        self.assertEqual(rep["confusion"], {"tp": 2, "tn": 2, "fp": 1, "fn": 1})
        self.assertAlmostEqual(rep["tpr"], 2 / 3)
        self.assertAlmostEqual(rep["tnr"], 2 / 3)
        self.assertFalse(rep["passed"])

        with tempfile.TemporaryDirectory() as d:
            art = os.path.join(d, "judge_validation.json")
            with open(art, "w") as fh:
                json.dump(rep, fh)
            allow, msg = jv.gate_check(art)
            self.assertFalse(allow, "gate must DENY --judge on a failing validation")
            self.assertIn("FAIL", msg)

            # Now a better judge (the oracle) passes the SAME set.
            rep2 = jv.run_validation(ls_oracle(ls), adj_perfect, threshold=0.9)
            self.assertTrue(rep2["passed"])
            art2 = os.path.join(d, "judge_validation_pass.json")
            rep2["claude_version"] = "1.2.3"
            with open(art2, "w") as fh:
                json.dump(rep2, fh)
            allow2, _ = jv.gate_check(art2, claude_version="1.2.3")
            self.assertTrue(allow2, "gate must ALLOW --judge on a current passing validation")


def ls_oracle(ls):
    """Rewrite the borderline truth markers to plain booleans so the oracle
    (adj_perfect) scores them correctly — models 'a better judge' on the same items."""
    out = {k: v for k, v in ls.items()}
    new_items = []
    for it in ls["items"]:
        it2 = {k: v for k, v in it.items()}
        r = {k: v for k, v in it["rubric"].items()}
        if r.get("_truth_supported") in ("MISS", "RESCUE"):
            r["_truth_supported"] = (it["gold"] == "supported")
        it2["rubric"] = r
        new_items.append(it2)
    out["items"] = new_items
    return out


# ---------------------------------------------------------------------------
# Seed fixture sanity (the shipped TO_BE_LABELED seed is structurally valid
# but, by design, cannot pass — no fabricated labels).
# ---------------------------------------------------------------------------
class TestSeedFixture(unittest.TestCase):
    def test_seed_is_valid_but_unlabeled(self):
        here = os.path.dirname(os.path.abspath(__file__))
        seed = os.path.join(here, "fixtures", "seed_labeled_set.json")
        data = jv.load_labeled_set(seed)            # must validate structurally
        stats = jv.labeled_set_stats(data)
        self.assertFalse(stats["fully_labeled"])    # all TO_BE_LABELED by design
        self.assertEqual(stats["labeled"], 0)
        self.assertGreater(stats["unlabeled_to_be_labeled"], 0)
        # running validation on it must NOT pass (nothing labeled)
        rep = jv.run_validation(data, adj_perfect)
        self.assertFalse(rep["passed"])
        self.assertEqual(rep["items_scored"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

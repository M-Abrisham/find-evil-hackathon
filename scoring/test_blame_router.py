#!/usr/bin/env python3
"""Tests for blame_router.py — the diagnose->route->keep/revert->ledger lap wiring.

Self-contained + deterministic: synthetic eval/ioc score JSONs shaped EXACTLY like the
real producers (eval/score.py and scoring/scorer.py CLI), a tiny contract-shaped playbook
fixture, a tmp ledger, and an INJECTED tune runner that reproduces tune_playbook.py's exact
on-disk effects (snapshot versions/<cat>/v<old>.md + version bump + appended step) by REUSING
tune_playbook.bump_version. NO network, NO live agent (no claude -p), NO real case.

The blamer itself is reached by SUBPROCESS in production AND here (blame_router never imports
it) — the real playbooks/blame_playbook.py runs as a child, so its ranking/routing/tripwire
are exercised for real. Only the LLM tune step is stubbed (it would otherwise call claude -p).

Run from scoring/:
    python3 -m unittest test_blame_router -v
"""
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent          # .../scoring
REPO_ROOT = HERE.parent                                  # repo root
sys.path.insert(0, str(REPO_ROOT / "playbooks"))         # for tune_playbook (test stub reuse only)


def _read(path):
    return pathlib.Path(path).read_text(encoding="utf-8")


def _write(path, text):
    pathlib.Path(path).write_text(text, encoding="utf-8")

import scorer
import keep_or_revert
import score_ledger
import blame_router
import tune_playbook as tune


# =============================================================================
# Synthetic producers — shaped EXACTLY like the real score JSONs.
# =============================================================================
def eval_score(*, missed=None, case_id="VIGIA-TEST-001",
               category_match=True, unbacked=0, false_positives=0):
    """A JSON shaped like eval/score.py build_score() output.

    `missed` maps a SCORE bucket -> list of missed rubric item strings (drives the only
    tune-actionable axis). per_bucket recalls are derived so the blamer's gap math works.
    """
    missed = missed or {}
    buckets = ["key_artifacts", "key_iocs", "timeline_events",
               "actor_accounts", "exfil_or_encryption_facts"]
    per_bucket = {}
    missed_evidence = {}
    for b in buckets:
        items = missed.get(b, [])
        # recall 0.0 when something missed, else 1.0 (shape only; values just need to be floats)
        per_bucket[b] = {"matched": 0 if items else 1, "total": 1,
                         "recall": 0.0 if items else 1.0}
        missed_evidence[b] = list(items)
    return {
        "case_id": case_id,
        "match_threshold": 0.55,
        "classification": {
            "predicted_category": "Ransomware" if category_match else "Phishing",
            "truth_category": "Ransomware",
            "category_match": bool(category_match),
            "subtype_match": True,
            "subtype_similarity": 0.9,
        },
        "evidence": {
            "rubric_items_recalled": 0,
            "false_positives": false_positives,
            "false_positive_rate": 0.0,
            "recall": 0.5,
            "f1": 0.5,
            "per_bucket": per_bucket,
            "missed_evidence": missed_evidence,
            "false_positive_findings": [],
        },
        "hallucination": {
            "unbacked_findings": unbacked,
            "hallucination_rate": 0.0,
            "total_findings": 1,
            "unbacked_list": [],
        },
        "headline": {
            "category_match": bool(category_match),
            "subtype_match": True,
            "evidence_recall": 0.5,
            "evidence_f1": 0.5,
            "false_positive_rate": 0.0,
            "hallucination_rate": 0.0,
        },
    }


def _agg(*, findable_recall, findable_found, findable_total, fabrication=0,
         verdicts=1, mitre_recall, mitre_found, mitre_total):
    """A full 16-key scorer.aggregate()-shaped dict (the keep/revert vector)."""
    a = dict(scorer.aggregate([]))  # canonical key set (zeros / None)
    a["findable_recall_micro"] = findable_recall
    a["findable_found"] = findable_found
    a["findable_total"] = findable_total
    a["fabrication_count_total"] = fabrication
    a["verdicts_emitted"] = verdicts
    a["mitre_recall_micro"] = mitre_recall
    a["mitre_found"] = mitre_found
    a["mitre_total"] = mitre_total
    a["cases"] = 1
    return a


def ioc_score(*, case_id="VIGIA-TEST-001", verdict="found", verdict_expected="MALICE",
              fabrications=None, mitre_present=None, mitre_found=1, mitre_total=1,
              findable_found=1, findable_total=2, failures=None, agg=None):
    """A JSON shaped like scoring/scorer.py CLI output: {"cases":[CaseResult],"aggregate":{16 keys}}.

    A single case carrying the fields the blamer reads from an ioc case (verdict,
    fabrications, mitre_*, failures), plus the aggregate the keep/revert gate consumes.
    """
    fabrications = fabrications or []
    mitre_present = mitre_present if mitre_present is not None else {"T1486": True}
    failures = failures or []
    case = {
        "case_id": case_id,
        "iocs": [],
        "total_findable": findable_total,
        "found_findable": findable_found,
        "findable_recall": (findable_found / findable_total) if findable_total else None,
        "total_iocs": findable_total,
        "found_total": findable_found,
        "full_recall": None,
        "fabrications": fabrications,
        "fabrication_count": len(fabrications),
        "asserted_cidrs": [],
        "verdict_expected": verdict_expected,
        "verdict": verdict,
        "mitre_present": mitre_present,
        "mitre_found": mitre_found,
        "mitre_total": mitre_total,
        "failures": failures,
    }
    if agg is None:
        agg = _agg(findable_recall=(findable_found / findable_total) if findable_total else None,
                   findable_found=findable_found, findable_total=findable_total,
                   fabrication=len(fabrications),
                   verdicts=1 if verdict == "found" else 0,
                   mitre_recall=(mitre_found / mitre_total) if mitre_total else None,
                   mitre_found=mitre_found, mitre_total=mitre_total)
    return {"cases": [case], "aggregate": agg}


# A minimal CONTRACT-SHAPED playbook: YAML frontmatter with an integer `version:` line and a
# `category_id`, plus a Steps section so the blamer + revert see a contract-shaped file.
PLAYBOOK = """---
category_id: ransomware-test
version: 1
sub_types: [crypto-locker]
---

# Ransomware (test playbook)

## Steps
- n: 1  # find the ransom note
  tool: ls
  check: grep
  emits: [key_artifacts]

## Tuning log
- 2026-01-01 | seed | none | initial
"""


class _TuneStub:
    """A deterministic stand-in for `tune_playbook.py` invoked via tune_command.

    Reproduces the real tuner's on-disk effect WITHOUT a live claude -p: writes the
    pre-tune snapshot versions/<cat>/v<old>.md verbatim, bumps the version (REUSING the
    frozen tune_playbook.bump_version — no reimplementation), appends a step + a tuning-log
    line, and writes the playbook back. Records that it was called + the cwd it ran in.

    Signature matches subprocess.run(cmd, cwd=..., capture_output=True, text=True) and
    returns an object exposing .returncode/.stdout/.stderr.
    """
    def __init__(self, versions_root):
        self.versions_root = versions_root
        self.calls = []

    def __call__(self, cmd, cwd=None, capture_output=True, text=True, **kw):
        self.calls.append({"cmd": list(cmd), "cwd": cwd})
        # Resolve --playbook from the emitted tune_command (relative to cwd, like the real run).
        pb_arg = cmd[cmd.index("--playbook") + 1]
        pb_path = os.path.join(cwd, pb_arg) if (cwd and not os.path.isabs(pb_arg)) else pb_arg
        text_in = _read(pb_path)
        cat = tune.fm_scalar(text_in, "category_id") or os.path.splitext(os.path.basename(pb_path))[0]
        new_text, v_old, v_new = tune.bump_version(text_in)  # REUSE frozen bump (no reimpl)
        # Append a real step block + tuning-log line (mimic the appended delta).
        new_text = new_text.rstrip("\n") + (
            "\n- n: 2  # tuned: emit the missed bucket\n"
            "  tool: ls\n  check: grep\n  emits: [key_iocs]\n"
            f"- {v_new}-tune | tuned key_iocs\n"
        )
        # Snapshot the PRE-tune playbook to versions/<cat>/v<old>.md (what revert restores).
        cat_dir = os.path.join(self.versions_root, cat)
        os.makedirs(cat_dir, exist_ok=True)
        _write(os.path.join(cat_dir, f"v{v_old}.md"), text_in)
        # Orphan artifacts the real tuner also writes (so revert's orphan-clean has work).
        _write(os.path.join(cat_dir, f"v{v_new}.diff"), "--- diff ---\n")
        _write(os.path.join(cat_dir, f"v{v_new}.trace.json"), "{}\n")
        _write(pb_path, new_text)

        class _R:
            returncode = 0
            stdout = f"TUNED: v{v_old} -> v{v_new}"
            stderr = ""
        return _R()


class BlameRouterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="blame_router_test_")
        self.ledger = os.path.join(self.tmp, "ledger.jsonl")
        # Playbook + its versions dir live together so revert finds the snapshot.
        self.pb_dir = os.path.join(self.tmp, "pb")
        os.makedirs(self.pb_dir, exist_ok=True)
        self.playbook = os.path.join(self.pb_dir, "ransomware-test.md")
        _write(self.playbook, PLAYBOOK)
        self.versions_dir = os.path.join(self.pb_dir, "versions")
        self.tune_stub = _TuneStub(self.versions_dir)

    def _write_json(self, name, obj):
        p = os.path.join(self.tmp, name)
        _write(p, json.dumps(obj))
        return p

    def _run(self, eval_obj, base_ioc_obj, post_ioc_obj, **kw):
        es = self._write_json("eval.json", eval_obj)
        bi = self._write_json("base_ioc.json", base_ioc_obj)
        pi = self._write_json("post_ioc.json", post_ioc_obj)
        return blame_router.diagnose_and_route(
            baseline_eval_score=es,
            baseline_ioc_score=bi,
            post_ioc_score=pi,
            playbook_path=self.playbook,
            case_id="VIGIA-TEST-001",
            ledger_path=self.ledger,
            versions_dir=self.versions_dir,
            repo_root=str(REPO_ROOT),
            tune_runner=self.tune_stub,
            **kw,
        )

    # ---- happy: missed_evidence worst, tune runnable, post IMPROVES recall, no regression -> KEEP
    def test_happy_keep_records_ledger(self):
        ev = eval_score(missed={"key_iocs": ["sha256:deadbeef"]})  # one missed bucket -> tune-actionable
        base = ioc_score(verdict="found", findable_found=1, findable_total=2,
                         mitre_found=1, mitre_total=1)  # findable_recall 0.5
        post = ioc_score(verdict="found", findable_found=2, findable_total=2,
                         mitre_found=1, mitre_total=1)  # findable_recall 1.0 (strict improve)
        out = self._run(ev, base, post)
        self.assertEqual(out["worst_failure_kind"], "missed_evidence")
        self.assertTrue(out["tuned"])
        self.assertEqual(out["decision"], "KEEP")
        self.assertTrue(out["ledger_row_appended"])
        # ledger row recorded + chain verifies
        score_ledger.assert_chain_ok(self.ledger)
        rows = score_ledger.read_rows(self.ledger)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["decision"], "KEEP")
        # KEEP => the playbook EDIT stays (version bumped to 2, snapshot v1 present)
        self.assertIn("version: 2", _read(self.playbook))
        self.assertTrue(os.path.isfile(os.path.join(self.versions_dir, "ransomware-test", "v1.md")))

    # ---- reward-hack guard: post REGRESSES verdicts_emitted -> REVERT + snapshot-restore + ledger
    def test_verdict_regression_reverts_rewardhack_guard(self):
        ev = eval_score(missed={"key_iocs": ["sha256:deadbeef"]})  # tune-actionable
        base = ioc_score(verdict="found", findable_found=1, findable_total=2)   # verdicts_emitted=1
        # A recall-improving tune that SECRETLY drops the verdict (reward hack): findable up,
        # but verdicts_emitted 1 -> 0. The gate MUST refuse it.
        post_agg = _agg(findable_recall=1.0, findable_found=2, findable_total=2,
                        verdicts=0,  # regression on a gated dim
                        mitre_recall=1.0, mitre_found=1, mitre_total=1)
        post = ioc_score(verdict="not_emitted", findable_found=2, findable_total=2, agg=post_agg)
        out = self._run(ev, base, post)
        self.assertTrue(out["tuned"])
        self.assertEqual(out["decision"], "REVERT")
        self.assertTrue(out["ledger_row_appended"])
        # snapshot-restore happened: playbook is byte-for-byte back to v1 (orphans cleaned)
        self.assertEqual(_read(self.playbook), PLAYBOOK)
        self.assertIn("version: 1", _read(self.playbook))
        self.assertFalse(os.path.isfile(os.path.join(self.versions_dir, "ransomware-test", "v2.diff")))
        rows = score_ledger.read_rows(self.ledger)
        self.assertEqual(rows[-1]["decision"], "REVERT")
        score_ledger.assert_chain_ok(self.ledger)

    # ---- reward-hack guard variant: post REGRESSES mitre_recall_micro -> REVERT
    def test_mitre_regression_reverts(self):
        ev = eval_score(missed={"key_iocs": ["sha256:deadbeef"]})
        base = ioc_score(verdict="found", findable_found=1, findable_total=2,
                         mitre_found=2, mitre_total=2)  # mitre_recall 1.0
        post_agg = _agg(findable_recall=1.0, findable_found=2, findable_total=2,
                        verdicts=1, mitre_recall=0.5, mitre_found=1, mitre_total=2)  # mitre regress
        post = ioc_score(verdict="found", findable_found=2, findable_total=2,
                         mitre_found=1, mitre_total=2, agg=post_agg)
        out = self._run(ev, base, post)
        self.assertEqual(out["decision"], "REVERT")
        self.assertEqual(_read(self.playbook), PLAYBOOK)  # restored

    # ---- needs_other_fix logging: worst=verdict_absent WITH a missed_evidence bucket also failing.
    # tune_command is non-null (missed_evidence present). UNADDRESSED must fire for verdict_absent
    # regardless of KEEP/REVERT.
    def test_needs_other_fix_logs_when_worst_not_tunable(self):
        ev = eval_score(missed={"key_iocs": ["sha256:deadbeef"]})  # missed bucket -> tune runs
        # verdict_absent is sev 100 (the worst), beating missed_evidence (sev 40).
        base = ioc_score(verdict="not_emitted", verdict_expected="MALICE",
                         findable_found=1, findable_total=2)
        post = ioc_score(verdict="found", findable_found=2, findable_total=2)  # KEEP-shaped
        # capture stderr to assert the UNADDRESSED line
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            out = self._run(ev, base, post)
        err = buf.getvalue()
        self.assertEqual(out["worst_failure_kind"], "verdict_absent")
        self.assertIn("verdict_absent", out["unaddressed"])
        self.assertIn(blame_router.UNADDRESSED_PREFIX, err)
        self.assertIn("kind=verdict_absent", err)
        self.assertTrue(out["tuned"])  # the missed_evidence bucket still drove a (guarded) tune

    # ---- no-tune: worst=verdict_absent and NO missed_evidence bucket failed -> tune_command None.
    def test_no_tune_no_ledger_row(self):
        ev = eval_score(missed={})  # nothing missed -> no tune-actionable failure
        base = ioc_score(verdict="not_emitted", verdict_expected="MALICE",
                         findable_found=2, findable_total=2)  # only verdict_absent
        post = ioc_score(verdict="found", findable_found=2, findable_total=2)
        blame_out = os.path.join(self.tmp, "blame.json")
        out = self._run(ev, base, post, blame_out=blame_out)
        self.assertEqual(out["worst_failure_kind"], "verdict_absent")
        self.assertFalse(out["tuned"])
        self.assertIsNone(out["decision"])
        self.assertFalse(out["ledger_row_appended"])
        self.assertEqual(len(self.tune_stub.calls), 0)  # tuner NEVER invoked
        # no ledger edit-row appended (no edit => no row)
        self.assertEqual(score_ledger.read_rows(self.ledger), [])
        # blame.json present (the blamer wrote it)
        self.assertTrue(os.path.isfile(blame_out))
        self.assertIn("verdict_absent", _read(blame_out))

    # ---- contract: blame_router SUBPROCESSES the blamer; it never imports/duplicates its logic.
    def test_router_does_not_import_blamer(self):
        src = _read(os.path.join(HERE, "blame_router.py"))
        self.assertNotIn("import blame_playbook", src)
        self.assertNotIn("from blame_playbook", src)
        # the blamer is reached only by subprocess (its script path is referenced)
        self.assertIn("blame_playbook.py", src)
        self.assertIn("subprocess", src)
        # blame_playbook must NOT be a loaded module attribute of blame_router
        self.assertFalse(hasattr(blame_router, "blame_playbook"))

    # ---- the no-tune call really skips the tuner even when tune_runner is provided.
    def test_no_tune_skips_injected_runner(self):
        ev = eval_score(missed={})
        base = ioc_score(verdict="found", findable_found=2, findable_total=2)
        post = ioc_score(verdict="found", findable_found=2, findable_total=2)
        # no failures at all -> blamer reports nothing-to-blame: worst None, no tune.
        out = self._run(ev, base, post)
        self.assertFalse(out["tuned"])
        self.assertEqual(len(self.tune_stub.calls), 0)


if __name__ == "__main__":
    unittest.main()

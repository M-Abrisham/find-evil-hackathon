#!/usr/bin/env python3
"""blame_router.py — wire the orphaned PB6 blamer into a deterministic, fixture-driven
"diagnose -> route -> keep/revert -> ledger" lap (roadmap 8.7 wiring; NOT a live run).

WHAT THIS CLOSES
----------------
playbooks/blame_playbook.py (the blamer) ranks the worst failure and emits a blame.json with
a ready-to-run ``tune_command``; scoring/{composite,keep_or_revert,score_ledger}.py decide and
record a candidate edit. Until now nothing JOINED them: the blamer was orphaned. This module is
that join, and ONLY that join — it never reimplements blamer, tuner, decider or ledger logic; it
SUBPROCESSES the blamer and the tuner and CALLS the frozen decider/ledger functions.

THE "NO LIVE RUN" CONTRACT
--------------------------
There is no agent invocation here (no run_blind, no ``claude -p``, no real case). Every score is a
FIXTURE supplied by the caller:

  * baseline_eval_score  — JSON path, shaped like eval/score.py output (missed_evidence buckets).
  * baseline_ioc_score   — JSON path, shaped like scoring/scorer.py CLI ({"cases":[...],"aggregate":{...}}).
  * post_ioc_score       — JSON path, the RE-SCORED scorer output representing the post-tune state.
                           Supplied as a fixture precisely because there is no live re-run; it is the
                           candidate's "after" vector that the keep/revert gate judges.

THE REWARD-HACK GUARD (the load-bearing part)
---------------------------------------------
``blame["tune_command"] != None`` only means "the blamer found a missed_evidence bucket a tuner CAN
append a step for". It is NOT "safe to keep". The tune is a CANDIDATE. We run it, then hand the
candidate's before/after aggregate vectors to keep_or_revert.decide (the composite 4-gated-dim gate):
a recall-tune that REGRESSES verdicts_emitted / mitre_recall_micro / raises fabrications => REVERT,
and we snapshot-restore the playbook. A tune is kept ONLY on KEEP.

ALWAYS-LOG needs_other_fix
--------------------------
If the WORST failure is not missed_evidence (verdict_absent / mitre_gap / fabrication / ...), a tuner
cannot fix it. We emit a loud, structured ``UNADDRESSED`` log line for every such worst-failure-kind,
whether or not a tune runs and regardless of the final KEEP/REVERT — so a verdict gap is never
silently swallowed by a recall tune.

Flat sibling imports (scoring/ has no __init__): import composite/keep_or_revert/score_ledger directly.
The blamer is reached by SUBPROCESS, never imported (so its logic can never be duplicated here).
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from typing import Any, Callable, Optional

import keep_or_revert  # flat sibling import (frozen decider + revert executor)
import score_ledger    # flat sibling import (frozen hash-chained ledger)

__all__ = ["diagnose_and_route", "run_blame_subprocess", "UNADDRESSED_PREFIX"]

#: Loud, grep-able prefix for the "a tuner cannot fix this worst failure" log line.
UNADDRESSED_PREFIX = "UNADDRESSED worst_failure"

# Repo-relative locations the blamer's emitted tune_command references (it builds
# ["python3", "playbooks/tune_playbook.py", ...] with REPO-RELATIVE paths), so any
# subprocess that runs the blamer or the tune_command must use repo_root as cwd.
_BLAME_REL = os.path.join("playbooks", "blame_playbook.py")


# =============================================================================
# Blame — SUBPROCESS the frozen blamer (never import / reimplement its logic).
# =============================================================================
def run_blame_subprocess(
    *,
    repo_root: str,
    baseline_eval_score: str,
    baseline_ioc_score: Optional[str],
    playbook_path: str,
    case_id: str,
    blame_out: str,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> dict:
    """Run ``playbooks/blame_playbook.py`` as a child process and parse its blame.json.

    REUSE, not reimplement: the worst-failure ranking, severity policy, routing and the
    anti-hallucination tripwire all live in the blamer; we only invoke it and read its
    output. ``runner`` is injectable purely so tests can assert the exact argv without a
    real fork; production uses subprocess.run.
    """
    cmd = [
        sys.executable, _BLAME_REL,
        "--score", baseline_eval_score,
        "--playbook", playbook_path,
        "--case-id", case_id,
        "--out", blame_out,
    ]
    if baseline_ioc_score:
        cmd += ["--ioc-score", baseline_ioc_score]
    proc = runner(cmd, cwd=repo_root, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"blame_playbook.py failed (exit {proc.returncode}): "
            f"{(proc.stderr or '').strip()[:600]}"
        )
    # The blamer exits 0 WITHOUT writing blame.json when there are NO failures to blame
    # ("nothing to blame: ..."). Treat that as an empty, no-failure blame (nothing to tune).
    if not os.path.isfile(blame_out):
        return {"case_id": case_id, "failure_count": 0,
                "worst_failure": None, "tune_command": None,
                "ranked_failures": [], "needs_other_fix": []}
    with open(blame_out, "r", encoding="utf-8") as fh:
        return json.load(fh)


# =============================================================================
# Small helpers (pure; no blamer/tuner logic).
# =============================================================================
def _load_json(path: str, label: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        raise RuntimeError(f"{label} not found: {path}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} is not valid JSON ({exc}): {path}")


def _aggregate_of(ioc_score: dict, label: str) -> dict:
    """Pull the 16-key ``aggregate`` object straight out of a scoring/scorer.py CLI JSON.

    The scorer already produced this vector; we lift it verbatim (no recompute). A bare
    single-aggregate dict (no wrapper) is accepted too, so a caller may pass either shape.
    """
    if not isinstance(ioc_score, dict):
        raise RuntimeError(f"{label} must be a JSON object")
    agg = ioc_score.get("aggregate")
    if isinstance(agg, dict):
        return agg
    # Already a bare aggregate? (has the gated keys but no 'cases'/'aggregate' wrapper)
    if "findable_recall_micro" in ioc_score or "verdicts_emitted" in ioc_score:
        return ioc_score
    raise RuntimeError(f"{label} has no 'aggregate' object (scorer CLI emits one)")


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _emit_unaddressed(worst: dict) -> str:
    """Build + print (stderr) the loud structured UNADDRESSED line; return it for tests."""
    line = (
        f"{UNADDRESSED_PREFIX} kind={worst.get('kind')} "
        f"route={worst.get('route')} remediation={worst.get('remediation')!r} "
        f"— NOT fixed by this tune lap"
    )
    print(line, file=sys.stderr)
    return line


# =============================================================================
# The lap: diagnose -> route -> (guarded) tune -> keep/revert -> ledger.
# =============================================================================
def diagnose_and_route(
    *,
    baseline_eval_score: str,
    baseline_ioc_score: Optional[str],
    playbook_path: str,
    case_id: str,
    post_ioc_score: str,
    ledger_path: str,
    versions_dir: Optional[str] = None,
    repo_root: Optional[str] = None,
    lap: int = 1,
    usage: Optional[dict] = None,
    blame_out: Optional[str] = None,
    eps_recall: float = 0.0,
    blame_runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    tune_runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
) -> dict:
    """Diagnose with the blamer, route the worst failure, and (if tune-actionable) run a
    GUARDED candidate tune that is kept only when keep_or_revert.decide says KEEP; record
    the lap in the hash-chained ledger.

    All scores are FIXTURE paths (no live run). REUSES the frozen blamer (subprocess),
    tuner (subprocess), decider and ledger (direct calls). ``tune_runner`` defaults to
    subprocess.run (production runs the real ``tune_command``); tests inject a deterministic
    runner so the lap has no live ``claude -p`` dependency.

    Returns::

        {case_id, worst_failure_kind, tuned: bool, decision: KEEP|REVERT|None,
         reason, unaddressed: [kinds], ledger_row_appended: bool}
    """
    repo_root = repo_root or os.getcwd()
    if tune_runner is None:
        tune_runner = subprocess.run

    # Work area for blame.json (the blamer always writes one when there is a failure).
    cleanup_dir = None
    if blame_out is None:
        cleanup_dir = tempfile.mkdtemp(prefix="blame_router_")
        blame_out = os.path.join(cleanup_dir, "blame.json")

    try:
        # ---- 1. BLAME (subprocess the frozen blamer) -------------------------------------
        blame = run_blame_subprocess(
            repo_root=repo_root,
            baseline_eval_score=baseline_eval_score,
            baseline_ioc_score=baseline_ioc_score,
            playbook_path=playbook_path,
            case_id=case_id,
            blame_out=blame_out,
            runner=blame_runner,
        )

        worst = blame.get("worst_failure") or {}
        worst_kind = worst.get("kind")
        tune_command = blame.get("tune_command")  # list | None

        result: dict[str, Any] = {
            "case_id": case_id,
            "worst_failure_kind": worst_kind,
            "tuned": False,
            "decision": None,
            "reason": None,
            "unaddressed": [],
            "ledger_row_appended": False,
        }

        # ---- 2. ALWAYS log needs_other_fix when the WORST failure is not tune-fixable -----
        # This fires whether or not a tune runs, and regardless of the final KEEP/REVERT.
        if worst and worst_kind != "missed_evidence":
            _emit_unaddressed(worst)
            result["unaddressed"].append(worst_kind)

        # ---- 3. GUARDED tune — only if the blamer says a tuner CAN act ---------------------
        if not tune_command:
            # No actionable tune (no missed_evidence bucket, or not contract-shaped). The
            # ledger records keep/revert of EDITS; with no edit there is no row to append.
            # blame.json is already on disk (kept if the caller supplied blame_out).
            result["tuned"] = False
            return result

        playbook_abs = os.path.abspath(playbook_path)

        # 3a. Restorable snapshot. tune_playbook writes versions/<cat>/v<old>.md itself; we
        # also capture the pre-edit bytes so a REVERT can be byte-verified for safety.
        pre_edit_bytes = _read_bytes(playbook_abs)

        # 3b. Execute the blamer's tune_command (runs tune_playbook.py: append + version bump).
        tune_proc = tune_runner(tune_command, cwd=repo_root, capture_output=True, text=True)
        if getattr(tune_proc, "returncode", 0) != 0:
            raise RuntimeError(
                f"tune_command failed (exit {tune_proc.returncode}): "
                f"{(getattr(tune_proc, 'stderr', '') or '').strip()[:600]}"
            )
        result["tuned"] = True

        # 3c. Before/after candidate vectors — lifted verbatim from the scorer CLI JSON.
        baseline_ioc = _load_json(baseline_ioc_score, "baseline ioc-score") if baseline_ioc_score else {}
        post_ioc = _load_json(post_ioc_score, "post ioc-score")
        baseline_agg = _aggregate_of(baseline_ioc, "baseline ioc-score")
        post_agg = _aggregate_of(post_ioc, "post ioc-score")

        # 3d. THE GUARD: keep_or_revert.decide (composite 4-gated-dim gate). A tune_command is
        # never trusted as "safe"; the candidate is kept ONLY on KEEP.
        decision, reason, _deltas = keep_or_revert.decide(
            baseline_agg, post_agg, eps_recall=eps_recall
        )
        result["decision"] = decision
        result["reason"] = reason

        blamed_failure = worst_kind or "(none)"
        # Provenance shas of the EDIT under test: bytes-of-playbook before vs after.
        sha_before = hashlib.sha256(pre_edit_bytes).hexdigest()
        post_edit_bytes = _read_bytes(playbook_abs)
        sha_after = hashlib.sha256(post_edit_bytes).hexdigest()

        if decision == "REVERT":
            # 3e-REVERT. Snapshot-restore FIRST (hard-fail, never half-revert), THEN record.
            keep_or_revert.revert(playbook_abs, versions_dir=versions_dir)
            # After restore the EDIT is undone; record the row with decision=REVERT so the
            # ledger shows the candidate was tried and rejected.
            if os.path.isfile(ledger_path):
                score_ledger.assert_chain_ok(ledger_path)
            score_ledger.append_lap(
                ledger_path, lap=lap, case=case_id, blamed_failure=blamed_failure,
                sha_before=sha_before, sha_after=sha_after,
                score_vector=post_agg, baseline_vector=baseline_agg,
                decision="REVERT", reason=reason, usage=usage,
            )
            score_ledger.assert_chain_ok(ledger_path)
            result["ledger_row_appended"] = True
        else:
            # 3e-KEEP. Integrity gate -> record -> re-verify (decide-then-record).
            if os.path.isfile(ledger_path):
                score_ledger.assert_chain_ok(ledger_path)
            score_ledger.append_lap(
                ledger_path, lap=lap, case=case_id, blamed_failure=blamed_failure,
                sha_before=sha_before, sha_after=sha_after,
                score_vector=post_agg, baseline_vector=baseline_agg,
                decision="KEEP", reason=reason, usage=usage,
            )
            score_ledger.assert_chain_ok(ledger_path)
            result["ledger_row_appended"] = True

        return result
    finally:
        if cleanup_dir is not None:
            # Keep blame.json only when the caller asked for a specific path; otherwise clean.
            try:
                if os.path.isfile(blame_out):
                    os.remove(blame_out)
                os.rmdir(cleanup_dir)
            except OSError:
                pass

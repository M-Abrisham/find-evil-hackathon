#!/usr/bin/env python3
"""run_loop.py — MVP scripted single-lap orchestrator (roadmap 8.6, freeze-day MVP).

Closes the propose/dispose chain on the CONTRACT plane, REUSING the verified stack
(scorer + composite + keep_or_revert + score_ledger) with ZERO reimplementation:

  score baseline report -> score candidate report -> keep_or_revert.decide()
  [PER-LAP CANDIDATE] -> (optional snapshot-restore revert) -> assert_chain_ok
  -> score_ledger.append_lap -> verify_chain   ==>  ONE hash-chained ledger row.

SCOPE (MVP, honest): this is a SCRIPTED lap over two report artifacts (e.g. a real
before/after contract change), NOT a live run->blame->tune->re-run lap. The live
chain is blocked by the two-scoring-planes gap (run_blind emits findings.json while
the keep/revert reward grades a markdown report); bridging that is the documented
NEXT step (needs the spine consolidated: eval/run_blind + parity + playbooks/blame
co-resident). A KEEP here is a PER-LAP CANDIDATE and MUST be confirmed by the RCDP
statistical N-round (Wilson + two-proportion) gate before being acted on; a REVERT
may be acted on per-lap.

Deterministic scorer = SOLE reward; no LLM; records-then-never-decides via the ledger.
Flat sibling imports (scoring/ has no __init__): import scorer, keep_or_revert, score_ledger.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from typing import Any, Optional

import scorer
import keep_or_revert
import score_ledger

__all__ = ["score_report_agg", "run_lap", "sha256_file"]


def sha256_file(path: Optional[str]) -> str:
    """sha256 of a file (artifact provenance for the ledger row); "" if absent."""
    if not path or not os.path.isfile(path):
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def score_report_agg(case_id: str, gt_path: str, input_path: str, report_path: str) -> dict:
    """Score ONE markdown report into a 16-key aggregate (reuses scorer; no reimpl)."""
    cr = scorer.score_case_from_files(case_id, gt_path, input_path, report_path)
    return scorer.aggregate([cr])


def run_lap(baseline_agg: dict, post_agg: dict, *, ledger_path: str, case: str,
            lap: int = 1, blamed_failure: str = "(scripted report A/B)",
            sha_before: str = "", sha_after: str = "", usage: Optional[dict] = None,
            eps_recall: float = 0.0, apply_revert: bool = False,
            revert_playbook: Optional[str] = None,
            versions_dir: Optional[str] = None) -> dict:
    """DECIDE (per-lap candidate) -> optional revert -> RECORD -> verify. Reuses the stack.

    The deterministic decision comes ONLY from keep_or_revert.decide (composite gate);
    this function never grades and never recomputes scores -- it records what decide()
    returned and what scorer.aggregate() produced.
    """
    decision, reason, deltas = keep_or_revert.decide(baseline_agg, post_agg, eps_recall=eps_recall)

    reverted = False
    if decision == "REVERT" and apply_revert and revert_playbook:
        keep_or_revert.revert(revert_playbook, versions_dir=versions_dir)  # snapshot-restore; hard-fails loud
        reverted = True

    # RECORD (DECIDE-then-RECORD). Integrity gate FIRST if the ledger already exists.
    if os.path.isfile(ledger_path):
        score_ledger.assert_chain_ok(ledger_path)
    row = score_ledger.append_lap(
        ledger_path, lap=lap, case=case, blamed_failure=blamed_failure,
        sha_before=sha_before, sha_after=sha_after,
        score_vector=post_agg, baseline_vector=baseline_agg,
        decision=decision, reason=reason, usage=usage,
    )
    # Re-verify the whole chain after the append (separate integrity gate; render does NOT verify).
    score_ledger.assert_chain_ok(ledger_path)
    return {"decision": decision, "reason": reason, "deltas": deltas,
            "reverted": reverted, "ledger_row": row}


_CANDIDATE_NOTE = ("NOTE: a KEEP is a PER-LAP CANDIDATE (unconfirmed). Route it to the RCDP "
                   "statistical N-round (Wilson + two-proportion) confirmer before acting; "
                   "a REVERT may be acted on per-lap.")


def _blame_main(argv: Optional[list] = None) -> int:
    """ADDITIVE `run_loop.py --blame ...` branch (roadmap 8.7 wiring).

    Parses the FIXTURE score/playbook paths and delegates to
    blame_router.diagnose_and_route, which subprocesses the frozen blamer + tuner and
    reuses keep_or_revert + score_ledger. No live agent run (every score is a fixture).
    """
    import blame_router  # lazy import: only the --blame path pays for it
    bp = argparse.ArgumentParser(
        prog="run_loop.py --blame",
        description="diagnose (blamer) -> route -> guarded tune -> keep/revert -> ledger, "
                    "over FIXTURE scores (no live run).")
    bp.add_argument("--baseline-eval-score", required=True,
                    help="eval/score.py JSON (missed_evidence buckets)")
    bp.add_argument("--baseline-ioc-score", default=None,
                    help="scoring/scorer.py CLI JSON ({cases,aggregate}) — baseline 'before' vector")
    bp.add_argument("--post-ioc-score", required=True,
                    help="scoring/scorer.py CLI JSON — candidate 'after' vector (fixture; no re-run)")
    bp.add_argument("--playbook", required=True, help="contract-shaped playbook .md to blame + tune")
    bp.add_argument("--case-id", required=True)
    bp.add_argument("--ledger", required=True)
    bp.add_argument("--versions-dir", default=None,
                    help="override <playbook_dir>/versions for the snapshot revert")
    bp.add_argument("--repo-root", default=None,
                    help="cwd for the blamer/tuner subprocesses (default: this repo root)")
    bp.add_argument("--lap", type=int, default=1)
    bp.add_argument("--blame-out", default=None, help="where to keep blame.json (default: temp)")
    bp.add_argument("--eps-recall", type=float, default=0.0)
    a = bp.parse_args(argv)
    if a.eps_recall < 0:
        print("error: --eps-recall must be >= 0", file=sys.stderr)
        return 2

    repo_root = a.repo_root or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = blame_router.diagnose_and_route(
        baseline_eval_score=a.baseline_eval_score,
        baseline_ioc_score=a.baseline_ioc_score,
        post_ioc_score=a.post_ioc_score,
        playbook_path=a.playbook,
        case_id=a.case_id,
        ledger_path=a.ledger,
        versions_dir=a.versions_dir,
        repo_root=repo_root,
        lap=a.lap,
        blame_out=a.blame_out,
        eps_recall=a.eps_recall,
    )
    print(json.dumps(out, indent=2))
    print(_CANDIDATE_NOTE, file=sys.stderr)
    # exit 0 unless an actionable tune was REVERTED (a rejected candidate is a non-zero signal).
    return 1 if out.get("decision") == "REVERT" else 0


def main(argv: Optional[list] = None) -> int:
    # ADDITIVE: a "--blame" first-arg routes to the blamer-wired diagnose->route->
    # keep/revert->ledger lap (blame_router). Everything below is unchanged.
    _av = sys.argv[1:] if argv is None else list(argv)
    if _av and _av[0] == "--blame":
        return _blame_main(_av[1:])
    p = argparse.ArgumentParser(
        description="MVP scripted single-lap orchestrator: score baseline+candidate report -> "
                    "decide (candidate) -> record one hash-chained ledger row -> verify.")
    p.add_argument("--case", required=True)
    p.add_argument("--gt", required=True, help="ground_truth/<case>.json")
    p.add_argument("--case-input", required=True, help="case_inputs/caseN.json")
    p.add_argument("--baseline-report", required=True)
    p.add_argument("--candidate-report", required=True)
    p.add_argument("--ledger", required=True)
    p.add_argument("--lap", type=int, default=1)
    p.add_argument("--blamed-failure", default="(scripted report A/B)")
    p.add_argument("--eps-recall", type=float, default=0.0,
                   help="float-recall tolerance, must be >= 0 (default 0.0)")
    p.add_argument("--apply", action="store_true",
                   help="on REVERT, snapshot-restore the playbook (needs --revert-playbook)")
    p.add_argument("--revert-playbook", default=None)
    p.add_argument("--versions-dir", default=None)
    a = p.parse_args(argv)
    if a.eps_recall < 0:
        print("error: --eps-recall must be >= 0", file=sys.stderr)
        return 2

    baseline_agg = score_report_agg(a.case, a.gt, a.case_input, a.baseline_report)
    post_agg = score_report_agg(a.case, a.gt, a.case_input, a.candidate_report)
    out = run_lap(
        baseline_agg, post_agg, ledger_path=a.ledger, case=a.case, lap=a.lap,
        blamed_failure=a.blamed_failure,
        sha_before=sha256_file(a.baseline_report), sha_after=sha256_file(a.candidate_report),
        eps_recall=a.eps_recall, apply_revert=a.apply, revert_playbook=a.revert_playbook,
        versions_dir=a.versions_dir,
    )
    print(json.dumps({"decision": out["decision"], "reason": out["reason"],
                      "reverted": out["reverted"]}, indent=2))
    print(score_ledger.render_markdown(a.ledger))
    print(_CANDIDATE_NOTE, file=sys.stderr)
    return 0 if out["decision"] == "KEEP" else 1


if __name__ == "__main__":
    raise SystemExit(main())

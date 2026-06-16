#!/usr/bin/env python3
"""Regression suite + guard-case registry  (Rule-Change Diagnosis Protocol, Stage 5 / section-7 tool #4).

OPERATOR-LAYER tool. Runs on josh-pc over the per-round score JSONs that the
operator emits AFTER the sealed run_batch export (it NEVER runs inside the jail
and NEVER reads sealed-orchestrator state). Built + unit-tested on the sift-vm
against SYNTHETIC fixtures only — no real cases / keys / ground_truth on the VM.

WHAT IT IS
----------
1. A guard-case REGISTRY (``guard_cases.json``): a frozen mapping
       shipped-rule  ->  the guard case that demonstrates the value the rule
                         protects   +   the exact PASS SIGNAL on that case.
   So when a rule is ever REMOVE/EDIT'd (Stage 3), the runner automatically
   re-tests the case the rule was written to fix (Stage 5.1 "every rule carries
   its own regression witness").

2. A RUNNER that re-scores the guard set from REAL scorer output and asserts
   MONOTONIC non-regression (Stage 5.2/5.3): a guard case that PASSED in the
   frozen baseline ledger and now FAILS is a REGRESSION and BLOCKS KEEP. The
   gate is "ZERO observed regressions" — NOT "CI excludes 0" — because the
   held-out inventory is tiny (spec 5.2).

WHAT IT CONSUMES  (real scorer shapes — see eval/score.py, contract-build/scoring/{scorer,presence_scorer}.py)
------------------------------------------------------------------------------
Each guard case names a ``signal`` whose ``source`` selects the scorer whose
per-round JSON it reads, mirroring the export BASE convention
``<case>_<arm>_round-<N>.<source>.json``:

  source="scorer"   -> contract-build/scoring/scorer.py CaseResult.to_dict():
                       {case_id, findable_recall, failures:[{type,value}],
                        fabrications:[...], fabrication_count, verdict, verdict_expected,
                        mitre_present:{code:bool}, ...}
  source="score"    -> eval/score.py build_score() top-level dict:
                       {case_id, classification:{category_match,...},
                        evidence:{per_bucket:{<b>:{recall,...}}, false_positive_findings:[...]},
                        hallucination:{unbacked_list:[{id,claim}], unbacked_findings, ...},
                        headline:{...}}
  source="presence" -> contract-build/scoring/presence_scorer.py PresenceResult.to_dict():
                       {report_id, passed, has_insufficient_evidence,
                        has_coverage_gaps_section, missing_fields:[...]}

A guard case may have a ``status``:
  AVAILABLE  — a real (or synthetic-test) score JSON exists; it is scored.
  PENDING    — the guard case has not been built/scored yet. It is NEVER
               invented: counted as PENDING, never PASS/FAIL, never a regression.

This file is stdlib-only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Callable


# =============================================================================
# Registry status + signal vocabulary
# =============================================================================
STATUS_AVAILABLE = "AVAILABLE"
STATUS_PENDING = "PENDING"

# Per-round score-file sources (which scorer emitted the JSON), and the file
# suffix the operator writes them under next to the export BASE.
SOURCE_SUFFIX = {
    "scorer": "scorer.json",      # contract-build/scoring/scorer.py "--- JSON ---" cases[i].to_dict()
    "score": "score.json",        # eval/score.py -o
    "presence": "presence.json",  # contract-build/scoring/presence_scorer.py to_dict()
}

# The verdict CLASS map, hand-mirrored from scorer.py:VERDICT_CLASSES /
# contract.yaml verdict.equivalence_classes. Used ONLY to interpret the
# diagnostic verdict_expected in a guard signal; the contract<->scorer drift
# check (tool #6) owns enforcing they stay in sync.
VERDICT_CLASSES: dict[str, set[str]] = {
    "malicious": {"MALICE", "MALICIOUS"},
    "non_malicious": {"NON_MALICE", "NONMALICE", "BENIGN"},
    "inconclusive": {"INCONCLUSIVE", "INDETERMINATE", "UNKNOWN"},
}


# =============================================================================
# FAIL/PASS predicates over the REAL scorer shapes
# -----------------------------------------------------------------------------
# Each predicate takes a parsed per-round score dict and returns True iff the
# guard PASSES (the protected value held). These are the frozen, auditable
# binary domain checks (spec Stage 1.3 / 5.2). A predicate MUST be defensive:
# a missing key => the round is not a clean PASS (returns False) so a silently
# schema-shifted score never masquerades as a pass.
# =============================================================================
def _sig_no_fabrication(d: dict) -> bool:
    """scorer.py: PASS iff zero fabricated/unbacked IOCs (fabrication_count == 0)."""
    return _get_int(d, "fabrication_count", default=None) == 0


def _sig_no_hallucination(d: dict) -> bool:
    """score.py: PASS iff hallucination.unbacked_list is empty (deterministic, judge-free)."""
    hall = d.get("hallucination")
    if not isinstance(hall, dict) or "unbacked_list" not in hall:
        return False
    ul = hall["unbacked_list"]
    return isinstance(ul, list) and len(ul) == 0


def _sig_ioc_not_in_failures(d: dict, ioc_value: str) -> bool:
    """scorer.py: PASS iff the named findable IOC value is NOT in failures[] (it was recalled)."""
    failures = d.get("failures")
    if not isinstance(failures, list):
        return False
    return not any(isinstance(f, dict) and f.get("value") == ioc_value for f in failures)


def _sig_verdict_class(d: dict, expected_class: str) -> bool:
    """scorer.py: PASS iff verdict=='found' (report verdict matched the expected class).

    NOTE (spec risk #5 — verdict-class collapse): scorer.py verdict_status returns
    "found" only when the report's class == the ground-truth class; it returns
    "not_emitted" for BOTH a missing verdict line AND a present-but-WRONG-class
    verdict. So this predicate cannot, by itself, distinguish "no verdict"
    (structural) from "wrong verdict" (reasoning) — both are a regression here,
    which is the conservative behavior for a guard. ``expected_class`` is recorded
    for documentation/audit; the scorer already encodes it via verdict_expected.
    """
    if expected_class not in VERDICT_CLASSES:
        return False
    return d.get("verdict") == "found"


def _sig_presence_passed(d: dict) -> bool:
    """presence_scorer.py: PASS iff passed==True (INSUFFICIENT_EVIDENCE token + Coverage-Gaps section)."""
    return d.get("passed") is True


def _sig_bucket_recall_full(d: dict, bucket: str) -> bool:
    """score.py: PASS iff evidence.per_bucket[bucket].recall == 1.0 (nothing missed in that bucket)."""
    ev = d.get("evidence")
    if not isinstance(ev, dict):
        return False
    per_bucket = ev.get("per_bucket")
    if not isinstance(per_bucket, dict) or bucket not in per_bucket:
        return False
    b = per_bucket[bucket]
    return isinstance(b, dict) and b.get("recall") == 1.0


def _get_int(d: dict, key: str, default: Any) -> Any:
    v = d.get(key, default)
    return v if isinstance(v, int) else default


# Predicate dispatch by signal "check" name. A signal in the registry is
# {check, source, [args]}; the runner binds args positionally after the dict.
SIGNAL_CHECKS: dict[str, Callable[..., bool]] = {
    "no_fabrication": _sig_no_fabrication,
    "no_hallucination": _sig_no_hallucination,
    "ioc_not_in_failures": _sig_ioc_not_in_failures,
    "verdict_class": _sig_verdict_class,
    "presence_passed": _sig_presence_passed,
    "bucket_recall_full": _sig_bucket_recall_full,
}


# =============================================================================
# Registry model
# =============================================================================
@dataclass
class GuardCase:
    rule_id: str                      # the shipped rule this guard witnesses (e.g. "G31")
    rule_summary: str                 # one-line description of the value the rule protects
    case_id: str                      # the guard case id (export BASE <case_id>)
    status: str                       # AVAILABLE | PENDING
    signal: dict                      # {check, source, args?}  the frozen PASS predicate
    note: str = ""

    def validate(self) -> list[str]:
        errs: list[str] = []
        if self.status not in (STATUS_AVAILABLE, STATUS_PENDING):
            errs.append(f"{self.rule_id}: bad status {self.status!r}")
        chk = self.signal.get("check")
        if chk not in SIGNAL_CHECKS:
            errs.append(f"{self.rule_id}: unknown signal check {chk!r}")
        src = self.signal.get("source")
        if src not in SOURCE_SUFFIX:
            errs.append(f"{self.rule_id}: unknown signal source {src!r}")
        return errs


@dataclass
class GuardOutcome:
    rule_id: str
    case_id: str
    status: str                       # AVAILABLE | PENDING
    result: str                       # PASS | FAIL | PENDING | MISSING
    rounds_total: int = 0
    rounds_passed: int = 0
    detail: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class SuiteRun:
    arm: str
    outcomes: list[GuardOutcome] = field(default_factory=list)
    regressions: list[dict] = field(default_factory=list)   # baseline PASS -> now not-PASS
    new_passes: list[str] = field(default_factory=list)
    blocked_keep: bool = False                              # any regression => True (Stage 5.2 gate)
    pending: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "arm": self.arm,
            "outcomes": [o.to_dict() for o in self.outcomes],
            "regressions": self.regressions,
            "new_passes": self.new_passes,
            "pending": self.pending,
            "blocked_keep": self.blocked_keep,
        }


# =============================================================================
# Registry loading
# =============================================================================
def load_registry(path: str) -> list[GuardCase]:
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    guards = [
        GuardCase(
            rule_id=g["rule_id"],
            rule_summary=g.get("rule_summary", ""),
            case_id=g["case_id"],
            status=g["status"],
            signal=g["signal"],
            note=g.get("note", ""),
        )
        for g in raw["guard_cases"]
    ]
    errs: list[str] = []
    # Each shipped rule must map to exactly one guard case (Stage 5.1).
    seen: set[str] = set()
    for g in guards:
        errs.extend(g.validate())
        if g.rule_id in seen:
            errs.append(f"duplicate rule_id {g.rule_id!r} (one guard case per rule)")
        seen.add(g.rule_id)
    if errs:
        raise ValueError("invalid guard registry:\n  " + "\n  ".join(errs))
    return guards


# =============================================================================
# Score-file resolution (export BASE convention) + signal evaluation
# =============================================================================
def round_score_paths(score_dir: str, case_id: str, arm: str, source: str) -> list[str]:
    """All per-round score files for (case, arm, source), sorted by round N.

    Mirrors the operator score-file convention: <case>_<arm>_round-<N>.<suffix>.
    """
    suffix = SOURCE_SUFFIX[source]
    prefix = f"{case_id}_{arm}_round-"
    hits: list[tuple[int, str]] = []
    if not os.path.isdir(score_dir):
        return []
    for name in os.listdir(score_dir):
        if not name.startswith(prefix) or not name.endswith("." + suffix):
            continue
        mid = name[len(prefix):-(len(suffix) + 1)]  # the "<N>" between round- and .suffix
        try:
            n = int(mid)
        except ValueError:
            continue
        hits.append((n, os.path.join(score_dir, name)))
    return [p for _, p in sorted(hits)]


def eval_signal(score: dict, signal: dict) -> bool:
    check = SIGNAL_CHECKS[signal["check"]]
    args = signal.get("args", [])
    return bool(check(score, *args))


def score_guard(guard: GuardCase, score_dir: str, arm: str) -> GuardOutcome:
    """Re-score one guard case across all its per-round files for the given arm.

    A guard PASSES iff it has >=1 round AND EVERY round satisfies the pass signal.
    A single failing round on a monotonic guard is a FAIL (we do not average a
    guard — Stage 5.2 wants zero observed regressions, not a rate).
    """
    if guard.status == STATUS_PENDING:
        return GuardOutcome(guard.rule_id, guard.case_id, STATUS_PENDING, "PENDING",
                            detail="guard case not yet built/scored")
    paths = round_score_paths(score_dir, guard.case_id, arm, guard.signal["source"])
    if not paths:
        return GuardOutcome(guard.rule_id, guard.case_id, STATUS_AVAILABLE, "MISSING",
                            detail=f"no {guard.signal['source']} score files for "
                                   f"{guard.case_id}_{arm}_round-*")
    passed = 0
    failing_rounds: list[str] = []
    for p in paths:
        with open(p, encoding="utf-8") as fh:
            score = json.load(fh)
        if eval_signal(score, guard.signal):
            passed += 1
        else:
            failing_rounds.append(os.path.basename(p))
    total = len(paths)
    result = "PASS" if passed == total else "FAIL"
    detail = "" if result == "PASS" else f"failing rounds: {', '.join(failing_rounds)}"
    return GuardOutcome(guard.rule_id, guard.case_id, STATUS_AVAILABLE, result,
                        rounds_total=total, rounds_passed=passed, detail=detail)


# =============================================================================
# Baseline ledger + monotonic non-regression
# =============================================================================
def load_baseline(path: str | None) -> dict[str, str]:
    """Baseline ledger: {rule_id: last-known result}. Absent/empty => no prior PASS."""
    if not path or not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return {k: v for k, v in data.get("results", {}).items()}


def run_suite(guards: list[GuardCase], score_dir: str, arm: str,
              baseline: dict[str, str]) -> SuiteRun:
    run = SuiteRun(arm=arm)
    for g in guards:
        outcome = score_guard(g, score_dir, arm)
        run.outcomes.append(outcome)
        if outcome.result == "PENDING":
            run.pending.append(g.rule_id)
            continue
        prior = baseline.get(g.rule_id)
        # MONOTONIC non-regression: a guard that PASSED in the baseline and is
        # now not PASS (FAIL or MISSING) is a regression => BLOCK KEEP.
        if prior == "PASS" and outcome.result != "PASS":
            run.regressions.append({
                "rule_id": g.rule_id,
                "case_id": g.case_id,
                "baseline": prior,
                "now": outcome.result,
                "detail": outcome.detail,
            })
        if prior != "PASS" and outcome.result == "PASS":
            run.new_passes.append(g.rule_id)
    run.blocked_keep = len(run.regressions) > 0
    return run


def results_ledger(run: SuiteRun) -> dict:
    """The new baseline ledger to freeze after a clean run (results per rule)."""
    return {"arm": run.arm,
            "results": {o.rule_id: o.result for o in run.outcomes}}


# =============================================================================
# Rendering
# =============================================================================
def render(run: SuiteRun) -> str:
    L: list[str] = []
    L.append(f"REGRESSION SUITE — guard-case monotonic non-regression  (arm={run.arm})")
    L.append("=" * 72)
    hdr = f"{'rule':<8}{'guard case':<28}{'result':<10}{'rounds':<10}"
    L.append(hdr)
    L.append("-" * 72)
    for o in run.outcomes:
        rounds = f"{o.rounds_passed}/{o.rounds_total}" if o.status == STATUS_AVAILABLE and o.result not in ("PENDING", "MISSING") else "-"
        L.append(f"{o.rule_id:<8}{o.case_id:<28}{o.result:<10}{rounds:<10}")
        if o.detail:
            L.append(f"        -> {o.detail}")
    L.append("-" * 72)
    if run.pending:
        L.append(f"PENDING (guard case not yet built — NOT scored): {', '.join(run.pending)}")
    if run.new_passes:
        L.append(f"NEW PASSES (vs baseline): {', '.join(run.new_passes)}")
    if run.regressions:
        L.append("")
        L.append("!! REGRESSIONS (baseline PASS -> now not-PASS) — BLOCKS KEEP:")
        for r in run.regressions:
            L.append(f"   {r['rule_id']} / {r['case_id']}: {r['baseline']} -> {r['now']}  {r['detail']}")
    L.append("")
    L.append(f"GATE: {'BLOCK KEEP (regressions observed)' if run.blocked_keep else 'CLEAN (zero observed regressions)'}")
    return "\n".join(L)


# =============================================================================
# CLI
# =============================================================================
def main(argv: list[str] | None = None) -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="Regression suite + guard-case registry runner.")
    ap.add_argument("--registry", default=os.path.join(here, "guard_cases.json"),
                    help="path to guard_cases.json (default: alongside this script)")
    ap.add_argument("--score-dir", required=True,
                    help="dir of per-round score JSONs (<case>_<arm>_round-N.<src>.json)")
    ap.add_argument("--arm", default="sift", help="arm to score (default: sift)")
    ap.add_argument("--baseline", default=None,
                    help="frozen baseline ledger JSON; a baseline-PASS now-FAIL is a regression")
    ap.add_argument("--json", action="store_true", help="emit JSON after the human render")
    ap.add_argument("--update-baseline", default=None,
                    help="write the new ledger here ONLY if the run is clean (no regressions)")
    args = ap.parse_args(argv)

    guards = load_registry(args.registry)
    baseline = load_baseline(args.baseline)
    run = run_suite(guards, args.score_dir, args.arm, baseline)

    print(render(run))
    if args.json:
        print("--- JSON ---")
        print(json.dumps(run.to_dict(), indent=2, sort_keys=True))

    if args.update_baseline and not run.blocked_keep:
        with open(args.update_baseline, "w", encoding="utf-8") as fh:
            json.dump(results_ledger(run), fh, indent=2, sort_keys=True)

    # Exit non-zero iff KEEP is blocked (a regression) — usable as a CI gate.
    return 1 if run.blocked_keep else 0


if __name__ == "__main__":
    sys.exit(main())

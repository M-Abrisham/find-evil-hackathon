#!/usr/bin/env python3
"""confirm_keep — candidate->confirmed-KEEP BRIDGE  (Rule-Change Diagnosis Protocol, Stage 4.3 confirm step).

WHAT IT IS
----------
The OPERATOR-side confirm step that turns run_loop.py's PER-LAP CANDIDATE (a rule
edit that LOOKED better in one campaign) into a STATISTICALLY-CONFIRMED verdict
before anything is frozen. It is the thin glue between the two existing diagnosis
gates — it owns NO statistics of its own:

  * the two-proportion 95% CI + SYSTEMATIC/GREY/STOCHASTIC classification come
    from ``aggregate_failures.py`` (Wilson / two_proportion_z / classify_vs_floor),
  * the zero-guard-regression gate comes from ``regression_suite.py``.

It MIRRORS the KEEP rule the ablation runner already encodes
(``ablation_runner.sh`` step 9 + README Stage 4):

    KEEP iff the target-metric improvement's two-proportion 95% CI EXCLUDES 0
    (in the IMPROVING direction) AND ``make regression`` shows ZERO guard-case
    regressions.

and ADDS the systematic-failure precondition the protocol requires (Stage 1.4):
the baseline failure being fixed must be a REAL systematic failure, not floor
noise — else there is nothing to "confirm fixing".

    CONFIRMED-KEEP  iff  (CI excludes 0, improving)  AND  (0 guard regressions)
                    AND  (baseline failure classified SYSTEMATIC, not STOCHASTIC).
    otherwise        ->  NOT-CONFIRMED   (CI straddles 0 / no improvement /
                                          INDETERMINATE / GREY / missing input)
                    or   REVERT          (a guard PASS->FAIL regression — a real
                                          protected value broke; the candidate is
                                          actively harmful and must be backed out).

BOUNDARIES (do NOT misread)
---------------------------
* The DETERMINISTIC scorer stays the SOLE reward. This tool reads scored
  per-round JSONs and RECORDS/CONFIRMS a decision; it computes no new score.
* This is ADVISORY / decision-support. It RECORDS the confirm verdict but the
  actual LEDGER APPEND (and the keep-or-revert action) stays run_loop.py's job.
  It is the OPERATOR-side confirm step and must NEVER be wired into the
  integrity-barred run_loop reward path.
* Be HONEST / conservative: ANY missing input, empty score-dir, or INDETERMINATE
  classification => NOT-CONFIRMED. It NEVER defaults to KEEP.

WIRING (export BASE convention, see eval/diagnosis/README.md)
------------------------------------------------------------
Reads the same per-round score JSONs the other diagnosis tools glob:
``<CASE>_<ARM>_round-<N>.{score,scorer,presence}.json``. The candidate's two
arms are, per aggregate_failures' own convention, ``--sift-arm`` (post / with
the candidate) vs ``--bare-arm`` (pre / baseline). The improvement is measured
as the candidate arm FAILING LESS than the baseline arm.

stdlib only. Imports aggregate_failures + regression_suite as SIBLINGS (the same
``import X`` style the other diagnosis tools use).
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# Sibling imports — match how the other diagnosis tools import each other
# (test_aggregate_failures: `import aggregate_failures as agg`;
#  test_regression_suite: `import regression_suite as rs`). No package prefix.
import aggregate_failures as agg
import regression_suite as rs


# Decision tokens.
CONFIRMED_KEEP = "CONFIRMED-KEEP"
NOT_CONFIRMED = "NOT-CONFIRMED"
REVERT = "REVERT"


def _improving_ci_excludes_zero(tp: dict) -> bool:
    """True iff the two-proportion difference 95% CI excludes 0 IN THE IMPROVING
    DIRECTION.

    ``tp`` is aggregate_failures.two_proportion_z(f1=candidate, n1, f2=baseline, n2)
    so diff = p_candidate - p_baseline over a FAIL predicate. A FALLING failure
    rate (the candidate fails LESS) is the improvement => diff < 0 and the whole
    CI below 0 (diff_ci_hi < 0). A rising rate (CI entirely above 0) is the
    candidate being WORSE — that is NOT an improvement and never a KEEP here.
    """
    if not tp.get("ci_excludes_zero"):
        return False
    hi = tp.get("diff_ci_hi")
    # Improving == candidate fails LESS == the whole difference CI is below zero.
    return hi is not None and hi < 0.0


def confirm(
    score_dir: str,
    predicate: str,
    *,
    candidate_arm: str = "sift",
    baseline_arm: str = "bare",
    floor_hi=None,
    floor_lo=None,
    act_line: float = 0.20,
    predicate_args: dict | None = None,
    registry: str | None = None,
    guard_score_dir: str | None = None,
    guard_baseline: str | None = None,
    case_filter: str | None = None,
) -> dict:
    """Compute the CONFIRMED-KEEP / NOT-CONFIRMED / REVERT decision.

    REUSES (never reimplements) the diagnosis stats:
      * aggregate_failures.discover_rounds / apply_predicate / aggregate_arm /
        classify_vs_floor / two_proportion_z
      * regression_suite.load_registry / load_baseline / run_suite
    """
    predicate_args = predicate_args or {}
    reasons: list[str] = []

    # ----------------------------------------------------------------------
    # Gate A — target-metric improvement (two-proportion 95% CI excludes 0,
    #          IMPROVING direction) + the baseline failure is SYSTEMATIC.
    # All math is aggregate_failures'. We only read its outputs.
    # ----------------------------------------------------------------------
    ci_excludes_zero = False
    classification = "INDETERMINATE"
    cross = None
    arm_summ: dict = {}

    records = agg.discover_rounds(score_dir, case_filter=case_filter)
    if not records:
        reasons.append(
            f"no per-round score files in {score_dir!r} "
            "(*_round-*.{score,scorer,presence}.json) -> conservative NOT-CONFIRMED")
        return _result(NOT_CONFIRMED, reasons, ci_excludes_zero, None,
                       classification, cross, arm_summ)

    agg.apply_predicate(records, predicate, **predicate_args)
    by_arm: dict[str, list] = {}
    for r in records:
        by_arm.setdefault(r.arm, []).append(r)
    arms = {a: agg.aggregate_arm(a, rs_) for a, rs_ in by_arm.items()}

    cand = arms.get(candidate_arm)
    base = arms.get(baseline_arm)
    for label, ar, name in (("candidate", cand, candidate_arm),
                            ("baseline", base, baseline_arm)):
        if ar is None:
            reasons.append(f"{label} arm {name!r} absent from score-dir -> NOT-CONFIRMED")
    if cand is None or base is None:
        return _result(NOT_CONFIRMED, reasons, ci_excludes_zero, None,
                       classification, cross, arm_summ)

    arm_summ = {
        candidate_arm: {"f": cand.f, "n_valid": cand.n_valid, "p_hat": cand.p_hat},
        baseline_arm: {"f": base.f, "n_valid": base.n_valid, "p_hat": base.p_hat},
    }

    if not cand.n_valid or not base.n_valid:
        reasons.append(
            f"empty denominator (candidate n={cand.n_valid}, baseline n={base.n_valid}) "
            "-> NOT-CONFIRMED")
        return _result(NOT_CONFIRMED, reasons, ci_excludes_zero, None,
                       classification, cross, arm_summ)

    # Two-proportion: candidate vs baseline FAIL rate (aggregate_failures' own test).
    cross = agg.two_proportion_z(cand.f, cand.n_valid, base.f, base.n_valid)
    ci_excludes_zero = _improving_ci_excludes_zero(cross)
    if ci_excludes_zero:
        reasons.append(
            f"improvement CONFIRMED: failure rate {base.p_hat:.3f}->{cand.p_hat:.3f}, "
            f"diff 95% CI [{cross['diff_ci_lo']:.3f},{cross['diff_ci_hi']:.3f}] excludes 0 (falling)")
    elif cross.get("ci_excludes_zero") and (cross.get("diff_ci_lo") or 0) > 0:
        reasons.append(
            f"candidate is WORSE: failure rate {base.p_hat:.3f}->{cand.p_hat:.3f}, "
            f"diff CI [{cross['diff_ci_lo']:.3f},{cross['diff_ci_hi']:.3f}] is ABOVE 0 -> NOT an improvement")
    else:
        reasons.append(
            "improvement NOT confirmed: two-proportion 95% CI straddles 0 "
            "(rate change is within noise) -> NOT-CONFIRMED")

    # SYSTEMATIC precondition: the BASELINE failure being fixed must be a real
    # systematic failure (not floor noise / not GREY / not INDETERMINATE).
    cls = agg.classify_vs_floor(base, floor_hi, floor_lo, act_line)
    classification = cls["label"]
    if classification == "SYSTEMATIC":
        reasons.append(f"baseline failure SYSTEMATIC: {cls['rationale']}")
    else:
        reasons.append(
            f"baseline failure NOT confirmed SYSTEMATIC (label={classification}): {cls['rationale']}")

    # ----------------------------------------------------------------------
    # Gate B — zero guard-case regressions (regression_suite owns the gate).
    # A guard PASS->FAIL is a REVERT: a protected value broke. This OVERRIDES
    # Gate A (mirror ablation_runner: the regression suite is a hard KEEP block).
    # ----------------------------------------------------------------------
    guard_regressions: int | None = None
    if registry is None:
        # Default to the registry shipped alongside regression_suite.py.
        here = os.path.dirname(os.path.abspath(rs.__file__))
        registry = os.path.join(here, "guard_cases.json")
    gdir = guard_score_dir or score_dir
    try:
        guards = rs.load_registry(registry)
        gbase = rs.load_baseline(guard_baseline)
        suite = rs.run_suite(guards, gdir, candidate_arm, gbase)
        guard_regressions = len(suite.regressions)
        if suite.blocked_keep:
            reasons.append(
                f"GUARD REGRESSION(S): {guard_regressions} guard case(s) went PASS->not-PASS "
                f"({', '.join(r['rule_id'] for r in suite.regressions)}) -> REVERT (hard block)")
        elif suite.pending and not any(o.result == "PASS" for o in suite.outcomes):
            reasons.append(
                "guard suite produced NO scored PASS (all PENDING/MISSING) -> "
                "cannot assert non-regression -> NOT-CONFIRMED")
        else:
            reasons.append("guard non-regression CLEAN (zero observed regressions)")
    except (OSError, ValueError, KeyError) as e:
        reasons.append(f"guard suite could not run ({e}) -> conservative NOT-CONFIRMED")

    # ----------------------------------------------------------------------
    # Combine. A guard regression is a REVERT and OVERRIDES everything.
    # Otherwise CONFIRMED-KEEP needs ALL THREE: improving CI, SYSTEMATIC,
    # zero guard regressions (and a guard gate that actually ran).
    # ----------------------------------------------------------------------
    if guard_regressions is not None and guard_regressions > 0:
        decision = REVERT
    elif (ci_excludes_zero
          and classification == "SYSTEMATIC"
          and guard_regressions == 0):
        decision = CONFIRMED_KEEP
    else:
        decision = NOT_CONFIRMED

    return _result(decision, reasons, ci_excludes_zero, guard_regressions,
                   classification, cross, arm_summ)


def _result(decision, reasons, ci_excludes_zero, guard_regressions,
            classification, cross, arm_summ) -> dict:
    return {
        "tool": "confirm_keep",
        "schema_version": 1,
        "decision": decision,
        "reasons": reasons,
        "ci_excludes_zero": ci_excludes_zero,
        "guard_regressions": guard_regressions,
        "classification": classification,
        "two_proportion": cross,
        "arms": arm_summ,
        "note": "ADVISORY confirm step. The deterministic scorer is the sole reward; "
                "this RECORDS/CONFIRMS but the ledger append + keep/revert action "
                "stay run_loop.py's job. Never wire into the integrity-barred reward.",
    }


# =============================================================================
# Render + CLI.
# =============================================================================
def render_human(res: dict) -> str:
    L = []
    L.append("=" * 78)
    L.append("CONFIRM-KEEP  (Rule-Change Diagnosis Protocol, Stage 4.3 — ADVISORY)")
    L.append("=" * 78)
    L.append(f"DECISION            : {res['decision']}")
    L.append(f"ci_excludes_zero    : {res['ci_excludes_zero']}  (improving direction)")
    L.append(f"guard_regressions   : {res['guard_regressions']}")
    L.append(f"classification      : {res['classification']}")
    tp = res.get("two_proportion")
    if tp and tp.get("diff") is not None:
        L.append(f"two-proportion diff : {tp['diff']*100:.1f}pp  "
                 f"95% CI [{(tp['diff_ci_lo'] or 0)*100:.1f}pp, {(tp['diff_ci_hi'] or 0)*100:.1f}pp]")
    L.append("")
    L.append("reasons:")
    for r in res["reasons"]:
        L.append(f"  - {r}")
    L.append("")
    L.append(f"note: {res['note']}")
    L.append("=" * 78)
    return "\n".join(L)


def _collect_predicate_args(args) -> dict:
    pkw = {}
    if args.ioc_value is not None:
        pkw["ioc_value"] = args.ioc_value
    if args.bucket is not None:
        pkw["bucket"] = args.bucket
    if args.threshold is not None:
        pkw["threshold"] = args.threshold
    return pkw


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="confirm_keep: candidate->confirmed-KEEP bridge. CONFIRMED-KEEP iff the "
                    "target-improvement two-proportion 95% CI excludes 0 (improving) AND zero "
                    "guard regressions AND the baseline failure is SYSTEMATIC. Reuses "
                    "aggregate_failures + regression_suite; no stats reimplemented.")
    # Reuse aggregate_failures' arg names/conventions.
    ap.add_argument("--score-dir", required=True,
                    help="dir of the candidate's per-round score JSONs "
                         "(<CASE>_<ARM>_round-N.{score,scorer,presence}.json)")
    ap.add_argument("--case", default=None, help="restrict to one case_id")
    ap.add_argument("--predicate", required=True, choices=sorted(agg.PREDICATES.keys()),
                    help="the FROZEN target FAIL predicate (must be an aggregate_failures predicate)")
    ap.add_argument("--ioc-value", default=None, help="for predicate 'specific_ioc'")
    ap.add_argument("--bucket", default=None, help="for predicate 'bucket_recall'")
    ap.add_argument("--threshold", type=float, default=None,
                    help="for predicate 'findable_recall' (default 1.0)")
    ap.add_argument("--floor-hi", type=float, default=None,
                    help="empirical noise-floor Wilson UPPER bound (passed to classify_vs_floor; "
                         "omit => classification INDETERMINATE => NOT-CONFIRMED)")
    ap.add_argument("--floor-lo", type=float, default=None)
    ap.add_argument("--act-line", type=float, default=0.20,
                    help="decision-tier p_hat act-line (passed to classify_vs_floor; default 0.20)")
    ap.add_argument("--sift-arm", default="sift",
                    help="the CANDIDATE arm (post / with the candidate edit; default 'sift')")
    ap.add_argument("--bare-arm", default="bare",
                    help="the BASELINE arm (pre / without the edit; default 'bare')")
    # regression_suite wiring.
    ap.add_argument("--guard-dir", default=None,
                    help="dir of guard-case per-round score JSONs (default: --score-dir)")
    ap.add_argument("--guard-cases", default=None,
                    help="path to guard_cases.json (default: alongside regression_suite.py)")
    ap.add_argument("--guard-baseline", default=None,
                    help="frozen guard baseline ledger; a baseline-PASS now-FAIL is a regression")
    ap.add_argument("-o", "--out", default=None, help="write the result JSON to this path")
    ap.add_argument("--json", action="store_true", help="print result JSON to stdout")
    ap.add_argument("--quiet", action="store_true", help="suppress the human render")
    args = ap.parse_args(argv)

    res = confirm(
        args.score_dir, args.predicate,
        candidate_arm=args.sift_arm, baseline_arm=args.bare_arm,
        floor_hi=args.floor_hi, floor_lo=args.floor_lo, act_line=args.act_line,
        predicate_args=_collect_predicate_args(args),
        registry=args.guard_cases, guard_score_dir=args.guard_dir,
        guard_baseline=args.guard_baseline, case_filter=args.case,
    )

    if not args.quiet:
        print(render_human(res))
    if args.json:
        if not args.quiet:
            print("\n--- JSON ---")
        print(json.dumps(res, indent=2, sort_keys=True))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=2, sort_keys=True)
        if not args.quiet:
            print(f"\nwrote {args.out}")

    # Exit 0 ONLY on CONFIRMED-KEEP; nonzero otherwise (usable as a gate).
    return 0 if res["decision"] == CONFIRMED_KEEP else 1


if __name__ == "__main__":
    raise SystemExit(main())

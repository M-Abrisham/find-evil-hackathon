#!/usr/bin/env python3
"""judge_validation.py — JUDGE-VALIDATION harness (diagnosis tool #2).

Measures the `score.py --judge` LLM-judge against a FROZEN, hand-labeled
borderline false-positive set and emits a confusion matrix + TPR/TNR + a
PASS/FAIL verdict versus a threshold (default 0.90).

WHERE IT RUNS / WHAT IT IS FOR
------------------------------
Operator/scoring layer on josh-pc (NEVER inside the sealed orchestrator).
Per RULE-CHANGE-DIAGNOSIS-PROTOCOL section 7 item 2 and Stage-2 Branch D:
the LLM judge (`score.py --judge` -> `llm_adjudicate`) may not move ANY
rate or routing until it passes a MEASURED confusion matrix (TPR AND TNR
both >= bar). Below the bar it is DECORATIVE — logged, never fed in — and
the freeze posture is judge-OFF with human adjudication of the remainder.

This harness produces the validation ARTIFACT that the gate inside
score.py reads. If no current passing artifact exists, score.py --judge
no-ops (see install_gate.md / the score.py patch).

WHAT THE JUDGE DECIDES (mirrors score.py exactly)
-------------------------------------------------
`llm_adjudicate` is handed score.py's `evidence.false_positive_findings`
(backed findings that hit no rubric item) and, per finding, returns
{"index", "supported": bool, "reason"}. "supported": true RESCUES the
finding (reclassifies a counted false-positive as rubric-supported) — i.e.
it moves the score. So for THIS harness:

    POSITIVE class  = item the judge SHOULD rescue  (gold supported == true)
    NEGATIVE class  = item the judge should leave as a FP (gold supported == false)

    TPR (sensitivity) = P(judge says supported | gold supported)
                        = how reliably it rescues a truly-supported finding
    TNR (specificity) = P(judge says unsupported | gold unsupported)
                        = how reliably it keeps a real FP flagged

A judge with low TNR is the dangerous one here: it would rescue genuine
false positives, silently inflating recall/precision. Hence BOTH must clear
the bar before the judge is allowed to touch a score.

LABELED-SET SCHEMA (the frozen artifact this harness consumes)
--------------------------------------------------------------
A JSON object:
  {
    "schema_version": 1,
    "set_id": "borderline-fp-v1",
    "frozen": true,                 # frozen sets are immutable; edit => new set_id
    "note": "...",
    "items": [
      {
        "id": "bfp-001",
        "finding": "<the false-positive finding claim text, verbatim>",
        "rubric": { "attack_type": "...",          # rubric VIEW score.py shows
                    "process_execution": [...],     # the EVIDENCE_BUCKETS
                    ... },
        "gold": "supported" | "unsupported" | "TO_BE_LABELED",
        "rationale": "<why a human assigned that gold label>"
      }, ...
    ]
  }

Items with gold == "TO_BE_LABELED" are SEED stubs: they are NOT scored and
MUST be hand-labeled by an operator before the set counts. A set that still
contains any TO_BE_LABELED item cannot PASS (it is not fully labeled).

This file ships ONLY a tiny SYNTHETIC seed (fixtures/seed_labeled_set.json)
with every gold == "TO_BE_LABELED" — real labels are added by a human on
josh-pc; we never fabricate gold labels here.

ADJUDICATION BACKEND
--------------------
By default the harness imports score.py's REAL `llm_adjudicate` so it
exercises the exact code path the gate protects. For unit tests and dry
runs you inject a pure-python adjudicator via `adjudicator=` (a callable
taking (false_positive_findings: list[str], rubric: dict) -> the same dict
shape llm_adjudicate returns: {"adjudicated":[{index,supported,reason}...]}).
NO network, NO API key in tests.

stdlib-only. Python 3.8+.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import math
import os
import sys
from typing import Any, Callable, Optional

SCHEMA_VERSION = 1
DEFAULT_THRESHOLD = 0.90

# Adjudicator signature: (false_positive_findings, rubric_view) -> dict|None
Adjudicator = Callable[[list], Optional[dict]]


# ---------------------------------------------------------------------------
# Labeled-set loading + validation
# ---------------------------------------------------------------------------
_GOLD_SUPPORTED = "supported"
_GOLD_UNSUPPORTED = "unsupported"
_GOLD_TODO = "TO_BE_LABELED"
_VALID_GOLD = {_GOLD_SUPPORTED, _GOLD_UNSUPPORTED, _GOLD_TODO}


class LabeledSetError(ValueError):
    """Raised when the labeled set is structurally invalid (a build error, not a judge fail)."""


def load_labeled_set(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return validate_labeled_set(data)


def validate_labeled_set(data: Any) -> dict:
    """Structural validation. Raises LabeledSetError on a malformed set."""
    if not isinstance(data, dict):
        raise LabeledSetError("labeled set must be a JSON object")
    items = data.get("items")
    if not isinstance(items, list) or not items:
        raise LabeledSetError("labeled set must have a non-empty 'items' list")
    seen_ids = set()
    for n, it in enumerate(items):
        if not isinstance(it, dict):
            raise LabeledSetError(f"item {n} is not an object")
        iid = it.get("id")
        if not isinstance(iid, str) or not iid.strip():
            raise LabeledSetError(f"item {n} missing non-empty string 'id'")
        if iid in seen_ids:
            raise LabeledSetError(f"duplicate item id {iid!r}")
        seen_ids.add(iid)
        if not isinstance(it.get("finding"), str) or not it["finding"].strip():
            raise LabeledSetError(f"item {iid} missing non-empty 'finding'")
        if not isinstance(it.get("rubric"), dict):
            raise LabeledSetError(f"item {iid} missing 'rubric' object")
        gold = it.get("gold")
        if gold not in _VALID_GOLD:
            raise LabeledSetError(
                f"item {iid} gold={gold!r} not one of {sorted(_VALID_GOLD)}"
            )
    return data


def labeled_set_stats(data: dict) -> dict:
    """Counts by gold label; surfaces unlabeled stubs."""
    items = data["items"]
    n_total = len(items)
    n_todo = sum(1 for it in items if it["gold"] == _GOLD_TODO)
    n_pos = sum(1 for it in items if it["gold"] == _GOLD_SUPPORTED)
    n_neg = sum(1 for it in items if it["gold"] == _GOLD_UNSUPPORTED)
    return {
        "set_id": data.get("set_id"),
        "frozen": bool(data.get("frozen", False)),
        "items_total": n_total,
        "labeled": n_pos + n_neg,
        "unlabeled_to_be_labeled": n_todo,
        "gold_supported": n_pos,
        "gold_unsupported": n_neg,
        "fully_labeled": n_todo == 0,
    }


# ---------------------------------------------------------------------------
# Wilson lower bound (consistent with the aggregator; behaves at 0/n and 1/1)
# ---------------------------------------------------------------------------
def wilson_interval(k: int, n: int, z: float = 1.959963984540054) -> tuple:
    """95% Wilson score interval for k successes in n trials. Returns (lo, hi).
    n==0 -> (0.0, 1.0) (no information)."""
    if n <= 0:
        return (0.0, 1.0)
    p = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    half = (z * math.sqrt((p * (1 - p) + z2 / (4 * n)) / n)) / denom
    lo = max(0.0, center - half)
    hi = min(1.0, center + half)
    return (lo, hi)


# ---------------------------------------------------------------------------
# Default adjudicator: the REAL score.py llm_adjudicate (subscription CLI).
# Imported lazily so the harness + tests stay import-clean without score.py.
# ---------------------------------------------------------------------------
def default_adjudicator(score_py_path: Optional[str] = None) -> Adjudicator:
    """Return an Adjudicator backed by score.py's real llm_adjudicate.
    score_py_path: dir containing score.py (defaults to eval/ next to this file
    in the deployed tree, else PYTHONPATH)."""
    import importlib.util

    cand = []
    if score_py_path:
        cand.append(os.path.join(score_py_path, "score.py"))
    here = os.path.dirname(os.path.abspath(__file__))
    cand.append(os.path.join(here, "..", "score.py"))      # eval/diagnosis/ -> eval/score.py
    cand.append(os.path.join(here, "score.py"))
    src = next((p for p in cand if os.path.isfile(p)), None)
    if src is None:
        raise LabeledSetError(
            "could not locate score.py for the default judge backend; "
            "pass --score-py DIR or inject adjudicator= in code"
        )
    spec = importlib.util.spec_from_file_location("_score_for_judge_val", src)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]

    def _adj(false_positive_findings: list, rubric: dict) -> Optional[dict]:
        return mod.llm_adjudicate(false_positive_findings, rubric)

    return _adj


# ---------------------------------------------------------------------------
# Core: run the judge over the labeled set and build the confusion matrix.
# ---------------------------------------------------------------------------
def _verdicts_to_index_map(adj_result: Optional[dict], n_items: int) -> dict:
    """From llm_adjudicate's {"adjudicated":[{index,supported,...}]} return
    {index -> bool supported}. Missing/None => treated as 'unsupported' (the
    judge declined to rescue), which is the SAFE default (no score moved)."""
    out = {i: False for i in range(n_items)}
    if not isinstance(adj_result, dict):
        return out
    for v in adj_result.get("adjudicated", []) or []:
        if not isinstance(v, dict):
            continue
        idx = v.get("index")
        if isinstance(idx, bool) or not isinstance(idx, int):
            continue
        if 0 <= idx < n_items:
            out[idx] = bool(v.get("supported"))
    return out


def run_validation(
    labeled_set: dict,
    adjudicator: Adjudicator,
    threshold: float = DEFAULT_THRESHOLD,
) -> dict:
    """Run `adjudicator` over the labeled set and compute the confusion matrix.

    Sends ALL labeled findings to the judge in ONE batch (mirrors how
    score.py hands llm_adjudicate the whole false_positive_findings list),
    pairing each finding with its own rubric is not possible in a single
    call, so we adjudicate PER-ITEM (one finding + its rubric) to honor that
    each labeled item carries its own rubric context. This is the faithful
    per-item analogue of the production call.
    """
    items = [it for it in labeled_set["items"] if it["gold"] != _GOLD_TODO]
    todo = [it for it in labeled_set["items"] if it["gold"] == _GOLD_TODO]

    tp = tn = fp = fn = 0
    per_item = []
    judge_errors = 0

    for it in items:
        gold_supported = it["gold"] == _GOLD_SUPPORTED
        adj = adjudicator([it["finding"]], it["rubric"])
        if adj is None:
            judge_errors += 1
            pred_supported = False   # judge unavailable => no rescue (safe)
            decided = False
        else:
            pred_supported = _verdicts_to_index_map(adj, 1)[0]
            decided = True
        # confusion (positive == supported/rescue)
        if gold_supported and pred_supported:
            tp += 1
            outcome = "TP"
        elif (not gold_supported) and (not pred_supported):
            tn += 1
            outcome = "TN"
        elif (not gold_supported) and pred_supported:
            fp += 1
            outcome = "FP"   # judge rescued a real false positive == DANGEROUS
        else:  # gold_supported and not pred_supported
            fn += 1
            outcome = "FN"
        per_item.append({
            "id": it["id"],
            "gold": it["gold"],
            "predicted_supported": pred_supported,
            "judge_decided": decided,
            "outcome": outcome,
        })

    n_pos = tp + fn          # gold supported
    n_neg = tn + fp          # gold unsupported
    tpr = (tp / n_pos) if n_pos else None
    tnr = (tn / n_neg) if n_neg else None
    tpr_lo = wilson_interval(tp, n_pos)[0] if n_pos else None
    tnr_lo = wilson_interval(tn, n_neg)[0] if n_neg else None

    stats = labeled_set_stats(labeled_set)
    fully_labeled = stats["fully_labeled"]

    # PASS requires: set fully labeled, BOTH classes represented (can't measure
    # a rate on an empty class), TPR and TNR both >= threshold, and no judge
    # errors (an unavailable judge cannot be validated).
    reasons = []
    if not fully_labeled:
        reasons.append(f"{len(todo)} item(s) still TO_BE_LABELED")
    if n_pos == 0:
        reasons.append("no gold-supported items (cannot measure TPR)")
    if n_neg == 0:
        reasons.append("no gold-unsupported items (cannot measure TNR)")
    if judge_errors:
        reasons.append(f"{judge_errors} judge error(s)/unavailable (cannot validate)")
    if tpr is not None and tpr < threshold:
        reasons.append(f"TPR {tpr:.3f} < {threshold:.2f}")
    if tnr is not None and tnr < threshold:
        reasons.append(f"TNR {tnr:.3f} < {threshold:.2f}")
    passed = len(reasons) == 0

    return {
        "tool": "judge_validation",
        "schema_version": SCHEMA_VERSION,
        "generated_utc": _dt.datetime.now(_dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "set_id": stats["set_id"],
        "set_frozen": stats["frozen"],
        "threshold": threshold,
        "fully_labeled": fully_labeled,
        "items_scored": len(items),
        "items_unlabeled": len(todo),
        "confusion": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "n_positive": n_pos,
        "n_negative": n_neg,
        "tpr": tpr,
        "tnr": tnr,
        "tpr_wilson_lo": tpr_lo,
        "tnr_wilson_lo": tnr_lo,
        "judge_errors": judge_errors,
        "passed": passed,
        "fail_reasons": reasons,
        "per_item": per_item,
    }


# ---------------------------------------------------------------------------
# Gate helper — imported by score.py to decide whether --judge may run.
# Kept here so the gate logic lives next to the harness that produces the
# artifact (single source of truth for "what counts as a current PASS").
# ---------------------------------------------------------------------------
GATE_ENV_VAR = "JUDGE_VALIDATION_ARTIFACT"  # path override for score.py


def artifact_is_current(artifact: dict, claude_version: Optional[str] = None) -> tuple:
    """Decide whether a validation artifact authorizes the judge RIGHT NOW.
    Returns (ok: bool, reason: str). 'Current' = passed AND (if a
    claude_version is supplied AND the artifact recorded one) versions match,
    because the judge is tied to one model snapshot (protocol 5.4).

    FAIL-CLOSED. `passed` must be the JSON boolean ``true`` (identity check): a
    truthy-but-non-bool value (1, "yes", [1], ...) is REJECTED, never read as a
    pass — a corrupt/hand-edited artifact must not silently authorize the judge."""
    if not isinstance(artifact, dict):
        return (False, "validation artifact is not a JSON object")
    if artifact.get("tool") != "judge_validation":
        return (False, "artifact is not a judge_validation result")
    passed = artifact.get("passed")
    if passed is not True:  # identity: reject 1 / "yes" / [1] / truthy-non-bool
        if passed is False or passed is None or "passed" not in artifact:
            rs = "; ".join(artifact.get("fail_reasons") or []) or "did not pass"
            return (False, f"validation FAILED ({rs})")
        return (False, f"artifact 'passed' is not boolean true "
                       f"(got {type(passed).__name__} {passed!r}) — refusing (fail-closed)")
    art_ver = artifact.get("claude_version")
    if claude_version and art_ver and art_ver != claude_version:
        return (False, f"version drift: artifact={art_ver} now={claude_version} (re-validate)")
    return (True, "validation current and passing")


def gate_check(artifact_path: Optional[str], claude_version: Optional[str] = None) -> tuple:
    """score.py calls this. Returns (allow_judge: bool, message: str)."""
    if not artifact_path:
        return (False, "no judge-validation artifact configured "
                       f"(set {GATE_ENV_VAR} or --judge-validation PATH)")
    if not os.path.isfile(artifact_path):
        return (False, f"judge-validation artifact not found: {artifact_path}")
    try:
        with open(artifact_path, "r", encoding="utf-8") as fh:
            art = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        return (False, f"could not read judge-validation artifact: {e}")
    ok, reason = artifact_is_current(art, claude_version)
    return (ok, reason)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def render(report: dict) -> str:
    c = report["confusion"]
    fmt = lambda x: "n/a" if x is None else f"{x:.3f}"
    lines = [
        "JUDGE VALIDATION — score.py --judge confusion matrix",
        f"  set: {report['set_id']}  (frozen={report['set_frozen']})  "
        f"threshold={report['threshold']:.2f}",
        f"  items scored: {report['items_scored']}"
        + (f"   (UNLABELED skipped: {report['items_unlabeled']})"
           if report["items_unlabeled"] else ""),
        "",
        "                 judge: SUPPORTED   judge: UNSUPPORTED",
        f"  gold SUPPORTED       TP={c['tp']:<6}        FN={c['fn']:<6}",
        f"  gold UNSUPPORTED     FP={c['fp']:<6}        TN={c['tn']:<6}",
        "",
        f"  TPR (rescue truly-supported): {fmt(report['tpr'])}"
        f"   [Wilson lo {fmt(report['tpr_wilson_lo'])}]",
        f"  TNR (keep real FP flagged):   {fmt(report['tnr'])}"
        f"   [Wilson lo {fmt(report['tnr_wilson_lo'])}]",
        "",
        f"  VERDICT: {'PASS — judge may run' if report['passed'] else 'FAIL — judge stays OFF'}",
    ]
    if not report["passed"]:
        for r in report["fail_reasons"]:
            lines.append(f"    - {r}")
        lines.append("  => keep judge OFF; route the ambiguous remainder to a HUMAN "
                     "(deterministic unbacked_list via empty literal_cited is judge-free).")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Validate score.py --judge against a frozen hand-labeled "
                    "borderline-FP set (TPR/TNR confusion matrix + PASS/FAIL).",
        epilog="OPERATOR/BUILD-TIME TOOLING. SUBSCRIPTION ONLY for the real judge "
               "backend. Below-threshold => judge stays OFF + human adjudication.",
    )
    ap.add_argument("-s", "--set", required=True,
                    help="path to the frozen labeled-set JSON")
    ap.add_argument("-o", "--out", default="judge_validation.json",
                    help="output artifact path (default: judge_validation.json)")
    ap.add_argument("-t", "--threshold", type=float, default=DEFAULT_THRESHOLD,
                    help=f"TPR/TNR bar (default {DEFAULT_THRESHOLD})")
    ap.add_argument("--score-py", default=None,
                    help="dir containing score.py for the real judge backend")
    ap.add_argument("--claude-version", default=None,
                    help="stamp this claude --version onto the artifact (ties it to one snapshot)")
    ap.add_argument("--dry-run", action="store_true",
                    help="validate the labeled set's structure/labeling and exit (no judge calls)")
    ap.add_argument("--quiet", action="store_true", help="suppress the human render")
    args = ap.parse_args(argv)

    try:
        ls = load_labeled_set(args.set)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot read labeled set: {e}", file=sys.stderr)
        return 2
    except LabeledSetError as e:
        print(f"ERROR: invalid labeled set: {e}", file=sys.stderr)
        return 2

    if args.dry_run:
        stats = labeled_set_stats(ls)
        print(json.dumps(stats, indent=2, sort_keys=True))
        if not stats["fully_labeled"]:
            print(f"\nNOT fully labeled: {stats['unlabeled_to_be_labeled']} "
                  f"item(s) still TO_BE_LABELED — cannot validate.", file=sys.stderr)
            return 1
        return 0

    try:
        adj = default_adjudicator(args.score_py)
    except LabeledSetError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    report = run_validation(ls, adj, threshold=args.threshold)
    if args.claude_version:
        report["claude_version"] = args.claude_version

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
        fh.write("\n")
    if not args.quiet:
        print(render(report))
        print(f"\nwrote {args.out}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

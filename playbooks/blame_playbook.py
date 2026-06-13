#!/usr/bin/env python3
"""
Protocol SIFT — PB6 blamer (BUILD-TIME TOOLING ONLY — do NOT commit to the team repo).

Closes the gap between the scorers and the EXISTING append-only rewriter (tune_playbook.py):
given a failed blind run's score(s) + the playbook, it ranks the WORST failure, attributes it
to a playbook_id + step, and emits a blame.json the loop hands straight to tune_playbook.py.

    blind run (eval/run_blind.py) -> score(s) -> THIS BLAMER -> tune_playbook.py -> next blind run

WHY THIS EXISTS (two facts the deep-search surfaced — do not "fix" by assuming them away):
  1. Two scorers, two shapes. eval/score.py emits `evidence.missed_evidence` (the 5 rubric
     buckets) — the ONLY thing tune_playbook.py can act on. scoring/scorer.py emits
     verdict / mitre / fabrications / findable failures — and is the ONLY place the project's
     stated #1 failure (verdict+MITRE absent) is visible. The blamer ingests BOTH so it can
     rank the real worst failure, then routes each failure to the remediation that can fix it.
  2. tune_playbook.py only ever acts on missed_evidence buckets. So verdict/MITRE/hallucination/
     misclassification failures are flagged `needs_other_fix` (CLAUDE.md / report skill / a
     Failure-mode falsify guard), NOT silently handed to a rewriter that cannot address them.

DETERMINISTIC — no LLM. (The STEP-NOT-EXECUTED vs STEP-EXECUTED-MISSED sub-fork is tune_playbook's
job, decided by its own `claude -p` call; the blamer only decides author-gap vs step-listed.)
STDLIB ONLY.  Reuses tune_playbook.py's parsing helpers so the two never drift.

Usage:
    python3 playbooks/blame_playbook.py --playbook playbooks/<cat>.md \\
            --score /cases/<id>/output/score.json [--ioc-score /cases/<id>/output/ioc.json] \\
            --case-id <id> [--out blame.json] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import tune_playbook as tune  # noqa: E402  reuse: SCORE_BUCKETS, fm_scalar, steps_emitting, split_frontmatter_span

SCORE_BUCKETS = tune.SCORE_BUCKETS

# Fixed importance order among the 5 evidence buckets. No weight exists in score.json
# (eval/score.py drops the rubric's per-item `weight`), so the bucket order is the only
# importance hint the scorer leaves us; key_artifacts highest .. exfil lowest.
BUCKET_RANK = {b: len(SCORE_BUCKETS) - i for i, b in enumerate(SCORE_BUCKETS)}

# ----------------------------------------------------------------------------
# Severity policy (higher = worse). DOCUMENTED + EASY TO RETUNE — change these
# numbers in one place. Grounded in the project's stated priorities:
#   * "the deterministic scorer is the truth";
#   * the agent's #1 known failure is verdict + MITRE absent (project memory);
#   * fabrication/hallucination is the failure class this project exists to eliminate.
# Base tier + a small recall-gap / bucket-rank tie-break added at detection time.
# ----------------------------------------------------------------------------
SEV = {
    "verdict_absent":   100,   # ioc-score: verdict == "not_emitted"   (project's stated #1 failure)
    "fabrication":       95,   # ioc-score: fabrication_count > 0       (anti-hallucination mandate)
    "hallucination":     90,   # eval-score: unbacked_findings > 0
    "mitre_gap":         80,   # ioc-score: ATT&CK techniques missing
    "misclassification": 70,   # eval-score: category_match == False
    "subtype_miss":      50,   # eval-score: category ok but subtype_match == False
    "missed_evidence":   40,   # eval-score: a non-empty missed_evidence bucket
    "findable_gap":      35,   # ioc-score: findable IOCs missed (failures[])
    "false_positive":    30,   # eval-score: false_positive findings
}

# Where each failure kind can actually be fixed. tune_playbook.py acts ONLY on missed_evidence
# buckets (it filters score -> SCORE_BUCKETS and exits if none survive), so everything else is
# routed elsewhere and must NOT be handed to tune.
ROUTE = {
    "missed_evidence":   ("tune_playbook", "append/strengthen the step that emits this bucket"),
    "verdict_absent":    ("agent_config", "CLAUDE.md / report skill: require an explicit verdict line"),
    "mitre_gap":         ("agent_config", "CLAUDE.md / report skill: require ATT&CK T-codes in the report"),
    "misclassification": ("agent_config", "triage/router or report skill: attack-type classification"),
    "subtype_miss":      ("agent_config", "report skill: sub-type precision"),
    "hallucination":     ("playbook_guard", "append a Failure-mode falsify guard (two-source rule)"),
    "fabrication":       ("playbook_guard", "append a Failure-mode falsify guard (no-fabrication rule)"),
    "findable_gap":      ("tune_or_guard", "map to a rubric bucket if backed, else a Failure-mode guard"),
    "false_positive":    ("playbook_guard", "tighten expect/check via a new falsify guard"),
}

# Tie-break ordering when severities collide: emit failures in this fixed kind order.
KIND_ORDER = list(SEV.keys())


# ----------------------------------------------------------------------------
# Failure construction
# ----------------------------------------------------------------------------
def _mk(kind: str, base: float, detail: str = "", items=None, bucket: str | None = None) -> dict:
    route, remediation = ROUTE[kind]
    return {
        "kind": kind,
        "severity": round(float(base), 3),
        "bucket": bucket,                       # one of SCORE_BUCKETS for missed_evidence, else None
        "detail": detail,
        "items": list(items or []),
        "route": route,
        "remediation": remediation,
        "actionable_by_tune": kind == "missed_evidence",
    }


def failures_from_eval(score: dict, emitters: dict) -> list[dict]:
    """Candidates from eval/score.py output (the only source of tune-actionable missed_evidence)."""
    out: list[dict] = []
    ev = score.get("evidence") or {}
    hal = score.get("hallucination") or {}
    head = score.get("headline") or {}
    cls = score.get("classification") or {}

    # hallucination (unbacked findings) — fabrication's eval-side twin
    n_unbacked = hal.get("unbacked_findings") or 0
    if n_unbacked:
        rate = hal.get("hallucination_rate") or 0
        out.append(_mk("hallucination", SEV["hallucination"] + rate * 10,
                       detail=f"{n_unbacked} unbacked finding(s) (rate {rate})",
                       items=[u.get("claim", "") for u in (hal.get("unbacked_list") or [])]))

    # misclassification / subtype miss (the verdict-shaped failure eval/score.py CAN express)
    cat_match = head.get("category_match")
    if cat_match is None:
        cat_match = cls.get("category_match")
    if cat_match is False:
        out.append(_mk("misclassification", SEV["misclassification"],
                       detail=f"predicted {cls.get('predicted_category')!r} != truth {cls.get('truth_category')!r}"))
    elif cls.get("subtype_match") is False and cat_match:
        out.append(_mk("subtype_miss", SEV["subtype_miss"], detail="attack-type ok but sub-type mismatch"))

    # false positives
    n_fp = ev.get("false_positives") or 0
    if n_fp:
        fpr = ev.get("false_positive_rate") or 0
        out.append(_mk("false_positive", SEV["false_positive"] + fpr * 10,
                       detail=f"{n_fp} false-positive finding(s) (rate {fpr})",
                       items=ev.get("false_positive_findings") or []))

    # missed evidence buckets — the ONLY tune-actionable axis; attribute each to its emitting step(s)
    missed = ev.get("missed_evidence") or {}
    per = ev.get("per_bucket") or {}
    for b in SCORE_BUCKETS:
        items = [m for m in (missed.get(b) or []) if m]
        if not items:
            continue
        recall = (per.get(b) or {}).get("recall")
        gap = (1 - recall) if isinstance(recall, (int, float)) else 1.0
        base = SEV["missed_evidence"] + BUCKET_RANK[b] + gap * 10
        who = emitters.get(b, [])
        f = _mk("missed_evidence", base, bucket=b,
                detail=f"{len(items)} missed rubric item(s)", items=items)
        f["steps_emitting_bucket"] = who                       # e.g. ["n=3 (Steps)", "L2 (Linux branch)"]
        f["blamed_steps"] = [m.group(1) for s in who if (m := re.match(r"^(n=.+?|L\d+)\s*\(", s))]
        f["blame_type"] = "author-gap" if not who else "step-listed"  # 1:1 with tune's NO-STEP-EMITS / STEP-LISTED
        out.append(f)
    return out


def select_ioc_case(ioc: dict, case_id: str) -> dict | None:
    """scoring/scorer.py emits {cases:[CaseResult...], aggregate:{...}}; pick this case."""
    if not isinstance(ioc, dict):
        return None
    if "verdict" in ioc and "cases" not in ioc:        # already a single CaseResult
        return ioc
    cases = ioc.get("cases")
    if not isinstance(cases, list):
        return None
    for c in cases:
        if isinstance(c, dict) and c.get("case_id") == case_id:
            return c
    return cases[0] if len(cases) == 1 and isinstance(cases[0], dict) else None


def failures_from_ioc(case: dict | None) -> list[dict]:
    """Candidates from scoring/scorer.py output — the ONLY place verdict/MITRE/fabrication live."""
    out: list[dict] = []
    if not case:
        return out

    if case.get("verdict") == "not_emitted":
        exp = case.get("verdict_expected") or ""
        out.append(_mk("verdict_absent", SEV["verdict_absent"],
                       detail=f"no verdict emitted (expected {exp!r})" if exp else "no verdict emitted"))

    nfab = case.get("fabrication_count") or 0
    if nfab:
        out.append(_mk("fabrication", SEV["fabrication"],
                       detail=f"{nfab} fabricated IOC(s)",
                       items=[f"{x.get('type')}:{x.get('value')}" for x in (case.get("fabrications") or [])]))

    mt = case.get("mitre_total") or 0
    mf = case.get("mitre_found") or 0
    if mt and mf < mt:
        missing = [k for k, v in (case.get("mitre_present") or {}).items() if not v]
        rec = mf / mt if mt else 0.0
        out.append(_mk("mitre_gap", SEV["mitre_gap"] + (1 - rec) * 10,
                       detail=f"{mt - mf}/{mt} ATT&CK technique(s) missing", items=missing))

    fails = case.get("failures") or []
    if fails:
        out.append(_mk("findable_gap", SEV["findable_gap"],
                       detail=f"{len(fails)} findable IOC(s) missed",
                       items=[f"{x.get('type')}:{x.get('value')}" for x in fails]))
    return out


# ----------------------------------------------------------------------------
# Playbook contract checks (reuse tune's frontmatter + emits parsing)
# ----------------------------------------------------------------------------
def playbook_facts(pb_text: str) -> dict:
    ver = tune.fm_scalar(pb_text, "version")
    has_version = bool(re.match(r"^\d+$", ver or ""))
    emitters = tune.steps_emitting(pb_text)
    has_emits = any(emitters[b] for b in SCORE_BUCKETS)
    pid = (tune.fm_scalar(pb_text, "category_id")
           or tune.fm_scalar(pb_text, "attack_type"))
    return {
        "emitters": emitters,
        "has_version": has_version,
        "version": int(ver) if has_version else None,
        "has_emits": has_emits,
        "playbook_id": pid,                    # may be "" -> caller falls back to file stem
        "contract_shaped": has_version and has_emits,
    }


def rank(failures: list[dict]) -> list[dict]:
    def key(f):
        return (-f["severity"], KIND_ORDER.index(f["kind"]),
                -BUCKET_RANK.get(f.get("bucket") or "", 0))
    return sorted(failures, key=key)


# ----------------------------------------------------------------------------
# Anti-hallucination tripwire.
# The blamer is deterministic, so it CANNOT invent findings — but a future code
# change could. This re-derives the allowed set for every emitted item straight
# from the raw inputs and refuses to write blame.json if anything fails to trace
# back. ("Reported X" must always mean "the score said X" / "the playbook has step X".)
# ----------------------------------------------------------------------------
def _allowed_items(kind: str, eval_score: dict | None, ioc_case: dict | None):
    ev = (eval_score or {}).get("evidence") or {}
    hal = (eval_score or {}).get("hallucination") or {}
    c = ioc_case or {}
    if kind == "hallucination":
        return {u.get("claim", "") for u in (hal.get("unbacked_list") or [])}
    if kind == "false_positive":
        return set(ev.get("false_positive_findings") or [])
    if kind == "mitre_gap":
        return {k for k, v in (c.get("mitre_present") or {}).items() if not v}
    if kind == "fabrication":
        return {f"{x.get('type')}:{x.get('value')}" for x in (c.get("fabrications") or [])}
    if kind == "findable_gap":
        return {f"{x.get('type')}:{x.get('value')}" for x in (c.get("failures") or [])}
    return None  # verdict_absent / misclassification / subtype_miss carry no enumerable items


def verify_provenance(blame: dict, pb_text: str, eval_score: dict | None,
                      ioc_case: dict | None) -> list[str]:
    """Return a list of provenance violations (empty == every item traces to an input)."""
    problems: list[str] = []
    missed = ((eval_score or {}).get("evidence") or {}).get("missed_evidence") or {}
    # steps that literally exist in the playbook (re-derived, independent of steps_emitting)
    present_steps = {"n=" + re.sub(r"\s+#.*$", "", m.group(1)).strip()
                     for m in re.finditer(r"^\s*-\s+n:\s*(.+?)\s*$", pb_text, re.M)}
    for f in blame.get("ranked_failures", []):
        kind = f.get("kind")
        if kind == "missed_evidence":
            b = f.get("bucket")
            if b not in SCORE_BUCKETS:
                problems.append(f"missed_evidence bucket is not a SCORE_BUCKET: {b!r}")
            src = missed.get(b) or []
            for it in f.get("items", []):
                if it not in src:
                    problems.append(f"fabricated missed_item (not in score evidence[{b}]): {it!r}")
            for s in f.get("blamed_steps", []):
                if s not in present_steps:
                    problems.append(f"blamed a step absent from the playbook: {s!r}")
        else:
            allowed = _allowed_items(kind, eval_score, ioc_case)
            if allowed is not None:
                for it in f.get("items", []):
                    if it not in allowed:
                        problems.append(f"fabricated {kind} item (not in source score): {it!r}")
    return problems


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def load_json(path: str, label: str) -> dict:
    try:
        return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"FATAL: {label} not found: {path}", file=sys.stderr)
        raise SystemExit(1)
    except json.JSONDecodeError as e:
        print(f"FATAL: {label} is not valid JSON ({e}): {path}", file=sys.stderr)
        raise SystemExit(1)


def build_blame(args) -> dict:
    pb_path = pathlib.Path(args.playbook)
    if not pb_path.is_file():
        print(f"FATAL: playbook not found: {args.playbook}", file=sys.stderr)
        raise SystemExit(1)
    pb_text = pb_path.read_text(encoding="utf-8")
    if tune.split_frontmatter_span(pb_text) is None:
        print(f"FATAL: playbook has no YAML frontmatter: {args.playbook}", file=sys.stderr)
        raise SystemExit(1)

    facts = playbook_facts(pb_text)
    playbook_id = facts["playbook_id"] or pb_path.stem

    failures: list[dict] = []
    eval_score: dict | None = None
    case: dict | None = None
    used_eval = used_ioc = False
    if args.score:
        eval_score = load_json(args.score, "eval score.json")
        failures += failures_from_eval(eval_score, facts["emitters"])
        used_eval = True
    if args.ioc_score:
        ioc = load_json(args.ioc_score, "ioc score.json")
        case = select_ioc_case(ioc, args.case_id)
        if case is None:
            print(f"WARN: --ioc-score has no case '{args.case_id}' and is not single-case; "
                  f"verdict/MITRE failures will be skipped.", file=sys.stderr)
        failures += failures_from_ioc(case)
        used_ioc = True

    ranked = rank(failures)
    tune_actionable = [f for f in ranked if f["actionable_by_tune"]]
    needs_other = [f for f in ranked if not f["actionable_by_tune"]]

    # tune_playbook can run iff there's a missed_evidence failure AND the playbook has `version:`
    # (bump_version raises otherwise). has_emits only affects whether attribution is author-gap.
    tune_blocked = None
    if not tune_actionable:
        tune_blocked = "no missed_evidence bucket failed — nothing for tune_playbook to append"
    elif not facts["has_version"]:
        tune_blocked = "playbook has no integer `version:` line — not contract-shaped; tune_playbook would raise"
    tune_runnable = tune_blocked is None

    tune_command = None
    if tune_runnable:
        cmd = ["python3", "playbooks/tune_playbook.py",
               "--playbook", args.playbook, "--score", args.score, "--case-id", args.case_id]
        tune_command = cmd

    blame = {
        "case_id": args.case_id,
        "playbook": args.playbook,
        "playbook_id": playbook_id,
        "playbook_version": facts["version"],
        "scores_ingested": {"eval_score": used_eval, "ioc_score": used_ioc},
        "diagnostics": {
            "playbook_contract_shaped": facts["contract_shaped"],
            "has_version": facts["has_version"],
            "step_attribution_available": facts["has_emits"],
            "tune_runnable": tune_runnable,
            "tune_blocked_reason": tune_blocked,
            "provenance_verified": True,   # set True only after the tripwire passes below
        },
        "failure_count": len(ranked),
        "worst_failure": ranked[0] if ranked else None,
        "ranked_failures": ranked,
        "tune_actionable": tune_actionable,
        "tune_command": tune_command,
        "needs_other_fix": needs_other,
    }

    # Anti-hallucination tripwire: refuse to emit blame that cites anything not in the inputs.
    problems = verify_provenance(blame, pb_text, eval_score, case)
    if problems:
        for p in problems:
            print(f"PROVENANCE VIOLATION: {p}", file=sys.stderr)
        print("FATAL: blamer cited an item with no provenance in its inputs — refusing to write "
              "blame.json (anti-hallucination tripwire).", file=sys.stderr)
        raise SystemExit(3)
    return blame


def main() -> int:
    ap = argparse.ArgumentParser(description="PB6 blamer: rank the worst failure and attribute it "
                                             "to a playbook step; emit blame.json for tune_playbook.py.")
    ap.add_argument("--playbook", required=True, help="contract-shaped playbook .md to blame + tune")
    ap.add_argument("--score", help="score.json from eval/score.py (missed_evidence buckets)")
    ap.add_argument("--ioc-score", dest="ioc_score",
                    help="score JSON from scoring/scorer.py (verdict/MITRE/fabrication/findable)")
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--out", default="blame.json", help="where to write blame.json (default: blame.json)")
    ap.add_argument("--dry-run", action="store_true", help="print blame.json to stdout; write nothing")
    args = ap.parse_args()

    if not args.score and not args.ioc_score:
        print("FATAL: provide at least one of --score (eval/score.py) or --ioc-score (scoring/scorer.py).",
              file=sys.stderr)
        return 2

    blame = build_blame(args)

    if blame["failure_count"] == 0:
        print(f"nothing to blame: no failures in the supplied score(s) for case {args.case_id}")
        return 0

    payload = json.dumps(blame, indent=2, ensure_ascii=False)
    if args.dry_run:
        print(payload)
    else:
        pathlib.Path(args.out).write_text(payload + "\n", encoding="utf-8")

    w = blame["worst_failure"]
    where = (f"-> {w['bucket']}" if w.get("bucket") else "")
    tip = ("run tune_command" if blame["tune_command"]
           else f"NOT tune-fixable ({blame['diagnostics']['tune_blocked_reason']})")
    print(f"blamed case {args.case_id}: worst = {w['kind']} (sev {w['severity']}) {where} | "
          f"{blame['failure_count']} failure(s); {len(blame['tune_actionable'])} tune-actionable; {tip}"
          + ("" if args.dry_run else f" | wrote {args.out}"))
    return 0


if __name__ == "__main__":
    sys.exit(main())

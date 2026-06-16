#!/usr/bin/env python3
"""errlens -- recurring error-analysis SENSOR for the Protocol SIFT eval loop.

ADVISORY ONLY. Produces + maintains the failure taxonomy and DETECTS new failure
modes from already-emitted scorer signals. It FEEDS the Rule-Change Diagnosis
Protocol (supplies the per-category FAIL predicates the operator freezes in
Stage 1.3, and flags new modes for the Stage-5 human open-coding pass). It NEVER
enters the keep/revert reward path, NEVER recomputes or modifies scores, and does
NOT touch scorer.py or score_ledger.py (both other-agent-owned).

Pipeline: load_taxonomy -> bucket each round's signals by per-category predicate
-> flag any FAILING round matching ZERO active category as a NEW-mode candidate
(staged for HUMAN open-coding, never auto-promoted) -> render a per-batch report
(raw COUNTS only -- the downstream statistical aggregator owns the pooling) +
append a JSONL log. Stdlib only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from typing import Any, Dict, List, Optional

__all__ = [
    "load_taxonomy", "active_records", "taxonomy_sha", "from_caseresult_dict",
    "is_failure", "bucket_round", "process_batch", "render_report", "append_log",
    "ErrlensError",
]


class ErrlensError(Exception):
    pass


# --- canonical hashing (taxonomy tamper/version guard) ----------------------
def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


def taxonomy_sha(categories: list) -> str:
    return hashlib.sha256(canonical_json(categories).encode("utf-8")).hexdigest()


_REQUIRED = ("id", "human_name", "severity_class", "status", "predicate",
             "scorer_signals_read", "related_rule_ids")
_SEVERITY = ("A", "B", "none")
_STATUS = ("active", "blind-spot", "advisory", "watchlist", "control")


def load_taxonomy(path: str, verify_sha: bool = True) -> dict:
    with open(path, encoding="utf-8") as fh:
        tax = json.load(fh)
    cats = tax.get("categories")
    if not isinstance(cats, list) or not cats:
        raise ErrlensError("taxonomy has no categories")
    seen = set()
    for r in cats:
        miss = [f for f in _REQUIRED if f not in r]
        if miss:
            raise ErrlensError(f"category {r.get('id', '?')} missing fields: {miss}")
        if r["id"] in seen:
            raise ErrlensError(f"duplicate category id: {r['id']}")
        seen.add(r["id"])
        if r["severity_class"] not in _SEVERITY:
            raise ErrlensError(f"category {r['id']} bad severity_class")
        if r["status"] not in _STATUS:
            raise ErrlensError(f"category {r['id']} bad status")
    if verify_sha:
        want, got = tax.get("taxonomy_sha"), taxonomy_sha(cats)
        if want != got:
            raise ErrlensError(
                "taxonomy_sha mismatch (record edited without re-stamping / "
                f"bumping taxonomy_version?): stored={want} computed={got}")
    return tax


def active_records(tax: dict) -> list:
    return [r for r in tax["categories"] if r["status"] == "active"]


# --- normalized round signals + read-only scorer adapter --------------------
def from_caseresult_dict(d: dict) -> dict:
    """Map a scorer.py CaseResult.to_dict() -> normalized errlens signals (read-only)."""
    iocs = d.get("iocs") or []
    has_findable_miss = any(
        (i.get("findable") and not i.get("found")) for i in iocs if isinstance(i, dict))
    return {
        "case": d.get("case_id") or d.get("case") or "?",
        "verdict": d.get("verdict"),
        "fabrication_count": int(d.get("fabrication_count", 0) or 0),
        "findable_recall": d.get("findable_recall", d.get("findable_recall_micro", "x")),
        "has_findable_miss": bool(has_findable_miss),
        "presence": d.get("presence"),
        "other_negative": list(d.get("other_negative", []) or []),
    }


def is_failure(s: dict) -> bool:
    return (s.get("verdict") == "not_emitted"
            or int(s.get("fabrication_count", 0) or 0) > 0
            or bool(s.get("has_findable_miss"))
            or s.get("findable_recall", "x") is None
            or s.get("presence") == "FAIL"
            or bool(s.get("other_negative")))


def _fired_signals(s: dict) -> list:
    out = []
    if s.get("verdict") == "not_emitted":
        out.append("verdict_not_emitted")
    if int(s.get("fabrication_count", 0) or 0) > 0:
        out.append("fabrication")
    if s.get("has_findable_miss"):
        out.append("recall_miss")
    if s.get("findable_recall", "x") is None:
        out.append("findability_ceiling")
    if s.get("presence") == "FAIL":
        out.append("presence_fail")
    out += list(s.get("other_negative", []) or [])
    return out


# --- predicates -------------------------------------------------------------
def _match(pred: dict, s: dict) -> bool:
    k = pred.get("kind")
    if k == "verdict_not_emitted":
        return s.get("verdict") == "not_emitted"
    if k == "fabrication_gt0":
        return int(s.get("fabrication_count", 0) or 0) > 0
    if k == "recall_miss":
        return bool(s.get("has_findable_miss"))
    if k == "findability_ceiling":
        return s.get("findable_recall", "x") is None or bool(s.get("findable_false"))
    if k == "presence_fail":
        return s.get("presence") == "FAIL"
    if k == "none":
        return False  # human-only / advisory; never auto-buckets
    raise ErrlensError(f"unknown predicate kind: {k}")


def bucket_round(s: dict, tax: dict) -> list:
    return [r["id"] for r in active_records(tax) if _match(r["predicate"], s)]


# --- batch processing (deterministic, idempotent) ---------------------------
def process_batch(rounds: list, tax: dict) -> dict:
    counts: Dict[str, dict] = {}
    for rec in active_records(tax):
        counts[rec["id"]] = {"sift": 0, "bare": 0, "severity": rec["severity_class"]}
    class_a: List[dict] = []
    new_modes: List[dict] = []
    for rnd in rounds:
        arm = rnd.get("arm", "sift")
        s = rnd.get("signals", {})
        matched = bucket_round(s, tax)
        for cid in matched:
            if arm not in ("sift", "bare"):
                counts[cid].setdefault(arm, 0)
            counts[cid][arm] = counts[cid].get(arm, 0) + 1
            if counts[cid]["severity"] == "A":
                class_a.append({"category": cid, "case": s.get("case"),
                                "arm": arm, "round_id": rnd.get("round_id")})
        if is_failure(s) and not matched:
            new_modes.append({
                "round_id": rnd.get("round_id"), "case": s.get("case"), "arm": arm,
                "raw_signals": _fired_signals(s),
                "taxonomy_version": tax.get("taxonomy_version"),
            })
    return {"counts": counts, "class_a": class_a, "new_mode_candidates": new_modes,
            "n_rounds": len(rounds), "taxonomy_version": tax.get("taxonomy_version")}


# --- reporting (raw integer counts ONLY; pooling is owned downstream) --------
def render_report(batch: dict, tax: dict, prev: Optional[dict] = None) -> str:
    L = ["# errlens report (advisory -- never a keep/revert signal)", "",
         f"taxonomy_version: {batch['taxonomy_version']}  |  rounds: {batch['n_rounds']}", ""]
    if batch["class_a"]:
        L.append("## Class-A (severe) -- investigate the one trace even at count 1")
        for h in batch["class_a"]:
            L.append(f"- {h['category']} | case={h.get('case')} | {h['arm']} | round {h.get('round_id')}")
        L.append("")
    L.append("## Per-category counts (raw integers; downstream owns the pooling)")
    L.append("| category | severity | sift | bare | delta sift vs last |")
    L.append("|---|---|---|---|---|")
    prev_counts = (prev or {}).get("counts", {})
    for rec in tax["categories"]:
        cid = rec["id"]
        if rec["status"] == "active":
            c = batch["counts"].get(cid, {"sift": 0, "bare": 0})
            pv = prev_counts.get(cid, {}).get("sift")
            delta = "n/a" if pv is None else f"{c['sift'] - pv:+d}"
            L.append(f"| {cid} | {rec['severity_class']} | {c['sift']} | {c['bare']} | {delta} |")
        else:
            L.append(f"| {cid} | {rec['severity_class']} | unobservable ({rec['status']}) | unobservable | n/a |")
    L.append("")
    L.append("## NEW-mode candidates (for HUMAN open-coding -- NOT auto-promoted)")
    if not batch["new_mode_candidates"]:
        L.append("none this batch")
    else:
        for nm in batch["new_mode_candidates"]:
            L.append(f"- round {nm.get('round_id')} | case={nm.get('case')} | signals={nm['raw_signals']}")
    L.append("")
    n_new = len(batch["new_mode_candidates"])
    L.append("## Saturation")
    if n_new:
        L.append(f"{n_new} new-mode candidate(s) this batch. A spike after a deploy = the change introduced unanticipated failures (re-open those traces).")
    else:
        L.append("0 new-mode candidates this batch (approaching saturation if this holds ~20 rounds).")
    return "\n".join(L) + "\n"


def append_log(batch: dict, path: str) -> None:
    row = {"counts": batch["counts"], "new_mode_candidates": batch["new_mode_candidates"],
           "n_rounds": batch["n_rounds"], "taxonomy_version": batch["taxonomy_version"]}
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(canonical_json(row) + "\n")


def _load_rounds(path: str) -> list:
    with open(path, encoding="utf-8") as fh:
        d = json.load(fh)
    return d["rounds"] if isinstance(d, dict) else d


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description="errlens advisory error-analysis sensor")
    sub = p.add_subparsers(dest="cmd", required=True)
    here = os.path.dirname(os.path.abspath(__file__))
    pb = sub.add_parser("bucket")
    pb.add_argument("--rounds", required=True)
    pb.add_argument("--taxonomy", default=os.path.join(here, "taxonomy.json"))
    pb.add_argument("--report")
    pb.add_argument("--log")
    for name in ("stamp", "verify"):
        sp = sub.add_parser(name)
        sp.add_argument("--taxonomy", required=True)
    a = p.parse_args(argv)
    if a.cmd == "stamp":
        with open(a.taxonomy, encoding="utf-8") as fh:
            tax = json.load(fh)
        tax["taxonomy_sha"] = taxonomy_sha(tax["categories"])
        with open(a.taxonomy, "w", encoding="utf-8") as fh:
            json.dump(tax, fh, indent=2)
            fh.write("\n")
        print("stamped taxonomy_sha", tax["taxonomy_sha"])
        return 0
    if a.cmd == "verify":
        load_taxonomy(a.taxonomy)
        print("taxonomy OK")
        return 0
    tax = load_taxonomy(a.taxonomy)
    batch = process_batch(_load_rounds(a.rounds), tax)
    rep = render_report(batch, tax)
    if a.report:
        with open(a.report, "w", encoding="utf-8") as fh:
            fh.write(rep)
    else:
        print(rep)
    if a.log:
        append_log(batch, a.log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

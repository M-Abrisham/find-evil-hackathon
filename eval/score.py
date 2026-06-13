#!/usr/bin/env python3
"""
Protocol SIFT — blind-investigation scorer (BUILD-TIME EVAL TOOLING ONLY, not hackathon-submission code).

Implements the "Blind scoring" loop from docs/research-runner-sandbox-antihallucination.md (section 5,
"Real test cases WITH ground-truth answer keys"): the operator extracts a published answer key into a
HIDDEN rubric; the agent gets only a read-only mount + a neutral prompt and emits structured findings
(claim + evidence_pointer + confidence); this script grades that blind run against the rubric.

It loads:
  - a findings.json  (eval/findings.schema.json shape) — what the agent reported
  - a rubric.json    (eval/rubric.schema.json shape)   — the hidden answer key
and computes four scores, then prints a readable scorecard and writes score.json:

  1. ATTACK-TYPE CLASSIFICATION  — exact category match vs the 24 on-box Detection-&-Analysis
     categories of the SIFT taxonomy (the parent-category taxonomy embedded below), AND a finer
     sub-type/alias match (predicted classification vs the rubric's attack_type.aliases).
     Secondary-category overlap earns partial credit on multi-stage incidents.
  2. KEY-EVIDENCE RECALL         — fuzzy/token-set match of findings to the rubric's evidence buckets
     (key_artifacts + key_iocs + timeline_events + actor_accounts + exfil_or_encryption_facts):
     precision, recall, F1.
  3. FALSE-POSITIVE RATE         — backed findings that match NO rubric item (asserted but unsupported).
  4. HALLUCINATION RATE          — findings whose evidence_pointer carries no verbatim backing
     (empty/missing literal_cited). THE HEADLINE METRIC: per docs section 5, "Require a citation per
     claim -> unbacked = auto hallucination flag."

STDLIB ONLY. Fuzzy matching is difflib (no third-party deps).

This script is OFFLINE by default and needs NO LLM. An OPTIONAL `--judge` pass can ask Claude to
adjudicate the borderline "false-positive" findings (is this finding actually supported by the rubric,
phrased differently?). That pass — like playbooks/build_playbook.py — runs through the Claude Code
headless CLI on the SUBSCRIPTION (it UNSETS ANTHROPIC_API_KEY so a stray key can't silently flip the
call to metered API billing). Runner is env-configurable via SCORE_AGENT (default: claude).

  SUBSCRIPTION ONLY — never an API key.  An LLM judge is a convenience, never required to score.

Usage:
    python3 eval/score.py --findings run/findings.json --rubric eval/keys/leakage.rubric.json
    python3 eval/score.py -f findings.json -r rubric.json --out score.json --threshold 0.72
    python3 eval/score.py --selftest        # runs on tiny mock data, zero real evidence, no LLM
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import shlex
import subprocess
import sys
from typing import Any


# ---------------------------------------------------------------------------
# The 24 on-box Detection-&-Analysis categories — the parent-category taxonomy.
# Verbatim from "Complete_IR_Investigation_Type_Taxonomy_NIST800-61_PICERL.txt"
# (the on-box analysis block) and mirrored in the schemas' sift_category enum.
# This list, NOT the model's knowledge, is the only source of valid categories.
# ---------------------------------------------------------------------------
CATEGORIES_24: list[str] = [
    "Acquisition, Custody & Cross-Platform Synthesis",
    "Endpoint / Disk & File System",
    "File Recovery, Carving & Data Reduction",
    "Memory (RAM) Forensics",
    "Windows Artifacts - Execution & User Activity",
    "Windows Registry & Persistence",
    "Windows Event Logs (EVTX/ETW)",
    "Linux / Unix Host Forensics",
    "macOS Forensics",
    "Browser, Email & Document Forensics",
    "Web / Perimeter & Server Compromise",
    "Network Forensics",
    "Malware Analysis & Triage",
    "Active Directory & Domain",
    "Cloud Identity & SaaS",
    "Cloud IaaS Control-Plane & Data",
    "Containers, CI/CD & Software Supply Chain",
    "Attack-Lifecycle Hunting (ATT&CK)",
    "Impact, Ransomware & Destructive",
    "Insider Threat, Fraud & Data Theft",
    "Steganography, Data-Hiding & Encryption",
    "Threat Hunting & IOC Sweeps",
    "Targeted Intrusion / APT & Specialized",
    "Virtualization & Mobile/Embedded",
]

# Rubric evidence buckets scored for recall (order = scorecard order).
EVIDENCE_BUCKETS = [
    "key_artifacts",
    "key_iocs",
    "timeline_events",
    "actor_accounts",
    "exfil_or_encryption_facts",
]

DEFAULT_MATCH_THRESHOLD = 0.55   # token-set similarity >= this counts as a match

# LLM-judge runner (subscription-authed CLI), mirroring playbooks/build_playbook.py knobs.
JUDGE_AGENT = os.environ.get("SCORE_AGENT", "claude")
JUDGE_MODEL = os.environ.get("SCORE_MODEL", "sonnet")
JUDGE_ARGS = shlex.split(os.environ.get("SCORE_AGENT_ARGS", ""))


# ---------------------------------------------------------------------------
# Text normalization + fuzzy / token-set matching (difflib only).
# ---------------------------------------------------------------------------
_WORD_RE = re.compile(r"[a-z0-9]+")
# Filler words that add noise to forensic phrasing but no signal for matching.
_STOP = frozenset(
    "the a an of to in on at for and or via with from by is was were be been "
    "this that these those it its as into used user account file device".split()
)


def _norm(s: str) -> str:
    return " ".join(_WORD_RE.findall((s or "").lower()))


def _tokens(s: str) -> set[str]:
    """Content tokens of a string: lowercased alnum words minus stopwords.
    Keeps short tokens (e.g. 'ip', 'usb', hashes, 'vid') because they are
    high-signal IOCs in this domain."""
    return {t for t in _WORD_RE.findall((s or "").lower()) if t not in _STOP}


def token_set_ratio(a: str, b: str) -> float:
    """Order-independent Jaccard-style token overlap, in [0,1].
    Robust to word reordering, which a sequence ratio is not."""
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def seq_ratio(a: str, b: str) -> float:
    """difflib character-sequence similarity in [0,1] (catches typos/substrings)."""
    return difflib.SequenceMatcher(None, _norm(a), _norm(b)).ratio()


def fuzzy_score(a: str, b: str) -> float:
    """Combined similarity: the better of token-set overlap, difflib sequence ratio,
    and a containment score, so 'USB device VID_0951' matches a rubric item that is a
    superset/subset of those tokens (the common case: a terse finding vs. a verbose
    rubric line, or vice versa)."""
    ts = token_set_ratio(a, b)
    sq = seq_ratio(a, b)
    ta, tb = _tokens(a), _tokens(b)
    contain = 0.0
    if ta and tb:
        smaller, larger = (ta, tb) if len(ta) <= len(tb) else (tb, ta)
        contain = len(smaller & larger) / len(smaller)   # how much of the smaller side is covered
    return max(ts, sq, 0.9 * contain)


def best_match(text: str, candidates: list[str]) -> tuple[int, float]:
    """Index + score of the best-matching candidate for `text` (-1, 0.0 if none)."""
    best_i, best_s = -1, 0.0
    for i, c in enumerate(candidates):
        s = fuzzy_score(text, c)
        if s > best_s:
            best_i, best_s = i, s
    return best_i, best_s


# ---------------------------------------------------------------------------
# Schema-shape helpers — tolerate both string and object rubric items, and a
# couple of legacy finding shapes, so the scorer is robust to schema drift.
# ---------------------------------------------------------------------------
def rubric_item_phrasings(item: Any) -> list[str]:
    """Acceptable phrasings of one rubric item (rubric_item OR timeline_item).
    Returns canonical text first, then any aliases; for timeline objects, the
    timestamp is folded into the canonical text so it can match."""
    if isinstance(item, str):
        return [item] if item.strip() else []
    if isinstance(item, dict):
        canon = item.get("value") or item.get("event") or ""
        ts = item.get("timestamp")
        if ts and canon and ts not in canon:
            canon = f"{ts} {canon}"
        out = [canon] if canon and canon.strip() else []
        out += [a for a in (item.get("aliases") or []) if isinstance(a, str) and a.strip()]
        return out
    return []


def rubric_buckets(rubric: dict) -> dict[str, list[list[str]]]:
    """Each bucket -> list of items, each item being its list of acceptable phrasings."""
    out: dict[str, list[list[str]]] = {}
    for b in EVIDENCE_BUCKETS:
        items = []
        for raw in (rubric.get(b) or []):
            phr = rubric_item_phrasings(raw)
            if phr:
                items.append(phr)
        out[b] = items
    return out


def rubric_attack(rubric: dict) -> tuple[str, list[str], list[str]]:
    """(primary category, secondary categories, attack-type alias phrasings)."""
    at = rubric.get("attack_type")
    if isinstance(at, dict):
        cat = str(at.get("category", "")).strip()
        sec = [str(s).strip() for s in (at.get("secondary_categories") or []) if str(s).strip()]
        aliases = [str(a) for a in (at.get("aliases") or []) if str(a).strip()]
    else:
        # Legacy/flat form: attack_type is a plain string.
        cat = str(at or "").strip()
        sec = [str(s).strip() for s in (rubric.get("secondary_categories") or []) if str(s).strip()]
        aliases = [str(a) for a in (rubric.get("attack_type_aliases") or []) if str(a).strip()]
    if cat and cat not in aliases:
        aliases = [cat] + aliases
    return cat, sec, aliases


def findings_classification(findings: dict) -> tuple[str, list[str], str, str]:
    """(primary category, secondary categories, confidence, rationale) from a findings doc.
    Tolerates the structured attack_type_classification object and a flat attack_type string."""
    cl = findings.get("attack_type_classification")
    if isinstance(cl, dict):
        cat = str(cl.get("category", "")).strip()
        sec = [str(s).strip() for s in (cl.get("secondary_categories") or []) if str(s).strip()]
        conf = str(cl.get("confidence", "")).strip()
        rationale = str(cl.get("rationale", "")).strip()
        return cat, sec, conf, rationale
    # Legacy/flat form: attack_type as a plain string, optional category.
    cat = str(findings.get("category", "")).strip()
    flat_type = str(findings.get("attack_type", "")).strip()
    return cat, [], "", flat_type


# ---------------------------------------------------------------------------
# Findings helpers — provenance / hallucination detection.
# ---------------------------------------------------------------------------
def _ep_strings(ep: Any) -> list[str]:
    """All non-empty backing strings carried by an evidence_pointer, across shapes.
    For the schema object shape, the load-bearing field is literal_cited (the verbatim
    quote that proves the claim) — artifact/offset alone are NOT backing."""
    out: list[str] = []
    if ep is None:
        return out
    if isinstance(ep, str):
        if ep.strip():
            out.append(ep.strip())
    elif isinstance(ep, list):
        out += [x.strip() for x in ep if isinstance(x, str) and x.strip()]
    elif isinstance(ep, dict):
        lit = ep.get("literal_cited")
        if isinstance(lit, str) and lit.strip():
            out.append(lit.strip())
        elif "literal_cited" not in ep:
            # No schema literal field -> fall back to any non-empty string value.
            out += [v.strip() for v in ep.values() if isinstance(v, str) and v.strip()]
    return out


def is_backed(evidence_pointer: Any) -> bool:
    """True iff the finding carries a real provenance backing (a verbatim literal).
    Empty string / whitespace / empty list / null / object with no literal_cited => UNBACKED
    => counted as a hallucination."""
    return bool(_ep_strings(evidence_pointer))


def finding_text(f: dict) -> str:
    return str(f.get("claim", "")).strip()


# ---------------------------------------------------------------------------
# Core scoring.
# ---------------------------------------------------------------------------
def score_classification(findings: dict, rubric: dict) -> dict:
    """Exact category match vs the 24, secondary-category overlap, and sub-type/alias match."""
    pred_cat, pred_sec, pred_conf, pred_rationale = findings_classification(findings)
    truth_cat, truth_sec, truth_aliases = rubric_attack(rubric)

    # Canonicalize both onto the 24 (defends against minor whitespace/punctuation drift).
    def canon(c: str) -> str:
        if c in CATEGORIES_24:
            return c
        i, s = best_match(c, CATEGORIES_24)
        return CATEGORIES_24[i] if (i >= 0 and s >= 0.6) else c

    pred_canon = canon(pred_cat) if pred_cat else ""
    truth_canon = canon(truth_cat) if truth_cat else ""
    category_match = bool(pred_canon) and pred_canon == truth_canon

    # Secondary-category overlap (partial credit on multi-stage incidents): does the agent name
    # the truth primary among its secondaries, or vice versa, or any shared secondary?
    pred_all = {pred_canon, *(canon(c) for c in pred_sec)} - {""}
    truth_all = {truth_canon, *(canon(c) for c in truth_sec)} - {""}
    secondary_overlap = bool(pred_all & truth_all)

    # Sub-type/alias match: the agent has no free-form type field, so we score its rationale
    # (and, in legacy docs, its flat attack_type) against the rubric's accepted phrasings.
    subtype_text = pred_rationale
    _, subtype_score = best_match(subtype_text, truth_aliases) if truth_aliases else (-1, 0.0)
    subtype_match = subtype_score >= DEFAULT_MATCH_THRESHOLD

    return {
        "predicted_category": pred_cat,
        "predicted_category_canonical": pred_canon,
        "predicted_secondary": pred_sec,
        "predicted_confidence": pred_conf,
        "truth_category": truth_cat,
        "truth_category_canonical": truth_canon,
        "truth_category_in_24": truth_canon in CATEGORIES_24,
        "category_match": bool(category_match),
        "secondary_overlap": secondary_overlap,
        "subtype_similarity": round(subtype_score, 4),
        "subtype_match": bool(subtype_match),
    }


def score_evidence(findings: dict, rubric: dict, threshold: float) -> dict:
    """Key-evidence recall/precision/F1 + false-positive rate, over BACKED findings only.

    A backed finding 'hits' a rubric item if fuzzy_score (against any of the item's accepted
    phrasings) >= threshold. Each rubric item is matched at most once and each finding credits at
    most one item (greedy by descending score) so neither side double-counts. A backed finding that
    hits no item is a false positive. Hallucinated (unbacked) findings are excluded here and scored
    separately. A finding is matched against ALL buckets (the structured finding has no 'kind')."""
    buckets = rubric_buckets(rubric)                       # bucket -> [ [phrasings], ... ]
    total_items = sum(len(v) for v in buckets.values())

    all_findings = list(findings.get("findings") or [])
    backed = [f for f in all_findings if is_backed(f.get("evidence_pointer"))]

    matched: dict[str, set[int]] = {b: set() for b in buckets}
    candidates: list[tuple[float, int, str, int]] = []
    for fi, f in enumerate(backed):
        text = finding_text(f)
        if not text:
            continue
        for bucket, items in buckets.items():
            for idx, phrasings in enumerate(items):
                s = max((fuzzy_score(text, p) for p in phrasings), default=0.0)
                if s >= threshold:
                    candidates.append((s, fi, bucket, idx))
    candidates.sort(key=lambda t: t[0], reverse=True)      # greedy: assign strongest matches first

    finding_hit: dict[int, tuple[str, int, float]] = {}
    for s, fi, bucket, idx in candidates:
        if idx in matched[bucket] or fi in finding_hit:
            continue
        matched[bucket].add(idx)
        finding_hit[fi] = (bucket, idx, s)

    recalled = sum(len(v) for v in matched.values())
    n_backed = len(backed)
    true_positive = len(finding_hit)
    false_positive = n_backed - true_positive

    recall = (recalled / total_items) if total_items else 0.0
    precision = (true_positive / n_backed) if n_backed else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fp_rate = (false_positive / n_backed) if n_backed else 0.0

    per_bucket, missed = {}, {}
    for b, items in buckets.items():
        per_bucket[b] = {
            "matched": len(matched[b]),
            "total": len(items),
            "recall": round((len(matched[b]) / len(items)) if items else 0.0, 4),
        }
        missed[b] = [items[i][0] for i in range(len(items)) if i not in matched[b]]

    false_positive_findings = [finding_text(backed[fi]) for fi in range(n_backed) if fi not in finding_hit]
    return {
        "rubric_items_total": total_items,
        "rubric_items_recalled": recalled,
        "backed_findings": n_backed,
        "true_positives": true_positive,
        "false_positives": false_positive,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fp_rate, 4),
        "per_bucket": per_bucket,
        "missed_evidence": missed,
        "false_positive_findings": false_positive_findings,
    }


def score_hallucination(findings: dict) -> dict:
    """THE HEADLINE METRIC. Fraction of findings whose evidence_pointer has no verbatim backing."""
    all_findings = list(findings.get("findings") or [])
    n = len(all_findings)
    unbacked = [
        (f.get("id") or f"#{i}", finding_text(f))
        for i, f in enumerate(all_findings)
        if not is_backed(f.get("evidence_pointer"))
    ]
    rate = (len(unbacked) / n) if n else 0.0
    return {
        "total_findings": n,
        "unbacked_findings": len(unbacked),
        "hallucination_rate": round(rate, 4),
        "unbacked_list": [{"id": str(i), "claim": c} for i, c in unbacked],
    }


# ---------------------------------------------------------------------------
# Optional LLM judge — subscription only, never required. Adjudicates false positives.
# ---------------------------------------------------------------------------
JUDGE_SYSTEM = (
    "You adjudicate forensic findings against a hidden answer-key rubric. For each finding, decide if it "
    "is SUPPORTED by ANY rubric item (same fact, different wording) — true/false — and give a one-line "
    "reason. Be strict: paraphrase of a real rubric item = supported; a new claim the rubric never makes = "
    "unsupported. Return ONLY a json array: "
    '[{"index":0,"supported":true,"reason":""}, ...]'
)


def llm_adjudicate(false_positive_findings: list[str], rubric: dict) -> dict | None:
    """Ask the subscription-authed Claude Code CLI whether each FP finding is actually rubric-supported.
    Returns None if disabled/unavailable; never raises into the score path."""
    if not false_positive_findings:
        return {"adjudicated": [], "note": "no false positives to adjudicate"}
    rubric_view = {k: rubric.get(k) for k in ("attack_type", *EVIDENCE_BUCKETS)}
    user = (
        "RUBRIC (hidden answer key):\n"
        + json.dumps(rubric_view, indent=2)
        + "\n\nFINDINGS flagged as false positives (index : claim):\n"
        + "\n".join(f"{i} : {c}" for i, c in enumerate(false_positive_findings))
    )
    env = os.environ.copy()
    # SUBSCRIPTION ONLY: a set ANTHROPIC_API_KEY silently overrides OAuth into metered billing — drop it.
    if env.pop("ANTHROPIC_API_KEY", None) is not None:
        print("  (unset ANTHROPIC_API_KEY for judge call -> subscription auth)", file=sys.stderr)
    cmd = [
        JUDGE_AGENT, "-p", user, "--model", JUDGE_MODEL,
        "--output-format", "json", "--append-system-prompt", JUDGE_SYSTEM, *JUDGE_ARGS,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=300)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"  (judge unavailable: {e}) — skipping LLM adjudication", file=sys.stderr)
        return None
    if r.returncode != 0:
        print(f"  (judge exit {r.returncode}: {r.stderr[:200]}) — skipping", file=sys.stderr)
        return None
    raw = r.stdout
    try:                                     # claude --output-format json wraps the text in .result
        raw = json.loads(raw).get("result", raw)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\[.*\]", raw, re.S)
    if not m:
        return None
    try:
        verdicts = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    rescued = [v for v in verdicts if isinstance(v, dict) and v.get("supported")]
    return {"adjudicated": verdicts, "rescued_count": len(rescued)}


# ---------------------------------------------------------------------------
# Assembly + scorecard rendering.
# ---------------------------------------------------------------------------
def build_score(findings: dict, rubric: dict, threshold: float) -> dict:
    cls = score_classification(findings, rubric)
    ev = score_evidence(findings, rubric, threshold)
    hal = score_hallucination(findings)
    return {
        "case_id": findings.get("case_id") or rubric.get("case_id") or "",
        "match_threshold": threshold,
        "classification": cls,
        "evidence": ev,
        "hallucination": hal,
        "headline": {
            "category_match": cls["category_match"],
            "subtype_match": cls["subtype_match"],
            "evidence_recall": ev["recall"],
            "evidence_f1": ev["f1"],
            "false_positive_rate": ev["false_positive_rate"],
            "hallucination_rate": hal["hallucination_rate"],
        },
    }


def run(findings: dict, rubric: dict, threshold: float, judge: bool) -> dict:
    score = build_score(findings, rubric, threshold)
    if judge:
        verdict = llm_adjudicate(score["evidence"]["false_positive_findings"], rubric)
        if verdict is not None:
            score["judge"] = verdict
    return score


def _bar(x: float, width: int = 24) -> str:
    n = max(0, min(width, round(x * width)))
    return "[" + "#" * n + "-" * (width - n) + "]"


def render_scorecard(score: dict) -> str:
    cls, ev, hal = score["classification"], score["evidence"], score["hallucination"]
    ck = lambda b: "PASS" if b else "MISS"
    L = []
    L.append("=" * 64)
    L.append(f" PROTOCOL SIFT — BLIND-INVESTIGATION SCORECARD   case: {score['case_id'] or '(unnamed)'}")
    L.append("=" * 64)
    L.append("")
    L.append(" 1. ATTACK-TYPE CLASSIFICATION  (vs the 24 on-box categories)")
    L.append(f"      category  : {ck(cls['category_match'])}")
    L.append(f"                  pred='{cls['predicted_category_canonical'] or cls['predicted_category']}'")
    L.append(f"                  truth='{cls['truth_category_canonical'] or cls['truth_category']}'")
    if cls["predicted_secondary"]:
        L.append(f"      secondary : overlap={ck(cls['secondary_overlap'])}  pred={cls['predicted_secondary']}")
    L.append(f"      sub-type  : {ck(cls['subtype_match'])}  (alias sim {cls['subtype_similarity']:.2f})")
    if not cls["truth_category_in_24"]:
        L.append("                  WARNING: rubric category is not one of the 24 on-box categories.")
    L.append("")
    L.append(" 2. KEY-EVIDENCE RECALL (fuzzy / token-set match)")
    L.append(f"      recall    {ev['recall']:.2f} {_bar(ev['recall'])}  "
             f"({ev['rubric_items_recalled']}/{ev['rubric_items_total']} rubric items)")
    L.append(f"      precision {ev['precision']:.2f} {_bar(ev['precision'])}")
    L.append(f"      F1        {ev['f1']:.2f} {_bar(ev['f1'])}")
    for b, d in ev["per_bucket"].items():
        if d["total"]:
            L.append(f"        - {b:<26} {d['matched']}/{d['total']}  (recall {d['recall']:.2f})")
    L.append("")
    L.append(" 3. FALSE-POSITIVE RATE (backed findings with no rubric support)")
    L.append(f"      rate {ev['false_positive_rate']:.2f} {_bar(ev['false_positive_rate'])}  "
             f"({ev['false_positives']}/{ev['backed_findings']} backed findings)")
    L.append("")
    L.append(" 4. HALLUCINATION RATE  <<< HEADLINE  (findings with no verbatim backing)")
    L.append(f"      rate {hal['hallucination_rate']:.2f} {_bar(hal['hallucination_rate'])}  "
             f"({hal['unbacked_findings']}/{hal['total_findings']} findings unbacked)")
    if hal["unbacked_list"]:
        L.append("      unbacked claims (auto-flagged hallucinations):")
        for u in hal["unbacked_list"][:10]:
            L.append(f"        ! [{u['id']}] {u['claim'][:70]}")
        if len(hal["unbacked_list"]) > 10:
            L.append(f"        ... +{len(hal['unbacked_list']) - 10} more")
    if ev["false_positive_findings"]:
        L.append("")
        L.append("   unsupported (false-positive) findings:")
        for c in ev["false_positive_findings"][:10]:
            L.append(f"        ? {c[:70]}")
    missed_flat = [f"{b}: {m}" for b, items in ev["missed_evidence"].items() for m in items]
    if missed_flat:
        L.append("")
        L.append("   missed rubric evidence (not found by the agent):")
        for m in missed_flat[:12]:
            L.append(f"        - {m[:70]}")
        if len(missed_flat) > 12:
            L.append(f"        ... +{len(missed_flat) - 12} more")
    if "judge" in score:
        j = score["judge"]
        rc = j.get("rescued_count", 0) if isinstance(j, dict) else 0
        L.append("")
        L.append(f"   LLM judge (subscription): rescued {rc} false-positive(s) as rubric-supported")
    L.append("")
    L.append("=" * 64)
    return "\n".join(L)


# ---------------------------------------------------------------------------
# I/O + CLI.
# ---------------------------------------------------------------------------
def _load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# --- self-test (tiny mock findings + rubric; ZERO real evidence, no LLM) ----
def selftest() -> int:
    rubric = {
        "schema_version": "1.0",
        "case_id": "mock-leakage",
        "source": "mock — selftest only",
        "attack_type": {
            "category": "Insider Threat, Fraud & Data Theft",
            "secondary_categories": ["Windows Artifacts - Execution & User Activity"],
            "aliases": ["insider data theft / IP exfiltration via USB", "data leakage", "insider exfiltration"],
        },
        "key_artifacts": [
            "setupapi.dev.log USB mass-storage install record",
            {"value": "LNK file pointing to E:\\confidential\\plans.xlsx",
             "aliases": ["plans.xlsx.lnk target on removable drive E"]},
            "SYSTEM hive USBSTOR device VID_0951&PID_1666",
        ],
        "key_iocs": [
            "USB serial 0951aabbccdd",
            "exfil file plans.xlsx",
        ],
        "timeline_events": [
            {"timestamp": "2011-03-12T04:10Z", "event": "USB device first connected"},
            "2011-03-12 04:18Z plans.xlsx copied to E:",
        ],
        "actor_accounts": [
            {"value": "insider account jsmith", "aliases": ["user jsmith", "employee John Smith"]},
        ],
        "exfil_or_encryption_facts": [
            "plans.xlsx exfiltrated to USB removable media (drive E)",
        ],
    }
    findings = {
        "schema_version": "1.0",
        "case_id": "mock-leakage",
        "attack_type_classification": {
            "category": "Insider Threat, Fraud & Data Theft",
            "secondary_categories": ["Windows Artifacts - Execution & User Activity"],
            "confidence": "confirmed",
            "rationale": "Insider exfiltration of plans.xlsx to a USB removable drive; supported by F-001..F-004.",
            "supporting_finding_ids": ["F-001", "F-002", "F-003", "F-004"],
        },
        "findings": [
            {"id": "F-001",
             "claim": "setupapi.dev.log shows a USB mass storage device install record",
             "tool_used": "RECmd", "confidence": "confirmed",
             "evidence_pointer": {"artifact": "SYSTEM hive", "offset_or_row": "USBSTOR\\Disk row 14",
                                  "literal_cited": "USBSTOR VID_0951&PID_1666 mass storage installed"},
             "sources": [{"tool": "RECmd", "artifact": "SYSTEM"}]},
            {"id": "F-002",
             "claim": "USB device serial 0951aabbccdd identified on the host",
             "tool_used": "RECmd", "confidence": "confirmed",
             "evidence_pointer": {"artifact": "SYSTEM hive", "offset_or_row": "row 14",
                                  "literal_cited": "0951aabbccdd&0"},
             "sources": [{"tool": "RECmd", "artifact": "SYSTEM"}]},
            {"id": "F-003",
             "claim": "USB device first connected 2011-03-12 04:10Z",
             "tool_used": "EvtxECmd", "confidence": "confirmed",
             "evidence_pointer": {"artifact": "Security.evtx", "offset_or_row": "evt 6416",
                                  "literal_cited": "2011-03-12 04:10:02Z PnP device added"},
             "sources": [{"tool": "EvtxECmd", "artifact": "Security.evtx"}]},
            {"id": "F-004",
             "claim": "file plans.xlsx copied to removable drive E (LNK target)",
             "tool_used": "LECmd", "confidence": "confirmed",
             "evidence_pointer": {"artifact": "plans.xlsx.lnk", "offset_or_row": "0",
                                  "literal_cited": "TargetIDList E:\\confidential\\plans.xlsx"},
             "sources": [{"tool": "LECmd", "artifact": "plans.xlsx.lnk"}]},
            # F-005: backed but NOT in rubric -> false positive.
            {"id": "F-005",
             "claim": "outbound C2 beacon to 8.8.8.8 every 60 seconds",
             "tool_used": "tcpdump", "confidence": "inferred",
             "evidence_pointer": {"artifact": "capture.pcap", "offset_or_row": "pkt 9001",
                                  "literal_cited": "8.8.8.8.443 > host beacon"},
             "sources": [{"tool": "tcpdump", "artifact": "capture.pcap"}]},
            # F-006: UNBACKED -> hallucination (empty literal_cited).
            {"id": "F-006",
             "claim": "attacker also wiped the Windows event log to cover tracks",
             "tool_used": "EvtxECmd", "confidence": "inferred",
             "evidence_pointer": {"artifact": "Security.evtx", "offset_or_row": "", "literal_cited": ""},
             "sources": [{"tool": "EvtxECmd", "artifact": "Security.evtx"}]},
            # F-007: UNBACKED -> hallucination (no evidence_pointer at all).
            {"id": "F-007",
             "claim": "data was emailed to a personal Gmail account",
             "tool_used": "libpff", "confidence": "inferred",
             "evidence_pointer": {},
             "sources": [{"tool": "libpff", "artifact": "outlook.pst"}]},
        ],
    }

    score = run(findings, rubric, DEFAULT_MATCH_THRESHOLD, judge=False)
    print(render_scorecard(score))
    print("\n--- selftest assertions ---")

    failures: list[str] = []

    def check(name: str, cond: bool, got: Any = None) -> None:
        status = "ok" if cond else "FAIL"
        print(f"  [{status}] {name}" + ("" if cond else f"  (got {got!r})"))
        if not cond:
            failures.append(name)

    cls, ev, hal = score["classification"], score["evidence"], score["hallucination"]
    check("category matches Insider Threat...",
          cls["category_match"] and cls["predicted_category_canonical"] == "Insider Threat, Fraud & Data Theft",
          cls["predicted_category_canonical"])
    check("truth category is one of the 24", cls["truth_category_in_24"], cls["truth_category_canonical"])
    check("secondary-category overlap detected", cls["secondary_overlap"] is True)
    check("sub-type/alias matches via rationale", cls["subtype_match"], cls["subtype_similarity"])
    check("total findings == 7", hal["total_findings"] == 7, hal["total_findings"])
    check("exactly 2 hallucinations (F-006,F-007)", hal["unbacked_findings"] == 2, hal["unbacked_findings"])
    check("hallucination_rate == 2/7", abs(hal["hallucination_rate"] - 2 / 7) < 1e-4, hal["hallucination_rate"])
    check("5 backed findings", ev["backed_findings"] == 5, ev["backed_findings"])
    check("exactly 1 false positive (F-005)", ev["false_positives"] == 1, ev["false_positives"])
    check("false_positive_rate == 1/5", abs(ev["false_positive_rate"] - 1 / 5) < 1e-4, ev["false_positive_rate"])
    check("4 true positives", ev["true_positives"] == 4, ev["true_positives"])
    check("precision == 4/5", abs(ev["precision"] - 4 / 5) < 1e-4, ev["precision"])
    check("recall >= 0.40 (>=4 of 9 rubric items)", ev["recall"] >= 0.40, ev["recall"])
    check("rubric items total == 9", ev["rubric_items_total"] == 9, ev["rubric_items_total"])

    # Negative control: a no-backing finding set must be 100% hallucination.
    empty = {"attack_type_classification": {"category": "Endpoint / Disk & File System"},
             "findings": [{"id": "X", "claim": "c",
                           "evidence_pointer": {"artifact": "a", "offset_or_row": "", "literal_cited": ""}}]}
    h2 = score_hallucination(empty)
    check("all-unbacked set -> hallucination_rate 1.0", h2["hallucination_rate"] == 1.0, h2["hallucination_rate"])

    # is_backed unit checks (across shapes).
    check("is_backed empty literal -> False",
          is_backed({"artifact": "a", "offset_or_row": "5", "literal_cited": ""}) is False)
    check("is_backed real literal -> True",
          is_backed({"artifact": "a", "offset_or_row": "5", "literal_cited": "x"}) is True)
    check("is_backed('') is False", is_backed("") is False)
    check("is_backed(None) is False", is_backed(None) is False)
    check("is_backed([]) is False", is_backed([]) is False)
    check("is_backed({}) is False", is_backed({}) is False)
    check("is_backed('x') is True", is_backed("x") is True)
    check("is_backed(['a']) is True", is_backed(["a"]) is True)

    # Negative control: wrong category must NOT match.
    wrong = {"attack_type_classification": {"category": "Network Forensics"}, "findings": []}
    cwrong = score_classification(wrong, rubric)
    check("wrong category -> no match", cwrong["category_match"] is False)

    if failures:
        print(f"\nSELFTEST FAILED: {len(failures)} assertion(s) -> {failures}")
        return 1
    print("\nSELFTEST PASSED")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Score a blind Protocol SIFT investigation (findings.json) against a hidden rubric.json.",
        epilog="BUILD-TIME EVAL TOOLING ONLY — not hackathon-submission code. SUBSCRIPTION ONLY for --judge.",
    )
    ap.add_argument("-f", "--findings", help="path to findings.json (findings.schema.json shape)")
    ap.add_argument("-r", "--rubric", help="path to rubric.json (rubric.schema.json shape)")
    ap.add_argument("-o", "--out", default="score.json", help="output score JSON path (default: score.json)")
    ap.add_argument("-t", "--threshold", type=float, default=DEFAULT_MATCH_THRESHOLD,
                    help=f"fuzzy match threshold 0..1 (default {DEFAULT_MATCH_THRESHOLD})")
    ap.add_argument("--judge", action="store_true",
                    help="adjudicate false positives with Claude (subscription CLI; unsets ANTHROPIC_API_KEY)")
    ap.add_argument("--quiet", action="store_true", help="suppress the human scorecard (still writes JSON)")
    ap.add_argument("--selftest", action="store_true", help="run on tiny mock data and exit (no real data, no LLM)")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.findings or not args.rubric:
        ap.error("--findings and --rubric are required (or use --selftest)")

    findings = _load_json(args.findings)
    rubric = _load_json(args.rubric)
    score = run(findings, rubric, args.threshold, judge=args.judge)

    if not args.quiet:
        print(render_scorecard(score))
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(score, fh, indent=2)
        fh.write("\n")
    if not args.quiet:
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

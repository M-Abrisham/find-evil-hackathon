#!/usr/bin/env python3
"""Failure-rate AGGREGATOR for the Rule-Change Diagnosis Protocol (Stage 1.4-1.6).

Operator/scoring-layer tool (runs on josh-pc, NEVER inside the sealed jail). Reads
N per-round score JSONs for one (case, arm), applies a FROZEN binary FAIL predicate
per round, drops INVALID rounds first, then computes per-arm f/n with a Wilson 95%
score interval, a two-proportion z test (sift-vs-bare and/or pre-vs-post), and a
same-signature clustering check. Classifies the failure as SYSTEMATIC / GREY /
STOCHASTIC against an empirical noise floor. Emits a per-case JSON report plus a
human summary.

STDLIB ONLY (math for Wilson / normal-approx). No third-party deps.

----------------------------------------------------------------------------------
INPUT SHAPES (consumes REAL scorer output; recon-verified):

  scorer.py  --json  -> stdout, JSON block after a literal "--- JSON ---" line:
      {"cases":[CaseResult.to_dict()...], "aggregate":{...}}
    CaseResult.to_dict() fields used:
      case_id, findable_recall (float|None), failures:[{type,value}],
      fabrications:[{type,value}], fabrication_count, verdict (one of
      "found"|"not_emitted"), verdict_expected, mitre_present:{code:bool},
      mitre_found, mitre_total
    NOTE: scorer.py has NO file-per-round writer. This tool's loader accepts EITHER
    a saved {"cases":[...],"aggregate":...} JSON file OR raw scorer stdout (it finds
    the "--- JSON ---" delimiter and parses the block after it). When a file holds a
    single CaseResult dict (an adapter wrote one round = one case), that is accepted too.

  score.py  -o score.json  -> the per-round file the blind path emits:
      {case_id, classification:{category_match:bool,...},
       evidence:{per_bucket:{<b>:{matched,total,recall}}, missed_evidence:{...},
                 false_positive_findings:[str], false_positive_rate, recall, ...},
       hallucination:{unbacked_findings:int, hallucination_rate, unbacked_list:[{id,claim}]},
       headline:{category_match, subtype_match, evidence_recall, false_positive_rate,
                 hallucination_rate}}

  presence_scorer.py  to_dict():
      {report_id, passed:bool, has_insufficient_evidence:bool,
       insufficient_evidence_count:int, has_coverage_gaps_section:bool, missing_fields:[...]}

The schema kind is auto-detected per file (presence of "classification"/"headline"
=> score.py; "iocs"/"findable_recall"/"verdict" => scorer.py CaseResult; "passed"
+ "has_insufficient_evidence" => presence).

----------------------------------------------------------------------------------
EXPORT/GLOB CONVENTION (recon): the sealed export BASE is
  <CASE_ID>_<ARM>_round-<N>
with sidecars <BASE>.findings.json / .manifest.json / .agent.stderr / .summary.md.
The operator scores each round LOCALLY into one of:
  <BASE>.score.json     (score.py -o)
  <BASE>.scorer.json    (captured scorer.py "--- JSON ---" block)
  <BASE>.presence.json  (presence to_dict)
This aggregator globs <CASE>_<ARM>_round-*.{score,scorer,presence}.json, groups by
(case,arm,round), and (when given the sidecars) applies the Stage-1.3(a) INVALID-RUN
filter using <BASE>.summary.md / .agent.stderr / a .network-needed marker.
"""
from __future__ import annotations

import argparse
import glob
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional

# =============================================================================
# Statistics (stdlib math only).
# =============================================================================
# Two-sided z for 95% CI. Use a fixed constant so we depend on nothing.
Z_95 = 1.959963984540054


def wilson_interval(f: int, n: int, z: float = Z_95) -> tuple[Optional[float], Optional[float]]:
    """Wilson score interval for a binomial proportion.

    Behaves at f==0 and f==n and small n (unlike the normal approximation).
    Returns (lo, hi). For n==0 returns (None, None).
    """
    if n <= 0:
        return (None, None)
    phat = f / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (phat + z2 / (2 * n)) / denom
    margin = (z * math.sqrt((phat * (1 - phat) + z2 / (4 * n)) / n)) / denom
    lo = center - margin
    hi = center + margin
    # Clamp to [0,1] for floating dust.
    return (max(0.0, lo), min(1.0, hi))


def two_proportion_z(f1: int, n1: int, f2: int, n2: int) -> dict[str, Any]:
    """Two-proportion z test on (p1 - p2). Pooled SE for the test statistic,
    unpooled SE for the difference CI (standard convention).

    Returns a dict with diff, z, two-sided p-value, and the 95% CI of the
    difference. p1 is treated as arm 1 (e.g. sift / post), p2 as arm 2
    (e.g. bare / pre). Returns nulls when either n is 0.
    """
    if n1 <= 0 or n2 <= 0:
        return {
            "p1": (f1 / n1) if n1 else None,
            "p2": (f2 / n2) if n2 else None,
            "diff": None, "z": None, "p_value": None,
            "diff_ci_lo": None, "diff_ci_hi": None,
            "ci_excludes_zero": None,
        }
    p1 = f1 / n1
    p2 = f2 / n2
    diff = p1 - p2
    # Pooled SE for the hypothesis test (H0: p1 == p2).
    p_pool = (f1 + f2) / (n1 + n2)
    se_pool = math.sqrt(p_pool * (1 - p_pool) * (1.0 / n1 + 1.0 / n2))
    if se_pool == 0:
        z = 0.0
    else:
        z = diff / se_pool
    p_value = 2.0 * (1.0 - _norm_cdf(abs(z)))
    # Unpooled SE for the difference CI.
    se_diff = math.sqrt(p1 * (1 - p1) / n1 + p2 * (1 - p2) / n2)
    ci_lo = diff - Z_95 * se_diff
    ci_hi = diff + Z_95 * se_diff
    return {
        "p1": p1, "p2": p2,
        "diff": diff, "z": z, "p_value": p_value,
        "diff_ci_lo": ci_lo, "diff_ci_hi": ci_hi,
        "ci_excludes_zero": (ci_lo > 0.0) or (ci_hi < 0.0),
    }


def _norm_cdf(x: float) -> float:
    """Standard normal CDF via the error function (stdlib math.erf)."""
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


# =============================================================================
# Round record + schema detection.
# =============================================================================
SCHEMA_SCORER = "scorer"      # scorer.py CaseResult
SCHEMA_SCORE = "score"        # score.py blind findings scorer
SCHEMA_PRESENCE = "presence"  # presence_scorer.py R5 gate

# Round-key parse from the export BASE: <CASE>_<ARM>_round-<N>[.suffix].json
_BASE_RE = re.compile(
    r"^(?P<case>.+?)_(?P<arm>[A-Za-z0-9-]+)_round-(?P<round>\d+)"
    r"(?:\.(?P<kind>score|scorer|presence))?\.json$"
)


@dataclass
class RoundRecord:
    case_id: str
    arm: str
    round_n: int
    path: str
    schema: str
    payload: dict           # the parsed score dict (one round = one case)
    # Resolved after FAIL predicate runs:
    valid: bool = True
    invalid_reason: Optional[str] = None
    failed: Optional[bool] = None   # None => excluded from denominator
    signature: Optional[str] = None


def detect_schema(payload: dict) -> str:
    if "classification" in payload or "headline" in payload:
        return SCHEMA_SCORE
    if "passed" in payload and "has_insufficient_evidence" in payload:
        return SCHEMA_PRESENCE
    if "findable_recall" in payload or "iocs" in payload or "verdict" in payload:
        return SCHEMA_SCORER
    raise ValueError("unrecognized score schema (no classification/headline, "
                     "no passed+has_insufficient_evidence, no findable_recall/iocs/verdict)")


def _extract_scorer_block(raw: str) -> dict:
    """Pull the JSON block after a literal '--- JSON ---' line from scorer.py stdout."""
    marker = "--- JSON ---"
    idx = raw.find(marker)
    if idx == -1:
        raise ValueError("no '--- JSON ---' delimiter in scorer stdout")
    block = raw[idx + len(marker):]
    return json.loads(block)


def load_round_payloads(path: str) -> list[dict]:
    """Load one file into one-or-more per-case score dicts.

    Handles: a single score dict; a scorer.py {"cases":[...],"aggregate":...}
    bundle (returns each CaseResult); and raw scorer stdout containing the
    '--- JSON ---' delimiter.
    """
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    # Raw scorer stdout?
    if "--- JSON ---" in text and not text.lstrip().startswith(("{", "[")):
        obj = _extract_scorer_block(text)
    else:
        obj = json.loads(text)
    if isinstance(obj, dict) and "cases" in obj and "aggregate" in obj:
        return list(obj["cases"])
    if isinstance(obj, list):
        return obj
    return [obj]


# =============================================================================
# Stage 1.3(a) INVALID-RUN filter (sidecar-driven, best-effort).
# =============================================================================
NONE_CAPTURED_RE = re.compile(r"\(none captured\)", re.IGNORECASE)


def invalid_reason_for(base: str, score_dir: str) -> Optional[str]:
    """Inspect the export sidecars for a BASE to decide if the round is a NON-SAMPLE.

    Returns a reason string when the round must be EXCLUDED from the denominator,
    else None. Best-effort: missing sidecars => treated as valid (the score file
    being present is itself evidence the round produced content).
    """
    net_marker = os.path.join(score_dir, f"{base}.network-needed")
    if os.path.exists(net_marker) or os.path.exists(
        os.path.join(score_dir, "needs-network", base)
    ):
        return "needs-network marker present (case demanded egress)"
    summary = os.path.join(score_dir, f"{base}.summary.md")
    stderr = os.path.join(score_dir, f"{base}.agent.stderr")
    has_stderr = os.path.exists(stderr) and os.path.getsize(stderr) > 0
    if os.path.exists(summary):
        try:
            with open(summary, encoding="utf-8") as fh:
                stext = fh.read()
            if NONE_CAPTURED_RE.search(stext):
                if has_stderr:
                    return "stderr populated + summary '(none captured)' => RUN/CLI failure"
                return "summary '(none captured)' => no findings emitted"
        except OSError:
            pass
    raw = os.path.join(score_dir, f"{base}.raw.txt")
    if os.path.exists(raw):
        return "run_blind unparseable output (<out>.raw.txt present) => schema-fail"
    return None


# =============================================================================
# FROZEN FAIL PREDICATE.
# =============================================================================
# A predicate is a (dimension, target) pair. One predicate per campaign (Stage 1.3).
# Each returns (failed: bool, signature: str) where signature is the IDENTITY of the
# failure for the same-signature clustering check (Stage 1.5). A None failed means
# the round is not scorable on this dimension (excluded).
#
# Predicates are pure functions of one per-round score dict. The signature is a
# stable string so identical failures collapse to one correlated event.

def _fail_findable_recall(p: dict, **kw) -> tuple[Optional[bool], Optional[str]]:
    """scorer.py: FAIL if findable_recall < threshold (default: any missing findable
    IOC, i.e. recall < 1.0). findable_recall None => 0 findable IOCs (BAD-CASE
    signal): NOT scorable => excluded.
    Signature = the sorted set of missing findable IOCs (failures[])."""
    thr = kw.get("threshold", 1.0)
    fr = p.get("findable_recall", None)
    if fr is None:
        return (None, None)  # BAD CASE / unsupportable key — excluded, flag upstream
    failed = fr < thr
    if not failed:
        return (False, None)
    miss = p.get("failures", [])
    sig = "missing:" + ",".join(sorted(f"{m.get('type')}={m.get('value')}" for m in miss)) \
        if miss else f"recall<{thr}"
    return (True, sig)


def _fail_specific_ioc(p: dict, **kw) -> tuple[Optional[bool], Optional[str]]:
    """scorer.py: FAIL if a SPECIFIC findable IOC value is in failures[] (the canonical
    'FAIL := SID S-... in failures[]' predicate)."""
    target = kw.get("ioc_value")
    if target is None:
        raise ValueError("predicate 'specific_ioc' requires --ioc-value")
    for m in p.get("failures", []):
        if str(m.get("value")) == str(target):
            return (True, f"missing:{m.get('type')}={target}")
    return (False, None)


def _fail_verdict(p: dict, **kw) -> tuple[Optional[bool], Optional[str]]:
    """scorer.py: FAIL if verdict == 'not_emitted' (missing OR wrong-class — these are
    INDISTINGUISHABLE from this field alone; see caveat. Cross-read OTEL/parse_report_verdict
    to split structural-vs-reasoning). Signature folds in the expected class."""
    v = p.get("verdict")
    if v is None:
        return (None, None)
    failed = v != "found"
    if not failed:
        return (False, None)
    return (True, f"verdict_not_emitted(expected={p.get('verdict_expected','?')})")


def _fail_fabrication(p: dict, **kw) -> tuple[Optional[bool], Optional[str]]:
    """scorer.py: FAIL if any fabrication (Class-A unbacked IOC). Signature = the sorted
    fabricated values."""
    fabs = p.get("fabrications", [])
    cnt = p.get("fabrication_count", len(fabs))
    if not cnt:
        return (False, None)
    sig = "fabricated:" + ",".join(sorted(f"{m.get('type')}={m.get('value')}" for m in fabs)) \
        if fabs else "fabrication"
    return (True, sig)


def _fail_category(p: dict, **kw) -> tuple[Optional[bool], Optional[str]]:
    """score.py: FAIL if classification.category_match is False."""
    cls = p.get("classification")
    if not isinstance(cls, dict) or "category_match" not in cls:
        # fall back to headline
        cls = {"category_match": p.get("headline", {}).get("category_match")}
    cm = cls.get("category_match")
    if cm is None:
        return (None, None)
    if cm:
        return (False, None)
    truth = (p.get("classification", {}) or {}).get("truth_category_canonical", "?")
    pred = (p.get("classification", {}) or {}).get("predicted_category_canonical", "?")
    return (True, f"category_miss(truth={truth},pred={pred})")


def _fail_bucket_recall(p: dict, **kw) -> tuple[Optional[bool], Optional[str]]:
    """score.py: FAIL if a named evidence bucket has recall==0 (item in missed_evidence).
    Requires --bucket. Signature = the sorted missed items in that bucket."""
    bucket = kw.get("bucket")
    if bucket is None:
        raise ValueError("predicate 'bucket_recall' requires --bucket")
    ev = p.get("evidence", {})
    pb = ev.get("per_bucket", {})
    if bucket not in pb:
        return (None, None)  # bucket not scored for this round
    rec = pb[bucket].get("recall")
    if rec is None:
        return (None, None)
    if rec > 0:
        return (False, None)
    missed = ev.get("missed_evidence", {}).get(bucket, [])
    sig = f"bucket_recall0[{bucket}]:" + ",".join(sorted(str(x) for x in missed)) \
        if missed else f"bucket_recall0[{bucket}]"
    return (True, sig)


def _fail_hallucination(p: dict, **kw) -> tuple[Optional[bool], Optional[str]]:
    """score.py: FAIL if hallucination.unbacked_list non-empty (DETERMINISTIC, judge-free:
    empty/missing literal_cited => auto-hallucination). Signature = sorted unbacked claims."""
    hal = p.get("hallucination", {})
    ub = hal.get("unbacked_list", [])
    if not ub:
        # fall back to count when list absent
        n = hal.get("unbacked_findings")
        if n is None:
            return (None, None)
        return ((n > 0), ("unbacked_findings" if n > 0 else None))
    sig = "unbacked:" + ",".join(sorted(str(u.get("claim", u.get("id"))) for u in ub))
    return (True, sig)


def _fail_false_positive(p: dict, **kw) -> tuple[Optional[bool], Optional[str]]:
    """score.py: FAIL if evidence.false_positive_findings non-empty (backed-but-not-in-rubric).
    Signature = sorted FP findings."""
    fps = p.get("evidence", {}).get("false_positive_findings", [])
    if not fps:
        return (False, None)
    return (True, "fp:" + ",".join(sorted(str(x) for x in fps)))


def _fail_presence(p: dict, **kw) -> tuple[Optional[bool], Optional[str]]:
    """presence_scorer.py: FAIL if passed is False (missing INSUFFICIENT_EVIDENCE token
    and/or '## Limitations & Coverage Gaps' section). Signature = sorted missing_fields."""
    passed = p.get("passed")
    if passed is None:
        return (None, None)
    if passed:
        return (False, None)
    mf = p.get("missing_fields", [])
    sig = "presence_missing:" + ",".join(sorted(str(x) for x in mf)) if mf else "presence_fail"
    return (True, sig)


PREDICATES = {
    "findable_recall": _fail_findable_recall,
    "specific_ioc": _fail_specific_ioc,
    "verdict": _fail_verdict,
    "fabrication": _fail_fabrication,
    "category": _fail_category,
    "bucket_recall": _fail_bucket_recall,
    "hallucination": _fail_hallucination,
    "false_positive": _fail_false_positive,
    "presence": _fail_presence,
}

# Which schema each predicate expects (for a friendly mismatch error / auto-skip).
PREDICATE_SCHEMA = {
    "findable_recall": SCHEMA_SCORER,
    "specific_ioc": SCHEMA_SCORER,
    "verdict": SCHEMA_SCORER,
    "fabrication": SCHEMA_SCORER,
    "category": SCHEMA_SCORE,
    "bucket_recall": SCHEMA_SCORE,
    "hallucination": SCHEMA_SCORE,
    "false_positive": SCHEMA_SCORE,
    "presence": SCHEMA_PRESENCE,
}


# =============================================================================
# Per-arm aggregation.
# =============================================================================
@dataclass
class ArmResult:
    arm: str
    n_total: int                 # rounds discovered for this arm
    n_invalid: int               # dropped by INVALID-RUN filter
    n_unscorable: int            # predicate returned None (e.g. findable_recall None)
    n_valid: int                 # denominator
    f: int                       # failures
    p_hat: Optional[float]
    wilson_lo: Optional[float]
    wilson_hi: Optional[float]
    # Clustering (Stage 1.5):
    distinct_signatures: int
    signature_counts: dict[str, int]
    clustered_f: int             # failures collapsed to ONE per distinct signature
    clustered_wilson_lo: Optional[float]
    clustered_wilson_hi: Optional[float]
    invalid_reasons: list[str] = field(default_factory=list)
    invalid_fraction: Optional[float] = None
    invalid_overflow: bool = False  # >20% lost => rate not trustworthy

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def aggregate_arm(arm: str, rounds: list[RoundRecord]) -> ArmResult:
    n_total = len(rounds)
    invalid = [r for r in rounds if not r.valid]
    valid_rounds = [r for r in rounds if r.valid]
    # Of valid rounds, those scorable on the predicate (failed is bool):
    scorable = [r for r in valid_rounds if r.failed is not None]
    unscorable = [r for r in valid_rounds if r.failed is None]
    n_valid = len(scorable)
    fails = [r for r in scorable if r.failed]
    f = len(fails)

    lo, hi = wilson_interval(f, n_valid)

    sig_counts = Counter(r.signature for r in fails if r.signature is not None)
    distinct = len(sig_counts)
    # Clustered: collapse identical signatures to one correlated event (Stage 1.5).
    # Failures with a None signature (couldn't identify) each count individually.
    none_sig = sum(1 for r in fails if r.signature is None)
    clustered_f = distinct + none_sig
    clo, chi = wilson_interval(min(clustered_f, n_valid), n_valid)

    n_invalid = len(invalid)
    inv_frac = (n_invalid / n_total) if n_total else None

    return ArmResult(
        arm=arm,
        n_total=n_total,
        n_invalid=n_invalid,
        n_unscorable=len(unscorable),
        n_valid=n_valid,
        f=f,
        p_hat=(f / n_valid) if n_valid else None,
        wilson_lo=lo, wilson_hi=hi,
        distinct_signatures=distinct,
        signature_counts=dict(sig_counts),
        clustered_f=clustered_f,
        clustered_wilson_lo=clo, clustered_wilson_hi=chi,
        invalid_reasons=[r.invalid_reason for r in invalid if r.invalid_reason],
        invalid_fraction=inv_frac,
        invalid_overflow=(inv_frac is not None and inv_frac > 0.20),
    )


# =============================================================================
# Classification vs empirical noise floor (Stage 1.4).
# =============================================================================
def classify_vs_floor(
    arm_res: ArmResult,
    floor_hi: Optional[float],
    floor_lo: Optional[float] = None,
    decision_act_p: float = 0.20,
) -> dict[str, Any]:
    """Classify SYSTEMATIC / GREY / STOCHASTIC against the empirical floor.

    floor_hi = the noise floor's Wilson UPPER bound (the bare-arm / known-good
    dimension intrinsic jitter). If unknown, classification is INDETERMINATE
    (the operator MUST establish the floor first — Stage 1.4).
    """
    if arm_res.p_hat is None:
        return {"label": "NO_VALID_ROUNDS", "rationale": "denominator is 0"}
    if floor_hi is None:
        return {"label": "INDETERMINATE",
                "rationale": "no empirical floor supplied; establish floor first (Stage 1.4)"}
    lo, hi, p = arm_res.wilson_lo, arm_res.wilson_hi, arm_res.p_hat
    # SYSTEMATIC: Wilson LOWER bound strictly above the floor's upper bound AND p material.
    if lo is not None and lo > floor_hi and p >= decision_act_p:
        return {"label": "SYSTEMATIC",
                "rationale": f"wilson_lo {lo:.4f} > floor_hi {floor_hi:.4f} and p_hat "
                             f"{p:.4f} >= act-line {decision_act_p}"}
    # STOCHASTIC (NOISE): Wilson UPPER bound at/below the floor's upper bound.
    if hi is not None and hi <= floor_hi:
        return {"label": "STOCHASTIC",
                "rationale": f"wilson_hi {hi:.4f} <= floor_hi {floor_hi:.4f} -> noise; "
                             f"watchlist only (Class-B)"}
    # Everything else straddles the band edge.
    return {"label": "GREY",
            "rationale": f"wilson CI [{lo:.4f},{hi:.4f}] straddles floor_hi {floor_hi:.4f} "
                         f"or p_hat<{decision_act_p}; escalate N (do NOT act)"}


# =============================================================================
# Cross-arm same-signature overlap (correlation diagnostic).
# =============================================================================
def shared_signatures(arms: dict[str, ArmResult]) -> dict[str, list[str]]:
    """Signatures that recur ACROSS arms (identical missed token / wrong verdict in
    both sift and bare) — a correlated-cause hint (Stage 1.5 / 1.6 UNIVERSAL)."""
    per_arm_sigs = {a: set(r.signature_counts.keys()) for a, r in arms.items()}
    if len(per_arm_sigs) < 2:
        return {}
    sets = list(per_arm_sigs.values())
    common = set.intersection(*sets) if sets else set()
    return {"shared_across_all_arms": sorted(common)} if common else {}


# =============================================================================
# Driver.
# =============================================================================
def discover_rounds(score_dir: str, case_filter: Optional[str] = None,
                    explicit_files: Optional[list[str]] = None) -> list[RoundRecord]:
    files: list[str] = []
    if explicit_files:
        files = explicit_files
    else:
        for kind in ("score", "scorer", "presence"):
            files += glob.glob(os.path.join(score_dir, f"*_round-*.{kind}.json"))
        # Also bare <BASE>.json (no kind suffix).
        files += [f for f in glob.glob(os.path.join(score_dir, "*_round-*.json"))
                  if not re.search(r"\.(score|scorer|presence)\.json$", f)]
    files = sorted(set(files))
    records: list[RoundRecord] = []
    for path in files:
        fname = os.path.basename(path)
        m = _BASE_RE.match(fname)
        if not m:
            continue
        case_id = m.group("case")
        arm = m.group("arm")
        round_n = int(m.group("round"))
        if case_filter and case_id != case_filter:
            continue
        kind = m.group("kind") or ""
        base = fname[: -len(".json")]
        if kind:
            base = base[: -(len(kind) + 1)]  # strip ".<kind>"
        try:
            payloads = load_round_payloads(path)
        except (ValueError, json.JSONDecodeError) as e:
            # Unparseable score file = schema-fail; record as INVALID round.
            records.append(RoundRecord(
                case_id=case_id, arm=arm, round_n=round_n, path=path,
                schema="unknown", payload={}, valid=False,
                invalid_reason=f"unparseable score file: {e}"))
            continue
        for payload in payloads:
            try:
                schema = detect_schema(payload)
            except ValueError as e:
                records.append(RoundRecord(
                    case_id=case_id, arm=arm, round_n=round_n, path=path,
                    schema="unknown", payload=payload, valid=False,
                    invalid_reason=str(e)))
                continue
            rec = RoundRecord(
                case_id=payload.get("case_id", case_id) or case_id,
                arm=arm, round_n=round_n, path=path, schema=schema, payload=payload)
            # Stage 1.3(a): sidecar-driven INVALID filter.
            reason = invalid_reason_for(base, os.path.dirname(path) or ".")
            if reason:
                rec.valid = False
                rec.invalid_reason = reason
            records.append(rec)
    return records


def apply_predicate(records: list[RoundRecord], predicate: str, **pkw) -> None:
    fn = PREDICATES[predicate]
    want_schema = PREDICATE_SCHEMA[predicate]
    for r in records:
        if not r.valid:
            continue
        if r.schema != want_schema:
            # Predicate cannot score this schema => unscorable (excluded), not a failure.
            r.failed = None
            r.signature = None
            continue
        failed, sig = fn(r.payload, **pkw)
        r.failed = failed
        r.signature = sig


def build_report(records: list[RoundRecord], predicate: str, predicate_args: dict,
                 floor_hi: Optional[float], floor_lo: Optional[float],
                 sift_arm: str, bare_arm: str,
                 decision_act_p: float) -> dict[str, Any]:
    by_arm: dict[str, list[RoundRecord]] = defaultdict(list)
    for r in records:
        by_arm[r.arm].append(r)
    arms: dict[str, ArmResult] = {a: aggregate_arm(a, rs) for a, rs in by_arm.items()}
    case_ids = sorted({r.case_id for r in records})

    arm_reports = {}
    for a, ar in arms.items():
        cls = classify_vs_floor(ar, floor_hi, floor_lo, decision_act_p)
        d = ar.to_dict()
        d["classification"] = cls
        arm_reports[a] = d

    # Two-proportion: sift-vs-bare (Stage 1.6 layer-involvement triage signal).
    cross = None
    if sift_arm in arms and bare_arm in arms:
        s, b = arms[sift_arm], arms[bare_arm]
        if s.n_valid and b.n_valid:
            tp = two_proportion_z(s.f, s.n_valid, b.f, b.n_valid)
            cross = {
                "kind": "sift_vs_bare",
                "arm1": sift_arm, "arm2": bare_arm,
                **tp,
                "interpretation": _interpret_sift_vs_bare(tp),
                "caveat": "LAYER-INVOLVEMENT TRIAGE ONLY. The bare delta bundles "
                          "{contract rules + CLAUDE.md prose + 5 skills + playbooks} as ONE "
                          "blob — it can NEVER implicate a specific rule. Confirm a clause only "
                          "via a single-artifact ablation lap (Stage 4).",
            }

    report = {
        "tool": "aggregate_failures",
        "schema_version": 1,
        "cases": case_ids,
        "predicate": {"name": predicate, "args": predicate_args},
        "floor": {"floor_hi": floor_hi, "floor_lo": floor_lo,
                  "note": "empirical noise floor Wilson UPPER bound; None => classification "
                          "INDETERMINATE (establish floor first, Stage 1.4)"},
        "decision_act_p": decision_act_p,
        "arms": arm_reports,
        "cross_arm": cross,
        "shared_signatures": shared_signatures(arms),
        "caveats": [
            "verdict 'not_emitted' collapses MISSING and WRONG-CLASS verdicts; this field "
            "alone cannot split structural (Branch-E) from reasoning (Branch-F) — cross-read "
            "OTEL/parse_report_verdict.",
            "Wilson (not normal-approx) used throughout; clustered CI collapses identical "
            "failure signatures to one correlated event (Stage 1.5) — report BOTH naive and "
            "clustered.",
            "cost (findings.json .total_cost_usd) is best-effort/absent in the export; not "
            "aggregated here.",
        ],
    }
    # Surface any >20% invalid-loss STOP condition prominently.
    overflow = [a for a, ar in arms.items() if ar.invalid_overflow]
    if overflow:
        report["STOP"] = (f"arms {overflow} lost >20% of rounds to the INVALID-RUN filter — "
                          f"harness/case unstable; DO NOT compute a content rate (Stage 1.3a).")
    return report


def _interpret_sift_vs_bare(tp: dict) -> str:
    diff = tp.get("diff")
    if diff is None:
        return "insufficient data"
    if not tp.get("ci_excludes_zero"):
        return ("UNIVERSAL: difference CI includes 0 — layer not net-distinguishable here. "
                "Does NOT exonerate the layer (identical end-rate, opposite causes possible). "
                "Route to Stage 2.")
    if diff > 0:
        return ("SIFT-WORSE: sift fails materially MORE (CI excludes 0). Triage flag that a "
                "built rule/skill/playbook MAY be hurting -> Branch-F hypothesis. Confirm only "
                "by single-artifact ablation.")
    return ("SIFT-BETTER: sift fails materially LESS. If sift still systematic -> ADD/EDIT "
            "candidate (clear Stage 2-3 first); if sift==0 -> SIFT-FIXED, positive guard evidence.")


# =============================================================================
# Human render.
# =============================================================================
def _fmt_ci(lo, hi) -> str:
    if lo is None or hi is None:
        return "n/a"
    return f"[{lo*100:.1f}%, {hi*100:.1f}%]"


def render_human(report: dict) -> str:
    L = []
    L.append("=" * 78)
    L.append("FAILURE-RATE AGGREGATOR  (Rule-Change Diagnosis Protocol, Stage 1.4-1.6)")
    L.append("=" * 78)
    L.append(f"cases     : {', '.join(report['cases']) or '(none)'}")
    pa = report["predicate"]
    L.append(f"predicate : {pa['name']}  args={pa['args'] or '{}'}")
    fl = report["floor"]
    L.append(f"floor_hi  : {fl['floor_hi'] if fl['floor_hi'] is not None else 'UNSET (classification INDETERMINATE)'}")
    if "STOP" in report:
        L.append("")
        L.append("  *** STOP ***  " + report["STOP"])
    L.append("")
    L.append(f"{'arm':<10}{'f/n':<10}{'p_hat':<9}{'Wilson 95% CI':<22}{'class':<14}")
    L.append("-" * 78)
    for arm, d in sorted(report["arms"].items()):
        fn = f"{d['f']}/{d['n_valid']}"
        ph = f"{d['p_hat']*100:.1f}%" if d["p_hat"] is not None else "n/a"
        ci = _fmt_ci(d["wilson_lo"], d["wilson_hi"])
        cls = d["classification"]["label"]
        L.append(f"{arm:<10}{fn:<10}{ph:<9}{ci:<22}{cls:<14}")
        # clustering line
        if d["distinct_signatures"] and d["distinct_signatures"] != d["f"]:
            cci = _fmt_ci(d["clustered_wilson_lo"], d["clustered_wilson_hi"])
            L.append(f"{'':<10}clustered f={d['clustered_f']} "
                     f"({d['distinct_signatures']} distinct sig) CI {cci}")
        if d["n_invalid"]:
            L.append(f"{'':<10}invalid dropped: {d['n_invalid']}/{d['n_total']} "
                     f"({(d['invalid_fraction'] or 0)*100:.0f}%)"
                     + ("  *** >20% STOP ***" if d["invalid_overflow"] else ""))
        if d["n_unscorable"]:
            L.append(f"{'':<10}unscorable (excluded, e.g. findable_recall None): {d['n_unscorable']}")
    L.append("")
    ca = report.get("cross_arm")
    if ca:
        L.append(f"sift-vs-bare ({ca['arm1']} - {ca['arm2']}): diff="
                 f"{(ca['diff'] or 0)*100:.1f}pp  z={ca['z']:.2f}  p={ca['p_value']:.4f}")
        L.append(f"  diff 95% CI [{(ca['diff_ci_lo'] or 0)*100:.1f}pp, "
                 f"{(ca['diff_ci_hi'] or 0)*100:.1f}pp]  excludes-0={ca['ci_excludes_zero']}")
        L.append(f"  => {ca['interpretation']}")
    ss = report.get("shared_signatures")
    if ss and ss.get("shared_across_all_arms"):
        L.append("")
        L.append("SHARED failure signatures across ALL arms (correlated-cause hint):")
        for s in ss["shared_across_all_arms"]:
            L.append(f"  - {s}")
    L.append("")
    L.append("caveats:")
    for c in report["caveats"]:
        L.append(f"  - {c}")
    L.append("=" * 78)
    return "\n".join(L)


# =============================================================================
# CLI.
# =============================================================================
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
        description="Failure-rate aggregator: per-round score JSONs -> per-arm f/n + "
                    "Wilson CI + two-proportion test + same-signature clustering.")
    ap.add_argument("--score-dir", default=".",
                    help="dir of <CASE>_<ARM>_round-N.{score,scorer,presence}.json (+ sidecars)")
    ap.add_argument("--case", default=None, help="restrict to one case_id")
    ap.add_argument("-f", "--file", action="append", default=None,
                    help="explicit score file(s); repeatable (overrides --score-dir glob)")
    ap.add_argument("--predicate", required=True, choices=sorted(PREDICATES.keys()),
                    help="the FROZEN binary FAIL predicate (one per campaign)")
    ap.add_argument("--ioc-value", default=None, help="for predicate 'specific_ioc'")
    ap.add_argument("--bucket", default=None, help="for predicate 'bucket_recall'")
    ap.add_argument("--threshold", type=float, default=None,
                    help="for predicate 'findable_recall' (default 1.0: any miss fails)")
    ap.add_argument("--floor-hi", type=float, default=None,
                    help="empirical noise floor Wilson UPPER bound (Stage 1.4). "
                         "Omit => classification INDETERMINATE.")
    ap.add_argument("--floor-lo", type=float, default=None)
    ap.add_argument("--sift-arm", default="sift")
    ap.add_argument("--bare-arm", default="bare")
    ap.add_argument("--act-line", type=float, default=0.20,
                    help="decision-tier p_hat act-line (default 0.20)")
    ap.add_argument("-o", "--out", default=None, help="write report JSON to this path")
    ap.add_argument("--json", action="store_true", help="print report JSON to stdout")
    ap.add_argument("--quiet", action="store_true", help="suppress the human render")
    args = ap.parse_args(argv)

    records = discover_rounds(args.score_dir, case_filter=args.case,
                              explicit_files=args.file)
    if not records:
        print("no round score files found "
              f"(looked in {args.score_dir!r} for *_round-*.{{score,scorer,presence}}.json)",
              file=sys.stderr)
        return 2

    pkw = _collect_predicate_args(args)
    apply_predicate(records, args.predicate, **pkw)
    report = build_report(records, args.predicate, pkw, args.floor_hi, args.floor_lo,
                          args.sift_arm, args.bare_arm, args.act_line)

    if not args.quiet:
        print(render_human(report))
    if args.json:
        if not args.quiet:
            print("\n--- JSON ---")
        print(json.dumps(report, indent=2, sort_keys=True))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, sort_keys=True)
        if not args.quiet:
            print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

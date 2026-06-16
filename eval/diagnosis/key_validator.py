#!/usr/bin/env python3
"""Answer-key validator — Branch-A build-time supportability gate + cross-arm KEY-DOUBT.

WHERE THIS RUNS
---------------
The OPERATOR / scoring layer on **josh-pc**, where the real cases, ground-truth
keys and rubrics live (they are gitignored / off-box; NEVER copied to the VM).
It is BUILT and unit-tested on the sift-vm against **synthetic** fixtures only.
It NEVER runs inside the sealed jail and never touches the orchestrator.

WHAT IT DOES (Stage-2 Branch A of the Rule-Change Diagnosis Protocol)
---------------------------------------------------------------------
A *bad / over-specified answer key* is the worst failure mode: the naive loop
would "fix" it by writing a rule that trains the agent toward a wrong answer.
This tool refuses to let a lap proceed on an unsupportable key, in two ways:

1. SUPPORTABILITY GATE (build-time, deterministic). For one case:
     (a) IOC side  — for each gold ground-truth file's `key_iocs[]` entry, reuse the
         REAL scorer's `load_case_input_text` + `ioc_present` to test whether the
         expected value actually appears in what the agent saw. An expected IOC
         that is NOT findable = the key asks for something the evidence lacks =
         an UNSUPPORTED label. If ZERO key_iocs are findable (the scorer would
         return findable_recall == None), the whole IOC key is unsupportable.
     (b) Rubric/blind side — for each rubric.json item that carries an
         `expected_artifact` (free-text "where to find it"), verify the artifact
         it names actually EXISTS in the read-only evidence mount. We cannot
         literally path-match a prose description, so we extract candidate
         filename/path tokens from the description and check the mount's file
         inventory. No extractable token => UNVERIFIABLE (advisory), not a hard
         block — we never falsely fail a prose-only description.

   VERDICT per case:
     - SUPPORTED       : every checkable expected answer is supported.
     - UNSUPPORTED     : >=1 expected answer is provably absent (HARD: refuse the
                         lap; route to BAD CASE -> fix/retire the case or key).
     - UNVERIFIABLE    : nothing provably absent, but >=1 item could not be
                         checked (advisory; lap may proceed with a flag).

2. CROSS-ARM KEY-DOUBT TRIGGER (post-hoc, over N rounds). When BOTH the sift and
   bare arms, across their rounds, **confidently + consistently + with backing**
   produce the SAME answer that CONTRADICTS the key, that is evidence against the
   KEY, not the agent (two arms of the same base model share correlated priors and
   can agree on a WRONG answer). => escalate to MANDATORY human key
   re-adjudication. TOUCH NO RULE. We consume the REAL per-round score JSONs:
     - score.py (blind findings.json) shape: classification.category_match,
       classification.predicted_category_canonical, classification.predicted_confidence,
       hallucination.hallucination_rate, hallucination.unbacked_findings.
     - scorer.py (report.md IOC) shape: verdict, verdict_expected, fabrication_count,
       findable_recall.

REUSE: imports the real `scorer` module for IOC supportability — no re-implemented
matching, so it tracks the source-of-truth shapes (CaseResult / ioc_present /
load_case_input_text). stdlib-only otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Import the REAL scorer as a library (source of truth for IOC supportability).
# It sits in contract-build/scoring/ in the repo; on josh-pc the operator runs
# this with that dir importable. We add a couple of likely locations to sys.path
# and fall back to a clear error if it is not importable.
# ---------------------------------------------------------------------------
def _import_scorer():
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        here,
        os.path.join(here, "..", "..", "contract-build", "scoring"),
        os.path.join(here, "..", "..", "..", "contract-build", "scoring"),
    ]
    for c in candidates:
        c = os.path.abspath(c)
        if os.path.isfile(os.path.join(c, "scorer.py")) and c not in sys.path:
            sys.path.insert(0, c)
    try:
        import scorer  # noqa: F401
        return scorer
    except ImportError as exc:  # pragma: no cover - environment guard
        raise ImportError(
            "validate_answer_key.py requires the deterministic IOC scorer "
            "(contract-build/scoring/scorer.py) on sys.path; could not import it: "
            f"{exc}"
        ) from exc


scorer = _import_scorer()


# ===========================================================================
# Verdicts / status enums (plain strings so JSON output is stable).
# ===========================================================================
SUPPORTED = "SUPPORTED"
UNSUPPORTED = "UNSUPPORTED"        # HARD: a label is provably absent -> refuse the lap
UNVERIFIABLE = "UNVERIFIABLE"      # advisory: could not check (prose-only / no IOCs)


# ===========================================================================
# Part 1a — IOC-side supportability (gold ground-truth file + scorer.ioc_present).
# ===========================================================================
@dataclass
class IOCSupport:
    type: str
    value: str
    findable: bool

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def check_iocs_supportable(gt: dict, input_text: str) -> dict:
    """For each ground-truth key_ioc, is its value present in what the agent saw?

    Reuses the REAL scorer (TYPE_KIND, ioc_present) so matching == the grader.
    Returns a per-IOC breakdown plus the headline supportability of the IOC key.
    """
    per_ioc: list[IOCSupport] = []
    unsupported: list[dict] = []
    for ioc in gt.get("key_iocs", []):
        kind = scorer.TYPE_KIND.get(ioc.get("type"))
        if kind is None:
            # Unknown type: record it but do not judge it (scorer would skip it).
            per_ioc.append(IOCSupport(type=ioc.get("type", "?"),
                                      value=ioc.get("value", ""), findable=False))
            unsupported.append({"type": ioc.get("type", "?"),
                                "value": ioc.get("value", ""),
                                "reason": "unknown_ioc_type"})
            continue
        findable = scorer.ioc_present(ioc, input_text)
        per_ioc.append(IOCSupport(type=ioc["type"], value=ioc["value"], findable=findable))
        if not findable:
            unsupported.append({"type": ioc["type"], "value": ioc["value"],
                                "reason": "value_absent_from_input"})

    total = len([p for p in per_ioc if scorer.TYPE_KIND.get(p.type) is not None])
    findable_n = sum(1 for p in per_ioc if p.findable)
    # Mirror the scorer's headline: None when there are 0 findable IOCs at all.
    findable_recall = (findable_n / total) if total else None

    if unsupported:
        # Any provably-absent value OR any unknown/un-scoreable IOC type = a bad/
        # over-specified key. This must win over the "no scoreable IOCs" branch so
        # an unknown-type-only key (total==0 but unsupported!=[]) is still flagged.
        status = UNSUPPORTED
    elif total == 0:
        status = UNVERIFIABLE            # no key_iocs at all -> nothing to gate on (blind-only case)
    elif findable_recall == 0 or findable_recall is None:
        status = UNSUPPORTED             # key asks for IOCs the evidence does not contain
    else:
        status = SUPPORTED

    return {
        "status": status,
        "total_key_iocs": total,
        "findable_iocs": findable_n,
        "findable_recall": findable_recall,
        "unsupported": unsupported,
        "per_ioc": [p.to_dict() for p in per_ioc],
    }


# ===========================================================================
# Part 1b — Rubric/blind-side supportability (expected_artifact vs the mount).
# ===========================================================================
# A free-text expected_artifact like
#   "setupapi.dev.log USB install record"  /  "NTUSER.DAT UserAssist"
#   "$MFT entry for stolen-doc.docx"        /  "/var/log/auth.log"
# We pull out file-name / path-ish tokens and look for any of them in the mount's
# recursive file inventory (basenames + relative paths, case-insensitive).
_ARTIFACT_TOKEN_RE = re.compile(
    r"""
    (?:[A-Za-z0-9_\-./\\$]+ \. [A-Za-z0-9]{1,8})   # foo.bar.ext  /  NTUSER.DAT  /  stolen-doc.docx
    | (?:\$[A-Za-z][A-Za-z0-9_]*)                  # $MFT $LogFile $UsnJrnl
    | (?:/[A-Za-z0-9_\-./]+)                        # absolute unix path /var/log/auth.log
    """,
    re.VERBOSE,
)
# Generic words that look filename-ish but are not artifacts to match on.
_TOKEN_STOPSET = {"e.g", "i.e", "etc", "vs"}


def extract_artifact_tokens(description: str) -> list[str]:
    """Candidate filename / path tokens from a free-text expected_artifact string."""
    toks: list[str] = []
    for m in _ARTIFACT_TOKEN_RE.findall(description or ""):
        t = m.strip().strip(".,;:()[]").lower()
        if not t or t in _TOKEN_STOPSET:
            continue
        toks.append(t)
    # de-dup, keep order
    seen: set[str] = set()
    out: list[str] = []
    for t in toks:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def list_mount_inventory(mount_dir: str) -> list[str]:
    """Recursive, case-folded inventory of the read-only evidence mount.

    Returns both relative paths (with both / and \\ flavours) and basenames so a
    description naming either a bare filename or a path component will match.
    """
    inv: set[str] = set()
    for root, _dirs, files in os.walk(mount_dir):
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, mount_dir).lower()
            inv.add(rel)
            inv.add(rel.replace(os.sep, "/"))
            inv.add(rel.replace(os.sep, "\\"))
            inv.add(name.lower())
    return sorted(inv)


def _token_in_inventory(token: str, inventory: list[str]) -> bool:
    """A token is present if it equals or is a path/substring component of any entry."""
    t = token.lstrip("/\\")
    for entry in inventory:
        if t == entry or t == os.path.basename(entry):
            return True
        # path-ish token: allow tail-of-path match (e.g. windows/system32/config/sam)
        if "/" in t or "\\" in t:
            norm_entry = entry.replace("\\", "/")
            norm_t = t.replace("\\", "/")
            if norm_entry.endswith(norm_t) or norm_t in norm_entry:
                return True
        else:
            # bare filename token: substring of a basename (handles $MFT inside paths)
            if t in os.path.basename(entry):
                return True
    return False


def check_rubric_artifacts(rubric: dict, inventory: list[str]) -> dict:
    """For each rubric item with an expected_artifact, does the named artifact exist?

    UNSUPPORTED: the description names concrete artifact token(s), NONE found in mount.
    UNVERIFIABLE: the description has no extractable artifact token (prose-only) — we
                  cannot prove absence, so we flag it advisory, never hard-block.
    """
    item_arrays = ("key_artifacts", "key_iocs", "actor_accounts",
                   "exfil_or_encryption_facts", "timeline_events")
    checked = 0
    supported_items: list[dict] = []
    unsupported_items: list[dict] = []
    unverifiable_items: list[dict] = []

    for arr in item_arrays:
        for item in rubric.get(arr, []):
            if not isinstance(item, dict):
                continue  # plain-string rubric items carry no expected_artifact
            ea = item.get("expected_artifact")
            if not ea:
                continue
            checked += 1
            value = item.get("value", "")
            tokens = extract_artifact_tokens(ea)
            row = {"section": arr, "value": value, "expected_artifact": ea,
                   "tokens": tokens}
            if not tokens:
                unverifiable_items.append({**row, "reason": "no_extractable_token"})
                continue
            hit = next((t for t in tokens if _token_in_inventory(t, inventory)), None)
            if hit is not None:
                supported_items.append({**row, "matched_token": hit})
            else:
                unsupported_items.append({**row, "reason": "artifact_absent_from_mount"})

    if unsupported_items:
        status = UNSUPPORTED
    elif checked == 0 or unverifiable_items:
        status = UNVERIFIABLE
    else:
        status = SUPPORTED

    return {
        "status": status,
        "items_with_expected_artifact": checked,
        "supported": supported_items,
        "unsupported": unsupported_items,
        "unverifiable": unverifiable_items,
    }


# ===========================================================================
# Part 1 roll-up — the per-case supportability verdict (the build-time GATE).
# ===========================================================================
def _rollup_status(*statuses: str) -> str:
    if UNSUPPORTED in statuses:
        return UNSUPPORTED
    if SUPPORTED in statuses:
        # SUPPORTED dominates UNVERIFIABLE only if nothing is unverifiable left
        return UNVERIFIABLE if UNVERIFIABLE in statuses else SUPPORTED
    return UNVERIFIABLE


def validate_key_supportability(
    case_id: str,
    gt: dict | None = None,
    input_text: str | None = None,
    rubric: dict | None = None,
    mount_inventory: list[str] | None = None,
) -> dict:
    """Run whichever sides are provided (IOC side and/or rubric side) and roll up.

    At least one side must be provided. The roll-up status is the gate:
      UNSUPPORTED -> refuse the lap (BAD CASE).
    """
    ioc_res = None
    rubric_res = None
    statuses: list[str] = []

    if gt is not None and input_text is not None:
        ioc_res = check_iocs_supportable(gt, input_text)
        statuses.append(ioc_res["status"])
    if rubric is not None and mount_inventory is not None:
        rubric_res = check_rubric_artifacts(rubric, mount_inventory)
        statuses.append(rubric_res["status"])

    if not statuses:
        raise ValueError(
            "validate_key_supportability: provide the IOC side (gt + input_text) "
            "and/or the rubric side (rubric + mount_inventory)."
        )

    status = _rollup_status(*statuses)
    return {
        "case_id": case_id,
        "status": status,
        "gate_pass": status != UNSUPPORTED,   # the lap may proceed iff not hard-unsupported
        "ioc_side": ioc_res,
        "rubric_side": rubric_res,
    }


def validate_key_from_files(
    case_id: str,
    gt_path: str | None = None,
    input_path: str | None = None,
    rubric_path: str | None = None,
    mount_dir: str | None = None,
) -> dict:
    """File-driven wrapper. Loads via the REAL scorer loaders where applicable."""
    gt = scorer.load_ground_truth(gt_path) if gt_path else None
    input_text = scorer.load_case_input_text(input_path) if input_path else None
    rubric = None
    if rubric_path:
        with open(rubric_path, encoding="utf-8") as fh:
            rubric = json.load(fh)
    inventory = list_mount_inventory(mount_dir) if mount_dir else None
    return validate_key_supportability(case_id, gt=gt, input_text=input_text,
                                       rubric=rubric, mount_inventory=inventory)


# ===========================================================================
# Part 2 — Cross-arm KEY-DOUBT trigger.
# ===========================================================================
# A round "contradicts the key with backing + confidence" when:
#   * blind (score.py) round: classification.category_match == False
#       AND it is backed: hallucination.unbacked_findings == 0 (deterministic,
#           judge-free; empty literal_cited => auto-unbacked) and
#           hallucination.hallucination_rate <= HALLUC_MAX
#       AND it is confident: predicted_confidence != "insufficient_evidence"
#     -> its "answer" for consistency = predicted_category_canonical.
#   * IOC (scorer.py) round: an ACTUAL positive contradiction — NOT a bare
#       failure-to-emit. scorer collapses missing AND present-but-wrong-class into
#       verdict == "not_emitted", so verdict alone cannot tell silence apart from a
#       wrong answer. A round counts as contradicting the key ONLY when, on top of
#       verdict == "not_emitted", there is a positive contrary assertion: either
#       the report EMITTED a VERDICT: token in a different class than verdict_expected
#       (reported_verdict present + classifiable + different class), OR it asserted a
#       contrary IOC (an asserted CIDR covering none of the input hosts). Both arms
#       merely producing no verdict (fabrication_count == 0, no asserted-contrary IOC)
#       is NOT a contradiction -> no KEY-DOUBT (a good key must not be over-flagged).
#       Backing still additionally requires fabrication_count == 0; the answer for
#       consistency = the round's reported verdict token if present, else a marker.
#
# KEY-DOUBT fires only when BOTH arms have >=1 such backed-contradicting round AND
# the arms AGREE on the same wrong answer across the rounds that contradict (their
# modal contradicting answer is identical), and the contradiction is CONSISTENT
# (a per-arm majority of valid rounds contradict). Anything weaker => agent-side
# (route to normal Stage-2), never key-doubt.

HALLUC_MAX = 0.0  # backed == zero hallucination by default (deterministic, judge-free)


def _blind_round_signal(score: dict) -> dict | None:
    """Extract (contradicts, backed, confident, answer) from a score.py round dict."""
    cls = score.get("classification")
    hal = score.get("hallucination")
    if cls is None or hal is None:
        return None
    contradicts = cls.get("category_match") is False
    backed = (hal.get("unbacked_findings", 1) == 0
              and float(hal.get("hallucination_rate", 1.0)) <= HALLUC_MAX)
    confident = cls.get("predicted_confidence") != "insufficient_evidence"
    answer = cls.get("predicted_category_canonical") or cls.get("predicted_category") or ""
    return {"contradicts": contradicts, "backed": backed,
            "confident": confident, "answer": answer}


def _asserted_contrary_ioc(score: dict) -> bool:
    """True iff the round positively ASSERTED an IOC-shaped claim that the input
    does not support (an asserted CIDR that covers none of the input hosts). This
    is a POSITIVE contrary signal (the report made a wrong claim), distinct from
    merely failing to emit anything."""
    for c in score.get("asserted_cidrs", []) or []:
        if isinstance(c, dict) and not c.get("covers_input_hosts", False):
            return True
    return False


def _reported_verdict_actively_contradicts(score: dict) -> bool:
    """True iff the report ACTUALLY emitted a VERDICT: token whose semantic class
    differs from the key's expected class. This is the backed, positive
    wrong-class contradiction (NOT a bare failure-to-emit).

    scorer collapses BOTH 'no verdict line at all' AND 'present-but-wrong-class'
    into verdict=='not_emitted', so verdict alone cannot tell the two apart. We
    use the round's recorded reported_verdict token: present + classifiable +
    in a DIFFERENT class than expected == an actual contradiction. Absent / empty
    / unclassifiable reported_verdict == the report simply did not assert a
    contrary verdict == NOT a contradiction."""
    rv = score.get("reported_verdict")
    if not isinstance(rv, str) or not rv.strip():
        return False
    rv_class = scorer._verdict_class(rv)
    if rv_class is None:
        return False  # emitted token isn't a recognized verdict -> no contrary class
    exp_class = scorer._verdict_class(score.get("verdict_expected", "") or "")
    if exp_class is None:
        return False  # key has no classifiable expected verdict -> nothing to contradict
    return rv_class != exp_class


def _ioc_round_signal(score: dict) -> dict | None:
    """Extract the (contradicts, backed, confident, answer) tuple from a scorer.py
    CaseResult round dict.

    A round CONTRADICTS the key only on an ACTUAL positive contradiction signal:
    the report emitted a wrong-class VERDICT, OR it asserted a contrary IOC. A
    round where scorer.verdict=='not_emitted' merely because the report produced
    NO verdict line (no positive contrary assertion, no asserted-contrary IOC) is
    a FAILURE TO EMIT, not a contradiction of the key — so it must NOT count, or a
    good key gets over-flagged when both arms simply stay silent."""
    if "verdict" not in score or "verdict_expected" not in score:
        return None
    wrong_class = score.get("verdict") == "not_emitted"  # missing OR wrong-class
    # Require a POSITIVE contradiction, not a bare failure-to-emit:
    positive_contradiction = (
        _reported_verdict_actively_contradicts(score)
        or _asserted_contrary_ioc(score)
    )
    contradicts = wrong_class and positive_contradiction
    backed = int(score.get("fabrication_count", 1)) == 0
    # scorer rounds carry no per-finding confidence; treat a present verdict as confident.
    confident = True
    # consistency answer: the reported verdict token if the round recorded one, else marker.
    answer = score.get("reported_verdict") or "<contradicts:not_emitted>"
    return {"contradicts": contradicts, "backed": backed,
            "confident": confident, "answer": answer}


def _round_signal(score: dict) -> dict | None:
    sig = _blind_round_signal(score)
    if sig is not None:
        return sig
    return _ioc_round_signal(score)


def _arm_summary(rounds: list[dict]) -> dict:
    """Per-arm: how many valid rounds contradict-with-backing-and-confidence, and the
    modal contradicting answer."""
    signals = [s for s in (_round_signal(r) for r in rounds) if s is not None]
    n_valid = len(signals)
    qualifying = [s for s in signals
                  if s["contradicts"] and s["backed"] and s["confident"]]
    # modal answer among qualifying rounds
    counts: dict[str, int] = {}
    for s in qualifying:
        counts[s["answer"]] = counts.get(s["answer"], 0) + 1
    modal = max(counts, key=counts.get) if counts else None
    modal_n = counts.get(modal, 0) if modal is not None else 0
    return {
        "n_valid": n_valid,
        "n_qualifying": len(qualifying),
        "modal_contradicting_answer": modal,
        "modal_count": modal_n,
        "answer_counts": counts,
        # CONSISTENT == a majority of valid rounds qualify AND they agree on the modal answer
        "consistent": (n_valid > 0 and modal is not None
                       and modal_n > n_valid / 2),
    }


def cross_arm_key_doubt(sift_rounds: list[dict], bare_rounds: list[dict]) -> dict:
    """KEY-DOUBT trigger across the two arms.

    Fires (escalate to human re-adjudication) iff BOTH arms are CONSISTENT in a
    backed+confident contradiction of the key AND agree on the SAME modal answer.
    """
    s = _arm_summary(sift_rounds)
    b = _arm_summary(bare_rounds)
    agree = (s["consistent"] and b["consistent"]
             and s["modal_contradicting_answer"] is not None
             and s["modal_contradicting_answer"] == b["modal_contradicting_answer"])
    if agree:
        verdict = "KEY_DOUBT"
        recommendation = ("BOTH arms confidently, consistently and with backing contradict "
                          "the key with the SAME answer -> MANDATORY human key "
                          "re-adjudication. TOUCH NO RULE.")
    else:
        verdict = "AGENT_SIDE"
        recommendation = ("Not both-arm consistent+agreeing backed contradiction -> this is "
                          "(likely) an agent-side failure; proceed with normal Stage-2 "
                          "root-cause. NOT a key-doubt escalation.")
    return {
        "verdict": verdict,
        "escalate_human_readjudication": agree,
        "agreed_answer": s["modal_contradicting_answer"] if agree else None,
        "sift": s,
        "bare": b,
        "recommendation": recommendation,
    }


# ===========================================================================
# CLI.
# ===========================================================================
def _print_json(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Answer-key validator: Branch-A supportability gate + cross-arm KEY-DOUBT.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gate", help="build-time supportability gate for one case")
    g.add_argument("--case-id", required=True)
    g.add_argument("--ground-truth", help="path to the gold ground-truth JSON file (IOC side)")
    g.add_argument("--case-input", help="path to the case_input.json the agent saw (IOC side)")
    g.add_argument("--rubric", help="path to the blind rubric.json (rubric side)")
    g.add_argument("--mount", help="path to the read-only evidence mount dir (rubric side)")
    g.add_argument("--json", action="store_true", help="emit JSON only (machine-readable)")

    d = sub.add_parser("key-doubt", help="cross-arm KEY-DOUBT over per-round score JSONs")
    d.add_argument("--sift", nargs="+", required=True, help="sift-arm per-round score JSON files")
    d.add_argument("--bare", nargs="+", required=True, help="bare-arm per-round score JSON files")
    d.add_argument("--json", action="store_true", help="emit JSON only")

    args = ap.parse_args(argv)

    if args.cmd == "gate":
        if not ((args.ground_truth and args.case_input) or (args.rubric and args.mount)):
            ap.error("provide --ground-truth + --case-input and/or --rubric + --mount")
        res = validate_key_from_files(
            args.case_id,
            gt_path=args.ground_truth, input_path=args.case_input,
            rubric_path=args.rubric, mount_dir=args.mount,
        )
        _print_json(res)
        # exit 2 == HARD unsupported key (refuse the lap); 0 == gate pass (incl. advisory).
        return 2 if res["status"] == UNSUPPORTED else 0

    if args.cmd == "key-doubt":
        def _load(paths: list[str]) -> list[dict]:
            out = []
            for p in paths:
                with open(p, encoding="utf-8") as fh:
                    out.append(json.load(fh))
            return out
        res = cross_arm_key_doubt(_load(args.sift), _load(args.bare))
        _print_json(res)
        # exit 3 == KEY-DOUBT escalation (do NOT run a rule lap); 0 == agent-side.
        return 3 if res["escalate_human_readjudication"] else 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())

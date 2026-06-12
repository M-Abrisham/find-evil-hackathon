#!/usr/bin/env python3
"""Post-run trace enrichment orchestrator for Protocol SIFT ("Fix A").

For ONE finished investigation this:

1. loads the Braintrust trace (``bt_client.get_trace``) + the raw-bash log
   (``bashlog.load_bash_log``) + the case input + the report;
2. for every tool span, computes the **skill owner** + **action phase**
   (``registry``) and the **per-call outcome** (``bashlog.outcome`` over the
   joined raw-bash record), splitting compound commands so each sub-tool is
   tagged, then DEEP-MERGES ``skill`` / ``phase`` / ``outcome`` onto that span;
3. computes the per-run **rollup** (per skill: tools_run, success_rate,
   iocs_surfaced via provenance), the run **scores** (findable_recall,
   fabrications, verdict, mitre — only if ground truth is reachable), the
   **IOC -> tool provenance** + candidate-fabrications, and ``skill_expected``
   vs ``skill_used`` if an answer key supplies expected tools/skills;
4. merges the rollup + scores onto the ROOT span.

It is **measurement-only**: it never re-runs the agent. Scores are OPTIONAL — the
run still enriches (tags/phases/outcomes/rollup) without ground truth.

CLI::

    python3 -m trace_enrich.enrich --session <session_id|trace_id> [--case caseN] \
        [--bash-log PATH] [--case-input PATH] [--report PATH] \
        [--ground-truth PATH] [--answer-key PATH] [--plan] [--verify]

``--plan`` is a DRY RUN: it prints exactly what WOULD be written and makes no
network calls beyond the read (and not even the read when ``--from-fixture`` /
all local inputs are supplied without a session). stdlib-only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Robust sibling/scorer imports: work both as ``python3 -m trace_enrich.enrich``
# (package context) and as a bare script / ``import`` from inside the dir.
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_HERE, os.pardir))
for _p in (_HERE, os.path.join(_REPO, "scoring")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:  # package-relative first
    from . import bt_client, bashlog, registry, provenance  # type: ignore
except Exception:  # pragma: no cover - standalone fallback
    import bt_client  # type: ignore
    import bashlog  # type: ignore
    import registry  # type: ignore
    import provenance  # type: ignore

# scorer is loaded lazily (only when ground truth is present) so a no-scores run
# never needs scoring/ on the path. provenance.py already vendors its own loader.


# ---------------------------------------------------------------------------
# Score normalisation -> Braintrust scores (numbers in [0,1]).
# ---------------------------------------------------------------------------
def _scores_from_case_result(result: Any) -> Dict[str, float]:
    """Map a scorer ``CaseResult`` to Braintrust scores in [0,1].

    * ``findable_recall`` — the primary metric (None when 0 findable -> omitted).
    * ``fabrications``    — 1.0 when zero fabrications, decaying toward 0 as the
      count grows (``1/(1+count)``) so "no fabrication" reads as a perfect score.
    * ``verdict``         — 1.0 if the ground-truth verdict was emitted, else 0.0.
    * ``mitre``           — MITRE technique recall (found/total), None -> omitted.
    """
    scores: Dict[str, float] = {}
    fr = getattr(result, "findable_recall", None)
    if isinstance(fr, (int, float)):
        scores["findable_recall"] = float(fr)

    fab = getattr(result, "fabrication_count", None)
    if isinstance(fab, int):
        scores["fabrications"] = 1.0 / (1.0 + fab)

    verdict = getattr(result, "verdict", None)
    if verdict is not None:
        scores["verdict"] = 1.0 if verdict == "found" else 0.0

    mt = getattr(result, "mitre_total", 0) or 0
    mf = getattr(result, "mitre_found", 0) or 0
    if mt:
        scores["mitre"] = mf / mt

    return scores


# ---------------------------------------------------------------------------
# Per-tool-span labelling.
# ---------------------------------------------------------------------------
def _label_tool_span(span: dict, bash_log: Dict[str, dict]) -> Dict[str, Any]:
    """Compute the metadata/tags to merge onto one tool span.

    Bash spans carry ``full_command`` -> split into sub-tools, each tagged with
    its owning skill + phase. The whole-pipeline ``outcome`` comes from the
    joined raw-bash record (single exit per pipeline; empty detected via stdout).
    Read/Write spans have no command; they get a ``tool_name``-derived label and
    no forensic skill/phase (they are not in the bash log).
    """
    tool_name = span.get("tool_name") or ""
    tuid = span.get("tool_use_id")
    command = span.get("command")

    enrich: Dict[str, Any] = {"tool_name": tool_name}
    tags: List[str] = []

    if command:  # a Bash span
        sub_tools = registry.tools_in(command)
        enrich["sub_tools"] = sub_tools
        skills = sorted({t["skill"] for t in sub_tools})
        phases = sorted({t["phase"] for t in sub_tools})
        # Primary (first real) tool drives the headline skill/phase tag.
        primary = sub_tools[0] if sub_tools else None
        enrich["skill"] = primary["skill"] if primary else registry.UNKNOWN
        enrich["phase"] = primary["phase"] if primary else registry.OTHER
        enrich["skills"] = skills
        enrich["phases"] = phases
        for s in skills:
            tags.append(f"skill:{s}")
        for p in phases:
            if p != registry.OTHER:
                tags.append(f"phase:{p}")
    elif tool_name in ("Read", "Write"):
        enrich["skill"] = "io"
        enrich["phase"] = "report" if tool_name == "Write" else "input"
        tags.append(f"tool:{tool_name.lower()}")
    else:
        enrich["skill"] = registry.UNKNOWN
        enrich["phase"] = registry.OTHER

    # Outcome: prefer the raw-bash classifier (worked/errored/returned-nothing).
    # Fall back to the trace's execution-span success boolean when the tool is
    # not in the bash log (Read/Write/MCP) or the join misses.
    entry = bash_log.get(tuid) if tuid else None
    if entry is not None:
        enrich["outcome"] = bashlog.outcome(entry)
        enrich["outcome_source"] = "bash_log"
    else:
        succ = span.get("success")
        if isinstance(succ, bool):
            enrich["outcome"] = bashlog.OK if succ else bashlog.ERRORED
            enrich["outcome_source"] = "trace_success"
        else:
            enrich["outcome"] = "unknown"
            enrich["outcome_source"] = "none"
    tags.append(f"outcome:{enrich['outcome']}")

    return {"metadata": {"enrich": enrich}, "tags": tags}


# ---------------------------------------------------------------------------
# Rollup.
# ---------------------------------------------------------------------------
def _build_rollup(
    labelled: List[dict],
    prov_records: List[dict],
    prov_summary: dict,
    *,
    answer_key: Optional[dict],
) -> Dict[str, Any]:
    """Per-skill rollup + provenance summary + skill_expected vs skill_used.

    ``labelled`` is the list of ``{span, label}`` pairs. We aggregate at the
    SUB-TOOL level (a compound command contributes to every skill it invokes),
    counting tools_run, success_rate (worked / ran), and IOCs surfaced by that
    skill's tools (via provenance ``tool_sources``).
    """
    # Map each tool_use_id -> its outcome + the skills/sub-tools it ran.
    per_skill: Dict[str, Dict[str, Any]] = {}

    def _bucket(skill: str) -> Dict[str, Any]:
        return per_skill.setdefault(
            skill,
            {"tools_run": 0, "tools_ok": 0, "iocs_surfaced": 0, "tokens": []},
        )

    # tool_use_id -> set of skills that ran in it (for IOC attribution).
    tuid_to_skills: Dict[str, set] = {}

    for pair in labelled:
        span = pair["span"]
        label = pair["label"]
        meta = label["metadata"]["enrich"]
        outcome = meta.get("outcome")
        tuid = span.get("tool_use_id")
        sub_tools = meta.get("sub_tools")

        if sub_tools:  # Bash: one count per real sub-tool
            skills_here = set()
            for st in sub_tools:
                skill = st["skill"]
                skills_here.add(skill)
                b = _bucket(skill)
                b["tools_run"] += 1
                b["tokens"].append(st["token"])
                if outcome == bashlog.OK:
                    b["tools_ok"] += 1
            if tuid:
                tuid_to_skills[tuid] = skills_here
        else:
            skill = meta.get("skill", registry.UNKNOWN)
            b = _bucket(skill)
            b["tools_run"] += 1
            if outcome == bashlog.OK:
                b["tools_ok"] += 1

    # Attribute surfaced IOCs to skills via provenance tool_sources.
    for rec in prov_records:
        for src in rec.get("tool_sources", []):
            if not src.startswith("tool:"):
                continue
            tuid = src[len("tool:"):]
            for skill in tuid_to_skills.get(tuid, ()):  # type: ignore[arg-type]
                per_skill[skill]["iocs_surfaced"] += 1

    # Finalise per-skill records (success_rate, dedup token list).
    skill_rollup: Dict[str, Any] = {}
    for skill, b in sorted(per_skill.items()):
        run = b["tools_run"]
        skill_rollup[skill] = {
            "tools_run": run,
            "tools_ok": b["tools_ok"],
            "success_rate": round(b["tools_ok"] / run, 4) if run else None,
            "iocs_surfaced": b["iocs_surfaced"],
            "tools": sorted(set(b["tokens"])) if b["tokens"] else [],
        }

    rollup: Dict[str, Any] = {
        "per_skill": skill_rollup,
        "provenance": prov_summary,
    }

    # skill_expected vs skill_used (only when an answer key provides expected).
    skills_used = sorted(
        s for s in skill_rollup
        if s not in (registry.UNKNOWN, registry.SHARED, "io")
    )
    rollup["skill_used"] = skills_used
    if answer_key:
        expected = _expected_skills(answer_key)
        if expected is not None:
            rollup["skill_expected"] = sorted(expected)
            rollup["skill_missing"] = sorted(set(expected) - set(skills_used))
            rollup["skill_unexpected"] = sorted(set(skills_used) - set(expected))

    return rollup


def _expected_skills(answer_key: dict) -> Optional[set]:
    """Pull expected skills from an answer key, if it declares any.

    Accepts either an explicit ``expected_skills`` list, or an
    ``expected_tools`` list which we map through the registry to owning skills.
    Returns None when the key declares neither.
    """
    if not isinstance(answer_key, dict):
        return None
    if isinstance(answer_key.get("expected_skills"), list):
        return {str(s) for s in answer_key["expected_skills"]}
    tools = answer_key.get("expected_tools")
    if isinstance(tools, list):
        out = set()
        for t in tools:
            sk = registry.skill_for(str(t))
            if sk not in (registry.UNKNOWN, registry.SHARED):
                out.add(sk)
        return out or None
    return None


# ---------------------------------------------------------------------------
# Provenance assembly.
# ---------------------------------------------------------------------------
def _gather_tool_stdouts(
    tool_spans: List[dict], bash_log: Dict[str, dict], *, read_persisted: bool
) -> Dict[str, str]:
    """``{tool_use_id: stdout}`` in bash-log order (defines provenance first-match)."""
    out: Dict[str, str] = {}
    # Preserve raw-bash log insertion order (it is the temporal order of calls).
    for tuid in bash_log:
        out[tuid] = bashlog.get_stdout(bash_log, tuid, read_persisted=read_persisted)
    # Include any tool spans not in the bash log with empty stdout (Read/Write),
    # so the dict still reflects the full set of tool calls (harmless for match).
    for span in tool_spans:
        tuid = span.get("tool_use_id")
        if tuid and tuid not in out:
            out[tuid] = ""
    return out


# ---------------------------------------------------------------------------
# Orchestrator.
# ---------------------------------------------------------------------------
class EnrichPlan:
    """The full set of writes the orchestrator computed, for plan or apply."""

    def __init__(self) -> None:
        self.root_span_id: Optional[str] = None
        self.root_metadata: Dict[str, Any] = {}
        self.root_scores: Dict[str, float] = {}
        self.root_tags: List[str] = []
        self.span_writes: List[dict] = []  # [{span_id, metadata, tags}]
        self.notes: List[str] = []

    def to_events(self) -> List[dict]:
        """All merges as a single insert batch (per-span + root)."""
        events: List[dict] = []
        for w in self.span_writes:
            ev: Dict[str, Any] = {"id": w["span_id"], "_is_merge": True}
            if w.get("metadata"):
                ev["metadata"] = w["metadata"]
            if w.get("tags"):
                ev["tags"] = w["tags"]
            events.append(ev)
        if self.root_span_id:
            ev = {"id": self.root_span_id, "_is_merge": True}
            if self.root_metadata:
                ev["metadata"] = self.root_metadata
            if self.root_tags:
                ev["tags"] = self.root_tags
            if self.root_scores:
                ev["scores"] = self.root_scores
            events.append(ev)
        return events

    def summary(self) -> dict:
        return {
            "root_span_id": self.root_span_id,
            "root_scores": self.root_scores,
            "root_tags": self.root_tags,
            "root_metadata_keys": sorted(self.root_metadata.keys()),
            "per_skill": (self.root_metadata.get("rollup") or {}).get("per_skill"),
            "span_writes": len(self.span_writes),
            "notes": self.notes,
        }


def build_plan(
    *,
    trace: dict,
    bash_log: Dict[str, dict],
    report_text: str,
    case_input_text: str,
    ground_truth: Optional[dict] = None,
    answer_key: Optional[dict] = None,
    case_id: str = "",
    read_persisted: bool = False,
) -> EnrichPlan:
    """Pure compute: turn loaded inputs into the exact set of merges to write.

    No network here — all I/O (read trace, POST merges) lives in the callers.
    This makes the whole enrichment unit-testable and dry-runnable.
    """
    plan = EnrichPlan()
    root = trace["root_span"]
    plan.root_span_id = root["span_id"]

    tool_spans = trace.get("tool_spans", [])

    # 1. Per-tool-span labels (skill / phase / outcome).
    labelled: List[dict] = []
    for span in tool_spans:
        label = _label_tool_span(span, bash_log)
        labelled.append({"span": span, "label": label})
        plan.span_writes.append(
            {
                "span_id": span["span_id"],
                "metadata": label["metadata"],
                "tags": label["tags"],
            }
        )

    # 2. IOC -> tool provenance (guardrail = tool stdout UNION case input).
    tool_stdouts = _gather_tool_stdouts(
        tool_spans, bash_log, read_persisted=read_persisted
    )
    prov_records = provenance.provenance(report_text, tool_stdouts, case_input_text)
    prov_summary = provenance.provenance_summary(prov_records)

    # 3. Rollup (per skill + provenance + skill_expected/used).
    rollup = _build_rollup(
        labelled, prov_records, prov_summary, answer_key=answer_key
    )

    # 4. Scores (only when ground truth is reachable).
    scores: Dict[str, float] = {}
    if ground_truth is not None:
        try:
            scorer = _load_scorer()
            result = scorer.score_case(
                case_id or trace.get("session_id") or "run",
                ground_truth,
                case_input_text,
                report_text,
            )
            scores = _scores_from_case_result(result)
            plan.notes.append(
                f"scored against ground truth: {sorted(scores.keys())}"
            )
        except Exception as exc:  # pragma: no cover - surfaced, not fatal
            plan.notes.append(f"scoring skipped (error): {exc}")
    else:
        plan.notes.append(
            "no ground truth supplied -> scores omitted; "
            "enrichment (tags/phases/outcomes/rollup) still applied"
        )

    # 5. Assemble root metadata + scores + tags.
    plan.root_metadata = {
        "enrich_version": 1,
        "case_id": case_id,
        "rollup": rollup,
        "n_tool_spans": len(tool_spans),
        "n_bash_calls": len(bash_log),
        "candidate_fabrications": prov_summary["candidate_fabrications"],
    }
    plan.root_scores = scores
    plan.root_tags = ["enriched"]
    if prov_summary["candidate_fabrication_count"]:
        plan.root_tags.append("has_candidate_fabrications")

    return plan


def _load_scorer():
    """Import scoring/scorer.py (already on sys.path from module top)."""
    import scorer  # type: ignore
    return scorer


# ---------------------------------------------------------------------------
# Apply.
# ---------------------------------------------------------------------------
def apply_plan(
    plan: EnrichPlan,
    *,
    project_id: Optional[str] = None,
    api_key: Optional[str] = None,
    batch: bool = True,
) -> Dict[str, Any]:
    """Write the plan to Braintrust (per-span merges + root merge).

    ``batch=True`` sends everything in one ``insert`` call (the API accepts many
    events). Returns ``{"row_ids": [...], "n_events": int}``.
    """
    events = plan.to_events()
    if not events:
        return {"row_ids": [], "n_events": 0}
    if batch:
        row_ids = bt_client.insert_events(
            events, project_id=project_id, api_key=api_key
        )
    else:  # one request per event (slower; useful for isolating a failure)
        row_ids = []
        for ev in events:
            row_ids.extend(
                bt_client.insert_events([ev], project_id=project_id, api_key=api_key)
            )
    return {"row_ids": row_ids, "n_events": len(events)}


# ---------------------------------------------------------------------------
# Input loading for the CLI (resolve case-shorthand to the standard paths).
# ---------------------------------------------------------------------------
#: trace ids / session ids for the three known cases (from the eval MANIFEST).
KNOWN_CASES = {
    "case1": {
        "trace_id": "4553d295272c37b822a3c12cb60b487a",
        "session_id": "d50b6132-4b67-4655-bda0-92c8a033f841",
        "case_id": "VIGIA-REAL-001",
    },
    "case2": {
        "trace_id": "c8c93ac98cba229f67f7f2c04a0a6553",
        "session_id": "60ec2a52-b517-450d-b953-f67290518a1f",
        "case_id": "VIGIA-REAL-002",
    },
    "case7": {
        "trace_id": "8f3266b5e66b4a31ad0c7e85f33e1dad",
        "session_id": "b2bb212f-d701-4bfc-bc9f-7f3556957d19",
        "case_id": "VIGIA-REAL-007",
    },
}


def _read_text(path: Optional[str]) -> str:
    if not path:
        return ""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _read_json(path: Optional[str]) -> Optional[dict]:
    if not path or not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _resolve_run_id(args: argparse.Namespace) -> str:
    if args.session:
        return args.session
    if args.case and args.case in KNOWN_CASES:
        # Prefer the explicit trace id; session id also works via get_trace.
        return KNOWN_CASES[args.case]["trace_id"]
    raise SystemExit("error: need --session <id> or a known --case (case1/2/7)")


def _resolve_case_input_text(args: argparse.Namespace) -> str:
    """Build the case-input haystack via scorer.load_case_input_text (findable
    semantics) when given a JSON path; else read raw text; else empty."""
    path = args.case_input
    if not path:
        return ""
    if path.endswith(".json"):
        try:
            scorer = _load_scorer()
            return scorer.load_case_input_text(path)
        except Exception:
            pass
    return _read_text(path)


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python3 -m trace_enrich.enrich",
        description="Post-run trace enrichment for Protocol SIFT (Fix A).",
    )
    ap.add_argument("--session", help="run id: 32-hex trace id OR Claude session uuid")
    ap.add_argument("--case", choices=sorted(KNOWN_CASES), help="known case shorthand")
    ap.add_argument("--bash-log", help="path to bash_raw_<session>.jsonl")
    ap.add_argument("--case-input", help="case input JSON (the agent's Read source)")
    ap.add_argument("--report", help="investigation report (.md) text")
    ap.add_argument("--ground-truth", help="ground_truth/<case>.json (enables scores)")
    ap.add_argument("--answer-key", help="JSON with expected_skills/expected_tools")
    ap.add_argument("--project", default=bt_client.PROJECT_NAME,
                    help=f"Braintrust project name (default: {bt_client.PROJECT_NAME})")
    ap.add_argument("--read-persisted", action="store_true",
                    help="read full persisted stdout for provenance (slower)")
    ap.add_argument("--no-batch", action="store_true",
                    help="apply: one insert per event instead of one batch")
    ap.add_argument("--plan", action="store_true",
                    help="DRY RUN: print what WOULD be written; no writes")
    ap.add_argument("--verify", action="store_true",
                    help="after apply, re-read the root span to confirm the write")
    ap.add_argument("--json", action="store_true", help="print the plan summary as JSON")
    args = ap.parse_args(argv)

    case_id = ""
    if args.case and args.case in KNOWN_CASES:
        case_id = KNOWN_CASES[args.case]["case_id"]

    # --- load the trace (needs the API key + network) ---
    try:
        api_key = bt_client.get_api_key()
        project_id = bt_client.resolve_project_id(args.project, api_key=api_key)
        run_id = _resolve_run_id(args)
        trace = bt_client.get_trace(run_id, project_id=project_id, api_key=api_key)
    except bt_client.BraintrustError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # --- load local inputs ---
    bash_log: Dict[str, dict] = {}
    if args.bash_log:
        bash_log = bashlog.load_bash_log(args.bash_log)
    report_text = _read_text(args.report)
    case_input_text = _resolve_case_input_text(args)
    ground_truth = _read_json(args.ground_truth)
    answer_key = _read_json(args.answer_key)

    # --- compute the plan ---
    plan = build_plan(
        trace=trace,
        bash_log=bash_log,
        report_text=report_text,
        case_input_text=case_input_text,
        ground_truth=ground_truth,
        answer_key=answer_key,
        case_id=case_id,
        read_persisted=args.read_persisted,
    )

    # --- output ---
    if args.plan:
        print("=== TRACE ENRICH — DRY RUN (no writes) ===")
        print(f"project        : {args.project} ({project_id})")
        print(f"run id         : {run_id}")
        print(f"root span id   : {plan.root_span_id}  (write target)")
        print(f"tool spans     : {len(trace.get('tool_spans', []))}")
        print(f"bash calls     : {len(bash_log)}")
        print(f"root scores    : {plan.root_scores or '(none — no ground truth)'}")
        print(f"root tags      : {plan.root_tags}")
        rollup = plan.root_metadata.get("rollup", {})
        print("per-skill rollup:")
        for skill, rec in (rollup.get("per_skill") or {}).items():
            print(
                f"  {skill:<18} run={rec['tools_run']:<3} "
                f"ok={rec['tools_ok']:<3} success_rate={rec['success_rate']} "
                f"iocs={rec['iocs_surfaced']} tools={rec['tools']}"
            )
        if "skill_expected" in rollup:
            print(f"skill_expected : {rollup['skill_expected']}")
            print(f"skill_used     : {rollup['skill_used']}")
            print(f"skill_missing  : {rollup.get('skill_missing')}")
        prov = rollup.get("provenance", {})
        print(
            f"provenance     : iocs_total={prov.get('iocs_total')} "
            f"from_tool={prov.get('iocs_from_tool')} "
            f"from_case_input={prov.get('iocs_from_case_input')} "
            f"candidate_fabrications={prov.get('candidate_fabrication_count')}"
        )
        print(f"per-span writes: {len(plan.span_writes)} (each: skill/phase/outcome)")
        print(f"total events   : {len(plan.to_events())}")
        for note in plan.notes:
            print(f"note           : {note}")
        if args.json:
            print("\n--- plan summary (JSON) ---")
            print(json.dumps(plan.summary(), indent=2, sort_keys=True, default=str))
        return 0

    # --- apply ---
    result = apply_plan(
        plan, project_id=project_id, api_key=api_key, batch=not args.no_batch
    )
    print(f"applied {result['n_events']} merge events; row_ids={len(result['row_ids'])}")
    deep_link = (
        f"https://www.braintrust.dev/app/{args.project}/p/{args.project}/logs"
        f"?r={trace['root_span_id']}"
    )
    print(f"view: {deep_link}")

    if args.verify:
        row = bt_client.read_span(
            plan.root_span_id, project_id=project_id, api_key=api_key, settle_seconds=4.0
        )
        if row:
            print("verify: root span scores =", row.get("scores"))
            print("verify: root span tags   =", row.get("tags"))
        else:
            print("verify: root span re-read returned nothing (indexing lag?)")

    if args.json:
        print(json.dumps(plan.summary(), indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

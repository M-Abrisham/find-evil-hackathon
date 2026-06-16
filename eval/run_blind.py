#!/usr/bin/env python3
"""
Protocol SIFT — BLIND evaluation runner (build-time tooling — NOT part of any hackathon submission).

Drives ONE blind investigation: point the AI at a read-only evidence mount and a neutral prompt
that does NOT reveal the attack type. The AI must (1) CLASSIFY the incident into the 24-category
on-box SIFT Detection-&-Analysis taxonomy by itself, then (2) investigate and emit findings JSON
matching findings.schema.json — every claim pinned to a literal copied from a named run-verified
tool's output. A separate scorer (not in scope here) compares that output to the HIDDEN rubric.

RUNTIME — Claude SUBSCRIPTION, never an API key:
  Calls go through the Claude Code headless CLI (`claude -p`), which uses your `claude login`
  subscription OAuth. A set ANTHROPIC_API_KEY would SILENTLY override that into metered API
  billing, so this script UNSETS it for the child process (matching playbooks/build_playbook.py).
  To use a different Claude-Code-compatible runner, set BLIND_AGENT (it must accept the same
  -p / --model / --output-format / --append-system-prompt interface, or be wrapped).

RUNS MUST *BE* PROTOCOL SIFT:
  `claude -p` auto-loads the user config layer (~/.claude/CLAUDE.md and ~/.claude/skills/) — that
  layer IS Protocol SIFT. At startup this script checks for both and warns LOUDLY on stderr if
  either is missing (the run would be bare Claude, not Protocol SIFT). It warns only — it does not
  fail — so a deliberate no-config baseline run stays possible.

PLAYBOOK-EQUIPPED runs (--playbook <path>):
  Optionally inject an OPERATOR-pre-selected Protocol SIFT playbook into the user prompt — BODY
  ONLY: the YAML frontmatter is STRIPPED before injection because it names the attack type
  (attack_type/category_id/sub_types), which would un-blind the classification. Classification
  stays BLIND — the agent must still classify the attack type itself from the evidence alone; the
  playbook only scripts HOW to investigate (the agent is told to follow its "Quick path" +
  "Steps"). The operator may pre-select it because, unlike the agent, the operator knows the
  case's ground truth for this validation run.

Setup (once):
    claude login                      # log in with the Pro/Max subscription
    # (no pip install, no ANTHROPIC_API_KEY)

Env knobs (all optional):
    BLIND_AGENT        the runner binary (default: claude)
    BLIND_MODEL        model alias (default: opus)
    BLIND_AGENT_ARGS   extra CLI args appended to every call (shlex-split). This is where you pass
                       the runner's sandbox / allowed-tools flags so the agent can run the on-box
                       forensic tools on the mount but cannot write to evidence or reach the network,
                       e.g. "--allowedTools Bash Read Grep --add-dir <mount>"
                       (exact flags depend on your runner/version — see eval/README.md).
    BLIND_TIMEOUT      per-run timeout seconds (default: 3600).

Usage:
    python run_blind.py --mount /cases/<id>/mounts/case --out /cases/<id>/output/findings.json \\
                        [--case-id <id>] [--playbook playbooks/<category>.md]

Exit status: 0 if a schema-valid findings.json was written; non-zero otherwise (the raw model
result is still saved next to --out as <out>.raw.txt for triage).
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys

MODEL = os.environ.get("BLIND_MODEL", "opus")          # `claude -p --model opus` = latest Opus
AGENT_CMD = os.environ.get("BLIND_AGENT", "claude")
AGENT_ARGS = shlex.split(os.environ.get("BLIND_AGENT_ARGS", ""))
TIMEOUT = int(os.environ.get("BLIND_TIMEOUT", "3600"))
HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
SCHEMA_PATH = HERE / "findings.schema.json"

# The 24 ON-BOX Detection-&-Analysis categories (the only valid classification labels). Kept in sync
# with findings.schema.json: loaded from it at runtime so there is a single source of truth.
FALLBACK_CATEGORIES = [
    "Acquisition, Custody & Cross-Platform Synthesis", "Endpoint / Disk & File System",
    "File Recovery, Carving & Data Reduction", "Memory (RAM) Forensics",
    "Windows Artifacts - Execution & User Activity", "Windows Registry & Persistence",
    "Windows Event Logs (EVTX/ETW)", "Linux / Unix Host Forensics", "macOS Forensics",
    "Browser, Email & Document Forensics", "Web / Perimeter & Server Compromise",
    "Network Forensics", "Malware Analysis & Triage", "Active Directory & Domain",
    "Cloud Identity & SaaS", "Cloud IaaS Control-Plane & Data",
    "Containers, CI/CD & Software Supply Chain", "Attack-Lifecycle Hunting (ATT&CK)",
    "Impact, Ransomware & Destructive", "Insider Threat, Fraud & Data Theft",
    "Steganography, Data-Hiding & Encryption", "Threat Hunting & IOC Sweeps",
    "Targeted Intrusion / APT & Specialized", "Virtualization & Mobile/Embedded",
]


def _read(p: pathlib.Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""


def _strip_frontmatter(md: str) -> str:
    """Drop a leading YAML frontmatter block (--- ... ---) from a playbook before injection.

    The frontmatter carries attack_type/category_id/sub_types — injecting it would LEAK the
    classification and un-blind the run. Only the body (Quick path, Steps, ...) is injected."""
    lines = md.splitlines(keepends=True)
    i = 0
    while i < len(lines) and not lines[i].strip():
        i += 1
    if i >= len(lines) or lines[i].strip() != "---":
        return md
    for j in range(i + 1, len(lines)):
        if lines[j].strip() == "---":
            return "".join(lines[j + 1:]).lstrip("\n")
    return md          # unterminated frontmatter: leave untouched rather than truncate


def _load_schema() -> dict:
    try:
        return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _categories(schema: dict) -> list[str]:
    """The 24 valid labels, read from the schema's enum so the prompt can never drift from it."""
    try:
        return list(schema["$defs"]["sift_category"]["enum"])
    except Exception:
        return FALLBACK_CATEGORIES


# Run-verified tool list — the ONLY tools the agent may name. This is box-derived truth (90 tools
# actually executed on the SIFT box), NOT the model's memory. Mirrors build_playbook.py's grounding.
VERIFIED_TOOLS = _read(ROOT / "Running_Tool_Claude_Verification")
FINDINGS_SCHEMA_TEXT = _read(SCHEMA_PATH)


def _system_prompt(categories: list[str]) -> str:
    cat_list = "\n".join(f"  - {c}" for c in categories)
    return f"""You are a digital-forensics investigator working a case BLIND on a SANS SIFT workstation.
You are NOT told what kind of incident this is. Determine it yourself, only from the evidence.

GOLDEN RULES (a blind, scored run — obey strictly):
1. READ-ONLY EVIDENCE. The mount is read-only; never write to, mount-rw, or modify any evidence
   byte. Do your scratch work outside the mount. Treat the original as untouchable.
2. CLASSIFY FIRST, THEN INVESTIGATE. Your single best attack/investigation type MUST be one of
   these 24 on-box SIFT Detection-&-Analysis categories (verbatim — copy the exact string):
{cat_list}
3. GROUND EVERY TOOL NAME. You may name a tool ONLY if it is in the RUN-VERIFIED tool list below
   (90 tools actually executed on this box). Do NOT name a tool from your own knowledge. Notable
   absences to respect: NO PECmd, NO SrumECmd, NO yara CLI (python3-yara lib only), NO Volatility 2
   (Vol3 `vol` only), Memory Baseliner and vss_carver absent (use vshadowmount/vshadowinfo). If the
   natural tool is off-box, say so — never claim you ran it.
4. QUOTE-FIRST GROUNDING. Every finding's evidence_pointer.literal_cited MUST be a substring you
   actually saw in that tool's output — copy it verbatim. A claim with no backing literal is a
   hallucination and will be scored against you. When the evidence does not support a claim, set
   confidence to "insufficient_evidence" and abstain — do NOT guess.
5. TWO-SOURCE RULE for conclusions: a claim corroborated by a second independent tool/artifact is a
   conclusion; a single-source claim is a lead — reflect that in confidence and sources[].

OUTPUT CONTRACT:
- Emit EXACTLY ONE JSON object that validates against the findings schema below — nothing else in
  your final message: no markdown, no code fence, no prose before or after. Start with '{{' end with '}}'.
- attack_type_classification.category is your single best label from the 24 above. Use
  secondary_categories for additional stages (multi-stage incidents are common).
- Each finding: {{id, claim, evidence_pointer{{artifact, offset_or_row, literal_cited}}, tool_used,
  confidence(confirmed|inferred|insufficient_evidence), sources[]}}.

=== RUN-VERIFIED TOOL LIST (the ONLY tools you may name) ===
{VERIFIED_TOOLS}

=== FINDINGS JSON SCHEMA (your final message must validate against this) ===
{FINDINGS_SCHEMA_TEXT}
"""


def _user_prompt(mount: str, case_id: str, playbook_md: str = "") -> str:
    # A non-empty playbook_md does NOT un-blind the run: the OPERATOR pre-selected the playbook
    # for this validation run (the operator, unlike the agent, knows the case's ground truth).
    # The agent must still produce its OWN classification from the evidence alone — the playbook
    # only scripts HOW to investigate (Quick path + Steps), never WHAT the answer is.
    playbook_section = ""
    if playbook_md:
        playbook_section = f"""

=== OPERATOR-SELECTED PROTOCOL SIFT PLAYBOOK (follow it) ===
The operator pre-selected this playbook for this run. Your classification in step 2 must still be
YOUR OWN, derived only from the evidence — do NOT copy or infer it from the playbook. For the
investigation itself (step 3), FOLLOW this playbook: execute its "Quick path" first, then work
through its "Steps" in order, still obeying every golden rule above (read-only evidence,
run-verified tools only, quote-first grounding).

{playbook_md}
=== END OPERATOR-SELECTED PLAYBOOK ===
"""
    return f"""A piece of digital evidence has been mounted READ-ONLY at:

    {mount}

You have NOT been told what happened. Investigate it end to end:
  1. Triage the mount (what OS / artifacts are present) using the run-verified on-box tools.
  2. CLASSIFY the incident into ONE of the 24 on-box SIFT categories (plus any secondary stages).
  3. Establish the facts: key artifacts, IOCs, the timeline, the accounts involved, and what data
     left or was encrypted/destroyed — each as a finding pinned to a literal you copied from a
     tool's output.
  4. Abstain (confidence="insufficient_evidence") on anything the evidence does not support.
{playbook_section}
case_id: {case_id}

Return ONLY the findings JSON object (validating against the schema you were given). No other text."""


def _warn_if_protocol_sift_not_installed() -> None:
    """Runs must BE Protocol SIFT: `claude -p` auto-loads the user config layer (~/.claude/CLAUDE.md
    and ~/.claude/skills/), and that layer IS Protocol SIFT. If either is missing the run is bare
    Claude. Warn loudly on stderr; do NOT fail (a deliberate no-config baseline stays possible)."""
    claude_home = pathlib.Path.home() / ".claude"
    missing = [p for p in (claude_home / "CLAUDE.md", claude_home / "skills") if not p.exists()]
    if not missing:
        return
    bar = "!" * 78
    print(bar, file=sys.stderr)
    print("WARNING: Protocol SIFT config layer NOT installed — this run will be BARE Claude,",
          file=sys.stderr)
    print("         not Protocol SIFT (`claude -p` auto-loads the user config layer):",
          file=sys.stderr)
    for p in missing:
        print(f"         missing: {p}", file=sys.stderr)
    print("         Install ~/.claude/CLAUDE.md + ~/.claude/skills/ so validation runs ARE",
          file=sys.stderr)
    print("         Protocol SIFT runs. Continuing anyway (warning only).", file=sys.stderr)
    print(bar, file=sys.stderr)


# --- lightweight, stdlib-only check that the emitted object matches the findings schema ----------
# Not a full JSON-Schema validator (avoids a third-party dependency per repo rules) — it enforces the
# structural contract a scorer relies on. A separate scorer can do strict validation if desired.
def _validate_findings(obj: object, categories: list[str]) -> list[str]:
    errs: list[str] = []
    if not isinstance(obj, dict):
        return ["top-level value is not a JSON object"]

    cls = obj.get("attack_type_classification")
    if not isinstance(cls, dict):
        errs.append("missing/invalid attack_type_classification (object required)")
    else:
        cat = cls.get("category")
        if cat not in categories:
            errs.append(f"attack_type_classification.category not one of the 24 categories: {cat!r}")
        if cls.get("confidence") not in ("confirmed", "inferred", "insufficient_evidence"):
            errs.append(f"attack_type_classification.confidence invalid: {cls.get('confidence')!r}")
        if not str(cls.get("rationale", "")).strip():
            errs.append("attack_type_classification.rationale is empty")
        sec = cls.get("secondary_categories", [])
        if not isinstance(sec, list) or any(c not in categories for c in sec):
            errs.append("attack_type_classification.secondary_categories has a non-taxonomy value")

    findings = obj.get("findings")
    if not isinstance(findings, list):
        errs.append("missing/invalid findings (array required)")
        return errs

    seen_ids: set[str] = set()
    for i, f in enumerate(findings):
        where = f"findings[{i}]"
        if not isinstance(f, dict):
            errs.append(f"{where} is not an object")
            continue
        fid = f.get("id")
        if not isinstance(fid, str) or not fid:
            errs.append(f"{where}.id missing")
        else:
            if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", fid):
                errs.append(f"{where}.id has invalid characters: {fid!r}")
            if fid in seen_ids:
                errs.append(f"{where}.id duplicate: {fid!r}")
            seen_ids.add(fid)
        if not str(f.get("claim", "")).strip():
            errs.append(f"{where}.claim empty")
        ep = f.get("evidence_pointer")
        if not isinstance(ep, dict):
            errs.append(f"{where}.evidence_pointer missing/invalid")
        else:
            if not str(ep.get("artifact", "")).strip():
                errs.append(f"{where}.evidence_pointer.artifact empty")
            if "offset_or_row" not in ep:
                errs.append(f"{where}.evidence_pointer.offset_or_row missing")
            if not str(ep.get("literal_cited", "")).strip():
                errs.append(f"{where}.evidence_pointer.literal_cited empty (claim is UNBACKED)")
        if not str(f.get("tool_used", "")).strip():
            errs.append(f"{where}.tool_used empty")
        if f.get("confidence") not in ("confirmed", "inferred", "insufficient_evidence"):
            errs.append(f"{where}.confidence invalid: {f.get('confidence')!r}")
        srcs = f.get("sources")
        if not isinstance(srcs, list) or not srcs:
            errs.append(f"{where}.sources must be a non-empty array")
        else:
            for j, s in enumerate(srcs):
                if not isinstance(s, dict) or not str(s.get("tool", "")).strip() \
                        or not str(s.get("artifact", "")).strip():
                    errs.append(f"{where}.sources[{j}] needs tool + artifact")
    return errs


def _extract_json(text: str) -> object:
    """Pull the findings object out of the model's final message, tolerating a stray code fence."""
    s = text.strip()
    m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", s, re.S)
    if m:
        s = m.group(1)
    # Otherwise take from the first '{' to the last '}' (the schema output is a single object).
    if not s.startswith("{"):
        i, jx = s.find("{"), s.rfind("}")
        if i != -1 and jx != -1 and jx > i:
            s = s[i:jx + 1]
    return json.loads(s)


def _call(system: str, user: str) -> tuple[str, float]:
    """One Claude turn via the SUBSCRIPTION-authed headless CLI. Returns (final_text, cost_usd)."""
    env = os.environ.copy()
    if env.pop("ANTHROPIC_API_KEY", None) is not None:
        print("  (unset ANTHROPIC_API_KEY for this call -> subscription auth)", file=sys.stderr)
    cmd = [AGENT_CMD, "-p", user, "--model", MODEL, "--output-format", "json",
           "--append-system-prompt", system, *AGENT_ARGS]
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=TIMEOUT)
    if r.returncode != 0:
        raise RuntimeError(f"{AGENT_CMD} -p failed (exit {r.returncode}): {r.stderr[:600]}")
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:                       # some runners print plain text
        return r.stdout.strip(), 0.0
    return str(data.get("result", "")).strip(), float(data.get("total_cost_usd", 0) or 0)


def run_blind(mount: str, out_path: pathlib.Path, case_id: str, playbook: str = "") -> int:
    _warn_if_protocol_sift_not_installed()
    mount_p = pathlib.Path(mount)
    if not mount_p.exists():
        print(f"ERROR: mount path does not exist: {mount}", file=sys.stderr)
        return 2
    playbook_md = ""
    if playbook:
        playbook_p = pathlib.Path(playbook)
        if not playbook_p.is_file():
            print(f"ERROR: --playbook path does not exist: {playbook}", file=sys.stderr)
            return 2
        playbook_md = _strip_frontmatter(_read(playbook_p))
        print(f"  (playbook-equipped run: injecting {playbook_p} BODY ONLY — YAML frontmatter "
              f"stripped so attack_type/category_id cannot un-blind the classification)",
              file=sys.stderr)
    schema = _load_schema()
    categories = _categories(schema)
    if not VERIFIED_TOOLS:
        print("WARNING: Running_Tool_Claude_Verification not found — tool grounding will be weak.",
              file=sys.stderr)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path = out_path.with_suffix(out_path.suffix + ".raw.txt")

    result, cost = _call(_system_prompt(categories),
                         _user_prompt(str(mount_p), case_id, playbook_md))
    raw_path.write_text(result, encoding="utf-8")      # always keep the raw result for triage

    try:
        obj = _extract_json(result)
    except Exception as e:
        print(f"FAIL  -> model output was not parseable JSON ({e}). Raw saved -> {raw_path}",
              file=sys.stderr)
        return 1

    if isinstance(obj, dict):
        obj.setdefault("case_id", case_id)

    errs = _validate_findings(obj, categories)
    out_path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")

    cat = (obj.get("attack_type_classification") or {}).get("category") if isinstance(obj, dict) else None
    n = len(obj.get("findings") or []) if isinstance(obj, dict) else 0
    if errs:
        print(f"WROTE (schema-INVALID) -> {out_path}")
        print(f"  classification: {cat!r}   findings: {n}   cost_usd: ${cost:.4f}")
        for e in errs[:25]:
            print(f"  [schema] {e}")
        if len(errs) > 25:
            print(f"  ... and {len(errs) - 25} more")
        return 1

    print(f"DONE  -> {out_path}")
    print(f"  classification: {cat!r}   findings: {n}   cost_usd (0 on subscription credit): ${cost:.4f}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Drive ONE blind Protocol SIFT investigation (subscription only).")
    ap.add_argument("--mount", required=True, help="read-only path the evidence is mounted at")
    ap.add_argument("--out", required=True, help="path to write the findings JSON")
    ap.add_argument("--case-id", default="", help="case identifier (default: derived from --mount)")
    ap.add_argument("--playbook", default="",
                    help="path to an OPERATOR-pre-selected Protocol SIFT playbook (markdown); its "
                         "BODY (YAML frontmatter stripped — it names the attack type) is injected "
                         "into the prompt and the agent must follow its Quick path + Steps — "
                         "classification stays blind")
    args = ap.parse_args()
    out_path = pathlib.Path(args.out).resolve()
    case_id = args.case_id or pathlib.Path(args.mount).resolve().parent.name or "blind-case"
    return run_blind(args.mount, out_path, case_id, playbook=args.playbook)


if __name__ == "__main__":
    sys.exit(main())

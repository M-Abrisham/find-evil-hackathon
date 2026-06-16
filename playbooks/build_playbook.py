#!/usr/bin/env python3
"""
SIFT Forensic Playbook Generator — a Claude-powered agent (OpenClaw / Claude Code, SUBSCRIPTION-driven).

BUILD-TIME TOOLING ONLY — not part of any hackathon submission. Given ONE attack type, it:
  1. AUTHORS a forensic playbook in the house hybrid template (readable + executable steps),
     grounded ONLY in the RUN-VERIFIED tool list. The authoring pack also injects: the LEGAL
     24-category-id list (pivots may target only those ids or SELF), the category's tool-map row
     (optional 3rd CLI arg), and the nearest 05-COOKBOOK.md gold exemplar (PB-EXEC / PB-PERSIST /
     PB-MEMDISK / PB-EXFIL, picked by keyword match on the category id);
  2. researches a grounded INTEL arm (web) for non-obvious real-case findings — tool-grounded so
     it can't name off-box tools (the failure the pilot caught: SRUM-DUMP, OneDriveExplorer, etc.).
     Intel is HELD and re-merged after EVERY verify/re-author pass (the intel-wipe fix); before any
     write the script asserts the marker is gone AND "Real-case notes" is non-empty, else fails loudly;
  3. adversarially VERIFIES it (the fix-applying editor pass) and loops until clean. Verify BLOCKS on:
     hallucinated/off-box tools, single-source conclusions, pivot ids outside the legal list,
     literal example paths or "..." in tool lines, and steps missing a check: predicate;
  4. runs a final SCORE-ONLY JUDGE call (separate from the editor; model $PLAYBOOK_JUDGE_MODEL,
     default "sonnet") whose JSON verdict is written to <out-dir>/<id>.verdict.json. A missing or
     unparseable verdict exits NONZERO — never a silent retry. Drivers gate on the verdict file.

SCORING LOCKS honored here:
  #1 every playbook version is PRESERVED — an existing <id>.md is archived to versions/<id>/v<N>.md
     with a versions/<id>/CHANGELOG line (utc date | reason) before the new write;
  #2 all edits in the verify loop are AGENT-ONLY (no human in the edit step — humans review/approve).

RUNTIME — Claude SUBSCRIPTION, not API keys:
  Calls go through the Claude Code headless CLI (`claude -p`), which uses your `claude login`
  subscription OAuth. A set ANTHROPIC_API_KEY would silently override that into metered API
  billing, so this script UNSETS it for the child process. To use OpenClaw (or any Claude-Code-
  compatible runner) instead, set PLAYBOOK_AGENT=openclaw (it must accept the same -p / --model /
  --output-format / --append-system-prompt interface, or wrap it).

Setup:
    claude login                      # one-time: log in with the Pro/Max subscription
    # (no pip install, no ANTHROPIC_API_KEY)

Env knobs (all optional):
    PLAYBOOK_AGENT        the runner binary (default: claude)
    PLAYBOOK_MODEL        author/verify model alias (default: opus)
    PLAYBOOK_JUDGE_MODEL  score-only judge model alias (default: sonnet)
    PLAYBOOK_AGENT_ARGS   extra CLI args appended to every call (shlex-split)
    PLAYBOOK_INTEL_ARGS   extra CLI args for the web INTEL call only — set this to enable web tools,
                          e.g. "--allowedTools WebSearch WebFetch" (exact flag depends on your runner)
    PLAYBOOK_ID_LIST      path to the category-id list, used ONLY if factory/categories.txt is absent

Call (one attack type at a time; tool-map row is optional):
    python build_playbook.py data-exfiltration-insider "Insider steals data via USB/cloud/email" \
        "<the category's row from the tool map, verbatim>"

OpenClaw (or any loop harness) drives it by calling this command once per attack type and moving to
the next only after it writes <id>.md + <id>.verdict.json and prints DONE.
"""
from __future__ import annotations

import datetime
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys

MODEL = os.environ.get("PLAYBOOK_MODEL", "opus")     # `claude -p --model opus` = latest Opus
JUDGE_MODEL = os.environ.get("PLAYBOOK_JUDGE_MODEL", "sonnet")   # score-only judge (cheap model)
# The web-research INTEL arm needs a security-capable model: Fable 5's safety filter blocks
# cybersecurity/malware web research ("API Error: Fable 5 has safety measures that flag ... cybersecurity").
# So the playbook AUTHOR/verify stay on MODEL (e.g. fable) while INTEL researches on a different model.
INTEL_MODEL = os.environ.get("PLAYBOOK_INTEL_MODEL", "sonnet")
AGENT_CMD = os.environ.get("PLAYBOOK_AGENT", "claude")
AGENT_ARGS = shlex.split(os.environ.get("PLAYBOOK_AGENT_ARGS", ""))
INTEL_ARGS = shlex.split(os.environ.get("PLAYBOOK_INTEL_ARGS", ""))   # set to enable web tools
HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
MAX_RETRIES = 2                       # loop-until-clean cap (can't spin forever)
INTEL_MARKER = "<!--INTEL-->"         # author leaves this where the web arm injects real-case notes


# --- grounding sources ------------------------------------------------------
def _read(p: pathlib.Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""


def _find(root: pathlib.Path, name_or_glob: str) -> str:
    """Read a file by exact name, falling back to a glob (handles trailing-space filenames)."""
    p = root / name_or_glob
    if p.exists():
        return _read(p)
    hits = sorted(root.glob(name_or_glob))
    return _read(hits[0]) if hits else ""


# The TWO authoritative attack-type <-> tool MAPS: the ONLY source of which attack/investigation
# types exist and which SIFT tools cover each. NOT Claude's own knowledge.
MAP_INVENTORY = _find(ROOT, "SIFT Inventory → IR Investigation Types")
MAP_TAXONOMY = _find(ROOT, "Complete_IR_Investigation_Type_Taxonomy*")   # filename has trailing spaces
# Runnability FILTER (a box-derived FILE, not memory): which mapped tools actually execute.
VERIFIED_TOOLS = _find(ROOT, "Running_Tool_Claude_Verification")
TEMPLATE = _read(HERE / "_TEMPLATE.md")                                  # the house hybrid format


# --- the legal category-id list (the pivot universe) ------------------------
def _category_ids() -> list[str]:
    """Parse the legal category ids. factory/categories.txt wins if present (repo layout:
    playbooks/factory/; deployed factory layout: categories.txt at the generator's ROOT);
    only then fall back to the file named by $PLAYBOOK_ID_LIST. Lines: <kebab-id>|<desc>."""
    paths = [HERE / "factory" / "categories.txt", ROOT / "factory" / "categories.txt",
             ROOT / "categories.txt", HERE / "categories.txt"]
    envp = os.environ.get("PLAYBOOK_ID_LIST", "")
    if envp:
        paths.append(pathlib.Path(envp))
    for p in paths:
        if p.exists():
            ids = [l.split("|", 1)[0].strip() for l in _read(p).splitlines()
                   if l.strip() and not l.lstrip().startswith("#")]
            if ids:
                return ids
    return []


CATEGORY_IDS = _category_ids()

PIVOT_RULE = ("PIVOT RULE — Pivots may target ONLY one of these category ids, or the literal SELF.\n"
              "Any other pivot target is a BLOCKING defect:\n"
              + "\n".join(f"  - {i}" for i in CATEGORY_IDS)) if CATEGORY_IDS else ""


# --- gold exemplar (05-COOKBOOK.md) ------------------------------------------
_COOKBOOK = _read(ROOT / "05-COOKBOOK.md") or _read(HERE / "05-COOKBOOK.md")

_EXEMPLAR_KEYWORDS = [          # first keyword found in the category id picks the exemplar
    ("exfil", "PB-EXFIL-001"), ("insider", "PB-EXFIL-001"), ("theft", "PB-EXFIL-001"),
    ("network", "PB-EXFIL-001"), ("cloud", "PB-EXFIL-001"), ("steg", "PB-EXFIL-001"),
    ("persist", "PB-PERSIST-001"), ("registry", "PB-PERSIST-001"),
    ("active-directory", "PB-PERSIST-001"), ("domain", "PB-PERSIST-001"),
    ("memory", "PB-MEMDISK-001"), ("disk", "PB-MEMDISK-001"), ("filesystem", "PB-MEMDISK-001"),
    ("carving", "PB-MEMDISK-001"), ("virtualization", "PB-MEMDISK-001"),
]                               # everything else (exec/malware/ransomware/logs/...) -> PB-EXEC-001


def _gold_exemplar(attack_id: str) -> str:
    """Extract the nearest cookbook gold playbook (### PB-XXX-001 section) for the category."""
    if not _COOKBOOK:
        return ""
    pb = next((pb for kw, pb in _EXEMPLAR_KEYWORDS if kw in attack_id), "PB-EXEC-001")
    m = re.search(rf"^### {re.escape(pb)} .*?(?=^### |^## |\Z)", _COOKBOOK, re.M | re.S)
    return m.group(0).strip() if m else ""


GROUNDING = f"""You may use ONLY the two attack-type<->tool MAP files below as the source of which
attack/investigation types exist and which SIFT tools cover each. Do NOT introduce an attack type or a
tool from your own training/knowledge — if it is not in these two files, it is out of scope.

=== MAP 1 of 2 — SIFT Inventory -> IR Investigation Types (investigation/attack type -> tools) ===
{MAP_INVENTORY}

=== MAP 2 of 2 — Complete IR Investigation-Type Taxonomy (attack categories -> tools, with on-box? flag) ===
{MAP_TAXONOMY}

=== RUNNABILITY FILTER — Running_Tool_Claude_Verification (which mapped tools ACTUALLY execute on the box) ===
A tool from the maps above may be USED in Steps only if it is runnable here. Tools the maps list but that
are absent/broken on the box (e.g. PECmd, SrumECmd, yara CLI, Memory Baseliner, vss_carver) MUST NOT be
used — use the verified substitute this file names, or tag ⚠️verify. This file is box-derived truth, not memory.
{VERIFIED_TOOLS}

=== PLAYBOOK TEMPLATE (author into EXACTLY this shape) ===
{TEMPLATE}
"""

AUTHOR_RULES = f"""You author forensic playbooks for the SANS SIFT Workstation (build-time only).
Rules:
- Use ONLY the two attack-type<->tool MAP files for which attack types and tools are in scope — never
  introduce an attack type or tool from your own knowledge. A tool may be USED in a Step only if it is
  ALSO runnable per the runnability filter; mapped-but-absent tools (PECmd, SrumECmd, yara CLI, Memory
  Baseliner, vss_carver) → use the verified substitute, or tag ⚠️verify. Unsure → ⚠️verify, never assert.
- Fill EVERY section of the hybrid template. The "Steps" section is EXECUTABLE: each step needs a
  real run-verified tool + exact args, an `expect` literal, a `check` shell predicate, a `falsify`,
  an `on_result` branch, `emits`/`serves` tags, and `provenance` (receipt_id, artifact, offset_or_row,
  literal_cited). Steps must read as a decision flow that always names the BEST NEXT STEP
  ("do X -> if you see Y, go to step N; else ...").
- `tool:` lines reference frontmatter `variables:` ONLY (#{{image_path}}, #{{mount_root}}, #{{case_out}},
  #{{ntfs_offset_sectors}}, #{{time_window}}). Literal example paths (e.g. /evidence/HOST01.E01, /mnt/c)
  and "..." placeholders are BANNED in tool lines. Step 0 (evidence inventory & access bootstrap) binds
  the variables; the numbered Linux branch (L1..Ln) follows the same step shape.
- Cover Windows + Linux + macOS (+ cloud where it applies). If SIFT lacks a tool for an OS, SAY SO.
- Map attacker types (insider / other-insider / external-commodity / external-targeted /
  supply-chain / innocent) into the Theories table; >=1 benign + >=1 malicious, each refuted.
- PLAIN language: a non-expert investigator must follow it; gloss every artifact term on first use
  and collect them in the Jargon decoder. Two-source rule on every conclusion.
- For the "Real-case notes" section, output ONLY its header line, then a line containing exactly
  {INTEL_MARKER} and nothing else. A separate grounded web arm fills it — do NOT write notes yourself.
Return ONLY the finished markdown playbook (start at the --- frontmatter; no preamble, no code fences)."""


def _author_system(tool_row: str, exemplar: str) -> str:
    """The authoring pack: base rules + legal-id pivot rule + the category's tool-map row (CLI arg 3)
    + the nearest cookbook gold exemplar."""
    parts = [AUTHOR_RULES]
    if PIVOT_RULE:
        parts.append(PIVOT_RULE)
    if tool_row:
        parts.append("CATEGORY TOOL-MAP ROW (the authoritative tool set for THIS category — "
                     "prefer these tools in Steps):\n" + tool_row)
    if exemplar:
        parts.append("GOLD EXEMPLAR (nearest cookbook playbook — match its expect/falsify rigor, "
                     "pivot discipline and failure_modes; your OUTPUT shape is the TEMPLATE above, "
                     "not this yaml):\n" + exemplar)
    return "\n\n".join(parts)


INTEL_SYSTEM = f"""You research REAL, documented forensic incidents to surface NON-OBVIOUS, high-signal
findings an investigator would otherwise miss (surprising artifact locations, in-the-wild anti-forensics,
per-OS quirks, cases where the obvious tool missed it). Use web search/fetch.
HARD GROUNDING GATE (this is why the pilot failed — obey it):
- A finding may describe WHERE to look or a TECHNIQUE, but must NOT name a tool as a directive unless that
  tool is in the two MAP files AND runnable per the runnability filter below. If the natural tool is off-box,
  say so and tag ⚠️verify
  — never tell the investigator to "run <off-box tool>".
- Every claim carries `[source · confidence: high/med/low]`. Never invent an incident or citation; if you
  cannot source it, drop it. Single-source operational claims are leads, not facts — phrase them as such.
{GROUNDING}
Return ONLY a markdown section body (5-9 bullet findings) to sit under the "Real-case notes" header. No header."""

VERIFY_SYSTEM = """You adversarially verify a draft SIFT playbook against the RUN-VERIFIED tool list.
Your job is to REFUTE it, not approve it. Apply small inline fixes; tag any still-unverified tool claim
with ⚠️verify. Check, specifically:
 (1) every named tool appears in the two MAP files AND is runnable per the runnability filter, and its
     "reveals" claim is accurate (list any tool not-in-maps OR not-runnable in hallucinated_tools — check
     the Real-case notes section too, that's where off-box tools sneak in); flag any attack type or tool
     introduced from the model's own knowledge rather than the maps;
 (2) no fabricated cases/citations; every real-case note has a source;
 (3) every CONCLUSION has >=2 independent sources (flag single-source conclusions);
 (4) Steps are executable (expect/falsify a program could actually check; provenance present);
 (5) plain language — every artifact term glossed; Windows/Linux/macOS covered;
 (6) every Pivots target resolves to a legal category id from the PIVOT RULE list (or SELF) — list every
     unresolvable target in unresolvable_pivots; ANY entry there is BLOCKING;
 (7) every step's tool: line uses #{variables} from the frontmatter variables: block ONLY — list any tool
     line containing a literal example path (e.g. /evidence/HOST01.E01, /mnt/c, C:\\Users) or a "..."
     placeholder in banned_literal_lines; ANY entry there is BLOCKING;
 (8) every step — Step 0, the Windows steps AND the L1..Ln Linux branch — has a check: shell predicate
     over its receipt file; list step ids missing it in steps_missing_check; ANY entry there is BLOCKING.
Score the rubric 0/1/2 each: grounded, jargon_free, decision_driven, multi_os, provenance_ready.
Return ONLY the corrected markdown — start at the `---` frontmatter, NO preamble or commentary before it,
NO ```yaml fence around the frontmatter — then on a NEW LINE a fenced json block EXACTLY like:
```json
{"rubric":{"grounded":0,"jargon_free":0,"decision_driven":0,"multi_os":0,"provenance_ready":0},
 "blocking":true,"hallucinated_tools":[],"unresolvable_pivots":[],"banned_literal_lines":[],
 "steps_missing_check":[],"fix_list":[{"section":"","problem":"","suggested_fix":""}],
 "one_line_verdict":""}
```
Set blocking=true if ANY tool is hallucinated OR any conclusion is single-source OR any of
unresolvable_pivots / banned_literal_lines / steps_missing_check is non-empty.""" \
    + (("\n\n" + PIVOT_RULE) if PIVOT_RULE else "")

JUDGE_SYSTEM = """You are a SCORE-ONLY judge of a FINISHED SIFT playbook. You do NOT edit, fix, or
rewrite anything — output NO markdown, apply NO changes; return ONLY the verdict json.
Grade against the same gates as the adversarial verifier:
 - hallucinated/off-box tools (check the Real-case notes too) and fabricated cases/citations;
 - single-source conclusions (two-source rule);
 - Pivots targets outside the legal PIVOT RULE list below (or SELF) -> unresolvable_pivots;
 - tool: lines with literal example paths or "..." instead of #{variables} -> banned_literal_lines;
 - steps (Step 0, Windows, L1..Ln Linux branch) lacking a check: predicate -> steps_missing_check;
 - missing/empty Real-case notes; plain language; Windows/Linux/macOS coverage; provenance per step.
Score the rubric 0/1/2 each: grounded, jargon_free, decision_driven, multi_os, provenance_ready.
Return EXACTLY ONE fenced json block and NOTHING else:
```json
{"rubric":{"grounded":0,"jargon_free":0,"decision_driven":0,"multi_os":0,"provenance_ready":0},
 "blocking":true,"hallucinated_tools":[],"unresolvable_pivots":[],"banned_literal_lines":[],
 "steps_missing_check":[],"fix_list":[{"section":"","problem":"","suggested_fix":""}],
 "one_line_verdict":""}
```
Set blocking=true if ANY tool is hallucinated OR any conclusion is single-source OR any of
unresolvable_pivots / banned_literal_lines / steps_missing_check is non-empty.""" \
    + (("\n\n" + PIVOT_RULE) if PIVOT_RULE else "")


def _strip_fences(s: str) -> str:
    return re.sub(r"^\s*```(?:markdown|md)?\s*", "", s).rsplit("```", 1)[0].strip() \
        if s.lstrip().startswith("```") else s.strip()


def _clean(md: str) -> str:
    """Normalize the saved playbook: drop any model preamble before the frontmatter, and unwrap a
    ```yaml-fenced frontmatter so the file is valid markdown the agent can load."""
    lines = _strip_fences(md).strip().splitlines()
    for i, l in enumerate(lines):                      # cut preamble before the frontmatter opener
        if l.strip() == "---":
            lines = lines[i:]
            break
    if len(lines) > 2 and lines[0].strip() == "---" and lines[1].strip().startswith("```"):
        del lines[1]                                   # drop the opening ```yaml
        for j in range(1, len(lines)):                 # drop its matching closing fence
            if lines[j].strip() == "```":
                del lines[j]
                break
    return "\n".join(lines).strip()


def _call(system: str, user: str, extra: list[str] | None = None,
          model: str = MODEL) -> tuple[str, float]:
    """One Claude turn via the SUBSCRIPTION-authed headless CLI. Returns (final_text, cost_usd)."""
    env = os.environ.copy()
    if env.pop("ANTHROPIC_API_KEY", None) is not None:
        print("  (unset ANTHROPIC_API_KEY for this call -> subscription auth)", file=sys.stderr)
    cmd = [AGENT_CMD, "-p", user, "--model", model, "--output-format", "json",
           "--append-system-prompt", system, *AGENT_ARGS, *(extra or [])]
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=900)
    if r.returncode != 0:
        # the real error from `claude -p --output-format json` lives in stdout, not stderr
        raise RuntimeError(f"{AGENT_CMD} -p failed (exit {r.returncode}): "
                           f"stderr={r.stderr[:400]!r} stdout={r.stdout[:600]!r}")
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:                       # some runners print plain text
        return r.stdout.strip(), 0.0
    return str(data.get("result", "")).strip(), float(data.get("total_cost_usd", 0) or 0)


def _split_verdict(text: str):
    """Pull the trailing ```json {...}``` verdict off the markdown."""
    m = re.search(r"```json\s*(\{.*\})\s*```", text, re.S)
    verdict = {}
    if m:
        try:
            verdict = json.loads(m.group(1))
        except Exception:
            verdict = {}
        text = text[: m.start()].rstrip()
    return text, verdict


def _parse_json_verdict(raw: str) -> dict:
    """Judge output -> dict; fenced ```json first, then bare json. {} on failure (caller exits nonzero
    — a missing/unparseable judge verdict is FATAL, never silently retried)."""
    m = re.search(r"```json\s*(\{.*\})\s*```", raw, re.S)
    for blob in ([m.group(1)] if m else []) + [raw.strip()]:
        try:
            v = json.loads(blob)
            if isinstance(v, dict):
                return v
        except Exception:
            pass
    return {}


_BLOCKING_KEYS = ("hallucinated_tools", "unresolvable_pivots",
                  "banned_literal_lines", "steps_missing_check")


def _is_blocking(verdict: dict) -> bool:
    return bool(verdict.get("blocking")) or any(verdict.get(k) for k in _BLOCKING_KEYS)


# matches the Real-case notes section header + its body (until the next #/## heading or EOF)
_NOTES_RE = re.compile(r"^##\s*Real-case notes[^\n]*\n(.*?)(?=^#{1,2} |\Z)", re.M | re.S | re.I)


def _merge_intel(md: str, intel: str) -> str:
    """Drop the grounded real-case notes into the marker the author left. IDEMPOTENT — re-run after
    EVERY verify/re-author pass (the intel-wipe fix: a revision can re-emit the marker or silently
    drop the section; re-merging restores the held intel either way)."""
    body = _strip_fences(intel) or "_(intel arm returned nothing — fill manually)_"
    if INTEL_MARKER in md:
        return md.replace(INTEL_MARKER, body)
    m = _NOTES_RE.search(md)
    if m and m.group(1).strip():
        return md                                       # notes intact — nothing to do
    if m:                                               # header survived but the body was wiped
        return md[: m.start(1)] + body + "\n\n" + md[m.start(1):]
    return f"{md}\n\n## Real-case notes (non-obvious things to look for)\n{body}\n"


def _intel_ok(md: str) -> bool:
    """True iff the marker is gone AND the Real-case notes section has a non-empty body."""
    m = _NOTES_RE.search(md)
    return INTEL_MARKER not in md and bool(m and m.group(1).strip())


def _archive_existing(out: pathlib.Path, attack_id: str) -> None:
    """SCORING LOCK #1 — every playbook version is preserved. Archive an existing <id>.md to
    versions/<id>/v<N>.md (N = count+1) and append a CHANGELOG line BEFORE the new write."""
    if not out.exists():
        return
    vdir = HERE / "versions" / attack_id
    vdir.mkdir(parents=True, exist_ok=True)
    n = len(list(vdir.glob("v*.md"))) + 1
    (vdir / f"v{n}.md").write_text(out.read_text(encoding="utf-8", errors="replace"),
                                   encoding="utf-8")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with (vdir / "CHANGELOG").open("a", encoding="utf-8") as fh:
        fh.write(f"{stamp} | archived v{n} before agent regeneration of {attack_id}\n")
    print(f"  archived previous version -> {vdir / f'v{n}.md'}")


def build(attack_id: str, desc: str, tool_row: str = "") -> None:
    if not CATEGORY_IDS:
        sys.exit("FATAL: no legal category-id list found (factory/categories.txt or $PLAYBOOK_ID_LIST)"
                 " — cannot enforce the pivot rule; refusing to author.")
    if attack_id not in CATEGORY_IDS:
        print(f"  warning: {attack_id!r} not in the legal category-id list", file=sys.stderr)

    author_system = _author_system(tool_row, _gold_exemplar(attack_id))
    spent = 0.0
    draft, c = _call(author_system, f"{GROUNDING}\n\nAuthor the playbook for attack type "
                                    f'"{attack_id}": {desc}')
    spent += c
    draft = _strip_fences(draft)

    # grounded INTEL arm fills the Real-case notes (web). `intel` is HELD for the whole build and
    # re-merged after every later pass. NON-FATAL: a flaky/unsupported web call must NEVER block the
    # whole playbook — log the real error to a sidecar and fall back to a ⚠️verify placeholder so the
    # rest of the (grounded, non-web) playbook still generates and passes the gate.
    try:
        intel, c = _call(INTEL_SYSTEM, f'Research real incidents of "{attack_id}" ({desc}).',
                         extra=INTEL_ARGS, model=INTEL_MODEL)
        spent += c
    except Exception as e:
        (HERE / f"{attack_id}.intel-error.txt").write_text(str(e), encoding="utf-8")
        print(f"  INTEL web call FAILED (non-fatal, placeholder used): {str(e)[:300]}", file=sys.stderr)
        intel = ("- ⚠️verify — web research was unavailable on this run; real-case notes pending. "
                 "Fill via the tune loop or a later regeneration once web intel works. "
                 "[source · pending · confidence: low]")
    md = _merge_intel(draft, intel)

    verdict: dict = {}
    for attempt in range(1, MAX_RETRIES + 2):
        out_md, verdict = _split_verdict(_call(VERIFY_SYSTEM, f"{GROUNDING}\n\nDRAFT:\n{md}")[0])
        md = _merge_intel(_strip_fences(out_md) or md, intel)   # verify edits can wipe the notes too
        if not _is_blocking(verdict) or attempt > MAX_RETRIES:
            break
        # loop-until-clean: feed the fix_list back into a re-author pass (AGENT-ONLY edits)
        fixes = json.dumps({k: verdict.get(k) for k in ("fix_list", *_BLOCKING_KEYS)
                            if verdict.get(k)})
        md, c = _call(author_system, f"{GROUNDING}\n\nRevise to FIX these verify issues "
                                     f"(especially un-grounded/off-box tools, illegal pivot ids, "
                                     f"literal paths or \"...\" in tool lines, missing check: "
                                     f"predicates): {fixes}\n\nDRAFT:\n{md}")
        spent += c
        md = _merge_intel(_strip_fences(md), intel)   # INTEL-WIPE FIX: re-merge after EVERY re-author

    final = _merge_intel(_clean(md), intel)
    # fail LOUDLY if the grounded intel was lost anywhere above — never write a wiped playbook
    if not _intel_ok(final):
        sys.exit(f"FATAL intel-wipe guard ({attack_id}): INTEL_MARKER still present or "
                 f"'Real-case notes' empty in the final markdown — refusing to write.")

    out = HERE / f"{attack_id}.md"
    _archive_existing(out, attack_id)                  # scoring lock #1: preserve every version
    out.write_text(final, encoding="utf-8")

    # final SCORE-ONLY judge (separate from the fix-applying editor; no edits, cheap model).
    raw, c = _call(JUDGE_SYSTEM, f"{GROUNDING}\n\nPLAYBOOK (final, already written):\n{final}",
                   model=JUDGE_MODEL)
    spent += c
    judge = _parse_json_verdict(raw)
    vpath = HERE / f"{attack_id}.verdict.json"
    if not judge or not isinstance(judge.get("rubric"), dict):
        print(f"FATAL: score-only judge ({JUDGE_MODEL}) returned a missing/unparseable verdict for "
              f"{attack_id}; raw head:\n{raw[:400]}", file=sys.stderr)
        sys.exit(3)                                    # never a silent retry
    vpath.write_text(json.dumps(judge, indent=2) + "\n", encoding="utf-8")

    r = judge.get("rubric") or {}
    print(f"DONE  -> {out}")
    print(f"  verdict -> {vpath}")
    print(f"  rubric  grounded:{r.get('grounded','?')} jargon:{r.get('jargon_free','?')} "
          f"decision:{r.get('decision_driven','?')} multi_os:{r.get('multi_os','?')} "
          f"provenance:{r.get('provenance_ready','?')}   blocking:{judge.get('blocking')}")
    for k in _BLOCKING_KEYS:
        if judge.get(k):
            print(f"  {k}: {judge[k]}")
    print(f"  verdict: {judge.get('one_line_verdict','')}")
    for f in (judge.get("fix_list") or []):
        print(f"  [fix] {f.get('section')}: {f.get('problem')}")
    if spent:
        print(f"  cost_usd (0 on subscription credit): ${spent:.4f}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit('usage: python build_playbook.py <attack-type-id> "<short description>" '
                 '["<category tool-map row>"]')
    build(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")

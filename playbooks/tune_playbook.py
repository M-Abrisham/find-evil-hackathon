#!/usr/bin/env python3
"""
Protocol SIFT — AGENT-ONLY playbook tuner (BUILD-TIME TOOLING ONLY — do NOT commit to the team repo).

Closes the validation loop's edit step WITHOUT a human in it (hackathon Rules L51 self-correction;
humans review/approve the SYSTEM outside this loop, never the edit itself):

    blind run (eval/run_blind.py) -> score (eval/score.py) -> THIS TUNER -> next blind run

Given --playbook --score <score.json> --case-id, it:
  1. Reads score.json's evidence.missed_evidence (the eval/score.py rubric buckets:
     key_artifacts|key_iocs|timeline_events|actor_accounts|exfil_or_encryption_facts).
  2. Mechanically pre-triages each missed bucket against the playbook's per-step `emits:` tags:
        NO-STEP-EMITS          no step emits the bucket  -> author gap, a new step is needed
        STEP-NOT-EXECUTED      steps emit it but branching/preconditions kept the agent away
        STEP-EXECUTED-MISSED   steps emit it and ran, but expect/check were too narrow
     (the agent decides between the last two; NO-STEP-EMITS is decided mechanically).
  3. Calls `claude -p` (SUBSCRIPTION ONLY — ANTHROPIC_API_KEY is unset for the child; model
     `fable` by default) to produce an APPEND-ONLY delta: new step block(s) / new falsify-style
     guard(s) as Failure-mode entries / one Tuning-log line. It NEVER rewrites existing text —
     to strengthen an existing step's falsify side it appends a new step or guard.
  4. Applies the delta: appends at the END of the targeted sections, appends the Tuning-log line,
     bumps `version:` in the frontmatter (the ONLY line allowed to change), and verifies the
     result is append-only with difflib (any deletion/rewrite aborts the apply).
  5. PRESERVES the iteration trace (hackathon scoring: every version + per-iteration trace):
        playbooks/versions/<category_id>/v<N>.md          the pre-tune playbook, verbatim
        playbooks/versions/<category_id>/v<N+1>.diff      unified diff of this iteration
        playbooks/versions/<category_id>/v<N+1>.trace.json prompt + raw agent reply + applied delta

Env knobs:  TUNE_AGENT (default: claude) · TUNE_MODEL (default: fable) · TUNE_AGENT_ARGS ·
            TUNE_TIMEOUT (default: 900 s)

STDLIB ONLY.  SUBSCRIPTION ONLY — never an API key.

Usage:
    python3 playbooks/tune_playbook.py --playbook playbooks/<cat>.md \\
            --score /cases/<id>/output/score.json --case-id <id> [--dry-run]
"""
from __future__ import annotations

import argparse
import datetime as _dt
import difflib
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent

AGENT = os.environ.get("TUNE_AGENT", "claude")
MODEL = os.environ.get("TUNE_MODEL", "fable")
AGENT_ARGS = shlex.split(os.environ.get("TUNE_AGENT_ARGS", ""))
TIMEOUT = int(os.environ.get("TUNE_TIMEOUT", "900"))

SCORE_BUCKETS = ["key_artifacts", "key_iocs", "timeline_events", "actor_accounts",
                 "exfil_or_encryption_facts"]

# Sections an append may target -> heading regex (matched against `##`-level headings).
SECTION_PATTERNS: dict[str, str] = {
    "steps": r"\bsteps\b",
    "linux branch": r"\blinux\b",
    "failure modes": r"\bfailure\s+modes?\b",
    "step 0": r"\bstep\s*0\b",
    "tuning log": r"\btuning\s+log\b",
}

BANNED_TOOL_LITERALS = [("/evidence", r"/evidence\b"), ("/mnt/c", r"/mnt/c\b"),
                        ('"..."', r"\.\.\.|…")]


# ---------------------------------------------------------------------------
# Light parsing (same conventions as validate_playbook.py; kept standalone).
# ---------------------------------------------------------------------------
def split_frontmatter_span(text: str) -> tuple[int, int] | None:
    """(start_line, end_line) of the --- delimiters, or None."""
    lines = text.splitlines()
    i = 0
    while i < len(lines) and not lines[i].strip():
        i += 1
    if i >= len(lines) or lines[i].strip() != "---":
        return None
    for j in range(i + 1, len(lines)):
        if lines[j].strip() == "---":
            return i, j
    return None


def fm_scalar(text: str, key: str) -> str:
    span = split_frontmatter_span(text)
    if span is None:
        return ""
    fm = "\n".join(text.splitlines()[span[0] + 1:span[1]])
    m = re.search(rf"^{re.escape(key)}:\s*(.+?)\s*$", fm, re.M)
    if not m:
        return ""
    v = re.sub(r"\s+#.*$", "", m.group(1)).strip()
    return v[1:-1] if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'" else v


def heading_spans(text: str) -> list[tuple[int, str, int]]:
    """[(heading_line_idx, heading_text, section_end_line_idx_exclusive)] for ##..#### headings."""
    lines = text.splitlines()
    heads = [(i, m.group(2)) for i, line in enumerate(lines)
             if (m := re.match(r"^(#{2,4})\s+(.*?)\s*$", line))]
    spans = []
    for k, (i, h) in enumerate(heads):
        end = heads[k + 1][0] if k + 1 < len(heads) else len(lines)
        spans.append((i, h, end))
    return spans


def steps_emitting(text: str) -> dict[str, list[str]]:
    """bucket -> ['n=3 (Steps …)', ...] scanned from every `- n:` block's `emits:` line."""
    out: dict[str, list[str]] = {b: [] for b in SCORE_BUCKETS}
    section = ""
    cur_n: str | None = None
    for line in text.splitlines():
        if (m := re.match(r"^(#{2,4})\s+(.*?)\s*$", line)):
            section = m.group(2)
            cur_n = None
            continue
        if (m := re.match(r"^\s*-\s+n:\s*(.+?)\s*$", line)):
            cur_n = re.sub(r"\s+#.*$", "", m.group(1)).strip()
            continue
        if cur_n and (m := re.match(r"^\s+emits:\s*\[(.*?)\]", line)):
            for b in (x.strip() for x in m.group(1).split(",") if x.strip()):
                if b in out:
                    out[b].append(f"n={cur_n} ({section})")
    return out


def find_section_span(text: str, key: str) -> tuple[int, str, int] | None:
    pat = SECTION_PATTERNS[key]
    for i, h, end in heading_spans(text):
        if re.search(pat, h, re.I):
            # "steps" must not swallow "Step 0" / "Tuning log" headings
            if key == "steps" and (re.search(r"\bstep\s*0\b", h, re.I)
                                   or re.search(r"\btuning\b", h, re.I)):
                continue
            return i, h, end
    return None


def normalize_section_name(name: str) -> str | None:
    n = (name or "").strip().lower()
    for key in SECTION_PATTERNS:
        if key in n or n in key:
            return key
    if "linux" in n:
        return "linux branch"
    if "failure" in n:
        return "failure modes"
    if "step" in n and "0" in n:
        return "step 0"
    if "step" in n:
        return "steps"
    return None


# ---------------------------------------------------------------------------
# Miss triage + prompt.
# ---------------------------------------------------------------------------
def triage(missed: dict[str, list[str]], emitters: dict[str, list[str]]) -> list[dict]:
    rows = []
    for bucket, items in missed.items():
        if not items:
            continue
        who = emitters.get(bucket, [])
        rows.append({
            "bucket": bucket,
            "missed_items": items,
            "steps_emitting_bucket": who,
            "mechanical_verdict": ("NO-STEP-EMITS (author gap — append a new step that emits "
                                   "this bucket)") if not who else
                                  ("STEP-LISTED — decide STEP-NOT-EXECUTED (precondition/branch "
                                   "kept the agent away) vs STEP-EXECUTED-MISSED (expect/check "
                                   "too narrow) and append the fix"),
        })
    return rows


SYSTEM_PROMPT = """You are the AUTONOMOUS playbook tuner for Protocol SIFT (agent-only edit loop — \
no human touches the edit). You receive one forensic-investigation playbook and the evidence \
buckets a blind validation run MISSED. Produce an APPEND-ONLY delta so the next run catches them.

HARD RULES:
- APPEND-ONLY. Never rewrite, renumber, or delete existing text. You may ONLY add:
  (a) new step blocks at the END of "Steps" (continue numbering after the last n) or at the END
      of the Linux branch (L<last+1>...),
  (b) new falsify-style guards as {mode, guard} entries at the END of "Failure modes",
  (c) exactly one new Tuning-log line (returned separately as tuning_log_line).
  To strengthen an existing step's falsify side, append a NEW step or failure-mode guard that
  re-checks it — do NOT edit the old step.
- New steps use the exact contract shape, fields in order:
  n, precondition (optional), tool, expect, check, falsify,
  on_result {expect_met, falsify_met, neither}, emits [...], serves [...],
  provenance {receipt_id, artifact, offset_or_row, literal_cited}.
- tool/check lines use #{variables} declared in the playbook frontmatter ONLY; literal example
  paths (/evidence, /mnt/c) and "..." are BANNED.
- emits values must be score buckets (key_artifacts|key_iocs|timeline_events|actor_accounts|
  exfil_or_encryption_facts); every new step must emit at least one MISSED bucket.
- serves values must come from the frontmatter sub_types list. Pivots target one of the 24
  category ids or SELF.
- Name only tools the playbook already names (they are run-verified on the SIFT box).

Return ONLY one JSON object, no markdown fence, shaped exactly:
{"triage": [{"bucket": "...", "verdict": "NO-STEP-EMITS|STEP-NOT-EXECUTED|STEP-EXECUTED-MISSED",
             "reason": "one line"}],
 "appends": [{"section": "Steps|Linux branch|Failure modes", "markdown": "block to append"}],
 "tuning_log_line": "YYYY-MM-DD | <case_id> | <bucket(s) missed> | <delta applied, one line>"}"""


def build_user_prompt(pb_text: str, case_id: str, rows: list[dict], score: dict) -> str:
    today = _dt.date.today().isoformat()
    headline = json.dumps(score.get("headline", {}), indent=2)
    triage_txt = "\n".join(
        f"- bucket {r['bucket']}: missed {len(r['missed_items'])} rubric item(s): "
        f"{json.dumps(r['missed_items'])}\n"
        f"  steps emitting this bucket: "
        f"{', '.join(r['steps_emitting_bucket']) or 'NONE'}\n"
        f"  mechanical pre-triage: {r['mechanical_verdict']}"
        for r in rows)
    return f"""case_id: {case_id}
date: {today}

SCORECARD HEADLINE (eval/score.py):
{headline}

MISS TRIAGE (mechanical pre-pass — finish it, then append the fix):
{triage_txt}

=== CURRENT PLAYBOOK (read-only context — your delta APPENDS to it) ===
{pb_text}
=== END PLAYBOOK ===

Produce the APPEND-ONLY delta JSON now."""


# ---------------------------------------------------------------------------
# Subscription-authed agent call (mirrors eval/run_blind.py / eval/score.py).
# ---------------------------------------------------------------------------
def call_agent(system: str, user: str) -> str:
    env = os.environ.copy()
    # SUBSCRIPTION ONLY: a set ANTHROPIC_API_KEY silently flips `claude` to metered API billing.
    if env.pop("ANTHROPIC_API_KEY", None) is not None:
        print("  (unset ANTHROPIC_API_KEY for tuner call -> subscription auth)", file=sys.stderr)
    cmd = [AGENT, "-p", user, "--model", MODEL, "--output-format", "json",
           "--append-system-prompt", system, *AGENT_ARGS]
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=TIMEOUT)
    if r.returncode != 0:
        raise RuntimeError(f"{AGENT} -p failed (exit {r.returncode}): {r.stderr[:600]}")
    try:
        return str(json.loads(r.stdout).get("result", "")).strip()
    except json.JSONDecodeError:                       # some runners print plain text
        return r.stdout.strip()


def extract_delta(text: str) -> dict:
    s = text.strip()
    m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", s, re.S)
    if m:
        s = m.group(1)
    if not s.startswith("{"):
        i, j = s.find("{"), s.rfind("}")
        if i != -1 and j > i:
            s = s[i:j + 1]
    return json.loads(s)


# ---------------------------------------------------------------------------
# Apply: append-only edits + version bump + append-only verification.
# ---------------------------------------------------------------------------
def screen_append(section_key: str, markdown: str) -> str | None:
    """Returns a rejection reason, or None if the append is acceptable."""
    if not markdown.strip():
        return "empty markdown"
    if re.match(r"^#{1,4}\s", markdown.lstrip()):
        return "append starts a new heading — appends go INSIDE an existing section"
    for line in markdown.splitlines():
        if re.match(r"^\s*tool:", line):
            for label, pat in BANNED_TOOL_LITERALS:
                if re.search(pat, line):
                    return f"tool line contains banned literal {label}"
    if section_key in ("steps", "linux branch", "step 0") and "- n:" not in markdown:
        return "step append contains no `- n:` block"
    if section_key == "failure modes" and "guard" not in markdown.lower():
        return "failure-mode append has no guard"
    return None


def append_into_section(text: str, section_key: str, markdown: str) -> str | None:
    span = find_section_span(text, section_key)
    if span is None:
        return None
    _, _, end = span
    lines = text.splitlines()
    insert_at = end
    while insert_at > 0 and not lines[insert_at - 1].strip():
        insert_at -= 1                                  # keep trailing blank lines after the append
    new_lines = lines[:insert_at] + markdown.rstrip("\n").splitlines() + lines[insert_at:]
    return "\n".join(new_lines) + ("\n" if text.endswith("\n") else "")


def bump_version(text: str) -> tuple[str, int, int]:
    span = split_frontmatter_span(text)
    if span is None:
        raise RuntimeError("playbook has no frontmatter — refusing to tune")
    lines = text.splitlines()
    for i in range(span[0] + 1, span[1]):
        m = re.match(r"^version:\s*(\d+)\s*$", lines[i])
        if m:
            old = int(m.group(1))
            lines[i] = f"version: {old + 1}"
            return "\n".join(lines) + ("\n" if text.endswith("\n") else ""), old, old + 1
    raise RuntimeError("no integer `version:` in frontmatter — playbook is not contract-shaped")


def assert_append_only(old: str, new: str) -> list[str]:
    """Only insertions are allowed, plus a 1-line replace of `version: N`."""
    old_l, new_l = old.splitlines(), new.splitlines()
    problems = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, old_l, new_l).get_opcodes():
        if tag in ("equal", "insert"):
            continue
        if tag == "replace" and all(re.match(r"^version:\s*\d+\s*$", x) for x in old_l[i1:i2]) \
                and all(re.match(r"^version:\s*\d+\s*$", x) for x in new_l[j1:j2]):
            continue
        problems.append(f"{tag}: existing lines {i1 + 1}-{i2} would change: "
                        f"{old_l[i1:i2][:2]!r}")
    return problems


# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Agent-only append-only playbook tuner "
                                             "(subscription claude -p; no human in the edit step).")
    ap.add_argument("--playbook", required=True)
    ap.add_argument("--score", required=True, help="score.json from eval/score.py")
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--dry-run", action="store_true",
                    help="build + print the miss-triage prompt, call nothing, change nothing")
    args = ap.parse_args()

    pb_path = pathlib.Path(args.playbook).resolve()
    pb_text = pb_path.read_text(encoding="utf-8")
    score = json.loads(pathlib.Path(args.score).read_text(encoding="utf-8"))

    missed_all = (score.get("evidence") or {}).get("missed_evidence") or {}
    missed = {b: v for b, v in missed_all.items() if v and b in SCORE_BUCKETS}
    if not missed:
        print("nothing to tune: score.json reports no missed evidence buckets")
        return 0

    rows = triage(missed, steps_emitting(pb_text))
    user_prompt = build_user_prompt(pb_text, args.case_id, rows, score)

    if args.dry_run:
        print("--- MISS-TRIAGE PROMPT (dry run; no agent call, no edit) ---")
        print(user_prompt)
        return 0

    category_id = fm_scalar(pb_text, "category_id") or fm_scalar(pb_text, "attack_type") \
        or pb_path.stem
    versions_dir = pb_path.parent / "versions" / category_id
    versions_dir.mkdir(parents=True, exist_ok=True)

    print(f"tuning {pb_path.name} for case {args.case_id}: "
          f"missed buckets = {', '.join(missed)}", file=sys.stderr)
    raw = call_agent(SYSTEM_PROMPT, user_prompt)
    try:
        delta = extract_delta(raw)
    except Exception as e:
        (versions_dir / f"failed-{args.case_id}.trace.json").write_text(json.dumps(
            {"case_id": args.case_id, "error": f"unparseable delta: {e}", "agent_raw": raw},
            indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"FAIL: agent returned unparseable delta ({e}); trace saved under {versions_dir}",
              file=sys.stderr)
        return 1

    # ---- screen + apply appends (bottom-up not needed: we re-locate sections every time) -----
    applied, rejected = [], []
    new_text = pb_text
    for ap_item in (delta.get("appends") or []):
        sec = normalize_section_name(str(ap_item.get("section", "")))
        md = str(ap_item.get("markdown", ""))
        if sec is None:
            rejected.append({"append": ap_item, "reason": "unknown target section"})
            continue
        reason = screen_append(sec, md)
        if reason:
            rejected.append({"append": ap_item, "reason": reason})
            continue
        candidate = append_into_section(new_text, sec, "\n" + md.strip("\n"))
        if candidate is None:
            rejected.append({"append": ap_item, "reason": f"section {sec!r} not found in playbook"})
            continue
        new_text = candidate
        applied.append({"section": sec, "markdown": md})

    if not applied:
        (versions_dir / f"failed-{args.case_id}.trace.json").write_text(json.dumps(
            {"case_id": args.case_id, "error": "no valid appends", "rejected": rejected,
             "agent_raw": raw}, indent=2, ensure_ascii=False), encoding="utf-8")
        print("FAIL: agent produced no applicable append-only delta; "
              f"trace saved under {versions_dir}", file=sys.stderr)
        return 1

    # ---- tuning-log line (always exactly one, appended) --------------------------------------
    log_line = str(delta.get("tuning_log_line") or "").replace("\n", " ").strip()
    if not log_line:
        log_line = (f"{_dt.date.today().isoformat()} | {args.case_id} | "
                    f"{';'.join(missed)} | appended {len(applied)} block(s): "
                    f"{', '.join(a['section'] for a in applied)}")
    with_log = append_into_section(new_text, "tuning log", f"- {log_line}")
    if with_log is not None:
        new_text = with_log
    else:
        print("WARN: no Tuning log section found — tuning line recorded only in the trace",
              file=sys.stderr)

    # ---- version bump + append-only verification ---------------------------------------------
    new_text, v_old, v_new = bump_version(new_text)
    problems = assert_append_only(pb_text, new_text)
    if problems:
        (versions_dir / f"failed-{args.case_id}.trace.json").write_text(json.dumps(
            {"case_id": args.case_id, "error": "append-only violation", "problems": problems,
             "agent_raw": raw}, indent=2, ensure_ascii=False), encoding="utf-8")
        print("FAIL: delta violated append-only — NOT applied:", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    # ---- preserve the iteration trace, then write -------------------------------------------
    (versions_dir / f"v{v_old}.md").write_text(pb_text, encoding="utf-8")
    diff = "".join(difflib.unified_diff(pb_text.splitlines(True), new_text.splitlines(True),
                                        fromfile=f"{category_id}/v{v_old}.md",
                                        tofile=f"{category_id}/v{v_new}.md"))
    (versions_dir / f"v{v_new}.diff").write_text(diff, encoding="utf-8")
    (versions_dir / f"v{v_new}.trace.json").write_text(json.dumps({
        "case_id": args.case_id, "date": _dt.date.today().isoformat(),
        "agent": AGENT, "model": MODEL,
        "missed_buckets": missed, "triage": rows,
        "agent_triage": delta.get("triage"),
        "applied": applied, "rejected": rejected, "tuning_log_line": log_line,
        "user_prompt": user_prompt, "agent_raw": raw,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    pb_path.write_text(new_text, encoding="utf-8")
    print(f"TUNED {pb_path.name}: v{v_old} -> v{v_new}; {len(applied)} append(s), "
          f"{len(rejected)} rejected; trace -> {versions_dir}/v{v_new}.trace.json")

    # ---- post-apply lint (report only — the factory gate enforces) ---------------------------
    linter = HERE / "validate_playbook.py"
    if linter.is_file():
        r = subprocess.run([sys.executable, str(linter), str(pb_path)],
                           capture_output=True, text=True)
        tag = "lint PASS" if r.returncode == 0 else "lint FAIL (factory gate will catch)"
        print(f"  {tag}:\n" + "\n".join(f"    {ln}" for ln in r.stdout.splitlines()[:15]))
    return 0


if __name__ == "__main__":
    sys.exit(main())

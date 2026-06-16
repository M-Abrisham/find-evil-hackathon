#!/usr/bin/env python3
"""
Protocol SIFT — PB1 tool-reconciliation gate (BUILD-TIME TOOLING ONLY — do NOT commit to the team repo).

GATE 0: nothing trusts a playbook until it names ONLY on-box tools. This parses the
OS-Coverage-Matrix FALSE-CLAIMS table (§B) for tools that are absent/broken on the SIFT box,
scans each playbook for any it names, and emits a per-playbook reconciliation report carrying
the verified substitute (§D). It exits non-zero if a playbook names an absent tool in an
EXECUTABLE position (a `tool:`/`check:`/`then:` line) for which no substitute is defined.

    source of truth = OS-Coverage-Matrix.md  (§B FALSE-CLAIMS + §D recipes)

Precision-first (a false "uses an absent tool" flag is itself a fabrication): tokens are matched
with strict word boundaries so `plaso prefetch` is never mistaken for `PECmd`, `python3-yara`/`yarac`
are never mistaken for the `yara` CLI, and ambiguous short tokens (`az`) are not matched at all.

STDLIB ONLY (no PyYAML — the matrix .md is parsed directly, not the generated os-coverage.yaml).

Usage:
    python3 playbooks/reconcile_playbook.py --all                       # every playbooks/*.md
    python3 playbooks/reconcile_playbook.py --playbook playbooks/ransomware-destructive.md
    [--matrix OS-Coverage-Matrix.md] [--out reconcile.json] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_MATRIX = HERE.parent / "OS-Coverage-Matrix.md"

# Verified substitutes (matrix §D + the planning doc's PB1 list; fact-checked 2026-06-12).
# Keyed by normalized token. A token absent from §B but present here is still honored.
SUBSTITUTIONS = {
    "pecmd":      "plaso `prefetch` (matrix §D recipe 7)",
    "srumecmd":   "plaso `srum` + `esedbexport` (matrix §D recipe 7)",
    "yara":       "python3-yara library (matrix §B)",
    "vss_carver": "`vshadowmount` / `vshadowinfo` (matrix §D recipe 9)",
    "mac_apt":    "plaso + `sqlite3`, routed around broken mac_apt (matrix §D recipe 2)",
}

# Token boundaries. A tool name is a real shell token unless it's part of a larger identifier.
#   LB excludes a preceding alnum/_/-/.  -> rejects `python3-yara` (- before) and `rules.yara` (. before),
#      but ALLOWS `/` so a path-qualified invocation `/usr/local/bin/yara` / `/opt/.../PECmd` matches.
#   LA excludes a following alnum/_/-     -> rejects `yarac`, but ALLOWS `/` and `.` so `PECmd/SrumECmd`
#      and `PECmd.exe` both match.
_LB = r"(?<![A-Za-z0-9_.-])"
_LA = r"(?![A-Za-z0-9_-])"

# Per-token matcher refinements for tokens whose naive boundary match is unsafe.
# value = a fully-formed regex (compiled case-insensitively), or None to DROP the token entirely
#         (too ambiguous to match without false positives).
REFINE = {
    "yara":     _LB + r"yara" + _LA,               # not python3-yara, not yarac, not rules.yara
    "mac_apt":  _LB + r"mac_apt(?:\.py)?" + _LA,
    "baseline": _LB + r"baseline\.py" + _LA,        # bare "baseline" is too common
    "az":       None,                               # 2-letter Azure-CLI token — unmatchable safely
    "pandas":   r"import\s+pandas\b|" + _LB + r"pandas" + _LA,
}

# Lines whose CONTENT is executed by the agent (a named tool here is a real, blocking problem).
_EXEC_FIELD_RE = re.compile(r"^\s*(?:-\s*)?(?:tool|check|precondition|then|on_result)\s*:", re.I)
_TABLE_ROW_RE = re.compile(r"^\s*\|(.+)\|\s*$")


# ---------------------------------------------------------------------------
# Parse the matrix §B FALSE-CLAIMS table.
# ---------------------------------------------------------------------------
def _section(text: str, header_re: str) -> str:
    """Return the body of the first `## ...` section whose heading matches header_re."""
    lines = text.splitlines()
    start = None
    for i, ln in enumerate(lines):
        if re.match(r"^##\s", ln) and re.search(header_re, ln, re.I):
            start = i + 1
            break
    if start is None:
        return ""
    end = len(lines)
    for j in range(start, len(lines)):
        if re.match(r"^##\s", lines[j]):
            end = j
            break
    return "\n".join(lines[start:end])


def _norm(tok: str) -> str:
    return re.sub(r"[^\w.+-]", "", tok.strip().lower())


def parse_false_claims(matrix_text: str) -> dict:
    """token -> {display, aliases, proof, parsed_substitute}. Parsed from §B FALSE-CLAIMS table."""
    body = _section(matrix_text, r"\bfalse[- ]claims\b")
    out: dict[str, dict] = {}
    for ln in body.splitlines():
        m = _TABLE_ROW_RE.match(ln)
        if not m:
            continue
        cells = [c.strip() for c in m.group(1).split("|")]
        if len(cells) < 3:
            continue
        name, proof = cells[0], cells[-1]
        if not name or name.lower() in ("tool", "------", ":------", "---") or set(name) <= set("-: "):
            continue
        display = re.sub(r"\*\*", "", name).strip()
        # aliases: split on "/", strip parenthetical qualifiers like "(Prefetch)"/"(Azure CLI)"
        aliases = []
        for part in display.split("/"):
            part = re.sub(r"\(.*?\)", "", part).strip()
            if part:
                aliases.append(part)
        # substitute hinted in the proof cell
        sub = None
        sm = (re.search(r"instead by ([^.;]+)", proof, re.I)
              or re.search(r"Use ([^.;]+?) instead", proof, re.I)
              or re.search(r"only ([^.;]+?) (?:library|GUI)", proof, re.I))
        if sm:
            sub = re.sub(r"\s+", " ", sm.group(1)).strip(" .`")
        for a in aliases:
            tok = _norm(a)
            if tok:
                out[tok] = {"display": display, "aliases": aliases, "proof": proof,
                            "parsed_substitute": sub}
    return out


def build_matchers(absent: dict) -> dict:
    """token -> (compiled_regex, display, substitute) ; drops tokens REFINE maps to None."""
    matchers = {}
    for tok, info in absent.items():
        if tok in REFINE:
            pat = REFINE[tok]
            if pat is None:
                continue
            rx = re.compile(pat, re.I)
        else:
            rx = re.compile(_LB + re.escape(tok) + _LA, re.I)
        sub = SUBSTITUTIONS.get(tok) or info.get("parsed_substitute")
        matchers[tok] = (rx, info["display"], sub)
    return matchers


# ---------------------------------------------------------------------------
# Scan one playbook.
# ---------------------------------------------------------------------------
def scan_playbook(pb_text: str, matchers: dict) -> list[dict]:
    hits: list[dict] = []
    exec_indent: int | None = None     # indent of the open executable field's block, or None
    for i, raw in enumerate(pb_text.splitlines(), start=1):
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip(" "))
        if _EXEC_FIELD_RE.match(raw):
            executable = True           # the `tool:`/`check:`/`then:` line itself (inline or block head)
            exec_indent = indent
        elif exec_indent is not None and stripped and indent > exec_indent:
            executable = True           # a continuation line inside that field's block (e.g. under `tool: |`)
        else:
            if stripped:                # a non-blank line at/under the field indent closes the block
                exec_indent = None
            executable = False
        for tok, (rx, display, sub) in matchers.items():
            if rx.search(raw):
                status = ("blocking" if executable and not sub
                          else "needs_substitution" if executable
                          else "prose")
                hits.append({
                    "tool": display,
                    "token": tok,
                    "line": i,
                    "line_text": stripped[:200],
                    "context": "executable" if executable else "prose",
                    "substitute": sub,
                    "status": status,                 # blocking | needs_substitution | prose
                    "blocking": status == "blocking",  # exec position + no known substitute
                })
    return hits


def reconcile_one(pb_path: pathlib.Path, matchers: dict) -> dict:
    pb_text = pb_path.read_text(encoding="utf-8")
    hits = scan_playbook(pb_text, matchers)
    blocking = [h for h in hits if h["status"] == "blocking"]
    needs_sub = [h for h in hits if h["status"] == "needs_substitution"]
    return {
        "playbook": str(pb_path),
        "absent_tools_named": sorted({h["tool"] for h in hits}),
        "hit_count": len(hits),
        "blocking_hits": len(blocking),
        "needs_substitution_hits": len(needs_sub),
        "substitutions_to_apply": sorted({f"{h['tool']} -> {h['substitute']}" for h in needs_sub}),
        "passes_gate": len(blocking) == 0,                              # runnable after substitution
        "fully_reconciled": len(blocking) == 0 and len(needs_sub) == 0,  # names ONLY on-box tools
        "hits": hits,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="PB1 GATE 0: reconcile playbook tools vs the "
                                             "OS-Coverage-Matrix FALSE-CLAIMS table.")
    ap.add_argument("--playbook", action="append", default=[], help="playbook .md (repeatable)")
    ap.add_argument("--all", action="store_true", help="reconcile every playbooks/*.md (skips _TEMPLATE)")
    ap.add_argument("--matrix", default=str(DEFAULT_MATRIX), help="OS-Coverage-Matrix.md")
    ap.add_argument("--out", default="reconcile.json")
    ap.add_argument("--dry-run", action="store_true", help="print the report; write nothing")
    args = ap.parse_args()

    matrix_path = pathlib.Path(args.matrix)
    if not matrix_path.is_file():
        print(f"FATAL: matrix not found: {args.matrix}", file=sys.stderr)
        return 1
    absent = parse_false_claims(matrix_path.read_text(encoding="utf-8"))
    if not absent:
        print(f"FATAL: no FALSE-CLAIMS (§B) table parsed from {args.matrix}", file=sys.stderr)
        return 1
    matchers = build_matchers(absent)

    targets: list[pathlib.Path] = [pathlib.Path(p) for p in args.playbook]
    if args.all:
        targets += sorted(p for p in HERE.glob("*.md") if p.name != "_TEMPLATE.md")
    targets = sorted({p.resolve() for p in targets})
    if not targets:
        print("FATAL: no playbooks given (use --playbook or --all).", file=sys.stderr)
        return 2

    reports = []
    for p in targets:
        if not p.is_file():
            print(f"WARN: skipping missing playbook: {p}", file=sys.stderr)
            continue
        reports.append(reconcile_one(p, matchers))

    summary = {
        "matrix": str(matrix_path),
        "absent_tools_known": sorted({m[1] for m in matchers.values()}),
        "playbooks": reports,
        "all_pass": all(r["passes_gate"] for r in reports),               # nothing unrecoverable
        "all_reconciled": all(r["fully_reconciled"] for r in reports),    # nothing left to substitute
    }
    payload = json.dumps(summary, indent=2, ensure_ascii=False)
    if args.dry_run:
        print(payload)
    else:
        pathlib.Path(args.out).write_text(payload + "\n", encoding="utf-8")

    for r in reports:
        tag = "PASS" if r["passes_gate"] else "FAIL"
        recon = "fully reconciled" if r["fully_reconciled"] else f"{r['needs_substitution_hits']} to substitute"
        named = ", ".join(r["absent_tools_named"]) or "none"
        print(f"[{tag}] {pathlib.Path(r['playbook']).name}: {r['blocking_hits']} blocking, "
              f"{recon}; absent tools named: {named}", file=sys.stderr)
    if not args.dry_run:
        print(f"wrote {args.out}")
    return 0 if summary["all_pass"] else 3


if __name__ == "__main__":
    sys.exit(main())

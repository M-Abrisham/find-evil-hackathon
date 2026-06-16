#!/usr/bin/env python3
"""
Protocol SIFT — playbook → Claude Code skill converter (BUILD-TIME TOOLING ONLY — do NOT commit
to the team repo; the GENERATED skills/ tree is what ships with Protocol SIFT).

Converts one attack-type playbook .md into a skill package with real progressive disclosure at
file granularity (the loader reads SKILL.md only; the references/ files are read on demand):

    skills/<category_id>/SKILL.md                       frontmatter: name + description (=trigger)
                                                        body: Quick path → Step 0 → Steps → close gate
    skills/<category_id>/references/real-case-notes.md  "Real-case notes" section
    skills/<category_id>/references/jargon.md           "Jargon decoder" section
    skills/<category_id>/references/cross-os.md         "Cross-OS notes" section

IDEMPOTENT: output is a pure function of the playbook text — re-running rewrites nothing that is
already up to date (byte-compare before write) and never duplicates content.

GRACEFUL DEGRADATION on pre-contract ("old shape") playbooks: missing category_id falls back to
attack_type; a missing Step 0 / close-gate section produces a WARN on stderr and is omitted (or,
for the close gate, falls back to the legacy "Done =" checklist); missing reference sections get
an explicit stub so the references/ paths always exist.

STDLIB ONLY.

Usage:
    python3 playbooks/skillify.py playbooks/<category>.md [...] [--skills-dir DIR]
    python3 playbooks/skillify.py --selftest      # runs on playbooks/ransomware-destructive.md
                                                  # (old shape) into a temp dir, twice, asserting
                                                  # warnings + idempotence; writes nothing in-repo
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_SKILLS_DIR = HERE.parent / "skills"


WARNINGS: list[str] = []        # collected so the selftest can assert graceful degradation


def warn(msg: str) -> None:
    WARNINGS.append(msg)
    print(f"WARN: {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Parsing (kept standalone on purpose — the template is still churning).
# ---------------------------------------------------------------------------
def split_frontmatter(text: str) -> tuple[str | None, str]:
    lines = text.splitlines()
    i = 0
    while i < len(lines) and not lines[i].strip():
        i += 1
    if i >= len(lines) or lines[i].strip() != "---":
        return None, text
    for j in range(i + 1, len(lines)):
        if lines[j].strip() == "---":
            return "\n".join(lines[i + 1:j]), "\n".join(lines[j + 1:])
    return None, text


def fm_scalar(fm_text: str, key: str) -> str:
    m = re.search(rf"^{re.escape(key)}:\s*(.+?)\s*$", fm_text, re.M)
    if not m:
        return ""
    v = re.sub(r"\s+#.*$", "", m.group(1)).strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    return v


def split_sections(body: str) -> list[tuple[str, str]]:
    """[(heading_text, content)] in document order; index 0 is the pre-heading preamble ('').
    Headings are `##`..`####` at column 0 (single `#` is skipped: bash comments in code samples
    look like `# ...`, and real playbooks may carry stray unpaired ``` fences, so no fence-tracking)."""
    sections: list[tuple[str, str]] = []
    cur_head, cur_lines = "", []
    for line in body.splitlines():
        m = re.match(r"^(#{2,4})\s+(.*?)\s*$", line)
        if m:
            sections.append((cur_head, "\n".join(cur_lines)))
            cur_head, cur_lines = m.group(2), []
        else:
            cur_lines.append(line)
    sections.append((cur_head, "\n".join(cur_lines)))
    return sections


def find_section(sections: list[tuple[str, str]], pattern: str) -> tuple[str, str] | None:
    for h, c in sections:
        if h and re.search(pattern, h, re.I):
            return h, c
    return None


def _block(title: str, found: tuple[str, str] | None) -> str:
    """One SKILL.md body section, original content verbatim."""
    if found is None:
        return ""
    return f"## {title}\n{found[1].strip()}\n"


# ---------------------------------------------------------------------------
# Conversion.
# ---------------------------------------------------------------------------
def convert(playbook_path: pathlib.Path, skills_dir: pathlib.Path) -> tuple[pathlib.Path, list[str]]:
    """Returns (skill_dir, list of 'wrote'/'unchanged' notes). Warnings go to stderr."""
    text = playbook_path.read_text(encoding="utf-8", errors="replace")
    fm_text, body = split_frontmatter(text)
    if fm_text is None:
        raise SystemExit(f"ERROR: {playbook_path} has no YAML frontmatter — cannot skillify")

    category_id = fm_scalar(fm_text, "category_id")
    if not category_id:
        category_id = fm_scalar(fm_text, "attack_type")
        if category_id:
            warn(f"{playbook_path.name}: no category_id in frontmatter — old shape; "
                 f"falling back to attack_type: {category_id}")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", category_id or ""):
        raise SystemExit(f"ERROR: {playbook_path} has no usable category_id/attack_type "
                         f"(got {category_id!r})")

    name = fm_scalar(fm_text, "name") or category_id
    description = fm_scalar(fm_text, "description")
    if not description:
        warn(f"{playbook_path.name}: no description (the skill trigger) — synthesizing a weak one")
        description = f"Load when investigating a suspected {name} incident."
    version = fm_scalar(fm_text, "version") or "0"
    if version == "0":
        warn(f"{playbook_path.name}: no version in frontmatter (pre-contract shape) — using v0")

    sections = split_sections(body)
    quick = find_section(sections, r"\bquick\s+path\b")
    step0 = find_section(sections, r"\bstep\s*0\b")
    steps = find_section(sections, r"\bsteps\b")
    close = find_section(sections, r"close[-\s]?gate")
    close_title = "Close gate (invariant — quick-path success does NOT waive it)"
    if close is None:
        legacy = find_section(sections, r"\bdone\b")
        if legacy is not None:
            warn(f"{playbook_path.name}: no CLOSE-GATE INVARIANT section — old shape; "
                 f"falling back to legacy section {legacy[0]!r}")
            close, close_title = legacy, "Close gate (legacy Done checklist)"

    for label, found in (("Quick path", quick), ("Step 0", step0),
                         ("Steps", steps), ("close gate", close)):
        if found is None:
            warn(f"{playbook_path.name}: missing section for SKILL.md body: {label} — omitted")

    skill_body = "\n".join(filter(None, [
        _block("Quick path", quick),
        _block("Step 0 — evidence inventory & access bootstrap", step0),
        _block("Steps", steps),
        _block(close_title, close),
    ]))

    skill_md = f"""---
name: {category_id}
description: {json.dumps(description)}
---

# {name}

> Generated by playbooks/skillify.py from `playbooks/{playbook_path.name}` (playbook v{version}).
> Do not hand-edit — edit the playbook and re-run skillify.
> Progressive disclosure: read a references/ file ONLY when its trigger applies —
> `references/real-case-notes.md` (non-obvious leads from real solved incidents),
> `references/jargon.md` (artifact/term decoder), `references/cross-os.md` (non-Windows variants).

{skill_body}"""

    def ref_doc(title: str, pattern: str, fname: str) -> str:
        found = find_section(sections, pattern)
        if found is None:
            warn(f"{playbook_path.name}: no {title!r} section — writing stub references/{fname}")
            content = f"_Source playbook (v{version}) has no {title} section yet._"
        else:
            content = found[1].strip()
        return (f"# {title} — {name}\n\n"
                f"> Extracted by skillify.py from `playbooks/{playbook_path.name}` "
                f"(playbook v{version}).\n\n{content}\n")

    refs = {
        "real-case-notes.md": ref_doc("Real-case notes", r"real[-\s]?case", "real-case-notes.md"),
        "jargon.md": ref_doc("Jargon decoder", r"\bjargon\b", "jargon.md"),
        "cross-os.md": ref_doc("Cross-OS notes", r"cross[-\s]?os", "cross-os.md"),
    }

    skill_dir = skills_dir / category_id
    (skill_dir / "references").mkdir(parents=True, exist_ok=True)
    notes: list[str] = []

    def write(path: pathlib.Path, content: str) -> None:
        if path.exists() and path.read_text(encoding="utf-8") == content:
            notes.append(f"unchanged {path}")
        else:
            path.write_text(content, encoding="utf-8")
            notes.append(f"wrote     {path}")

    write(skill_dir / "SKILL.md", skill_md)
    for fname, content in refs.items():
        write(skill_dir / "references" / fname, content)
    return skill_dir, notes


# ---------------------------------------------------------------------------
# Selftest — old-shape playbook, temp output, run twice (idempotence), no repo writes.
# ---------------------------------------------------------------------------
def selftest() -> int:
    target = HERE / "ransomware-destructive.md"
    if not target.is_file():
        print(f"SELFTEST FAIL: sample playbook missing: {target}")
        return 1
    ok = True
    with tempfile.TemporaryDirectory(prefix="skillify-selftest-") as tmp:
        out = pathlib.Path(tmp) / "skills"
        skill_dir, notes1 = convert(target, out)
        expected = [skill_dir / "SKILL.md",
                    skill_dir / "references" / "real-case-notes.md",
                    skill_dir / "references" / "jargon.md",
                    skill_dir / "references" / "cross-os.md"]
        for p in expected:
            if not p.is_file():
                print(f"SELFTEST FAIL: missing output {p}")
                ok = False
        skill = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
        for needle in ("name: ransomware-destructive", "description:", "## Quick path", "## Steps"):
            if needle not in skill:
                print(f"SELFTEST FAIL: SKILL.md missing {needle!r}")
                ok = False
        if "Done" not in skill:  # old shape: close gate degrades to the legacy Done checklist
            print("SELFTEST FAIL: legacy Done checklist not carried into the close-gate block")
            ok = False
        # old shape must WARN about the missing Step 0 (graceful degradation, not silence)
        if not any("Step 0" in w for w in WARNINGS):
            print("SELFTEST FAIL: no warning emitted for the missing Step 0 section")
            ok = False
        # the old playbook HAS a Jargon decoder section, so jargon.md must not be a stub
        jargon = (skill_dir / "references" / "jargon.md").read_text(encoding="utf-8")
        if "has no" in jargon:
            print("SELFTEST FAIL: jargon.md is a stub but the source has a Jargon decoder section")
            ok = False
        # idempotence: second run must change nothing
        _, notes2 = convert(target, out)
        changed = [n for n in notes2 if n.startswith("wrote")]
        if changed:
            print("SELFTEST FAIL: second run was not idempotent:")
            for n in changed:
                print(f"  {n}")
            ok = False
    print("SELFTEST " + ("PASS" if ok else "FAIL")
          + " (old-shape playbook degraded gracefully; warnings above are expected)")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="Convert playbook .md into skills/<category_id>/ "
                                             "(SKILL.md + references/). Idempotent.")
    ap.add_argument("playbooks", nargs="*", help="playbook .md file(s) to convert")
    ap.add_argument("--skills-dir", default=str(DEFAULT_SKILLS_DIR),
                    help=f"output skills root (default: {DEFAULT_SKILLS_DIR})")
    ap.add_argument("--selftest", action="store_true", help="run the embedded selftest")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.playbooks:
        ap.error("give at least one playbook .md (or --selftest)")
    rc = 0
    for pb in args.playbooks:
        p = pathlib.Path(pb)
        if not p.is_file():
            print(f"ERROR: not a file: {pb}", file=sys.stderr)
            rc = 1
            continue
        skill_dir, notes = convert(p, pathlib.Path(args.skills_dir))
        print(f"{pb} -> {skill_dir}")
        for n in notes:
            print(f"  {n}")
    return rc


if __name__ == "__main__":
    sys.exit(main())

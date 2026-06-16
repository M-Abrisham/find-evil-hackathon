#!/usr/bin/env python3
"""check_contract_sync.py — Deliverable-Contract render/deploy DRIFT check (R8).

WHY THIS EXISTS
---------------
The Deliverable Contract (verdict vocabulary, IOC columns/vocab, MITRE rule) has a
single source of truth: ``protocol-sift-build/contract.yaml``. That contract is
*rendered* into one or more ``CLAUDE.md`` files (a repo ``global/CLAUDE.md`` and/or a
deployed ``~/.claude/CLAUDE.md``) between the markers::

    <!-- DELIVERABLE-CONTRACT:START ... -->
    ...
    <!-- DELIVERABLE-CONTRACT:END -->

If a ``CLAUDE.md`` is a STALE MIRROR — edited by hand, deployed from an old YAML, or
simply never re-rendered — the running agent grades against a contract that no longer
matches the source of truth. That stale-mirror skew is exactly the false alarm this
whole audit tripped on. This script catches it deterministically.

WHAT IT CHECKS
--------------
It derives a CANONICAL contract (the load-bearing, machine-graded fields only) from
``contract.yaml``:

  * verdict: vocabulary tokens, confidence levels, dimensions, rules, equivalence classes
  * ioc:     confidence vocab, columns, allowed types (+ value forms), rules
  * mitre:   framework, columns, code format, rules

…then extracts the contract block from each target ``CLAUDE.md`` (the text between the
START/END markers), parses the SAME canonical fields back out of the rendered prose,
and compares. Comparison is on the canonical fields — robust to cosmetic markdown /
whitespace differences, but it FAILS on any real divergence (a changed/added/removed
verdict token, IOC column, MITRE rule, etc.).

EXIT CODE
---------
  0  every target's contract block matches contract.yaml
  1  drift detected (a unified diff of the canonical contract is printed per target)
  2  usage / IO error (missing file, no contract block in a target, bad YAML)

DEPENDENCIES
------------
Stdlib only. The project renderer (protocol-sift-build/render_contract.py) is NOT
imported because it does a top-level ``import yaml`` (PyYAML, third-party) and is not
importable in a stdlib-only environment; a tiny in-module parser reads the subset of
YAML that contract.yaml uses.

PUBLIC API
----------
    load_contract_yaml(path) -> dict
    canonical_from_yaml(contract: dict) -> str
    extract_contract_block(claude_md_text: str) -> str | None
    canonical_from_claude_md(block_text: str) -> str
    diff_target(yaml_path, claude_md_path) -> tuple[bool, str]   # (in_sync, unified_diff)
    check(yaml_path, targets: list[str]) -> int                  # process exit code

CLI
---
    python3 scoring/check_contract_sync.py \
        --contract /path/to/contract.yaml \
        TARGET_CLAUDE_MD [TARGET_CLAUDE_MD ...]

If --contract is omitted it defaults to ../../protocol-sift-build/contract.yaml
relative to this file (the canonical build-dir location).

MAKEFILE WIRING (snippet — do NOT applied here; add to the repo Makefile yourself)
----------------------------------------------------------------------------------
Append to find-evil-hackathon/Makefile (tabs, not spaces, for the recipe line):

    CONTRACT_YAML ?= ../protocol-sift-build/contract.yaml
    GLOBAL_CLAUDE_MD ?= global/CLAUDE.md
    DEPLOYED_CLAUDE_MD ?= $(HOME)/.claude/CLAUDE.md

    .PHONY: check-contract
    check-contract:
    	python3 scoring/check_contract_sync.py --contract $(CONTRACT_YAML) \
    	    $(GLOBAL_CLAUDE_MD) $(wildcard $(DEPLOYED_CLAUDE_MD))

(``$(wildcard ...)`` lets the deployed copy be optional: it is only checked if present.)
"""
from __future__ import annotations

import argparse
import difflib
import os
import sys

# --------------------------------------------------------------------------------------
# Marker constants — MUST match protocol-sift-build/render_contract.py.
# --------------------------------------------------------------------------------------
START_PREFIX = "<!-- DELIVERABLE-CONTRACT:START"
END_MARKER = "<!-- DELIVERABLE-CONTRACT:END -->"

_DEFAULT_CONTRACT = os.path.normpath(
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "..", "protocol-sift-build", "contract.yaml",
    )
)


# ======================================================================================
# Tiny stdlib YAML reader (only the subset contract.yaml uses)
# ======================================================================================
# Supported: nested mappings by 2-space indent; scalar values; "- item" sequences of
# scalars; inline flow lists "[a, b, c]"; inline flow mappings "{k: v, k2: v2}";
# quoted scalars; "# ..." comments. This is intentionally narrow and validated against
# the real contract.yaml — it is NOT a general YAML implementation.

def _strip_comment(s: str) -> str:
    """Remove a trailing ``# comment`` not inside quotes or brackets."""
    out = []
    in_s = in_d = False
    depth = 0
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif not in_s and not in_d:
            if ch in "[{":
                depth += 1
            elif ch in "]}":
                depth = max(0, depth - 1)
            elif ch == "#" and depth == 0:
                # comment only if preceded by start-of-line or whitespace
                if i == 0 or s[i - 1] in " \t":
                    break
        out.append(ch)
        i += 1
    return "".join(out)


def _unquote(s: str):
    s = s.strip()
    if len(s) >= 2 and ((s[0] == s[-1] == '"') or (s[0] == s[-1] == "'")):
        return s[1:-1]
    return s


def _scalar(s: str):
    s = s.strip()
    if s == "":
        return None
    if (len(s) >= 2) and ((s[0] == s[-1] == '"') or (s[0] == s[-1] == "'")):
        return _unquote(s)
    low = s.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "~", "none"):
        return None
    try:
        if s.lstrip("-").isdigit():
            return int(s)
    except ValueError:
        pass
    return s


def _parse_flow(s: str):
    """Parse an inline flow collection: [..] list or {..} map (one level deep)."""
    s = s.strip()
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [_scalar(p) for p in _split_flow(inner)]
    if s.startswith("{") and s.endswith("}"):
        inner = s[1:-1].strip()
        out = {}
        if not inner:
            return out
        for p in _split_flow(inner):
            if ":" in p:
                k, _, val = p.partition(":")
                out[_unquote(k.strip())] = _scalar(val)
        return out
    return _scalar(s)


def _split_flow(inner: str):
    """Split a flow body on top-level commas (respecting quotes/brackets)."""
    parts, buf, depth, in_s, in_d = [], [], 0, False, False
    for ch in inner:
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        if not in_s and not in_d:
            if ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
            elif ch == "," and depth == 0:
                parts.append("".join(buf).strip())
                buf = []
                continue
        buf.append(ch)
    if "".join(buf).strip():
        parts.append("".join(buf).strip())
    return parts


_BLOCK_SCALAR_INDICATORS = ("|-", "|+", ">-", ">+", "|", ">")


def _is_block_scalar(s: str) -> bool:
    """True if ``s`` is a YAML block-scalar header (``>``, ``|``, ``>-``, ``|-`` …)."""
    return s.strip() in _BLOCK_SCALAR_INDICATORS


def _collect_block_scalar(lines, idx: int, parent_indent: int):
    """Fold the continuation lines of a block scalar into one string.

    ``idx`` points at the FIRST continuation line (already deeper-indented than the
    key/dash that introduced the ``>-``/``|`` header). All deeper-indented lines are
    consumed and joined with single spaces — the canonical form normalizes whitespace
    anyway (it runs ``" ".join(str(r).split())``), so folded vs. literal is immaterial
    here. Returns (text, next_idx).
    """
    parts = []
    while idx < len(lines) and lines[idx].indent > parent_indent:
        parts.append(lines[idx].text.strip())
        idx += 1
    return " ".join(parts), idx


class _Line:
    __slots__ = ("indent", "text")

    def __init__(self, indent: int, text: str):
        self.indent = indent
        self.text = text


def _lines(text: str):
    out = []
    for raw in text.splitlines():
        stripped = _strip_comment(raw).rstrip()
        if stripped.strip() == "":
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        out.append(_Line(indent, stripped.strip()))
    return out


def _parse_block(lines, idx: int, indent: int):
    """Parse a mapping or sequence at >= ``indent``. Returns (value, next_idx)."""
    if idx >= len(lines):
        return None, idx
    first = lines[idx]
    is_seq = first.text.startswith("- ") or first.text == "-"
    if is_seq:
        return _parse_seq(lines, idx, first.indent)
    return _parse_map(lines, idx, first.indent)


def _parse_map(lines, idx: int, indent: int):
    out = {}
    while idx < len(lines):
        ln = lines[idx]
        if ln.indent < indent:
            break
        if ln.indent > indent:
            # shouldn't happen for well-formed input; skip defensively
            idx += 1
            continue
        if ln.text.startswith("- "):
            break
        key, _, rest = ln.text.partition(":")
        key = key.strip()
        rest = rest.strip()
        if rest and _is_block_scalar(rest):
            # "key: >-" : fold the deeper-indented continuation lines into the value
            text, idx = _collect_block_scalar(lines, idx + 1, ln.indent)
            out[key] = _scalar(text)
        elif rest:
            out[key] = _parse_flow(rest) if rest[0] in "[{" else _scalar(rest)
            idx += 1
        else:
            # nested block follows at deeper indent
            child_idx = idx + 1
            if child_idx < len(lines) and lines[child_idx].indent > indent:
                val, idx = _parse_block(lines, child_idx, lines[child_idx].indent)
                out[key] = val
            else:
                out[key] = None
                idx += 1
    return out, idx


def _parse_seq(lines, idx: int, indent: int):
    out = []
    while idx < len(lines):
        ln = lines[idx]
        if ln.indent < indent or not (ln.text.startswith("- ") or ln.text == "-"):
            break
        if ln.indent > indent:
            idx += 1
            continue
        item = ln.text[1:].strip()  # drop leading '-'
        if _is_block_scalar(item):
            # "- >-" / "- |" : the folded/literal content is the deeper-indented lines
            text, idx = _collect_block_scalar(lines, idx + 1, ln.indent)
            out.append(_scalar(text))
        elif item == "":
            child_idx = idx + 1
            if child_idx < len(lines) and lines[child_idx].indent > indent:
                val, idx = _parse_block(lines, child_idx, lines[child_idx].indent)
                out.append(val)
            else:
                out.append(None)
                idx += 1
        elif item[0] in "[{":
            out.append(_parse_flow(item))
            idx += 1
        elif ":" in item and not (item.startswith('"') or item.startswith("'")):
            # inline mapping starting on the dash line, e.g. "- token: MALICE"
            # Build a synthetic mapping: this line's pair + any deeper-indented siblings.
            k, _, v = item.partition(":")
            entry = {}
            entry[k.strip()] = _parse_flow(v.strip()) if v.strip() and v.strip()[0] in "[{" else _scalar(v.strip())
            # the implied map's key indent is the column where the key text begins
            key_col = ln.indent + 2
            idx += 1
            while idx < len(lines) and lines[idx].indent >= key_col and not (
                lines[idx].text.startswith("- ") or lines[idx].text == "-"
            ) and lines[idx].indent == key_col:
                kk, _, vv = lines[idx].text.partition(":")
                vv = vv.strip()
                entry[kk.strip()] = (
                    _parse_flow(vv) if vv and vv[0] in "[{" else _scalar(vv)
                )
                idx += 1
            out.append(entry)
        else:
            out.append(_scalar(item))
            idx += 1
    return out, idx


def parse_yaml(text: str) -> dict:
    """Parse the narrow YAML subset used by contract.yaml into a dict."""
    lines = _lines(text)
    if not lines:
        return {}
    val, _ = _parse_block(lines, 0, lines[0].indent)
    if not isinstance(val, dict):
        raise ValueError("contract.yaml did not parse to a mapping at the top level")
    return val


def load_contract_yaml(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return parse_yaml(f.read())


# ======================================================================================
# Canonical contract representation (the comparable, machine-graded fields)
# ======================================================================================
# A stable, line-oriented text form so divergence shows up as a clean unified diff.

def _as_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def _canon_lines_from_fields(verdict: dict, ioc: dict, mitre: dict) -> list[str]:
    L: list[str] = []

    # --- VERDICT ------------------------------------------------------------------
    L.append("[VERDICT]")
    toks = [str(t.get("token", "")).strip() for t in _as_list(verdict.get("vocabulary"))]
    L.append("tokens: " + " | ".join(toks))
    L.append("confidence_levels: " + " | ".join(str(x) for x in _as_list(verdict.get("confidence_levels"))))
    L.append("dimensions: " + " | ".join(str(x) for x in _as_list(verdict.get("dimensions"))))
    for r in _as_list(verdict.get("rules")):
        L.append("rule: " + " ".join(str(r).split()))
    # NOTE: verdict.equivalence_classes are deliberately EXCLUDED from this canonical
    # form. The renderer (protocol-sift-build/render_contract.py) does not emit them
    # into the CLAUDE.md contract block — they are a scorer-internal table mirrored in
    # scoring/scorer.py:VERDICT_CLASSES, not part of the deployed agent contract. A
    # render/deploy DRIFT check must compare only what is actually rendered, or a
    # faithfully-rendered CLAUDE.md would report a false drift.

    # --- IOC ----------------------------------------------------------------------
    L.append("[IOC]")
    L.append("columns: " + " | ".join(str(x) for x in _as_list(ioc.get("columns"))))
    L.append("confidence_vocab: " + " | ".join(str(x) for x in _as_list(ioc.get("confidence_vocab"))))
    for t in _as_list(ioc.get("types")):
        if isinstance(t, dict):
            ty = str(t.get("type", "")).strip()
            vf = " ".join(str(t.get("value_form", "")).split())
            L.append(f"type {ty}: {vf}")
        else:
            L.append(f"type {t}:")
    for r in _as_list(ioc.get("rules")):
        L.append("rule: " + " ".join(str(r).split()))

    # --- MITRE --------------------------------------------------------------------
    L.append("[MITRE]")
    L.append("framework: " + " ".join(str(mitre.get("framework", "")).split()))
    L.append("columns: " + " | ".join(str(x) for x in _as_list(mitre.get("columns"))))
    L.append("code_format: " + " ".join(str(mitre.get("code_format", "")).split()))
    for r in _as_list(mitre.get("rules")):
        L.append("rule: " + " ".join(str(r).split()))

    return L


def canonical_from_yaml(contract: dict) -> str:
    """Canonical comparable text derived directly from the parsed contract.yaml dict."""
    verdict = contract.get("verdict") or {}
    ioc = contract.get("ioc") or {}
    mitre = contract.get("mitre") or {}
    return "\n".join(_canon_lines_from_fields(verdict, ioc, mitre)) + "\n"


# ======================================================================================
# Extract + parse the contract block out of a rendered CLAUDE.md
# ======================================================================================

def extract_contract_block(claude_md_text: str):
    """Return the text BETWEEN the START and END markers, or None if absent.

    The START marker line is variable (it carries a parenthetical), so we match its
    fixed prefix and take everything from the end of that marker line up to END.
    """
    start = claude_md_text.find(START_PREFIX)
    if start == -1:
        return None
    # advance to the end of the START marker (the closing '-->')
    close = claude_md_text.find("-->", start)
    if close == -1:
        return None
    body_start = close + len("-->")
    end = claude_md_text.find(END_MARKER, body_start)
    if end == -1:
        return None
    return claude_md_text[body_start:end].strip("\n")


def _bullet_value(line: str) -> str:
    """For a line like ``- T1234 — meaning`` or ``- rule text`` return the text after '- '."""
    s = line.strip()
    if s.startswith("- "):
        s = s[2:]
    elif s.startswith("-"):
        s = s[1:]
    return s.strip()


def _split_em(s: str):
    """Split a bullet on the em-dash separator used by the renderer (' — ')."""
    for sep in (" — ", " - "):
        if sep in s:
            head, _, tail = s.partition(sep)
            return head.strip(), tail.strip()
    return s.strip(), ""


def canonical_from_claude_md(block_text: str) -> str:
    """Parse the SAME canonical fields back out of a rendered contract block.

    This mirrors protocol-sift-build/render_contract.py's output structure. It reads:
      verdict tokens (the ``- TOKEN — meaning`` bullets under the Verdict heading),
      confidence levels + dimensions (from the intro sentence),
      verdict rules (bullets after the fenced Format example),
      IOC columns + confidence vocab (from the intro sentence + the table header),
      IOC types (``- `type` — value_form`` bullets),
      IOC rules, MITRE framework / columns / code format / rules.
    """
    lines = block_text.splitlines()

    # Locate the three numbered section headings.
    def find_heading(substr: str) -> int:
        for i, ln in enumerate(lines):
            if ln.lstrip().startswith("###") and substr.lower() in ln.lower():
                return i
        return -1

    i_verdict = find_heading("Verdict")
    i_ioc = find_heading("Indicators of Compromise")
    i_mitre = find_heading("MITRE")

    verdict = {"vocabulary": [], "confidence_levels": [], "dimensions": [],
               "rules": [], "equivalence_classes": {}}
    ioc = {"columns": [], "confidence_vocab": [], "types": [], "rules": []}
    mitre = {"framework": "", "columns": [], "code_format": "", "rules": []}

    def section(lo: int, hi: int):
        if lo == -1:
            return []
        return lines[lo + 1: (hi if hi != -1 else len(lines))]

    # ---- VERDICT section ----
    vsec = section(i_verdict, i_ioc)
    in_fence = False
    seen_fence = False
    for ln in vsec:
        s = ln.strip()
        if s.startswith("```"):
            in_fence = not in_fence
            seen_fence = True
            continue
        if in_fence:
            continue
        # token bullets: "- MALICE — meaning" where head is ALLCAPS-ish token
        if s.startswith("- "):
            head, tail = _split_em(_bullet_value(s))
            tok = head.replace("`", "").strip()
            is_token = (
                tail
                and tok
                and tok.replace("_", "").replace("-", "").isalnum()
                and tok.upper() == tok
                and " " not in tok
            )
            if is_token and not seen_fence:
                verdict["vocabulary"].append({"token": tok})
            else:
                # a rule bullet (renderer puts rules after the fenced example)
                verdict["rules"].append(_bullet_value(s))
        else:
            low = s.lower()
            if "levels:" in low:
                # "...Levels: HIGH, MODERATE, LOW."
                tail = s[low.index("levels:") + len("levels:"):]
                verdict["confidence_levels"] = [
                    p.strip().rstrip(".").strip()
                    for p in tail.replace(".", "").split(",") if p.strip()
                ]
            if "confidence per dimension" in low and "(" in s:
                dims = s[s.index("(") + 1: s.index(")")] if ")" in s else ""
                verdict["dimensions"] = [d.strip() for d in dims.split(",") if d.strip()]

    # ---- IOC section ----
    isec = section(i_ioc, i_mitre)
    in_table = False
    for ln in isec:
        s = ln.strip()
        low = s.lower()
        if s.startswith("|"):
            # header row carries the columns; skip the separator + placeholder rows
            cells = [c.strip() for c in s.strip("|").split("|")]
            if not in_table and any(c and "---" not in c for c in cells) and "<" not in s:
                ioc["columns"] = [c for c in cells if c]
                in_table = True
            continue
        if "confidence is one of" in low:
            tail = s[low.index("confidence is one of") + len("confidence is one of"):]
            ioc["confidence_vocab"] = [
                p.strip().rstrip(".").strip()
                for p in tail.replace(".", "").split(",") if p.strip()
            ]
        if s.startswith("- "):
            body = _bullet_value(s)
            head, tail = _split_em(body)
            ht = head.replace("`", "").strip()
            # a type bullet looks like "`email` — lowercase"; rules are full sentences
            if tail and " " not in ht and ht.islower() or (tail and "_" in ht and " " not in ht):
                ioc["types"].append({"type": ht, "value_form": tail})
            else:
                ioc["rules"].append(body)

    # ---- MITRE section ----
    msec = section(i_mitre, -1)
    for ln in msec:
        s = ln.strip()
        low = s.lower()
        if s.startswith("|"):
            cells = [c.strip() for c in s.strip("|").split("|")]
            if not mitre["columns"] and any(c and "---" not in c for c in cells) and "<" not in s:
                mitre["columns"] = [c for c in cells if c]
            continue
        if "framework:" in low:
            seg = s[low.index("framework:") + len("framework:"):]
            # framework runs up to the next sentence boundary ". "
            fw = seg.split(". Code")[0].split(".  Code")[0]
            fw = fw.split("Code format")[0]
            mitre["framework"] = fw.strip().rstrip(".").strip()
        if "code format:" in low:
            seg = s[low.index("code format:") + len("code format:"):]
            mitre["code_format"] = seg.strip().rstrip(".").strip()
        if s.startswith("- "):
            mitre["rules"].append(_bullet_value(s))

    return "\n".join(_canon_lines_from_fields(verdict, ioc, mitre)) + "\n"


# ======================================================================================
# Comparison + CLI
# ======================================================================================

def diff_target(yaml_path: str, claude_md_path: str):
    """Return (in_sync: bool, unified_diff: str) for one target CLAUDE.md.

    Raises FileNotFoundError / ValueError on IO or structural problems so the CLI can
    map them to exit code 2.
    """
    contract = load_contract_yaml(yaml_path)
    expected = canonical_from_yaml(contract)

    with open(claude_md_path, "r", encoding="utf-8") as f:
        md = f.read()
    block = extract_contract_block(md)
    if block is None:
        raise ValueError(
            f"no DELIVERABLE-CONTRACT block found in {claude_md_path} "
            f"(expected markers {START_PREFIX!r} ... {END_MARKER!r})"
        )
    actual = canonical_from_claude_md(block)

    if expected == actual:
        return True, ""
    diff = "".join(
        difflib.unified_diff(
            expected.splitlines(keepends=True),
            actual.splitlines(keepends=True),
            fromfile=f"contract.yaml (canonical) :: {yaml_path}",
            tofile=f"deployed contract block :: {claude_md_path}",
            lineterm="\n",
        )
    )
    return False, diff


def check(yaml_path: str, targets) -> int:
    """Check every target; return a process exit code (0 ok, 1 drift, 2 error)."""
    if not targets:
        print("check_contract_sync: no target CLAUDE.md paths given", file=sys.stderr)
        return 2
    if not os.path.isfile(yaml_path):
        print(f"check_contract_sync: contract not found: {yaml_path}", file=sys.stderr)
        return 2

    any_drift = False
    for tgt in targets:
        try:
            in_sync, diff = diff_target(yaml_path, tgt)
        except (FileNotFoundError, ValueError) as e:
            print(f"check_contract_sync: ERROR for {tgt}: {e}", file=sys.stderr)
            return 2
        if in_sync:
            print(f"[OK]    {tgt} — contract block in sync with {yaml_path}")
        else:
            any_drift = True
            print(f"[DRIFT] {tgt} — contract block diverges from {yaml_path}:")
            print(diff)
    return 1 if any_drift else 0


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="check_contract_sync.py",
        description="Fail (exit 1) if any deployed CLAUDE.md's Deliverable-Contract "
                    "block has drifted from contract.yaml.",
    )
    p.add_argument(
        "--contract",
        default=_DEFAULT_CONTRACT,
        help=f"path to contract.yaml (default: {_DEFAULT_CONTRACT})",
    )
    p.add_argument(
        "targets",
        nargs="+",
        metavar="CLAUDE_MD",
        help="one or more target CLAUDE.md files to verify",
    )
    return p


def main(argv=None) -> int:
    args = _build_argparser().parse_args(argv)
    return check(args.contract, args.targets)


if __name__ == "__main__":
    sys.exit(main())

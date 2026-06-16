#!/usr/bin/env python3
"""
Protocol SIFT — R4 EMISSION-BLOCKING report validator (BUILD-TIME TOOLING ONLY — do NOT commit
to the team repo, and DO NOT wire it into ~/.claude until you have read the snippet below).

WHAT THIS IS
------------
A PreToolUse / Stop hook that validates a Protocol SIFT deliverable report against the DEPLOYED
deliverable contract (protocol-sift-build/contract.yaml) and EXITS NON-ZERO (exit 2) to BLOCK the
write whenever the report violates the contract. It is the report-side analogue of the existing
``validate_cmd.sh`` Bash gate in this directory: same hook contract (stdin JSON, exit 2 = block,
reason on stderr), same "stdlib + python3 only" rule, same DERIVED-FROM-SINGLE-SOURCE discipline.

CHECKS PERFORMED (all must pass or the write is blocked)
--------------------------------------------------------
  1. VERDICT line       — exactly one line matching ``VERDICT: <TOKEN> ...`` whose TOKEN belongs to
                          the contract's verdict vocabulary (via the same semantic equivalence
                          classes the scorer uses, so MALICIOUS == MALICE etc.). The contract
                          requires per-dimension confidence (act / attribution) — we warn-then-block
                          if the qualifier is missing, matching contract rule
                          "Always attach per-dimension confidence".
  2. IOC table rows     — every data row of the IOC table is well-formed ``Type | Value | Confidence``
                          with exactly the contract columns, a non-empty Value, a Type in the
                          contract taxonomy, and a Confidence token in the contract's
                          ``ioc.confidence_vocab`` ([CONFIRMED, INFERRED, UNCERTAIN]).
  3. Required sections  — the report is non-trivial: required H2 section headers are present and not
                          empty/placeholder (e.g. no "TODO", "TBD", "<...>", or a header with no body).

The VERDICT regex and the equivalence-class matching MIRROR
``protocol-sift-build/scoring/scorer.py`` (``_VERDICT_LINE_RE`` / ``VERDICT_CLASSES``) so a report
that this hook PASSES is one the deterministic scorer can READ — the whole point is to fail closed
at emission time instead of silently scoring a 0 later.

THE CONTRACT IS THE SINGLE SOURCE OF TRUTH
------------------------------------------
Legal vocab (verdict tokens + equivalence classes, IOC confidence vocab, IOC types, IOC columns) is
read at runtime from the contract YAML. Default path: ``/Users/mehrnooshabrishamkar/protocol-sift-build/contract.yaml``
Override order:  --contract <path>  >  $SIFT_CONTRACT  >  default.
YAML is parsed by a TINY embedded stdlib parser (``_parse_contract_yaml``) — NO PyYAML — covering only
the small, fixed subset of YAML this contract uses (mappings, list-of-scalars, ``- {k: v, ...}`` inline
maps, ``[a, b]`` flow lists, ``#`` comments). If the contract cannot be read/parsed, we fall back to an
EMBEDDED MIRROR of the vocab (kept in sync with contract.yaml v1) so the hook still fails closed
rather than failing open.

HOOK INPUT (how the report text is obtained), in priority order
---------------------------------------------------------------
  * ``--report-file <path>``         : read the report markdown directly from a file (handy for tests / CI)
  * ``--stdin-json`` or piped JSON   : read a Claude Code hook event from stdin and pull the report text
                                       out of it. Recognized shapes (PreToolUse on Write/Edit, or Stop):
                                         Write  -> tool_input.content
                                         Edit   -> tool_input.new_string  (validates the NEW text)
                                         Stop / file-on-disk -> tool_input.file_path (read the file)
                                       Only fires for Write/Edit whose file_path matches ./reports/*.md
                                       (override the glob with --reports-glob / $SIFT_REPORTS_GLOB);
                                       any other tool/path is a no-op pass (exit 0).
  * ``--text -`` / positional ``-``  : read raw report markdown from stdin (no JSON envelope)

EXIT CODES (Claude Code hook contract)
--------------------------------------
  0  = allow the write (report valid, OR event is not an in-scope report write)
  2  = BLOCK the write; human-readable reasons are printed to stderr for the model to fix
  1  = the hook itself errored (e.g. bad args). Claude Code treats non-2 non-zero as a
       non-blocking error, so a hook bug never silently eats a write.

settings.json WIRING SNIPPET — *** EMITTED ONLY, NOT APPLIED ***
----------------------------------------------------------------
Add to the SUT-side managed settings.json (the same file that already wires validate_cmd.sh).
This validator is INERT until you add this block yourself:

    "hooks": {
      "PreToolUse": [
        {
          "matcher": "Write|Edit",
          "hooks": [
            {
              "type": "command",
              "command": "$CLAUDE_PROJECT_DIR/sift-runner/validate_report.py --stdin-json"
            }
          ]
        }
      ],
      "Stop": [
        {
          "hooks": [
            {
              "type": "command",
              "command": "$CLAUDE_PROJECT_DIR/sift-runner/validate_report.py --stdin-json"
            }
          ]
        }
      ]
    }

  * The PreToolUse matcher is "Write|Edit"; the script itself filters to ./reports/*.md and
    no-ops on everything else, so a broad matcher is safe.
  * Set the contract path on the box via the env var if it differs from the default:
        "env": { "SIFT_CONTRACT": "/abs/path/to/contract.yaml" }
  * Merge the "hooks" block with the existing one in settings.json (which already has a
    PreToolUse "Bash" -> validate_cmd.sh entry); JSON has no include, so append the
    Write|Edit object to the existing PreToolUse array rather than replacing it.

PUBLIC API
----------
    load_contract(path=None)            -> ContractVocab          (vocab from YAML or mirror)
    validate_report(text, vocab)        -> list[str]              (violation messages; [] == valid)
    extract_report_from_event(obj, ...) -> (text|None, reason)    (pull report md out of a hook event)
    main(argv=None)                     -> int                    (CLI / hook entrypoint; exit code)
"""
from __future__ import annotations

import dataclasses
import json
import os
import re
import sys
from typing import Optional

# Default contract path (overridable by --contract, then $SIFT_CONTRACT, then this).
DEFAULT_CONTRACT_PATH = "contract/contract.yaml"  # relative fallback; real path comes from --contract or $SIFT_CONTRACT on the box
DEFAULT_REPORTS_GLOB = "reports/*.md"

# ---------------------------------------------------------------------------------------------------
# EMBEDDED MIRROR of contract.yaml v1 vocab — fail-closed fallback if the YAML can't be read/parsed.
# Keep in sync with protocol-sift-build/contract.yaml (verdict.* and ioc.*).
# ---------------------------------------------------------------------------------------------------
_MIRROR_VERDICT_TOKENS = ["MALICE", "NON_MALICE", "INCONCLUSIVE"]
_MIRROR_VERDICT_CLASSES = {
    "malicious": ["MALICE", "MALICIOUS"],
    "non_malicious": ["NON_MALICE", "NONMALICE", "BENIGN"],
    "inconclusive": ["INCONCLUSIVE", "INDETERMINATE", "UNKNOWN"],
}
_MIRROR_CONFIDENCE_LEVELS = ["HIGH", "MODERATE", "LOW"]
_MIRROR_IOC_CONFIDENCE_VOCAB = ["CONFIRMED", "INFERRED", "UNCERTAIN"]
_MIRROR_IOC_COLUMNS = ["Type", "Value", "Confidence"]
_MIRROR_IOC_TYPES = [
    "email", "file_hash", "ip_address", "mac_address",
    "windows_sid", "file_path", "hostname", "username",
]


# ===================================================================================================
# Tiny stdlib YAML parser — covers ONLY the subset contract.yaml uses (no PyYAML).
# ===================================================================================================
def _strip_comment(line: str) -> str:
    """Remove a trailing ``#`` comment, but not inside a quoted scalar."""
    out = []
    in_s = in_d = False
    for ch in line:
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == "#" and not in_s and not in_d:
            break
        out.append(ch)
    return "".join(out)


def _unquote(s: str):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    return s


def _parse_scalar(s: str):
    s = _unquote(s)
    if s == "":
        return None
    low = s.lower()
    if low in ("true", "false"):
        return low == "true"
    if re.fullmatch(r"-?\d+", s):
        try:
            return int(s)
        except ValueError:
            return s
    return s


def _parse_flow_list(s: str):
    """``[a, b, c]`` -> list of scalars."""
    inner = s.strip()[1:-1].strip()
    if not inner:
        return []
    return [_parse_scalar(p) for p in _split_top_level(inner, ",")]


def _parse_flow_map(s: str):
    """``{k: v, k2: v2}`` -> dict of scalars."""
    inner = s.strip()[1:-1].strip()
    out = {}
    if not inner:
        return out
    for part in _split_top_level(inner, ","):
        if ":" not in part:
            continue
        k, _, v = part.partition(":")
        out[_unquote(k.strip())] = _parse_scalar(v.strip())
    return out


def _split_top_level(s: str, sep: str):
    """Split ``s`` on ``sep`` ignoring separators inside [], {}, '', "" ."""
    parts, buf = [], []
    depth = 0
    in_s = in_d = False
    for ch in s:
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        if not in_s and not in_d:
            if ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
            elif ch == sep and depth == 0:
                parts.append("".join(buf))
                buf = []
                continue
        buf.append(ch)
    parts.append("".join(buf))
    return parts


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


class _Lines:
    """A rewindable line cursor over (indent, content) pairs (blank/comment lines dropped)."""

    def __init__(self, raw: str):
        self.items = []
        for ln in raw.splitlines():
            body = _strip_comment(ln).rstrip()
            if body.strip() == "":
                continue
            self.items.append((_indent(body), body.strip()))
        self.i = 0

    def peek(self):
        return self.items[self.i] if self.i < len(self.items) else None

    def next(self):
        it = self.items[self.i]
        self.i += 1
        return it


def _parse_block(lines: _Lines, min_indent: int):
    """Parse a YAML block at >= ``min_indent``. Returns dict | list | None."""
    first = lines.peek()
    if first is None or first[0] < min_indent:
        return None
    indent = first[0]

    if first[1].startswith("- "):  # a sequence
        seq = []
        while True:
            cur = lines.peek()
            if cur is None or cur[0] < indent or not cur[1].startswith("- "):
                break
            lines.next()
            item = cur[1][2:].strip()
            if item.startswith("{") and item.endswith("}"):
                seq.append(_parse_flow_map(item))
            elif item.startswith("[") and item.endswith("]"):
                seq.append(_parse_flow_list(item))
            elif ":" in item and not item.startswith("'") and not item.startswith('"'):
                # inline first key of a mapping item, e.g. "- token: MALICE"
                m = {}
                k, _, v = item.partition(":")
                v = v.strip()
                if v:
                    m[k.strip()] = _parse_scalar(v)
                sub = _parse_block(lines, indent + 1)
                if isinstance(sub, dict):
                    m.update(sub)
                seq.append(m)
            else:
                seq.append(_parse_scalar(item))
        return seq

    # a mapping
    mapping = {}
    while True:
        cur = lines.peek()
        if cur is None or cur[0] < indent or cur[1].startswith("- "):
            break
        if cur[0] > indent:  # deeper than expected for this map level -> let caller handle
            break
        lines.next()
        key_part = cur[1]
        if ":" not in key_part:
            continue
        k, _, v = key_part.partition(":")
        k = k.strip()
        v = v.strip()
        if v == "":  # nested block follows
            child = _parse_block(lines, indent + 1)
            mapping[k] = child
        elif v.startswith("[") and v.endswith("]"):
            mapping[k] = _parse_flow_list(v)
        elif v.startswith("{") and v.endswith("}"):
            mapping[k] = _parse_flow_map(v)
        else:
            mapping[k] = _parse_scalar(v)
    return mapping


def _parse_contract_yaml(raw: str) -> dict:
    """Parse the small YAML subset used by contract.yaml into nested dict/list scalars."""
    lines = _Lines(raw)
    result = _parse_block(lines, 0)
    return result if isinstance(result, dict) else {}


# ===================================================================================================
# Contract vocab model
# ===================================================================================================
@dataclasses.dataclass
class ContractVocab:
    verdict_tokens: list           # canonical tokens, e.g. [MALICE, NON_MALICE, INCONCLUSIVE]
    verdict_classes: dict          # class -> [synonym tokens]
    confidence_levels: list        # verdict per-dimension confidence, e.g. [HIGH, MODERATE, LOW]
    ioc_confidence_vocab: list     # [CONFIRMED, INFERRED, UNCERTAIN]
    ioc_columns: list              # [Type, Value, Confidence]
    ioc_types: list                # taxonomy of IOC types
    source: str                    # "contract:<path>" or "embedded-mirror"

    def all_verdict_synonyms_norm(self) -> set:
        out = set()
        for toks in self.verdict_classes.values():
            for t in toks:
                out.add(_norm_token(t))
        for t in self.verdict_tokens:
            out.add(_norm_token(t))
        return out

    def verdict_class_of(self, token: str):
        n = _norm_token(token)
        for cls, toks in self.verdict_classes.items():
            if n in {_norm_token(t) for t in toks}:
                return cls
        # token might be a canonical vocab token not enumerated in a class
        if n in {_norm_token(t) for t in self.verdict_tokens}:
            return n  # treat as its own class
        return None


def _norm_token(t) -> str:
    return str(t).strip().upper().replace("-", "_")


def _mirror_vocab() -> ContractVocab:
    return ContractVocab(
        verdict_tokens=list(_MIRROR_VERDICT_TOKENS),
        verdict_classes={k: list(v) for k, v in _MIRROR_VERDICT_CLASSES.items()},
        confidence_levels=list(_MIRROR_CONFIDENCE_LEVELS),
        ioc_confidence_vocab=list(_MIRROR_IOC_CONFIDENCE_VOCAB),
        ioc_columns=list(_MIRROR_IOC_COLUMNS),
        ioc_types=list(_MIRROR_IOC_TYPES),
        source="embedded-mirror",
    )


def load_contract(path: Optional[str] = None) -> ContractVocab:
    """Load the deliverable-contract vocab.

    Resolution: explicit ``path`` arg > ``$SIFT_CONTRACT`` > ``DEFAULT_CONTRACT_PATH``.
    On any read/parse failure, fall back to the embedded mirror (fail closed, not open)."""
    resolved = path or os.environ.get("SIFT_CONTRACT") or DEFAULT_CONTRACT_PATH
    try:
        with open(resolved, "r", encoding="utf-8") as fh:
            raw = fh.read()
        doc = _parse_contract_yaml(raw)
    except (OSError, ValueError, Exception):  # noqa: BLE001 — any failure -> mirror
        return _mirror_vocab()

    try:
        verdict = doc.get("verdict") or {}
        ioc = doc.get("ioc") or {}

        vocab_entries = verdict.get("vocabulary") or []
        verdict_tokens = []
        for e in vocab_entries:
            if isinstance(e, dict) and e.get("token"):
                verdict_tokens.append(str(e["token"]))
            elif isinstance(e, str):
                verdict_tokens.append(e)

        eq = verdict.get("equivalence_classes") or {}
        verdict_classes = {}
        for cls, toks in eq.items():
            if isinstance(toks, list):
                verdict_classes[cls] = [str(t) for t in toks]

        confidence_levels = [str(x) for x in (verdict.get("confidence_levels") or [])]

        ioc_conf = [str(x) for x in (ioc.get("confidence_vocab") or [])]
        ioc_cols = [str(x) for x in (ioc.get("columns") or [])]
        ioc_type_entries = ioc.get("types") or []
        ioc_types = []
        for e in ioc_type_entries:
            if isinstance(e, dict) and e.get("type"):
                ioc_types.append(str(e["type"]))
            elif isinstance(e, str):
                ioc_types.append(e)

        # If the YAML parsed but a required vocab is empty, the parse is suspect -> mirror.
        if not verdict_tokens or not ioc_conf or not ioc_cols:
            return _mirror_vocab()

        if not verdict_classes:
            verdict_classes = {t.lower(): [t] for t in verdict_tokens}
        if not confidence_levels:
            confidence_levels = list(_MIRROR_CONFIDENCE_LEVELS)
        if not ioc_types:
            ioc_types = list(_MIRROR_IOC_TYPES)

        return ContractVocab(
            verdict_tokens=verdict_tokens,
            verdict_classes=verdict_classes,
            confidence_levels=confidence_levels,
            ioc_confidence_vocab=ioc_conf,
            ioc_columns=ioc_cols,
            ioc_types=ioc_types,
            source=f"contract:{resolved}",
        )
    except Exception:  # noqa: BLE001
        return _mirror_vocab()


# ===================================================================================================
# Report validation
# ===================================================================================================
# Mirror scorer.py:_VERDICT_LINE_RE so a report we PASS is one the scorer can READ.
_VERDICT_LINE_RE = re.compile(r"VERDICT:\s*\*{0,2}\s*([A-Za-z][A-Za-z_-]*)", re.IGNORECASE)
# The full verdict line, to inspect per-dimension confidence qualifiers.
_VERDICT_FULL_RE = re.compile(r"^.*VERDICT:.*$", re.IGNORECASE | re.MULTILINE)

# Required H2 sections (## ...). Header text matched case-insensitively as a substring of the line.
REQUIRED_SECTIONS = ["IOC", "VERDICT"]
# Placeholder/empty markers that should never survive into an emitted report.
_PLACEHOLDER_RE = re.compile(r"(?:\bTODO\b|\bTBD\b|\bFIXME\b|<[^>\n]*\.\.\.[^>\n]*>|\.\.\.placeholder)", re.IGNORECASE)


def _split_table_row(line: str) -> Optional[list]:
    """Split a markdown table row ``| a | b | c |`` into cells, or None if not a table row."""
    s = line.strip()
    if "|" not in s:
        return None
    # strip a single leading/trailing pipe, then split
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [c.strip() for c in s.split("|")]


def _is_separator_row(cells: list) -> bool:
    """A markdown header separator row like ``| --- | :--: | --- |``."""
    return all(re.fullmatch(r":?-{1,}:?", c) is not None and c != "" for c in cells) if cells else False


def _find_ioc_table(text: str, vocab: ContractVocab):
    """Locate the IOC table.

    Returns (header_cells, data_rows, header_lineno) or None. The IOC table is the markdown table
    whose header row contains all contract columns (Type/Value/Confidence), case-insensitively."""
    lines = text.splitlines()
    want = {c.lower() for c in vocab.ioc_columns}
    for idx, line in enumerate(lines):
        cells = _split_table_row(line)
        if not cells:
            continue
        if {c.lower() for c in cells} >= want and len(cells) >= len(vocab.ioc_columns):
            # collect following data rows (skip the separator row)
            data = []
            j = idx + 1
            while j < len(lines):
                rc = _split_table_row(lines[j])
                if rc is None:
                    break
                if _is_separator_row(rc):
                    j += 1
                    continue
                data.append((j + 1, rc))  # 1-based line number for messages
                j += 1
            return cells, data, idx + 1
    return None


def _check_verdict(text: str, vocab: ContractVocab) -> list:
    problems = []
    tokens = _VERDICT_LINE_RE.findall(text)
    if not tokens:
        problems.append(
            "VERDICT: no `VERDICT:` line found. The report MUST end with a line like "
            "`VERDICT: <TOKEN> — act: <CONF>, attribution: <CONF>` where <TOKEN> is one of "
            f"{vocab.verdict_tokens}."
        )
        return problems

    # The contract says the verdict is the LAST section; the scorer reads the LAST recognized token.
    known = [t for t in tokens if vocab.verdict_class_of(t) is not None]
    chosen = known[-1] if known else tokens[-1]
    if vocab.verdict_class_of(chosen) is None:
        problems.append(
            f"VERDICT: token '{chosen}' is not in the contract verdict vocabulary. "
            f"Legal tokens (incl. synonyms): {sorted(vocab.all_verdict_synonyms_norm())}."
        )
        return problems

    # Per-dimension confidence qualifier check (contract rule: never an unqualified verdict).
    # A properly-qualified VERDICT line must EXIST (carry BOTH act + attribution on one line);
    # a later prose mention of the verdict (e.g. "see the VERDICT: MALICE line above") must NOT
    # invalidate an already-qualified authoritative line.
    full_lines = _VERDICT_FULL_RE.findall(text)
    conf_alt = "|".join(re.escape(c) for c in vocab.confidence_levels)
    act_re = re.compile(r"\bact\b\s*[:=]\s*(?:%s)" % conf_alt, re.IGNORECASE)
    attr_re = re.compile(r"\battribution\b\s*[:=]\s*(?:%s)" % conf_alt, re.IGNORECASE)
    qualified = any(act_re.search(ln) and attr_re.search(ln) for ln in full_lines)
    if not qualified:
        any_act = any(act_re.search(ln) for ln in full_lines)
        any_attr = any(attr_re.search(ln) for ln in full_lines)
        missing = [d for d, present in (("act", any_act), ("attribution", any_attr)) if not present]
        if not missing:  # both qualifiers appear, but never together on ONE verdict line
            missing = ["act", "attribution"]
        problems.append(
            "VERDICT: missing per-dimension confidence qualifier(s): "
            f"{missing}. Contract requires e.g. `VERDICT: {chosen} — act: HIGH, attribution: MODERATE` "
            f"with confidence from {vocab.confidence_levels}."
        )
    return problems


def _check_ioc_table(text: str, vocab: ContractVocab) -> list:
    problems = []
    found = _find_ioc_table(text, vocab)
    if found is None:
        problems.append(
            "IOC: could not find a well-formed IOC table with the contract columns "
            f"{vocab.ioc_columns}. Provide one markdown table whose header is "
            "`| Type | Value | Confidence |`."
        )
        return problems

    header, data, hdr_ln = found
    ncols = len(vocab.ioc_columns)
    # Map contract column name -> index in the actual header (case-insensitive).
    lower_hdr = [c.lower() for c in header]
    col_idx = {}
    for col in vocab.ioc_columns:
        try:
            col_idx[col] = lower_hdr.index(col.lower())
        except ValueError:
            problems.append(f"IOC: header is missing required column '{col}' (got {header}).")
    if problems:
        return problems

    conf_norm = {c.upper() for c in vocab.ioc_confidence_vocab}
    type_norm = {t.lower() for t in vocab.ioc_types}

    if not data:
        problems.append(
            f"IOC: table at line {hdr_ln} has a header but ZERO data rows. If there are genuinely "
            "no indicators, that is itself suspicious for a SIFT report — emit at least the rows you "
            "have, or an explicit no-IOC note outside the table."
        )
        return problems

    for ln, cells in data:
        if len(cells) != ncols:
            problems.append(
                f"IOC row at line {ln} is malformed: expected {ncols} cells "
                f"({vocab.ioc_columns}), got {len(cells)} -> {cells}."
            )
            continue
        typ = cells[col_idx["Type"]]
        val = cells[col_idx["Value"]]
        conf = cells[col_idx["Confidence"]]
        if val.strip() == "":
            problems.append(f"IOC row at line {ln}: empty Value cell -> {cells}.")
        if typ.strip() == "":
            problems.append(f"IOC row at line {ln}: empty Type cell -> {cells}.")
        elif typ.strip().lower() not in type_norm:
            problems.append(
                f"IOC row at line {ln}: Type '{typ}' is not in the contract taxonomy "
                f"{sorted(type_norm)}."
            )
        if conf.strip().upper() not in conf_norm:
            problems.append(
                f"IOC row at line {ln}: Confidence '{conf}' is not in the contract confidence "
                f"vocab {sorted(conf_norm)}."
            )
    return problems


def _check_required_sections(text: str, vocab: ContractVocab) -> list:
    problems = []
    if not text.strip():
        return ["REPORT: empty report content."]

    lines = text.splitlines()
    # Collect ## headers with their (start, end) body spans.
    headers = []
    for i, ln in enumerate(lines):
        if re.match(r"^\s*#{1,6}\s+\S", ln):
            headers.append((i, ln.strip()))
    # Map each header to its body (lines until the next header).
    for hi, (i, htext) in enumerate(headers):
        end = headers[hi + 1][0] if hi + 1 < len(headers) else len(lines)
        body = "\n".join(lines[i + 1:end]).strip()
        if _PLACEHOLDER_RE.search(htext) or _PLACEHOLDER_RE.search(body):
            problems.append(
                f"SECTION: '{htext}' contains an unresolved placeholder (TODO/TBD/<...>). "
                "Required sections must be filled before emission."
            )

    joined = "\n".join(h[1] for h in headers).upper()
    body_all = text.upper()
    for req in REQUIRED_SECTIONS:
        # VERDICT/IOC may appear as a header OR be checked structurally elsewhere; here we just
        # ensure the keyword is present somewhere meaningful so a stub report can't slip through.
        if req.upper() not in joined and req.upper() not in body_all:
            problems.append(
                f"SECTION: required section/keyword '{req}' not found in the report."
            )
    return problems


def validate_report(text: str, vocab: ContractVocab) -> list:
    """Return a list of violation messages (empty list == report is valid)."""
    problems = []
    problems += _check_required_sections(text, vocab)
    problems += _check_verdict(text, vocab)
    problems += _check_ioc_table(text, vocab)
    return problems


# ===================================================================================================
# Hook-event extraction
# ===================================================================================================
def _matches_reports_glob(file_path: str, glob_pat: str) -> bool:
    """True if ``file_path`` matches the reports glob (matched on the path tail, fnmatch-style)."""
    import fnmatch

    if not file_path:
        return False
    fp = file_path.replace("\\", "/")
    # match against the full path AND the trailing 'reports/...md' tail so absolute paths match.
    if fnmatch.fnmatch(fp, "*" + glob_pat) or fnmatch.fnmatch(fp, glob_pat) or fnmatch.fnmatch(fp, "*/" + glob_pat):
        return True
    return False


def extract_report_from_event(obj: dict, reports_glob: str = DEFAULT_REPORTS_GLOB):
    """Pull the report markdown out of a Claude Code hook event dict.

    Returns ``(text_or_None, reason)``. ``text is None`` means "not an in-scope report write,
    pass (exit 0)"; ``reason`` explains why.

    Recognized event shapes:
      Write -> tool_input.content                 (validate the content being written)
      Edit  -> tool_input.new_string              (validate the post-edit text)
      else  -> tool_input.file_path on disk       (Stop, or write w/o inline content -> read file)
    Only fires when tool_input.file_path matches ``reports_glob``.
    """
    if not isinstance(obj, dict):
        return None, "stdin was not a JSON object"

    tool = obj.get("tool_name") or obj.get("tool") or ""
    ti = obj.get("tool_input") or {}
    file_path = ti.get("file_path") or ti.get("path") or ""

    # Stop events may carry no tool_input; nothing to validate from the envelope.
    if tool in ("Write", "Edit") and file_path:
        if not _matches_reports_glob(file_path, reports_glob):
            return None, f"file_path '{file_path}' is not an in-scope report ({reports_glob})"
        if tool == "Write":
            content = ti.get("content")
            if content is not None:
                return content, "Write.content"
        if tool == "Edit":
            new = ti.get("new_string")
            if new is not None:
                return new, "Edit.new_string"
        # fall through to reading from disk
        try:
            with open(file_path, "r", encoding="utf-8") as fh:
                return fh.read(), f"read from disk {file_path}"
        except OSError as e:
            return None, f"could not read {file_path}: {e}"

    return None, f"tool '{tool}' / path '{file_path}' not an in-scope report write"


# ===================================================================================================
# CLI / hook entrypoint
# ===================================================================================================
def _parse_args(argv):
    opts = {
        "contract": None,
        "report_file": None,
        "stdin_json": False,
        "text_stdin": False,
        "reports_glob": os.environ.get("SIFT_REPORTS_GLOB", DEFAULT_REPORTS_GLOB),
    }
    it = iter(argv)
    for a in it:
        if a == "--contract":
            opts["contract"] = next(it, None)
        elif a == "--report-file":
            opts["report_file"] = next(it, None)
        elif a == "--reports-glob":
            opts["reports_glob"] = next(it, None) or opts["reports_glob"]
        elif a == "--stdin-json":
            opts["stdin_json"] = True
        elif a in ("--text", "-"):
            opts["text_stdin"] = True
        else:
            raise SystemExit(f"validate_report.py: unknown argument '{a}'")
    return opts


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        opts = _parse_args(argv)
    except SystemExit as e:
        print(str(e), file=sys.stderr)
        return 1

    vocab = load_contract(opts["contract"])

    # 1) explicit report file
    if opts["report_file"]:
        try:
            with open(opts["report_file"], "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError as e:
            print(f"validate_report.py: cannot read --report-file: {e}", file=sys.stderr)
            return 1
    # 2) raw text on stdin
    elif opts["text_stdin"]:
        text = sys.stdin.read()
    # 3) hook JSON on stdin (default if nothing else and stdin is piped)
    else:
        raw = sys.stdin.read()
        if not raw.strip():
            # No payload at all -> nothing to validate -> allow (don't block on an empty hook call).
            return 0
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            # Not JSON: treat the raw text as the report only if --stdin-json was NOT requested.
            if opts["stdin_json"]:
                print("validate_report.py: --stdin-json set but stdin is not valid JSON", file=sys.stderr)
                return 1
            text = raw
            obj = None
        else:
            extracted, reason = extract_report_from_event(obj, opts["reports_glob"])
            if extracted is None:
                # Not an in-scope report write -> allow silently.
                return 0
            text = extracted

    problems = validate_report(text, vocab)
    if problems:
        print(
            f"BLOCKED by validate_report.py: report violates the deliverable contract "
            f"({vocab.source}). Fix and re-emit:",
            file=sys.stderr,
        )
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

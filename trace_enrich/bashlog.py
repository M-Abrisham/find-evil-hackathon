#!/usr/bin/env python3
"""Loader + outcome classifier for Protocol SIFT raw-bash logs.

These ``bash_raw_<session_id>.jsonl`` files are written by a forensic-audit
hook on the SIFT VM at::

    .../analysis/braintrust_raw/bash_raw_<session_id>.jsonl

They are **BASH-ONLY** -- Read/Write/MCP tool calls never appear here. Each
line is one JSON object describing a single Bash tool invocation. The schema
(verified against real logs on 2026-06-12) is::

    {
      "ts": "2026-06-12T04:01:49Z",            # ISO-8601 Z timestamp
      "session_id": "d50b6132-...",            # Claude Code session
      "tool_use_id": "toolu_01URsr...",        # JOIN KEY to the Braintrust span
      "cwd": "/home/ubuntu/.../protocol-sift",
      "transcript_path": ".../<session>.jsonl",
      "command": "ls -la && echo ... || ...",  # the FULL shell pipeline
      "description": "Inspect workspace",       # the agent's own label
      "stdout": "...",                          # inline stdout (may be truncated)
      "stderr": "",
      "tool_response": {
        "stdout": "...",                        # mirror of top-level stdout
        "stderr": "",
        "interrupted": false,
        "isImage": false,
        "noOutputExpected": false,
        "persistedOutputPath": ".../tool-results/<id>.txt",  # OPTIONAL
        "persistedOutputSize": 168894                        # OPTIONAL
      }
    }

IMPORTANT schema facts that shape this module
---------------------------------------------
* There is **NO** ``exit_code`` / ``returncode`` field anywhere -- not at the
  top level and not inside ``tool_response``. The orchestration brief warned
  not to promise per-sub-tool exit codes; the reality is we get *no* numeric
  exit code at all. So ``outcome()`` is inferred from ``stderr`` text, the
  ``interrupted`` flag, and stdout emptiness -- never from a return code.
* For large outputs the inline ``stdout`` is truncated (observed at 30000
  chars) while ``persistedOutputPath`` / ``persistedOutputSize`` point at the
  full capture on disk. We surface those so a provenance step can read the full
  text when present, but emptiness detection only needs the inline stdout.

Per-BASH-CALL contract
----------------------
One log line == one shell pipeline == ONE outcome. A pipeline like
``fls ... | icat ... && yara ...`` produces a single stdout/stderr pair and a
single ``interrupted`` flag, so we classify it as a whole. Splitting a compound
command into its sub-tools (for skill-owner tagging) happens elsewhere; this
module deliberately does not attribute outcomes to individual sub-tools.

stdlib-only. No third-party deps.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterator, Optional

# ---------------------------------------------------------------------------
# Outcome classification
# ---------------------------------------------------------------------------

# Outcome vocabulary, per-bash-call.
OK = "ok"
ERRORED = "errored"
EMPTY = "empty"

#: Substrings / patterns in stderr (or, as a fallback, stdout) that signal a
#: real failure even though the log carries no exit code. Matched
#: case-insensitively. Kept deliberately conservative -- we only want to flag
#: text that almost certainly indicates a failed command, not benign
#: diagnostics that tools print to stderr on success.
_ERROR_PATTERNS = (
    r"command not found",
    r"no such file or directory",
    r"not found",
    r"permission denied",
    r"cannot open",
    r"cannot access",
    r"cannot stat",
    r"cannot remove",
    r"cannot create",
    r"operation not permitted",
    r"\bunrecognized\b",
    r"\binvalid (?:option|argument|choice|value)\b",
    r"\bsyntax error\b",
    r"\bsegmentation fault\b",
    r"\bcore dumped\b",
    r"\btraceback \(most recent call last\)",
    r"\b[a-z_]*error:",          # python/tool "FooError:" / "error:"
    r"^error\b",                  # a line that starts with "error"
    r"\bfatal\b",
    r"\bunable to\b",
    r"\bfailed\b",
    r"\bbad (?:option|flag|magic)\b",
    r"\busage:",                  # tools that print usage when args are wrong
    r"\bexit code [1-9]",         # a tool that echoes its own non-zero exit
)

_ERROR_RE = re.compile("|".join(_ERROR_PATTERNS), re.IGNORECASE | re.MULTILINE)


def _text(entry: Dict[str, Any], field: str) -> str:
    """Return ``entry[field]`` (or the nested ``tool_response`` mirror) as str.

    The top-level ``stdout``/``stderr`` and the ``tool_response`` copy are
    normally identical, but we coalesce defensively in case one side is missing.
    """
    val = entry.get(field)
    if val is None:
        tr = entry.get("tool_response")
        if isinstance(tr, dict):
            val = tr.get(field)
    return val if isinstance(val, str) else ""


def stderr_looks_like_error(stderr: str) -> bool:
    """True if ``stderr`` text matches a clear command-failure pattern.

    Exposed for testing and for callers that want the heuristic alone.
    """
    if not stderr or not stderr.strip():
        return False
    return _ERROR_RE.search(stderr) is not None


def outcome(entry: Dict[str, Any]) -> str:
    """Classify a single bash-call entry as ``ok`` / ``errored`` / ``empty``.

    This is a **per-BASH-CALL** verdict: one shell pipeline -> one outcome. We
    have no exit code, so the rule is:

    1. ``errored`` -- the call was ``interrupted`` (timeout/kill), OR ``stderr``
       matches a clear error pattern (``stderr_looks_like_error``).
    2. ``empty``   -- it did not error but produced no stdout (blank/whitespace),
       UNLESS the command itself declared ``noOutputExpected`` (then it's ``ok``).
    3. ``ok``      -- it produced non-blank stdout and showed no error signal.

    A non-empty ``stderr`` that does NOT match an error pattern (e.g. a progress
    bar or an informational notice many forensic tools print to stderr) does
    not by itself make the call ``errored``; it is judged on the rules above.
    """
    tr = entry.get("tool_response")
    tr = tr if isinstance(tr, dict) else {}

    # (1) hard failure signals first.
    if tr.get("interrupted") is True:
        return ERRORED

    stderr = _text(entry, "stderr")
    if stderr_looks_like_error(stderr):
        return ERRORED

    # (2) succeeded-but-no-output.
    stdout = _text(entry, "stdout")
    if not stdout.strip():
        # Some commands legitimately produce nothing (e.g. `mkdir`, a grep that
        # the agent ran expecting a match-or-nothing). The hook records that
        # intent in `noOutputExpected`; honour it so we don't flag silent
        # housekeeping as a returned-nothing analysis step.
        if tr.get("noOutputExpected") is True:
            return OK
        # If output was persisted to disk but the inline copy is blank, it is
        # not really empty -- treat as ok and let provenance read the file.
        if tr.get("persistedOutputPath"):
            return OK
        return EMPTY

    return OK


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def iter_bash_log(path: str) -> Iterator[Dict[str, Any]]:
    """Yield each parsed JSON object from a bash_raw ``.jsonl`` file.

    Blank lines are skipped. Malformed lines are skipped silently (the log is
    appended to by a hook during a live run and a final line can be partial).
    """
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (ValueError, json.JSONDecodeError):
                continue
            if isinstance(obj, dict):
                yield obj


def _normalize_entry(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Project a raw log object into the stable shape callers depend on.

    The raw schema carries no exit code, so we expose ``outcome`` (the derived
    verdict) instead of a fake numeric code, while preserving the underlying
    fields a provenance/rollup step needs.
    """
    tr = raw.get("tool_response")
    tr = tr if isinstance(tr, dict) else {}
    entry: Dict[str, Any] = {
        "tool_use_id": raw.get("tool_use_id"),
        "session_id": raw.get("session_id"),
        "ts": raw.get("ts"),
        "command": raw.get("command", "") or "",
        "description": raw.get("description", "") or "",
        "stdout": _text(raw, "stdout"),
        "stderr": _text(raw, "stderr"),
        "interrupted": bool(tr.get("interrupted")),
        "no_output_expected": bool(tr.get("noOutputExpected")),
        "persisted_output_path": tr.get("persistedOutputPath"),
        "persisted_output_size": tr.get("persistedOutputSize"),
        "cwd": raw.get("cwd"),
        "transcript_path": raw.get("transcript_path"),
        # keep the original for any field we didn't surface explicitly
        "raw": raw,
    }
    entry["outcome"] = outcome(raw)
    return entry


def load_bash_log(path: str) -> Dict[str, Dict[str, Any]]:
    """Load a bash_raw log into a dict keyed by ``tool_use_id``.

    Returns ``{tool_use_id: entry}`` where each ``entry`` has at least::

        command, stdout, stderr, outcome, interrupted, no_output_expected,
        persisted_output_path, persisted_output_size, session_id, ts, raw

    Note: ``tool_use_id`` is the JOIN KEY to the Braintrust trace. If the same
    id appears twice (it should not within one session) the LAST occurrence
    wins, matching append-order semantics. Entries with no ``tool_use_id`` are
    dropped, since they cannot be joined to a span.
    """
    result: Dict[str, Dict[str, Any]] = {}
    for raw in iter_bash_log(path):
        tuid = raw.get("tool_use_id")
        if not tuid:
            continue
        result[tuid] = _normalize_entry(raw)
    return result


# ---------------------------------------------------------------------------
# Provenance helper
# ---------------------------------------------------------------------------


def get_stdout(
    log: Dict[str, Dict[str, Any]],
    tool_use_id: str,
    *,
    read_persisted: bool = False,
) -> str:
    """Return the stdout text for ``tool_use_id`` (for IOC->tool provenance).

    By default returns the inline ``stdout`` recorded in the log (which may be
    truncated for very large outputs). When ``read_persisted=True`` and the
    entry has a ``persisted_output_path`` whose inline stdout is shorter than
    the persisted size, the full captured output is read from that file and
    returned instead (falling back to the inline text if the file is
    unreadable). Returns ``""`` when the id is unknown.
    """
    entry = log.get(tool_use_id)
    if entry is None:
        return ""
    inline = entry.get("stdout", "") or ""

    if read_persisted:
        full = _read_persisted(entry)
        if full is not None and len(full) >= len(inline):
            return full
    return inline


def _read_persisted(entry: Dict[str, Any]) -> Optional[str]:
    """Read the full persisted stdout file if present and larger than inline."""
    path = entry.get("persisted_output_path")
    if not path:
        return None
    size = entry.get("persisted_output_size")
    inline_len = len(entry.get("stdout", "") or "")
    # Only bother if the persisted capture is plausibly larger than inline.
    if isinstance(size, int) and size <= inline_len:
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


__all__ = [
    "OK",
    "ERRORED",
    "EMPTY",
    "load_bash_log",
    "iter_bash_log",
    "outcome",
    "stderr_looks_like_error",
    "get_stdout",
]

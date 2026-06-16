#!/usr/bin/env python3
"""R6 - Per-command HASH-CHAINED command ledger (PostToolUse hook).

BUILD-TIME TOOLING ONLY (Protocol SIFT). Not hackathon-submission code.
Do NOT commit secrets. STDLIB ONLY (hashlib, json). INERT until the user wires it.

WHAT THIS IS
------------
A PostToolUse hook for Claude Code. After every tool call the SIFT agent makes,
Claude Code invokes this script with the hook event JSON on stdin. We APPEND one
JSON line to a tamper-evident, hash-chained ledger that records, per tool call:

    {
      "v": 1,                       # ledger format version
      "seq": 0,                     # monotonic 0-based sequence index
      "ts": "2026-06-14T...Z",      # UTC ISO-8601 capture time
      "tool": "Bash",               # tool_name from the hook payload
      "command": "mmls disk.E01",   # command (Bash) or compact args repr (other tools)
      "output_sha256": "...",       # sha256 of the tool's STDOUT/response (NOT stored verbatim)
      "output_len": 1234,           # byte length of the hashed output (sanity / dedup)
      "session_id": "abc",          # Claude Code session id if present
      "prev_hash": "GENESIS" | hex, # entry_hash of the PREVIOUS line (chain link)
      "receipt_id": "uuid-ish",     # opaque per-entry id for cross-referencing
      "entry_hash": "hex"           # sha256(prev_hash + canonical(entry-without-entry_hash))
    }

The chain property: entry_hash[i] = sha256( prev_hash[i] || canonical_json(entry_i) )
and prev_hash[i] = entry_hash[i-1] (prev_hash[0] = "GENESIS"). Any mutation,
insertion, deletion, or reordering breaks the recomputation at the first affected
index. See verify_ledger.py.

This is DISTINCT from the per-LAP optimizer score ledger. This ledger is the
chain-of-custody for the System-Under-Test's actual tool invocations.

LEDGER LOCATION
---------------
Resolved in priority order (so the agent's own writable tree never holds the
authoritative custody log):
    1. --ledger PATH            (CLI arg)
    2. $SIFT_LEDGER_PATH        (env)
    3. ~/.sift-custody/command_ledger.jsonl   (default, OUTSIDE the project /
                                               agent-writable dirs)

FAILURE POLICY (important for a hook)
-------------------------------------
A custody-logging hook must NEVER break the agent run. On ANY internal error we
print a diagnostic to stderr and exit 0 (non-blocking). PostToolUse cannot
retroactively deny a call anyway; its job here is to record, not to gate.

SETTINGS.JSON WIRING SNIPPET  --  DO NOT APPLY AUTOMATICALLY
------------------------------------------------------------
Add a "PostToolUse" array alongside the existing "PreToolUse" in
sift-runner/settings.json (this repo already has a "hooks" object):

    "hooks": {
      "PreToolUse": [ ... existing validate_cmd.sh entry ... ],
      "PostToolUse": [
        {
          "matcher": "*",
          "hooks": [
            {
              "type": "command",
              "command": "python3 $CLAUDE_PROJECT_DIR/sift-runner/ledger_hook.py"
            }
          ]
        }
      ]
    }

  - matcher "*" records ALL tools (Bash, Read, Grep, ...). Use "Bash" to record
    only shell commands.
  - To pin the ledger path explicitly, append it as an arg, e.g.:
      "command": "python3 $CLAUDE_PROJECT_DIR/sift-runner/ledger_hook.py --ledger /var/lib/sift/custody.jsonl"
  - Or set SIFT_LEDGER_PATH in the environment / settings "env" block.

PUBLIC API
----------
    canonical_bytes(obj)                 -> bytes   (stable, sorted, compact JSON)
    sha256_hex(data)                     -> str
    extract_fields(hook_event)           -> dict    (tool/command/output from raw JSON)
    compute_entry_hash(prev_hash, entry) -> str
    build_entry(hook_event, prev_hash, seq, now=None, receipt_id=None) -> dict
    read_last_line(path)                 -> str|None
    last_state(path)                     -> (prev_hash, next_seq)
    append_entry(path, hook_event, ...)  -> dict     (the entry written)
    resolve_ledger_path(arg=None, env=None) -> str
    main(argv=None, stdin=None)          -> int
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone

GENESIS = "GENESIS"
LEDGER_VERSION = 1
DEFAULT_LEDGER_REL = os.path.join("~", ".sift-custody", "command_ledger.jsonl")


# --------------------------------------------------------------------------- #
# Canonicalization + hashing
# --------------------------------------------------------------------------- #
def canonical_bytes(obj) -> bytes:
    """Deterministic JSON bytes: sorted keys, no insignificant whitespace.

    Used both for hashing entries and for re-hashing on verify, so the two MUST
    use this exact function. ensure_ascii=True so the byte stream is stable
    regardless of locale/encoding quirks.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def sha256_hex(data) -> str:
    """sha256 of bytes (or str -> utf-8) -> lowercase hex digest."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    elif not isinstance(data, (bytes, bytearray)):
        data = str(data).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def compute_entry_hash(prev_hash: str, entry: dict) -> str:
    """entry_hash = sha256( prev_hash_bytes || canonical(entry sans entry_hash) ).

    The entry passed in may or may not already carry an 'entry_hash' key; we
    strip it before hashing so the digest never depends on itself. We bind the
    prev_hash explicitly into the preimage (in addition to entry['prev_hash'])
    so a reorder that leaves prev_hash text intact still fails recomputation.
    """
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    h = hashlib.sha256()
    h.update(prev_hash.encode("utf-8"))
    h.update(b"\x1f")  # unit separator: domain boundary between link and body
    h.update(canonical_bytes(body))
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# Hook payload extraction
# --------------------------------------------------------------------------- #
def _stringify_command(tool_name: str, tool_input) -> str:
    """Best-effort human/audit-readable command string for any tool.

    Bash -> the literal command. Read/Grep/etc -> a compact, sorted-key repr of
    tool_input so the ledger stays meaningful for non-shell tools too.
    """
    if not isinstance(tool_input, dict):
        return "" if tool_input is None else str(tool_input)
    if tool_name == "Bash" and "command" in tool_input:
        return str(tool_input.get("command", ""))
    # Generic tools: canonical repr of the inputs (stable + greppable).
    try:
        return canonical_bytes(tool_input).decode("utf-8")
    except Exception:
        return str(tool_input)


def _extract_output(hook_event: dict):
    """Pull the tool's output/response out of the (varied) hook payload shapes.

    Claude Code has used a few shapes over versions; we look in priority order
    and always return a *string* to hash. We hash, never store, the raw output
    (forensic outputs can be huge / sensitive).
    """
    # PostToolUse canonical: tool_response (str OR dict with stdout/stdout-ish).
    resp = hook_event.get("tool_response")
    if resp is None:
        resp = hook_event.get("tool_output")
    if resp is None:
        # Some shapes nest it under tool_input-adjacent keys; last resort.
        resp = hook_event.get("output")

    if resp is None:
        return ""
    if isinstance(resp, str):
        return resp
    if isinstance(resp, dict):
        for key in ("stdout", "output", "content", "text", "result", "stderr"):
            if key in resp and resp[key] is not None:
                val = resp[key]
                return val if isinstance(val, str) else canonical_bytes(val).decode("utf-8")
        # No known text field -> hash the whole response canonically.
        return canonical_bytes(resp).decode("utf-8")
    # list / number / bool -> canonical form.
    try:
        return canonical_bytes(resp).decode("utf-8")
    except Exception:
        return str(resp)


def extract_fields(hook_event: dict) -> dict:
    """Normalize a raw hook event into the audit-relevant fields.

    Returns {tool, command, output, session_id}. Pure (no I/O, no clock).
    """
    if not isinstance(hook_event, dict):
        hook_event = {}
    tool = hook_event.get("tool_name") or hook_event.get("tool") or ""
    tool_input = hook_event.get("tool_input", {})
    command = _stringify_command(tool, tool_input)
    output = _extract_output(hook_event)
    session_id = (
        hook_event.get("session_id")
        or hook_event.get("sessionId")
        or ""
    )
    return {
        "tool": tool,
        "command": command,
        "output": output,
        "session_id": session_id,
    }


# --------------------------------------------------------------------------- #
# Entry construction
# --------------------------------------------------------------------------- #
def build_entry(hook_event: dict, prev_hash: str, seq: int,
                now=None, receipt_id=None) -> dict:
    """Build one fully-formed, self-consistent ledger entry (incl. entry_hash).

    `now` (a datetime, assumed/forced to UTC) and `receipt_id` are injectable so
    tests are deterministic. The returned dict is ready to json.dumps onto a line.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    if receipt_id is None:
        receipt_id = str(uuid.uuid4())

    fields = extract_fields(hook_event)
    output = fields["output"]
    output_bytes = output.encode("utf-8") if isinstance(output, str) else bytes(output)

    entry = {
        "v": LEDGER_VERSION,
        "seq": int(seq),
        "ts": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "tool": fields["tool"],
        "command": fields["command"],
        "output_sha256": sha256_hex(output_bytes),
        "output_len": len(output_bytes),
        "session_id": fields["session_id"],
        "prev_hash": prev_hash,
        "receipt_id": receipt_id,
    }
    entry["entry_hash"] = compute_entry_hash(prev_hash, entry)
    return entry


# --------------------------------------------------------------------------- #
# Ledger I/O
# --------------------------------------------------------------------------- #
def resolve_ledger_path(arg=None, env=None) -> str:
    """Resolve the ledger path: --arg > $SIFT_LEDGER_PATH > default (~/.sift-custody)."""
    if arg:
        return os.path.abspath(os.path.expanduser(arg))
    env = env if env is not None else os.environ.get("SIFT_LEDGER_PATH")
    if env:
        return os.path.abspath(os.path.expanduser(env))
    return os.path.abspath(os.path.expanduser(DEFAULT_LEDGER_REL))


def read_last_line(path: str):
    """Return the last NON-EMPTY line of the ledger, or None if file is empty/absent."""
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return None
    last = None
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            s = line.strip()
            if s:
                last = s
    return last


def last_state(path: str):
    """Return (prev_hash_for_next, next_seq) by inspecting the tail of the ledger.

    On a fresh/empty ledger -> (GENESIS, 0). If the tail line is corrupt/unreadable
    we fall back to GENESIS/0 rather than crash (verify_ledger.py is the auditor;
    the hook must stay non-fatal).
    """
    last = read_last_line(path)
    if last is None:
        return GENESIS, 0
    try:
        rec = json.loads(last)
        return rec["entry_hash"], int(rec["seq"]) + 1
    except Exception:
        return GENESIS, 0


def append_entry(path: str, hook_event: dict, now=None, receipt_id=None) -> dict:
    """Append exactly one chained entry for `hook_event`; return the entry dict.

    Creates parent dirs if needed. Writes one compact JSON line + newline.
    """
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)

    prev_hash, seq = last_state(path)
    entry = build_entry(hook_event, prev_hash, seq, now=now, receipt_id=receipt_id)
    line = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    return entry


# --------------------------------------------------------------------------- #
# CLI / hook entrypoint
# --------------------------------------------------------------------------- #
def _parse_args(argv):
    """Tiny argparse-free parser: supports --ledger PATH / --ledger=PATH."""
    ledger = None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--ledger":
            if i + 1 < len(argv):
                ledger = argv[i + 1]
                i += 2
                continue
            i += 1
        elif a.startswith("--ledger="):
            ledger = a.split("=", 1)[1]
            i += 1
        else:
            i += 1
    return ledger


def main(argv=None, stdin=None) -> int:
    """Hook entrypoint. Reads hook JSON from stdin, appends one ledger entry.

    ALWAYS returns 0 (non-blocking) even on error: a custody logger must not be
    able to abort the SIFT run. Diagnostics go to stderr.
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    stdin = sys.stdin if stdin is None else stdin
    try:
        ledger_arg = _parse_args(argv)
        path = resolve_ledger_path(ledger_arg)

        raw = stdin.read()
        if raw is None or not str(raw).strip():
            # No payload (e.g. invoked manually with no stdin) -> nothing to log.
            return 0
        try:
            event = json.loads(raw)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"[ledger_hook] unparseable hook JSON: {exc}\n")
            return 0

        # Only PostToolUse-shaped events carry a tool; ignore anything else quietly.
        if not isinstance(event, dict) or not (
            event.get("tool_name") or event.get("tool")
        ):
            return 0

        entry = append_entry(path, event)
        sys.stderr.write(
            f"[ledger_hook] seq={entry['seq']} tool={entry['tool']!r} "
            f"receipt={entry['receipt_id']} -> {path}\n"
        )
        return 0
    except Exception as exc:  # noqa: BLE001 - never break the agent run
        sys.stderr.write(f"[ledger_hook] non-fatal error (run not blocked): {exc}\n")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

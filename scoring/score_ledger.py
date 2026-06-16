#!/usr/bin/env python3
"""Hash-chained, tamper-evident **per-LAP score ledger** for the eval loop.

One JSON line per optimization lap. Each line records the lap's keep/revert
DECISION together with the exact scorer ``aggregate()`` output it was based on.

This module RECORDS, it never DECIDES and it never RECOMPUTES a score. The
keep/revert decision is made elsewhere (by the eval loop); ``append_lap`` only
persists, byte-for-byte, the score vector the scorer already produced (after a
no-float SANITIZE pass that turns the scorer's micro-recall floats into stable
fixed-decimal strings — see :func:`sanitize_score_vector`). It is the SCORE
ledger, distinct from the per-command *receipts* ledger; this is a STANDALONE
module (no cross-module imports) that faithfully copies the canonical-JSON /
no-float / SHA-256 hash-chain / flock-writer / verify-chain primitives of
``sift_agent.ledger``.

Row schema (``score-ledger-v1`` — one JSON object per line)
-----------------------------------------------------------
::

    schema_version    "score-ledger-v1"  — present on EVERY line
    lap               int   — the optimization lap number
    ts                UTC ISO-8601 with a trailing "Z"
    case              str   — case id this lap was driven by (e.g. VIGIA-REAL-001)
    blamed_failure    str   — the failure this lap tried to fix (e.g. "verdict_absent")
    edit              {sha_before:str, sha_after:str} — the config edit under test
    score_vector      dict  — SANITIZED aggregate() of the CANDIDATE (this lap)
    baseline_vector   dict  — SANITIZED aggregate() of the BASELINE compared to
    decision          "KEEP" | "REVERT"  — recorded, NOT decided here
    reason            str   — human/agent rationale for the decision
    usage             dict  — token / cost / session metadata (no floats)
    prev_row_sha256   str   — previous row's row_hash ("0"*64 genesis on row 1)
    row_hash          str   — SHA-256 of the canonical row MINUS row_hash

Hashing: ``row_hash`` is the SHA-256 of the canonical row with ``row_hash``
removed; ``prev_row_sha256`` IS part of the preimage — that link is what makes
re-ordering or deleting a middle row detectable.

The float problem (and why we sanitize, not recompute)
------------------------------------------------------
The scorer's ``aggregate()`` returns four micro metrics as Python floats
(true-division), or ``None`` when their denominator is 0. A float's text repr is
not guaranteed stable across Python / json builds — exactly what makes a hashed
ledger non-reproducible — so the no-float canonicalizer REFUSES floats.
:func:`sanitize_score_vector` keeps every integer component VERBATIM and
re-expresses each recall as a fixed-decimal STRING ``f"{num/den:.4f}"`` derived
from those verbatim integer components (``None`` denominator → JSON ``null``).
This is a stable *formatting* of a ratio the scorer already computed — it is NOT
recomputing the score.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

__all__ = [
    "SCHEMA_VERSION",
    "GENESIS_PREV_HASH",
    "DEFAULT_LEDGER_PATH",
    "RECALL_COMPONENTS",
    "INT_KEYS",
    "ScoreLedgerError",
    "ScoreLedgerChainError",
    "canonical_json",
    "canonical_bytes",
    "compute_row_hash",
    "sanitize_score_vector",
    "append_lap",
    "read_rows",
    "VerifyResult",
    "verify_chain",
    "assert_chain_ok",
    "render_markdown",
    "main",
]

# =============================================================================
# Named constants.
# =============================================================================
#: Schema tag stamped on every score-ledger row.
SCHEMA_VERSION = "score-ledger-v1"

#: The genesis sentinel: sixty-four ASCII zeros. ``prev_row_sha256`` of the
#: FIRST row in any chain is exactly this, so a missing row 1 is detectable.
GENESIS_PREV_HASH = "0" * 64

#: Default runtime ledger path (git-ignored; CODE is committed, the data is not).
DEFAULT_LEDGER_PATH = os.environ.get(
    "SCORE_LEDGER_PATH", os.path.expanduser("~/score-ledger/ledger.jsonl")
)

#: The four micro-recall metrics aggregate() returns as float-or-None, mapped to
#: the verbatim INTEGER (numerator, denominator) component keys we derive the
#: fixed-decimal string from. ``None`` denominator → JSON null.
RECALL_COMPONENTS: dict[str, tuple[str, str]] = {
    "findable_recall_micro": ("findable_found", "findable_total"),
    "full_recall_micro": ("full_found", "full_total"),
    "mitre_recall_micro": ("mitre_found", "mitre_total"),
    "mitre_precision_micro": ("mitre_grounded_total", "mitre_emitted_total"),
}

#: The integer-valued aggregate() keys, kept VERBATIM by sanitize_score_vector.
INT_KEYS: tuple[str, ...] = (
    "cases",
    "fabrication_count_total",
    "findable_found",
    "findable_total",
    "full_found",
    "full_total",
    "invalid_mitre_total",
    "mitre_emitted_total",
    "mitre_found",
    "mitre_grounded_total",
    "mitre_total",
    "verdicts_emitted",
)


class ScoreLedgerError(Exception):
    """A row could not be built/written because it violates an invariant."""


class ScoreLedgerChainError(ScoreLedgerError):
    """The chain failed verification — callers must refuse to proceed."""


# =============================================================================
# Canonicalization + hashing — the EXACT, pinned serialization.
# =============================================================================
def canonical_json(obj: Any) -> str:
    """Canonical JSON text for ``obj`` — the only serialization that is hashed.

    Pinned EXACTLY (or hashes will not reproduce): sorted keys, compact
    separators, ASCII-only, ``allow_nan=False`` (a NaN/Infinity RAISES rather
    than emitting non-standard JSON). Ints stay ints.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def canonical_bytes(obj: Any) -> bytes:
    """UTF-8 bytes of :func:`canonical_json` — the SHA-256 preimage."""
    return canonical_json(obj).encode("utf-8")


def compute_row_hash(row: dict[str, Any]) -> str:
    """SHA-256 (lowercase hex) of the canonical row **excluding** ``row_hash``.

    ``prev_row_sha256`` IS part of the preimage — that is the link that makes
    reordering or deleting a middle row detectable. ``row_hash`` is excluded
    from its own input.
    """
    core = {k: v for k, v in row.items() if k != "row_hash"}
    return hashlib.sha256(canonical_bytes(core)).hexdigest()


def _has_float(obj: Any) -> bool:
    """True if ``obj`` contains any ``float`` (recursively).

    ``bool`` is a subclass of ``int`` (not ``float``) and is allowed. Floats are
    rejected because their text repr is not guaranteed stable across Python /
    json versions — exactly what would make a hashed ledger non-reproducible.
    """
    if isinstance(obj, float):
        return True
    if isinstance(obj, dict):
        return any(_has_float(v) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return any(_has_float(v) for v in obj)
    return False


def _utc_now_z() -> str:
    """Host UTC, tz-aware, ISO-8601, ``Z`` suffix — e.g. ``2026-06-15T01:02:03Z``."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# =============================================================================
# The float -> fixed-decimal-string adapter (sanitize, never recompute).
# =============================================================================
def sanitize_score_vector(agg: dict[str, Any]) -> dict[str, Any]:
    """Adapt a scorer ``aggregate()`` dict into a hash-stable, no-float vector.

    Every INTEGER key is kept VERBATIM. Each of the four micro metrics in
    :data:`RECALL_COMPONENTS` is re-expressed as a fixed-decimal STRING
    ``f"{num/den:.4f}"`` derived from its verbatim integer (numerator,
    denominator) components — or JSON ``null`` when the denominator is 0 (the
    scorer's None-denominator path). Any other (non-recall, non-int) key is
    carried through verbatim. This is a stable FORMATTING of a ratio the scorer
    already produced; it does NOT recompute the score.

    Raises :class:`ScoreLedgerError` if a float survives (e.g. a non-recall key
    carried a raw float), so a non-reproducible row can never be built.
    """
    if not isinstance(agg, dict):
        raise ScoreLedgerError(f"score vector must be a dict, got {type(agg).__name__}")

    result: dict[str, Any] = {}
    recall_keys = set(RECALL_COMPONENTS)

    for key, value in agg.items():
        if key in recall_keys:
            num_key, den_key = RECALL_COMPONENTS[key]
            num = agg.get(num_key)
            den = agg.get(den_key)
            if not isinstance(num, int) or isinstance(num, bool):
                raise ScoreLedgerError(
                    f"recall {key!r} needs an int numerator {num_key!r}, got {num!r}"
                )
            if not isinstance(den, int) or isinstance(den, bool):
                raise ScoreLedgerError(
                    f"recall {key!r} needs an int denominator {den_key!r}, got {den!r}"
                )
            # den == 0 -> scorer emits None -> we persist JSON null. Else format
            # from the verbatim int components (NOT from the float aggregate()
            # produced, so the stored string is reproducible and audit-derivable).
            result[key] = None if den == 0 else f"{num / den:.4f}"
        else:
            # Integer counters and any other scalar carried verbatim.
            result[key] = value

    if _has_float(result):
        raise ScoreLedgerError(
            "sanitized score vector still contains a float; all ratios must be "
            "fixed-decimal strings and all counts must be ints (hash stability)"
        )
    return result


# =============================================================================
# Row construction + invariants.
# =============================================================================
_REQUIRED_ROW_KEYS = (
    "schema_version",
    "lap",
    "ts",
    "case",
    "blamed_failure",
    "edit",
    "score_vector",
    "baseline_vector",
    "decision",
    "reason",
    "usage",
)

_LEGAL_DECISIONS = ("KEEP", "REVERT")


def _assert_row_invariants(row: dict[str, Any]) -> None:
    """Fail-fast guards for a NEW row (raise :class:`ScoreLedgerError`)."""
    if _has_float(row):
        raise ScoreLedgerError(
            "row contains a float; recalls/cost must be fixed-decimal strings "
            "and counts must be ints (hash stability)"
        )
    decision = row.get("decision")
    if decision not in _LEGAL_DECISIONS:
        raise ScoreLedgerError(
            f"illegal decision {decision!r}; must be one of {_LEGAL_DECISIONS}"
        )
    lap = row.get("lap")
    if not isinstance(lap, int) or isinstance(lap, bool):
        raise ScoreLedgerError(f"lap must be an int, got {lap!r}")
    edit = row.get("edit")
    if not isinstance(edit, dict) or "sha_before" not in edit or "sha_after" not in edit:
        raise ScoreLedgerError(
            "edit must be a dict with 'sha_before' and 'sha_after' keys"
        )


def build_row(
    *,
    lap: int,
    case: str,
    blamed_failure: str,
    sha_before: str,
    sha_after: str,
    score_vector: dict[str, Any],
    baseline_vector: dict[str, Any],
    decision: str,
    reason: str,
    usage: dict[str, Any] | None = None,
    ts: str | None = None,
    sanitize: bool = True,
) -> dict[str, Any]:
    """Build ONE row dict — WITHOUT ``prev_row_sha256`` / ``row_hash``.

    By default both ``score_vector`` and ``baseline_vector`` are run through
    :func:`sanitize_score_vector` (set ``sanitize=False`` to store an
    already-sanitized vector verbatim). Chaining is applied later under the
    file lock so a row links against the true current tail. We NEVER recompute a
    score here — we only persist (sanitized) what was passed in.
    """
    sv = sanitize_score_vector(score_vector) if sanitize else dict(score_vector)
    bv = sanitize_score_vector(baseline_vector) if sanitize else dict(baseline_vector)

    if usage is None:
        usage = {
            "input_tokens": 0,
            "output_tokens": 0,
            "session_id": None,
            "cost_usd": "0.00",
            "note": "usage not supplied",
        }

    row: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "lap": lap,
        "ts": ts or _utc_now_z(),
        "case": case,
        "blamed_failure": blamed_failure,
        "edit": {"sha_before": sha_before, "sha_after": sha_after},
        "score_vector": sv,
        "baseline_vector": bv,
        "decision": decision,
        "reason": reason,
        "usage": usage,
    }
    _assert_row_invariants(row)
    return row


# =============================================================================
# The writer — atomic, flock-serialized, tail-read INSIDE the lock.
# =============================================================================
def _read_tail_row_hash(path: str) -> str:
    """Return the last complete line's ``row_hash``, else :data:`GENESIS_PREV_HASH`.

    Reads BACKWARD from EOF (O(line length)). A trailing partial line (no
    terminating newline — a torn write) is ignored; only a fully
    newline-terminated line is considered. MUST be called while holding the
    exclusive lock so the tail it reads is the true tail.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return GENESIS_PREV_HASH
    if size == 0:
        return GENESIS_PREV_HASH

    chunk = 65536
    buf = b""
    with open(path, "rb") as f:
        pos = size
        while pos > 0:
            step = min(chunk, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf
            if buf.count(b"\n") >= 2:
                break

    last_nl = buf.rfind(b"\n")
    if last_nl == -1:
        return GENESIS_PREV_HASH
    prev_nl = buf.rfind(b"\n", 0, last_nl)
    line = buf[prev_nl + 1 : last_nl]
    if not line.strip():
        return GENESIS_PREV_HASH
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return GENESIS_PREV_HASH
    h = obj.get("row_hash") if isinstance(obj, dict) else None
    return h if isinstance(h, str) else GENESIS_PREV_HASH


def _chain_and_write(path: str, row: dict[str, Any]) -> dict[str, Any]:
    """Link ``row`` onto the current tail and durably append it (under the lock).

    Takes ``flock(LOCK_EX)``, reads the chain tip INSIDE the lock, sets
    ``prev_row_sha256``, re-checks invariants, computes ``row_hash``, writes the
    whole ``line + "\\n"`` in a single ``os.write`` to an ``O_APPEND`` fd,
    ``fsync``s, and releases. Holding the lock across read-tip → append
    serializes concurrent writers so they cannot fork the chain.
    """
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)

    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        prev_hash = _read_tail_row_hash(path)  # tail-read MUST be inside the lock
        row.pop("row_hash", None)
        row["prev_row_sha256"] = prev_hash
        _assert_row_invariants(row)
        row["row_hash"] = compute_row_hash(row)
        line = (canonical_json(row) + "\n").encode("utf-8")
        os.write(fd, line)  # O_APPEND → single atomic write at EOF
        os.fsync(fd)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    return row


def append_lap(
    path: str | None = None,
    *,
    lap: int,
    case: str,
    blamed_failure: str,
    sha_before: str,
    sha_after: str,
    score_vector: dict[str, Any],
    baseline_vector: dict[str, Any],
    decision: str,
    reason: str,
    usage: dict[str, Any] | None = None,
    ts: str | None = None,
    sanitize: bool = True,
) -> dict[str, Any]:
    """Build, chain, and durably append ONE lap row to the ledger at ``path``.

    RECORDS the keep/revert ``decision`` (it does not decide). Stores the
    SANITIZED ``score_vector`` / ``baseline_vector`` byte-for-byte — it does NOT
    call the scorer or recompute any score.
    """
    path = path or DEFAULT_LEDGER_PATH
    row = build_row(
        lap=lap,
        case=case,
        blamed_failure=blamed_failure,
        sha_before=sha_before,
        sha_after=sha_after,
        score_vector=score_vector,
        baseline_vector=baseline_vector,
        decision=decision,
        reason=reason,
        usage=usage,
        ts=ts,
        sanitize=sanitize,
    )
    return _chain_and_write(path, row)


def read_rows(path: str | None = None) -> list[dict[str, Any]]:
    """Return all complete rows as a list of dicts (a torn trailing line is skipped).

    Convenience reader for render/inspection — NOT the integrity gate (that is
    :func:`verify_chain`). Blank lines and a final un-terminated line are skipped.
    """
    path = path or DEFAULT_LEDGER_PATH
    rows: list[dict[str, Any]] = []
    try:
        f = open(path, "rb")
    except FileNotFoundError:
        return rows
    with f:
        for raw_line in f:
            if not raw_line.endswith(b"\n"):
                break  # torn trailing write
            raw = raw_line[:-1]
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(obj, dict):
                rows.append(obj)
    return rows


# =============================================================================
# Verification — fail closed on a mid-file break; tolerate a torn trailing line.
# =============================================================================
@dataclass
class VerifyResult:
    """Outcome of :func:`verify_chain`.

    ``ok`` is the single go/no-go. ``broken_at`` pinpoints the FIRST mid-file
    break (line + byte offset) past which nothing is trusted.
    """

    path: str
    ok: bool = False
    chain_ok: bool = False
    n_rows: int = 0
    genesis_ok: bool = False
    trailing_partial: bool = False
    trailing_partial_offset: int | None = None
    broken_at: dict[str, Any] | None = None
    blank_lines_skipped: int = 0
    errors: list[str] = field(default_factory=list)

    def _fail(self, line: int, offset: int, reason: str) -> None:
        self.chain_ok = False
        self.ok = False
        self.broken_at = {"line": line, "byte_offset": offset, "reason": reason}
        self.errors.append(f"line {line} (byte {offset}): {reason}")

    def summary(self) -> str:
        lines = [
            f"ledger: {self.path}",
            f"result: {'OK' if self.ok else 'FAILED'}  "
            f"(chain_ok={self.chain_ok}, rows={self.n_rows}, "
            f"genesis_ok={self.genesis_ok})",
        ]
        if self.broken_at:
            b = self.broken_at
            lines.append(
                f"CHAIN BROKEN at line {b['line']} (byte offset {b['byte_offset']}): "
                f"{b['reason']} — refusing to splice past the gap"
            )
        if self.trailing_partial:
            lines.append(
                f"trailing partial line tolerated at byte {self.trailing_partial_offset} "
                "(incomplete write, ignored)"
            )
        return "\n".join(lines)

    def raise_if_broken(self) -> "VerifyResult":
        if not self.ok:
            raise ScoreLedgerChainError(self.summary())
        return self


def verify_chain(path: str | None = None) -> VerifyResult:
    """Walk the chain and report integrity. Fail closed on any mid-file break.

    Per row, in order: (1) the line parses as a JSON object carrying a string
    ``row_hash``; (2) ``row_hash`` recomputes from the canonical row (minus
    ``row_hash``); (3) ``prev_row_sha256`` equals the previous row's
    ``row_hash`` — and row 1's equals :data:`GENESIS_PREV_HASH`. A torn TRAILING
    line (no terminating newline) is tolerated and ignored, as is a
    blank/whitespace-only line (it carries no hash, so the chain links across
    it; a deletion still breaks the prev-link). ANY break in a fully-written
    line is fatal: verification stops, records the exact line + byte offset, and
    never splices past the gap. Streamed line-by-line (bounded memory).
    """
    path = path or DEFAULT_LEDGER_PATH
    result = VerifyResult(path=path)

    try:
        f = open(path, "rb")
    except FileNotFoundError:
        # No ledger yet — vacuously valid.
        result.ok = True
        result.chain_ok = True
        result.genesis_ok = True
        result.errors.append("ledger file does not exist yet (0 rows)")
        return result
    except OSError as exc:
        result.ok = False
        result.errors.append(f"cannot open ledger: {exc}")
        return result

    prev_row_hash = GENESIS_PREV_HASH
    offset = 0
    lineno = 0

    with f:
        while True:
            off = offset
            raw_line = f.readline()
            if not raw_line:
                break  # EOF
            offset += len(raw_line)
            if not raw_line.endswith(b"\n"):
                # Torn final write — our writer always writes "<json>\n" in one
                # atomic os.write, so a missing newline means an incomplete row.
                result.trailing_partial = True
                result.trailing_partial_offset = off
                break
            lineno += 1
            raw = raw_line[:-1]

            if not raw.strip():
                result.blank_lines_skipped += 1
                result.errors.append(f"line {lineno} (byte {off}): blank line skipped")
                continue

            try:
                row = json.loads(raw)
            except (json.JSONDecodeError, ValueError) as exc:
                result._fail(lineno, off, f"malformed JSON: {exc}")
                return result
            if not isinstance(row, dict):
                result._fail(lineno, off, "row is not a JSON object")
                return result

            stored = row.get("row_hash")
            if not isinstance(stored, str):
                result._fail(lineno, off, "missing or non-string row_hash")
                return result

            recomputed = compute_row_hash(row)
            if recomputed != stored:
                result._fail(
                    lineno, off,
                    f"row_hash mismatch (stored {stored}, recomputed {recomputed})",
                )
                return result

            is_first_row = result.n_rows == 0
            prev = row.get("prev_row_sha256")
            if prev != prev_row_hash:
                if is_first_row:
                    result._fail(
                        lineno, off,
                        f"genesis prev_row_sha256 mismatch "
                        f"(expected {GENESIS_PREV_HASH}, got {prev})",
                    )
                else:
                    result._fail(
                        lineno, off,
                        f"prev_row_sha256 link broken "
                        f"(expected {prev_row_hash}, got {prev})",
                    )
                return result
            if is_first_row:
                result.genesis_ok = True

            prev_row_hash = stored
            result.n_rows += 1

    result.chain_ok = True
    if result.n_rows == 0:
        result.genesis_ok = True
    result.ok = result.chain_ok
    return result


def assert_chain_ok(path: str | None = None) -> VerifyResult:
    """Verify and RAISE :class:`ScoreLedgerChainError` if the chain is not OK."""
    return verify_chain(path).raise_if_broken()


# =============================================================================
# Rendering — a per-lap markdown table with delta-vs-baseline per score dim.
# =============================================================================
#: Score dimensions shown in the render table, in display order.
_RENDER_DIMS: tuple[str, ...] = (
    "findable_recall_micro",
    "findable_found",
    "findable_total",
    "full_recall_micro",
    "full_found",
    "full_total",
    "mitre_recall_micro",
    "mitre_found",
    "mitre_total",
    "mitre_precision_micro",
    "mitre_grounded_total",
    "mitre_emitted_total",
    "invalid_mitre_total",
    "fabrication_count_total",
    "verdicts_emitted",
    "cases",
)


def _as_number(v: Any) -> float | int | None:
    """Coerce a stored cell (int, fixed-decimal string, or null) to a number."""
    if v is None:
        return None
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return float(v)
        except ValueError:
            return None
    if isinstance(v, float):
        return v
    return None


def _fmt_cell(value: Any, baseline: Any) -> str:
    """Render one dim cell as ``value (delta-vs-baseline)``.

    Stored recalls are fixed-decimal strings (or null); counts are ints. The
    delta is computed from the numeric coercions; ``null`` values render as
    ``n/a`` and yield no delta.
    """
    disp = "n/a" if value is None else str(value)
    nv = _as_number(value)
    bv = _as_number(baseline)
    if nv is None or bv is None:
        return disp
    delta = nv - bv
    if isinstance(value, str):  # recall string → show signed 4dp delta
        sign = "+" if delta >= 0 else ""
        return f"{disp} ({sign}{delta:.4f})"
    sign = "+" if delta >= 0 else ""
    return f"{disp} ({sign}{int(delta)})"


def render_markdown(path: str | None = None, rows: list[dict[str, Any]] | None = None) -> str:
    """Render the ledger as a per-lap markdown table.

    Columns: lap | case | blamed_failure | <each score dim with
    delta-vs-baseline> | decision | reason | tokens. The delta for each dim is
    ``score_vector[dim] - baseline_vector[dim]`` from the row itself (the
    baseline the lap was actually compared against), so the table is
    self-describing per row.
    """
    if rows is None:
        rows = read_rows(path)

    header_dims = list(_RENDER_DIMS)
    header = ["lap", "case", "blamed_failure"] + header_dims + ["decision", "reason", "tokens"]
    sep = ["---"] * len(header)
    out = ["| " + " | ".join(header) + " |", "| " + " | ".join(sep) + " |"]

    for row in rows:
        sv = row.get("score_vector", {}) or {}
        bv = row.get("baseline_vector", {}) or {}
        usage = row.get("usage", {}) or {}
        cells = [
            str(row.get("lap", "")),
            str(row.get("case", "")),
            str(row.get("blamed_failure", "")),
        ]
        for dim in header_dims:
            cells.append(_fmt_cell(sv.get(dim), bv.get(dim)))
        in_tok = usage.get("input_tokens")
        out_tok = usage.get("output_tokens")
        tok = f"in={in_tok} out={out_tok}"
        cells += [str(row.get("decision", "")), str(row.get("reason", "")), tok]
        out.append("| " + " | ".join(cells) + " |")

    return "\n".join(out)


# =============================================================================
# CLI — stdlib only; subcommands append / verify / render.
# =============================================================================
def _load_json_arg(value: str) -> dict[str, Any]:
    """Load a JSON dict from a @file path or an inline JSON string."""
    if value.startswith("@"):
        with open(value[1:], "r", encoding="utf-8") as fh:
            return json.load(fh)
    return json.loads(value)


def _cmd_append(args: argparse.Namespace) -> int:
    score_vector = _load_json_arg(args.score_vector)
    baseline_vector = _load_json_arg(args.baseline_vector)
    usage = _load_json_arg(args.usage) if args.usage else None
    row = append_lap(
        args.path,
        lap=args.lap,
        case=args.case,
        blamed_failure=args.blamed_failure,
        sha_before=args.sha_before,
        sha_after=args.sha_after,
        score_vector=score_vector,
        baseline_vector=baseline_vector,
        decision=args.decision,
        reason=args.reason,
        usage=usage,
    )
    print(f"appended lap {row['lap']} (row_hash {row['row_hash'][:16]}...) to {args.path}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    result = verify_chain(args.path)
    print(result.summary())
    return 0 if result.ok else 1


def _cmd_render(args: argparse.Namespace) -> int:
    print(render_markdown(args.path))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Per-lap score ledger (record-only, hash-chained, no-float)."
    )
    ap.add_argument(
        "--path", default=DEFAULT_LEDGER_PATH,
        help=f"ledger path (default {DEFAULT_LEDGER_PATH})",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("append", help="append one lap row (records a KEEP/REVERT decision)")
    pa.add_argument("--lap", type=int, required=True)
    pa.add_argument("--case", required=True)
    pa.add_argument("--blamed-failure", required=True, dest="blamed_failure")
    pa.add_argument("--sha-before", required=True, dest="sha_before")
    pa.add_argument("--sha-after", required=True, dest="sha_after")
    pa.add_argument("--score-vector", required=True, dest="score_vector",
                    help="@file.json or inline JSON of the candidate aggregate()")
    pa.add_argument("--baseline-vector", required=True, dest="baseline_vector",
                    help="@file.json or inline JSON of the baseline aggregate()")
    pa.add_argument("--decision", required=True, choices=_LEGAL_DECISIONS)
    pa.add_argument("--reason", required=True)
    pa.add_argument("--usage", default=None, help="@file.json or inline JSON usage meta")
    pa.set_defaults(func=_cmd_append)

    pv = sub.add_parser("verify", help="verify chain integrity (non-zero exit on a break)")
    pv.set_defaults(func=_cmd_verify)

    pr = sub.add_parser("render", help="render the per-lap markdown table")
    pr.set_defaults(func=_cmd_render)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

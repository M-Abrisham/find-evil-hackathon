"""Hash-chained, tamper-evident provenance ledger for SIFT tool receipts.

Goal
----
Every forensic tool invocation the agent makes is recorded as one **receipt**
— a single JSON line appended to ``receipts.jsonl``. The receipts are linked
into a SHA-256 hash chain (each line carries the previous line's
``entry_hash`` in its own ``prev_hash``), so any after-the-fact edit,
re-order, or deletion of a middle line is detectable by re-walking the chain.

This module EXTENDS the ``log_entry()`` single-writer pattern of the case
helper ``log_tool.py`` (a lone choke point that builds an entry dict and
appends one JSON line) — it does not rebuild it from scratch and it never
rewrites history. The canonical-serialization contract is the SAME one used by
:mod:`sift_agent.finding` (sorted keys, ASCII-only, ints stay ints, no floats,
no ``NaN``/``Infinity``) so hashes reproduce byte-for-byte across machines and
Python builds. Token attribution reuses
:func:`sift_agent.telemetry.stamp_receipt` (a tool row records the *issuing
agent turn's* tokens, explicitly labelled — never a fabricated per-tool count).

Receipt schema (one JSON object per line)
-----------------------------------------
Required, on every live receipt::

    schema_version    "receipts-v1"  — present on EVERY line
    receipt_id        uuid4 string
    ts                host UTC ISO-8601 with a trailing "Z"
    agent             which agent/operator issued the call
    tool              structured tool name (e.g. "vol", "MFTECmd")
    args              structured args (list[str] or str)
    evidence_ref      reference to the evidence item (image/mount/hive) or null
    output_path       where the tool output was written, or null
    output_sha256     SHA-256 of the output artifact, or null
    output_bytes      size of the output artifact in bytes, or null
    invocation_status one of {ok, path_failure, empty_output, error}
    exit_code         process exit code, or null
    tokens            issuing-agent-turn token attribution (labelled dict)
    prev_hash         previous line's entry_hash ("0"*64 genesis on line 1)
    entry_hash        SHA-256 of the canonical receipt MINUS entry_hash

Optionally carried (legacy ``log_tool.py`` fields, only when supplied):
``status``, ``note``, ``stdout``, ``stderr``, ``elapsed_s`` (stored as a
fixed-decimal STRING, never a float), and ``error``.

The empty-output trap
---------------------
A tool that legitimately produces NOTHING (e.g. ``mmls`` on a single-volume
E01) writes a zero-byte artifact whose SHA-256 is the empty-string digest
``e3b0c442…`` (:data:`EMPTY_SHA256`). A *failed* run, a *placeholder*, and a
*genuinely-empty real artifact* would otherwise collide on that one digest and
read as "a real artifact". We refuse that collision:

* ``empty_output``  — the artifact EXISTS and is zero bytes →
  ``output_sha256 == EMPTY_SHA256`` is recorded, but the status is NEVER ``ok``.
* ``path_failure``  — the expected artifact is MISSING → ``output_sha256`` is
  recorded as ``null`` (we never hash the empty string in its place).
* ``ok``            — a real, non-empty artifact; ``output_sha256`` is never
  the empty digest.

The invariant (``EMPTY_SHA256`` ⇒ ``empty_output``, and ``ok`` ⇒ not the empty
digest) is enforced at build time and re-checked by :func:`verify_chain`.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

__all__ = [
    "SCHEMA_VERSION",
    "LEGACY_SCHEMA_VERSION",
    "MIGRATION_SCHEMA_VERSION",
    "GENESIS_PREV_HASH",
    "EMPTY_SHA256",
    "DEFAULT_LEDGER_PATH",
    "InvocationStatus",
    "LedgerError",
    "LedgerChainError",
    "canonical_json",
    "canonical_bytes",
    "compute_entry_hash",
    "sha256_file",
    "classify_invocation",
    "build_receipt",
    "Ledger",
    "append_receipt",
    "VerifyResult",
    "verify_chain",
    "assert_chain_ok",
    "backfill_chain",
]

# =============================================================================
# Named constants — shared by the live writer AND the back-fill.
# =============================================================================
#: Schema tag stamped on every live receipt line.
SCHEMA_VERSION = "receipts-v1"
#: Schema tag applied to historical ``tools.jsonl`` lines during back-fill.
LEGACY_SCHEMA_VERSION = "tools-v0"
#: Schema tag for the migration-marker entry written by the back-fill.
MIGRATION_SCHEMA_VERSION = "receipts-migration-v1"

#: The single NAMED genesis sentinel: sixty-four ASCII zeros. ``prev_hash`` of
#: the FIRST entry in any chain (live ledger or back-fill) is exactly this.
#: Used by both :class:`Ledger` and :func:`backfill_chain` so a chain's start
#: is unambiguous and a missing line-1 is detectable.
GENESIS_PREV_HASH = "0" * 64

#: SHA-256 of the empty string — the digest a zero-byte artifact hashes to.
#: ``hashlib.sha256(b"").hexdigest()`` == this literal.
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()  # e3b0c442…7852b855

#: Default location of the live ledger. Overridable via ``LEDGER_PATH`` or the
#: :class:`Ledger` constructor. Lives in the per-case dir (it holds case
#: data / PII) — it is git-ignored and must NEVER be committed.
DEFAULT_LEDGER_PATH = os.path.expanduser("~/josh/cases/Rocba/receipts.jsonl")


class InvocationStatus:
    """The four legal ``invocation_status`` values (see module docstring)."""

    OK = "ok"
    PATH_FAILURE = "path_failure"
    EMPTY_OUTPUT = "empty_output"
    ERROR = "error"

    ALL = ("ok", "path_failure", "empty_output", "error")


class LedgerError(Exception):
    """A receipt could not be built/written because it violates an invariant."""


class LedgerChainError(LedgerError):
    """The chain failed verification — callers must refuse to proceed."""


# =============================================================================
# Canonicalization + hashing — the EXACT, pinned serialization.
# =============================================================================
def canonical_json(obj: Any) -> str:
    """Canonical JSON text for ``obj`` — the only serialization that is hashed.

    Pinned EXACTLY (or hashes will not reproduce): sorted keys (key-order
    independent), compact separators (no whitespace ambiguity), ASCII-only
    (non-ASCII bytes deterministic), and ``allow_nan=False`` (a ``NaN`` /
    ``Infinity`` raises rather than emitting non-standard JSON). Ints stay ints.
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


def compute_entry_hash(entry: dict[str, Any]) -> str:
    """SHA-256 (lowercase hex) of the canonical entry **excluding** ``entry_hash``.

    ``prev_hash`` IS part of the preimage — that is the link that makes
    reordering or deleting a middle entry detectable. ``entry_hash`` is excluded
    from its own input.
    """
    core = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(canonical_bytes(core)).hexdigest()


def _has_float(obj: Any) -> bool:
    """True if ``obj`` contains any ``float`` (recursively).

    ``bool`` is a subclass of ``int`` (not ``float``) and is allowed. Floats are
    rejected in NEWLY-built receipts because their text repr is not guaranteed
    stable across Python/json versions — exactly what would make a hashed ledger
    non-reproducible. (The back-fill does NOT call this: it must hash legacy
    lines verbatim, floats and all, to faithfully cover their real content.)
    """
    if isinstance(obj, float):
        return True
    if isinstance(obj, dict):
        return any(_has_float(v) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return any(_has_float(v) for v in obj)
    return False


def sha256_file(path: str, *, chunk_size: int = 65536) -> tuple[str, int]:
    """Stream ``path`` and return ``(hex_digest, n_bytes)``.

    Streamed in 64 KiB chunks so arbitrarily large artifacts hash in O(1) memory.
    """
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk_size)
            if not block:
                break
            h.update(block)
            n += len(block)
    return h.hexdigest(), n


def _utc_now_z() -> str:
    """Host UTC, ISO-8601, ``Z`` suffix — e.g. ``2026-06-09T01:02:03Z``."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# =============================================================================
# Receipt construction.
# =============================================================================
def classify_invocation(
    *,
    exit_code: int | None,
    errored: bool,
    output_path: str | None,
    output_exists: bool,
    output_bytes: int,
) -> str:
    """Decide ``invocation_status`` so an empty/failed/placeholder run can never
    masquerade as a real artifact.

    Precedence: ``error`` (raised, or non-zero exit) → ``path_failure``
    (expected artifact missing) → ``empty_output`` (artifact exists, zero bytes)
    → ``ok`` (everything else, incl. a real non-empty artifact or a stdout-only
    tool with no ``output_path``).
    """
    if errored or (exit_code is not None and exit_code != 0):
        return InvocationStatus.ERROR
    if output_path is not None and not output_exists:
        return InvocationStatus.PATH_FAILURE
    if output_path is not None and output_bytes == 0:
        return InvocationStatus.EMPTY_OUTPUT
    return InvocationStatus.OK


def _tokens_from_telemetry(tool: str, exit_code: int | None) -> dict[str, Any]:
    """Issuing-agent-turn tokens via :func:`sift_agent.telemetry.stamp_receipt`.

    Reuses the telemetry stamp helper so a tool row records the SAME labelled
    shape the telemetry ledger uses (``source="issuing_agent_turn"`` + the
    no-fabrication note) and is also reflected on the telemetry ledger. The
    import is lazy and tolerant: if ``telemetry`` (and its ``na0s`` dependency)
    is unavailable, we record an explicit ``unavailable`` marker rather than
    fabricating a count.
    """
    try:
        from sift_agent import telemetry
    except Exception as exc:  # noqa: BLE001 — degrade honestly, never fabricate
        return {
            "source": "unavailable",
            "agent_turn_id": None,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "note": f"telemetry unavailable ({exc!r}); no LLM token attribution",
        }
    stamped = telemetry.stamp_receipt({"tool": tool, "exit_code": exit_code})
    return stamped["tokens"]


def build_receipt(
    *,
    agent: str,
    tool: str,
    args: Any,
    evidence_ref: str | None = None,
    output_path: str | None = None,
    exit_code: int | None = None,
    errored: bool = False,
    error: str | None = None,
    tokens: dict[str, Any] | None = None,
    ts: str | None = None,
    receipt_id: str | None = None,
    # carried legacy log_tool.py fields (optional) ---------------------------
    status: str | None = None,
    note: str | None = None,
    stdout: str | None = None,
    stderr: str | None = None,
    elapsed_s: Any | None = None,
) -> dict[str, Any]:
    """Build ONE receipt dict — WITHOUT ``prev_hash``/``entry_hash``.

    Chaining (``prev_hash`` from the tail, then ``entry_hash``) is applied by
    :meth:`Ledger._chain_and_write` under the file lock, so a receipt's link is
    always computed against the true current tail. The output artifact at
    ``output_path`` (if given and present) is streamed once for its SHA-256 and
    byte count here. Raises :class:`LedgerError` if the result would carry a
    float or violate the empty-output invariant.
    """
    output_sha256: str | None = None
    output_bytes: int | None = None
    output_exists = False
    if output_path is not None and os.path.isfile(output_path):
        try:
            output_sha256, output_bytes = sha256_file(output_path)
            output_exists = True
        except OSError:
            # TOCTOU: the artifact vanished/became unreadable between the
            # isfile() check and the open() (e.g. evidence unmounted mid-run).
            # Fall through as "not present" → classify_invocation records a
            # path_failure with a null digest. Degrade honestly, never crash,
            # never fabricate. NOTE: ``output_path`` is trusted operator/agent
            # input; isfile()/open() follow symlinks, so a symlinked artifact is
            # hashed at its target. Callers handling untrusted paths should
            # resolve + validate against an evidence root before passing them.
            output_exists = False
            output_sha256, output_bytes = None, None

    inv = classify_invocation(
        exit_code=exit_code,
        errored=errored or error is not None,
        output_path=output_path,
        output_exists=output_exists,
        output_bytes=output_bytes if output_bytes is not None else 0,
    )

    # A missing expected artifact records a NULL digest — never the empty-string
    # digest — so it cannot be confused with a genuinely-empty real artifact.
    if inv == InvocationStatus.PATH_FAILURE:
        output_sha256 = None
        output_bytes = None

    if tokens is None:
        tokens = _tokens_from_telemetry(tool, exit_code)

    receipt: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "receipt_id": receipt_id or str(uuid.uuid4()),
        "ts": ts or _utc_now_z(),
        "agent": agent,
        "tool": tool,
        "args": args,
        "evidence_ref": evidence_ref,
        "output_path": output_path,
        "output_sha256": output_sha256,
        "output_bytes": output_bytes,
        "invocation_status": inv,
        "exit_code": exit_code,
        "tokens": tokens,
    }

    # Carry legacy fields only when supplied. elapsed_s is coerced to a
    # fixed-decimal STRING (never a float) to keep the receipt hash-stable.
    if status is not None:
        receipt["status"] = status
    if note is not None:
        receipt["note"] = note
    if stdout is not None:
        receipt["stdout"] = stdout
    if stderr is not None:
        receipt["stderr"] = stderr
    if elapsed_s is not None:
        receipt["elapsed_s"] = (
            elapsed_s if isinstance(elapsed_s, str) else f"{float(elapsed_s):.3f}"
        )
    if error is not None:
        receipt["error"] = error

    _assert_receipt_invariants(receipt)
    return receipt


def _assert_receipt_invariants(receipt: dict[str, Any]) -> None:
    """Fail-fast guards for a NEW receipt (raise :class:`LedgerError`)."""
    if _has_float(receipt):
        raise LedgerError(
            "receipt contains a float; cost/confidence/elapsed must be "
            "fixed-decimal strings and counts must be ints (hash stability)"
        )
    inv = receipt.get("invocation_status")
    if inv not in InvocationStatus.ALL:
        raise LedgerError(f"illegal invocation_status {inv!r}")
    osha = receipt.get("output_sha256")
    # The empty-string digest may ONLY appear on an explicitly-empty artifact.
    if osha == EMPTY_SHA256 and inv != InvocationStatus.EMPTY_OUTPUT:
        raise LedgerError(
            "output_sha256 is the empty-string digest but invocation_status is "
            f"{inv!r}; an empty/failed/placeholder run must not look like a real artifact"
        )
    # An "ok" artifact is real and non-empty.
    if inv == InvocationStatus.OK and osha == EMPTY_SHA256:
        raise LedgerError("invocation_status=ok cannot carry the empty-string digest")


# =============================================================================
# The writer — atomic, flock-serialized, tail-read INSIDE the lock.
# =============================================================================
def _read_tail_entry_hash(path: str) -> str:
    """Return the last complete line's ``entry_hash``, else :data:`GENESIS_PREV_HASH`.

    Reads BACKWARD from EOF so it is O(line length), not O(file size). A trailing
    partial line (no terminating newline — a torn write) is ignored; only a
    fully newline-terminated line is considered. MUST be called while holding the
    exclusive lock (the writer does), so the tail it reads is the true tail.
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
        return GENESIS_PREV_HASH  # no complete line at all
    # Everything after the last newline is a trailing partial → ignore it.
    prev_nl = buf.rfind(b"\n", 0, last_nl)
    line = buf[prev_nl + 1 : last_nl]
    if not line.strip():
        return GENESIS_PREV_HASH
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return GENESIS_PREV_HASH
    h = obj.get("entry_hash") if isinstance(obj, dict) else None
    return h if isinstance(h, str) else GENESIS_PREV_HASH


class Ledger:
    """Append-only writer for ``receipts.jsonl`` — concurrency- and crash-safe.

    Each :meth:`append` takes ``flock(LOCK_EX)``, reads the chain tip *inside*
    the lock, builds + links the receipt, writes the whole ``line + "\\n"`` in a
    single ``os.write`` to an ``O_APPEND`` fd, ``fsync``s, and releases. Holding
    the exclusive lock across read-tip → append serializes concurrent writers so
    they cannot compute the same ``prev_hash`` and fork the chain.

    ``flock`` is advisory and per-host; it does not protect against writers on a
    different NFS client. For local-filesystem multi-process/-thread agents (our
    case) it is sufficient.
    """

    def __init__(self, path: str | None = None) -> None:
        self.path = path or os.environ.get("LEDGER_PATH") or DEFAULT_LEDGER_PATH

    def append(self, **receipt_kwargs: Any) -> dict[str, Any]:
        """Build (via :func:`build_receipt`), chain, and durably append a receipt."""
        receipt = build_receipt(**receipt_kwargs)
        return self._chain_and_write(receipt)

    def append_prebuilt(self, receipt: dict[str, Any]) -> dict[str, Any]:
        """Chain + append an already-built receipt dict (its ``prev_hash`` /
        ``entry_hash`` are (re)computed under the lock).

        The empty-SHA-trap / no-float invariants are enforced here too, so this
        path cannot smuggle a malformed receipt past the guards that
        :func:`build_receipt` applies to :meth:`append`.
        """
        return self._chain_and_write(dict(receipt))

    def _chain_and_write(self, receipt: dict[str, Any]) -> dict[str, Any]:
        parent = os.path.dirname(self.path)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)

        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            # --- tail-read MUST be inside the lock ---
            prev_hash = _read_tail_entry_hash(self.path)
            receipt.pop("entry_hash", None)
            receipt["prev_hash"] = prev_hash
            # Enforce invariants on BOTH write paths (append + append_prebuilt),
            # not just inside build_receipt — write-time prevention is the first
            # line of defence against an empty-digest collision reaching disk.
            _assert_receipt_invariants(receipt)
            receipt["entry_hash"] = compute_entry_hash(receipt)
            line = (canonical_json(receipt) + "\n").encode("utf-8")
            os.write(fd, line)  # O_APPEND → single atomic write at EOF
            os.fsync(fd)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        return receipt


def append_receipt(path: str | None = None, **receipt_kwargs: Any) -> dict[str, Any]:
    """Convenience: append one receipt to the ledger at ``path`` (or the default)."""
    return Ledger(path).append(**receipt_kwargs)


# =============================================================================
# Verification — run AT STARTUP and on demand. Fail closed on a mid-file break.
# =============================================================================
@dataclass
class VerifyResult:
    """Outcome of :func:`verify_chain`.

    ``ok`` is the single go/no-go. ``chain_ok`` is specifically the hash-link
    integrity; ``broken_at`` pinpoints the FIRST mid-file break (line + byte
    offset) past which nothing is trusted. Output-artifact and duplicate-id
    findings are reported separately but also drive ``ok``.
    """

    path: str
    ok: bool = False
    chain_ok: bool = False
    n_entries: int = 0
    genesis_ok: bool = False
    trailing_partial: bool = False
    trailing_partial_offset: int | None = None
    broken_at: dict[str, Any] | None = None
    blank_lines_skipped: int = 0
    duplicate_receipt_ids: list[dict[str, Any]] = field(default_factory=list)
    output_checks: list[dict[str, Any]] = field(default_factory=list)
    collision_flags: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def _fail(self, line: int, offset: int, reason: str) -> None:
        self.chain_ok = False
        self.ok = False
        self.broken_at = {"line": line, "byte_offset": offset, "reason": reason}
        self.errors.append(f"line {line} (byte {offset}): {reason}")

    @property
    def output_mismatches(self) -> list[dict[str, Any]]:
        return [c for c in self.output_checks if c["status"] == "mismatch"]

    @property
    def output_missing(self) -> list[dict[str, Any]]:
        return [c for c in self.output_checks if c["status"] == "missing"]

    def summary(self) -> str:
        lines = [
            f"ledger: {self.path}",
            f"result: {'OK' if self.ok else 'FAILED'}  "
            f"(chain_ok={self.chain_ok}, entries={self.n_entries}, "
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
        for d in self.duplicate_receipt_ids:
            lines.append(f"DUPLICATE receipt_id {d['receipt_id']} on lines {d['lines']}")
        for c in self.output_mismatches:
            lines.append(
                f"OUTPUT MISMATCH line {c['line']}: {c['output_path']} "
                f"recorded={c['recorded']} actual={c['actual']}"
            )
        for c in self.output_missing:
            lines.append(f"output missing line {c['line']}: {c['output_path']}")
        for cf in self.collision_flags:
            lines.append(
                f"EMPTY-DIGEST COLLISION line {cf['line']}: status={cf['invocation_status']} "
                "carries the empty-string digest but is not tagged empty_output"
            )
        return "\n".join(lines)

    def raise_if_broken(self) -> "VerifyResult":
        if not self.ok:
            raise LedgerChainError(self.summary())
        return self


def verify_chain(
    path: str | None = None,
    *,
    check_outputs: bool = True,
    outputs_strict: bool = False,
) -> VerifyResult:
    """Walk the chain and report integrity. Fail closed on any mid-file break.

    Checks, in order, per entry:

    1. the line parses as a JSON object and carries a string ``entry_hash``;
    2. ``entry_hash`` recomputes from the canonical entry (minus ``entry_hash``);
    3. ``prev_hash`` equals the previous entry's ``entry_hash`` — and line 1's
       ``prev_hash`` equals :data:`GENESIS_PREV_HASH`;
    4. ``receipt_id`` is not a duplicate of an earlier line;
    5. the empty-digest invariant holds (``EMPTY_SHA256`` ⇒ ``empty_output``);
    6. (if ``check_outputs``) the artifact at ``output_path`` still hashes to the
       recorded ``output_sha256`` (streamed).

    A partial/malformed TRAILING line (no terminating newline — a torn final
    write) is tolerated and ignored, as is a blank/whitespace-only line (the
    writer never emits one, and a blank line carries no hash so it cannot mask a
    deletion — that still breaks the ``prev_hash`` link). ANY break in a
    fully-written (newline-terminated) entry line is fatal: verification stops at
    that line, records the exact line number + byte offset, and never splices
    past the gap. ``ok`` is also ``False`` on a duplicate ``receipt_id``, an
    output mismatch, an empty-digest collision, or (only when ``outputs_strict``)
    a missing output file.

    The file is streamed line-by-line (O(line length) memory), so an
    arbitrarily large ledger verifies without being loaded whole into RAM.
    """
    path = path or os.environ.get("LEDGER_PATH") or DEFAULT_LEDGER_PATH
    result = VerifyResult(path=path)

    try:
        f = open(path, "rb")
    except FileNotFoundError:
        # No ledger yet — vacuously valid (a fresh agent has written nothing).
        result.ok = True
        result.chain_ok = True
        result.genesis_ok = True
        result.errors.append("ledger file does not exist yet (0 entries)")
        return result
    except OSError as exc:
        # A directory, an unreadable path, etc. — report, do not crash.
        result.ok = False
        result.errors.append(f"cannot open ledger: {exc}")
        return result

    prev_entry_hash = GENESIS_PREV_HASH
    seen_ids: dict[Any, int] = {}
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
                # Final line lacks its terminating newline → a torn final write.
                # Our writer always writes "<json>\n" in one atomic os.write, so
                # absence of the newline means an incomplete record → ignore it.
                result.trailing_partial = True
                result.trailing_partial_offset = off
                break
            lineno += 1
            raw = raw_line[:-1]  # strip the trailing newline

            if not raw.strip():
                # Blank/whitespace-only line: the writer never emits one and it
                # carries no hash, so skip it (the chain links across it) rather
                # than failing — mirrors the writer's tail-read leniency.
                result.blank_lines_skipped += 1
                result.errors.append(f"line {lineno} (byte {off}): blank line skipped")
                continue

            try:
                entry = json.loads(raw)
            except (json.JSONDecodeError, ValueError) as exc:
                result._fail(lineno, off, f"malformed JSON: {exc}")
                return result
            if not isinstance(entry, dict):
                result._fail(lineno, off, "entry is not a JSON object")
                return result

            stored = entry.get("entry_hash")
            if not isinstance(stored, str):
                result._fail(lineno, off, "missing or non-string entry_hash")
                return result

            recomputed = compute_entry_hash(entry)
            if recomputed != stored:
                result._fail(
                    lineno, off,
                    f"entry_hash mismatch (stored {stored}, recomputed {recomputed})",
                )
                return result

            is_first_entry = result.n_entries == 0
            prev = entry.get("prev_hash")
            if prev != prev_entry_hash:
                if is_first_entry:
                    result._fail(
                        lineno, off,
                        f"genesis prev_hash mismatch (expected {GENESIS_PREV_HASH}, got {prev})",
                    )
                else:
                    result._fail(
                        lineno, off,
                        f"prev_hash link broken (expected {prev_entry_hash}, got {prev})",
                    )
                return result
            if is_first_entry:
                result.genesis_ok = True

            # Flag only collisions of a PRESENT id. A missing/null receipt_id
            # (e.g. back-filled legacy "tools-v0" lines, which we never fabricate
            # an id for) is not a "duplicate id" and must not be flagged.
            rid = entry.get("receipt_id")
            if rid is not None:
                if rid in seen_ids:
                    result.duplicate_receipt_ids.append(
                        {"receipt_id": rid, "lines": [seen_ids[rid], lineno]}
                    )
                else:
                    seen_ids[rid] = lineno

            # Empty-digest collision: a real-looking digest that is actually empty.
            osha = entry.get("output_sha256")
            inv = entry.get("invocation_status")
            if osha == EMPTY_SHA256 and inv != InvocationStatus.EMPTY_OUTPUT:
                result.collision_flags.append(
                    {"line": lineno, "receipt_id": rid, "invocation_status": inv}
                )

            if check_outputs:
                result.output_checks.append(_check_output_artifact(lineno, entry))

            prev_entry_hash = stored
            result.n_entries += 1

    # Reached the end with no mid-file break.
    result.chain_ok = True
    if result.n_entries == 0:
        result.genesis_ok = True

    result.ok = (
        result.chain_ok
        and not result.duplicate_receipt_ids
        and not result.output_mismatches
        and not result.collision_flags
        and (not outputs_strict or not result.output_missing)
    )
    return result


def _check_output_artifact(line: int, entry: dict[str, Any]) -> dict[str, Any]:
    """Re-hash an entry's output artifact and classify the result."""
    osha = entry.get("output_sha256")
    opath = entry.get("output_path")
    base = {"line": line, "output_path": opath, "recorded": osha}
    if osha is None or opath is None:
        return {**base, "status": "skipped"}
    if not os.path.isfile(opath):
        return {**base, "status": "missing", "actual": None}
    actual, _ = sha256_file(opath)
    if actual == osha:
        return {**base, "status": "empty_ok" if osha == EMPTY_SHA256 else "matched",
                "actual": actual}
    return {**base, "status": "mismatch", "actual": actual}


def assert_chain_ok(path: str | None = None, **kwargs: Any) -> VerifyResult:
    """Verify and RAISE :class:`LedgerChainError` if the chain is not OK.

    Call this at agent startup: on a broken chain the agent must alert and refuse
    to proceed rather than appending onto an untrusted ledger.
    """
    return verify_chain(path, **kwargs).raise_if_broken()


# =============================================================================
# Back-fill — chain historical tools.jsonl onto a COPY; original never touched.
# =============================================================================
def backfill_chain(
    src_path: str,
    dst_path: str,
    *,
    agent: str = "ledger-backfill",
    migrated_at: str | None = None,
    expected_source_sha256: str | None = None,
) -> dict[str, Any]:
    """Hash-chain the historical ``tools.jsonl`` at ``src_path`` into ``dst_path``.

    The original is opened **read-only** and never modified. Each legacy line is
    parsed, tagged ``schema_version="tools-v0"`` (force-set, so every legacy line
    is unambiguously marked), and chained verbatim — its real original fields are
    hashed as-is (floats and all), and genuinely-missing target fields
    (``agent``/``evidence_ref``/``output_*``/``tokens``) are left ABSENT, never
    fabricated. A migration-marker entry is appended as the chain TIP, itself
    chained, recording the source path + its SHA-256 + line count so the
    migration's provenance is bound into the chain.

    Source and destination are both streamed (bounded memory): the source is
    hashed in a first read-only pass so the custody check can abort BEFORE
    anything is written, then re-read line-by-line while chained entries are
    streamed straight to a temp file that is atomically ``os.replace``-d over the
    destination. Line 1's ``prev_hash`` is :data:`GENESIS_PREV_HASH`; every
    subsequent entry (including the marker) links to its predecessor. Returns a
    small summary dict. Raises :class:`LedgerError` if ``expected_source_sha256``
    is given and does not match the source, or if a legacy line is not a JSON
    object — in either case nothing is written.
    """
    # --- Pass 1 (read-only, streamed): hash the source for the custody gate. ---
    src_sha, src_bytes = sha256_file(src_path)
    if expected_source_sha256 is not None and expected_source_sha256 != src_sha:
        raise LedgerError(
            f"source sha256 {src_sha} != expected {expected_source_sha256}; "
            "refusing to back-fill a source that does not match its baseline"
        )

    parent = os.path.dirname(dst_path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)

    # --- Pass 2 (read-only, streamed): parse → tag → chain → stream-write. ---
    tmp = f"{dst_path}.tmp.{os.getpid()}"
    prev = GENESIS_PREV_HASH
    legacy_count = 0
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with open(src_path, "rb") as f:  # READ-ONLY
            idx = 0
            for raw_line in f:
                if not raw_line.strip():
                    continue  # blank/whitespace line in source → not an entry
                idx += 1
                try:
                    obj = json.loads(raw_line)
                except (json.JSONDecodeError, ValueError) as exc:
                    raise LedgerError(f"legacy line {idx} malformed JSON: {exc}")
                if not isinstance(obj, dict):
                    raise LedgerError(f"legacy line {idx} is not a JSON object")
                obj = dict(obj)
                # Force-tag the schema so EVERY legacy line is unambiguously
                # "tools-v0" (real tools.jsonl lines carry no schema_version; a
                # poisoned one with a different tag must not pass through). Do
                # NOT invent target fields that were never recorded.
                obj["schema_version"] = LEGACY_SCHEMA_VERSION
                obj["prev_hash"] = prev
                obj["entry_hash"] = compute_entry_hash(obj)
                prev = obj["entry_hash"]
                legacy_count += 1
                os.write(fd, (canonical_json(obj) + "\n").encode("utf-8"))

        marker: dict[str, Any] = {
            "schema_version": MIGRATION_SCHEMA_VERSION,
            "kind": "migration_marker",
            "receipt_id": str(uuid.uuid4()),
            "ts": migrated_at or _utc_now_z(),
            "agent": agent,
            "source_path": os.path.abspath(src_path),
            "source_sha256": src_sha,
            "source_bytes": src_bytes,
            "legacy_schema": LEGACY_SCHEMA_VERSION,
            "legacy_line_count": legacy_count,
            "genesis_prev_hash": GENESIS_PREV_HASH,
            "note": (
                "back-fill chain over historical tools.jsonl; original opened "
                "read-only and never modified; missing target fields left absent, "
                "not fabricated; legacy lines hashed verbatim incl. original numbers"
            ),
            "prev_hash": prev,
        }
        marker["entry_hash"] = compute_entry_hash(marker)
        os.write(fd, (canonical_json(marker) + "\n").encode("utf-8"))
        os.fsync(fd)
    except BaseException:
        # Never leave a partial chain in place on any failure.
        os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    else:
        os.close(fd)
    os.replace(tmp, dst_path)  # atomic publish

    return {
        "dst_path": dst_path,
        "source_path": os.path.abspath(src_path),
        "source_sha256": src_sha,
        "source_bytes": src_bytes,
        "legacy_line_count": legacy_count,
        "n_entries": legacy_count + 1,
        "tip_entry_hash": marker["entry_hash"],
        "marker_receipt_id": marker["receipt_id"],
    }

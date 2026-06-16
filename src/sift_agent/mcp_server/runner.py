"""The ONE vetted read-only subprocess chokepoint for the SIFT MCP server.

WHY THIS FILE IS SPECIAL (read this before touching it)
-------------------------------------------------------
The rest of :mod:`sift_agent.mcp_server` is *capability-free*: it imports no
``subprocess`` / ``os.system`` / ``pty`` / ``eval`` and therefore cannot spawn a
process at all. That is the architectural guardrail that makes evidence mutation
impossible by construction (see :mod:`sift_agent.mcp_server.registry`).

Real forensic work, though, means *running real tools* — ``vol``, ``fls``,
``MFTECmd`` … . This module is the single, deliberate exception: it is the **only
file in the entire codebase permitted to call a subprocess**. The AST guard in
``tests/test_mcp_server.py`` enforces exactly that — ``subprocess`` / ``os.system``
/ ``os.popen`` may appear ONLY here, and even *here* ``shell=True`` /
``os.system`` / ``os.popen`` / ``eval`` / ``exec`` are forbidden. The guardrail
therefore shrank from "no subprocess anywhere" to "subprocess reachable only via
``runner.py``, and only without a shell" — a single auditable chokepoint instead
of a scatter of ``subprocess`` calls.

How it stays safe (no shell is reachable, ever)
-----------------------------------------------
1. Closed binary whitelist — :data:`BINARY_WHITELIST` maps a ``tool_key`` to a
   **server-controlled launcher prefix of absolute paths** resolved at import
   time (via ``shutil.which`` / ``os.path.realpath`` — never a subprocess). A
   caller picks a ``tool_key``; it can never supply a path, an interpreter, or a
   raw command string. A ``tool_key`` not in the map is refused before anything
   runs.
2. argv LIST, never a string — :func:`run_tool` builds ``[*prefix, *args]`` and
   hands that LIST to :func:`subprocess.run` with ``shell=False``. There is no
   shell to interpret metacharacters, no ``>``/``|`` redirection, no command
   string. A caller's argument is always one literal ``argv`` element.
3. Bounded + audited — every call runs with a timeout, ``capture_output=True``,
   and is stamped into the forensic ledger via
   :func:`sift_agent.telemetry.stamp_receipt` (UTC ts + the issuing turn's
   tokens), so even a tool that errors leaves a provenance row.

The agent-facing verb: capture + hash-chained receipt + capped return
---------------------------------------------------------------------
:func:`run_tool` is the low-level chokepoint. The verb a typed MCP wrapper (and
the agent behind it) actually uses is :func:`run_tool_captured`, which wraps the
chokepoint with the data-spine receipt contract:

* the FULL raw stdout is captured to a file under a designated scratch dir
  (never evidence — :func:`_refuse_evidence_path` rejects ``/cases``, ``/mnt``,
  ``/media`` and any ``evidence/`` directory) and hashed (SHA-256);
* ONE hash-chained, append-only receipt line (``receipts-v1``: receipt_id, UTC
  ``ts``, agent, tool, args, evidence_ref, output_path, output_sha256,
  output_bytes, invocation_status, exit_code, tokens, prev_hash, entry_hash) is
  written via a thin :class:`ReceiptWriter` seam — for EVERY call, including
  refused and failed ones;
* the caller gets back capped, structured rows (≤ :data:`MAX_RETURN_ROWS`,
  mirroring ``query_store``'s ≤50-row discipline) plus the ``receipt_id`` —
  never the raw dump, so a tool cannot blow the model's context window.

Because the runner must write capture files and receipt lines, this module is
also the ONLY file in the package permitted to open a file for writing — the
same AST guard that pins ``subprocess`` here pins write-mode ``open()`` here.
Everything else in the package stays read-only by construction.

.. note:: **Branch-reconciliation seam (do not fork the ledger).** The canonical
   hash-chained ledger (``sift_agent.ledger`` — ``build_receipt`` /
   ``Ledger.append`` / ``verify_chain``, plus the SQLite store) lives on the
   ``feat/sqlite-store`` / ``feat/query-store`` branches. This module therefore
   defines only a thin :class:`ReceiptWriter` interface and a deliberately
   minimal :class:`JsonlReceiptWriter` whose line format, canonical JSON
   serialization, hashing preimage, and field names are IDENTICAL to
   ``ledger.py``'s ``receipts-v1`` contract (same ``canonical_json``, same
   ``entry_hash``-excludes-itself rule, same ``GENESIS_PREV_HASH``, same
   empty-output trap). TODO(branch-reconciliation): when the branches merge,
   delete :class:`JsonlReceiptWriter` / :func:`verify_receipts` /
   ``_canonical_json`` / ``_compute_entry_hash`` here and inject an adapter
   over ``sift_agent.ledger.Ledger`` as the :class:`ReceiptWriter`; the AST
   guard's write-open allowance then extends to ``ledger.py`` (or receipt
   writes stay routed through this module — decide at merge).

Adding a tool = add a read-only forensic binary to :data:`_RECIPES`. Adding an
*execution path* is impossible without editing this file, which the guard makes
loud.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import types
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, Sequence

from sift_agent import telemetry

__all__ = [
    "BINARY_WHITELIST",
    "WHITELISTED_TOOLS",
    "DEFAULT_TIMEOUT",
    "MAX_RETURN_ROWS",
    "RECEIPTS_SCHEMA_VERSION",
    "GENESIS_PREV_HASH",
    "EMPTY_SHA256",
    "ResolvedTool",
    "ToolResult",
    "CappedToolResult",
    "RunnerError",
    "ToolNotAllowed",
    "ToolUnavailable",
    "ToolArgumentError",
    "ToolTimeout",
    "CapturePathError",
    "ReceiptWriter",
    "JsonlReceiptWriter",
    "run_tool",
    "run_tool_captured",
    "verify_receipts",
    "scratch_output_dir",
    "inventory",
    "tool_version",
    "capture_versions",
]

# Default wall-clock ceiling for a single tool run. Forensic parses (a full $MFT,
# a memory plugin) can be slow, so the default is generous but finite — a hung
# tool can never block the agent forever. Overridable per call and via env.
DEFAULT_TIMEOUT = float(os.getenv("SIFT_RUNNER_TIMEOUT", "300"))

# Hard ceiling on the rows a captured run returns to the model — the same ≤50
# discipline as ``query_store``'s MAX_LIMIT (feat/query-store). The FULL output
# always lands in the capture file; only the model-facing slice is capped.
MAX_RETURN_ROWS = 50

# ---- receipts-v1 contract constants (MUST match sift_agent.ledger) ----------
#: Schema tag stamped on every receipt line (same literal as ledger.py).
RECEIPTS_SCHEMA_VERSION = "receipts-v1"
#: ``prev_hash`` of the first entry in any chain: sixty-four ASCII zeros.
GENESIS_PREV_HASH = "0" * 64
#: SHA-256 of the empty string — what a zero-byte capture hashes to. A receipt
#: carrying it may NEVER claim ``invocation_status="ok"`` (the empty-output trap).
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

# Where full tool output is captured. ONLY scratch/analysis space is legal —
# never evidence (see _refuse_evidence_path). Overridable per call and via env.
DEFAULT_CAPTURE_DIR = os.getenv("SIFT_CAPTURE_DIR", "./analysis/captures")

# Evidence roots that the capture/receipt writer must refuse outright, plus the
# directory-segment name that marks an evidence tree wherever it sits. Mirrors
# the chain-of-custody rule in CLAUDE.md ("never modify /cases/, /mnt/, /media/,
# or any evidence/ directory").
_EVIDENCE_PATH_PREFIXES = ("/cases", "/mnt", "/media")
_EVIDENCE_SEGMENT = "evidence"


# -----------------------------------------------------------------------------
# Errors. Distinct types so a caller can tell "you asked for a tool that is not
# on the whitelist" (a guardrail refusal) apart from "the tool ran and failed".
# -----------------------------------------------------------------------------
class RunnerError(Exception):
    """Base class for every error raised by the read-only runner."""


class ToolNotAllowed(RunnerError):
    """Raised when ``tool_key`` is not in the closed :data:`BINARY_WHITELIST`.

    This is what stops an attempt to run an arbitrary binary: only vetted
    read-only forensic tool keys exist, and a key outside that set is refused
    before any process is spawned.
    """


class ToolUnavailable(RunnerError):
    """Raised when a whitelisted tool did not resolve to a binary on this box."""


class ToolArgumentError(RunnerError):
    """Raised when ``args`` is not a list of clean strings.

    Guards the argv contract: a raw command *string* (``"fls -r image.E01"``) is
    rejected so a caller can never smuggle in something shell-shaped; each arg
    must be a ``str`` with no NUL byte and becomes exactly one ``argv`` element.
    """


class ToolTimeout(RunnerError):
    """Raised when a tool exceeds its timeout (the process is killed first)."""


class CapturePathError(RunnerError):
    """Raised when a capture/receipt path points into an evidence directory.

    The runner writes ONLY to designated scratch space. A capture dir or
    receipts file under ``/cases``, ``/mnt``, ``/media`` or any ``evidence/``
    directory is refused before anything is opened — spoliation through the
    capture path is impossible by construction, not by policy.
    """


# -----------------------------------------------------------------------------
# Whitelist data model.
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class ResolvedTool:
    """A whitelisted tool resolved (or not) to an absolute launcher prefix.

    Attributes
    ----------
    tool_key:     Stable id a caller passes to :func:`run_tool`.
    prefix:       Server-controlled argv prefix of absolute paths
                  (``("/usr/bin/fls",)`` or ``("/usr/bin/dotnet", ".../MFTECmd.dll")``).
                  Empty when the tool did not resolve.
    available:    ``True`` iff every element of the launcher resolved on this box.
    reason:       ``"ok"`` or a human-readable reason the tool is unavailable.
    version_args: argv used by :func:`tool_version` to probe the tool's version.
    description:  One-liner (what the tool reads / does).
    """

    tool_key: str
    prefix: tuple[str, ...]
    available: bool
    reason: str
    version_args: tuple[str, ...]
    description: str


@dataclass(frozen=True)
class ToolResult:
    """The captured outcome of one :func:`run_tool` call."""

    tool_key: str
    argv: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float


# -----------------------------------------------------------------------------
# The closed set of read-only forensic tools we are willing to launch.
#
# Each recipe says HOW to resolve a launcher prefix using only filesystem checks
# (no subprocess): a native PATH binary, a .NET dll run via ``dotnet``, or a
# Python script run via a pinned interpreter. Only binaries on the Day-2 roadmap
# that genuinely read evidence are listed; every one was confirmed present on the
# SIFT box before being added here.
#
# Recipe shape: (interpreter, target, version_args, description)
#   interpreter=None  -> ``target`` is a native binary (PATH name or absolute).
#   interpreter set   -> launcher is [resolve(interpreter), <abs target>], e.g.
#                        dotnet <dll>  or  <venv python> <script.py>.
# -----------------------------------------------------------------------------
_EZ = "/opt/zimmermantools"

_RECIPES: dict[str, tuple[str | None, str, tuple[str, ...], str]] = {
    # --- Volatility 3 (memory) ---------------------------------------------
    # frameworkinfo needs no image and is the only invocation whose stdout
    # carries the "Volatility 3 Framework x.y.z" banner (--help has no version).
    "vol": (None, "vol", ("frameworkinfo",), "Volatility 3 — memory image analysis (read-only)."),
    # --- The Sleuth Kit (disk / file system) -------------------------------
    "fls": (None, "fls", ("-V",), "Sleuth Kit fls — list file names from a disk image (read-only)."),
    # --- libesedb (ESE / EDB databases: SRUM, Windows.edb, NTDS) -----------
    "esedbexport": (None, "esedbexport", ("-V",),
                    "esedbexport — extract tables from ESE/EDB databases (read-only)."),
    # --- USN journal parser (Python) ---------------------------------------
    "usn.py": ("/opt/usnparser/bin/python3", "/opt/usnparser/bin/usn.py", ("--version",),
               "usnparser usn.py — parse the NTFS $UsnJrnl change journal (read-only)."),
    # --- Eric Zimmerman .NET tools (run via dotnet) ------------------------
    "MFTECmd": ("dotnet", f"{_EZ}/MFTECmd.dll", ("--help",),
                "MFTECmd — parse $MFT / $J / $Boot / $SDS NTFS metadata (read-only)."),
    "EvtxECmd": ("dotnet", f"{_EZ}/EvtxeCmd/EvtxECmd.dll", ("--help",),
                 "EvtxECmd — parse Windows .evtx event logs (read-only)."),
    # RECmd is System.CommandLine-based: --help omits the version; --version
    # prints it bare ("2026.5.0+<sha>").
    "RECmd": ("dotnet", f"{_EZ}/RECmd/RECmd.dll", ("--version",),
              "RECmd — query Windows registry hives in bulk (read-only)."),
    "LECmd": ("dotnet", f"{_EZ}/LECmd.dll", ("--help",),
              "LECmd — parse .lnk shortcut files (read-only)."),
    "JLECmd": ("dotnet", f"{_EZ}/JLECmd.dll", ("--help",),
               "JLECmd — parse Jump Lists (read-only)."),
    "SBECmd": ("dotnet", f"{_EZ}/SBECmd.dll", ("--help",),
               "SBECmd — parse ShellBags from registry hives (read-only)."),
    "RBCmd": ("dotnet", f"{_EZ}/RBCmd.dll", ("--help",),
              "RBCmd — parse $Recycle.Bin $I records (read-only)."),
    "SQLECmd": ("dotnet", f"{_EZ}/SQLECmd/SQLECmd.dll", ("--help",),
                "SQLECmd — run vetted queries against SQLite databases (read-only)."),
}

# Per-tool flags whose VALUE names an output file/dir the tool itself will
# WRITE. The chokepoint refuses any such value that resolves into an evidence
# root — so even a whitelisted read-only PARSER cannot be aimed to write its
# report into /cases//mnt//media/ or an evidence/ tree via its own output
# options. This closes the "redirect the tool's output onto the evidence" hole
# that the binary whitelist alone cannot see; the OS-level ro evidence mounts
# remain the backstop. Values may follow the flag as the next argv element or
# be '='-joined. A typed wrapper should source these values from
# :func:`scratch_output_dir`; this guard catches everything else.
_OUTPUT_PATH_FLAGS: dict[str, tuple[str, ...]] = {
    "vol": ("-o", "--output-dir"),
    "esedbexport": ("-t", "-l"),
    "usn.py": ("-o", "--outfile"),
    "MFTECmd": ("--csv", "--csvf", "--json", "--jsonf", "--body", "--bodyf", "--dd"),
    "EvtxECmd": ("--csv", "--csvf", "--json", "--jsonf", "--xml", "--xmlf"),
    "RECmd": ("--csv", "--csvf", "--json", "--jsonf"),
    "LECmd": ("--csv", "--csvf", "--json", "--jsonf", "--xml", "--html"),
    "JLECmd": ("--csv", "--csvf", "--json", "--jsonf", "--xml", "--html"),
    "SBECmd": ("--csv", "--csvf", "--json", "--jsonf"),
    "RBCmd": ("--csv", "--csvf"),
    "SQLECmd": ("--csv", "--csvf", "--json", "--jsonf"),
    # fls writes only to stdout — no output flag to police.
}


def _check_output_redirection(tool_key: str, args: Sequence[str]) -> None:
    """Refuse output-flag values that resolve into evidence.

    Raises :class:`CapturePathError` BEFORE any process is spawned. Only string
    elements are inspected — non-strings are rejected later by
    :func:`_build_argv` with a more precise error.
    """
    flags = _OUTPUT_PATH_FLAGS.get(tool_key, ())
    if not flags:
        return
    items = list(args)
    for i, a in enumerate(items):
        if not isinstance(a, str):
            continue
        for flag in flags:
            if a == flag and i + 1 < len(items) and isinstance(items[i + 1], str):
                _refuse_evidence_path(items[i + 1])
            elif a.startswith(flag + "="):
                _refuse_evidence_path(a[len(flag) + 1:])


def _resolve_prefix(interpreter: str | None, target: str) -> tuple[tuple[str, ...], str]:
    """Resolve a recipe to an absolute launcher prefix — filesystem only, no subprocess.

    Returns ``(prefix, reason)``. ``prefix`` is empty and ``reason`` explains why
    when anything fails to resolve, so an absent tool degrades to "unavailable"
    instead of crashing import.
    """

    def _resolve_one(name: str, *, must_exec: bool) -> tuple[str | None, str]:
        if os.path.isabs(name):
            if not os.path.isfile(name):
                return None, f"not found: {name}"
            if must_exec and not os.access(name, os.X_OK):
                return None, f"not executable: {name}"
            return os.path.realpath(name), "ok"
        found = shutil.which(name)
        if not found:
            return None, f"not on PATH: {name}"
        return os.path.realpath(found), "ok"

    parts: list[str] = []
    if interpreter is not None:
        interp, reason = _resolve_one(interpreter, must_exec=True)
        if interp is None:
            return (), reason
        parts.append(interp)
        # The target is a module file (.dll / .py) — must exist, need not be +x.
        if not os.path.isfile(target):
            return (), f"not found: {target}"
        parts.append(os.path.realpath(target))
    else:
        binary, reason = _resolve_one(target, must_exec=True)
        if binary is None:
            return (), reason
        parts.append(binary)
    return tuple(parts), "ok"


def _build_whitelist() -> dict[str, ResolvedTool]:
    """Resolve every recipe once, at import. Pure (filesystem checks only)."""
    table: dict[str, ResolvedTool] = {}
    for key, (interpreter, target, version_args, description) in _RECIPES.items():
        prefix, reason = _resolve_prefix(interpreter, target)
        table[key] = ResolvedTool(
            tool_key=key,
            prefix=prefix,
            available=bool(prefix),
            reason=reason,
            version_args=version_args,
            description=description,
        )
    return table


# The single source of truth: tool_key -> ResolvedTool. Built at import time with
# NO subprocess (only shutil.which / os.path lookups), so importing the package
# never spawns a process and the AST guard's "subprocess only inside calls" holds.
#
# Wrapped in a read-only MappingProxyType so no other module can ADD a launcher
# at runtime (``BINARY_WHITELIST["sh"] = …`` raises TypeError — an adversarial
# review found that mutation would have been a whitelist bypass that the AST
# scan alone could not see; the scan now ALSO flags whitelist-mutation syntax
# outside runner.py, so the two guards back each other up. Python offers no
# absolute module immutability — rebinding the module attribute itself is why
# ``setattr``/whitelist assignment outside runner.py is an AST offense too).
BINARY_WHITELIST: Mapping[str, ResolvedTool] = types.MappingProxyType(_build_whitelist())
WHITELISTED_TOOLS: tuple[str, ...] = tuple(sorted(BINARY_WHITELIST))


# -----------------------------------------------------------------------------
# argv construction — the only place a caller's input meets the launcher prefix.
# -----------------------------------------------------------------------------
def _build_argv(prefix: tuple[str, ...], args: Sequence[str]) -> list[str]:
    """Validate ``args`` and return ``[*prefix, *args]`` as a clean argv LIST.

    Rejects a raw command *string* (so ``"fls -r img"`` can't be smuggled in as
    one shell-shaped blob), non-string elements, and NUL bytes. With this in
    hand the caller's input can only ever be literal ``argv`` elements under
    ``shell=False`` — never shell syntax.
    """
    if isinstance(args, (str, bytes)):
        raise ToolArgumentError(
            "args must be a LIST of strings, not a single command string "
            f"({args!r}); pass e.g. ['-f', '/path/img.E01'], never 'fls -f ...'"
        )
    argv = list(prefix)
    for i, a in enumerate(args):
        if not isinstance(a, str):
            raise ToolArgumentError(
                f"argument {i} must be a string, got {type(a).__name__}: {a!r}"
            )
        if "\x00" in a:
            raise ToolArgumentError(f"argument {i} contains a NUL byte: {a!r}")
        argv.append(a)
    return argv


def run_tool(
    tool_key: str,
    args: Sequence[str] | None = None,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    cwd: str | None = None,
    audit: bool = True,
) -> ToolResult:
    """Run a whitelisted read-only forensic tool — the ONLY subprocess in the codebase.

    Parameters
    ----------
    tool_key: Must be a key in :data:`BINARY_WHITELIST`; anything else raises
              :class:`ToolNotAllowed` before any process is spawned.
    args:     A LIST of string arguments appended to the tool's server-controlled
              launcher prefix. NOT a command string (see :func:`_build_argv`).
    timeout:  Wall-clock ceiling (seconds); on overrun the process is killed and
              :class:`ToolTimeout` is raised.
    cwd:      Optional working directory (e.g. an output dir under ``./analysis``).
              The evidence is never written; output goes wherever the tool's own
              ``args`` direct it.
    audit:    When ``True`` (default) the call is stamped into the forensic ledger
              via :func:`telemetry.stamp_receipt` — a provenance row even on failure.

    Returns :class:`ToolResult` with ``stdout`` / ``stderr`` / ``exit_code``.

    Hard invariants (the whole reason this function exists):
    ``shell=False`` always; argv is a LIST; no shell, no redirection, no
    user-supplied raw command string ever reaches a shell.
    """
    if tool_key not in BINARY_WHITELIST:
        if audit:
            _stamp(tool_key, (), exit_code=127, error="tool not whitelisted (blocked)")
        raise ToolNotAllowed(
            f"tool_key {tool_key!r} is not whitelisted; the runner can launch "
            f"only {list(WHITELISTED_TOOLS)} and has no arbitrary-binary path"
        )

    tool = BINARY_WHITELIST[tool_key]
    if not tool.available:
        if audit:
            _stamp(tool_key, tuple(args or ()), exit_code=127,
                   error=f"tool unavailable: {tool.reason}")
        raise ToolUnavailable(
            f"tool {tool_key!r} is whitelisted but did not resolve on this box: {tool.reason}"
        )

    argv = _build_argv(tool.prefix, args or [])

    # A whitelisted parser must not be AIMED at the evidence with its own
    # output options (MFTECmd --csv /mnt/... etc.) — refused before any spawn.
    try:
        _check_output_redirection(tool_key, args or [])
    except CapturePathError:
        if audit:
            _stamp(tool_key, tuple(args or ()), exit_code=126,
                   error="output redirection into evidence (blocked)")
        raise

    t0 = time.monotonic()
    try:
        # The single subprocess in the whole codebase. shell=False is the point:
        # argv is a list, so no shell ever interprets it — no metacharacters, no
        # redirection, no word-splitting. capture_output pipes stdout/stderr;
        # check=False so we return a non-zero exit code rather than raising.
        completed = subprocess.run(  # noqa: S603 — argv list, shell=False, vetted prefix
            argv,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        duration_ms = (time.monotonic() - t0) * 1000.0
        if audit:
            _stamp(tool_key, tuple(args or ()), exit_code=124,
                   error=f"timeout after {timeout}s")
        raise ToolTimeout(
            f"tool {tool_key!r} exceeded {timeout}s and was killed"
        ) from exc

    duration_ms = (time.monotonic() - t0) * 1000.0
    if audit:
        _stamp(tool_key, tuple(args or ()), exit_code=completed.returncode, error="")
    return ToolResult(
        tool_key=tool_key,
        argv=tuple(argv),
        exit_code=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        duration_ms=duration_ms,
    )


# =============================================================================
# Capture + hash-chained receipt + capped return — the agent-facing verb.
#
# Everything below implements the data-spine receipt contract around run_tool().
# The serialization/hashing helpers are pinned BYTE-FOR-BYTE to the canonical
# ledger on feat/sqlite-store (sift_agent.ledger) so the two chains reconcile
# at merge. See the module docstring's "Branch-reconciliation seam" note.
# =============================================================================
def _canonical_json(obj) -> str:
    """Canonical JSON — pinned EXACTLY like ``ledger.canonical_json``.

    Sorted keys, compact separators, ASCII-only, ``allow_nan=False``. This is
    the only serialization that is hashed; any drift breaks chain reconciliation.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _compute_entry_hash(entry: dict) -> str:
    """SHA-256 hex of the canonical entry EXCLUDING ``entry_hash`` (its own field).

    ``prev_hash`` IS part of the preimage — the link that makes reordering or
    deleting a middle line detectable. Same rule as ``ledger.compute_entry_hash``.
    """
    core = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(_canonical_json(core).encode("utf-8")).hexdigest()


def _sha256_file(path: str) -> tuple[str, int]:
    """Stream ``path`` (read-only) and return ``(hex_digest, n_bytes)``."""
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as fh:
        while True:
            block = fh.read(65536)
            if not block:
                break
            h.update(block)
            n += len(block)
    return h.hexdigest(), n


def _utc_now_z() -> str:
    """Host UTC, ISO-8601 with a trailing ``Z`` — same format as ledger.py."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _has_float(obj) -> bool:
    """True if ``obj`` contains any float (recursively); bool/int are fine.

    Floats are banned in receipts (their repr is not stable across Python/json
    builds — exactly what would make a hashed ledger non-reproducible).
    """
    if isinstance(obj, float):
        return True
    if isinstance(obj, dict):
        return any(_has_float(v) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return any(_has_float(v) for v in obj)
    return False


def _refuse_evidence_path(path: str) -> str:
    """Realpath ``path`` and raise :class:`CapturePathError` if it is evidence.

    Refused: the filesystem root, anything under ``/cases``/``/mnt``/``/media``,
    and any path with an ``evidence`` directory segment (case-insensitive).
    Returns the resolved real path on success. Symlinks are resolved FIRST, so a
    scratch-looking symlink into an evidence tree is refused too.
    """
    real = os.path.realpath(os.path.expanduser(path))
    if real == "/":
        raise CapturePathError("refusing to write at the filesystem root")
    for prefix in _EVIDENCE_PATH_PREFIXES:
        if real == prefix or real.startswith(prefix + "/"):
            raise CapturePathError(
                f"refusing to write under evidence root {prefix!r}: {real}"
            )
    segments = [s.lower() for s in real.split("/") if s]
    if _EVIDENCE_SEGMENT in segments:
        raise CapturePathError(
            f"refusing to write inside an 'evidence' directory: {real}"
        )
    return real


def _ensure_capture_dir(path: str) -> str:
    """Validate ``path`` against the evidence guard and create it if needed."""
    real = _refuse_evidence_path(path)
    os.makedirs(real, exist_ok=True)
    return real


def scratch_output_dir(name: str, *, capture_dir: str | None = None) -> str:
    """A validated scratch directory for tools that write their OWN output files.

    Some whitelisted parsers take an output-directory flag (``MFTECmd --csv``,
    ``EvtxECmd --csv``, ``esedbexport -t`` …). A typed wrapper MUST source that
    argument from here and never from the caller: the returned path is created
    under the (evidence-guarded) capture root, and traversal cannot escape it —
    ``name`` must be relative, and the JOINED path is symlink-resolved and
    required to stay under the root. Combined with :func:`_refuse_evidence_path`
    this keeps contract rule #3: tool output goes ONLY to designated scratch,
    never to evidence, no matter what the model asks for.
    """
    base = _ensure_capture_dir(capture_dir or DEFAULT_CAPTURE_DIR)
    if not name or os.path.isabs(name):
        raise CapturePathError(
            f"scratch output dir name must be a non-empty RELATIVE path, got {name!r}"
        )
    real = os.path.realpath(os.path.join(base, name))
    if real != base and not real.startswith(base + os.sep):
        raise CapturePathError(
            f"scratch output dir {name!r} escapes the capture root: {real}"
        )
    _refuse_evidence_path(real)  # belt and braces (root could sit anywhere legal)
    os.makedirs(real, exist_ok=True)
    return real


def _safe_args(args) -> list:
    """Render call args as a JSON-safe, float-free list for the receipt.

    Strings pass through; anything else (including the rejected raw-string /
    non-string forms that made the call fail validation) is recorded as its
    ``repr`` so even a REFUSED call leaves a faithful, hashable receipt.
    """
    if args is None:
        return []
    if isinstance(args, (str, bytes)):
        return [repr(args)]
    return [a if isinstance(a, str) else repr(a) for a in args]


def _turn_tokens() -> dict:
    """Issuing-agent-turn token attribution, in telemetry's labelled shape.

    Identical fields to ``telemetry.stamp_receipt``'s ``tokens`` block (and to
    the canonical ledger's): a tool spends no LLM tokens of its own, so the row
    carries the issuing turn's counts, explicitly labelled — never fabricated.
    """
    turn = telemetry.current_turn_usage()
    return {
        "source": "issuing_agent_turn",
        "agent_turn_id": turn["agent_turn_id"],
        "input_tokens": int(turn["input_tokens"]),
        "output_tokens": int(turn["output_tokens"]),
        "total_tokens": int(turn["total_tokens"]),
        "note": "tool execution consumes no LLM tokens; counts are the agent "
        "turn that issued the call",
    }


def _assert_receipt_invariants(receipt: dict) -> None:
    """Fail-fast checks mirrored from ``ledger._assert_receipt_invariants``."""
    if _has_float(receipt):
        raise RunnerError(
            "receipt contains a float; durations must be fixed-decimal strings "
            "and counts ints (hash stability)"
        )
    inv = receipt.get("invocation_status")
    if inv not in ("ok", "path_failure", "empty_output", "error"):
        raise RunnerError(f"illegal invocation_status {inv!r}")
    osha = receipt.get("output_sha256")
    if osha == EMPTY_SHA256 and inv != "empty_output":
        raise RunnerError(
            "output_sha256 is the empty-string digest but invocation_status is "
            f"{inv!r}; an empty capture must never look like a real artifact"
        )
    if inv == "ok" and osha == EMPTY_SHA256:
        raise RunnerError("invocation_status=ok cannot carry the empty-string digest")


class ReceiptWriter:
    """Thin seam between the runner and the provenance ledger.

    The runner only ever calls :meth:`append` with a receipt dict that has NO
    ``prev_hash``/``entry_hash`` yet; the writer chains and persists it and
    returns the completed line. TODO(branch-reconciliation): at merge, the
    canonical implementation is an adapter over ``sift_agent.ledger.Ledger``
    (feat/sqlite-store) — same ``receipts-v1`` fields, same canonical JSON,
    same hashing. :class:`JsonlReceiptWriter` below is the deliberately minimal
    stand-in so this branch does not fork a second ledger.
    """

    def append(self, receipt: dict) -> dict:
        raise NotImplementedError


class JsonlReceiptWriter(ReceiptWriter):
    """Minimal append-only, hash-chained ``receipts.jsonl`` writer.

    flock-serialized: the tail's ``entry_hash`` is read INSIDE the exclusive
    lock, so a receipt's ``prev_hash`` is always computed against the true
    current tail even with concurrent writers. The path is validated against
    the evidence guard at construction time.
    """

    def __init__(self, path: str) -> None:
        self.path = _refuse_evidence_path(path)
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    def _tail_entry_hash(self) -> str:
        """Last complete line's ``entry_hash``, else genesis. Call under lock."""
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return GENESIS_PREV_HASH
        if size == 0:
            return GENESIS_PREV_HASH
        window = min(size, 1024 * 1024)
        with open(self.path, "rb") as fh:
            fh.seek(size - window)
            blob = fh.read(window)
        # Only fully newline-terminated lines count (a torn write is ignored).
        complete, _, _partial = blob.rpartition(b"\n")
        for raw in reversed(complete.split(b"\n")):
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw.decode("utf-8"))
                return str(entry["entry_hash"])
            except (ValueError, KeyError, UnicodeDecodeError) as exc:
                raise RunnerError(
                    f"receipts file {self.path!r} has a corrupt tail line; "
                    f"refusing to chain onto it ({exc!r})"
                ) from exc
        return GENESIS_PREV_HASH

    def append(self, receipt: dict) -> dict:
        if "prev_hash" in receipt or "entry_hash" in receipt:
            raise RunnerError("receipt must not be pre-chained; the writer links it")
        _assert_receipt_invariants(receipt)
        # 'a' mode: append-only file handle; existing bytes are never rewritten.
        with open(self.path, "a", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                chained = dict(receipt)
                chained["prev_hash"] = self._tail_entry_hash()
                chained["entry_hash"] = _compute_entry_hash(chained)
                fh.write(_canonical_json(chained) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        return chained


def verify_receipts(path: str) -> dict:
    """Minimal chain verifier (the §2.3 ``verify_chain`` check) for the seam.

    Re-reads ``path``, recomputes every ``entry_hash`` from the canonical form,
    and checks each line's ``prev_hash`` against the previous line's
    ``entry_hash`` (genesis on line 1). Returns
    ``{"ok", "entries", "first_bad_line", "reason"}`` — line numbers are 1-based.
    TODO(branch-reconciliation): superseded by ``sift_agent.ledger.verify_chain``.
    """
    expected_prev = GENESIS_PREV_HASH
    entries = 0
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except ValueError:
                return {"ok": False, "entries": entries, "first_bad_line": lineno,
                        "reason": "unparseable JSON line"}
            if entry.get("prev_hash") != expected_prev:
                return {"ok": False, "entries": entries, "first_bad_line": lineno,
                        "reason": "prev_hash does not match prior entry_hash"}
            if _compute_entry_hash(entry) != entry.get("entry_hash"):
                return {"ok": False, "entries": entries, "first_bad_line": lineno,
                        "reason": "entry_hash does not recompute from canonical form"}
            expected_prev = entry["entry_hash"]
            entries += 1
    return {"ok": True, "entries": entries, "first_bad_line": None, "reason": ""}


@dataclass(frozen=True)
class CappedToolResult:
    """The model-facing outcome of one captured run — capped, never the raw dump.

    ``rows`` holds at most :data:`MAX_RETURN_ROWS` stdout lines; the FULL output
    lives at ``output_path`` (SHA-256 ``output_sha256``) and is referenced by the
    hash-chained receipt ``receipt_id``. ``total_rows``/``truncated`` make the
    cap explicit so the agent knows to query the capture, not re-run the tool.
    """

    tool_key: str
    receipt_id: str
    entry_hash: str
    invocation_status: str
    exit_code: int | None
    rows: tuple[str, ...]
    total_rows: int
    truncated: bool
    stderr_tail: str
    output_path: str | None
    output_sha256: str | None
    output_bytes: int | None
    duration_ms: float


_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")


def run_tool_captured(
    tool_key: str,
    args: Sequence[str] | None = None,
    *,
    evidence_ref: str | None = None,
    agent: str = "sift-agent",
    capture_dir: str | None = None,
    receipt_writer: ReceiptWriter | None = None,
    max_rows: int = MAX_RETURN_ROWS,
    timeout: float = DEFAULT_TIMEOUT,
) -> CappedToolResult:
    """Run a whitelisted tool with full capture, a hash-chained receipt, and a
    capped structured return — the verb typed MCP wrappers must use.

    Flow: validate the scratch capture dir (evidence paths are refused) →
    :func:`run_tool` (the single subprocess chokepoint) → write FULL stdout to
    ``<capture_dir>/<receipt_id>__<tool>.out`` (exclusive create; stderr to a
    ``.err`` sidecar when present) → hash it → append ONE ``receipts-v1`` line
    via the :class:`ReceiptWriter` seam → return ≤ ``max_rows`` stdout rows +
    the ``receipt_id``. A refused, failed, or timed-out call still writes a
    receipt (``invocation_status="error"``) before the error propagates — every
    call leaves a chained provenance line, success or not.

    ``max_rows`` must be in ``1..MAX_RETURN_ROWS`` (the query_store discipline);
    out of range raises :class:`ToolArgumentError`.
    """
    if isinstance(max_rows, bool) or not isinstance(max_rows, int) or not (
        1 <= max_rows <= MAX_RETURN_ROWS
    ):
        raise ToolArgumentError(
            f"max_rows must be an int in 1..{MAX_RETURN_ROWS}, got {max_rows!r}"
        )

    cap_dir = _ensure_capture_dir(capture_dir or DEFAULT_CAPTURE_DIR)
    writer = receipt_writer or JsonlReceiptWriter(
        os.getenv("SIFT_RECEIPTS_PATH") or os.path.join(cap_dir, "receipts.jsonl")
    )
    receipt_id = str(uuid.uuid4())

    def _base_receipt() -> dict:
        return {
            "schema_version": RECEIPTS_SCHEMA_VERSION,
            "receipt_id": receipt_id,
            "ts": _utc_now_z(),
            "agent": agent,
            "tool": tool_key,
            "args": _safe_args(args),
            "evidence_ref": evidence_ref,
            "tokens": _turn_tokens(),
        }

    t0 = time.monotonic()
    try:
        result = run_tool(tool_key, args, timeout=timeout)
    except RunnerError as exc:
        # Refused (not whitelisted / unavailable / bad args) or timed out: no
        # output exists, but the attempt itself is chained into the ledger.
        receipt = _base_receipt()
        receipt.update(
            output_path=None,
            output_sha256=None,
            output_bytes=None,
            invocation_status="error",
            exit_code=None,
            error=repr(exc),
            elapsed_s=f"{time.monotonic() - t0:.3f}",
        )
        writer.append(receipt)
        raise

    duration_ms = (time.monotonic() - t0) * 1000.0

    # ---- capture the FULL raw output (scratch space only, never evidence) ----
    out_path: str | None = None
    out_sha: str | None = None
    out_bytes: int | None = None
    slug = _SLUG_RE.sub("_", tool_key)
    if result.stdout or result.exit_code == 0:
        # A successful run always leaves a capture artifact (possibly empty —
        # honestly recorded as empty_output). A failed run with NO stdout leaves
        # no artifact: a null digest can never impersonate a real one.
        out_path = os.path.join(cap_dir, f"{receipt_id}__{slug}.out")
        with open(out_path, "x", encoding="utf-8") as fh:
            fh.write(result.stdout)
        out_sha, out_bytes = _sha256_file(out_path)
    if result.stderr:
        err_path = os.path.join(cap_dir, f"{receipt_id}__{slug}.err")
        with open(err_path, "x", encoding="utf-8") as fh:
            fh.write(result.stderr)

    # ---- invocation_status (the empty-output trap, mirrored from ledger.py) --
    if result.exit_code != 0:
        status = "error"
        if out_sha == EMPTY_SHA256:
            # zero-byte capture on a failed run: drop the artifact reference so
            # the empty digest can't collide with "a real empty artifact".
            out_sha, out_bytes = None, None
    elif out_bytes == 0:
        status = "empty_output"
    else:
        status = "ok"

    receipt = _base_receipt()
    receipt.update(
        output_path=out_path,
        output_sha256=out_sha,
        output_bytes=out_bytes,
        invocation_status=status,
        exit_code=result.exit_code,
        elapsed_s=f"{duration_ms / 1000.0:.3f}",
    )
    if result.stderr:
        receipt["stderr"] = result.stderr[-2000:]
    chained = writer.append(receipt)

    # ---- capped, structured, model-facing return -----------------------------
    lines = result.stdout.splitlines()
    return CappedToolResult(
        tool_key=tool_key,
        receipt_id=receipt_id,
        entry_hash=chained["entry_hash"],
        invocation_status=status,
        exit_code=result.exit_code,
        rows=tuple(lines[:max_rows]),
        total_rows=len(lines),
        truncated=len(lines) > max_rows,
        stderr_tail=result.stderr[-2000:],
        output_path=out_path,
        output_sha256=out_sha,
        output_bytes=out_bytes,
        duration_ms=duration_ms,
    )


# -----------------------------------------------------------------------------
# Audit + introspection helpers.
# -----------------------------------------------------------------------------
def _stamp(tool_key: str, args: tuple[str, ...], *, exit_code: int, error: str) -> dict:
    """Route one tool execution through ``telemetry.stamp_receipt`` (UTC ts + tokens)."""
    receipt: dict = {
        "tool": f"runner:{tool_key}",
        "exit_code": exit_code,
        "read_only": True,
        "args": list(args),
    }
    prefix = BINARY_WHITELIST[tool_key].prefix if tool_key in BINARY_WHITELIST else ()
    if prefix:
        receipt["binary"] = prefix[0]
    if error:
        receipt["error"] = error
    return telemetry.stamp_receipt(receipt)


def inventory(*, include_versions: bool = False) -> list[dict]:
    """Return the resolved whitelist as structured rows — the capability map.

    This is what lets the agent (and the Day-2 tool-capability probe) route by
    CAPABILITY rather than a hardcoded name: per tool ``name``, ``present``,
    ``resolved_path`` (the actual binary/dll/script), the full ``launcher``
    argv prefix, and ``version``.

    With ``include_versions=False`` (default) this is pure — no subprocess, no
    file reads — and ``version`` is ``None``. With ``include_versions=True``
    each PRESENT tool's version probe runs once through :func:`run_tool`
    (cached across calls); absent tools report ``"unavailable"``.
    """
    rows = []
    for key in WHITELISTED_TOOLS:
        t = BINARY_WHITELIST[key]
        version = None
        if include_versions:
            version = tool_version(key)
        rows.append(
            {
                "name": t.tool_key,
                "tool_key": t.tool_key,
                "present": t.available,
                "resolved_path": t.prefix[-1] if t.prefix else None,
                "launcher": list(t.prefix),
                "version": version,
                "reason": t.reason,
                "description": t.description,
            }
        )
    return rows


_VERSION_CACHE: dict[str, str] = {}


def tool_version(tool_key: str, *, timeout: float = 60.0) -> str:
    """Best-effort version string for a tool (cached). Runs the tool's version probe.

    This DOES spawn a subprocess (through :func:`run_tool`), so it is never called
    at import and never by the test suite against real tools — only when a host
    explicitly asks (e.g. :func:`capture_versions` at startup). Returns
    ``"unavailable"`` / ``"unknown"`` rather than raising.
    """
    if tool_key in _VERSION_CACHE:
        return _VERSION_CACHE[tool_key]
    tool = BINARY_WHITELIST.get(tool_key)
    if tool is None or not tool.available:
        version = "unavailable"
    else:
        try:
            res = run_tool(tool_key, list(tool.version_args), timeout=timeout, audit=False)
            blob = f"{res.stdout}\n{res.stderr}"
            version = _first_version_line(blob) or "unknown"
        except RunnerError:
            version = "unknown"
    _VERSION_CACHE[tool_key] = version
    return version


_VERSION_NUM_RE = re.compile(r"\d+\.\d+")
_VERSION_WORD_RE = re.compile(r"\b(version|ver)\b", re.IGNORECASE)


def _first_version_line(blob: str) -> str:
    """Pull a plausible version line out of a tool's --help/-V banner.

    Prefers a line carrying both a version-ish WORD and a dotted number (so
    ``--recover ...`` or a flag-usage line never wins just because it contains
    the letters ``ver``); falls back to the first line with a dotted number
    (e.g. ``Volatility 3 Framework 2.20.0``), then the first non-empty line.
    """
    lines = [ln.strip() for ln in blob.splitlines() if ln.strip()]
    for line in lines:
        if _VERSION_WORD_RE.search(line) and _VERSION_NUM_RE.search(line):
            return line
    for line in lines:
        if _VERSION_NUM_RE.search(line):
            return line
    return lines[0] if lines else ""


def capture_versions(*, timeout: float = 60.0) -> dict[str, str]:
    """Probe and cache every available tool's version. Host calls this at startup.

    NOT invoked at import (so importing the package spawns nothing) and NOT used
    by the test suite against real binaries. One subprocess per available tool.
    """
    return {key: tool_version(key, timeout=timeout) for key in WHITELISTED_TOOLS}

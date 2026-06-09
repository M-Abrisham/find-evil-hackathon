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

Adding a tool = add a read-only forensic binary to :data:`_RECIPES`. Adding an
*execution path* is impossible without editing this file, which the guard makes
loud.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Sequence

from sift_agent import telemetry

__all__ = [
    "BINARY_WHITELIST",
    "WHITELISTED_TOOLS",
    "DEFAULT_TIMEOUT",
    "ResolvedTool",
    "ToolResult",
    "RunnerError",
    "ToolNotAllowed",
    "ToolUnavailable",
    "ToolArgumentError",
    "ToolTimeout",
    "run_tool",
    "inventory",
    "tool_version",
    "capture_versions",
]

# Default wall-clock ceiling for a single tool run. Forensic parses (a full $MFT,
# a memory plugin) can be slow, so the default is generous but finite — a hung
# tool can never block the agent forever. Overridable per call and via env.
DEFAULT_TIMEOUT = float(os.getenv("SIFT_RUNNER_TIMEOUT", "300"))


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
    "vol": (None, "vol", ("--help",), "Volatility 3 — memory image analysis (read-only)."),
    # --- The Sleuth Kit (disk / file system) -------------------------------
    "fls": (None, "fls", ("-V",), "Sleuth Kit fls — list file names from a disk image (read-only)."),
    # --- libesedb (ESE / EDB databases: SRUM, Windows.edb, NTDS) -----------
    "esedbexport": (None, "esedbexport", ("-V",),
                    "esedbexport — extract tables from ESE/EDB databases (read-only)."),
    # --- USN journal parser (Python) ---------------------------------------
    "usn.py": ("/opt/usnparser/bin/python3", "/opt/usnparser/bin/usn.py", ("-h",),
               "usnparser usn.py — parse the NTFS $UsnJrnl change journal (read-only)."),
    # --- Eric Zimmerman .NET tools (run via dotnet) ------------------------
    "MFTECmd": ("dotnet", f"{_EZ}/MFTECmd.dll", ("--help",),
                "MFTECmd — parse $MFT / $J / $Boot / $SDS NTFS metadata (read-only)."),
    "EvtxECmd": ("dotnet", f"{_EZ}/EvtxeCmd/EvtxECmd.dll", ("--help",),
                 "EvtxECmd — parse Windows .evtx event logs (read-only)."),
    "RECmd": ("dotnet", f"{_EZ}/RECmd/RECmd.dll", ("--help",),
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
BINARY_WHITELIST: dict[str, ResolvedTool] = _build_whitelist()
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


def inventory() -> list[dict]:
    """Return the resolved whitelist as plain dicts — no subprocess, no versions.

    Useful for a host/operator to see, without running anything, exactly which
    forensic binaries this runner can launch and where each resolved to.
    """
    rows = []
    for key in WHITELISTED_TOOLS:
        t = BINARY_WHITELIST[key]
        rows.append(
            {
                "tool_key": t.tool_key,
                "available": t.available,
                "prefix": list(t.prefix),
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


def _first_version_line(blob: str) -> str:
    """Pull a plausible version line out of a tool's --help/-V banner."""
    lines = [ln.strip() for ln in blob.splitlines() if ln.strip()]
    for line in lines:
        low = line.lower()
        if "version" in low or "ver " in low:
            return line
    # Fall back to the first non-empty line.
    return lines[0] if lines else ""


def capture_versions(*, timeout: float = 60.0) -> dict[str, str]:
    """Probe and cache every available tool's version. Host calls this at startup.

    NOT invoked at import (so importing the package spawns nothing) and NOT used
    by the test suite against real binaries. One subprocess per available tool.
    """
    return {key: tool_version(key, timeout=timeout) for key in WHITELISTED_TOOLS}

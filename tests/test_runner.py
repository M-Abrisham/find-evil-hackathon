"""Tests for the single vetted subprocess chokepoint (``runner.py``).

These prove the runner's *behaviour* — the closed whitelist, the argv-LIST
contract (never a command string), ``shell=False``, timeout handling, and audit
routing — WITHOUT running any real forensic tool or touching evidence. Where a
live process is needed we use ``sys.executable`` (always present, harmless) as a
stand-in, or monkeypatch ``subprocess.run`` to capture how it is invoked.
"""

import json
import logging
import sys

import pytest

from sift_agent import telemetry
from sift_agent.mcp_server import runner
from sift_agent.mcp_server.runner import (
    BINARY_WHITELIST,
    WHITELISTED_TOOLS,
    ResolvedTool,
    ToolArgumentError,
    ToolNotAllowed,
    ToolResult,
    ToolTimeout,
    ToolUnavailable,
    inventory,
    run_tool,
)

# The Day-2 roadmap whitelist — exactly the read-only forensic tools the runner
# is allowed to launch (the binaries confirmed present on the SIFT box).
_EXPECTED_TOOL_KEYS = {
    "vol", "fls", "esedbexport", "usn.py",
    "MFTECmd", "EvtxECmd", "RECmd", "LECmd", "JLECmd", "SBECmd", "RBCmd", "SQLECmd",
}


# ---------------------------------------------------------------------------
# Fixtures: a harmless, fully-resolved fake tool so we can exercise run_tool's
# execution path without invoking a real forensic binary. ``sys.executable`` is
# the launcher; we drive it with ``-c`` snippets.
# ---------------------------------------------------------------------------
@pytest.fixture
def fake_tool(monkeypatch):
    spec = ResolvedTool(
        tool_key="py_probe",
        prefix=(sys.executable,),
        available=True,
        reason="ok",
        version_args=("-c", "pass"),
        description="harmless python stand-in for runner tests",
    )
    monkeypatch.setitem(BINARY_WHITELIST, "py_probe", spec)
    return spec


@pytest.fixture
def ledger():
    """Capture sift.telemetry ledger lines in-memory (no file is written)."""

    class _Capture(logging.Handler):
        def __init__(self):
            super().__init__()
            self.lines = []

        def emit(self, record):
            self.lines.append(record.getMessage())

    handler = _Capture()
    logger = logging.getLogger("sift.telemetry")
    prev = logger.level
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    telemetry.COST.reset()
    telemetry.begin_turn("runner-turn-001")
    try:
        yield handler
    finally:
        logger.removeHandler(handler)
        logger.setLevel(prev)


# ---------------------------------------------------------------------------
# The closed whitelist
# ---------------------------------------------------------------------------
def test_whitelist_keys_are_exactly_the_roadmap_tools():
    assert set(WHITELISTED_TOOLS) == _EXPECTED_TOOL_KEYS
    assert list(WHITELISTED_TOOLS) == sorted(WHITELISTED_TOOLS)


def test_whitelist_resolution_is_pure_and_well_formed():
    # Built at import with no subprocess; every entry is a typed ResolvedTool and
    # any resolved launcher is a tuple of ABSOLUTE paths.
    for key in WHITELISTED_TOOLS:
        tool = BINARY_WHITELIST[key]
        assert isinstance(tool, ResolvedTool)
        assert isinstance(tool.prefix, tuple)
        assert tool.available is bool(tool.prefix)
        if tool.available:
            assert all(p.startswith("/") for p in tool.prefix), tool.prefix


def test_expected_tools_resolve_on_this_box():
    """On the SIFT box every roadmap tool resolves; elsewhere, skip gracefully."""
    missing = {k: BINARY_WHITELIST[k].reason for k in _EXPECTED_TOOL_KEYS
               if not BINARY_WHITELIST[k].available}
    if missing:
        pytest.skip(f"not the SIFT box — unresolved forensic tools: {missing}")
    # All present: assert the launcher shapes are what we expect.
    assert BINARY_WHITELIST["fls"].prefix[0].endswith("/fls")
    assert BINARY_WHITELIST["MFTECmd"].prefix[0].endswith("/dotnet")
    assert BINARY_WHITELIST["MFTECmd"].prefix[1].endswith("MFTECmd.dll")
    assert BINARY_WHITELIST["usn.py"].prefix[1].endswith("usn.py")


def test_inventory_is_pure_and_covers_every_tool():
    rows = inventory()
    assert {r["tool_key"] for r in rows} == _EXPECTED_TOOL_KEYS
    for r in rows:
        assert set(r) == {"tool_key", "available", "prefix", "reason", "description"}


# ---------------------------------------------------------------------------
# The guardrail refusals (no process is spawned)
# ---------------------------------------------------------------------------
def test_unknown_tool_key_is_refused():
    for bad in ["rm", "bash", "sh", "execute_shell", "vol; rm -rf /", "dd"]:
        with pytest.raises(ToolNotAllowed):
            run_tool(bad, ["whatever"], audit=False)


def test_unavailable_tool_raises(monkeypatch):
    spec = ResolvedTool(
        tool_key="ghost", prefix=(), available=False, reason="not on PATH: ghost",
        version_args=(), description="x",
    )
    monkeypatch.setitem(BINARY_WHITELIST, "ghost", spec)
    with pytest.raises(ToolUnavailable):
        run_tool("ghost", ["-h"], audit=False)


# ---------------------------------------------------------------------------
# The argv-LIST contract: a raw command string can never be smuggled in
# ---------------------------------------------------------------------------
def test_args_must_be_a_list_not_a_command_string(fake_tool):
    with pytest.raises(ToolArgumentError):
        run_tool("py_probe", "-c print(1)", audit=False)  # a string, not a list
    with pytest.raises(ToolArgumentError):
        run_tool("py_probe", b"-c", audit=False)  # bytes are rejected too


def test_args_must_be_strings_without_nul(fake_tool):
    with pytest.raises(ToolArgumentError):
        run_tool("py_probe", ["-c", 123], audit=False)  # non-string element
    with pytest.raises(ToolArgumentError):
        run_tool("py_probe", ["bad\x00arg"], audit=False)  # NUL byte


# ---------------------------------------------------------------------------
# Real execution through the chokepoint (harmless python stand-in, shell=False)
# ---------------------------------------------------------------------------
def test_run_tool_executes_and_captures_streams(fake_tool):
    res = run_tool(
        "py_probe",
        ["-c", "import sys; sys.stdout.write('OUT'); sys.stderr.write('ERR'); sys.exit(3)"],
        audit=False,
    )
    assert isinstance(res, ToolResult)
    assert res.exit_code == 3
    assert "OUT" in res.stdout
    assert "ERR" in res.stderr
    # argv is prefix + our args, in order — a LIST, never a shell string.
    assert res.argv[0] == sys.executable
    assert res.argv[1] == "-c"
    assert res.duration_ms >= 0


def test_run_tool_calls_subprocess_with_shell_false(fake_tool, monkeypatch):
    captured = {}

    class _Completed:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def _fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _Completed()

    monkeypatch.setattr(runner.subprocess, "run", _fake_run)
    run_tool("py_probe", ["--version"], audit=False)

    assert isinstance(captured["argv"], list)  # argv LIST, not a string
    assert captured["argv"][0] == sys.executable
    assert captured["kwargs"]["shell"] is False  # the whole point
    assert captured["kwargs"]["capture_output"] is True
    assert "timeout" in captured["kwargs"]


def test_run_tool_times_out(fake_tool):
    with pytest.raises(ToolTimeout):
        run_tool("py_probe", ["-c", "import time; time.sleep(5)"], timeout=0.2, audit=False)


# ---------------------------------------------------------------------------
# Audit routing: executions AND blocked attempts land in the forensic ledger
# ---------------------------------------------------------------------------
def test_execution_is_stamped_into_the_ledger(fake_tool, ledger):
    run_tool("py_probe", ["-c", "print('hi')"])  # audit=True (default)
    rows = [json.loads(x) for x in ledger.lines if json.loads(x)["kind"] == "tool_exec"]
    assert any(r["tool"] == "runner:py_probe" and r["exit_code"] == 0 for r in rows)


def test_blocked_tool_key_is_still_audited(ledger):
    with pytest.raises(ToolNotAllowed):
        run_tool("execute_shell", ["whoami"])  # audit=True
    rows = [json.loads(x) for x in ledger.lines if json.loads(x)["kind"] == "tool_exec"]
    blocked = next(r for r in rows if r["tool"] == "runner:execute_shell")
    assert blocked["exit_code"] == 127  # refused before any execution
    assert blocked["agent_turn_id"] == "runner-turn-001"

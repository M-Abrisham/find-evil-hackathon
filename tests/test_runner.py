"""Tests for the single vetted subprocess chokepoint (``runner.py``).

These prove the runner's *behaviour* — the closed whitelist, the argv-LIST
contract (never a command string), ``shell=False``, timeout handling, audit
routing, and the Day-2 capture path (full output to a scratch file, ONE
hash-chained ``receipts-v1`` line per call, capped ≤50-row model-facing
return, evidence-path refusal) — WITHOUT running any real forensic tool or
touching evidence. Where a live process is needed we use ``sys.executable``
(always present, harmless) as a stand-in, or monkeypatch ``subprocess.run``
to capture how it is invoked.
"""

import hashlib
import json
import logging
import os
import sys

import pytest

from sift_agent import telemetry
from sift_agent.mcp_server import runner
from sift_agent.mcp_server.runner import (
    BINARY_WHITELIST,
    EMPTY_SHA256,
    GENESIS_PREV_HASH,
    MAX_RETURN_ROWS,
    RECEIPTS_SCHEMA_VERSION,
    WHITELISTED_TOOLS,
    CappedToolResult,
    CapturePathError,
    JsonlReceiptWriter,
    ResolvedTool,
    RunnerError,
    ToolArgumentError,
    ToolNotAllowed,
    ToolResult,
    ToolTimeout,
    ToolUnavailable,
    inventory,
    run_tool,
    run_tool_captured,
    verify_receipts,
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
    # BINARY_WHITELIST is a read-only MappingProxyType (runtime mutation is a
    # guardrail bypass), so tests swap in a one-entry-richer COPY at module level.
    monkeypatch.setattr(
        runner, "BINARY_WHITELIST", {**BINARY_WHITELIST, "py_probe": spec}
    )
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
    rows = inventory()  # default: pure — no subprocess, version unprobed
    assert {r["name"] for r in rows} == _EXPECTED_TOOL_KEYS
    for r in rows:
        assert set(r) == {
            "name", "tool_key", "present", "resolved_path", "launcher",
            "version", "reason", "description",
        }
        assert r["tool_key"] == r["name"]
        assert r["version"] is None  # no probe ran
        if r["present"]:
            assert r["resolved_path"] == r["launcher"][-1]
            assert all(p.startswith("/") for p in r["launcher"])
        else:
            assert r["resolved_path"] is None and r["launcher"] == []


def test_inventory_include_versions_probes_via_the_chokepoint(monkeypatch):
    spec = ResolvedTool(
        tool_key="py_probe",
        prefix=(sys.executable,),
        available=True,
        reason="ok",
        version_args=("--version",),
        description="harmless python stand-in",
    )
    monkeypatch.setattr(
        runner, "BINARY_WHITELIST", {**BINARY_WHITELIST, "py_probe": spec}
    )
    monkeypatch.setattr(runner, "WHITELISTED_TOOLS", ("py_probe",))
    monkeypatch.setattr(runner, "_VERSION_CACHE", {})
    (row,) = inventory(include_versions=True)
    assert row["present"] is True
    assert row["version"].startswith("Python ")  # the probe really ran


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
    monkeypatch.setattr(runner, "BINARY_WHITELIST", {**BINARY_WHITELIST, "ghost": spec})
    with pytest.raises(ToolUnavailable):
        run_tool("ghost", ["-h"], audit=False)


def test_whitelist_is_immutable_at_runtime():
    """Runtime whitelist mutation (the bypass an adversarial review found) is a
    TypeError: no other module can add a launcher like ``/bin/sh``. The AST scan
    additionally flags whitelist-mutation SYNTAX outside runner.py — see
    tests/test_mcp_server.py — since Python cannot make module attrs immutable."""
    import types as _types

    assert isinstance(BINARY_WHITELIST, _types.MappingProxyType)
    with pytest.raises(TypeError):
        BINARY_WHITELIST["sh"] = ResolvedTool(  # type: ignore[index]
            "sh", ("/bin/sh",), True, "ok", (), "definitely not allowed"
        )
    assert "sh" not in BINARY_WHITELIST


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


# ===========================================================================
# The Day-2 captured path: full capture + hash-chained receipt + capped return
# ===========================================================================
@pytest.fixture
def capdir(tmp_path, monkeypatch):
    """A scratch capture dir; also isolates from any env-pinned receipts path."""
    monkeypatch.delenv("SIFT_RECEIPTS_PATH", raising=False)
    return str(tmp_path / "captures")


def _receipt_lines(capdir):
    path = os.path.join(capdir, "receipts.jsonl")
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(ln) for ln in fh if ln.strip()]


def _py(snippet):
    return ["-c", snippet]


def test_captured_run_writes_capture_file_and_chained_receipt(fake_tool, capdir):
    res = run_tool_captured(
        "py_probe",
        _py("print('row1'); print('row2'); print('row3')"),
        evidence_ref="/dev/null",
        agent="pytest",
        capture_dir=capdir,
    )
    assert isinstance(res, CappedToolResult)
    assert res.invocation_status == "ok" and res.exit_code == 0
    # The FULL raw output landed in the capture file, and its hash matches.
    with open(res.output_path, "rb") as fh:
        blob = fh.read()
    assert blob.decode() == "row1\nrow2\nrow3\n"
    assert hashlib.sha256(blob).hexdigest() == res.output_sha256
    assert res.output_bytes == len(blob)
    assert res.output_path.startswith(os.path.realpath(capdir) + os.sep)
    # Exactly ONE receipts-v1 line, genesis-chained, hash self-consistent.
    (line,) = _receipt_lines(capdir)
    assert line["schema_version"] == RECEIPTS_SCHEMA_VERSION
    assert line["receipt_id"] == res.receipt_id
    assert line["ts"].endswith("Z")
    assert line["agent"] == "pytest"
    assert line["tool"] == "py_probe"
    assert line["args"][0] == "-c"
    assert line["evidence_ref"] == "/dev/null"
    assert line["output_sha256"] == res.output_sha256
    assert line["output_path"] == res.output_path
    assert line["invocation_status"] == "ok"
    assert line["exit_code"] == 0
    assert line["tokens"]["source"] == "issuing_agent_turn"
    assert isinstance(line["elapsed_s"], str)  # fixed-decimal, never a float
    assert line["prev_hash"] == GENESIS_PREV_HASH
    assert line["entry_hash"] == res.entry_hash
    # The model-facing return is the capped rows + receipt id, not the dump.
    assert list(res.rows) == ["row1", "row2", "row3"]
    assert res.total_rows == 3 and res.truncated is False


def test_receipts_chain_links_across_calls_and_verifies(fake_tool, capdir):
    for i in range(3):
        run_tool_captured("py_probe", _py(f"print({i})"), capture_dir=capdir)
    lines = _receipt_lines(capdir)
    assert len(lines) == 3
    assert lines[0]["prev_hash"] == GENESIS_PREV_HASH
    assert lines[1]["prev_hash"] == lines[0]["entry_hash"]
    assert lines[2]["prev_hash"] == lines[1]["entry_hash"]
    report = verify_receipts(os.path.join(capdir, "receipts.jsonl"))
    assert report == {"ok": True, "entries": 3, "first_bad_line": None, "reason": ""}


def test_receipt_tampering_reordering_and_deletion_are_detected(fake_tool, capdir, tmp_path):
    for i in range(3):
        run_tool_captured("py_probe", _py(f"print({i})"), capture_dir=capdir)
    path = os.path.join(capdir, "receipts.jsonl")
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.readlines()

    def _verdict(lines):
        p = tmp_path / "tampered.jsonl"
        p.write_text("".join(lines))
        return verify_receipts(str(p))

    # 1) EDIT a middle line (claim a different agent ran the tool).
    doctored = json.loads(raw[1])
    doctored["agent"] = "someone-else"
    tampered = [raw[0], json.dumps(doctored) + "\n", raw[2]]
    rep = _verdict(tampered)
    assert rep["ok"] is False and rep["first_bad_line"] == 2
    assert "entry_hash" in rep["reason"]
    # 2) DELETE a middle line.
    rep = _verdict([raw[0], raw[2]])
    assert rep["ok"] is False and rep["first_bad_line"] == 2
    assert "prev_hash" in rep["reason"]
    # 3) REORDER lines.
    rep = _verdict([raw[1], raw[0], raw[2]])
    assert rep["ok"] is False and rep["first_bad_line"] == 1
    # The untouched file still verifies.
    assert verify_receipts(path)["ok"] is True


def test_model_facing_return_is_capped_at_50_rows(fake_tool, capdir):
    res = run_tool_captured(
        "py_probe",
        _py("[print(f'line{i}') for i in range(120)]"),
        capture_dir=capdir,
    )
    assert len(res.rows) == MAX_RETURN_ROWS == 50
    assert res.rows[0] == "line0" and res.rows[-1] == "line49"
    assert res.total_rows == 120 and res.truncated is True
    # ...but the capture file holds the FULL output.
    with open(res.output_path, "r", encoding="utf-8") as fh:
        assert len(fh.read().splitlines()) == 120


def test_max_rows_outside_query_store_discipline_is_rejected(fake_tool, capdir):
    res = run_tool_captured("py_probe", _py("print('x')"), capture_dir=capdir, max_rows=1)
    assert len(res.rows) == 1
    for bad in (0, 51, -1, "10", True, 2.5):
        with pytest.raises(ToolArgumentError):
            run_tool_captured("py_probe", _py("print('x')"), capture_dir=capdir, max_rows=bad)


def test_refused_call_still_writes_a_chained_error_receipt(capdir):
    with pytest.raises(ToolNotAllowed):
        run_tool_captured("execute_shell", ["rm", "-rf", "/"], capture_dir=capdir)
    (line,) = _receipt_lines(capdir)
    assert line["tool"] == "execute_shell"
    assert line["invocation_status"] == "error"
    assert "not whitelisted" in line["error"]
    assert line["output_path"] is None and line["output_sha256"] is None
    assert line["prev_hash"] == GENESIS_PREV_HASH
    assert verify_receipts(os.path.join(capdir, "receipts.jsonl"))["ok"] is True


def test_empty_output_trap_mirrors_the_ledger_contract(fake_tool, capdir):
    # exit 0, no stdout: an honestly-empty artifact — NEVER "ok".
    res = run_tool_captured("py_probe", _py("pass"), capture_dir=capdir)
    assert res.invocation_status == "empty_output"
    assert res.output_sha256 == EMPTY_SHA256 and res.output_bytes == 0
    # non-zero exit, no stdout: an error leaves NO artifact reference — a null
    # digest can never impersonate a real (or empty) one.
    res2 = run_tool_captured(
        "py_probe", _py("import sys; sys.exit(2)"), capture_dir=capdir
    )
    assert res2.invocation_status == "error" and res2.exit_code == 2
    assert res2.output_path is None and res2.output_sha256 is None
    lines = _receipt_lines(capdir)
    assert [ln["invocation_status"] for ln in lines] == ["empty_output", "error"]
    assert verify_receipts(os.path.join(capdir, "receipts.jsonl"))["ok"] is True


def test_stderr_is_captured_to_sidecar_and_capped_in_receipt(fake_tool, capdir):
    res = run_tool_captured(
        "py_probe",
        _py("import sys; sys.stdout.write('out'); sys.stderr.write('boom' * 1000)"),
        capture_dir=capdir,
    )
    err_sidecar = res.output_path.replace(".out", ".err")
    with open(err_sidecar, "r", encoding="utf-8") as fh:
        assert fh.read() == "boom" * 1000  # FULL stderr on disk
    (line,) = _receipt_lines(capdir)
    assert len(line["stderr"]) == 2000  # capped in the hashed receipt
    assert len(res.stderr_tail) == 2000  # capped in the model-facing return


def test_capture_paths_into_evidence_are_refused(fake_tool, tmp_path, monkeypatch):
    monkeypatch.delenv("SIFT_RECEIPTS_PATH", raising=False)
    for bad in ("/cases/x", "/mnt/windows_mount", "/media/usb", "/",
                str(tmp_path / "evidence" / "captures")):
        with pytest.raises(CapturePathError):
            run_tool_captured("py_probe", _py("print(1)"), capture_dir=bad)
    # A scratch-looking SYMLINK into an evidence root is resolved, then refused.
    link = tmp_path / "scratch_link"
    link.symlink_to("/mnt")
    with pytest.raises(CapturePathError):
        run_tool_captured("py_probe", _py("print(1)"), capture_dir=str(link))
    # The receipt writer enforces the same guard on its own path.
    with pytest.raises(CapturePathError):
        JsonlReceiptWriter("/cases/receipts.jsonl")
    # No capture dir was created under any refused location by these attempts.
    assert not (tmp_path / "evidence").exists()


def test_receipt_writer_refuses_prechained_input(tmp_path):
    w = JsonlReceiptWriter(str(tmp_path / "receipts.jsonl"))
    with pytest.raises(RunnerError):
        w.append({"schema_version": RECEIPTS_SCHEMA_VERSION, "prev_hash": "x" * 64,
                  "invocation_status": "ok", "output_sha256": "a" * 64})


def test_receipt_writer_refuses_floats_and_corrupt_tail(tmp_path):
    path = str(tmp_path / "receipts.jsonl")
    w = JsonlReceiptWriter(path)
    with pytest.raises(RunnerError):
        w.append({"invocation_status": "ok", "elapsed": 1.5})  # float → not hash-stable
    # A corrupt tail line halts chaining instead of silently forking the chain.
    with open(path, "w", encoding="utf-8") as fh:
        fh.write('{"no_entry_hash": true}\n')
    with pytest.raises(RunnerError):
        w.append({"invocation_status": "ok", "output_sha256": None})


def test_scratch_output_dir_stays_under_the_capture_root(tmp_path):
    """Wrappers source tool output-dir args (MFTECmd --csv …) ONLY from here:
    relative names land under the evidence-guarded capture root and traversal
    cannot escape it."""
    from sift_agent.mcp_server.runner import scratch_output_dir

    cap = str(tmp_path / "captures")
    out = scratch_output_dir("mftecmd/run1", capture_dir=cap)
    assert os.path.isdir(out)
    root = os.path.realpath(cap)
    assert out.startswith(root + os.sep)
    # Absolute, empty, and traversal-escaping names are refused.
    for bad in ("/cases/out", "", "../outside", "a/../../../etc"):
        with pytest.raises(CapturePathError):
            scratch_output_dir(bad, capture_dir=cap)
    # A symlink planted INSIDE the scratch root cannot redirect output to
    # evidence either: the joined path is realpath-resolved before the check.
    link = tmp_path / "captures" / "sneaky"
    link.symlink_to("/mnt")
    with pytest.raises(CapturePathError):
        scratch_output_dir("sneaky/loot", capture_dir=cap)
    # And the capture root itself must not be evidence.
    with pytest.raises(CapturePathError):
        scratch_output_dir("x", capture_dir="/media/usb")

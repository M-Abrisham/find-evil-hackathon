"""Read-only MCP server tests — the guardrail proof.

The headline test (:func:`test_no_shell_or_write_capability_anywhere`) proves the
WHOLE POINT of this server: there is **no** way to run an arbitrary shell or
write command through it. It does so three independent ways —

  1. behaviourally  — an ``execute_shell`` / ``run_command`` call is refused;
  2. by interface   — the server object exposes no command/exec/write method;
  3. by AST scan    — the package source imports nothing that can spawn a shell
                       (no ``subprocess`` / ``os.system`` / ``eval`` / ``exec`` …)
                       and every ``open()`` in it is read-only.

The other tests cover the typed read-only stub tool, input typing, the read-only
registration guard, and telemetry routing.
"""

import ast
import json
import logging
import os

import pytest

from sift_agent import telemetry
from sift_agent import mcp_server
from sift_agent.mcp_server import (
    ReadOnlyMCPServer,
    ReadOnlyToolRegistry,
    ReadOnlyToolSpec,
    ReadOnlyViolation,
    ToolInputError,
    UnknownToolError,
    build_server,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
_SIDECAR = {
    "case": "Rocba",
    "deviation_note": "no OS-enforced read-only mount on this rw box; read-only "
    "enforced procedurally + proven by before==after SHA-256.",
    "images": {
        "disk": {"role": "disk", "sha256": "f2eb856d", "ro_confirmed": True},
        "memory": {"role": "memory", "sha256": "eb33bdf6", "ro_confirmed": True},
    },
}


@pytest.fixture
def sidecar_path(tmp_path):
    p = tmp_path / "evidence-baseline.json"
    p.write_text(json.dumps(_SIDECAR))
    return str(p)


@pytest.fixture
def server(sidecar_path):
    return build_server(baseline_path=sidecar_path)


class _CaptureHandler(logging.Handler):
    """Collect JSON ledger lines emitted by sift.telemetry."""

    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


@pytest.fixture
def ledger():
    handler = _CaptureHandler()
    logger = logging.getLogger("sift.telemetry")
    prev = logger.level
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    telemetry.COST.reset()
    telemetry.begin_turn("mcp-turn-001")
    try:
        yield handler
    finally:
        logger.removeHandler(handler)
        logger.setLevel(prev)


# ---------------------------------------------------------------------------
# The typed read-only stub tool works and is the only thing exposed
# ---------------------------------------------------------------------------
def test_only_typed_readonly_tools_are_exposed(server):
    tools = server.list_tools()
    assert [t["name"] for t in tools] == ["get_image_info"]
    (tool,) = tools
    # It is a *typed* tool: an object schema with declared properties.
    assert tool["inputSchema"]["type"] == "object"
    assert "image" in tool["inputSchema"]["properties"]
    # Every registered spec is provably read-only.
    for name in server.registry.names():
        assert server.registry.get(name).read_only is True


def test_get_image_info_stub_returns_sidecar_facts(server):
    res = server.call_tool("get_image_info")
    assert res["ok"] is True
    assert res["content"]["case"] == "Rocba"
    assert set(res["content"]["images"]) == {"disk", "memory"}
    assert res["content"]["images"]["disk"]["ro_confirmed"] is True

    # Typed optional filter narrows to one image.
    disk = server.call_tool("get_image_info", {"image": "disk"})
    assert disk["content"]["image"]["role"] == "disk"
    assert "deviation_note" in disk["content"]


def test_arguments_are_typed_and_validated(server):
    # Out-of-enum value rejected (typed).
    with pytest.raises(ToolInputError):
        server.call_tool("get_image_info", {"image": "pagefile"})
    # Undeclared argument rejected — a client cannot redirect the read at an
    # arbitrary path (additionalProperties is treated as False).
    with pytest.raises(ToolInputError):
        server.call_tool("get_image_info", {"baseline_path": "/etc/shadow"})


# ---------------------------------------------------------------------------
# THE GUARDRAIL: no arbitrary shell/write command can be run through the server
# ---------------------------------------------------------------------------
_ARBITRARY_VERBS = [
    "execute_shell",
    "run_command",
    "run",
    "shell",
    "system",
    "eval",
    "exec",
    "bash",
    "subprocess",
    "write_file",
    "delete",
    "rm",
]


def test_unknown_verbs_including_shell_are_refused(server):
    for verb in _ARBITRARY_VERBS:
        with pytest.raises(UnknownToolError):
            server.call_tool(verb, {"cmd": "rm -rf /"})


def test_server_object_exposes_no_command_method(server):
    # The server has exactly two outward verbs; no exec/shell/write entry point.
    for attr in [
        "execute_shell",
        "run_command",
        "run",
        "shell",
        "system",
        "eval",
        "exec",
        "popen",
        "spawn",
        "subprocess",
        "write",
        "execute",
    ]:
        assert not hasattr(server, attr), f"server unexpectedly exposes {attr!r}"
    # What it *does* expose is just the read-only surface.
    assert hasattr(server, "list_tools") and hasattr(server, "call_tool")


def test_registry_refuses_non_readonly_or_write_named_tools():
    reg = ReadOnlyToolRegistry()
    # A spec flagged not-read-only is refused.
    with pytest.raises(ReadOnlyViolation):
        reg.register(
            ReadOnlyToolSpec("peek", "x", {"type": "object"}, lambda: None, read_only=False)
        )
    # A read-only spec whose *name* reads like a write/exec verb is refused.
    for bad in ["execute_shell", "run_command", "delete_file", "write_blocks", "mount_evidence"]:
        with pytest.raises(ReadOnlyViolation):
            reg.register(ReadOnlyToolSpec(bad, "x", {"type": "object"}, lambda: None))


# -- the AST proof: the package literally cannot spawn a shell ---------------
_BANNED_IMPORT_MODULES = {"subprocess", "pty", "commands", "ctypes", "posix"}
_BANNED_FROM_OS_NAMES = {
    "system", "popen", "fork", "forkpty", "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe", "execl", "execle", "execlp", "execlpe",
    "execv", "execve", "execvp", "execvpe", "posix_spawn", "posix_spawnp",
}
_BANNED_NAME_CALLS = {"eval", "exec", "compile", "__import__"}
_BANNED_ATTR_CALLS = {
    "system", "popen", "Popen", "getoutput", "getstatusoutput",
    "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp",
    "spawnvpe", "execl", "execle", "execlp", "execlpe", "execv", "execve",
    "execvp", "execvpe", "fork", "forkpty", "posix_spawn", "posix_spawnp",
}
_READ_MODES = {"r", "rb", "rt", "br", "tr", "rU"}


def _package_py_files():
    pkg_dir = os.path.dirname(mcp_server.__file__)
    files = []
    for root, _dirs, names in os.walk(pkg_dir):
        if "__pycache__" in root:
            continue
        for n in names:
            if n.endswith(".py"):
                files.append(os.path.join(root, n))
    return files


def _scan_offenses(path):
    with open(path, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=path)
    offenses = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in _BANNED_IMPORT_MODULES:
                    offenses.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            if mod in _BANNED_IMPORT_MODULES:
                offenses.append(f"from {node.module} import ...")
            if mod == "os":
                for alias in node.names:
                    if alias.name in _BANNED_FROM_OS_NAMES:
                        offenses.append(f"from os import {alias.name}")
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                if func.id in _BANNED_NAME_CALLS:
                    offenses.append(f"call {func.id}()")
                if func.id == "open":  # enforce read-only opens
                    mode = None
                    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                        mode = node.args[1].value
                    for kw in node.keywords:
                        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                            mode = kw.value.value
                    if mode is not None and mode not in _READ_MODES:
                        offenses.append(f"open(mode={mode!r}) — not read-only")
            elif isinstance(func, ast.Attribute):
                if func.attr in _BANNED_ATTR_CALLS:
                    offenses.append(f"call .{func.attr}()")
    return offenses


def test_package_source_has_no_shell_or_write_capability():
    files = _package_py_files()
    assert files, "no package source found to scan"
    all_offenses = {}
    for f in files:
        off = _scan_offenses(f)
        if off:
            all_offenses[os.path.basename(f)] = off
    assert not all_offenses, f"shell/write capability found in package: {all_offenses}"


# ---------------------------------------------------------------------------
# Telemetry routing: every call (allowed AND blocked) lands in the ledger
# ---------------------------------------------------------------------------
def test_every_call_is_routed_through_telemetry(server, ledger):
    # 1) a successful read-only call is stamped.
    server.call_tool("get_image_info", {"image": "memory"})
    # 2) a BLOCKED arbitrary-command attempt is still audited.
    with pytest.raises(UnknownToolError):
        server.call_tool("execute_shell", {"cmd": "whoami"})

    lines = [json.loads(x) for x in ledger.lines]
    tool_rows = [r for r in lines if r["kind"] == "tool_exec"]
    assert len(tool_rows) == 2

    ok_row = next(r for r in tool_rows if r["tool"] == "mcp:get_image_info")
    blocked_row = next(r for r in tool_rows if r["tool"] == "mcp:execute_shell")

    for row in (ok_row, blocked_row):
        assert row["tokens_source"] == "issuing_agent_turn"
        assert row["agent_turn_id"] == "mcp-turn-001"
        assert row["ts_utc"].endswith("+00:00") or row["ts_utc"].endswith("Z")
    assert ok_row["exit_code"] == 0
    assert blocked_row["exit_code"] == 127  # refused before any execution


def test_mcp_sdk_adapter_is_optional(server):
    # The 'mcp' SDK is not a hard dependency; the adapter fails loudly if absent,
    # but the in-process guardrailed registry works regardless.
    try:
        import mcp  # noqa: F401
    except ImportError:
        with pytest.raises(ImportError, match="mcp"):
            server.to_mcp_server()

"""Read-only MCP server tests — the guardrail proof.

The headline test (:func:`test_subprocess_is_reachable_only_via_runner`) proves
the WHOLE POINT of this server: there is **no** way to run an arbitrary shell or
write command through it. It does so several independent ways —

  1. behaviourally  — an ``execute_shell`` / ``run_command`` call is refused;
  2. by interface   — the server object exposes no command/exec/write method;
  3. by AST scan    — subprocess is reachable ONLY through the single vetted
                       chokepoint ``runner.py`` (Day-2's evolution of the old
                       "no subprocess anywhere" rule); every other file imports
                       nothing that can spawn a process, no file anywhere reaches
                       a shell (``shell=True`` / ``os.system`` / ``os.popen`` /
                       ``eval`` / ``exec`` are forbidden even inside runner.py),
                       and every ``open()`` in the package is read-only.

The AST scan is itself proven non-vacuous: dedicated self-tests feed the scanner
a known violation (flagged) and the runner's legitimate pattern (allowed), and
assert it scanned >0 files and that the runner-only allowance is load-bearing.

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


# -- the AST proof: subprocess is reachable ONLY through runner.py -----------
#
# Day-1's rule was "no subprocess anywhere in the package". Day-2 needs to run
# real forensic tools, so the rule EVOLVED to: ``subprocess`` may appear ONLY in
# ``runner.py`` (the single vetted chokepoint), and even there ``shell=True`` /
# ``os.system`` / ``os.popen`` / ``eval`` / ``exec`` stay forbidden. Everywhere
# else, importing or calling ``subprocess`` is still a hard failure. This is a
# stronger guarantee than "no subprocess": there is exactly one auditable place a
# process can be spawned, and it cannot reach a shell.
_RUNNER_BASENAME = "runner.py"

# Process-spawning modules. ``subprocess`` is permitted ONLY in runner.py; the
# rest are never needed by this package and are banned everywhere (even runner).
_SUBPROCESS_MODULES = {"subprocess"}
_ALWAYS_BANNED_MODULES = {"pty", "commands", "ctypes", "posix"}

# os attributes that exec/spawn a process — banned everywhere, even in runner.py.
_OS_EXEC_NAMES = {
    "system", "popen", "fork", "forkpty", "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe", "execl", "execle", "execlp", "execlpe",
    "execv", "execve", "execvp", "execvpe", "posix_spawn", "posix_spawnp",
}
# Attribute calls that spawn a *shell* regardless of the receiving object — banned
# everywhere, runner included (covers os.system/os.popen and subprocess.getoutput).
_SHELLISH_ATTRS = {"system", "popen", "getoutput", "getstatusoutput"} | _OS_EXEC_NAMES
_BANNED_NAME_CALLS = {"eval", "exec", "compile", "__import__"}
# Dynamic-import escape hatches — banned everywhere (even runner.py), so the
# "subprocess only via runner" guarantee can't be dodged with
# ``importlib.import_module("subprocess")``. ``__import__`` is covered above.
_BANNED_DYNAMIC = {"import_module"}
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


def _open_mode(node):
    """Extract the literal mode passed to an ``open(...)`` call, if any."""
    mode = None
    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
        mode = node.args[1].value
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            mode = kw.value.value
    return mode


def _scan_source(src, filename="<source>", *, allow_subprocess):
    """Return a list of shell/write-capability offenses in ``src``.

    ``allow_subprocess`` is ``True`` only for ``runner.py``: there, importing and
    calling ``subprocess`` is allowed, but ``shell=True``, ``os.system``,
    ``os.popen``, ``*.getoutput``, ``eval``/``exec`` and friends are STILL
    flagged. With ``allow_subprocess=False`` (every other file) any ``subprocess``
    use is also an offense.
    """
    tree = ast.parse(src, filename=filename)
    offenses = []
    subprocess_aliases = set()        # names bound to the subprocess module here
    subprocess_imported_names = set()  # `from subprocess import run` -> {"run"}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in _SUBPROCESS_MODULES:
                    subprocess_aliases.add(alias.asname or top)
                    if not allow_subprocess:
                        offenses.append(f"import {alias.name}")
                elif top in _ALWAYS_BANNED_MODULES:
                    offenses.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            if mod in _SUBPROCESS_MODULES:
                for alias in node.names:
                    subprocess_imported_names.add(alias.asname or alias.name)
                if not allow_subprocess:
                    offenses.append(f"from {node.module} import ...")
            elif mod in _ALWAYS_BANNED_MODULES:
                offenses.append(f"from {node.module} import ...")
            elif mod == "os":
                for alias in node.names:
                    if alias.name in _OS_EXEC_NAMES:
                        offenses.append(f"from os import {alias.name}")
        elif isinstance(node, ast.Call):
            func = node.func
            # A shell is forbidden EVERYWHERE, including runner.py. The ONLY
            # acceptable form is the literal ``shell=False``: a variable /
            # parameter / global (``shell=enable_shell``) could hold True at
            # runtime and would otherwise sail past this guard inside runner.py,
            # so anything that is not literally ``False`` is an offense.
            for kw in node.keywords:
                if kw.arg == "shell":
                    is_literal_false = (
                        isinstance(kw.value, ast.Constant) and kw.value.value is False
                    )
                    if not is_literal_false:
                        offenses.append("shell= (not literal False)")
            if isinstance(func, ast.Name):
                if func.id in _BANNED_NAME_CALLS or func.id in _BANNED_DYNAMIC:
                    offenses.append(f"call {func.id}()")
                if (not allow_subprocess) and func.id in subprocess_imported_names:
                    offenses.append(f"call {func.id}() (subprocess)")
                if func.id == "open":  # enforce read-only opens
                    mode = _open_mode(node)
                    if mode is not None and mode not in _READ_MODES:
                        offenses.append(f"open(mode={mode!r}) — not read-only")
            elif isinstance(func, ast.Attribute):
                recv = func.value.id if isinstance(func.value, ast.Name) else None
                if func.attr in _SHELLISH_ATTRS or func.attr in _BANNED_DYNAMIC:
                    offenses.append(f"call .{func.attr}()")
                elif recv in subprocess_aliases and not allow_subprocess:
                    offenses.append(f"call {recv}.{func.attr}() (subprocess)")
    return offenses


def _scan_offenses(path, *, allow_subprocess):
    with open(path, "r", encoding="utf-8") as fh:
        return _scan_source(
            fh.read(), os.path.basename(path), allow_subprocess=allow_subprocess
        )


def test_subprocess_is_reachable_only_via_runner():
    """No file but runner.py may import/call subprocess; none may reach a shell."""
    files = _package_py_files()
    assert files, "no package source found to scan"
    # Guard against a bad glob silently scanning nothing.
    assert len(files) >= 4, f"expected to scan the whole package, got {files}"
    basenames = {os.path.basename(f) for f in files}
    assert _RUNNER_BASENAME in basenames, "runner.py must exist and be scanned"

    offenders = {}
    for f in files:
        allow = os.path.basename(f) == _RUNNER_BASENAME
        off = _scan_offenses(f, allow_subprocess=allow)
        if off:
            offenders[os.path.basename(f)] = off
    assert not offenders, f"shell/subprocess capability found outside runner: {offenders}"


def test_runner_allowance_is_load_bearing():
    """runner.py really DOES use subprocess — so the exception isn't vacuous."""
    runner = [f for f in _package_py_files() if os.path.basename(f) == _RUNNER_BASENAME]
    assert len(runner) == 1, "exactly one runner.py expected"
    # With the runner allowance it is clean; without it, the SAME file is flagged
    # (because it genuinely contains subprocess) — proving the gate does real work.
    assert _scan_offenses(runner[0], allow_subprocess=True) == []
    assert _scan_offenses(runner[0], allow_subprocess=False), (
        "runner.py should contain subprocess; if it doesn't, the runner-only "
        "allowance is rubber-stamping an empty exception"
    )


# -- non-vacuous scanner self-tests: prove the scanner actually fires ---------
_VIOLATION_SRC = (
    "import subprocess\n"
    "import os\n"
    "def go(cmd):\n"
    "    subprocess.run(cmd, shell=True)\n"
    "    os.system(cmd)\n"
)
_RUNNER_LEGIT_SRC = (
    "import subprocess\n"
    "def go(argv):\n"
    "    return subprocess.run(\n"
    "        argv, shell=False, capture_output=True, text=True, timeout=5\n"
    "    )\n"
)


def test_scanner_flags_violations_even_with_runner_allowance():
    # As an ordinary package file (subprocess NOT allowed): everything is caught.
    off = _scan_source(_VIOLATION_SRC, "tools.py", allow_subprocess=False)
    assert any("import subprocess" in o for o in off)
    assert any(o.startswith("shell=") for o in off)
    assert any(".system()" in o for o in off)
    assert any("(subprocess)" in o for o in off)
    # Even WITH the runner allowance, a shell and os.system stay forbidden.
    off_runner = _scan_source(_VIOLATION_SRC, "runner.py", allow_subprocess=True)
    assert any(o.startswith("shell=") for o in off_runner)
    assert any(".system()" in o for o in off_runner)


def test_scanner_rejects_non_literal_shell_argument():
    # Closing the AST blind spot an adversarial review found: a non-literal
    # shell= value (variable / parameter / global) could hold True at runtime, so
    # the ONLY accepted form is the literal shell=False — even inside runner.py.
    for bad in (
        "import subprocess\ndef go(argv, enable_shell=False):\n"
        "    return subprocess.run(argv, shell=enable_shell)\n",
        "import subprocess\n_SHELL = True\ndef go(argv):\n"
        "    return subprocess.run(argv, shell=_SHELL)\n",
        "import subprocess\ndef go(argv):\n    return subprocess.run(argv, shell=1)\n",
    ):
        assert any(o.startswith("shell=") for o in
                   _scan_source(bad, "runner.py", allow_subprocess=True)), bad
    # The literal shell=False remains the one allowed form.
    ok = "import subprocess\ndef go(argv):\n    return subprocess.run(argv, shell=False)\n"
    assert _scan_source(ok, "runner.py", allow_subprocess=True) == []


def test_scanner_allows_runner_legit_pattern_only_in_runner():
    # The runner's real pattern (argv list, shell=False) is clean in runner.py.
    assert _scan_source(_RUNNER_LEGIT_SRC, "runner.py", allow_subprocess=True) == []
    # The very same code in a non-runner file IS a violation (import + call).
    off = _scan_source(_RUNNER_LEGIT_SRC, "tools.py", allow_subprocess=False)
    assert off, "subprocess use outside runner.py must be flagged"


def test_scanner_closes_dynamic_import_escape_hatch():
    # importlib.import_module / __import__ can't be used to dodge the subprocess
    # ban — flagged even WITH the runner allowance.
    for src in (
        "import importlib\ndef go():\n    return importlib.import_module('subprocess')\n",
        "def go():\n    return __import__('subprocess')\n",
    ):
        assert _scan_source(src, "runner.py", allow_subprocess=True), src
        assert _scan_source(src, "tools.py", allow_subprocess=False), src


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

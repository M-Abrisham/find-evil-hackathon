"""Read-only MCP server tests — the guardrail proof.

The headline test (:func:`test_subprocess_is_reachable_only_via_runner`) proves
the WHOLE POINT of this server: there is **no** way to run an arbitrary shell or
write command through it. It does so several independent ways —

  1. behaviourally  — an ``execute_shell`` / ``run_command`` call is refused;
  2. by interface   — the server object exposes no command/exec/write method;
  3. by AST scan    — subprocess is reachable ONLY through the single vetted
                       chokepoint ``runner.py`` (Day-2's evolution of the old
                       "no subprocess anywhere" rule), scanned over the WHOLE
                       ``sift_agent`` package; every other file imports nothing
                       that can spawn a process, no file anywhere reaches a
                       shell (``shell=True`` / ``os.system`` / ``os.popen`` /
                       ``eval`` / ``exec`` are forbidden even inside runner.py),
                       and every ``open()`` outside runner.py is read-only
                       (runner.py alone may write — capture files + receipt
                       lines — and its targets are runtime-guarded against
                       evidence paths);
  4. by verb surface — no registered MCP tool name, whitelisted tool key, or
                       outward server attribute reads as a destructive verb.

The AST scan is itself proven non-vacuous several ways: self-tests feed the
scanner known violations (flagged) and the runner's legitimate pattern
(allowed); the runner-only allowance is shown to be load-bearing; and a planted
KNOWN-BAD fixture module (``tests/fixtures/planted_subprocess_violation.py``)
is copied into a replica of the real package tree and the SAME tree-walk scan
used by the headline test must catch it — a guard that passes a tree containing
that file would be worthless, and this proves ours doesn't.

The other tests cover the typed read-only stub tool, input typing, the read-only
registration guard, and telemetry routing.
"""

import ast
import json
import logging
import os
import re
import shutil

import pytest

import sift_agent
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
# everywhere, runner included (covers os.system/os.popen, subprocess.getoutput,
# and asyncio's subprocess spawners, which an adversarial bypass review found
# would otherwise slip past a scan focused on the ``subprocess`` module alone).
_SHELLISH_ATTRS = {
    "system", "popen", "getoutput", "getstatusoutput",
    "create_subprocess_shell", "create_subprocess_exec",
    "subprocess_shell", "subprocess_exec",
} | _OS_EXEC_NAMES
# ``setattr``/``vars``/``globals`` are banned with eval/exec: they are the
# remaining syntax for rebinding the runner's whitelist from another module
# (``setattr(runner, "BINARY_WHITELIST", …)``); nothing in this package needs them.
_BANNED_NAME_CALLS = {"eval", "exec", "compile", "__import__", "setattr", "delattr",
                      "vars", "globals"}
# Dynamic-import escape hatches — banned everywhere (even runner.py), so the
# "subprocess only via runner" guarantee can't be dodged with
# ``importlib.import_module("subprocess")`` or ``importlib.__import__(...)``
# (the attribute form of ``__import__`` — the Name form is banned above).
_BANNED_DYNAMIC = {"import_module", "__import__"}
_READ_MODES = {"r", "rb", "rt", "br", "tr", "rU"}

# Write capability beyond builtin ``open()`` — flagged outside runner.py (the
# bypass review found ``Path.write_text`` / ``os.remove`` / ``shutil.rmtree``
# would slip past a mode-string check on ``open`` alone). Receiver-aware where a
# bare attribute name would collide with harmless methods (``list.remove``,
# ``str.replace``); unconditional where it cannot (``write_text``).
_WRITE_ATTRS_ANY_RECV = {"write_text", "write_bytes", "unlink", "rmdir", "touch"}
_OS_WRITE_NAMES = {
    "remove", "unlink", "rename", "renames", "replace", "truncate", "chmod",
    "chown", "rmdir", "removedirs", "makedirs", "mkdir", "symlink", "link",
    "mknod", "open",
}
_SHUTIL_WRITE_NAMES = {"rmtree", "copyfile", "copy", "copy2", "copytree", "move",
                       "chown", "make_archive", "unpack_archive"}

# The runner's whitelist must not be MUTATED from any other module — adding a
# launcher at runtime (``BINARY_WHITELIST["sh"] = …``) would bypass the closed
# set without ever importing subprocess. Runtime already refuses (it is a
# MappingProxyType); this makes the *syntax* a build failure too.
_PROTECTED_GLOBALS = {"BINARY_WHITELIST", "WHITELISTED_TOOLS", "_RECIPES"}
_DICT_MUTATORS = {"update", "setdefault", "pop", "popitem", "clear", "__setitem__"}


def _package_py_files(pkg_dir=None):
    """Every .py file under the WHOLE ``sift_agent`` package (not just the
    mcp_server subpackage) — or under an explicit ``pkg_dir`` so the planted-
    violation self-test can aim the SAME walk at a replica tree."""
    if pkg_dir is None:
        pkg_dir = os.path.dirname(sift_agent.__file__)
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


def _scan_source(src, filename="<source>", *, allow_subprocess, allow_write_open=False):
    """Return a list of shell/write-capability offenses in ``src``.

    ``allow_subprocess`` is ``True`` only for ``runner.py``: there, importing and
    calling ``subprocess`` is allowed, but ``shell=True``, ``os.system``,
    ``os.popen``, ``*.getoutput``, ``eval``/``exec`` and friends are STILL
    flagged. With ``allow_subprocess=False`` (every other file) any ``subprocess``
    use is also an offense.

    ``allow_write_open`` is likewise ``True`` only for ``runner.py``, which must
    write capture files + receipt lines (to runtime-guarded scratch paths, never
    evidence — see ``runner._refuse_evidence_path``). Everywhere else ANY write
    capability is an offense: a write-mode ``open()``, the ``os``/``shutil``/
    ``pathlib`` write calls, and mutation of the runner's whitelist globals.
    The rest of the package is read-only by construction.

    Threat model (stated honestly): an AST scan catches capability creep and
    plainly-written bypasses; it cannot decide what obfuscated code does at
    runtime (no static scan can). It is one layer — the typed registry, the
    closed whitelist (a runtime ``MappingProxyType``), the evidence-path guard,
    and review are the others.
    """
    tree = ast.parse(src, filename=filename)
    offenses = []
    subprocess_aliases = set()        # names bound to the subprocess module here
    subprocess_imported_names = set()  # `from subprocess import run` -> {"run"}
    protected_local = set(_PROTECTED_GLOBALS)  # incl. `... import X as Y` aliases

    def _touches_protected(target):
        """True if an assignment/delete target reaches a protected global."""
        if isinstance(target, (ast.Tuple, ast.List)):
            return any(_touches_protected(t) for t in target.elts)
        if isinstance(target, ast.Starred):
            return _touches_protected(target.value)
        if isinstance(target, ast.Name):
            return target.id in protected_local
        if isinstance(target, ast.Attribute):
            return target.attr in _PROTECTED_GLOBALS
        if isinstance(target, ast.Subscript):
            base = target.value
            if isinstance(base, ast.Name):
                return base.id in protected_local
            if isinstance(base, ast.Attribute):
                # runner.BINARY_WHITELIST[...] and runner.__dict__[...]
                return base.attr in _PROTECTED_GLOBALS or base.attr == "__dict__"
        return False

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
                    elif alias.name in _OS_WRITE_NAMES and not allow_write_open:
                        offenses.append(f"from os import {alias.name} (write)")
            elif mod == "shutil" and not allow_write_open:
                for alias in node.names:
                    if alias.name in _SHUTIL_WRITE_NAMES:
                        offenses.append(f"from shutil import {alias.name} (write)")
            # Track aliasing of the protected whitelist globals so
            # `from .runner import BINARY_WHITELIST as W; W[...] = …` is caught.
            for alias in node.names:
                if alias.name in _PROTECTED_GLOBALS:
                    protected_local.add(alias.asname or alias.name)
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Delete)):
            if not allow_write_open:  # runner.py owns (and builds) the whitelist
                targets = (
                    node.targets if isinstance(node, (ast.Assign, ast.Delete))
                    else [node.target]
                )
                for t in targets:
                    if _touches_protected(t):
                        offenses.append("whitelist mutation (assignment/delete)")
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
                if func.id == "open" and not allow_write_open:
                    # enforce read-only opens everywhere but runner.py
                    mode = _open_mode(node)
                    if mode is not None and mode not in _READ_MODES:
                        offenses.append(f"open(mode={mode!r}) — not read-only")
            elif isinstance(func, ast.Attribute):
                recv = func.value.id if isinstance(func.value, ast.Name) else None
                if func.attr in _SHELLISH_ATTRS or func.attr in _BANNED_DYNAMIC:
                    offenses.append(f"call .{func.attr}()")
                elif recv in subprocess_aliases and not allow_subprocess:
                    offenses.append(f"call {recv}.{func.attr}() (subprocess)")
                if not allow_write_open:
                    # Write capability beyond builtin open(): pathlib writers on
                    # any receiver; os/shutil writers on their module receiver.
                    if func.attr in _WRITE_ATTRS_ANY_RECV:
                        offenses.append(f"call .{func.attr}() (write)")
                    elif recv == "os" and func.attr in _OS_WRITE_NAMES:
                        offenses.append(f"call os.{func.attr}() (write)")
                    elif recv == "shutil" and func.attr in _SHUTIL_WRITE_NAMES:
                        offenses.append(f"call shutil.{func.attr}() (write)")
                    # Whitelist mutation via dict methods, plain or dotted:
                    # BINARY_WHITELIST.update(...) / runner.BINARY_WHITELIST.pop(...)
                    if func.attr in _DICT_MUTATORS:
                        base = func.value
                        if (isinstance(base, ast.Name) and base.id in protected_local) or (
                            isinstance(base, ast.Attribute)
                            and base.attr in _PROTECTED_GLOBALS
                        ):
                            offenses.append(
                                f"whitelist mutation (.{func.attr}())"
                            )
    return offenses


def _scan_offenses(path, *, allow_subprocess, allow_write_open=False):
    with open(path, "r", encoding="utf-8") as fh:
        return _scan_source(
            fh.read(),
            os.path.basename(path),
            allow_subprocess=allow_subprocess,
            allow_write_open=allow_write_open,
        )


def _scan_tree(pkg_dir=None):
    """Run the headline scan over a package tree; return {basename: offenses}.

    Factored out so the planted-violation self-test exercises the IDENTICAL
    walk + per-file policy that gates the real package.
    """
    files = _package_py_files(pkg_dir)
    assert files, "no package source found to scan"
    offenders = {}
    for f in files:
        allow = os.path.basename(f) == _RUNNER_BASENAME
        off = _scan_offenses(f, allow_subprocess=allow, allow_write_open=allow)
        if off:
            offenders[os.path.basename(f)] = off
    return files, offenders


def test_subprocess_is_reachable_only_via_runner():
    """No file but runner.py may import/call subprocess or open for write, in
    the WHOLE sift_agent package; no file anywhere may reach a shell."""
    files, offenders = _scan_tree()
    # Guard against a bad glob silently scanning nothing. The whole package =
    # sift_agent (__init__, finding, telemetry) + the mcp_server subpackage.
    assert len(files) >= 7, f"expected to scan the whole sift_agent package, got {files}"
    basenames = {os.path.basename(f) for f in files}
    assert _RUNNER_BASENAME in basenames, "runner.py must exist and be scanned"
    assert "telemetry.py" in basenames, "scan must cover sift_agent, not just mcp_server"
    assert not offenders, f"shell/subprocess/write capability found outside runner: {offenders}"


def test_runner_allowance_is_load_bearing():
    """runner.py really DOES use subprocess + write-mode open — so neither
    exception is vacuous."""
    runner = [f for f in _package_py_files() if os.path.basename(f) == _RUNNER_BASENAME]
    assert len(runner) == 1, "exactly one runner.py expected"
    # With the runner allowances it is clean; without them, the SAME file is
    # flagged (it genuinely contains subprocess AND write-mode opens for the
    # capture/receipt files) — proving each gate does real work.
    assert _scan_offenses(runner[0], allow_subprocess=True, allow_write_open=True) == []
    no_subprocess = _scan_offenses(runner[0], allow_subprocess=False, allow_write_open=True)
    assert any("subprocess" in o for o in no_subprocess), (
        "runner.py should contain subprocess; if it doesn't, the runner-only "
        "allowance is rubber-stamping an empty exception"
    )
    no_write = _scan_offenses(runner[0], allow_subprocess=True, allow_write_open=False)
    assert any(o.startswith("open(") for o in no_write), (
        "runner.py should contain write-mode opens (capture + receipts); if it "
        "doesn't, the write allowance is rubber-stamping an empty exception"
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


def test_scanner_flags_write_open_outside_runner_only():
    # The write-open allowance is runner-scoped: the same source is an offense
    # as an ordinary package file and clean only under the runner allowance.
    src = 'def save(p, data):\n    with open(p, "w") as fh:\n        fh.write(data)\n'
    off = _scan_source(src, "tools.py", allow_subprocess=False)
    assert any(o.startswith("open(") for o in off), off
    assert _scan_source(src, "runner.py", allow_subprocess=True, allow_write_open=True) == []
    # Read-only opens stay clean everywhere.
    ok = 'def load(p):\n    with open(p, "r") as fh:\n        return fh.read()\n'
    assert _scan_source(ok, "tools.py", allow_subprocess=False) == []


def test_scanner_closes_spawn_holes_found_by_bypass_review():
    """asyncio's process spawners and importlib.__import__ are banned EVERYWHERE
    (even runner.py): each would have been a working bypass of a scan focused on
    the ``subprocess`` module alone."""
    spawny = [
        "import asyncio\nasync def go(c):\n    await asyncio.create_subprocess_shell(c)\n",
        "import asyncio\nasync def go(c):\n    await asyncio.create_subprocess_exec(c)\n",
        "import importlib\ndef go():\n    return importlib.__import__('subprocess')\n",
    ]
    for src in spawny:
        assert _scan_source(src, "tools.py", allow_subprocess=False), src
        # no allowance legitimizes these — not even the runner's
        assert _scan_source(
            src, "runner.py", allow_subprocess=True, allow_write_open=True
        ), src


def test_scanner_flags_write_capability_beyond_builtin_open():
    """Path.write_text / os.remove / shutil.rmtree / os.open / `from os import
    unlink` are write capability even though no ``open(..., "w")`` appears —
    flagged outside runner.py, allowed inside it (runner legitimately makedirs)."""
    writey = [
        "from pathlib import Path\ndef go(p):\n    Path(p).write_text('x')\n",
        "import os\ndef go(p):\n    os.remove(p)\n",
        "import os\ndef go(p):\n    os.rename(p, p + '.bak')\n",
        "import os\ndef go(p):\n    os.open(p, 1)\n",
        "import shutil\ndef go(s, d):\n    shutil.rmtree(s)\n",
        "import shutil\ndef go(s, d):\n    shutil.copyfile(s, d)\n",
        "from os import unlink\n",
        "from shutil import rmtree\n",
    ]
    for src in writey:
        off = _scan_source(src, "tools.py", allow_subprocess=False)
        assert any("write" in o for o in off), (src, off)
        # The runner allowance covers them (its targets are runtime-guarded
        # against evidence paths by _refuse_evidence_path).
        assert _scan_source(
            src, "runner.py", allow_subprocess=True, allow_write_open=True
        ) == [], src
    # Read-only os/shutil/pathlib use stays clean everywhere.
    ok = (
        "import os, shutil\nfrom pathlib import Path\n"
        "def go(p):\n"
        "    return os.path.exists(p), shutil.which('fls'), Path(p).read_text()\n"
    )
    assert _scan_source(ok, "tools.py", allow_subprocess=False) == []


def test_scanner_flags_whitelist_mutation_outside_runner():
    """Adding a launcher at runtime (``BINARY_WHITELIST['sh'] = …``) would bypass
    the closed whitelist without importing subprocess — the exact hole the
    adversarial review found. Mutation SYNTAX is a build failure outside
    runner.py (runtime already refuses: the whitelist is a MappingProxyType)."""
    mutations = [
        "from sift_agent.mcp_server.runner import BINARY_WHITELIST\n"
        "BINARY_WHITELIST['sh'] = object()\n",
        # aliasing does not dodge the scan
        "from sift_agent.mcp_server.runner import BINARY_WHITELIST as W\n"
        "W['sh'] = object()\n",
        "from sift_agent.mcp_server.runner import BINARY_WHITELIST\n"
        "BINARY_WHITELIST.update({'sh': object()})\n",
        # rebinding the module attribute / its __dict__
        "from sift_agent.mcp_server import runner\nrunner.BINARY_WHITELIST = {}\n",
        "from sift_agent.mcp_server import runner\n"
        "runner.__dict__['BINARY_WHITELIST'] = {}\n",
        "from sift_agent.mcp_server import runner\n"
        "setattr(runner, 'BINARY_WHITELIST', {})\n",
        "from sift_agent.mcp_server import runner\ndel runner.BINARY_WHITELIST\n",
        "from sift_agent.mcp_server.runner import _RECIPES\n_RECIPES['sh'] = ()\n",
    ]
    for src in mutations:
        assert _scan_source(src, "tools.py", allow_subprocess=False), src
    # runner.py itself builds the whitelist — assignment there is legitimate.
    own = "BINARY_WHITELIST = _build_whitelist()\n"
    assert _scan_source(own, "runner.py", allow_subprocess=True, allow_write_open=True) == []
    # READING the whitelist anywhere is fine (that is the whole point of it).
    read = (
        "from sift_agent.mcp_server.runner import BINARY_WHITELIST\n"
        "def go(k):\n    return BINARY_WHITELIST[k]\n"
    )
    assert _scan_source(read, "tools.py", allow_subprocess=False) == []


# -- the planted KNOWN-BAD module: the tree-level non-vacuity proof ----------
_PLANTED_FIXTURE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "fixtures",
    "planted_subprocess_violation.py",
)


def test_planted_violation_in_a_package_replica_is_caught(tmp_path):
    """Copy the REAL package tree, plant the known-bad fixture inside, and run
    the IDENTICAL tree scan the headline test uses: it must fail loudly on the
    plant and pass once the plant is removed. A guard that passed a tree
    containing this module would be worthless — this proves ours doesn't."""
    pkg_dir = os.path.dirname(sift_agent.__file__)
    replica = tmp_path / "sift_agent_replica"
    shutil.copytree(
        pkg_dir, replica, ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
    )

    # 1) The clean replica passes — same verdict as the real tree.
    _files, offenders = _scan_tree(str(replica))
    assert not offenders, f"replica of the real tree should be clean: {offenders}"

    # 2) Plant the violation INSIDE the package (next to the typed tools, where
    #    a careless/with-malice change would actually land) and rescan.
    with open(_PLANTED_FIXTURE, "r", encoding="utf-8") as fh:
        bad_src = fh.read()
    plant = replica / "mcp_server" / "exfil_helper.py"
    plant.write_text(bad_src)
    files, offenders = _scan_tree(str(replica))
    assert str(plant) in files, "the planted module must be walked"
    assert "exfil_helper.py" in offenders, (
        "the tree scan FAILED to flag a planted subprocess/shell/write module — "
        "the guard is vacuous"
    )
    caught = offenders["exfil_helper.py"]
    assert any("import subprocess" in o for o in caught)
    assert any(o.startswith("shell=") for o in caught)
    assert any(".system()" in o for o in caught)
    assert any(o.startswith("open(") for o in caught)

    # 3) Even planted AS runner.py itself (maximum allowance), the shell and
    #    os.system offenses still fail the scan — the chokepoint cannot
    #    legitimize a shell.
    plant.unlink()
    runner_plant = replica / "mcp_server" / "runner.py"  # overwrite the replica's
    runner_plant.write_text(bad_src)
    _files, offenders = _scan_tree(str(replica))
    assert "runner.py" in offenders, "a shell inside runner.py must still fail"


# -- the public tool surface names no destructive verb ------------------------
_DESTRUCTIVE_VERBS = {
    "write", "delete", "remove", "rm", "unlink", "erase", "wipe", "shred",
    "mkfs", "format", "mount", "umount", "unmount", "chmod", "chown", "dd",
    "truncate", "kill", "move", "mv", "rename", "copy", "cp", "patch",
    "modify", "update", "set", "put", "create",
    "shell", "exec", "execute", "eval", "system", "popen", "spawn", "bash", "sh",
}


def _name_tokens(name):
    """camelCase/snake_case-aware word split, lowercased."""
    return {t.lower() for t in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z0-9]+", name)}


def test_public_tool_surface_names_no_destructive_verb(server):
    # (a) every registered MCP tool name
    mcp_names = [t["name"] for t in server.list_tools()]
    assert mcp_names, "expected at least one registered tool"
    # (b) every whitelisted runner tool key
    from sift_agent.mcp_server.runner import WHITELISTED_TOOLS

    surface = list(mcp_names) + list(WHITELISTED_TOOLS)
    for name in surface:
        hits = _name_tokens(name) & _DESTRUCTIVE_VERBS
        assert not hits, f"destructive verb {hits} in public tool surface name {name!r}"
    # (c) non-vacuity: the same check rejects what it must reject.
    for bad in ("write_file", "rm", "dd", "mount_rw", "format_disk", "execute_shell"):
        assert _name_tokens(bad) & _DESTRUCTIVE_VERBS, bad


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

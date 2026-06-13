#!/usr/bin/env python3
"""Tool-ACCESS failure classifier for Protocol SIFT traces.

``bashlog.outcome`` says a call ``errored`` — this module says WHY, for the one
class of error the eval loop must see explicitly: **the tool itself could not be
accessed** (as opposed to a tool that ran fine but errored on the evidence).

Reasons (the ``tool_unavailable`` vocabulary):

    command-not-found   the binary does not exist on the box ("command not found")
    broken-import       the tool launched but its runtime deps are broken
                        (e.g. mac_apt -> ModuleNotFoundError: kaitaistruct)
    missing-library     dynamic linker failure (".so: cannot open shared object")
    gui-no-display      a GUI tool was invoked in the headless session
                        ("cannot open display", qt.qpa.xcb, Gtk-WARNING)
    exec-permission     the command path exists but is not executable
    network-blocked     the tool needed egress and the sandbox denied it
                        ("Could not resolve host", "Network is unreachable")

Why this matters: ``reconcile_playbook.py`` catches absent tools STATICALLY
(before a run); this catches them AT RUNTIME in the playground — including
failures reconcile can't see (a GUI tool invoked headless, a dep broken since
verification, egress blocks). Each failure lands on the Braintrust span as a
``tool_unavailable:<token>`` tag + ``metadata.enrich.tool_access``, and on the
root span as a rollup, so "the agent reached for a tool it couldn't use" is
filterable in the log traces instead of buried in stderr text.

Deliberately conservative (same philosophy as ``bashlog._ERROR_PATTERNS``):
only signatures that almost certainly mean the TOOL was inaccessible, never
generic errors. stdlib-only.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

try:  # package-relative first (same convention as enrich.py)
    from . import registry  # type: ignore
except Exception:  # pragma: no cover - standalone fallback
    import registry  # type: ignore

# Each rule: (reason, compiled regex). Group "tok" captures the failing tool
# token when the message names one. Order matters — first match per line wins,
# most specific first.
_RULES: List[tuple] = [
    # bash/sh/zsh: "bash: line 1: PECmd: command not found" / "sh: 1: vol2: not found"
    ("command-not-found",
     re.compile(r"^(?:bash|sh|zsh|/bin/\w+)?[: ]*(?:line \d+[: ]*|\d+[: ]*)?"
                r"(?P<tok>[\w./+-]+):\s*(?:command )?not found\s*$",
                re.IGNORECASE | re.MULTILINE)),
    # env/which style: "env: 'vss_carver': No such file or directory"
    ("command-not-found",
     re.compile(r"^env: '?(?P<tok>[\w./+-]+)'?: No such file or directory",
                re.IGNORECASE | re.MULTILINE)),
    # python tool with broken deps (the mac_apt kaitaistruct case)
    ("broken-import",
     re.compile(r"\b(?:ModuleNotFoundError|ImportError)\b[^\n]*?"
                r"(?:No module named\s+)?'?(?P<tok>[\w.]+)'?",
                re.IGNORECASE)),
    # dynamic linker: "tool: error while loading shared libraries: libX.so.1: cannot open shared object file"
    ("missing-library",
     re.compile(r"^(?P<tok>[\w./+-]+): error while loading shared libraries",
                re.IGNORECASE | re.MULTILINE)),
    # GUI tool invoked headless
    ("gui-no-display",
     re.compile(r"cannot open display|could not connect to display"
                r"|qt\.qpa\.(?:xcb|plugin)|Gtk-WARNING[^\n]*display"
                r"|no DISPLAY environment variable",
                re.IGNORECASE)),
    # exec permission: "bash: /opt/x/tool: Permission denied"
    ("exec-permission",
     re.compile(r"^(?:bash|sh|zsh)?[: ]*(?:line \d+[: ]*)?"
                r"(?P<tok>/[\w./+-]+):\s*Permission denied\s*$",
                re.IGNORECASE | re.MULTILINE)),
    # sandbox egress block (forensic box: evidence analysis never needs egress)
    ("network-blocked",
     re.compile(r"Could not resolve host|Temporary failure in name resolution"
                r"|Network is unreachable|getaddrinfo[^\n]*failed",
                re.IGNORECASE)),
]


def _first_real_token(command: str) -> str:
    """The headline tool token of a command, via the registry's splitter."""
    subs = registry.tools_in(command or "")
    return subs[0]["token"] if subs else ""


def classify(stderr: str, stdout: str = "", command: str = "") -> List[Dict[str, Any]]:
    """Scan one bash call's output for tool-access failures.

    Returns ``[{reason, token, evidence}, ...]`` (deduped; empty = no access
    failure). ``token`` is the failing tool when the message names one, else
    the command's headline token; ``evidence`` is the matched line, truncated.
    """
    text = (stderr or "") + ("\n" + stdout if stdout else "")
    if not text.strip():
        return []
    found: List[Dict[str, Any]] = []
    seen: set = set()
    for reason, rx in _RULES:
        for m in rx.finditer(text):
            tok = (m.groupdict().get("tok") or "").strip().strip("'\"")
            # A captured path like /opt/x/PECmd.dll -> keep the basename-ish token.
            if "/" in tok:
                tok = tok.rstrip("/").rsplit("/", 1)[-1]
            if not tok or reason == "gui-no-display":
                tok = tok or _first_real_token(command)
            key = (reason, tok.lower())
            if key in seen:
                continue
            seen.add(key)
            line = m.group(0).strip().splitlines()[0]
            found.append({
                "reason": reason,
                "token": tok,
                "evidence": line[:200],
            })
    return found


def label_fields(failures: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build the ``metadata.enrich.tool_access`` block + tags for one span."""
    if not failures:
        return {"enrich": {}, "tags": []}
    tags = [f"tool_unavailable:{f['token']}" for f in failures if f["token"]]
    tags += sorted({f"access_fail:{f['reason']}" for f in failures})
    return {
        "enrich": {"tool_access": {"unavailable": True, "failures": failures}},
        "tags": tags,
    }


__all__ = ["classify", "label_fields"]

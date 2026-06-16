#!/usr/bin/env python3
"""Deterministic tool -> skill / phase mapping layer for Protocol SIFT trace enrichment.

Pure, stdlib-only, no network. Sourced directly from the five SKILL.md Tool tables
(``~/protocol-sift/skills/<name>/SKILL.md``) plus ``~/protocol-sift/global/CLAUDE.md``
("Installed Tool Paths" + "Tool Routing").

This module answers three questions about a forensic command, deterministically:

1. **skill_for(token)**  -> which SKILL.md manual owns this tool
   (one of ``sleuthkit``, ``plaso-timeline``, ``memory-analysis``,
   ``windows-artifacts``, ``yara-hunting``, or ``shared`` / ``unknown``).
2. **phase_for(token)**  -> which forensic phase the tool belongs to
   (``discovery`` / ``extract`` / ``analyze`` / ``report`` / ``other``).
3. **tools_in(command)** -> for a full (possibly compound) shell command, the
   ordered list of ``{token, skill, phase}`` for each real sub-tool invoked.

Design rules
------------
* **Do not force a false 1:1.** Genuinely ambiguous binaries (``strings``,
  ``file``, ``grep``, ``cp`` ...) map to ``"shared"`` rather than being pinned to
  one skill. ``bulk_extractor`` appears in the sleuthkit SKILL but is a generic
  carver, so it is treated as ``shared`` per the enrichment spec.
* **Handle invocation variants.** ``log2timeline.py`` (``.py`` suffix),
  ``dotnet /opt/.../EvtxECmd.dll`` and a bare ``EvtxECmd`` (``.dll`` / case
  variants), ``python3 /opt/volatility3*/vol.py`` and bare ``vol.py`` /
  ``volatility`` all resolve to the right skill.
* **Phase is per-tool**, derived from the tool's role in the methodology
  (discovery = find structure, extract = pull bytes out, analyze = parse /
  hunt, report = render output). Unknown tools default to ``"other"``.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List


# ---------------------------------------------------------------------------
# Sentinel skill / phase values
# ---------------------------------------------------------------------------

SHARED = "shared"      # generic binary used by multiple skills; do not force 1:1
UNKNOWN = "unknown"    # token we have no mapping for at all
OTHER = "other"        # phase fallback for unmapped / non-forensic tokens

SKILLS = (
    "sleuthkit",
    "plaso-timeline",
    "memory-analysis",
    "windows-artifacts",
    "yara-hunting",
)


# ---------------------------------------------------------------------------
# TOOL_TO_SKILL  —  every forensic binary -> exactly one owning skill
# ---------------------------------------------------------------------------
# Keys are *normalised tokens* (lowercase, see _normalise_token): no path, no
# ``.py`` / ``.dll`` / ``.exe`` suffix. e.g. "log2timeline.py" -> "log2timeline",
# ".../EvtxeCmd/EvtxECmd.dll" -> "evtxecmd".

TOOL_TO_SKILL: Dict[str, str] = {}


def _register(skill: str, *tokens: str) -> None:
    for tok in tokens:
        TOOL_TO_SKILL[tok] = skill


# --- sleuthkit / EWF (sleuthkit SKILL.md "Tool Reference") -----------------
# NOTE: bulk_extractor + photorec appear in the sleuthkit table but are generic
# carvers; bulk_extractor -> shared per spec. photorec stays sleuthkit (TSK-suite
# signature carver with no cross-skill use here).
_register(
    "sleuthkit",
    "ewfinfo", "ewfverify", "ewfmount",
    "img_stat", "mmls", "fsstat",
    "fls", "icat", "istat", "ffind", "ils",
    "blkls", "blkcat", "tsk_recover", "mactime",
    "photorec",
)

# --- plaso-timeline (plaso-timeline SKILL.md "Tools") ----------------------
_register(
    "plaso-timeline",
    "log2timeline", "psort", "pinfo", "psteal", "image_export",
)

# --- memory-analysis (memory-analysis SKILL.md "Tools") --------------------
# vol.py (Volatility 3) + baseline.py (Memory Baseliner). "volatility" /
# "volatility3" aliases included; bare "vol" handled below.
_register(
    "memory-analysis",
    "vol", "volatility", "volatility3", "baseline",
)

# --- windows-artifacts (EZ Tools / Event Logs / Registry) ------------------
# All resolve from either a bare name ("EvtxECmd"), a ".dll" path
# ("dotnet .../EvtxECmd.dll"), or a ".exe" (GUI). Stored lowercase.
_register(
    "windows-artifacts",
    "pecmd", "appcompatcacheparser", "amcacheparser", "mftecmd",
    "jlecmd", "lecmd", "wxtcmd", "sbecmd", "rbcmd", "bstrings",
    "srumecmd", "evtxecmd", "recmd", "sqlecmd",
    # GUI EZ tools (run via wine) — still owned by windows-artifacts
    "timelineexplorer", "registryexplorer", "mftexplorer",
    "shellbagsexplorer", "vscmount",
    # ASEP collection tool referenced in the skill
    "autorunsc", "autoruns",
)

# --- yara-hunting (yara-hunting SKILL.md "Tool Reference") ------------------
_register(
    "yara-hunting",
    "yara", "yarac",
)

# --- shared / ambiguous (explicitly NOT forced to one skill) ---------------
# Generic utilities that several skills invoke. Includes bulk_extractor (carver
# used in multiple contexts) and the strings/file/grep/cp/... family per spec.
_register(
    SHARED,
    "bulk_extractor",
    "strings", "file", "exiftool",
    "grep", "egrep", "fgrep", "zgrep",
    "cat", "ls", "mkdir", "cp", "mv", "rm", "find",
    "md5sum", "sha1sum", "sha256sum", "hashdeep",
    "sed", "awk", "cut", "sort", "uniq", "tee", "head", "tail",
    "wc", "tr", "nl", "xxd", "od", "less", "more",
    "umount", "mount", "ping",
    # report renderer is a Protocol SIFT utility, not owned by a forensic SKILL
    "generate_pdf_report",
)


# ---------------------------------------------------------------------------
# TOOL_TO_PHASE  —  forensic action phase per tool
# ---------------------------------------------------------------------------
# discovery : find structure / metadata (no bytes extracted)
# extract   : pull file/byte content out of an image
# analyze   : parse / hunt / correlate extracted artifacts
# report    : render final human/structured output
# Anything absent -> phase_for() returns OTHER ("other").

TOOL_TO_PHASE: Dict[str, str] = {}


def _register_phase(phase: str, *tokens: str) -> None:
    for tok in tokens:
        TOOL_TO_PHASE[tok] = phase


# discovery — image/partition/filesystem/inode enumeration + plaso/ewf metadata
_register_phase(
    "discovery",
    "fls", "mmls", "fsstat", "img_stat", "ils",
    "istat", "ffind",
    "pinfo",            # pinfo.py — inspect .plaso metadata
    "ewfinfo", "ewfverify", "ewfmount",
    "log2timeline",     # ingest/parse evidence sources into the .plaso store
)

# extract — pull bytes/files out of an image
_register_phase(
    "extract",
    "icat", "tsk_recover", "blkls", "blkcat",
    "image_export",     # image_export.py
    "photorec",
    "bulk_extractor",   # carving feature extraction
)

# analyze — parse / hunt / correlate
_register_phase(
    "analyze",
    "vol", "volatility", "volatility3", "baseline",
    "yara", "yarac",
    "mactime",
    # EZ Tools parsers (*ECmd / RECmd / bstrings) — all analysis
    "pecmd", "appcompatcacheparser", "amcacheparser", "mftecmd",
    "jlecmd", "lecmd", "wxtcmd", "sbecmd", "rbcmd", "bstrings",
    "srumecmd", "evtxecmd", "recmd", "sqlecmd",
    "autorunsc", "autoruns",
)

# report — render exports / final documents
_register_phase(
    "report",
    "psort", "psteal",          # export .plaso -> csv/json
    "generate_pdf_report",      # report generator
    "timelineexplorer", "registryexplorer",
    "mftexplorer", "shellbagsexplorer",
)


# ---------------------------------------------------------------------------
# Tokenisation helpers
# ---------------------------------------------------------------------------

# Prefixes that wrap a real tool and must be stripped to reach it.
_WRAPPER_PREFIXES = {"sudo", "python", "python2", "python3", "dotnet", "wine", "env"}

# sudo flags that take no argument (so we keep scanning for the real tool).
_SUDO_FLAG_RE = re.compile(r"^-")

# env VAR=VALUE assignment (e.g. "OFFSET=1024", "FOO=bar").
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# A real command name starts with a letter, ``_``, or is path-like
# (``/``, ``.``, ``~``). Pure numbers / arithmetic operators (left over from a
# ``$(( 2048 * 512 ))`` substitution) are NOT commands and must be ignored.
_COMMAND_NAME_RE = re.compile(r"^[~./]?[A-Za-z_][\w.\-/]*$|^[/.~][\w.\-/]+$")

# Splits a compound command into segments on shell control operators.
#   |  ||  &&  ;  |&     (also handles surrounding whitespace)
# We deliberately keep it simple and stdlib-only (no shlex AST): forensic
# commands in this corpus are straight pipelines, not nested subshells.
_SEGMENT_SPLIT_RE = re.compile(r"\|\||&&|\||;|\|&|&(?!&)")

# Command-substitution boundaries: $( ... ) and back-ticks. We turn the
# boundaries into split points so an inner tool (e.g. $(( ... )) arithmetic is
# stripped, `$(fls ...)` surfaces fls) is seen as its own segment.
_CMDSUB_BOUNDARY_RE = re.compile(r"\$\(\(|\)\)|\$\(|\)|`|<\(|>\(")


def _normalise_token(raw: str) -> str:
    """Reduce a raw argv token to a comparable tool key.

    * strip directory components  (``/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll`` -> ``EvtxECmd.dll``)
    * strip a single trailing ``.py`` / ``.dll`` / ``.exe`` suffix
    * lowercase
    """
    tok = raw.strip().strip("'\"")
    if not tok:
        return ""
    # Drop any redirection / quoting leftovers.
    tok = tok.lstrip("<>")
    # basename
    tok = os.path.basename(tok)
    # strip a known executable suffix (only one, case-insensitive)
    low = tok.lower()
    for suf in (".py", ".dll", ".exe"):
        if low.endswith(suf):
            tok = tok[: -len(suf)]
            break
    return tok.lower()


def _extract_tool_token(segment: str) -> str:
    """Given one command segment, return the normalised real tool token.

    Strips leading ``sudo`` (and its flags), ``python3`` / ``python`` /
    ``dotnet`` / ``wine`` / ``env`` wrappers, and ``VAR=value`` env assignments,
    then returns the first meaningful argument normalised via _normalise_token.
    Returns ``""`` if the segment has no real tool token.
    """
    words = segment.split()
    i = 0
    while i < len(words):
        w = words[i]

        # skip env assignments (FOO=bar)
        if _ENV_ASSIGN_RE.match(w):
            i += 1
            continue

        base = os.path.basename(w).lower()
        # strip exec-suffix for wrapper detection (python3 vs python3.11 etc.)
        wrapper_key = base
        if wrapper_key.startswith("python") and not wrapper_key == "python":
            # python3, python3.11, python2 -> normalise family to "python"
            wrapper_key = "python"

        if wrapper_key in _WRAPPER_PREFIXES:
            i += 1
            # after sudo, consume any sudo flags (e.g. `sudo -u root`, `sudo -E`)
            if base == "sudo":
                while i < len(words) and _SUDO_FLAG_RE.match(words[i]):
                    # `-u root` style: flag plus its value
                    flag = words[i]
                    i += 1
                    if flag in ("-u", "-g", "-p", "-C", "-D", "-h", "-U", "-r", "-T"):
                        if i < len(words) and not words[i].startswith("-"):
                            i += 1
            continue

        # first non-wrapper, non-env, non-flag word == the tool
        if w.startswith("-"):
            # leading flag with no command yet (rare) — skip it
            i += 1
            continue

        # skip arithmetic / numeric leftovers (e.g. "2048", "*", "512" from a
        # $(( 2048 * 512 )) substitution): these are not command names.
        if not _COMMAND_NAME_RE.match(w):
            i += 1
            continue

        return _normalise_token(w)

    return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def skill_for(token: str) -> str:
    """Return the owning skill for a tool token.

    Accepts either a raw token (``"EvtxECmd.dll"``, ``"/opt/.../vol.py"``) or an
    already-normalised one. Returns one of the SKILLS, ``"shared"``, or
    ``"unknown"``.
    """
    norm = _normalise_token(token)
    if not norm:
        return UNKNOWN
    return TOOL_TO_SKILL.get(norm, UNKNOWN)


def phase_for(token: str) -> str:
    """Return the forensic phase for a tool token.

    discovery / extract / analyze / report, else ``"other"``.
    """
    norm = _normalise_token(token)
    if not norm:
        return OTHER
    return TOOL_TO_PHASE.get(norm, OTHER)


def split_command(command: str) -> List[str]:
    """Split a (possibly compound) shell command into ordered tool tokens.

    Splits on ``|``, ``&&``, ``;``, ``||``, ``|&`` and command-substitution
    boundaries (``$( )``, back-ticks, ``$(( ))`` arithmetic, process
    substitution ``<( )`` / ``>( )``). For each resulting segment, strips
    leading ``sudo`` / ``python3`` / ``dotnet`` / ``wine`` / ``env`` and
    ``VAR=value`` assignments and returns the real tool token.

    Empty segments and segments with no tool token are dropped. Order is
    preserved (left-to-right as written).
    """
    if not command or not command.strip():
        return []

    # First explode command-substitution boundaries into separators so an inner
    # tool becomes its own segment, then split on shell control operators.
    flattened = _CMDSUB_BOUNDARY_RE.sub("\n", command)
    rough = _SEGMENT_SPLIT_RE.split(flattened)

    tokens: List[str] = []
    for seg in rough:
        for sub in seg.split("\n"):
            sub = sub.strip()
            if not sub:
                continue
            tok = _extract_tool_token(sub)
            if tok:
                tokens.append(tok)
    return tokens


def tools_in(command: str) -> List[Dict[str, str]]:
    """Decompose a command into ``[{token, skill, phase}, ...]`` in order.

    One entry per real sub-tool found by :func:`split_command`. Each carries its
    normalised ``token`` and the deterministic ``skill`` / ``phase`` labels.
    """
    out: List[Dict[str, str]] = []
    for tok in split_command(command):
        out.append(
            {
                "token": tok,
                "skill": TOOL_TO_SKILL.get(tok, UNKNOWN),
                "phase": TOOL_TO_PHASE.get(tok, OTHER),
            }
        )
    return out

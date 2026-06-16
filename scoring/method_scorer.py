#!/usr/bin/env python3
"""R2 — glass-box DISCIPLINE scorer for Protocol SIFT.

Grades a finished investigation **report** for *discipline*, not for answers:

* **(b) Corroboration** — does a ``CONFIRMED`` IOC actually rest on >= 2 distinct
  *artifact-type* sources that agree, with no conflicting receipt? (Decision 1.)
* **(c) Identity-before-labeling** — for every object the report affirmatively
  asserts is malicious, is there a type-appropriate *identity-resolving* receipt
  (a hash, a process/baseline pivot, a signer check) backing it? (Decision 2.)

This is a BEST-PRACTICE grader that EXCEEDS the deployed contract (which only
requires single-source grounding). It is **advisory** — never a keep/revert
signal until validated against a real run + human eyes.

What it reuses (does NOT reimplement)
-------------------------------------
* ``scoring/scorer.py``        — IOC extractors / normalisers (clean kinds).
* ``trace_enrich/provenance.py`` — per-IOC ``source`` / ``tool_sources`` /
  ``in_case_input`` / ``candidate_fabrication`` (stdout-indexed, 5 clean kinds).
* ``trace_enrich/bashlog.py``  — ``load_bash_log()`` -> per ``tool_use_id``:
  ``command`` / ``stdout`` / ``persisted_output_path`` / ``outcome`` / ...

Stdlib-only. No third-party deps (repo policy). ``unittest``, not pytest.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Cross-package imports WITHOUT assuming a particular cwd / sys.path. We mirror
# provenance.py's importlib loader so this works run-as-script, run-as-module,
# or imported from a test that put scoring/ on the path.
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, os.pardir))


def _load_module(modname: str, *relpath: str):
    """Load ``modname`` from ``<repo>/<relpath>`` via importlib (cwd-independent)."""
    try:
        return __import__(modname)
    except Exception:
        pass
    path = os.path.join(_REPO_ROOT, *relpath)
    path = os.path.abspath(path)
    spec = importlib.util.spec_from_file_location(modname, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {modname} from {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(modname, mod)
    spec.loader.exec_module(mod)
    return mod


scorer = _load_module("scorer", "scoring", "scorer.py")
provenance = _load_module("provenance", "trace_enrich", "provenance.py")
bashlog = _load_module("bashlog", "trace_enrich", "bashlog.py")


# ===========================================================================
# Shared constants
# ===========================================================================
#: The only kinds provenance + scorer can extract as concrete bash-findable
#: values. Corroboration scoring is restricted to these (spec: "Restrict scoring
#: to the 5 bash-extractable clean kinds").
CLEAN_KINDS = ("email", "hash", "mac", "ipv4", "sid")

#: Confidence labels in the report IOC table.
CONFIRMED = "CONFIRMED"
INFERRED = "INFERRED"
UNCERTAIN = "UNCERTAIN"
_CONF_TOKENS = (CONFIRMED, INFERRED, UNCERTAIN)


# ===========================================================================
# Report parsing — IOC table rows (Type | Value | Confidence | ...)
# ===========================================================================
def _split_md_cells(row: str) -> List[str]:
    """Split a markdown table row into trimmed cells (reuses scorer's style)."""
    s = row.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [c.strip() for c in s.split("|")]


_CONF_RE = re.compile(r"\b(CONFIRMED|INFERRED|UNCERTAIN)\b", re.IGNORECASE)


def parse_ioc_rows(report_text: str) -> List[Dict[str, Any]]:
    """Every markdown table row that carries a confidence token + >= 1 clean IOC.

    We do NOT require a rigid header (reports vary). A row qualifies when it is a
    pipe-row that (a) contains exactly one of CONFIRMED/INFERRED/UNCERTAIN and
    (b) yields >= 1 clean-kind IOC token from its cells. Each extracted clean IOC
    in the row becomes one record carrying that row's confidence + raw text.

    Returns records::

        {"kind", "value", "confidence", "row_text"}

    ``value`` is normalised (scorer.normalize) so it joins to provenance.
    """
    rows: List[Dict[str, Any]] = []
    for line in report_text.splitlines():
        if "|" not in line:
            continue
        stripped = line.lstrip()
        if not stripped.startswith("|"):
            continue
        # markdown separator row (|---|---|) -> skip
        if re.match(r"^\s*\|[\s:|-]+\|?\s*$", line):
            continue
        m = _CONF_RE.search(line)
        if not m:
            continue
        confidence = m.group(1).upper()
        row_text = line
        # Extract clean IOCs from the whole row (cell boundaries don't matter for
        # the regex extractors; the confidence column text is harmless noise).
        for kind in CLEAN_KINDS:
            for tok in sorted(scorer.extract_tokens(row_text, kind)):
                rows.append(
                    {
                        "kind": kind,
                        "value": tok,
                        "confidence": confidence,
                        "row_text": row_text,
                    }
                )
    return rows


# ===========================================================================
# Decision 1 — Corroboration: count distinct (tool, artifact-type) SOURCES.
# ===========================================================================
# Forensic tool/artifact taxonomy. We resolve a bash COMMAND to a coarse
# (tool-family, artifact-type) pair. Two tool_use_ids dedup to ONE source when
# they share the same (family, artifact). Two *different* artifact-types in one
# command still count as 2 (the locked choice). The artifact axis is what makes
# "psscan vs pslist" two sources but "psscan re-run twice" one source.

# Map a normalised tool token (registry-style) -> coarse artifact-type. The
# token is the *forensic output/artifact the tool reads*, not the binary name,
# so distinct artifacts of the same suite separate into distinct sources.
_TOOL_ARTIFACT: Dict[str, str] = {
    # --- Sleuthkit / filesystem ---
    "fls": "filesystem", "icat": "filesystem", "istat": "filesystem",
    "ffind": "filesystem", "ils": "filesystem", "fsstat": "filesystem",
    "mmls": "partition", "img_stat": "image", "mactime": "fs-timeline",
    "tsk_recover": "filesystem", "blkls": "filesystem", "blkcat": "filesystem",
    # --- EWF (chain of custody — never a forensic content source) ---
    "ewfinfo": "container", "ewfverify": "container", "ewfmount": "container",
    # --- plaso super-timeline ---
    "log2timeline": "plaso-timeline", "psort": "plaso-timeline",
    "psteal": "plaso-timeline", "pinfo": "plaso-timeline",
    "image_export": "plaso-export",
    # --- memory (Volatility / baseline) — artifact split is per-plugin below ---
    "vol": "memory", "volatility": "memory", "volatility3": "memory",
    "baseline": "memory-baseline",
    # --- windows EZ-tools: each parser reads a DIFFERENT registry/log artifact ---
    "pecmd": "prefetch",
    "appcompatcacheparser": "shimcache",
    "amcacheparser": "amcache",
    "mftecmd": "mft",
    "jlecmd": "jumplists", "lecmd": "lnk",
    "wxtcmd": "wxt", "sbecmd": "shellbags", "rbcmd": "recyclebin",
    "bstrings": "strings", "srumecmd": "srum",
    "evtxecmd": "evtx", "recmd": "registry", "sqlecmd": "sqlite",
    "autorunsc": "asep", "autoruns": "asep",
    # --- yara ---
    "yara": "yara", "yarac": "yara",
    # --- hashing (content identity, not a separate corroboration artifact) ---
    "md5sum": "hash-receipt", "sha1sum": "hash-receipt",
    "sha256sum": "hash-receipt", "hashdeep": "hash-receipt",
    "sha256deep": "hash-receipt", "md5deep": "hash-receipt",
    "hfind": "hash-db", "sorter": "hash-db",
    # --- generic carve over a strings dump = WEAK (R7) ---
    "strings": "strings",
    "grep": "grep", "egrep": "grep", "fgrep": "grep", "zgrep": "grep",
}

# Volatility plugin -> artifact-type. ``windows.psscan`` vs ``windows.pslist``
# are DIFFERENT scan strategies over memory and the locked decision counts the
# two as distinct artifact-types; ``netscan`` vs ``netstat`` likewise.
_VOL_PLUGIN_ARTIFACT = [
    (re.compile(r"\bpsscan\b", re.I), "mem-psscan"),
    (re.compile(r"\bpslist\b", re.I), "mem-pslist"),
    (re.compile(r"\bpstree\b", re.I), "mem-pstree"),
    (re.compile(r"\bpsxview\b", re.I), "mem-psxview"),
    (re.compile(r"\bnetscan\b", re.I), "mem-netscan"),
    (re.compile(r"\bnetstat\b", re.I), "mem-netstat"),
    (re.compile(r"\bmalfind\b", re.I), "mem-malfind"),
    (re.compile(r"\bdlllist\b", re.I), "mem-dlllist"),
    (re.compile(r"\bcmdline\b", re.I), "mem-cmdline"),
    (re.compile(r"\bhandles\b", re.I), "mem-handles"),
    (re.compile(r"\bmodules\b", re.I), "mem-modules"),
    (re.compile(r"\bsvcscan\b", re.I), "mem-svcscan"),
    (re.compile(r"\bfilescan\b", re.I), "mem-filescan"),
]

#: Artifact-types that are WEAK memory carves (R7 weak-source override).
_WEAK_ARTIFACTS = {"strings", "grep"}

#: Artifact-types that are NOT forensic-content corroboration at all.
_NONSOURCE_ARTIFACTS = {"container"}


def _segment_commands(command: str) -> List[str]:
    """Split a compound shell pipeline into its sub-command segments.

    We reuse registry's segment regexes via its public ``split_command`` ONLY to
    get tool tokens; but to resolve an *artifact per segment* we also need the
    raw segment text (for volatility plugin / strings-input detection). So we do
    a light local split on shell control operators.
    """
    if not command:
        return []
    # Also split process/command-substitution boundaries (`<(...)`, `>(...)`,
    # `$(...)`) so each inner command (e.g. each plugin in
    # `diff <(vol ... psscan) <(vol ... pslist)`) resolves to its OWN
    # artifact-type — two artifact-types in one command count as 2 (locked).
    rough = re.split(r"\|\||&&|\||;|\|&|&(?!&)|<\(|>\(|\$\(|\)", command)
    return [s.strip() for s in rough if s.strip()]


def _resolve_segment_artifact(segment: str) -> Optional[Tuple[str, str]]:
    """Resolve one command segment to ``(tool_family, artifact_type)`` or None.

    Uses registry-style tokenisation to find the real tool token, then maps it
    to an artifact-type. Volatility plugins refine ``memory`` to the per-plugin
    artifact so psscan/pslist/netscan/netstat separate. Returns None when the
    segment has no recognised forensic tool (DEDUP-APPROX fallback handles it).
    """
    # registry.split_command on the whole-segment gives ordered tokens; the first
    # recognised forensic token is the segment's tool.
    try:
        from importlib import import_module  # noqa: F401
        registry = _load_module("registry", "trace_enrich", "registry.py")
        tokens = registry.split_command(segment)
    except Exception:
        tokens = segment.split()

    family = None
    artifact = None
    for tok in tokens:
        norm = tok.lower()
        # registry already strips paths/suffixes via split_command; normalise dll/py just in case
        for suf in (".py", ".dll", ".exe"):
            if norm.endswith(suf):
                norm = norm[: -len(suf)]
        if norm in _TOOL_ARTIFACT:
            family = norm
            artifact = _TOOL_ARTIFACT[norm]
            break

    if family is None:
        return None

    # Refine volatility to its plugin artifact.
    if artifact == "memory":
        for rx, plug in _VOL_PLUGIN_ARTIFACT:
            if rx.search(segment):
                artifact = plug
                break

    # A `strings ... | grep` carve over memory is weak: if a strings segment is
    # present we keep its weak artifact (caller applies R7 override).
    return (family, artifact)


def build_artifact_index(bash_log: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """``tool_use_id -> {family, artifact, command, resolved}`` for every call.

    ``resolved`` is False when no forensic tool could be parsed (DEDUP-APPROX:
    the caller falls back to per-tool_use_id distinctness for that id).
    """
    out: Dict[str, Dict[str, Any]] = {}
    for tuid, entry in bash_log.items():
        command = entry.get("command", "") or ""
        # A command may surface SEVERAL artifact-types (compound pipeline). We
        # record the SET of (family, artifact) pairs across its segments; two
        # different artifact-types in one command count as 2 (locked).
        pairs: List[Tuple[str, str]] = []
        for seg in _segment_commands(command):
            res = _resolve_segment_artifact(seg)
            if res is not None and res not in pairs:
                pairs.append(res)
        out[tuid] = {
            "command": command,
            "pairs": pairs,             # list[(family, artifact)]
            "resolved": bool(pairs),
        }
    return out


def _entry_is_unverifiable(entry: Dict[str, Any], value: str) -> bool:
    """True when this receipt could only support corroboration off-band.

    Spec: an IOC whose corroboration could only live in persisted-only /
    truncated stdout (``persistedOutputPath`` set AND value not in the inline
    stdout) is UNVERIFIABLE — not a fail.
    """
    if not entry:
        return False
    inline = entry.get("stdout", "") or ""
    persisted = entry.get("persisted_output_path")
    if persisted and value.lower() not in inline.lower():
        return True
    return False


# Source-record for one CONFIRMED/labelled IOC after corroboration analysis.
def _distinct_sources_for_ioc(
    rec: Dict[str, Any],
    prov_rec: Dict[str, Any],
    artifact_index: Dict[str, Dict[str, Any]],
    bash_log: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """Count distinct (family, artifact) sources backing ``rec``'s value.

    Returns::

        {
          "distinct_sources": set[(family,artifact)],
          "weak_only": bool,           # only strings/grep carve -> R7 cap
          "dedup_approx": bool,        # some matching id couldn't be parsed
          "unverifiable": bool,        # only persisted/truncated support
          "from_case_input": bool,
          "n_sources": int,            # incl. +1 for case_input (capped)
        }
    """
    value = rec["value"]
    matched_ids = [s.split("tool:", 1)[1] for s in prov_rec.get("tool_sources", [])
                   if s.startswith("tool:")]

    distinct: set[Tuple[str, str]] = set()
    dedup_approx = False
    any_inline = False
    any_unverifiable_only = True  # flips False as soon as one inline match found

    for tuid in matched_ids:
        entry = bash_log.get(tuid, {})
        # UNVERIFIABLE guard: value only in persisted/truncated -> don't credit.
        if _entry_is_unverifiable(entry, value):
            continue
        any_inline = True
        any_unverifiable_only = False
        ai = artifact_index.get(tuid)
        if ai is None or not ai["resolved"]:
            # DEDUP-APPROX: fall back to a synthetic per-id source.
            dedup_approx = True
            distinct.add(("__unresolved__", tuid))
            continue
        for pair in ai["pairs"]:
            distinct.add(pair)

    # Drop pure chain-of-custody container sources — never corroboration.
    distinct = {p for p in distinct if p[1] not in _NONSOURCE_ARTIFACTS}

    # R7 weak-source override: if the ONLY non-weak content is strings/grep carve
    # with no second non-strings artifact, collapse to a single weak source.
    non_weak = {p for p in distinct if p[1] not in _WEAK_ARTIFACTS}
    weak = {p for p in distinct if p[1] in _WEAK_ARTIFACTS}
    weak_only = bool(weak) and not non_weak

    if weak_only:
        # caps at INFERRED -> treat as exactly ONE source.
        effective = {("__weak_strings__", "carve")}
    else:
        # weak sources don't ADD to a real corroboration count.
        effective = non_weak if non_weak else distinct

    from_case_input = bool(prov_rec.get("in_case_input"))
    n = len(effective)
    if from_case_input:
        n += 1  # case_input counts as at most +1 source

    unverifiable = (not matched_ids) and from_case_input is False \
        or (bool(matched_ids) and any_unverifiable_only and not any_inline)

    return {
        "distinct_sources": sorted(f"{f}:{a}" for f, a in effective),
        "weak_only": weak_only,
        "dedup_approx": dedup_approx,
        "unverifiable": unverifiable,
        "from_case_input": from_case_input,
        "n_sources": n,
    }


def _has_conflict(
    rec: Dict[str, Any],
    bash_log: Dict[str, Dict[str, Any]],
) -> bool:
    """R8 self-consistency: does any receipt assert a CONFLICTING value for this
    IOC's *role*?

    We can only detect a narrow, safe class of conflict deterministically: for a
    hash IOC, if a receipt that names the SAME file/object reports a DIFFERENT
    hash of the same length, that is a conflict. (General cross-value conflict
    needs object binding we don't have for fuzzy kinds, so we stay conservative.)
    """
    if rec["kind"] != "hash":
        return False
    value = rec["value"]
    same_len = len(value)
    for entry in bash_log.values():
        out = (entry.get("stdout", "") or "")
        cmd = (entry.get("command", "") or "")
        text = out + "\n" + cmd
        # gather hashes of the same length in receipts that also mention our value
        hashes = scorer.extract_tokens(text, "hash")
        sized = {h for h in hashes if len(h) == same_len}
        if value in sized and len(sized) > 1:
            # this receipt surfaced OUR hash AND a different same-length hash
            # right next to it -> a self-inconsistency signal.
            return True
    return False


def score_corroboration(
    report_text: str,
    bash_log: Dict[str, Dict[str, Any]],
    case_input_text: str = "",
) -> Dict[str, Any]:
    """Grade corroboration discipline for every clean-kind IOC row in the report.

    Returns the corroboration block of the score output (see ``score_report``).
    """
    rows = parse_ioc_rows(report_text)

    # Build the provenance map once (per-IOC source / tool_sources / fabrication).
    tool_stdouts = {tuid: (e.get("stdout", "") or "") for tuid, e in bash_log.items()}
    prov_records = provenance.provenance(report_text, tool_stdouts, case_input_text)
    prov_by_key = {(r["kind"], r["ioc"]): r for r in prov_records}

    artifact_index = build_artifact_index(bash_log)

    rows_out: List[Dict[str, Any]] = []
    confirmed_verifiable = 0
    confirmed_pass = 0
    violations_single: List[Dict[str, Any]] = []
    violations_conflict: List[Dict[str, Any]] = []
    violations_fabricated: List[Dict[str, Any]] = []
    n_unverifiable = 0
    n_dedup_approx = 0

    for rec in rows:
        key = (rec["kind"], rec["value"])
        prov_rec = prov_by_key.get(key)
        if prov_rec is None:
            # Shouldn't happen (provenance extracts the same clean kinds), but be safe.
            continue

        grounded_in_tool = str(prov_rec.get("source") or "").startswith("tool:")
        fabricated = prov_rec.get("candidate_fabrication", False)

        analysis = _distinct_sources_for_ioc(rec, prov_rec, artifact_index, bash_log)
        conflict = _has_conflict(rec, bash_log)

        # A value provenance calls fabricated (absent from INLINE stdout + input)
        # is actually UNVERIFIABLE -- not fabricated -- when some receipt's full
        # output was persisted/truncated off-band and could hold it. Override
        # before the fabrication check so a disciplined run is never falsely
        # accused. (No persisted receipt anywhere -> genuine fabrication stands.)
        persisted_unverifiable = fabricated and any(
            _entry_is_unverifiable(e, rec["value"]) for e in bash_log.values()
        )
        if persisted_unverifiable:
            fabricated = False

        # ---- classify the correct label for this row ----
        if persisted_unverifiable:
            correct = "UNVERIFIABLE"
            status = "unverifiable"
        elif fabricated:
            correct = "UNCERTAIN"   # absent from receipts + input -> abstain
            status = "fabricated"
        elif conflict:
            correct = "UNCERTAIN"
            status = "conflict"
        elif analysis["unverifiable"]:
            correct = "UNVERIFIABLE"
            status = "unverifiable"
        elif analysis["weak_only"]:
            correct = INFERRED       # R7 cap
            status = "weak-source"
        elif grounded_in_tool and analysis["n_sources"] >= 2:
            correct = CONFIRMED
            status = "ok"
        elif grounded_in_tool or analysis["from_case_input"]:
            correct = INFERRED       # grounded but single source
            status = "single-source"
        else:
            correct = "UNCERTAIN"
            status = "ungrounded"

        is_unverifiable = (correct == "UNVERIFIABLE")
        if is_unverifiable:
            n_unverifiable += 1
        if analysis["dedup_approx"]:
            n_dedup_approx += 1

        row_out = {
            "kind": rec["kind"],
            "value": rec["value"],
            "reported_confidence": rec["confidence"],
            "correct_label": correct,
            "distinct_source_count": analysis["n_sources"],
            "distinct_sources": analysis["distinct_sources"],
            "from_case_input": analysis["from_case_input"],
            "weak_source_override": analysis["weak_only"],
            "dedup_approx": analysis["dedup_approx"],
            "conflict": conflict,
            "fabricated": fabricated,
            "status": status,
            "violation": False,
        }

        # ---- score: only verifiable CONFIRMED rows count toward the rate ----
        if rec["confidence"] == CONFIRMED and not is_unverifiable:
            confirmed_verifiable += 1
            if correct == CONFIRMED:
                confirmed_pass += 1
            else:
                row_out["violation"] = True
                v = {"kind": rec["kind"], "value": rec["value"],
                     "reported": CONFIRMED, "correct": correct}
                if status == "fabricated":
                    violations_fabricated.append(v)
                elif status == "conflict":
                    violations_conflict.append(v)
                else:  # single-source or weak-source -> single-source violation
                    violations_single.append(v)

        rows_out.append(row_out)

    pass_rate = (confirmed_pass / confirmed_verifiable) if confirmed_verifiable else None

    return {
        "corroboration_pass_rate": pass_rate,
        "confirmed_verifiable": confirmed_verifiable,
        "confirmed_pass": confirmed_pass,
        "rows": rows_out,
        "violations_confirmed_single_source": violations_single,
        "violations_confirmed_conflicting": violations_conflict,
        "violations_confirmed_fabricated": violations_fabricated,
        "unverifiable_count": n_unverifiable,
        "dedup_approx_count": n_dedup_approx,
    }


# ===========================================================================
# Decision 2 — Identity-before-labeling (keyword-match the prose, "weak" form).
# ===========================================================================
#: Malice keywords. A sentence/row that co-occurs an object with one of these is
#: an affirmative malicious ASSERTION about that object. We do NOT key on
#: CONFIRMED (that is confidence-of-existence, not a verdict).
_MALICE_RE = re.compile(
    r"\b(?:"
    r"attacker(?:'s|s)?|adversary|malicious|maliciously|malware|"
    r"c2|command[ -]and[ -]control|beacon(?:ing)?|"
    r"backdoor|dropper|loader|implant|rootkit|trojan|"
    r"ransomware|keylogger|stealer|infostealer|spyware|"
    r"exfil(?:trat\w*)?|payload|weaponized|"
    r"compromis\w+|threat actor|apt\d*"
    r")\b",
    re.IGNORECASE,
)

#: Known-good / signed / allow-list keywords. An object co-asserted malicious AND
#: known-good is the MRC.exe contradiction class.
_KNOWN_GOOD_RE = re.compile(
    r"\b(?:"
    r"nsrl|known[ -]good|known[ -]benign|legitimate|whitelist\w*|allow[ -]?list\w*|"
    r"microsoft[ -]signed|signed by microsoft|valid(?:ly)? signed|"
    r"digitally signed|trusted publisher|baseline match\w*|expected system file"
    r")\b",
    re.IGNORECASE,
)

#: Execution-claim keywords (for the overreach check). A claim of execution needs
#: run-evidence (Prefetch run-count / Amcache+source / SRUM / 4688), NOT mere
#: presence (Shimcache / a file listing).
_EXECUTION_RE = re.compile(
    r"\b(?:"
    r"execut\w+|was run|were run|ran on|launched|invoked|"
    r"run[ -]count|times executed|process (?:started|spawned|created)"
    r")\b",
    re.IGNORECASE,
)

#: Identity-resolving receipt regexes per object type (accept BOTH live-skill and
#: playbook tool names — hfind/sha256deep/sorter are playbook-only, included).
_ID_RECEIPT = {
    "file": re.compile(
        r"md5sum|sha256sum|sha1sum|md5deep|sha256deep|hashdeep|hfind|sorter|"
        r"amcacheparser.*(?:-w|-b)\b|yara.*hash\.(?:md5|sha256)|imphash|virustotal",
        re.IGNORECASE,
    ),
    "process": re.compile(
        r"windows\.(?:pstree|psscan|pslist)|\bpstree\b|baseline\.py.*-proc",
        re.IGNORECASE,
    ),
    "persistence": re.compile(
        r"autorunsc.*-s\b|not verified|signer|vanillawindowsreference|baseline|"
        r"memory.?baseliner|baseline\.py.*(?:-drv|-svc)",
        re.IGNORECASE,
    ),
}

#: Execution-evidence receipts (Prefetch run-count, Amcache+source, SRUM, 4688).
_EXEC_RECEIPT = re.compile(
    r"pecmd|prefetch|run[ -]?count|amcacheparser|\bamcache\b|srumecmd|\bsrum\b|"
    r"\b4688\b|evtxecmd.*4688",
    re.IGNORECASE,
)

#: Presence-only support (Shimcache / a plain file listing). If execution is
#: claimed and ONLY these back it -> overreach.
_PRESENCE_RECEIPT = re.compile(
    r"appcompatcacheparser|shimcache|\bfls\b|\bls\b|\bmftecmd\b|file listing",
    re.IGNORECASE,
)

#: Chain-of-custody container hashing — EXCLUDED from identity.
_COC_RE = re.compile(r"ewfinfo|ewfverify|\.e01\b|\.raw\b|\.001\b", re.IGNORECASE)

#: A reported object token (file/binary/process/service/task name, USB serial).
#: Used to find "asserted malicious about O" sentences for non-clean objects.
_OBJECT_TOKEN_RE = re.compile(
    r"\b[\w\-]+\.(?:exe|dll|sys|ps1|bat|vbs|scr|com|js|jar|hta|cpl)\b",
    re.IGNORECASE,
)


def _sentences(text: str) -> List[str]:
    """Naive sentence + row splitter (period / newline / table-row bounded)."""
    # split on sentence punctuation and on line boundaries so an IOC table row is
    # its own unit.
    parts = re.split(r"(?<=[.!?])\s+|\n", text)
    return [p.strip() for p in parts if p.strip()]


def _object_type(token: str, context: str = "") -> str:
    """Coarse PRIMARY object type for identity-receipt selection.

    Uses the extension first, then the asserting sentence's wording: an object
    named as a *process* (``process X``, ``X.exe ran``) resolves via the PROCESS
    receipts; a *driver/service/task/persistence* via the PERSISTENCE receipts.
    The primary type is only a hint — ``_identity_receipt_present`` also accepts
    any OTHER type-appropriate identity receipt as a fallback.
    """
    low = token.lower()
    ctx = (context or "").lower()
    if low.endswith(".sys") or re.search(r"\bdriver\b", ctx):
        return "persistence"   # driver
    if re.search(r"\b(service|svc|scheduled task|task|autorun|run key|registry run|"
                 r"persistence|asep)\b", ctx) or \
       re.search(r"\b(service|svc|scheduled task|task|autorun|run key|registry run)\b", low):
        return "persistence"
    if re.search(r"\bprocess(?:es)?\b", ctx):
        return "process"
    if low.endswith((".exe", ".dll", ".ps1", ".bat", ".vbs", ".scr", ".com",
                     ".js", ".jar", ".hta", ".cpl")):
        return "file"
    return "file"


def _identity_receipt_present(
    obj_value: str,
    obj_type: str,
    obj_kind: Optional[str],
    bash_log: Dict[str, Dict[str, Any]],
    prov_rec: Optional[Dict[str, Any]],
) -> Tuple[bool, bool]:
    """Is there a type-appropriate identity-resolving receipt for ``obj_value``?

    Returns ``(present, weak_linkage)``.

    Linkage:
      * For hash / ipv4 objects we use provenance (the value is in a receipt's
        stdout) AND require the receipt command to be an identity tool.
      * Otherwise (process path / service / task / driver / USB serial) we
        substring-match the object name in the receipt command/stdout and mark
        the linkage *weak*.
    """
    # Try the object's PRIMARY identity-receipt family first, then fall back to
    # the other families: a malicious binary's identity is type-appropriately
    # resolved by a hash OR a process-baseline pivot (the spec's 3 categories are
    # all valid identity receipts for an executable object).
    primary = _ID_RECEIPT.get(obj_type, _ID_RECEIPT["file"])
    type_res = [primary] + [r for r in _ID_RECEIPT.values() if r is not primary]

    def _any_id_tool(text: str) -> bool:
        return any(rx.search(text) for rx in type_res)

    # provenance-based linkage for clean kinds that provenance can bind.
    if obj_kind in ("hash", "ipv4") and prov_rec is not None:
        for s in prov_rec.get("tool_sources", []):
            if not s.startswith("tool:"):
                continue
            tuid = s.split("tool:", 1)[1]
            entry = bash_log.get(tuid, {})
            cmd = entry.get("command", "") or ""
            if _COC_RE.search(cmd) and not _any_id_tool(cmd):
                continue  # chain-of-custody container hashing is not identity
            if _any_id_tool(cmd):
                return True, False
        # value is in receipts but no identity tool produced it -> fall through to
        # substring fallback (weak) below.

    # substring-weak fallback: object name appears in an identity-tool receipt.
    needle = obj_value.lower()
    for entry in bash_log.values():
        cmd = entry.get("command", "") or ""
        out = entry.get("stdout", "") or ""
        hay = (cmd + "\n" + out).lower()
        if needle and needle in hay:
            if _COC_RE.search(cmd) and not _any_id_tool(cmd):
                continue
            if _any_id_tool(cmd) or _any_id_tool(out):
                return True, True
    return False, False


def _execution_overreach(
    obj_value: str,
    bash_log: Dict[str, Dict[str, Any]],
) -> bool:
    """True when execution is claimed but only presence-evidence backs the object.

    Caller has already established the sentence claims execution. We check the
    receipts mentioning the object: if a run-evidence receipt exists -> not
    overreach; if only presence receipts mention it -> overreach.
    """
    needle = obj_value.lower()
    saw_presence = False
    for entry in bash_log.values():
        cmd = entry.get("command", "") or ""
        out = entry.get("stdout", "") or ""
        hay = (cmd + "\n" + out).lower()
        if needle and needle in hay:
            if _EXEC_RECEIPT.search(cmd) or _EXEC_RECEIPT.search(out):
                return False  # real execution evidence exists -> no overreach
            if _PRESENCE_RECEIPT.search(cmd) or _PRESENCE_RECEIPT.search(out):
                saw_presence = True
    # also accept run-count language already in the report's receipt text? handled
    # by caller. Overreach iff we only ever saw presence-class support.
    return saw_presence


def _collect_asserted_objects(report_text: str) -> List[Dict[str, Any]]:
    """Find objects affirmatively asserted malicious + the asserting sentence.

    An object is:
      * a clean IOC (hash/ipv4) token, OR
      * a file/binary/driver name (``*.exe`` / ``*.dll`` / ``*.sys`` / ...),
    that co-occurs with a malice keyword in the same sentence/row. Pure existence
    statements and the case-level VERDICT token are out of scope.
    """
    asserted: List[Dict[str, Any]] = []
    seen: set = set()
    for sent in _sentences(report_text):
        # Skip the case-level verdict line entirely (out of scope).
        if re.match(r"^\s*\**\s*VERDICT\s*:", sent, re.IGNORECASE):
            continue
        if not _MALICE_RE.search(sent):
            continue

        # clean-kind objects (hash / ipv4) named in a malicious sentence
        for kind in ("hash", "ipv4"):
            for tok in sorted(scorer.extract_tokens(sent, kind)):
                k = (kind, tok)
                if k in seen:
                    continue
                seen.add(k)
                asserted.append({
                    "value": tok, "kind": kind,
                    "obj_type": _object_type(tok, sent),
                    "sentence": sent,
                })
        # filename / driver objects
        for m in _OBJECT_TOKEN_RE.finditer(sent):
            tok = m.group(0)
            k = ("name", tok.lower())
            if k in seen:
                continue
            seen.add(k)
            asserted.append({
                "value": tok, "kind": None,
                "obj_type": _object_type(tok, sent), "sentence": sent,
            })
    return asserted


def score_identity(
    report_text: str,
    bash_log: Dict[str, Dict[str, Any]],
    case_input_text: str = "",
) -> Dict[str, Any]:
    """Grade identity-before-labeling for every asserted-malicious object.

    Soft-unverifiable (never a hard fail) when there are NO bash receipts at all:
    fall back to checking the identity facts appear in the report's IOC/evidence
    text.
    """
    objects = _collect_asserted_objects(report_text)

    # No bash receipts -> soft path (some cases are artifact-summary, zero bash).
    no_receipts = len(bash_log) == 0

    tool_stdouts = {tuid: (e.get("stdout", "") or "") for tuid, e in bash_log.items()}
    prov_records = provenance.provenance(report_text, tool_stdouts, case_input_text)
    prov_by_key = {(r["kind"], r["ioc"]): r for r in prov_records}

    rows_out: List[Dict[str, Any]] = []
    verifiable = 0
    passed = 0
    not_resolved: List[Dict[str, Any]] = []
    overreach: List[Dict[str, Any]] = []
    known_good_contradiction: List[Dict[str, Any]] = []
    soft_unverifiable = 0
    weak_linkage = 0

    for obj in objects:
        sentence = obj["sentence"]
        prov_rec = prov_by_key.get((obj["kind"], obj["value"])) if obj["kind"] else None

        # ---- known-good contradiction flag (independent of pass/fail rate) ----
        contradiction = bool(_KNOWN_GOOD_RE.search(sentence))
        if contradiction:
            known_good_contradiction.append(
                {"value": obj["value"], "sentence": sentence}
            )

        # ---- overreach: execution claimed w/ only presence support ----
        is_exec_claim = bool(_EXECUTION_RE.search(sentence))
        over = False
        if is_exec_claim and not no_receipts:
            over = _execution_overreach(obj["value"], bash_log)
            if over:
                overreach.append({"value": obj["value"], "sentence": sentence})

        # ---- identity-resolving receipt present? ----
        if no_receipts:
            # soft fallback: do the identity facts appear in the report itself?
            # (a hash for the object, or an explicit "not verified"/signer note)
            soft_ok = bool(
                scorer.extract_tokens(report_text, "hash")
            ) or bool(re.search(r"not verified|signer|unsigned|baseline", report_text, re.I))
            status = "soft-unverifiable"
            soft_unverifiable += 1
            present, weak = (soft_ok, True)
            row = {
                "value": obj["value"], "obj_type": obj["obj_type"],
                "sentence": sentence, "identity_receipt": soft_ok,
                "weak_linkage": True, "status": status,
                "overreach": over, "known_good_contradiction": contradiction,
                "scored": False,
            }
            rows_out.append(row)
            continue

        present, weak = _identity_receipt_present(
            obj["value"], obj["obj_type"], obj["kind"], bash_log, prov_rec
        )
        if weak:
            weak_linkage += 1

        verifiable += 1
        if present:
            passed += 1
            status = "resolved"
        else:
            status = "not-resolved"
            not_resolved.append({"value": obj["value"], "sentence": sentence})

        rows_out.append({
            "value": obj["value"], "obj_type": obj["obj_type"],
            "sentence": sentence, "identity_receipt": present,
            "weak_linkage": weak, "status": status,
            "overreach": over, "known_good_contradiction": contradiction,
            "scored": True,
        })

    pass_rate = (passed / verifiable) if verifiable else None

    return {
        "identity_pass_rate": pass_rate,
        "verifiable_assertions": verifiable,
        "passed_assertions": passed,
        "rows": rows_out,
        "violations_identity_not_resolved": not_resolved,
        "violations_overreach_presence_as_execution": overreach,
        "violations_malicious_label_contradicts_known_good": known_good_contradiction,
        "identity_unverifiable_from_receipts": soft_unverifiable,
        "weak_linkage_count": weak_linkage,
    }


# ===========================================================================
# Public API — score a report (b) + (c) and emit the spec score-output dict.
# ===========================================================================
def score_report(
    report_text: str,
    bash_log: Dict[str, Dict[str, Any]],
    case_input_text: str = "",
) -> Dict[str, Any]:
    """The R2 discipline score for one report (advisory).

    Parameters
    ----------
    report_text : str
        The investigation report markdown.
    bash_log : dict
        ``{tool_use_id: entry}`` from ``bashlog.load_bash_log()``.
    case_input_text : str
        The case file as the agent read it (``scorer.load_case_input_text``).

    Returns the spec score-output dict::

        {
          "corroboration_pass_rate", "identity_pass_rate",
          "violations": {...},  "counts": {...},
          "corroboration": {...full block...},
          "identity": {...full block...},
          "advisory": True,
        }
    """
    corr = score_corroboration(report_text, bash_log, case_input_text)
    ident = score_identity(report_text, bash_log, case_input_text)

    return {
        "corroboration_pass_rate": corr["corroboration_pass_rate"],
        "identity_pass_rate": ident["identity_pass_rate"],
        "violations": {
            "confirmed_single_source": corr["violations_confirmed_single_source"],
            "confirmed_conflicting": corr["violations_confirmed_conflicting"],
            "confirmed_fabricated": corr["violations_confirmed_fabricated"],
            "identity_not_resolved": ident["violations_identity_not_resolved"],
            "overreach_presence_as_execution":
                ident["violations_overreach_presence_as_execution"],
            "malicious_label_contradicts_known_good":
                ident["violations_malicious_label_contradicts_known_good"],
        },
        "counts": {
            "unverifiable": corr["unverifiable_count"],
            "dedup_approx": corr["dedup_approx_count"],
            "identity_unverifiable_from_receipts":
                ident["identity_unverifiable_from_receipts"],
            "weak_linkage": ident["weak_linkage_count"],
            "confirmed_verifiable": corr["confirmed_verifiable"],
            "confirmed_pass": corr["confirmed_pass"],
            "identity_verifiable": ident["verifiable_assertions"],
            "identity_passed": ident["passed_assertions"],
        },
        "corroboration": corr,
        "identity": ident,
        # Advisory only until validated against a real run + human eyes (Hamel H2).
        "advisory": True,
    }


def score_report_from_files(
    report_path: str,
    bash_raw_path: str,
    case_input_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Load report + bash_raw (+ optional case input) from disk and score."""
    report_text = scorer.load_report_text(report_path)
    bash_log = bashlog.load_bash_log(bash_raw_path)
    case_input_text = ""
    if case_input_path:
        case_input_text = scorer.load_case_input_text(case_input_path)
    return score_report(report_text, bash_log, case_input_text)


# ===========================================================================
# CLI / __main__
# ===========================================================================
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="R2 glass-box DISCIPLINE scorer (corroboration + identity). Advisory."
    )
    ap.add_argument("report_path", help="path to the investigation report (.md)")
    ap.add_argument("bash_raw_path", help="path to bash_raw_<session>.jsonl")
    ap.add_argument("case_input_path", nargs="?", default=None,
                    help="optional case input JSON (the agent's 'findable' haystack)")
    args = ap.parse_args(argv)

    result = score_report_from_files(
        args.report_path, args.bash_raw_path, args.case_input_path
    )
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""G13 -- per-claim CITED-receipt grounding verifier (ADVISORY).

Implements the never-built "quote-before-claim" leg of the discipline scorer:
for each factual literal a report row asserts, resolve the receipt the row
CITES (an ART-NNN case artifact or a tool:<id> bash receipt) and check the
literal appears VERBATIM in THAT specific source. Per-claim statuses:

  cited_grounded         literal is in the single source it cited
  cited_grounded_union   multi-citation row; literal is in one of the cited
                         sources (cannot pin which -> weaker)
  mis_cited              literal is real (appears elsewhere) but NOT in any
                         cited source   <-- the bypass scorer.py misses
  ungrounded             literal appears in no source at all (fab candidate)
  unverifiable_read_mcp  literal cited to a non-bash (Read/MCP) receipt
  unverifiable_truncated cited bash receipt persisted but unreadable
  uncited                row asserts a literal with no citation
  abstained              UNCERTAIN / INSUFFICIENT row (exempt -- rewards
                         calibrated abstention)

STANDING CONSTRAINTS honored:
  * ADVISORY ONLY. Output is a self-contained {"advisory": True, ...} dict;
    NOT imported by scoring/scorer.py and NEVER wired into aggregate() or any
    keep/revert composite. Promotion requires human TPR/TNR + bootstrap CI.
  * ANTI-GOODHART. Cannot touch scorer.py find_fabrications/CLEAN_KINDS/
    aggregate; fabrication=0 stays byte-for-byte untradeable. Fuzzy /
    ungrounded / mis_cited flow only into advisory buckets.
  * KEY-INDEPENDENT. Never reads ground_truth. A correct off-key literal that
    is correctly cited scores cited_grounded.
  * STDLIB ONLY (re, unicodedata, json, os, sys, importlib). No LLM.

NOTE: the G13-BUILD-SPEC placed this inside method_scorer.py; that file does
not exist on the sift-vm (R2 is Mac-only), so G13 ships as a standalone
advisory sibling -- trivially foldable into method_scorer.py if R2 is rebuilt.
load_bash_log is bash-only (entries carry no tool_name), so the
unverifiable_read_mcp branch is exercised only by synthetic fixtures today;
real Read/MCP receipts need a span-aware loader (future work).
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
import unicodedata
from typing import Any, Dict, List, Optional, Tuple


# --- cross-package loaders (reuse provenance.py's proven pattern) ------------
def _load_module(modname: str, relpath: str):
    try:
        return __import__(modname)
    except Exception:
        pass
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.abspath(os.path.join(here, relpath))
    spec = importlib.util.spec_from_file_location(modname, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {modname} from {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(modname, mod)
    spec.loader.exec_module(mod)
    return mod


_scorer = _load_module("scorer", "scorer.py")
_bashlog = _load_module("bashlog", os.path.join(os.pardir, "trace_enrich", "bashlog.py"))

CLEAN_KINDS = set(_scorer.CLEAN_KINDS)              # email, hash, mac, ipv4, sid
NORMALIZED_KINDS = {"path", "file_path", "registry_key"}
ADVISORY_KINDS = {"username", "hostname"}

ART_ID_RE = re.compile(r"\bART-\d{2,}\b", re.IGNORECASE)
TOOL_ID_RE = re.compile(r"\btool:([A-Za-z0-9_\-]+)|\b(toolu_[A-Za-z0-9]+)\b", re.IGNORECASE)
_CONF_RE = re.compile(
    r"\b(CONFIRMED|INFERRED|UNCERTAIN|INSUFFICIENT(?:_EVIDENCE)?|NOT[ _]ESTABLISHED)\b",
    re.IGNORECASE,
)
_ZW_RE = re.compile(r"[​‌‍‎‏‪-‮⁠﻿]")
_ABSTAIN = {"UNCERTAIN", "INSUFFICIENT", "INSUFFICIENT_EVIDENCE", "NOT ESTABLISHED", "NOT_ESTABLISHED"}


# --- canonicalisation + verbatim matcher (G13-2) ----------------------------
def _canon(s: str) -> str:
    s = unicodedata.normalize("NFKC", s or "")
    s = _ZW_RE.sub("", s)
    s = re.sub(r"\s+", " ", s)
    return s.strip()


_HIVE_ALIASES = [
    (re.compile(r"hkey_local_machine", re.I), "hklm"),
    (re.compile(r"hkey_current_user", re.I), "hkcu"),
    (re.compile(r"hkey_classes_root", re.I), "hkcr"),
    (re.compile(r"hkey_current_config", re.I), "hkcc"),
    (re.compile(r"hkey_users", re.I), "hku"),
    (re.compile(r"\bcurrentcontrolset\b", re.I), "controlsetnnn"),
    (re.compile(r"\bcontrolset\d+\b", re.I), "controlsetnnn"),
]


def _norm_registry(v: str) -> str:
    v = _canon(v).replace("\\", "/").lower()
    for pat, rep in _HIVE_ALIASES:
        v = pat.sub(rep, v)
    return v.rstrip("/")


def _boundary_substr(needle: str, hay: str) -> bool:
    """True iff needle occurs in hay ending at a segment/word boundary."""
    if not needle:
        return False
    start = 0
    while True:
        i = hay.find(needle, start)
        if i < 0:
            return False
        end = i + len(needle)
        if end == len(hay) or hay[end] in "/\\ \t|":
            return True
        start = i + 1


def literal_in_context(literal: str, context: str, kind: str) -> Tuple[bool, str]:
    """Deterministic, conservative 'does literal appear verbatim in context'.

    Returns (grounded, tier). Biased to NOT-grounded when uncertain so it never
    false-grounds a different value (one-char-off hash, hive prefix, etc.).
    """
    if not literal:
        return False, "none"
    # CLEAN kinds: boundary-safe token membership (agrees with scorer.py).
    if kind in CLEAN_KINDS:
        try:
            toks = _scorer.extract_tokens(_canon(context), kind)
            want = _scorer.normalize(kind, _canon(literal))
        except Exception:
            return False, "none"
        return (want in toks, "clean_token" if want in toks else "none")
    # registry: hive-normalised, boundary-guarded substring.
    if kind == "registry_key":
        nl, nc = _norm_registry(literal), _norm_registry(context)
        return (True, "normalized") if _boundary_substr(nl, nc) else (False, "none")
    # path: separator/case-normalised substring.
    if kind in ("path", "file_path"):
        nl = _scorer._norm_path(literal)
        nc = _canon(context).replace("\\", "/").lower()
        return (True, "normalized") if (nl and nl in nc) else (False, "none")
    # username/hostname/other text: canon exact then case-insensitive.
    cl, cc = _canon(literal), _canon(context)
    if cl and cl in cc:
        return True, "exact"
    if cl and cl.lower() in cc.lower():
        return True, "normalized"
    return False, "none"


# --- citation resolution (G13-1) --------------------------------------------
def load_case_input_obj(path: str) -> dict:
    """Parsed case-input JSON object (keeps artifact_id -> content)."""
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def build_citation_index(bash_log: Optional[dict], case_input_obj: Optional[dict]) -> Dict[str, dict]:
    """Map each citation id (upper-cased) to the ONE source it names.

    ART-NNN -> {src_kind:'artifact', content:<str>}; tool:<id>/toolu_<id> ->
    {src_kind:'bash'|'read'|'mcp', tuid:<id>}. Key-independent.
    """
    idx: Dict[str, dict] = {}
    arts = (case_input_obj or {}).get("artifacts")
    if isinstance(arts, list):
        for a in arts:
            if not isinstance(a, dict):
                continue
            aid = a.get("artifact_id")
            if not isinstance(aid, str) or not aid.strip():
                continue
            parts = [str(a.get("content", "") or "")]
            fa = a.get("forensic_anomalies")
            if isinstance(fa, list):
                parts.extend(str(x) for x in fa)
            elif isinstance(fa, str):
                parts.append(fa)
            idx[aid.strip().upper()] = {  # duplicate artifact_id: last wins
                "src_kind": "artifact",
                "content": "\n".join(p for p in parts if p),
                "tuid": None,
            }
    for tuid, entry in (bash_log or {}).items():
        tname = ""
        if isinstance(entry, dict):
            tname = str(entry.get("tool_name") or "").lower()
        sk = "bash"
        if tname in ("read", "write"):
            sk = "read"
        elif "mcp" in tname:
            sk = "mcp"
        idx["TOOL:" + str(tuid).upper()] = {"src_kind": sk, "content": None, "tuid": tuid}
    return idx


def _citations_in(text: str) -> List[str]:
    out: List[str] = []
    for m in ART_ID_RE.findall(text):
        out.append(m.upper())
    for m in TOOL_ID_RE.finditer(text):
        tid = m.group(1) or m.group(2)
        if tid:
            out.append("TOOL:" + tid.upper())
    # stable de-dup
    seen, uniq = set(), []
    for c in out:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq


# --- literal extraction (clean via scorer; fuzzy here, G13-4) ----------------
def _raw_clean(text: str, kind: str) -> List[str]:
    if kind == "email":
        return _scorer.EMAIL_RE.findall(text)
    if kind == "hash":
        return _scorer.HASH_RE.findall(text)
    if kind == "mac":
        return _scorer.MAC_RE.findall(text)
    if kind == "ipv4":
        return _scorer.extract_ipv4(text)
    if kind == "sid":
        return _scorer.SID_RE.findall(text)
    return []


_PATH_RE = re.compile(r"(?:[A-Za-z]:[\\/]|\\\\[^\\/\s|`]+[\\/])[^\s|`<>]+")
_REG_RE = re.compile(
    r"\b(?:HK(?:LM|CU|CR|U|CC)|HKEY_[A-Z_]+)(?:[\\/][^\s|`<>]+)+", re.IGNORECASE
)
_REG_RE2 = re.compile(
    r"\b(?:Current)?ControlSet\d*(?:[\\/][^\s|`<>]+)+", re.IGNORECASE
)
_USER_ANCHOR_RE = re.compile(
    r"(?:user(?:name)?|owner|logon|account|profile)\W{0,4}[:=]\s*([A-Za-z][\w .\-]{0,40}?)(?:\s*[|`,;]|$)",
    re.IGNORECASE,
)
_USER_PATH_RE = re.compile(r"(?:Users|Documents and Settings)[\\/]([^\\/\s|`<>]+)", re.IGNORECASE)


def extract_fuzzy_literals(text: str, kind: str) -> List[str]:
    """Anchor-gated extraction of path / registry_key / username literals."""
    if kind in ("path", "file_path"):
        return list(dict.fromkeys(_PATH_RE.findall(text)))
    if kind == "registry_key":
        out = list(_REG_RE.findall(text)) + list(_REG_RE2.findall(text))
        return list(dict.fromkeys(out))
    if kind == "username":
        out = [m.strip() for m in _USER_ANCHOR_RE.findall(text)]
        out += [m.strip() for m in _USER_PATH_RE.findall(text)]
        return list(dict.fromkeys(u for u in out if u))
    return []


def _row_label(text: str) -> Optional[str]:
    m = _CONF_RE.search(text)
    if not m:
        return None
    return m.group(1).upper().replace("  ", " ")


def _row_literals(text: str) -> List[Tuple[str, str]]:
    """(literal, kind) pairs in a line, clean kinds + fuzzy kinds."""
    out: List[Tuple[str, str]] = []
    for kind in ("email", "hash", "mac", "ipv4", "sid"):
        for raw in _raw_clean(text, kind):
            out.append((raw, kind))
    for kind in ("file_path", "registry_key", "username"):
        for raw in extract_fuzzy_literals(text, kind):
            out.append((raw, kind))
    # de-dup on (normalised-ish literal, kind)
    seen, uniq = set(), []
    for lit, kind in out:
        key = (lit.lower(), kind)
        if key not in seen:
            seen.add(key)
            uniq.append((lit, kind))
    return uniq


def parse_grounding_rows(report_text: str) -> List[dict]:
    """One record per (line that carries a literal): literals, citations, label.

    Covers both markdown table rows and prose lines (single consistent parser);
    citation binding is per-line (conservative)."""
    rows = []
    for line in (report_text or "").splitlines():
        if not line.strip():
            continue
        lits = _row_literals(line)
        if not lits:
            continue
        rows.append({
            "line": line.strip(),
            "literals": lits,
            "citations": _citations_in(line),
            "label": _row_label(line),
        })
    return rows


def _tier_of(kind: str) -> str:
    if kind in CLEAN_KINDS:
        return "strict"
    if kind in NORMALIZED_KINDS:
        return "normalized"
    return "advisory"


# --- the verifier (G13-3) ---------------------------------------------------
_STATUSES = (
    "cited_grounded", "cited_grounded_union", "mis_cited", "ungrounded",
    "unverifiable_read_mcp", "unverifiable_truncated", "uncited", "abstained",
)


def score_grounding(report_text: str, bash_log: Optional[dict], case_input_obj: Optional[dict]) -> dict:
    idx = build_citation_index(bash_log, case_input_obj)
    bash_log = bash_log or {}
    # whole-input + all-receipt haystack (for mis_cited vs ungrounded).
    whole_parts = []
    for v in idx.values():
        if v["src_kind"] == "artifact" and v.get("content"):
            whole_parts.append(v["content"])
    for tuid in bash_log:
        whole_parts.append(_bashlog.get_stdout(bash_log, tuid, read_persisted=True))
    whole_context = "\n".join(p for p in whole_parts if p)

    findings = []
    for row in parse_grounding_rows(report_text):
        label = row["label"]
        cites = row["citations"]
        for literal, kind in row["literals"]:
            tier = _tier_of(kind)
            rec = {"literal": literal, "kind": kind, "tier": tier,
                   "label": label, "citations": list(cites), "status": None}
            if label in _ABSTAIN:
                rec["status"] = "abstained"
                findings.append(rec)
                continue
            if not cites:
                rec["status"] = "uncited"
                findings.append(rec)
                continue
            resolved = [(c, idx.get(c)) for c in cites]
            if any(r is None for _, r in resolved):
                rec["status"] = "unverifiable_read_mcp"  # unresolved citation
                findings.append(rec)
                continue
            if any(r["src_kind"] in ("read", "mcp") for _, r in resolved):
                rec["status"] = "unverifiable_read_mcp"
                findings.append(rec)
                continue
            cited_parts, persisted_unread = [], False
            for _, r in resolved:
                if r["src_kind"] == "artifact":
                    cited_parts.append(r.get("content") or "")
                else:
                    tuid = r["tuid"]
                    cited_parts.append(_bashlog.get_stdout(bash_log, tuid, read_persisted=True))
                    e = bash_log.get(tuid) or {}
                    if e.get("persisted_output_path") and not _bashlog._read_persisted(e):
                        persisted_unread = True
            cited_context = "\n".join(p for p in cited_parts if p)
            grounded, _t = literal_in_context(literal, cited_context, kind)
            if grounded:
                rec["status"] = "cited_grounded" if len(cites) == 1 else "cited_grounded_union"
                findings.append(rec)
                continue
            in_whole, _t2 = literal_in_context(literal, whole_context, kind)
            if in_whole:
                rec["status"] = "mis_cited"
            elif persisted_unread:
                rec["status"] = "unverifiable_truncated"
            else:
                rec["status"] = "ungrounded"
            findings.append(rec)

    counts = {s: 0 for s in _STATUSES}
    per_tier = {t: {s: 0 for s in _STATUSES} for t in ("strict", "normalized", "advisory")}
    for f in findings:
        counts[f["status"]] += 1
        per_tier[f["tier"]][f["status"]] += 1

    # citation_precision over strict+normalized, scored (non-advisory, non-abstain).
    cg = per_tier["strict"]["cited_grounded"] + per_tier["normalized"]["cited_grounded"]
    mc = per_tier["strict"]["mis_cited"] + per_tier["normalized"]["mis_cited"]
    precision = (cg / (cg + mc)) if (cg + mc) else None

    violations = {
        "mis_cited": [f for f in findings if f["status"] == "mis_cited"],
        "ungrounded_literal": [f for f in findings if f["status"] == "ungrounded" and f["tier"] != "advisory"],
        "uncited_claim": [f for f in findings if f["status"] == "uncited" and f["tier"] != "advisory"],
        "advisory": [f for f in findings if f["tier"] == "advisory" and f["status"] in ("mis_cited", "ungrounded")],
    }
    return {
        "advisory": True,
        "citation_precision": precision,
        "counts": counts,
        "per_tier": per_tier,
        "violations": violations,
        "findings": findings,
        "note": "ADVISORY ONLY -- not a keep/revert signal; key-independent; "
                "fabrication=0 (scorer.py) is untouched. Read/MCP path needs a "
                "span-aware loader; thin real coverage until a raw-evidence case lands.",
    }


# --- advisory wrapper + CLI (G13-5) -----------------------------------------
def score_report(report_text: str, bash_log: Optional[dict] = None, case_input_obj: Optional[dict] = None) -> dict:
    g = score_grounding(report_text, bash_log, case_input_obj)
    return {"advisory": True, "citation_precision": g["citation_precision"], "grounding": g}


def score_report_from_files(report_path: str, bash_log_path: Optional[str] = None,
                            case_input_path: Optional[str] = None) -> dict:
    report_text = open(report_path, encoding="utf-8").read()
    bash_log = _bashlog.load_bash_log(bash_log_path) if bash_log_path else {}
    case_obj = load_case_input_obj(case_input_path) if case_input_path else {}
    return score_report(report_text, bash_log, case_obj)


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    p = argparse.ArgumentParser(description="G13 advisory cited-receipt grounding verifier")
    p.add_argument("--report", required=True)
    p.add_argument("--bash-log", default=None)
    p.add_argument("--case-input", default=None)
    a = p.parse_args(argv)
    out = score_report_from_files(a.report, a.bash_log, a.case_input)
    print(json.dumps(out, indent=2, default=lambda o: f"<{type(o).__name__}>"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Deterministic IOC scorer for the VIGIA DFIR cases.

Grades a Protocol SIFT investigation report against a case's ``ground_truth.json``
using **exact-token matching only** — no LLM judge anywhere in this file.

Design rule (the whole point of this harness)
----------------------------------------------
Grade only facts the agent could actually find, and penalise facts it made up.
The ground truth lists IOCs derived from the *full disk image*, but the agent
only ever sees the case file's artifact summaries. So:

* The PRIMARY metric is IOC recall over the **findable** subset — IOCs whose
  value actually appears in the agent's input. Rewarding IOCs that are absent
  from the input would train the agent to hallucinate, the exact failure this
  project exists to fix.
* A **fabrication** penalty flags IOC-shaped tokens the report asserts that are
  not present in the input.

Matching, per type
------------------
Clean types (email, file_hash, mac_address, ip_address, windows_sid) are
regex-extracted, normalised, and **set-compared**. Fuzzy types (file_path,
hostname, username) are matched by **substring** of the normalised ground-truth
value (usernames additionally token-boundary-anchored).

Normalisation is the *weakest correct form only* — it never lets a wrong answer
pass:

==============  ==========================================================
type            normalisation
==============  ==========================================================
email           lowercase
file_hash       lowercase, strip ``0x`` prefix, strip spaces/colons
mac_address     strip ``:`` ``-`` ``.``, lowercase
ip_address      exact (octets validated 0-255 on extraction)
windows_sid     uppercase
file_path       ``\\`` -> ``/``, drop trailing slash, case-insensitive
hostname        case-insensitive (substring)
username        case-insensitive (token-boundary substring; diagnostic only)
==============  ==========================================================

CIDR handling (research-backed): a ``/NN`` range is a separate annotated class,
not a host IOC. Its network/base address (e.g. ``10.11.11.0`` from
``10.11.11.0/24``) is **never** extracted as a host IP and **never** counted as a
fabrication — per RFC 950/919 the all-zeros host field is the network id, not an
assignable host, so flagging it would be a category error.

username handling (research-backed): usernames are weak/contextual identity
indicators (PRISM IOC benchmark excludes them; MISP/STIX model them as contextual
attributes). They are scored fuzzily and contribute ONLY to the full-recall
diagnostic — never to the headline findable-recall, and never to fabrication.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any


# =============================================================================
# Type taxonomy: ground-truth IOC ``type`` -> internal scoring kind.
# =============================================================================
TYPE_KIND = {
    "email": "email",
    "file_hash": "hash",
    "mac_address": "mac",
    "ip_address": "ipv4",
    "windows_sid": "sid",
    "file_path": "path",
    "hostname": "hostname",
    "username": "username",
}

#: Clean kinds: extract + normalise + set-compare. These are also the only kinds
#: subject to the fabrication penalty (email, hash, MAC, IPv4, SID).
CLEAN_KINDS = {"email", "hash", "mac", "ipv4", "sid"}
#: Fuzzy kinds: substring search of the normalised ground-truth value.
FUZZY_KINDS = {"path", "hostname", "username"}


# =============================================================================
# Normalisers — the weakest correct form only; never pass a wrong answer.
# =============================================================================
def _norm_email(v: str) -> str:
    return v.strip().lower()


def _norm_hash(v: str) -> str:
    v = v.strip().lower()
    if v.startswith("0x"):
        v = v[2:]
    return re.sub(r"[\s:]", "", v)


def _norm_mac(v: str) -> str:
    return re.sub(r"[:\-.]", "", v.strip().lower())


def _norm_ipv4(v: str) -> str:
    return v.strip()


def _norm_sid(v: str) -> str:
    return v.strip().upper()


def _norm_path(v: str) -> str:
    v = v.strip().replace("\\", "/").lower()
    if len(v) > 1:
        v = v.rstrip("/")
    return v


def _norm_lower(v: str) -> str:  # hostname, username
    return v.strip().lower()


NORMALISERS = {
    "email": _norm_email,
    "hash": _norm_hash,
    "mac": _norm_mac,
    "ipv4": _norm_ipv4,
    "sid": _norm_sid,
    "path": _norm_path,
    "hostname": _norm_lower,
    "username": _norm_lower,
}


def normalize(kind: str, value: str) -> str:
    """Normalise ``value`` for its scoring ``kind`` (the weakest correct form)."""
    return NORMALISERS[kind](value)


# =============================================================================
# Extractors — regex for the clean kinds; CIDR matched before bare IPv4.
# =============================================================================
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# MD5 / SHA-1 / SHA-256, longest first so a 64-hex is not also read as a 32-hex.
HASH_RE = re.compile(
    r"\b(?:0x)?[0-9a-fA-F]{64}\b|\b(?:0x)?[0-9a-fA-F]{40}\b|\b(?:0x)?[0-9a-fA-F]{32}\b"
)
# Colon/hyphen 6-octet form, or Cisco dotted-triple form.
MAC_RE = re.compile(
    r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b|\b(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}\b"
)
SID_RE = re.compile(r"\bS-1-\d+(?:-\d+)+\b", re.IGNORECASE)
CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def _valid_ipv4(tok: str) -> bool:
    parts = tok.split(".")
    return len(parts) == 4 and all(p and int(p) <= 255 for p in parts)


def extract_cidrs(text: str) -> list[str]:
    """All ``a.b.c.d/NN`` ranges whose base parses as a valid network."""
    out = []
    for tok in CIDR_RE.findall(text):
        ip = tok.split("/")[0]
        if _valid_ipv4(ip):
            out.append(tok)
    return out


def extract_ipv4(text: str) -> list[str]:
    """Bare host IPv4s, with CIDR spans masked out first.

    Masking the CIDR spans is what stops ``10.11.11.0`` inside ``10.11.11.0/24``
    from being mis-read as a fabricated host address.
    """
    masked = CIDR_RE.sub(" ", text)
    return [ip for ip in IPV4_RE.findall(masked) if _valid_ipv4(ip)]


def extract_tokens(text: str, kind: str) -> set[str]:
    """Normalised set of clean-kind tokens found in ``text``."""
    if kind == "email":
        raw: list[str] = EMAIL_RE.findall(text)
    elif kind == "hash":
        raw = HASH_RE.findall(text)
    elif kind == "mac":
        raw = MAC_RE.findall(text)
    elif kind == "ipv4":
        raw = extract_ipv4(text)
    elif kind == "sid":
        raw = SID_RE.findall(text)
    else:
        raise ValueError(f"not a clean kind: {kind}")
    return {normalize(kind, t) for t in raw}


def extract_mitre(text: str) -> set[str]:
    """Uppercased MITRE technique ids present in ``text`` (e.g. ``T1595.001``)."""
    return {t.upper() for t in MITRE_RE.findall(text)}


# =============================================================================
# Presence tests — does an IOC value appear in a given haystack?
# =============================================================================
def _fuzzy_present(value: str, text: str, kind: str) -> bool:
    nv = normalize(kind, value)
    if not nv:
        return False
    if kind == "path":
        return nv in text.replace("\\", "/").lower()
    if kind == "hostname":
        return nv in text.lower()
    if kind == "username":  # token-boundary anchored to avoid spurious hits
        pat = r"(?<![A-Za-z0-9_])" + re.escape(nv) + r"(?![A-Za-z0-9_])"
        return re.search(pat, text.lower()) is not None
    raise ValueError(f"not a fuzzy kind: {kind}")


def ioc_present(ioc: dict, text: str) -> bool:
    """True if ``ioc``'s value appears in ``text`` under its type's matching rule."""
    kind = TYPE_KIND[ioc["type"]]
    if kind in CLEAN_KINDS:
        return normalize(kind, ioc["value"]) in extract_tokens(text, kind)
    return _fuzzy_present(ioc["value"], text, kind)


# =============================================================================
# Verdict / MITRE / fabrication.
# =============================================================================
# Verdict equivalence classes — synonym token lists per semantic class.
# SOURCE OF TRUTH: protocol-sift/contract/contract.yaml (verdict.equivalence_classes).
# Mirrored here so the scorer has no cross-machine runtime dependency; keep the two in
# sync (Phase 6 unifies them). Scoring matches the parsed ``VERDICT:`` line FIELD against
# these classes — never a prose substring — so ``NON_MALICE`` is never misread as ``MALICE``.
VERDICT_CLASSES: dict[str, set[str]] = {
    "malicious":     {"MALICE", "MALICIOUS"},
    "non_malicious": {"NON_MALICE", "NONMALICE", "BENIGN"},
    "inconclusive":  {"INCONCLUSIVE", "INDETERMINATE", "UNKNOWN"},
}

# The explicit verdict line the Deliverable Contract requires, e.g.
#   VERDICT: MALICE — act: HIGH, attribution: MODERATE
_VERDICT_LINE_RE = re.compile(r"VERDICT:\s*\*{0,2}\s*([A-Za-z][A-Za-z_-]*)", re.IGNORECASE)


def _verdict_class(token: str) -> str | None:
    """Semantic class for a verdict token (case- and ``-``/``_``-insensitive), or None."""
    norm = token.strip().upper().replace("-", "_")
    for cls, members in VERDICT_CLASSES.items():
        if norm in {m.upper().replace("-", "_") for m in members}:
            return cls
    return None


def parse_report_verdict(report_text: str) -> str | None:
    """The token on the report's ``VERDICT:`` line — the LAST recognized one, since the
    contract places the real verdict last — or None if there is no ``VERDICT:`` line."""
    matches = _VERDICT_LINE_RE.findall(report_text)
    if not matches:
        return None
    known = [t for t in matches if _verdict_class(t) is not None]
    return known[-1] if known else matches[-1]


def verdict_status(report_text: str, gt_verdict: str) -> str:
    """``"found"`` iff the report's parsed ``VERDICT:`` token is in the SAME semantic
    class as the ground-truth verdict; otherwise ``"not_emitted"``.

    Parses the explicit ``VERDICT:`` line ONLY (never a prose substring), so a benign
    ``VERDICT: NON_MALICE`` is never mis-scored as ``MALICE`` and any synonym within a
    class matches. A present-but-wrong-class verdict returns ``"not_emitted"`` — no
    correct verdict was emitted."""
    token = parse_report_verdict(report_text)
    if token is None:
        return "not_emitted"
    gt_class = _verdict_class(gt_verdict)
    return "found" if (gt_class is not None and _verdict_class(token) == gt_class) else "not_emitted"


def _mitre_satisfied(gt_code: str, found: set[str]) -> bool:
    """Is a ground-truth technique satisfied by the report's extracted codes?

    Hierarchy-aware: an exact hit always counts; additionally, when the GT code is a
    PARENT (no ``.sub`` part) it is satisfied by ANY reported sub-technique of it, since
    a sub-technique entails its parent (e.g. report ``T1567.002`` satisfies GT ``T1567``).
    The looser reverse — a reported parent satisfying a GT *sub* — is NOT credited, nor is
    a sibling sub (``T1585.002`` never satisfies GT ``T1585.001``); we never reward a
    mapping vaguer or different than the key requires.
    """
    gt = gt_code.upper()
    if gt in found:
        return True
    if "." not in gt:  # GT is a parent -> any reported sub-technique of it counts
        return any(f.startswith(gt + ".") for f in found)
    return False


def mitre_recall(report_text: str, ttps: list[str]) -> tuple[dict[str, bool], int, int]:
    """Per-technique presence map + (present, total).

    Matching is MITRE-hierarchy aware via :func:`_mitre_satisfied`: a GT parent code is
    satisfied by an exact hit OR any reported sub-technique of it; a GT sub code needs an
    exact hit. Raw extraction (:func:`extract_mitre`) stays literal — the hierarchy logic
    lives only here, at the recall/credit layer."""
    found = extract_mitre(report_text)
    present = {t: _mitre_satisfied(t, found) for t in ttps}
    return present, sum(present.values()), len(ttps)


def find_fabrications(
    report_text: str, input_text: str
) -> tuple[list[dict], list[dict]]:
    """IOC-shaped tokens asserted by the report but absent from the input.

    Returns ``(fabrications, asserted_cidrs)``. Fabrications cover only the clean
    fabrication kinds (email, hash, MAC, IPv4, SID). CIDR ranges are reported
    separately as a diagnostic — never counted as a fabricated host IOC.
    """
    fabrications: list[dict] = []
    for kind in ("email", "hash", "mac", "ipv4", "sid"):
        in_report = extract_tokens(report_text, kind)
        in_input = extract_tokens(input_text, kind)
        for tok in sorted(in_report - in_input):
            fabrications.append({"type": kind, "value": tok})

    input_ips = extract_tokens(input_text, "ipv4")
    asserted_cidrs: list[dict] = []
    for cidr in sorted(set(extract_cidrs(report_text)) - set(extract_cidrs(input_text))):
        covered = _covered_input_hosts(cidr, input_ips)
        asserted_cidrs.append({"value": cidr, "covers_input_hosts": covered})
    return fabrications, asserted_cidrs


def _covered_input_hosts(cidr: str, input_ips: set[str]) -> list[str]:
    """Which input host IPs fall inside ``cidr`` (explains an inferred subnet)."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    out = []
    for ip in sorted(input_ips):
        try:
            if ipaddress.ip_address(ip) in net:
                out.append(ip)
        except ValueError:
            continue
    return out


# =============================================================================
# Per-case scoring.
# =============================================================================
@dataclass
class IOCRecord:
    type: str
    value: str
    kind: str
    findable: bool
    found_in_report: bool
    normalized: str
    match_mode: str  # "clean" | "fuzzy"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class CaseResult:
    case_id: str
    iocs: list[IOCRecord]
    total_findable: int
    found_findable: int
    findable_recall: float | None  # PRIMARY headline; None when 0 findable
    total_iocs: int
    found_total: int
    full_recall: float | None  # diagnostic only
    fabrications: list[dict]
    fabrication_count: int
    asserted_cidrs: list[dict]
    verdict_expected: str
    verdict: str
    mitre_present: dict[str, bool]
    mitre_found: int
    mitre_total: int
    failures: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["iocs"] = [r.to_dict() for r in self.iocs]
        return d


def score_case(
    case_id: str, gt: dict, input_text: str, report_text: str
) -> CaseResult:
    """Score one case from parsed ground truth + raw input/report text."""
    records: list[IOCRecord] = []
    failures: list[dict] = []
    total_findable = found_findable = found_total = 0

    for ioc in gt.get("key_iocs", []):
        kind = TYPE_KIND.get(ioc["type"])
        if kind is None:  # unknown type: record, never silently drop
            continue
        findable = ioc_present(ioc, input_text)
        found = ioc_present(ioc, report_text)
        records.append(
            IOCRecord(
                type=ioc["type"],
                value=ioc["value"],
                kind=kind,
                findable=findable,
                found_in_report=found,
                normalized=normalize(kind, ioc["value"]),
                match_mode="clean" if kind in CLEAN_KINDS else "fuzzy",
            )
        )
        found_total += found
        if findable:
            total_findable += 1
            if found:
                found_findable += 1
            else:
                failures.append({"type": ioc["type"], "value": ioc["value"]})

    fabrications, asserted_cidrs = find_fabrications(report_text, input_text)
    present, mitre_found, mitre_total = mitre_recall(
        report_text, gt.get("mitre_ttps", [])
    )
    total_iocs = len(records)

    return CaseResult(
        case_id=case_id,
        iocs=records,
        total_findable=total_findable,
        found_findable=found_findable,
        findable_recall=(found_findable / total_findable) if total_findable else None,
        total_iocs=total_iocs,
        found_total=found_total,
        full_recall=(found_total / total_iocs) if total_iocs else None,
        fabrications=fabrications,
        fabrication_count=len(fabrications),
        asserted_cidrs=asserted_cidrs,
        verdict_expected=gt.get("verdict", ""),
        verdict=verdict_status(report_text, gt.get("verdict", "")),
        mitre_present=present,
        mitre_found=mitre_found,
        mitre_total=mitre_total,
        failures=failures,
    )


# =============================================================================
# Input loading: faithful "what the agent saw" haystack.
# =============================================================================
def _collect_strings(obj: Any) -> list[str]:
    """All string leaves of a parsed JSON object (real, un-escaped values)."""
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        out: list[str] = []
        for v in obj.values():
            out.extend(_collect_strings(v))
        return out
    if isinstance(obj, list):
        out = []
        for v in obj:
            out.extend(_collect_strings(v))
        return out
    return []


def load_case_input_text(path: str) -> str:
    """The case file as the agent reads it: all string values, real backslashes."""
    with open(path, encoding="utf-8") as fh:
        return "\n".join(_collect_strings(json.load(fh)))


def load_ground_truth(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def load_report_text(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# =============================================================================
# The 3 real cases (data lives under data/, gitignored — never commit case data).
# =============================================================================
CASES = [
    ("VIGIA-REAL-001", "ground_truth/VIGIA-REAL-001.json",
     "case_inputs/case1.json", "reports/VIGIA-REAL-001_investigation_report.md"),
    ("VIGIA-REAL-002", "ground_truth/VIGIA-REAL-002.json",
     "case_inputs/case2.json", "reports/VIGIA-REAL-002_investigation_report.md"),
    ("VIGIA-REAL-007", "ground_truth/VIGIA-REAL-007.json",
     "case_inputs/case7.json", "reports/VIGIA-REAL-007_investigation_report.md"),
]


def score_case_from_files(case_id: str, gt_path: str, input_path: str, report_path: str) -> CaseResult:
    return score_case(
        case_id,
        load_ground_truth(gt_path),
        load_case_input_text(input_path),
        load_report_text(report_path),
    )


# =============================================================================
# Aggregation + reporting.
# =============================================================================
def aggregate(results: list[CaseResult]) -> dict:
    sf = sum(r.total_findable for r in results)
    ff = sum(r.found_findable for r in results)
    si = sum(r.total_iocs for r in results)
    fi = sum(r.found_total for r in results)
    mt = sum(r.mitre_total for r in results)
    mf = sum(r.mitre_found for r in results)
    return {
        "findable_recall_micro": (ff / sf) if sf else None,
        "findable_found": ff,
        "findable_total": sf,
        "fabrication_count_total": sum(r.fabrication_count for r in results),
        "verdicts_emitted": sum(1 for r in results if r.verdict == "found"),
        "cases": len(results),
        "mitre_recall_micro": (mf / mt) if mt else None,
        "mitre_found": mf,
        "mitre_total": mt,
        "full_recall_micro": (fi / si) if si else None,
        "full_found": fi,
        "full_total": si,
    }


def _frac(n: int, d: int | None) -> str:
    if not d:
        return f"{n}/0 (n/a)"
    return f"{n}/{d} ({100 * n / d:.0f}%)"


def render(results: list[CaseResult], agg: dict) -> str:
    lines: list[str] = []
    lines.append("=" * 92)
    lines.append("VIGIA DFIR — deterministic IOC scorer  (exact-token matching, no LLM judge)")
    lines.append("=" * 92)

    # Per-case table.
    hdr = f"{'case':<16}{'findable_recall':<18}{'fabr':<6}{'verdict':<14}{'mitre':<12}{'full_recall':<14}"
    lines.append("")
    lines.append("PER-CASE  (findable_recall = PRIMARY metric; full_recall = diagnostic)")
    lines.append("-" * 92)
    lines.append(hdr)
    lines.append("-" * 92)
    for r in results:
        lines.append(
            f"{r.case_id:<16}"
            f"{_frac(r.found_findable, r.total_findable):<18}"
            f"{r.fabrication_count:<6}"
            f"{r.verdict:<14}"
            f"{_frac(r.mitre_found, r.mitre_total):<12}"
            f"{_frac(r.found_total, r.total_iocs):<14}"
        )
    lines.append("-" * 92)
    lines.append(
        f"{'AGGREGATE':<16}"
        f"{_frac(agg['findable_found'], agg['findable_total']):<18}"
        f"{agg['fabrication_count_total']:<6}"
        f"{str(agg['verdicts_emitted']) + '/' + str(agg['cases']) + ' emit':<14}"
        f"{_frac(agg['mitre_found'], agg['mitre_total']):<12}"
        f"{_frac(agg['full_found'], agg['full_total']):<14}"
    )

    # Recall failures.
    lines.append("")
    lines.append("RECALL FAILURES  (findable IOCs missing from the report)")
    lines.append("-" * 92)
    any_fail = False
    for r in results:
        for f in r.failures:
            any_fail = True
            lines.append(f"  {r.case_id}  {f['type']:<14} {f['value']}")
    if not any_fail:
        lines.append("  (none — every findable IOC was recovered)")

    # Fabricated tokens.
    lines.append("")
    lines.append("FABRICATED TOKENS  (IOC-shaped tokens in report, absent from input)")
    lines.append("-" * 92)
    any_fab = False
    for r in results:
        for f in r.fabrications:
            any_fab = True
            lines.append(f"  {r.case_id}  {f['type']:<8} {f['value']}")
    if not any_fab:
        lines.append("  (none)")

    # Asserted CIDR ranges (diagnostic).
    cidr_rows = [(r.case_id, c) for r in results for c in r.asserted_cidrs]
    if cidr_rows:
        lines.append("")
        lines.append("ASSERTED NETWORK RANGES  (CIDR; diagnostic, NOT counted as fabrication)")
        lines.append("-" * 92)
        for cid, c in cidr_rows:
            cov = c["covers_input_hosts"]
            note = f"covers input host(s): {', '.join(cov)}" if cov else "not derivable from input hosts"
            lines.append(f"  {cid}  {c['value']:<20} ({note})")

    # Headline restatement.
    lines.append("")
    lines.append("=" * 92)
    lines.append(
        f"HEADLINE  findable IOC recall (micro): {_frac(agg['findable_found'], agg['findable_total'])}"
        f"   |   fabrications: {agg['fabrication_count_total']}"
        f"   |   verdicts emitted: {agg['verdicts_emitted']}/{agg['cases']}"
        f"   |   MITRE recall: {_frac(agg['mitre_found'], agg['mitre_total'])}"
    )
    lines.append("=" * 92)
    return "\n".join(lines)


# =============================================================================
# CLI.
# =============================================================================
def _default_data_dir() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Deterministic IOC scorer for VIGIA DFIR cases.")
    ap.add_argument("--data-dir", default=_default_data_dir(),
                    help="dir holding ground_truth/, case_inputs/, reports/ (default: ./data)")
    ap.add_argument("--case", help="score a single case id (e.g. VIGIA-REAL-001)")
    ap.add_argument("--json", action="store_true", help="also print the full structured result as JSON")
    args = ap.parse_args(argv)

    selected = [c for c in CASES if (args.case is None or c[0] == args.case)]
    if not selected:
        ap.error(f"unknown case: {args.case}")

    results: list[CaseResult] = []
    for case_id, gt_rel, in_rel, rep_rel in selected:
        results.append(score_case_from_files(
            case_id,
            os.path.join(args.data_dir, gt_rel),
            os.path.join(args.data_dir, in_rel),
            os.path.join(args.data_dir, rep_rel),
        ))

    agg = aggregate(results)
    print(render(results, agg))
    if args.json:
        print("\n--- JSON ---")
        print(json.dumps({"cases": [r.to_dict() for r in results], "aggregate": agg},
                         indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

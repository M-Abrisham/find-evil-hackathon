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
# MITRE table parsing + citation-precision + id-validity.
# ADDITIVE: recall (extract_mitre / _mitre_satisfied / mitre_recall) is UNCHANGED.
# precision + validity are KEY-INDEPENDENT — they never read gt["mitre_ttps"].
# =============================================================================
ART_ID_RE = re.compile(r"\bART-\d{2,}\b", re.IGNORECASE)
_MITRE_HDR_RE = re.compile(
    r"^\s*\|\s*technique\s*\|\s*t-?code\s*\|\s*evidencing\s+artifact\s*\|\s*$",
    re.IGNORECASE,
)
_MITRE_SEP_RE = re.compile(r"^\s*\|[\s:|-]+\|\s*$")


@dataclass
class MitreRow:
    technique_name: str
    code: str
    evidencing: str
    citations: list[str]

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _split_md_cells(row: str) -> list[str]:
    s = row.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [c.strip() for c in s.split("|")]


def parse_mitre_table(report_text: str) -> list[MitreRow]:
    """Structured rows of the emitted MITRE table ONLY.

    Located by its exact contract header; the body is bounded to contiguous
    pipe-rows, so the trailing prose ``> Only techniques ...`` note (which cites
    bare T-codes precisely to explain what was *excluded*) is never a row. The
    code is read from COLUMN 2 only, so a second T-code inside a citation cell
    (e.g. ``... overlaps T1665``) can never displace the row's real code.

    Substrate for the citation-precision metric; RECALL still uses the lenient
    :func:`extract_mitre` (unchanged), so existing tests stay green.
    """
    lines = report_text.splitlines()
    rows: list[MitreRow] = []
    i = 0
    while i < len(lines):
        if _MITRE_HDR_RE.match(lines[i]):
            j = i + 1
            if j < len(lines) and _MITRE_SEP_RE.match(lines[j]):
                j += 1
            while j < len(lines) and lines[j].lstrip().startswith("|"):
                cells = _split_md_cells(lines[j])
                if len(cells) >= 3:
                    code_m = MITRE_RE.search(cells[1])  # COLUMN 2 only
                    if code_m:  # skips the "<technique name> | T#### | ..." placeholder
                        rows.append(MitreRow(
                            technique_name=cells[0],
                            code=code_m.group(0).upper(),
                            evidencing=cells[2],
                            citations=[c.upper() for c in ART_ID_RE.findall(cells[2])],
                        ))
                j += 1
            i = j
            continue
        i += 1
    return rows


def _row_grounded(evidencing_cell: str) -> bool:
    """A MITRE row is grounded iff its Evidencing cell cites an ART-id OR a
    tool-output token (the contract allows "ART-id or tool output"). Empty or
    placeholder cells are not grounded."""
    cell = evidencing_cell.strip()
    if not cell or cell in {"-", "—", "N/A", "<ART-id / tool output>"}:
        return False
    if ART_ID_RE.search(cell):
        return True
    return "`" in cell  # tool-output fallback: a backtick-quoted tool/value token


def mitre_precision(report_text: str) -> tuple[float | None, int, int, list[str]]:
    """Grounded-citation precision over the EMITTED MITRE table only.

    Returns ``(precision, grounded, emitted, ungrounded_codes)``. ``precision`` is
    ``None`` when the report has no MITRE table (n/a — never a false 0). NEVER reads
    ``gt``: a row is judged solely by whether it cites evidence, so a correct
    evidence-cited mapping absent from the answer key still scores 1.0 (the
    anti-Goodhart property). The only thing penalised is an uncited row — i.e.
    literal recall-padding.
    """
    rows = parse_mitre_table(report_text)
    if not rows:
        return None, 0, 0, []
    grounded = 0
    ungrounded: list[str] = []
    for r in rows:
        if _row_grounded(r.evidencing):
            grounded += 1
        else:
            ungrounded.append(r.code)
    return grounded / len(rows), grounded, len(rows), ungrounded


# --- Frozen offline ATT&CK Enterprise technique-id catalog -------------------
# SOURCE: MITRE ATT&CK Enterprise STIX bundle (mitre/cti enterprise-attack.json),
# the non-deprecated / non-revoked attack-pattern external_ids. Generated ONCE,
# offline, committed as a static literal so the scorer keeps NO runtime/network
# dependency (same policy as VERDICT_CLASSES). Refresh only on an intentional
# ATT&CK version bump. Key-INDEPENDENT: a SUPERSET of every answer-key code AND of
# the agent's defensible off-key codes, so membership never penalises a correct
# mapping merely absent from the key.
VALID_MITRE_IDS: frozenset[str] = frozenset({
    "T1001", "T1001.001", "T1001.002", "T1001.003", "T1003", "T1003.001", "T1003.002", "T1003.003",
    "T1003.004", "T1003.005", "T1003.006", "T1003.007", "T1003.008", "T1005", "T1006", "T1007",
    "T1008", "T1010", "T1011", "T1011.001", "T1012", "T1014", "T1016", "T1016.001",
    "T1016.002", "T1018", "T1020", "T1020.001", "T1021", "T1021.001", "T1021.002", "T1021.003",
    "T1021.004", "T1021.005", "T1021.006", "T1021.007", "T1021.008", "T1025", "T1027", "T1027.001",
    "T1027.002", "T1027.003", "T1027.004", "T1027.005", "T1027.006", "T1027.007", "T1027.008", "T1027.009",
    "T1027.010", "T1027.011", "T1027.012", "T1027.013", "T1027.014", "T1027.015", "T1027.016", "T1027.017",
    "T1027.018", "T1029", "T1030", "T1033", "T1036", "T1036.001", "T1036.002", "T1036.003",
    "T1036.004", "T1036.005", "T1036.006", "T1036.007", "T1036.008", "T1036.009", "T1036.010", "T1036.011",
    "T1036.012", "T1037", "T1037.001", "T1037.002", "T1037.003", "T1037.004", "T1037.005", "T1039",
    "T1040", "T1041", "T1046", "T1047", "T1048", "T1048.001", "T1048.002", "T1048.003",
    "T1049", "T1052", "T1052.001", "T1053", "T1053.002", "T1053.003", "T1053.005", "T1053.006",
    "T1053.007", "T1055", "T1055.001", "T1055.002", "T1055.003", "T1055.004", "T1055.005", "T1055.008",
    "T1055.009", "T1055.011", "T1055.012", "T1055.013", "T1055.014", "T1055.015", "T1056", "T1056.001",
    "T1056.002", "T1056.003", "T1056.004", "T1057", "T1059", "T1059.001", "T1059.002", "T1059.003",
    "T1059.004", "T1059.005", "T1059.006", "T1059.007", "T1059.008", "T1059.009", "T1059.010", "T1059.011",
    "T1059.012", "T1059.013", "T1068", "T1069", "T1069.001", "T1069.002", "T1069.003", "T1070",
    "T1070.003", "T1070.004", "T1070.005", "T1070.006", "T1070.007", "T1070.008", "T1070.009", "T1070.010",
    "T1071", "T1071.001", "T1071.002", "T1071.003", "T1071.004", "T1071.005", "T1072", "T1074",
    "T1074.001", "T1074.002", "T1078", "T1078.001", "T1078.002", "T1078.003", "T1078.004", "T1080",
    "T1082", "T1083", "T1087", "T1087.001", "T1087.002", "T1087.003", "T1087.004", "T1090",
    "T1090.001", "T1090.002", "T1090.003", "T1090.004", "T1091", "T1092", "T1095", "T1098",
    "T1098.001", "T1098.002", "T1098.003", "T1098.004", "T1098.005", "T1098.006", "T1098.007", "T1102",
    "T1102.001", "T1102.002", "T1102.003", "T1104", "T1105", "T1106", "T1110", "T1110.001",
    "T1110.002", "T1110.003", "T1110.004", "T1111", "T1112", "T1113", "T1114", "T1114.001",
    "T1114.002", "T1114.003", "T1115", "T1119", "T1120", "T1123", "T1124", "T1125",
    "T1127", "T1127.001", "T1127.002", "T1127.003", "T1129", "T1132", "T1132.001", "T1132.002",
    "T1133", "T1134", "T1134.001", "T1134.002", "T1134.003", "T1134.004", "T1134.005", "T1135",
    "T1136", "T1136.001", "T1136.002", "T1136.003", "T1137", "T1137.001", "T1137.002", "T1137.003",
    "T1137.004", "T1137.005", "T1137.006", "T1140", "T1176", "T1176.001", "T1176.002", "T1185",
    "T1187", "T1189", "T1190", "T1195", "T1195.001", "T1195.002", "T1195.003", "T1197",
    "T1199", "T1200", "T1201", "T1202", "T1203", "T1204", "T1204.001", "T1204.002",
    "T1204.003", "T1204.004", "T1204.005", "T1205", "T1205.001", "T1205.002", "T1207", "T1210",
    "T1211", "T1212", "T1213", "T1213.001", "T1213.002", "T1213.003", "T1213.004", "T1213.005",
    "T1213.006", "T1216", "T1216.001", "T1216.002", "T1217", "T1218", "T1218.001", "T1218.002",
    "T1218.003", "T1218.004", "T1218.005", "T1218.007", "T1218.008", "T1218.009", "T1218.010", "T1218.011",
    "T1218.012", "T1218.013", "T1218.014", "T1218.015", "T1219", "T1219.001", "T1219.002", "T1219.003",
    "T1220", "T1221", "T1222", "T1222.001", "T1222.002", "T1480", "T1480.001", "T1480.002",
    "T1482", "T1484", "T1484.001", "T1484.002", "T1485", "T1485.001", "T1486", "T1489",
    "T1490", "T1491", "T1491.001", "T1491.002", "T1495", "T1496", "T1496.001", "T1496.002",
    "T1496.003", "T1496.004", "T1497", "T1497.001", "T1497.002", "T1497.003", "T1498", "T1498.001",
    "T1498.002", "T1499", "T1499.001", "T1499.002", "T1499.003", "T1499.004", "T1505", "T1505.001",
    "T1505.002", "T1505.003", "T1505.004", "T1505.005", "T1505.006", "T1518", "T1518.001", "T1518.002",
    "T1525", "T1526", "T1528", "T1529", "T1530", "T1531", "T1534", "T1535",
    "T1537", "T1538", "T1539", "T1542", "T1542.001", "T1542.002", "T1542.003", "T1542.004",
    "T1542.005", "T1543", "T1543.001", "T1543.002", "T1543.003", "T1543.004", "T1543.005", "T1546",
    "T1546.001", "T1546.002", "T1546.003", "T1546.004", "T1546.005", "T1546.006", "T1546.007", "T1546.008",
    "T1546.009", "T1546.010", "T1546.011", "T1546.012", "T1546.013", "T1546.014", "T1546.015", "T1546.016",
    "T1546.017", "T1546.018", "T1547", "T1547.001", "T1547.002", "T1547.003", "T1547.004", "T1547.005",
    "T1547.006", "T1547.007", "T1547.008", "T1547.009", "T1547.010", "T1547.012", "T1547.013", "T1547.014",
    "T1547.015", "T1548", "T1548.001", "T1548.002", "T1548.003", "T1548.004", "T1548.005", "T1548.006",
    "T1550", "T1550.001", "T1550.002", "T1550.003", "T1550.004", "T1552", "T1552.001", "T1552.002",
    "T1552.003", "T1552.004", "T1552.005", "T1552.006", "T1552.007", "T1552.008", "T1553", "T1553.001",
    "T1553.002", "T1553.003", "T1553.004", "T1553.005", "T1553.006", "T1554", "T1555", "T1555.001",
    "T1555.002", "T1555.003", "T1555.004", "T1555.005", "T1555.006", "T1556", "T1556.001", "T1556.002",
    "T1556.003", "T1556.004", "T1556.005", "T1556.006", "T1556.007", "T1556.008", "T1556.009", "T1557",
    "T1557.001", "T1557.002", "T1557.003", "T1557.004", "T1558", "T1558.001", "T1558.002", "T1558.003",
    "T1558.004", "T1558.005", "T1559", "T1559.001", "T1559.002", "T1559.003", "T1560", "T1560.001",
    "T1560.002", "T1560.003", "T1561", "T1561.001", "T1561.002", "T1563", "T1563.001", "T1563.002",
    "T1564", "T1564.001", "T1564.002", "T1564.003", "T1564.004", "T1564.005", "T1564.006", "T1564.007",
    "T1564.008", "T1564.009", "T1564.010", "T1564.011", "T1564.012", "T1564.013", "T1564.014", "T1565",
    "T1565.001", "T1565.002", "T1565.003", "T1566", "T1566.001", "T1566.002", "T1566.003", "T1566.004",
    "T1567", "T1567.001", "T1567.002", "T1567.003", "T1567.004", "T1568", "T1568.001", "T1568.002",
    "T1568.003", "T1569", "T1569.001", "T1569.002", "T1569.003", "T1570", "T1571", "T1572",
    "T1573", "T1573.001", "T1573.002", "T1574", "T1574.001", "T1574.004", "T1574.005", "T1574.006",
    "T1574.007", "T1574.008", "T1574.009", "T1574.010", "T1574.011", "T1574.012", "T1574.013", "T1574.014",
    "T1578", "T1578.001", "T1578.002", "T1578.003", "T1578.004", "T1578.005", "T1580", "T1583",
    "T1583.001", "T1583.002", "T1583.003", "T1583.004", "T1583.005", "T1583.006", "T1583.007", "T1583.008",
    "T1584", "T1584.001", "T1584.002", "T1584.003", "T1584.004", "T1584.005", "T1584.006", "T1584.007",
    "T1584.008", "T1585", "T1585.001", "T1585.002", "T1585.003", "T1586", "T1586.001", "T1586.002",
    "T1586.003", "T1587", "T1587.001", "T1587.002", "T1587.003", "T1587.004", "T1588", "T1588.001",
    "T1588.002", "T1588.003", "T1588.004", "T1588.005", "T1588.006", "T1588.007", "T1589", "T1589.001",
    "T1589.002", "T1589.003", "T1590", "T1590.001", "T1590.002", "T1590.003", "T1590.004", "T1590.005",
    "T1590.006", "T1591", "T1591.001", "T1591.002", "T1591.003", "T1591.004", "T1592", "T1592.001",
    "T1592.002", "T1592.003", "T1592.004", "T1593", "T1593.001", "T1593.002", "T1593.003", "T1594",
    "T1595", "T1595.001", "T1595.002", "T1595.003", "T1596", "T1596.001", "T1596.002", "T1596.003",
    "T1596.004", "T1596.005", "T1597", "T1597.001", "T1597.002", "T1598", "T1598.001", "T1598.002",
    "T1598.003", "T1598.004", "T1599", "T1599.001", "T1600", "T1600.001", "T1600.002", "T1601",
    "T1601.001", "T1601.002", "T1602", "T1602.001", "T1602.002", "T1606", "T1606.001", "T1606.002",
    "T1608", "T1608.001", "T1608.002", "T1608.003", "T1608.004", "T1608.005", "T1608.006", "T1609",
    "T1610", "T1611", "T1612", "T1613", "T1614", "T1614.001", "T1615", "T1619",
    "T1620", "T1621", "T1622", "T1647", "T1648", "T1649", "T1650", "T1651",
    "T1652", "T1653", "T1654", "T1657", "T1659", "T1665", "T1666", "T1667",
    "T1668", "T1669", "T1671", "T1673", "T1674", "T1675", "T1677", "T1678",
    "T1679", "T1680", "T1681", "T1682", "T1683", "T1683.001", "T1683.002", "T1684",
    "T1684.001", "T1684.002", "T1685", "T1685.001", "T1685.002", "T1685.003", "T1685.004", "T1685.005",
    "T1685.006", "T1686", "T1686.001", "T1686.002", "T1686.003", "T1687", "T1688", "T1689",
    "T1690",
})


def mitre_validity(report_text: str) -> list[str]:
    """Extracted T-codes that are NOT real ATT&CK Enterprise ids (sorted).

    Reuses :func:`extract_mitre` so it inspects the EXACT tokens the recall path
    sees. Key-INDEPENDENT: asks only "is this a real ATT&CK id?", never "is it in
    the answer key?" — so a valid-but-off-key code (e.g. report-001's T1557)
    returns clean. Flags fabricated ids (T9999) and silent-truncation artefacts
    (T1234.5678, which MITRE_RE degrades to the non-existent T1234).
    """
    return sorted(c for c in extract_mitre(report_text) if c not in VALID_MITRE_IDS)


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
    # --- additive MITRE diagnostics: NEVER affect recall/verdict/IOC numbers ---
    mitre_rows: list[dict] = field(default_factory=list)
    mitre_emitted: int = 0
    mitre_grounded: int = 0
    mitre_precision: float | None = None
    mitre_ungrounded: list[str] = field(default_factory=list)
    invalid_mitre_codes: list[str] = field(default_factory=list)
    invalid_mitre_count: int = 0

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
    mitre_table_rows = parse_mitre_table(report_text)
    m_prec, m_grounded, m_emitted, m_ungrounded = mitre_precision(report_text)
    invalid_codes = mitre_validity(report_text)
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
        mitre_rows=[r.to_dict() for r in mitre_table_rows],
        mitre_emitted=m_emitted,
        mitre_grounded=m_grounded,
        mitre_precision=m_prec,
        mitre_ungrounded=m_ungrounded,
        invalid_mitre_codes=invalid_codes,
        invalid_mitre_count=len(invalid_codes),
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
    mg = sum(r.mitre_grounded for r in results)
    me = sum(r.mitre_emitted for r in results)
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
        "mitre_precision_micro": (mg / me) if me else None,
        "mitre_grounded_total": mg,
        "mitre_emitted_total": me,
        "invalid_mitre_total": sum(r.invalid_mitre_count for r in results),
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

    # MITRE precision (grounded rows / emitted rows; key-independent).
    lines.append("")
    lines.append("MITRE PRECISION  (grounded rows / emitted rows; key-independent — evidence citation only)")
    lines.append("-" * 92)
    for r in results:
        if r.mitre_precision is None:
            lines.append(f"  {r.case_id}  (no MITRE table — n/a)")
        else:
            extra = f"   UNGROUNDED: {chr(44).join(r.mitre_ungrounded)}" if r.mitre_ungrounded else ""
            lines.append(f"  {r.case_id}  {_frac(r.mitre_grounded, r.mitre_emitted)}{extra}")

    # Invalid MITRE codes (T-code shape but not a real ATT&CK id).
    lines.append("")
    lines.append("INVALID MITRE CODES  (T-code shape but not a real ATT&CK Enterprise id)")
    lines.append("-" * 92)
    any_inv = False
    for r in results:
        for c in r.invalid_mitre_codes:
            any_inv = True
            lines.append(f"  {r.case_id}  {c}")
    if not any_inv:
        lines.append("  (none — every emitted code is a real ATT&CK id)")

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

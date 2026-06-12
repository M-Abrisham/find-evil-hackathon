"""
Validate dataset/cases.jsonl against Phase 2 contracts.

Exit 0: all hard checks pass (warnings are printed but do not fail).
Exit 1: at least one hard check fails.
"""

import json
import re
import sys
import pathlib

ROOT = pathlib.Path(__file__).parent.parent
CASES_FILE = ROOT / "dataset" / "cases.jsonl"
MANIFEST_FILE = ROOT / "dataset" / "manifest.txt"

KNOWN_TOOLS = [
    "vol.py", "volatility", "MFTECmd", "EvtxECmd", "PECmd",
    "RECmd", "LECmd", "JLECmd", "log2timeline", "psort", "mmls",
    "fls", "icat",
]

GRID_SLOTS = {
    ("memory-analysis", "happy"), ("memory-analysis", "ambiguous"), ("memory-analysis", "absent"),
    ("sleuthkit", "happy"), ("sleuthkit", "ambiguous"), ("sleuthkit", "absent"),
    ("windows-artifacts", "happy"), ("windows-artifacts", "ambiguous"), ("windows-artifacts", "absent"),
    ("plaso-timeline", "happy"), ("plaso-timeline", "ambiguous"), ("plaso-timeline", "absent"),
    ("yara-hunting", "happy"), ("yara-hunting", "ambiguous"), ("yara-hunting", "absent"),
}

ALL_S = {"S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8"}

ABSENCE_CONTRACT = (
    'If the requested artifact does not exist in that folder, reply with a single line '
    'beginning "ABSENT:" describing what you searched for, and perform no further analysis.'
)

ABSPATH_RE = re.compile(r"/home/ubuntu/[^\s\"']+")


def load_manifest():
    if not MANIFEST_FILE.exists():
        return set(), []
    lines = MANIFEST_FILE.read_text().splitlines()
    return set(lines), lines


def check_path_in_manifest(path, manifest_set, manifest_lines):
    """Return True if path is a file in manifest or a directory prefix of >=1 manifest line."""
    if path in manifest_set:
        return True
    prefix = path.rstrip("/") + "/"
    return any(line.startswith(prefix) for line in manifest_lines)


def main():
    errors = []
    warnings = []

    # Load manifest
    manifest_set, manifest_lines = load_manifest()
    if not manifest_set:
        warnings.append("dataset/manifest.txt not found or empty — path checks skipped")

    # Parse JSONL
    if not CASES_FILE.exists():
        errors.append("dataset/cases.jsonl not found")
        _report(errors, warnings)
        sys.exit(1)

    cases = []
    for lineno, line in enumerate(CASES_FILE.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            case = json.loads(line)
            case["_lineno"] = lineno
            cases.append(case)
        except json.JSONDecodeError as e:
            errors.append(f"line {lineno}: JSON parse error: {e}")

    if errors:
        _report(errors, warnings)
        sys.exit(1)

    print(f"Parsed {len(cases)} cases.")

    # 1. Unique IDs
    seen_ids = {}
    for c in cases:
        cid = c.get("id", "")
        if cid in seen_ids:
            errors.append(f"Duplicate id '{cid}' at lines {seen_ids[cid]} and {c['_lineno']}")
        else:
            seen_ids[cid] = c["_lineno"]

    # 2. All 15 grid slots present
    covered_slots = set()
    for c in cases:
        slot = (c.get("feature"), c.get("scenario"))
        covered_slots.add(slot)
    for slot in GRID_SLOTS:
        if slot not in covered_slots:
            errors.append(f"Missing grid slot: feature={slot[0]} scenario={slot[1]}")

    # 3. Path checks for happy/ambiguous
    for c in cases:
        if c.get("scenario") not in ("happy", "ambiguous"):
            continue
        inp = c.get("input", "")
        paths = ABSPATH_RE.findall(inp)
        for path in paths:
            path = path.rstrip(".,;\"')")
            if manifest_set and not check_path_in_manifest(path, manifest_set, manifest_lines):
                errors.append(
                    f"[{c['id']}] path not in manifest: {path}"
                )

    # 4. Absent-scenario checks
    for c in cases:
        if c.get("scenario") != "absent":
            continue
        cid = c["id"]
        exp = c.get("expected", {})

        # absence_token must be set
        if exp.get("absence_token") != "ABSENT:":
            errors.append(f"[{cid}] absent case missing absence_token='ABSENT:'")

        # absent_re must be set
        absent_re_str = exp.get("absent_re")
        if not absent_re_str:
            errors.append(f"[{cid}] absent case missing absent_re")
        elif manifest_lines:
            try:
                pat = re.compile(absent_re_str)
                matches = [ln for ln in manifest_lines if pat.search(ln)]
                if matches:
                    errors.append(
                        f"[{cid}] absent_re '{absent_re_str}' matched {len(matches)} "
                        f"manifest lines (expected 0): {matches[:3]}"
                    )
            except re.error as e:
                errors.append(f"[{cid}] absent_re is invalid regex: {e}")

        # contract sentence must appear verbatim
        if ABSENCE_CONTRACT not in c.get("input", ""):
            errors.append(f"[{cid}] absent case missing verbatim contract sentence")

    # 5. S-series coverage: every S1-S8 in at least one s_asserts
    covered_s = set()
    for c in cases:
        covered_s.update(c.get("expected", {}).get("s_asserts", []))
    for s in ALL_S:
        if s not in covered_s:
            errors.append(f"S-assert {s} not covered by any case s_asserts")

    # 6. Warn on tool name leakage in inputs (word-boundary match to avoid substrings)
    tool_patterns = [(t, re.compile(r"\b" + re.escape(t) + r"\b", re.IGNORECASE)) for t in KNOWN_TOOLS]
    for c in cases:
        inp = c.get("input", "")
        for tool, pat in tool_patterns:
            if pat.search(inp):
                warnings.append(
                    f"[{c['id']}] input contains known tool name '{tool}' — flag for human review"
                )

    _report(errors, warnings)
    if errors:
        sys.exit(1)
    print("All checks passed.")


def _report(errors, warnings):
    for w in warnings:
        print(f"WARN  {w}")
    for e in errors:
        print(f"ERROR {e}")


if __name__ == "__main__":
    main()

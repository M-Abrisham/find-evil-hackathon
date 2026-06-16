#!/usr/bin/env python3
"""R6 - Verifier for the hash-chained command ledger (chain-of-custody auditor).

BUILD-TIME TOOLING ONLY (Protocol SIFT). Not hackathon-submission code.
STDLIB ONLY (hashlib, json). Distinct from the per-LAP optimizer score ledger.

WHAT IT CHECKS
--------------
Reads the JSONL ledger produced by ledger_hook.py and verifies the whole hash
chain. It detects, and reports the FIRST broken 0-based index for, every class
of tamper:

    * MUTATION  - any field of any entry changed (entry_hash recompute mismatch).
    * INSERTION - an extra line spliced in (its prev_hash won't match the real
                  predecessor's entry_hash; or seq stops being contiguous).
    * DELETION  - a line removed (the next line's prev_hash points at a hash that
                  is no longer present / seq gap).
    * REORDERING - lines swapped (prev_hash linkage and/or seq order break).

HOW (the invariants, all enforced):
    1. entry_hash[i] == compute_entry_hash(prev_hash[i], entry_i)   (self-integrity)
    2. prev_hash[0]  == "GENESIS"
    3. prev_hash[i]  == entry_hash[i-1]   for i > 0                  (chain linkage)
    4. seq[i]        == i                  (monotone, gap-free, 0-based)
    5. each line is valid JSON with the required fields

Any single tamper trips at least one of these at a deterministic index, which we
report. We surface ALL detected problems but the process exit code + the
"first_broken_index" make the break point unambiguous.

EXIT CODES
----------
    0  - chain intact (and non-empty, unless --allow-empty).
    1  - tampering / corruption detected (report on stdout, details on stderr).
    2  - usage / file-not-found error.

PUBLIC API
----------
    verify_lines(lines)  -> VerifyResult     (pure; lines = list of raw str)
    verify_file(path)    -> VerifyResult
    format_report(result, path=None) -> str
    main(argv=None)      -> int

USAGE
    python3 verify_ledger.py /path/to/command_ledger.jsonl
    python3 verify_ledger.py --ledger /path/to/ledger.jsonl --json
    python3 verify_ledger.py            # uses $SIFT_LEDGER_PATH or the default
"""

from __future__ import annotations

import json
import os
import sys

# Import the chain primitives from the hook so the SAME hashing logic is used to
# verify as to write (single source of truth). Fall back to a path insert if run
# from another cwd.
try:
    from ledger_hook import (
        GENESIS,
        compute_entry_hash,
        resolve_ledger_path,
    )
except Exception:  # pragma: no cover - import shim for odd cwd
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from ledger_hook import (  # type: ignore
        GENESIS,
        compute_entry_hash,
        resolve_ledger_path,
    )

REQUIRED_FIELDS = (
    "v", "seq", "ts", "tool", "command",
    "output_sha256", "output_len", "prev_hash", "receipt_id", "entry_hash",
)


class VerifyResult:
    """Outcome of a chain verification.

    Attributes:
        ok                : bool   - True iff no problems found and chain non-empty.
        count             : int    - number of (non-blank) entries inspected.
        first_broken_index: int|None - 0-based index of the FIRST broken entry.
        problems          : list[dict] - {index, kind, detail} per detected issue.
    """

    def __init__(self):
        self.ok = False
        self.count = 0
        self.first_broken_index = None
        self.problems = []

    def add(self, index, kind, detail):
        self.problems.append({"index": index, "kind": kind, "detail": detail})
        if self.first_broken_index is None or (
            index is not None and index < self.first_broken_index
        ):
            # Track the smallest concrete index; index=None problems don't move it.
            if index is not None:
                if self.first_broken_index is None or index < self.first_broken_index:
                    self.first_broken_index = index

    def as_dict(self):
        return {
            "ok": self.ok,
            "count": self.count,
            "first_broken_index": self.first_broken_index,
            "problems": self.problems,
        }


def verify_lines(lines, allow_empty=False) -> VerifyResult:
    """Verify a list of raw ledger lines (strings). Pure: no I/O.

    Blank lines are skipped (a trailing newline is normal). Returns a
    VerifyResult; .ok is True only if every invariant holds for every entry.
    """
    result = VerifyResult()

    # Keep original file line numbers for diagnostics, but index entries 0..n-1.
    entries = []  # (raw_str,) for non-blank lines
    for raw in lines:
        if raw is None:
            continue
        s = raw.strip()
        if s:
            entries.append(s)

    result.count = len(entries)

    if not entries:
        if allow_empty:
            result.ok = True
        else:
            result.add(None, "EMPTY", "ledger is empty (no entries to verify)")
        return result

    expected_prev = GENESIS
    for i, raw in enumerate(entries):
        # 1. parseable JSON
        try:
            rec = json.loads(raw)
        except Exception as exc:  # noqa: BLE001
            result.add(i, "CORRUPT_JSON", f"entry {i} is not valid JSON: {exc}")
            # Cannot continue the chain past an unparseable link.
            break

        if not isinstance(rec, dict):
            result.add(i, "CORRUPT_JSON", f"entry {i} is not a JSON object")
            break

        # 2. required fields present
        missing = [f for f in REQUIRED_FIELDS if f not in rec]
        if missing:
            result.add(i, "MISSING_FIELDS",
                       f"entry {i} missing fields: {','.join(missing)}")
            break

        stored_entry_hash = rec.get("entry_hash")
        stored_prev_hash = rec.get("prev_hash")

        # 3. self-integrity: recompute entry_hash over the body + its own prev_hash.
        recomputed = compute_entry_hash(stored_prev_hash, rec)
        if recomputed != stored_entry_hash:
            result.add(
                i, "MUTATION",
                f"entry {i} entry_hash mismatch (field tampered): "
                f"stored={stored_entry_hash} recomputed={recomputed}",
            )
            # Self-integrity failed -> this entry is untrustworthy. Keep scanning
            # later entries against the STORED hashes so we still surface a full
            # picture, but the break point is already pinned at i.

        # 4. chain linkage: prev_hash must equal the previous entry's entry_hash
        #    (GENESIS for the first). Catches insertion / deletion / reordering.
        if stored_prev_hash != expected_prev:
            if i == 0:
                result.add(
                    i, "BAD_GENESIS",
                    f"entry 0 prev_hash={stored_prev_hash!r} != {GENESIS!r} "
                    f"(deletion of original head, reorder, or tampered prev_hash)",
                )
            else:
                result.add(
                    i, "BROKEN_LINK",
                    f"entry {i} prev_hash={stored_prev_hash} does not match "
                    f"previous entry_hash={expected_prev} "
                    f"(insertion, deletion, reorder, or tampered prev_hash)",
                )

        # 5. seq must be contiguous 0..n-1. Catches insertion/deletion/reorder
        #    even in the (cryptographically impossible w/o key) case linkage held.
        if rec.get("seq") != i:
            result.add(
                i, "BAD_SEQ",
                f"entry {i} seq={rec.get('seq')} expected {i} "
                f"(insertion, deletion, or reorder)",
            )

        # Next link must chain off THIS entry's (stored) entry_hash.
        expected_prev = stored_entry_hash

    result.ok = (len(result.problems) == 0)
    return result


def verify_file(path: str, allow_empty=False) -> VerifyResult:
    """Read `path` and verify it. Raises FileNotFoundError if absent."""
    with open(path, "r", encoding="utf-8") as fh:
        lines = fh.readlines()
    return verify_lines(lines, allow_empty=allow_empty)


def format_report(result: VerifyResult, path=None) -> str:
    """Human-readable verification report."""
    loc = f" {path}" if path else ""
    if result.ok:
        return (f"LEDGER OK{loc}: {result.count} entr"
                f"{'y' if result.count == 1 else 'ies'}, chain intact.")
    lines = [f"LEDGER TAMPERED/INVALID{loc}: {result.count} entries inspected."]
    if result.first_broken_index is not None:
        lines.append(f"  first broken index: {result.first_broken_index}")
    for p in result.problems:
        idx = "-" if p["index"] is None else p["index"]
        lines.append(f"  [idx {idx}] {p['kind']}: {p['detail']}")
    return "\n".join(lines)


def _parse_args(argv):
    """Returns (path_or_None, want_json, allow_empty)."""
    path = None
    want_json = False
    allow_empty = False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--json", "-j"):
            want_json = True
        elif a == "--allow-empty":
            allow_empty = True
        elif a == "--ledger":
            if i + 1 < len(argv):
                path = argv[i + 1]
                i += 1
        elif a.startswith("--ledger="):
            path = a.split("=", 1)[1]
        elif a in ("-h", "--help"):
            path = "__HELP__"
        elif not a.startswith("-"):
            path = a
        i += 1
    return path, want_json, allow_empty


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    path, want_json, allow_empty = _parse_args(argv)

    if path == "__HELP__":
        sys.stdout.write(__doc__ or "")
        return 2

    # No explicit path -> fall back to the same resolution the hook uses.
    resolved = resolve_ledger_path(path) if path else resolve_ledger_path(None)

    if not os.path.exists(resolved):
        sys.stderr.write(f"verify_ledger: ledger not found: {resolved}\n")
        return 2

    try:
        result = verify_file(resolved, allow_empty=allow_empty)
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"verify_ledger: error reading {resolved}: {exc}\n")
        return 2

    if want_json:
        out = result.as_dict()
        out["path"] = resolved
        sys.stdout.write(json.dumps(out, indent=2) + "\n")
    else:
        sys.stdout.write(format_report(result, path=resolved) + "\n")

    if not result.ok:
        sys.stderr.write(
            f"verify_ledger: FAILED at index {result.first_broken_index}\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

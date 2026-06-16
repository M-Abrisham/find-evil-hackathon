"""End-to-end integration: a REAL forensic binary through the runner.

The rest of the runner suite (``test_runner.py``) proves the chokepoint's
*behaviour* with a harmless ``sys.executable`` stand-in and never launches a real
forensic tool. This module is the one place we close that gap: it spawns an
actual whitelisted binary (Sleuth Kit ``fls``) through :func:`run_tool_captured`
and asserts the full data-spine contract held end-to-end against a live process —
output captured to scratch, hashed, and pinned by a genesis-chained,
self-verifying ``receipts-v1`` line.

``fls -V`` only prints its version: it needs no image, touches no evidence, and
finishes instantly — the smallest honest exercise of the real execution path.
When ``fls`` is not installed (a bare CI box) the test SKIPS rather than fails,
so the suite stays green everywhere while still proving the live path wherever a
forensic tool is present.
"""

import hashlib
import json
import os

import pytest

from sift_agent.mcp_server.runner import (
    GENESIS_PREV_HASH,
    RECEIPTS_SCHEMA_VERSION,
    BINARY_WHITELIST,
    CappedToolResult,
    run_tool_captured,
    verify_receipts,
)

# Resolved once at import (the whitelist is built with filesystem checks only).
# If fls did not resolve on this host, skip — the stand-in unit tests still cover
# the runner; only the live-binary proof is host-dependent.
_FLS = BINARY_WHITELIST.get("fls")
requires_fls = pytest.mark.skipif(
    _FLS is None or not _FLS.available,
    reason="Sleuth Kit 'fls' is not installed on this host; the live-binary "
    "integration spawn is skipped (the runner's behaviour is still covered by "
    "test_runner.py's stand-in tests).",
)


@requires_fls
def test_real_fls_runs_through_runner_and_writes_a_verified_receipt(tmp_path, monkeypatch):
    # Hermetic: a private capture dir and no env-pinned receipts path, so this is
    # a fresh chain that starts at genesis regardless of any host state.
    monkeypatch.delenv("SIFT_RECEIPTS_PATH", raising=False)
    capdir = str(tmp_path / "captures")

    # The real spawn: fls -V through the single vetted chokepoint (shell=False).
    res = run_tool_captured("fls", ["-V"], agent="integration", capture_dir=capdir)

    assert isinstance(res, CappedToolResult)
    assert res.invocation_status == "ok"
    assert res.exit_code == 0
    # fls -V prints its banner to stdout; that is the row the model gets back.
    assert any("Sleuth Kit" in row for row in res.rows)

    # The FULL raw output landed in a capture file under our scratch dir, and the
    # receipt's digest is the real SHA-256 of those bytes (not a fabricated one).
    assert res.output_path and os.path.exists(res.output_path)
    assert res.output_path.startswith(os.path.realpath(capdir) + os.sep)
    with open(res.output_path, "rb") as fh:
        blob = fh.read()
    assert blob  # a real version banner is non-empty
    assert hashlib.sha256(blob).hexdigest() == res.output_sha256
    assert res.output_bytes == len(blob)

    # Exactly ONE receipt line was written, and it describes THIS call.
    receipts_path = os.path.join(capdir, "receipts.jsonl")
    assert os.path.exists(receipts_path), "the run must leave a provenance receipt"
    with open(receipts_path, "r", encoding="utf-8") as fh:
        lines = [ln for ln in fh if ln.strip()]
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["schema_version"] == RECEIPTS_SCHEMA_VERSION
    assert entry["receipt_id"] == res.receipt_id
    assert entry["agent"] == "integration"
    assert entry["tool"] == "fls"
    assert entry["args"] == ["-V"]
    assert entry["invocation_status"] == "ok"
    assert entry["exit_code"] == 0
    assert entry["output_sha256"] == res.output_sha256
    assert entry["ts"].endswith("Z")
    # First entry in a fresh chain: prev_hash is genesis, entry_hash is returned.
    assert entry["prev_hash"] == GENESIS_PREV_HASH
    assert entry["entry_hash"] == res.entry_hash

    # And the chain recomputes/verifies independently.
    report = verify_receipts(receipts_path)
    assert report["ok"] is True
    assert report["entries"] == 1

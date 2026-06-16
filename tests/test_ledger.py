"""Tests for the hash-chained provenance ledger (:mod:`sift_agent.ledger`).

Covers the contract: a clean chain verifies; a tampered middle line fails closed
at the exact line + byte offset; a partial trailing line is tolerated; a
duplicate receipt_id is flagged; canonical serialization is byte-stable; an
empty-output run is tagged ``empty_output`` (never a silent real artifact); the
write path is concurrency-safe; and the back-fill chains history on a copy
without touching the original.
"""

import hashlib
import json
import os
import threading

import pytest

from sift_agent import ledger
from sift_agent.ledger import (
    EMPTY_SHA256,
    GENESIS_PREV_HASH,
    InvocationStatus,
    Ledger,
    LedgerChainError,
    LedgerError,
    assert_chain_ok,
    backfill_chain,
    build_receipt,
    canonical_json,
    compute_entry_hash,
    sha256_file,
    verify_chain,
)

# Deterministic token block so receipt hashes are reproducible without telemetry.
FIXED_TOKENS = {
    "source": "issuing_agent_turn",
    "agent_turn_id": "agent-turn-001",
    "input_tokens": 1200,
    "output_tokens": 350,
    "total_tokens": 1550,
    "note": "tool execution consumes no LLM tokens; counts are the issuing turn",
}


def _append(led: Ledger, *, tool="fls", args=None, **kw):
    """Append a receipt with deterministic tokens (no telemetry dependency)."""
    return led.append(
        agent="sift-agent",
        tool=tool,
        args=args if args is not None else ["-r", "-o", "0"],
        tokens=FIXED_TOKENS,
        **kw,
    )


# =============================================================================
# Canonicalization + hashing.
# =============================================================================
def test_canonical_roundtrip_is_byte_stable():
    receipt = build_receipt(
        agent="sift-agent",
        tool="vol",
        args=["windows.netscan"],
        evidence_ref="mem.raw",
        exit_code=0,
        tokens=FIXED_TOKENS,
        ts="2026-06-09T01:00:00Z",
        receipt_id="rid-1",
    )
    once = canonical_json(receipt)
    twice = canonical_json(json.loads(once))
    assert once == twice  # re-serializing the parsed form is byte-identical

    # And the entry hash is reproducible across calls and key orderings.
    h1 = compute_entry_hash(receipt)
    reordered = dict(reversed(list(receipt.items())))
    h2 = compute_entry_hash(reordered)
    assert h1 == h2 == compute_entry_hash(json.loads(once))


def test_entry_hash_excludes_itself_but_covers_prev_hash():
    base = build_receipt(
        agent="a", tool="t", args="x", tokens=FIXED_TOKENS,
        ts="2026-06-09T01:00:00Z", receipt_id="rid",
    )
    base["prev_hash"] = GENESIS_PREV_HASH
    h = compute_entry_hash(base)
    # Adding entry_hash does not change the recomputed hash (it is excluded).
    base["entry_hash"] = h
    assert compute_entry_hash(base) == h
    # Changing prev_hash DOES change it (the link is part of the preimage).
    base2 = dict(base)
    base2["prev_hash"] = "1" * 64
    assert compute_entry_hash(base2) != h


def test_canonical_json_rejects_nan_and_floats_in_new_receipts():
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})
    # build_receipt refuses a float sneaking in (here via a float in tokens).
    with pytest.raises(LedgerError):
        build_receipt(
            agent="a", tool="t", args="x",
            tokens={**FIXED_TOKENS, "input_tokens": 1.5},
        )


def test_elapsed_s_is_stored_as_fixed_decimal_string():
    r = build_receipt(
        agent="a", tool="t", args="x", tokens=FIXED_TOKENS, elapsed_s=0.0,
    )
    assert r["elapsed_s"] == "0.000"
    assert isinstance(r["elapsed_s"], str)


def test_sha256_file_streams_correctly(tmp_path):
    blob = os.urandom(200_000)
    p = tmp_path / "artifact.bin"
    p.write_bytes(blob)
    digest, nbytes = sha256_file(str(p))
    assert digest == hashlib.sha256(blob).hexdigest()
    assert nbytes == len(blob)


# =============================================================================
# 1) Three entries → verify_chain passes (and the genesis link is correct).
# =============================================================================
def test_three_entries_verify_passes(tmp_path):
    path = str(tmp_path / "receipts.jsonl")
    led = Ledger(path)
    r1 = _append(led, tool="ewfmount", args=["case.E01"])
    r2 = _append(led, tool="fls", args=["-r"])
    r3 = _append(led, tool="vol", args=["windows.pslist"])

    # The first link is genesis; each next links to the prior entry_hash.
    assert r1["prev_hash"] == GENESIS_PREV_HASH
    assert r2["prev_hash"] == r1["entry_hash"]
    assert r3["prev_hash"] == r2["entry_hash"]

    result = verify_chain(path)
    assert result.ok, result.summary()
    assert result.chain_ok and result.genesis_ok
    assert result.n_entries == 3
    assert result.broken_at is None
    assert_chain_ok(path)  # does not raise


# =============================================================================
# 2) Tamper a middle line → fails closed at the EXACT line + byte offset.
# =============================================================================
def test_tampered_middle_line_fails_closed_at_exact_offset(tmp_path):
    path = str(tmp_path / "receipts.jsonl")
    led = Ledger(path)
    _append(led, tool="ewfmount")
    _append(led, tool="fls")
    _append(led, tool="vol")

    raw = open(path, "rb").read()
    lines = raw.split(b"\n")[:-1]  # drop trailing empty from final newline
    # Byte offset where line 2 starts = len(line1) + 1 newline.
    line2_offset = len(lines[0]) + 1

    # Mutate a field on line 2 WITHOUT fixing its entry_hash (a naive tamper).
    entry2 = json.loads(lines[1])
    entry2["note"] = "tampered: exfil hidden"
    lines[1] = canonical_json(entry2).encode()
    open(path, "wb").write(b"\n".join(lines) + b"\n")

    result = verify_chain(path)
    assert not result.ok
    assert not result.chain_ok
    assert result.broken_at is not None
    assert result.broken_at["line"] == 2
    assert result.broken_at["byte_offset"] == line2_offset
    assert "entry_hash mismatch" in result.broken_at["reason"]
    # Fail-closed: it verified only line 1 and refused to splice past the gap.
    assert result.n_entries == 1
    with pytest.raises(LedgerChainError):
        assert_chain_ok(path)


def test_deleted_middle_line_breaks_prev_hash_link(tmp_path):
    path = str(tmp_path / "receipts.jsonl")
    led = Ledger(path)
    _append(led, tool="a")
    _append(led, tool="b")
    _append(led, tool="c")

    lines = open(path, "rb").read().split(b"\n")[:-1]
    del lines[1]  # remove the middle entry entirely
    open(path, "wb").write(b"\n".join(lines) + b"\n")

    result = verify_chain(path)
    assert not result.ok
    # Old line 3 is now line 2; its prev_hash points at the deleted entry.
    assert result.broken_at["line"] == 2
    assert "prev_hash link broken" in result.broken_at["reason"]


def test_genesis_line_must_be_genesis(tmp_path):
    path = str(tmp_path / "receipts.jsonl")
    led = Ledger(path)
    _append(led, tool="a")
    _append(led, tool="b")
    lines = open(path, "rb").read().split(b"\n")[:-1]
    del lines[0]  # drop line 1 → line 2 (non-genesis prev) is now first
    open(path, "wb").write(b"\n".join(lines) + b"\n")

    result = verify_chain(path)
    assert not result.ok
    assert result.broken_at["line"] == 1
    assert "genesis prev_hash mismatch" in result.broken_at["reason"]


# =============================================================================
# 3) Partial / malformed TRAILING line → tolerated (ignored).
# =============================================================================
def test_partial_trailing_line_is_tolerated(tmp_path):
    path = str(tmp_path / "receipts.jsonl")
    led = Ledger(path)
    _append(led, tool="a")
    _append(led, tool="b")
    _append(led, tool="c")

    # Simulate a torn final write: append bytes with no terminating newline.
    with open(path, "ab") as f:
        f.write(b'{"schema_version":"receipts-v1","receipt_id":"partial",')

    result = verify_chain(path)
    assert result.ok, result.summary()
    assert result.trailing_partial is True
    assert result.n_entries == 3  # the 3 complete entries still verify


def test_corrupt_complete_middle_line_is_not_tolerated(tmp_path):
    # A *newline-terminated* (complete) but unparseable line is real corruption.
    path = str(tmp_path / "receipts.jsonl")
    led = Ledger(path)
    _append(led, tool="a")
    _append(led, tool="b")
    lines = open(path, "rb").read().split(b"\n")[:-1]
    lines.insert(1, b"{not valid json")  # complete (we re-add the newline)
    open(path, "wb").write(b"\n".join(lines) + b"\n")

    result = verify_chain(path)
    assert not result.ok
    assert result.broken_at["line"] == 2
    assert "malformed JSON" in result.broken_at["reason"]


# =============================================================================
# 4) Duplicate receipt_id → flagged.
# =============================================================================
def test_duplicate_receipt_id_is_flagged(tmp_path):
    path = str(tmp_path / "receipts.jsonl")
    led = Ledger(path)
    _append(led, tool="a", receipt_id="dup-rid")
    _append(led, tool="b", receipt_id="dup-rid")  # same id, second use

    result = verify_chain(path)
    # The chain itself is intact, but the duplicate id makes it not-ok.
    assert result.chain_ok is True
    assert result.ok is False
    assert len(result.duplicate_receipt_ids) == 1
    flag = result.duplicate_receipt_ids[0]
    assert flag["receipt_id"] == "dup-rid"
    assert flag["lines"] == [1, 2]


# =============================================================================
# 5) Empty-output run → tagged empty_output, never a silent real artifact.
# =============================================================================
def test_empty_output_is_tagged_not_silent_real_artifact(tmp_path):
    empty = tmp_path / "mmls_single_volume.txt"
    empty.write_bytes(b"")  # 0-byte artifact (e.g. mmls on a single-volume E01)

    r = build_receipt(
        agent="sift-agent", tool="mmls", args=["case.E01"],
        output_path=str(empty), exit_code=0, tokens=FIXED_TOKENS,
    )
    assert r["invocation_status"] == InvocationStatus.EMPTY_OUTPUT
    assert r["output_sha256"] == EMPTY_SHA256  # the e3b0c442… empty digest
    assert r["output_bytes"] == 0
    assert r["invocation_status"] != InvocationStatus.OK  # NOT a real artifact


def test_missing_output_is_path_failure_with_null_digest(tmp_path):
    r = build_receipt(
        agent="sift-agent", tool="EvtxECmd", args=["-f", "Security.evtx"],
        output_path=str(tmp_path / "does_not_exist.csv"),
        exit_code=0, tokens=FIXED_TOKENS,
    )
    assert r["invocation_status"] == InvocationStatus.PATH_FAILURE
    # A failure records NULL, never the empty-string digest → no collision.
    assert r["output_sha256"] is None
    assert r["output_bytes"] is None


def test_error_exit_classifies_as_error(tmp_path):
    out = tmp_path / "o.txt"
    out.write_text("partial output before crash")
    r = build_receipt(
        agent="a", tool="t", args="x", output_path=str(out),
        exit_code=1, tokens=FIXED_TOKENS,
    )
    assert r["invocation_status"] == InvocationStatus.ERROR


def test_build_refuses_empty_digest_on_ok():
    # Directly asserting the invariant guard (ok + empty digest is impossible).
    with pytest.raises(LedgerError):
        ledger._assert_receipt_invariants(
            {"invocation_status": "ok", "output_sha256": EMPTY_SHA256}
        )


def test_verify_flags_empty_digest_collision(tmp_path):
    # Hand-craft a forged entry that build_receipt would refuse, to prove
    # verify_chain independently catches the empty-digest collision.
    path = str(tmp_path / "receipts.jsonl")
    forged = {
        "schema_version": "receipts-v1",
        "receipt_id": "forged-1",
        "invocation_status": "ok",          # claims a real artifact …
        "output_sha256": EMPTY_SHA256,        # … but it is the empty digest
        "output_path": "/evidence/fake.bin",
        "prev_hash": GENESIS_PREV_HASH,
    }
    forged["entry_hash"] = compute_entry_hash(forged)
    with open(path, "w") as f:
        f.write(canonical_json(forged) + "\n")

    result = verify_chain(path, check_outputs=False)
    assert not result.ok
    assert result.chain_ok is True  # the hash itself is internally consistent …
    assert len(result.collision_flags) == 1  # … but the collision is flagged


# =============================================================================
# Output-artifact verification.
# =============================================================================
def test_verify_detects_output_artifact_mutation(tmp_path):
    art = tmp_path / "exports" / "pslist.csv"
    art.parent.mkdir()
    art.write_text("pid,ppid,name\n4,0,System\n")
    path = str(tmp_path / "receipts.jsonl")
    led = Ledger(path)
    _append(led, tool="vol", args=["windows.pslist"], output_path=str(art), exit_code=0)

    assert verify_chain(path).ok  # matches as recorded

    art.write_text("pid,ppid,name\n4,0,TAMPERED\n")  # mutate the artifact
    result = verify_chain(path)
    assert not result.ok
    assert len(result.output_mismatches) == 1
    assert result.chain_ok is True  # chain intact; the *artifact* changed


def test_missing_output_is_warning_unless_strict(tmp_path):
    art = tmp_path / "out.txt"
    art.write_text("data")
    path = str(tmp_path / "receipts.jsonl")
    led = Ledger(path)
    _append(led, tool="t", output_path=str(art), exit_code=0)
    art.unlink()  # artifact gone (e.g. evidence unmounted)

    assert verify_chain(path).ok is True  # default: missing = warning
    assert verify_chain(path, outputs_strict=True).ok is False


# =============================================================================
# Empty / new ledger.
# =============================================================================
def test_empty_and_missing_ledger_verify_ok(tmp_path):
    missing = str(tmp_path / "nope.jsonl")
    assert verify_chain(missing).ok is True  # no ledger yet
    empty = tmp_path / "empty.jsonl"
    empty.write_bytes(b"")
    assert verify_chain(str(empty)).ok is True


# =============================================================================
# Concurrency — flock + O_APPEND keep parallel writers from forking the chain.
# =============================================================================
def test_concurrent_appends_do_not_fork_the_chain(tmp_path):
    path = str(tmp_path / "receipts.jsonl")
    n_threads, per_thread = 8, 25
    barrier = threading.Barrier(n_threads)

    def worker(tid):
        led = Ledger(path)
        barrier.wait()  # maximize contention
        for k in range(per_thread):
            _append(led, tool=f"t{tid}", args=[str(k)], receipt_id=f"{tid}-{k}")

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    result = verify_chain(path)
    assert result.ok, result.summary()
    assert result.n_entries == n_threads * per_thread
    assert not result.duplicate_receipt_ids
    # Every entry_hash is unique (no two writers produced the same line).
    hashes = [json.loads(l)["entry_hash"] for l in open(path)]
    assert len(set(hashes)) == len(hashes)


# =============================================================================
# Back-fill — chain history on a COPY; original never modified.
# =============================================================================
LEGACY_LINES = [
    {"timestamp": "2026-06-08T01:33:12Z", "status": "RUN",
     "command": "ewfmount case.E01", "note": "mount", "stdout": "", "stderr": ""},
    # carries a float (0.0) just like the real tools.jsonl line 2 — hashed verbatim
    {"timestamp": "2026-06-08T01:33:12Z", "status": "ERR", "command": "ewfmount + bad",
     "returncode": 1, "elapsed_s": 0.0, "note": "fail", "stdout": "x", "stderr": "y"},
    {"timestamp": "2026-06-08T01:33:19Z", "status": "OK", "command": "fls -r",
     "returncode": 0, "elapsed_s": 0, "note": "ok", "stdout": "Users/", "stderr": ""},
]


def _write_legacy(tmp_path):
    src = tmp_path / "tools.jsonl"
    src.write_text("".join(json.dumps(o) + "\n" for o in LEGACY_LINES))
    return src


def test_backfill_chains_history_and_appends_marker(tmp_path):
    src = _write_legacy(tmp_path)
    before = src.read_bytes()
    before_sha = hashlib.sha256(before).hexdigest()
    dst = tmp_path / "analysis" / "tools.chain.jsonl"

    summary = backfill_chain(str(src), str(dst), agent="tester",
                             migrated_at="2026-06-09T02:00:00Z")

    # Original is byte-for-byte untouched.
    assert src.read_bytes() == before
    assert summary["source_sha256"] == before_sha
    assert summary["legacy_line_count"] == 3
    assert summary["n_entries"] == 4  # 3 legacy + 1 marker

    entries = [json.loads(l) for l in open(dst)]
    assert entries[0]["prev_hash"] == GENESIS_PREV_HASH
    for prev, cur in zip(entries, entries[1:]):
        assert cur["prev_hash"] == prev["entry_hash"]
    # Legacy lines tagged tools-v0; original content preserved.
    for e in entries[:3]:
        assert e["schema_version"] == "tools-v0"
    assert entries[0]["command"] == "ewfmount case.E01"
    # The marker is the chained tip and records the source's digest + count.
    marker = entries[3]
    assert marker["kind"] == "migration_marker"
    assert marker["source_sha256"] == before_sha
    assert marker["legacy_line_count"] == 3
    assert marker["entry_hash"] == summary["tip_entry_hash"]

    # The produced chain verifies (outputs are vacuous for legacy lines).
    assert verify_chain(str(dst), check_outputs=False).ok


def test_backfill_custody_check_rejects_wrong_source_sha(tmp_path):
    src = _write_legacy(tmp_path)
    dst = tmp_path / "out.jsonl"
    with pytest.raises(LedgerError):
        backfill_chain(str(src), str(dst), expected_source_sha256="0" * 64)
    assert not dst.exists()  # nothing written on a custody-check failure


def test_backfill_rejects_malformed_json_source(tmp_path):
    # A corrupt legacy line raises LedgerError (not a raw JSONDecodeError) and
    # publishes nothing — no partial chain, no stray temp file.
    src = tmp_path / "tools.jsonl"
    src.write_text(json.dumps(LEGACY_LINES[0]) + "\n" + "{not valid json\n")
    dst = tmp_path / "analysis" / "tools.chain.jsonl"
    with pytest.raises(LedgerError) as ei:
        backfill_chain(str(src), str(dst))
    assert "malformed JSON" in str(ei.value)
    assert not dst.exists()  # atomic publish never ran
    assert list((tmp_path / "analysis").glob("tools.chain.jsonl.tmp.*")) == []


# =============================================================================
# Regression tests for the hardening fixes surfaced by the adversarial review:
# graceful error reporting, write-path invariant enforcement, and blank-line
# tolerance (reader/writer symmetry).
# =============================================================================
def test_verify_chain_rejects_directory_path(tmp_path):
    # A directory is a path that exists but is not a ledger file: report it,
    # never crash with an uncaught IsADirectoryError.
    result = verify_chain(str(tmp_path))
    assert result.ok is False
    assert any("cannot open ledger" in e for e in result.errors)


def test_verify_rejects_missing_or_nonstring_entry_hash(tmp_path):
    bads = [
        {"prev_hash": GENESIS_PREV_HASH, "x": 1},             # entry_hash absent
        {"prev_hash": GENESIS_PREV_HASH, "entry_hash": 123},  # non-string entry_hash
    ]
    for i, bad in enumerate(bads):
        path = tmp_path / f"bad_{i}.jsonl"
        path.write_text(canonical_json(bad) + "\n")
        result = verify_chain(str(path), check_outputs=False)
        assert not result.ok
        assert result.broken_at["line"] == 1
        assert "missing or non-string entry_hash" in result.broken_at["reason"]


def test_verify_rejects_non_dict_json_entry(tmp_path):
    # Valid JSON, but an array is not a receipt object.
    path = tmp_path / "arr.jsonl"
    path.write_text("[1, 2, 3]\n")
    result = verify_chain(str(path), check_outputs=False)
    assert not result.ok
    assert result.broken_at["line"] == 1
    assert "not a JSON object" in result.broken_at["reason"]


def test_append_prebuilt_enforces_invariants(tmp_path):
    path = str(tmp_path / "receipts.jsonl")
    led = Ledger(path)

    # A valid prebuilt receipt chains, writes, and verifies.
    good = build_receipt(agent="a", tool="t", args="x", exit_code=0, tokens=FIXED_TOKENS)
    written = led.append_prebuilt(good)
    assert written["prev_hash"] == GENESIS_PREV_HASH
    assert verify_chain(path).ok

    # A forged "ok + empty-digest" receipt is refused at the write path (the same
    # guard build_receipt applies), so it can never reach disk via append_prebuilt.
    forged = {
        "schema_version": "receipts-v1",
        "receipt_id": "forged",
        "invocation_status": "ok",
        "output_sha256": EMPTY_SHA256,
        "tool": "x",
    }
    with pytest.raises(LedgerError):
        led.append_prebuilt(forged)
    # The good entry is still the only one on disk; the forgery was not appended.
    assert verify_chain(path).n_entries == 1


def test_classify_invocation_ok_for_real_artifact(tmp_path):
    art = tmp_path / "real.csv"
    art.write_text("col\nval\n")  # a real, non-empty artifact
    r = build_receipt(agent="a", tool="MFTECmd", args=["-f", "$MFT"],
                      output_path=str(art), exit_code=0, tokens=FIXED_TOKENS)
    assert r["invocation_status"] == InvocationStatus.OK
    assert r["output_sha256"] not in (None, EMPTY_SHA256)
    assert r["output_bytes"] == art.stat().st_size


def test_whitespace_only_and_blank_lines_are_tolerated(tmp_path):
    # A file of only blank lines has no entries and verifies OK.
    ws = tmp_path / "ws.jsonl"
    ws.write_text("\n   \n\t\n")
    r = verify_chain(str(ws), check_outputs=False)
    assert r.ok is True
    assert r.n_entries == 0
    assert r.blank_lines_skipped == 3

    # A blank line interleaved among real entries is skipped, not fatal: the
    # chain links across it (the writer never emits one; it carries no hash).
    path = tmp_path / "receipts.jsonl"
    led = Ledger(str(path))
    _append(led, tool="a")
    _append(led, tool="b")
    lines = open(path, "rb").read().split(b"\n")[:-1]
    lines.insert(1, b"   ")  # blank line between entry 1 and entry 2
    open(path, "wb").write(b"\n".join(lines) + b"\n")
    r2 = verify_chain(str(path), check_outputs=False)
    assert r2.ok is True
    assert r2.n_entries == 2
    assert r2.blank_lines_skipped == 1


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses file permission checks")
def test_unreadable_artifact_degrades_to_path_failure(tmp_path):
    art = tmp_path / "locked.bin"
    art.write_bytes(b"secret output")
    os.chmod(art, 0o000)  # exists (isfile True) but unreadable → open() raises
    try:
        r = build_receipt(agent="a", tool="t", args="x",
                          output_path=str(art), exit_code=0, tokens=FIXED_TOKENS)
    finally:
        os.chmod(art, 0o644)  # restore so pytest tmp cleanup can remove it
    # The OSError while hashing is caught and recorded as a path_failure with a
    # NULL digest — never crash, never the empty-string digest.
    assert r["invocation_status"] == InvocationStatus.PATH_FAILURE
    assert r["output_sha256"] is None

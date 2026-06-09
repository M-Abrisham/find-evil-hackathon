"""Tests for the per-case SQLite evidence store (:mod:`sift_agent.store`).

These prove the GUARANTEE, not just the happy path: traceability is enforced by
the DB itself. A valid capture + chunks + row inserts; a row missing its
``native_locator``, carrying a zero ``byte_len``, a malformed ``sha256``, an
unknown ``evidence_source``, or an orphan ``capture_id`` is REJECTED by the
schema (NOT NULL / CHECK / FOREIGN KEY) — and the FK rejection is shown to be
load-bearing on the ``foreign_keys=ON`` PRAGMA. The byte-range -> chunk lookup
the Day-3 verifier relies on returns the right chunk(s), and the deterministic
``root_sha256`` recomputes from the leaves. Schema versioning fails loud rather
than silently migrating, and timestamps share the canonical ``...Z`` shape with
:mod:`sift_agent.finding` so the disk<->memory JOIN lines up.
"""

import hashlib
import json
import sqlite3
from contextlib import closing

import pytest

from sift_agent import store
from sift_agent.finding import CREATED_TS_RE  # cross-module timestamp-shape check
from sift_agent.store import (
    SCHEMA_VERSION,
    StoreError,
    compute_root_sha256,
    connect,
    init_store,
)

# --- canonical, fully-valid fixture data -------------------------------------
# Synthetic uuid4-shaped receipt ids (NOT live case data) — the store's
# receipt_id column holds the ledger's receipt_id value verbatim.
RECEIPT_ID = "00000000-0000-4000-8000-000000000001"
CASE_ID = "Rocba"
# Both evidence images carry a baseline (the case has a disk E01 AND a memory
# dump); the store records both, seeded as a {role: sha256} mapping.
DISK_BASELINE = "f2eb856d6fb48e3928e6b6d388b2f116a57b735137354a7eaddca951d81b5c67"
MEM_BASELINE = "eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563"
BASELINE = {"disk": DISK_BASELINE, "memory": MEM_BASELINE}

# Two leaf chunks of a captured output: [0,100) and [100,150).
_SEG0, _SEG1 = b"A" * 100, b"B" * 50
H0 = hashlib.sha256(_SEG0).hexdigest()
H1 = hashlib.sha256(_SEG1).hexdigest()
ROOT = compute_root_sha256([H0, H1])
TOTAL_BYTES, SEGMENT_SIZE = 150, 100

ROW_COLS = (
    "artifact_type", "evidence_source", "native_locator", "capture_id",
    "byte_start", "byte_len", "receipt_id", "proc", "pid", "path",
    "sha256", "ip", "ts",
)


def _db(tmp_path):
    """Path to a fresh store file under the test's tmp dir (OUTSIDE the repo)."""
    return str(tmp_path / "store.sqlite")


def _fresh(tmp_path, **kw):
    """init_store at a fresh path; return (db_path)."""
    path = _db(tmp_path)
    init_store(path, case_id=CASE_ID, evidence_baseline_sha256=BASELINE, **kw)
    return path


def _insert_capture(conn, **overrides):
    """Insert a fully-valid capture; return its capture_id (rowid alias)."""
    vals = {
        "source_tool": "vol",
        "tool_version": "2.28.0",
        "receipt_id": RECEIPT_ID,
        "capture_path": "/home/ubuntu/josh/cases/Rocba/index/captures/vol-pslist.txt",
        "total_bytes": TOTAL_BYTES,
        "segment_size": SEGMENT_SIZE,
        "root_sha256": ROOT,
        "created_utc": "2026-06-09T01:22:09Z",
        **overrides,
    }
    cols = ",".join(vals)
    cur = conn.execute(
        f"INSERT INTO captures({cols}) VALUES ({','.join('?' * len(vals))})",
        tuple(vals.values()),
    )
    return cur.lastrowid


def _insert_chunk(conn, capture_id, seq, offset, length, sha256):
    conn.execute(
        "INSERT INTO capture_chunks(capture_id, seq, offset, length, sha256) "
        "VALUES (?, ?, ?, ?, ?)",
        (capture_id, seq, offset, length, sha256),
    )


def _valid_row(capture_id, **overrides):
    """A fully-valid `rows` value dict; override exactly one field per neg test."""
    vals = {
        "artifact_type": "process",
        "evidence_source": "memory",
        "native_locator": "pid=4711;ppid=620;create_time=2020-11-16T02:30:00Z;offset=0x7e2a000",
        "capture_id": capture_id,
        "byte_start": 120,
        "byte_len": 20,
        "receipt_id": RECEIPT_ID,
        "proc": "evil.exe",
        "pid": 4711,
        "path": r"C:\Users\rocba\AppData\evil.exe",
        "sha256": hashlib.sha256(b"row-artifact").hexdigest(),
        "ip": "10.0.0.5",
        "ts": "2026-06-09T01:22:09Z",
    }
    vals.update(overrides)
    return vals


def _insert_row(conn, vals):
    conn.execute(
        f"INSERT INTO rows({','.join(ROW_COLS)}) "
        f"VALUES ({','.join('?' * len(ROW_COLS))})",
        tuple(vals[c] for c in ROW_COLS),
    )


def _capture_with_two_chunks(conn):
    """Insert the canonical capture + its two leaf chunks; return capture_id."""
    cid = _insert_capture(conn)
    _insert_chunk(conn, cid, 0, 0, 100, H0)
    _insert_chunk(conn, cid, 1, 100, 50, H1)
    return cid


# =============================================================================
# PRAGMAs — the guarantees are only real if these are set on every connection.
# =============================================================================
def test_connect_enforces_foreign_keys_and_wal(tmp_path):
    path = _fresh(tmp_path)
    with closing(connect(path)) as conn:
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000


# =============================================================================
# Happy path — a valid capture + 2 chunks + 1 row inserts OK.
# =============================================================================
def test_valid_capture_chunks_and_row_insert_ok(tmp_path):
    path = _fresh(tmp_path)
    with closing(connect(path)) as conn:
        cid = _capture_with_two_chunks(conn)
        _insert_row(conn, _valid_row(cid))
        conn.commit()

        assert conn.execute("SELECT COUNT(*) FROM captures").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM capture_chunks").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM rows").fetchone()[0] == 1
        # sha256 NULL is explicitly allowed by the CHECK (it's optional).
        _insert_row(conn, _valid_row(cid, sha256=None))
        conn.commit()
        assert conn.execute("SELECT COUNT(*) FROM rows").fetchone()[0] == 2


# =============================================================================
# Rejections — each negative test mutates EXACTLY ONE field of an otherwise
# fully-valid row, so the failure can only be the constraint under test.
# =============================================================================
def test_native_locator_null_rejected(tmp_path):
    path = _fresh(tmp_path)
    with closing(connect(path)) as conn:
        cid = _capture_with_two_chunks(conn)
        # Pinned to the column's own constraint message so no OTHER NOT NULL/CHECK
        # can satisfy this test — it must fail on native_locator specifically.
        with pytest.raises(sqlite3.IntegrityError, match=r"NOT NULL.*rows\.native_locator"):
            _insert_row(conn, _valid_row(cid, native_locator=None))


def test_byte_len_zero_rejected(tmp_path):
    path = _fresh(tmp_path)
    with closing(connect(path)) as conn:
        cid = _capture_with_two_chunks(conn)
        with pytest.raises(sqlite3.IntegrityError, match=r"byte_len > 0"):
            _insert_row(conn, _valid_row(cid, byte_len=0))


def test_sha256_wrong_length_rejected(tmp_path):
    path = _fresh(tmp_path)
    with closing(connect(path)) as conn:
        cid = _capture_with_two_chunks(conn)
        with pytest.raises(sqlite3.IntegrityError, match=r"length\(sha256\)=64"):
            _insert_row(conn, _valid_row(cid, sha256="a" * 63))  # 63 != 64


def test_evidence_source_unknown_rejected(tmp_path):
    path = _fresh(tmp_path)
    with closing(connect(path)) as conn:
        cid = _capture_with_two_chunks(conn)
        with pytest.raises(sqlite3.IntegrityError, match=r"evidence_source IN"):
            _insert_row(conn, _valid_row(cid, evidence_source="network"))


def test_chunk_zero_length_rejected(tmp_path):
    path = _fresh(tmp_path)
    with closing(connect(path)) as conn:
        cid = _insert_capture(conn)
        with pytest.raises(sqlite3.IntegrityError, match=r"length > 0"):
            _insert_chunk(conn, cid, 0, 0, 0, H0)  # length=0


def test_chunk_pk_uniqueness_rejected(tmp_path):
    path = _fresh(tmp_path)
    with closing(connect(path)) as conn:
        cid = _insert_capture(conn)
        _insert_chunk(conn, cid, 0, 0, 100, H0)
        with pytest.raises(sqlite3.IntegrityError, match=r"UNIQUE constraint failed: capture_chunks"):
            _insert_chunk(conn, cid, 0, 0, 100, H1)  # duplicate (capture_id, seq)


# =============================================================================
# Foreign key — an orphan capture_id is rejected, and that rejection is shown to
# DEPEND on the foreign_keys=ON pragma (load-bearing, not incidental).
# =============================================================================
def test_orphan_capture_id_rejected(tmp_path):
    path = _fresh(tmp_path)
    with closing(connect(path)) as conn:
        _capture_with_two_chunks(conn)  # capture_id == 1 exists
        with pytest.raises(sqlite3.IntegrityError, match=r"FOREIGN KEY constraint failed"):
            _insert_row(conn, _valid_row(999_999))  # no such capture


def test_fk_pragma_is_load_bearing(tmp_path):
    """The SAME orphan insert is ACCEPTED on a raw connection with no pragma —
    proving connect()'s ``foreign_keys=ON`` is what enforces the FK."""
    path = _fresh(tmp_path)
    raw = sqlite3.connect(path)  # deliberately NO PRAGMA foreign_keys
    try:
        assert raw.execute("PRAGMA foreign_keys").fetchone()[0] == 0
        _insert_row(raw, _valid_row(999_999))  # orphan capture_id — accepted
        raw.commit()
        assert raw.execute("SELECT COUNT(*) FROM rows").fetchone()[0] == 1
    finally:
        raw.close()


def test_orphan_chunk_capture_id_rejected(tmp_path):
    """capture_chunks.capture_id REFERENCES captures: a chunk pointing at a
    non-existent capture is REJECTED under foreign_keys=ON (mirrors the rows
    orphan test) — and the rejection is shown to depend on the pragma."""
    path = _fresh(tmp_path)
    with closing(connect(path)) as conn:
        # The FK is actually declared on capture_chunks (not just rows).
        assert conn.execute("PRAGMA foreign_key_list(capture_chunks)").fetchall() != []
        with pytest.raises(sqlite3.IntegrityError, match=r"FOREIGN KEY constraint failed"):
            _insert_chunk(conn, 999_999, 0, 0, 100, H0)  # no parent capture


def test_chunk_fk_pragma_is_load_bearing(tmp_path):
    """The SAME orphan chunk is ACCEPTED on a raw connection with no pragma —
    proving connect()'s ``foreign_keys=ON`` is what enforces the chunk FK too."""
    path = _fresh(tmp_path)
    raw = sqlite3.connect(path)  # deliberately NO PRAGMA foreign_keys
    try:
        assert raw.execute("PRAGMA foreign_keys").fetchone()[0] == 0
        _insert_chunk(raw, 999_999, 0, 0, 100, H0)  # orphan chunk — accepted
        raw.commit()
        assert raw.execute("SELECT COUNT(*) FROM capture_chunks").fetchone()[0] == 1
    finally:
        raw.close()


# =============================================================================
# byte_range -> chunk lookup — the read the Day-3 verifier relies on. A cited
# [start, end] range maps to the overlapping chunk(s) by offset/length:
#   chunk overlaps [start, end)  <=>  offset < end AND offset + length > start.
# =============================================================================
def _chunks_for_range(conn, capture_id, start, end):
    return [
        r[0]
        for r in conn.execute(
            "SELECT seq FROM capture_chunks "
            "WHERE capture_id = ? AND offset < ? AND offset + length > ? "
            "ORDER BY seq",
            (capture_id, end, start),
        ).fetchall()
    ]


def test_byte_range_resolves_to_correct_chunks(tmp_path):
    path = _fresh(tmp_path)
    with closing(connect(path)) as conn:
        cid = _capture_with_two_chunks(conn)  # chunk0=[0,100), chunk1=[100,150)
        conn.commit()
        assert _chunks_for_range(conn, cid, 120, 140) == [1]   # inside chunk1
        assert _chunks_for_range(conn, cid, 10, 20) == [0]     # inside chunk0
        assert _chunks_for_range(conn, cid, 90, 110) == [0, 1]  # spans boundary
        assert _chunks_for_range(conn, cid, 0, 150) == [0, 1]   # whole capture
        # Half-open [start, end): the boundary cases that distinguish < from <=.
        # A citation ending EXACTLY at chunk1's start must NOT pull in chunk1.
        assert _chunks_for_range(conn, cid, 0, 100) == [0]
        assert _chunks_for_range(conn, cid, 100, 150) == [1]
        assert _chunks_for_range(conn, cid, 100, 100) == []    # zero-width at boundary


# =============================================================================
# Deterministic root hash — recomputes from the stored leaves, in seq order.
# =============================================================================
def test_root_sha256_recomputes_from_leaves(tmp_path):
    path = _fresh(tmp_path)
    with closing(connect(path)) as conn:
        cid = _capture_with_two_chunks(conn)
        conn.commit()
        stored_root = conn.execute(
            "SELECT root_sha256 FROM captures WHERE capture_id = ?", (cid,)
        ).fetchone()[0]
        leaves = [
            r[0]
            for r in conn.execute(
                "SELECT sha256 FROM capture_chunks WHERE capture_id = ? ORDER BY seq",
                (cid,),
            ).fetchall()
        ]
        assert compute_root_sha256(leaves) == stored_root
        # seq order matters: the reversed concatenation must NOT match.
        assert compute_root_sha256(list(reversed(leaves))) != stored_root
        # Anchor to an INDEPENDENT hand computation of the documented formula
        # (sha256 over the concatenated raw leaf digests) — not just the function
        # against itself — so the test pins the VALUE, not merely self-consistency.
        independent = hashlib.sha256(bytes.fromhex(H0) + bytes.fromhex(H1)).hexdigest()
        assert stored_root == independent == ROOT


def test_compute_root_sha256_rejects_malformed_leaf():
    with pytest.raises(StoreError, match="zero chunks"):
        compute_root_sha256([])                   # a capture must have >=1 leaf
    with pytest.raises(StoreError):
        compute_root_sha256(["not-hex"])
    with pytest.raises(StoreError):
        compute_root_sha256(["a" * 63])          # wrong length
    with pytest.raises(StoreError):
        compute_root_sha256([H0.upper()])         # not lowercase


# =============================================================================
# store_meta seeding + schema versioning — fail loud, never silently migrate.
# =============================================================================
def test_init_store_seeds_meta_with_canonical_shapes(tmp_path):
    path = _fresh(tmp_path)
    with closing(connect(path)) as conn:
        meta = dict(conn.execute("SELECT key, value FROM store_meta").fetchall())
    assert meta["schema_version"] == SCHEMA_VERSION
    assert meta["case_id"] == CASE_ID
    # BOTH evidence baselines (disk + memory) are stored as one canonical JSON
    # value — not just one image's hash.
    stored_baselines = json.loads(meta["evidence_baseline_sha256"])
    assert stored_baselines == {"disk": DISK_BASELINE, "memory": MEM_BASELINE}
    # created_utc shares finding.py's canonical UTC-Z shape (disk<->memory JOIN).
    assert CREATED_TS_RE.match(meta["created_utc"])


def test_init_store_fresh_with_no_seed_kwargs(tmp_path):
    """A bare init_store(path) still creates all four tables and auto-seeds
    schema_version + created_utc; the optional case_id / evidence_baseline_sha256
    are simply absent (None is skipped, not stored as a null/empty value)."""
    path = _db(tmp_path)
    init_store(path)
    with closing(connect(path)) as conn:
        tables = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert {"store_meta", "captures", "capture_chunks", "rows"} <= tables
        meta = dict(conn.execute("SELECT key, value FROM store_meta").fetchall())
    assert meta["schema_version"] == SCHEMA_VERSION
    assert CREATED_TS_RE.match(meta["created_utc"])
    assert "case_id" not in meta
    assert "evidence_baseline_sha256" not in meta


def test_init_store_is_idempotent(tmp_path):
    path = _db(tmp_path)
    init_store(path, case_id=CASE_ID, evidence_baseline_sha256=BASELINE,
               created_utc="2026-06-09T00:00:00Z")
    with closing(connect(path)) as conn:
        before = dict(conn.execute("SELECT key, value FROM store_meta").fetchall())
        _capture_with_two_chunks(conn)
        conn.commit()
    # Second init must not drop tables, clobber seeds, or change created_utc.
    init_store(path, case_id=CASE_ID, evidence_baseline_sha256=BASELINE,
               created_utc="2099-01-01T00:00:00Z")
    with closing(connect(path)) as conn:
        after = dict(conn.execute("SELECT key, value FROM store_meta").fetchall())
        assert conn.execute("SELECT COUNT(*) FROM captures").fetchone()[0] == 1
    assert after == before
    assert after["created_utc"] == "2026-06-09T00:00:00Z"


def test_schema_version_mismatch_fails_loud(tmp_path):
    path = _fresh(tmp_path)
    with closing(connect(path)) as conn:
        conn.execute("UPDATE store_meta SET value = '2' WHERE key = 'schema_version'")
        conn.commit()
    with pytest.raises(StoreError, match="schema_version"):
        init_store(path)


def test_conflicting_case_rebind_rejected(tmp_path):
    path = _db(tmp_path)
    init_store(path, case_id="Rocba")
    with pytest.raises(StoreError, match="re-bind|case_id"):
        init_store(path, case_id="SomeOtherCase")

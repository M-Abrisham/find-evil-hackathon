"""Tests for the store read path (:func:`sift_agent.store.query_store`).

query_store is the agent's ONLY read into the per-case store and these prove its
contract STRUCTURALLY: it is read-only by construction (an INSERT/UPDATE through
its connection raises — mode=ro is load-bearing), it is hard-capped at 50
(a bigger limit is rejected, never silently truncated), it only filters on a
whitelist of columns with bound parameters (an unknown key is rejected; the
caller can never inject SQL), it paginates by KEYSET (every matching row visited
exactly once, no dup/gap, next_cursor None on the last page), every returned row
carries the traceability quartet (native_locator + byte_start + byte_len +
receipt_id), and an empty match yields an empty, well-formed page.
"""

import hashlib
import sqlite3
from contextlib import closing

import pytest

from sift_agent import store
from sift_agent.store import (
    MAX_LIMIT,
    RETURN_COLUMNS,
    connect,
    connect_readonly,
    init_store,
    query_store,
)

H_EVIL = hashlib.sha256(b"evil").hexdigest()
H_DLL = hashlib.sha256(b"dll").hexdigest()
RID = "00000000-0000-4000-8000-000000000099"

# Known dataset spanning disk + memory. Insert order == row_id order (1..N), so
# expected_ids() below maps a predicate over DATA straight to row_ids. Expected
# results are DERIVED from DATA (no magic counts) so the data can be tweaked
# without silently invalidating the assertions.
DATA = [
    # artifact_type, evidence_source, proc,          pid,  path,                 sha256,  ip,          ts
    ("process",  "memory", "evil.exe",    100,  r"C:\evil.exe",        H_EVIL, "10.0.0.1", "2026-06-01T00:00:00Z"),
    ("process",  "memory", "evil.exe",    101,  r"C:\evil.exe",        None,   "10.0.0.1", "2026-06-02T00:00:00Z"),
    ("netconn",  "memory", "svchost.exe", 102,  None,                  None,   "10.0.0.2", "2026-06-03T00:00:00Z"),
    ("process",  "memory", "calc.exe",    103,  r"C:\calc.exe",        H_EVIL, None,       "2026-06-04T00:00:00Z"),
    ("file",     "memory", None,          None, r"C:\temp\a.dll",      H_DLL,  None,       "2026-06-05T00:00:00Z"),
    ("process",  "memory", "evil.exe",    104,  r"C:\evil.exe",        H_EVIL, "10.0.0.1", "2026-06-06T00:00:00Z"),
    ("netconn",  "memory", "evil.exe",    105,  None,                  None,   "8.8.8.8",  "2026-06-07T00:00:00Z"),
    ("file",     "disk",   None,          None, r"C:\windows\x.sys",   H_DLL,  None,       "2026-06-08T00:00:00Z"),
    ("registry", "disk",   None,          None, r"HKLM\Run",           None,   None,       "2026-06-09T00:00:00Z"),
    ("file",     "disk",   None,          None, r"C:\evil.exe",        H_EVIL, None,       "2026-06-10T00:00:00Z"),
    ("mft",      "disk",   None,          None, r"C:\evil.exe",        None,   None,       "2026-06-11T00:00:00Z"),
    ("file",     "disk",   None,          None, r"C:\temp\a.dll",      H_DLL,  None,       "2026-06-12T00:00:00Z"),
]
_FIELDS = ("artifact_type", "evidence_source", "proc", "pid", "path", "sha256", "ip", "ts")


def _spec(row):
    return dict(zip(_FIELDS, row))


def expected_ids(pred):
    """row_ids (1-based, == insert order) whose DATA spec satisfies ``pred``."""
    return [i for i, row in enumerate(DATA, start=1) if pred(_spec(row))]


def _seed(tmp_path):
    """Create a store, insert one capture + the DATA rows (row_ids 1..N), close
    the writer (checkpointing WAL) and return the db path."""
    db = str(tmp_path / "store.sqlite")
    init_store(db, case_id="Rocba")
    with closing(connect(db)) as conn:
        root = store.compute_root_sha256([hashlib.sha256(b"cap").hexdigest()])
        cur = conn.execute(
            "INSERT INTO captures(source_tool,receipt_id,capture_path,total_bytes,"
            "segment_size,root_sha256,created_utc) VALUES(?,?,?,?,?,?,?)",
            ("vol", RID, "/out/cap.txt", 4096, 1024, root, "2026-06-09T00:00:00Z"),
        )
        cid = cur.lastrowid
        for i, row in enumerate(DATA, start=1):
            s = _spec(row)
            conn.execute(
                "INSERT INTO rows(artifact_type,evidence_source,native_locator,"
                "capture_id,byte_start,byte_len,receipt_id,proc,pid,path,sha256,ip,ts) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    s["artifact_type"], s["evidence_source"], f"loc:{i}",
                    cid, i * 10, 8, RID,
                    s["proc"], s["pid"], s["path"], s["sha256"], s["ip"], s["ts"],
                ),
            )
        conn.commit()
        # Insert order must equal row_id order for expected_ids() to hold.
        ids = [r[0] for r in conn.execute("SELECT row_id FROM rows ORDER BY row_id").fetchall()]
        assert ids == list(range(1, len(DATA) + 1))
    return db


def _page_ids(result):
    return [r["row_id"] for r in result["rows"]]


def _all_ids(db, filters, limit):
    """Walk every page via keyset; assert no page exceeds limit and the cursor
    contract holds; return the full list of row_ids visited (in order)."""
    ids, cursor, pages = [], None, 0
    while True:
        r = query_store(filters, limit=limit, cursor=cursor, db_path=db)
        assert r["returned"] == len(r["rows"]) <= limit
        ids += _page_ids(r)
        pages += 1
        if r["truncated"]:
            assert r["next_cursor"] == r["rows"][-1]["row_id"]  # last id of THIS page
            cursor = r["next_cursor"]
        else:
            assert r["next_cursor"] is None  # exhausted
            break
        assert pages <= len(DATA) + 2  # loop guard
    return ids


# =============================================================================
# Cap + counts.
# =============================================================================
def test_returns_at_most_limit_and_full_total_count(tmp_path):
    db = _seed(tmp_path)
    r = query_store({}, limit=5, db_path=db)
    assert r["returned"] == 5
    assert len(r["rows"]) == 5
    assert r["total_count"] == len(DATA)        # full match, ignores paging
    assert r["truncated"] is True               # more pages remain
    assert r["next_cursor"] == r["rows"][-1]["row_id"]


def test_filters_empty_matches_all(tmp_path):
    db = _seed(tmp_path)
    r = query_store({}, limit=MAX_LIMIT, db_path=db)
    assert r["total_count"] == len(DATA)
    assert r["returned"] == len(DATA)
    assert r["truncated"] is False
    assert _page_ids(r) == list(range(1, len(DATA) + 1))


# =============================================================================
# Keyset pagination — every matching row exactly once, no dup/gap.
# =============================================================================
def test_keyset_pagination_visits_each_row_exactly_once(tmp_path):
    db = _seed(tmp_path)
    pred = lambda s: s["evidence_source"] == "memory"
    want = expected_ids(pred)
    assert len(want) > 3  # ensure multiple pages at limit=3
    visited = _all_ids(db, {"evidence_source": "memory"}, limit=3)
    assert visited == sorted(visited)             # ascending by row_id
    assert len(visited) == len(set(visited))      # no duplicates
    assert sorted(visited) == want                # no gaps; exactly the matches


def test_pagination_total_count_constant_across_pages(tmp_path):
    db = _seed(tmp_path)
    want = expected_ids(lambda s: s["evidence_source"] == "memory")
    cursor, seen = None, 0
    while True:
        r = query_store({"evidence_source": "memory"}, limit=2, cursor=cursor, db_path=db)
        assert r["total_count"] == len(want)      # total_count ignores paging
        seen += r["returned"]
        if not r["truncated"]:
            break
        cursor = r["next_cursor"]
    assert seen == len(want)


def test_exact_multiple_pagination_emits_no_phantom_page(tmp_path):
    """Boundary the limit+1 lookahead exists for: when the match count is an
    EXACT MULTIPLE of the page size, the final full page must report
    truncated=False / next_cursor=None and NO empty trailing page is fetched.
    (A naive `truncated = returned == limit` would emit a phantom empty page.)"""
    db = _seed(tmp_path)
    want = expected_ids(lambda s: s["artifact_type"] == "file")
    limit = 2
    assert len(want) % limit == 0 and len(want) // limit >= 2  # genuine multi-page exact multiple
    pages, cursor, ids = 0, None, []
    while True:
        r = query_store({"artifact_type": "file"}, limit=limit, cursor=cursor, db_path=db)
        pages += 1
        ids += _page_ids(r)
        assert r["total_count"] == len(want)        # constant across pages, ignores paging
        if r["truncated"]:
            assert r["returned"] == limit           # a full page
            cursor = r["next_cursor"]
        else:
            assert r["next_cursor"] is None
            break
        assert pages <= len(want)                   # runaway guard
    assert pages == len(want) // limit              # EXACTLY k pages — no phantom empty page
    assert sorted(ids) == want


def test_count_equal_to_limit_is_single_untruncated_page(tmp_path):
    """The subtlest exact-multiple case: match count == limit. One full page,
    truncated=False, next_cursor=None — not a truncated page with an empty next."""
    db = _seed(tmp_path)
    want = expected_ids(lambda s: s["sha256"] == H_DLL)
    assert len(want) >= 1
    r = query_store({"sha256": H_DLL}, limit=len(want), db_path=db)  # limit == match count
    assert r["returned"] == len(want)
    assert r["truncated"] is False
    assert r["next_cursor"] is None
    assert sorted(_page_ids(r)) == want


def test_total_count_constant_across_empty_filter_pages(tmp_path):
    """total_count is the full-table count on EVERY page of a multi-page walk —
    the cursor predicate narrows the page query but never the COUNT."""
    db = _seed(tmp_path)
    cursor, pages = None, 0
    while True:
        r = query_store({}, limit=5, cursor=cursor, db_path=db)
        assert r["total_count"] == len(DATA)        # cursor ignored by COUNT
        pages += 1
        if not r["truncated"]:
            break
        cursor = r["next_cursor"]
    assert pages == -(-len(DATA) // 5)              # ceil(12/5) == 3 pages


# =============================================================================
# Traceability — every returned row carries the quartet.
# =============================================================================
def test_every_returned_row_carries_traceability_quartet(tmp_path):
    db = _seed(tmp_path)
    r = query_store({}, limit=MAX_LIMIT, db_path=db)
    for row in r["rows"]:
        assert set(RETURN_COLUMNS) <= set(row)            # full column set present
        for col in ("native_locator", "byte_start", "byte_len", "receipt_id"):
            assert row[col] is not None
        assert row["byte_len"] > 0
        assert row["receipt_id"] == RID


def test_payload_bounded_to_known_columns(tmp_path):
    db = _seed(tmp_path)
    r = query_store({}, limit=1, db_path=db)
    # The payload is bounded to exactly the whitelisted RETURN_COLUMNS — no extra
    # column leaks in. (Raw captured bytes are never in the DB to begin with:
    # they live in the capture FILE via captures.capture_path, so the verifier
    # reads the byte_range separately.)
    assert set(r["rows"][0]) == set(RETURN_COLUMNS)


# =============================================================================
# Filtering — each pivot column, membership, ts range, IS NULL.
# =============================================================================
def test_filter_by_each_pivot_column(tmp_path):
    db = _seed(tmp_path)
    cases = [
        ({"artifact_type": "process"}, lambda s: s["artifact_type"] == "process"),
        ({"evidence_source": "disk"}, lambda s: s["evidence_source"] == "disk"),
        ({"proc": "evil.exe"}, lambda s: s["proc"] == "evil.exe"),
        ({"pid": 100}, lambda s: s["pid"] == 100),
        ({"path": r"C:\evil.exe"}, lambda s: s["path"] == r"C:\evil.exe"),
        ({"sha256": H_EVIL}, lambda s: s["sha256"] == H_EVIL),
        ({"ip": "10.0.0.1"}, lambda s: s["ip"] == "10.0.0.1"),
        ({"ts": "2026-06-04T00:00:00Z"}, lambda s: s["ts"] == "2026-06-04T00:00:00Z"),
    ]
    for filters, pred in cases:
        r = query_store(filters, limit=MAX_LIMIT, db_path=db)
        want = expected_ids(pred)
        assert want, f"test data has no match for {filters}"  # guard a vacuous case
        assert sorted(_page_ids(r)) == want, filters
        assert r["total_count"] == len(want), filters
        col, val = next(iter(filters.items()))
        for row in r["rows"]:
            assert row[col] == val                # only matches returned


def test_membership_in_filter(tmp_path):
    db = _seed(tmp_path)
    r = query_store({"artifact_type": ["netconn", "registry"]}, limit=MAX_LIMIT, db_path=db)
    want = expected_ids(lambda s: s["artifact_type"] in ("netconn", "registry"))
    assert sorted(_page_ids(r)) == want
    assert r["total_count"] == len(want)


def test_ts_range(tmp_path):
    db = _seed(tmp_path)
    lo, hi = "2026-06-03T00:00:00Z", "2026-06-05T00:00:00Z"
    r = query_store({"ts_from": lo, "ts_to": hi}, limit=MAX_LIMIT, db_path=db)
    want = expected_ids(lambda s: lo <= s["ts"] <= hi)
    assert sorted(_page_ids(r)) == want
    # open-ended ranges
    r_from = query_store({"ts_from": hi}, limit=MAX_LIMIT, db_path=db)
    assert sorted(_page_ids(r_from)) == expected_ids(lambda s: s["ts"] >= hi)
    r_to = query_store({"ts_to": lo}, limit=MAX_LIMIT, db_path=db)
    assert sorted(_page_ids(r_to)) == expected_ids(lambda s: s["ts"] <= lo)


def test_equality_none_matches_is_null(tmp_path):
    db = _seed(tmp_path)
    r = query_store({"sha256": None}, limit=MAX_LIMIT, db_path=db)
    want = expected_ids(lambda s: s["sha256"] is None)
    assert sorted(_page_ids(r)) == want
    assert all(row["sha256"] is None for row in r["rows"])


def test_combined_filters_are_anded(tmp_path):
    db = _seed(tmp_path)
    r = query_store(
        {"evidence_source": "memory", "proc": "evil.exe"}, limit=MAX_LIMIT, db_path=db
    )
    want = expected_ids(lambda s: s["evidence_source"] == "memory" and s["proc"] == "evil.exe")
    assert sorted(_page_ids(r)) == want


# =============================================================================
# Rejections — no raw SQL, hard cap.
# =============================================================================
def test_unknown_filter_key_rejected(tmp_path):
    db = _seed(tmp_path)
    with pytest.raises(ValueError, match="unknown filter key"):
        query_store({"bogus": 1}, db_path=db)


def test_non_pivot_columns_not_queryable(tmp_path):
    """Trace/identity columns are returned but NOT filterable (only the 8 pivots)."""
    db = _seed(tmp_path)
    for key in ("row_id", "capture_id", "native_locator", "byte_start", "receipt_id"):
        with pytest.raises(ValueError, match="unknown filter key"):
            query_store({key: 1}, db_path=db)


def test_empty_membership_list_rejected(tmp_path):
    db = _seed(tmp_path)
    with pytest.raises(ValueError, match="empty membership"):
        query_store({"artifact_type": []}, db_path=db)


def test_limit_over_cap_rejected(tmp_path):
    db = _seed(tmp_path)
    with pytest.raises(ValueError, match="limit"):
        query_store({}, limit=MAX_LIMIT + 1, db_path=db)


def test_limit_non_positive_and_bool_rejected(tmp_path):
    db = _seed(tmp_path)
    for bad in (0, -1, True):
        with pytest.raises(ValueError, match="limit"):
            query_store({}, limit=bad, db_path=db)


def test_limit_boundaries_accepted(tmp_path):
    db = _seed(tmp_path)
    assert query_store({}, limit=1, db_path=db)["returned"] == 1
    # exactly the cap is allowed (we seed fewer than the cap, so we get them all)
    assert query_store({}, limit=MAX_LIMIT, db_path=db)["returned"] == len(DATA)


def test_bad_cursor_rejected(tmp_path):
    db = _seed(tmp_path)
    for bad in ("5", 1.0, True):
        with pytest.raises(ValueError, match="cursor"):
            query_store({}, cursor=bad, db_path=db)


def test_cursor_int_edges_accepted(tmp_path):
    """Accepted int cursors behave sanely: 0 / negative start before the first
    row (all rows visible); a cursor past the last row_id yields an empty page."""
    db = _seed(tmp_path)
    for low in (0, -1):
        r = query_store({}, cursor=low, db_path=db, limit=MAX_LIMIT)
        assert _page_ids(r) == list(range(1, len(DATA) + 1))
    past = query_store({}, cursor=len(DATA) + 1000, db_path=db)
    assert past["rows"] == [] and past["next_cursor"] is None
    assert past["total_count"] == len(DATA)   # COUNT ignores the cursor


# =============================================================================
# Read-only by construction — the architectural guardrail.
# =============================================================================
def test_read_only_connection_rejects_writes(tmp_path):
    db = _seed(tmp_path)
    ro = connect_readonly(db)
    try:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            ro.execute(
                "INSERT INTO rows(artifact_type,evidence_source,native_locator,"
                "capture_id,byte_start,byte_len,receipt_id) VALUES('x','disk','l',1,0,1,'r')"
            )
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            ro.execute("UPDATE rows SET proc='hacked' WHERE row_id=1")
        # reads still work on the same connection
        assert ro.execute("SELECT COUNT(*) FROM rows").fetchone()[0] == len(DATA)
    finally:
        ro.close()


def test_mode_ro_is_load_bearing(tmp_path):
    """The SAME UPDATE succeeds on a read-write connect() — proving it is the
    mode=ro flag (not some other obstacle) that blocks query_store's writes."""
    db = _seed(tmp_path)
    with closing(connect(db)) as rw:                 # read-write
        rw.execute("UPDATE rows SET proc='ok' WHERE row_id=1")
        rw.commit()
        assert rw.execute("SELECT proc FROM rows WHERE row_id=1").fetchone()[0] == "ok"
    with closing(connect_readonly(db)) as ro:        # read-only
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            ro.execute("UPDATE rows SET proc='hacked' WHERE row_id=1")


# =============================================================================
# Empty results.
# =============================================================================
def test_no_match_returns_empty_page(tmp_path):
    db = _seed(tmp_path)
    r = query_store({"proc": "does-not-exist"}, db_path=db)
    assert r["rows"] == []
    assert r["total_count"] == 0
    assert r["returned"] == 0
    assert r["truncated"] is False
    assert r["next_cursor"] is None


def test_empty_store_returns_empty_page(tmp_path):
    db = str(tmp_path / "empty.sqlite")
    init_store(db, case_id="Rocba")
    r = query_store({}, db_path=db)
    assert r == {"rows": [], "total_count": 0, "returned": 0,
                 "truncated": False, "next_cursor": None}

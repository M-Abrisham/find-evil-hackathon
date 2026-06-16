"""build_index tests — schema, streamed loader, byte-range round-trip, receipts,
and the no-parse-time-date-filter guarantee.

Uses a small synthetic ``json_line`` export (the same shape psort emits) so the
test is fast and hermetic — no plaso run, no evidence touched.
"""

import json
import sqlite3

import pytest

from sift_agent import ledger as _ledger
from sift_agent.build_index import (
    Artifact,
    TABLE_NAME,
    build_index,
    extract_row,
    init_db,
    iter_export_rows,
    load_export,
)


# A normal in-window event, a second event, one with NO _event_values_hash, and a
# TIMESTOMPED event whose stamp is far in the future (year 2099) — it must still
# load (the incident window is applied later as a query, never at parse time).
_TS_2020 = 1605486000000000   # 2020-11-16 ~ in incident window (µs since epoch)
_TS_2099 = 4070908800000000   # 2099-01-01 — out of any 2020 window (timestomp)

_EVENTS = [
    {
        "_event_values_hash": "aaaa1111bbbb2222cccc3333dddd4444",
        "data_type": "windows:registry:key_value",
        "timestamp": _TS_2020,
        "timestamp_desc": "Last Written Time",
        "process_name": "evil.exe",
        "pid": 4321,
        "filename": "C:/Windows/Temp/evil.exe",
        "sha256_hash": "deadbeef" * 8,
        "ip_address": "10.0.0.66",
    },
    {
        "_event_values_hash": "eeee5555ffff6666aaaa7777bbbb8888",
        "data_type": "fs:stat",
        "timestamp": _TS_2020 + 1_000_000,
        "timestamp_desc": "Content Modification Time",
        "display_name": "TSK:/Users/rocba/ntuser.dat",
    },
    {
        # NO _event_values_hash → loader must synthesize a NON-NULL "syn:" locator
        "data_type": "syslog:line",
        "timestamp": _TS_2020 + 2_000_000,
        "timestamp_desc": "Recording Time",
        "process_identifier": "777",          # pid as string → coerced to int
    },
    {
        # TIMESTOMPED, far-future stamp — must NOT be dropped at parse time
        "_event_values_hash": "9999000011112222333344445555aaaa",
        "data_type": "fs:stat",
        "timestamp": _TS_2099,
        "timestamp_desc": "Creation Time",
        "filename": "C:/Windows/System32/legit_but_stomped.sys",
    },
]


def _write_export(path):
    """Write a json_line export with a blank line in the middle (to test skip)."""
    lines = [json.dumps(_EVENTS[0]), json.dumps(_EVENTS[1]), "",
             json.dumps(_EVENTS[2]), json.dumps(_EVENTS[3])]
    data = ("\n".join(lines) + "\n").encode("utf-8")
    path.write_bytes(data)
    return path


@pytest.fixture
def export(tmp_path):
    return _write_export(tmp_path / "rocba_timeline.jsonl")


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "index.sqlite")


@pytest.fixture
def ledger(tmp_path):
    return _ledger.Ledger(path=str(tmp_path / "receipts.jsonl"))


# ---------------------------------------------------------------------------
# byte-range round-trip: the stored slice reproduces the exact source bytes
# ---------------------------------------------------------------------------
def test_iter_offsets_reproduce_source_bytes(export):
    raw = export.read_bytes()
    seen = 0
    for start, length, content in iter_export_rows(str(export)):
        if length == 0:
            continue  # the blank line
        assert raw[start:start + length] == content        # exact slice
        assert json.loads(content)                          # and valid JSON
        seen += 1
    assert seen == 4


def test_schema_columns_present(db_path):
    conn = init_db(db_path)
    cols = {r[1] for r in conn.execute(f"PRAGMA table_info({TABLE_NAME})")}
    conn.close()
    # two NON-NULL locator columns + the 6 pivots
    for required in (
        "native_locator", "byte_range",
        "process_name", "pid", "file_path", "sha256", "ip", "ts_utc",
    ):
        assert required in cols
    # the locator columns are NOT NULL in the DDL
    conn = sqlite3.connect(db_path)
    notnull = {r[1] for r in conn.execute(f"PRAGMA table_info({TABLE_NAME})") if r[3] == 1}
    conn.close()
    assert {"native_locator", "byte_range"} <= notnull


# ---------------------------------------------------------------------------
# Full build_index run
# ---------------------------------------------------------------------------
def test_build_index_loads_all_rows_with_locators_and_pivots(export, db_path, ledger):
    artifact = Artifact(name="super_timeline", export_path=str(export),
                        evidence_ref="/mnt/windows_mount")
    result = build_index(artifact, db_path=db_path, ledger=ledger)

    # Returns only counts + handle + receipt — never rows.
    assert result.n_rows == 4
    assert result.handle() == {"db_path": db_path, "table": TABLE_NAME}
    assert result.start_receipt_id and result.done_receipt_id
    assert not hasattr(result, "rows")

    conn = sqlite3.connect(db_path)
    try:
        # every row has NON-NULL native_locator AND byte_range
        nulls = conn.execute(
            f"SELECT COUNT(*) FROM {TABLE_NAME} "
            "WHERE native_locator IS NULL OR byte_range IS NULL"
        ).fetchone()[0]
        assert nulls == 0

        # pivots mapped on the first event
        row = conn.execute(
            f"SELECT process_name, pid, file_path, sha256, ip, ts_utc, native_locator "
            f"FROM {TABLE_NAME} WHERE native_locator='aaaa1111bbbb2222cccc3333dddd4444'"
        ).fetchone()
        assert row[0] == "evil.exe"
        assert row[1] == 4321
        assert row[2] == "C:/Windows/Temp/evil.exe"
        assert row[3] == "deadbeef" * 8
        assert row[4] == "10.0.0.66"
        assert row[5].startswith("2020-11-16")        # ts derived from µs timestamp

        # pid given as a string is coerced to an int
        pid_str_row = conn.execute(
            f"SELECT pid FROM {TABLE_NAME} WHERE data_type='syslog:line'"
        ).fetchone()
        assert pid_str_row[0] == 777

        # the event with no _event_values_hash got a synthesized, NON-NULL locator
        syn = conn.execute(
            f"SELECT native_locator FROM {TABLE_NAME} WHERE data_type='syslog:line'"
        ).fetchone()[0]
        assert syn.startswith("syn:")

        # byte_range really points at the row's bytes in the export
        br_row = conn.execute(
            f"SELECT byte_start, byte_len FROM {TABLE_NAME} "
            "WHERE native_locator='aaaa1111bbbb2222cccc3333dddd4444'"
        ).fetchone()
        with open(export, "rb") as fh:
            fh.seek(br_row[0])
            sliced = fh.read(br_row[1])
        assert json.loads(sliced)["process_name"] == "evil.exe"
    finally:
        conn.close()


def test_timestomped_out_of_window_row_is_NOT_dropped(export, db_path, ledger):
    """The whole point: a far-future (timestomped) event is still indexed."""
    artifact = Artifact(name="super_timeline", export_path=str(export))
    build_index(artifact, db_path=db_path, ledger=ledger)

    conn = sqlite3.connect(db_path)
    try:
        # The 2099 row exists in the store...
        stomped = conn.execute(
            f"SELECT ts_utc, file_path FROM {TABLE_NAME} WHERE ts_utc LIKE '2099-%'"
        ).fetchall()
        assert len(stomped) == 1
        assert stomped[0][1].endswith("legit_but_stomped.sys")

        # ...and a *query-time* incident-window filter is what would exclude it —
        # demonstrating the filter lives in the query, not the parse.
        in_window = conn.execute(
            f"SELECT COUNT(*) FROM {TABLE_NAME} "
            "WHERE ts_utc BETWEEN '2020-11-01' AND '2020-11-30'"
        ).fetchone()[0]
        total = conn.execute(f"SELECT COUNT(*) FROM {TABLE_NAME}").fetchone()[0]
        assert in_window == 3 and total == 4   # the stomped row is in the store, not the window
    finally:
        conn.close()


def test_load_export_refuses_a_date_filter(export, db_path):
    conn = init_db(db_path)
    try:
        with pytest.raises(ValueError, match="does NOT date-filter"):
            load_export(conn, str(export), date_filter="2020-11-01..2020-11-30")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Receipts: START + DONE chained into the ledger; DONE carries the export sha256
# ---------------------------------------------------------------------------
def test_start_and_done_receipts_are_chained_and_carry_export_hash(export, db_path, tmp_path):
    ledger_path = str(tmp_path / "receipts.jsonl")
    ledger = _ledger.Ledger(path=ledger_path)
    artifact = Artifact(name="super_timeline", export_path=str(export),
                        evidence_ref="/mnt/windows_mount")
    result = build_index(artifact, db_path=db_path, ledger=ledger)

    # the ledger chain verifies end-to-end
    vr = _ledger.verify_chain(ledger_path)
    assert vr.ok, vr.summary()
    assert vr.n_entries == 2          # exactly START + DONE

    receipts = [json.loads(l) for l in open(ledger_path)]
    start, done = receipts[0], receipts[1]
    assert "START" in start["note"] and start["tool"] == "build_index"
    assert "DONE" in done["note"] and "no_date_filter=true" in done["note"]

    # DONE receipt's streamed sha256 == the export's actual sha256
    actual_sha, actual_bytes = _ledger.sha256_file(str(export))
    assert done["output_sha256"] == actual_sha == result.export_sha256
    assert done["output_bytes"] == actual_bytes

    # index_meta recorded the same provenance
    conn = sqlite3.connect(db_path)
    meta = dict(conn.execute("SELECT key, value FROM index_meta").fetchall())
    conn.close()
    assert meta["export_sha256"] == actual_sha
    assert meta["n_rows"] == "4"
    assert meta["no_date_filter"] == "true"


# ---------------------------------------------------------------------------
# producer_cmd path: build_index runs the producer when the export is missing
# ---------------------------------------------------------------------------
def test_build_index_runs_producer_when_export_missing(tmp_path, db_path, ledger):
    export_path = tmp_path / "produced.jsonl"
    payload = json.dumps(_EVENTS[0])
    producer = [
        "python3", "-c",
        f"open({str(export_path)!r}, 'w').write({payload!r} + '\\n')",
    ]
    artifact = Artifact(
        name="produced", export_path=str(export_path), producer_cmd=producer
    )
    assert not export_path.exists()
    result = build_index(artifact, db_path=db_path, ledger=ledger)
    assert export_path.exists()        # producer ran
    assert result.n_rows == 1

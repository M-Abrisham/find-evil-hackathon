"""build_index — parse a heavy forensic artifact ONCE into a queryable per-case index.

Contract (per 09-SCALING / 03-DATA-SPINE)
-----------------------------------------
A heavy artifact (e.g. the 81 GiB super-timeline) is far too large to hand to a
model. ``build_index`` turns it into a **per-case SQLite store** the agent can
*query* (pivot + window filter) while only ever returning COUNTS + a table
HANDLE + a RECEIPT to any model — never raw rows. The pipeline:

  1. Parse the artifact ONCE → stream the tool's output to an ``output_path``
     capture (the "export"). The export is hashed with a SEGMENTED/STREAMED
     SHA-256 (:func:`sift_agent.ledger.sha256_file`, 64 KiB chunks) — the whole
     file is never read into memory, never shown to a model.
  2. Bulk-load every export row into the per-case SQLite store. Each row carries
     two NON-NULL locator columns — ``native_locator`` (the plaso event's native
     id) and ``byte_range`` ("start,len" into the export) — plus the six pivot
     columns ``process_name, pid, file_path, sha256, ip, ts_utc``.
  3. Log a START and a DONE receipt to the hash-chained ledger
     (:class:`sift_agent.ledger.Ledger`), whose token attribution already routes
     through :func:`sift_agent.telemetry.stamp_receipt`.

NO PARSE-TIME DATE FILTER (critical)
------------------------------------
The FULL timeline is parsed and loaded — there is deliberately no date/slice
filter at parse or load time. The incident window is applied LATER as a *query*
filter (``WHERE ts_utc BETWEEN ...``). A timestomped event whose stamp falls
outside the window must still be in the store, or it would be silently dropped
before anyone could notice the anomaly. :func:`load_export` asserts no date
predicate was passed.

OUTSIDE THE AGENT-LOOP BUDGET
-----------------------------
``build_index`` is meant to run in a detached batch/overnight job, not inside an
agent turn. It returns a tiny :class:`IndexResult` (counts + handle + receipt
ids); it never streams rows back to a model.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterator

from sift_agent import ledger as _ledger

__all__ = [
    "TABLE_NAME",
    "SCHEMA_SQL",
    "DEFAULT_DB_PATH",
    "Artifact",
    "IndexResult",
    "init_db",
    "iter_export_rows",
    "extract_row",
    "load_export",
    "build_index",
]

# Per-case store. Lives in the case dir (case data — gitignored, NEVER committed).
DEFAULT_DB_PATH = os.path.expanduser("~/josh/cases/Rocba/index/rocba_index.sqlite")

TABLE_NAME = "timeline"

# -----------------------------------------------------------------------------
# Schema. Two NON-NULL locator columns + the 6 pivots + provenance.
#
#   native_locator  the plaso event's native identity (json_line emits no literal
#                   UUID; its closest native per-event id is ``_event_values_hash``,
#                   used here; synthesized from the row bytes only if absent so the
#                   column is NEVER null and NEVER fabricated silently).
#   byte_range      "start,len" — the exact byte slice of the export that produced
#                   this row, so a finding can cite the source bytes. byte_start /
#                   byte_len are the same value pre-parsed for a direct seek+read.
#
# The 6 pivots are nullable on purpose: not every event has a process/pid/ip.
# ts_utc is the *event* time; it is NOT filtered here (window applied at query).
# -----------------------------------------------------------------------------
SCHEMA_SQL = f"""
CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
    id             INTEGER PRIMARY KEY,
    native_locator TEXT    NOT NULL,   -- plaso native event id (_event_values_hash)
    byte_range     TEXT    NOT NULL,   -- "start,len" byte slice into the export
    byte_start     INTEGER NOT NULL,   -- parsed start offset (direct seek)
    byte_len       INTEGER NOT NULL,   -- parsed length
    process_name   TEXT,               -- pivot 1
    pid            INTEGER,            -- pivot 2
    file_path      TEXT,               -- pivot 3
    sha256         TEXT,               -- pivot 4
    ip             TEXT,               -- pivot 5
    ts_utc         TEXT,               -- pivot 6 (ISO-8601 UTC; NOT filtered at parse)
    source_export  TEXT    NOT NULL,   -- which export capture these bytes index
    data_type      TEXT,               -- plaso data_type (context)
    timestamp_desc TEXT                -- plaso MACB / timestamp description
);
CREATE INDEX IF NOT EXISTS idx_{TABLE_NAME}_ts        ON {TABLE_NAME} (ts_utc);
CREATE INDEX IF NOT EXISTS idx_{TABLE_NAME}_pid       ON {TABLE_NAME} (pid);
CREATE INDEX IF NOT EXISTS idx_{TABLE_NAME}_proc      ON {TABLE_NAME} (process_name);
CREATE INDEX IF NOT EXISTS idx_{TABLE_NAME}_ip        ON {TABLE_NAME} (ip);
CREATE INDEX IF NOT EXISTS idx_{TABLE_NAME}_sha       ON {TABLE_NAME} (sha256);
CREATE INDEX IF NOT EXISTS idx_{TABLE_NAME}_path      ON {TABLE_NAME} (file_path);
CREATE INDEX IF NOT EXISTS idx_{TABLE_NAME}_locator   ON {TABLE_NAME} (native_locator);

CREATE TABLE IF NOT EXISTS index_meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

# Insert column order (id is autoincrement, omitted).
_INSERT_COLUMNS = (
    "native_locator", "byte_range", "byte_start", "byte_len",
    "process_name", "pid", "file_path", "sha256", "ip", "ts_utc",
    "source_export", "data_type", "timestamp_desc",
)
_INSERT_SQL = (
    f"INSERT INTO {TABLE_NAME} (" + ", ".join(_INSERT_COLUMNS) + ") "
    "VALUES (" + ", ".join("?" for _ in _INSERT_COLUMNS) + ")"
)

# Field-name priority maps: json_line attribute names → pivot value. First hit wins.
_PROCESS_KEYS = ("process_name", "executable", "application", "process")
_PID_KEYS = ("pid", "process_identifier")
_FILEPATH_KEYS = ("filename", "display_name", "path", "full_path", "file_path")
_SHA256_KEYS = ("sha256_hash", "sha256", "hash_sha256")
_IP_KEYS = (
    "ip_address", "source_ip", "src_ip", "dest_ip", "destination_ip",
    "host_ip", "remote_ip", "ip",
)

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass
class Artifact:
    """A heavy artifact to index.

    name:         logical name (e.g. ``"super_timeline"``) — used in receipts.
    export_path:  the capture path the parse output is streamed to / read from.
    fmt:          export format: ``"json_line"`` (default, richest) or ``"l2tcsv"``.
    evidence_ref: read-only evidence the artifact derives from (for the receipt).
    producer_cmd: optional argv that PRODUCES ``export_path`` (parse-once step,
                  e.g. ``psort.py -o json_line -w <export> <store.plaso>``). Run
                  only when ``export_path`` does not already exist.
    """

    name: str
    export_path: str
    fmt: str = "json_line"
    evidence_ref: str | None = None
    producer_cmd: list[str] | None = None


@dataclass
class IndexResult:
    """What ``build_index`` returns — counts + handle + receipt. NO rows, ever."""

    artifact: str
    db_path: str
    table: str
    n_rows: int
    export_path: str
    export_sha256: str | None
    export_bytes: int | None
    start_receipt_id: str | None
    done_receipt_id: str | None
    skipped_blank: int = 0
    parse_errors: int = 0

    def handle(self) -> dict[str, str]:
        """The table handle a caller queries against (no data leaves)."""
        return {"db_path": self.db_path, "table": self.table}


# -----------------------------------------------------------------------------
# DB
# -----------------------------------------------------------------------------
def init_db(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open/create the per-case SQLite store and ensure the schema + bulk pragmas."""
    parent = os.path.dirname(db_path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(db_path)
    # Bulk-load tuning: WAL + relaxed sync. A fresh per-case build, so safe.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA_SQL)
    return conn


# -----------------------------------------------------------------------------
# Export parsing — streamed, byte-offset tracked. Never loads the file whole.
# -----------------------------------------------------------------------------
def iter_export_rows(export_path: str) -> Iterator[tuple[int, int, bytes]]:
    """Yield ``(byte_start, byte_len, line_bytes)`` for each non-blank export line.

    Streams the file in binary and tracks the running byte offset, so
    ``open(export_path,'rb').seek(byte_start); read(byte_len)`` reproduces exactly
    the bytes of ``line_bytes`` (the JSON object, trailing newline excluded). The
    file is read line-by-line — never slurped into memory.
    """
    offset = 0
    with open(export_path, "rb") as fh:
        for raw in fh:
            start = offset
            offset += len(raw)
            content = raw.rstrip(b"\r\n")
            if not content.strip():
                # blank line — still advance the offset, but emit nothing
                yield start, 0, b""
                continue
            yield start, len(content), content


def _first(ev: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for k in keys:
        v = ev.get(k)
        if v not in (None, ""):
            return v
    return None


def _coerce_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value)
    return None


def _ts_utc_from_event(ev: dict[str, Any]) -> str | None:
    """ISO-8601 UTC (``...Z``) from plaso json_line ``timestamp`` (µs since epoch).

    Returns ``None`` if absent or out of representable range — the row is STILL
    loaded (no date filtering); only the pivot value is null.
    """
    ts = ev.get("timestamp")
    if not isinstance(ts, int) or isinstance(ts, bool):
        return None
    try:
        sec, micro = divmod(ts, 1_000_000)
        dt = _EPOCH + timedelta(seconds=sec, microseconds=micro)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    except (OverflowError, ValueError, OSError):
        return None


def extract_row(
    event: dict[str, Any], byte_start: int, byte_len: int, source_export: str, line_bytes: bytes
) -> tuple:
    """Map one parsed export event → the INSERT tuple (matches ``_INSERT_COLUMNS``).

    ``native_locator`` is the plaso ``_event_values_hash`` when present (its native
    per-event id) and otherwise a ``syn:`` -prefixed SHA-256 of the row bytes — so
    the column is never null and a synthesized id is never mistaken for a real one.
    """
    locator = event.get("_event_values_hash")
    if not isinstance(locator, str) or not locator:
        import hashlib

        locator = "syn:" + hashlib.sha256(line_bytes).hexdigest()[:32]

    byte_range = f"{byte_start},{byte_len}"
    pid = _coerce_int(_first(event, _PID_KEYS))
    return (
        locator,
        byte_range,
        byte_start,
        byte_len,
        _first(event, _PROCESS_KEYS),
        pid,
        _first(event, _FILEPATH_KEYS),
        _first(event, _SHA256_KEYS),
        _first(event, _IP_KEYS),
        _ts_utc_from_event(event),
        source_export,
        event.get("data_type"),
        event.get("timestamp_desc"),
    )


def load_export(
    conn: sqlite3.Connection,
    export_path: str,
    *,
    fmt: str = "json_line",
    batch_size: int = 2000,
    date_filter: None = None,
) -> dict[str, int]:
    """Stream the export into the store. NO date filtering (window applied later).

    ``date_filter`` exists ONLY to assert it is never used: passing anything other
    than ``None`` raises, documenting in code that out-of-window (timestomped) rows
    must not be dropped at load time.
    """
    if date_filter is not None:
        raise ValueError(
            "load_export does NOT date-filter at parse/load time; the incident "
            "window is a QUERY filter so timestomped out-of-window rows survive"
        )
    if fmt != "json_line":
        raise NotImplementedError(
            f"fmt={fmt!r} not implemented; this loader targets psort 'json_line' "
            "(it carries _event_values_hash + structured fields for the pivots)"
        )

    n_rows = skipped_blank = parse_errors = 0
    batch: list[tuple] = []
    cur = conn.cursor()
    cur.execute("BEGIN")
    for byte_start, byte_len, content in iter_export_rows(export_path):
        if byte_len == 0:
            skipped_blank += 1
            continue
        try:
            event = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            parse_errors += 1
            continue
        if not isinstance(event, dict):
            parse_errors += 1
            continue
        batch.append(extract_row(event, byte_start, byte_len, export_path, content))
        if len(batch) >= batch_size:
            cur.executemany(_INSERT_SQL, batch)
            batch.clear()
            n_rows += batch_size
    if batch:
        cur.executemany(_INSERT_SQL, batch)
        n_rows += len(batch)
    conn.commit()
    return {"n_rows": n_rows, "skipped_blank": skipped_blank, "parse_errors": parse_errors}


# -----------------------------------------------------------------------------
# The entry point.
# -----------------------------------------------------------------------------
def _run_producer(cmd: list[str], log_path: str | None) -> int:
    """Run the parse-once producer (e.g. psort), streaming its output to a log."""
    if log_path:
        with open(log_path, "ab") as logf:
            return subprocess.call(cmd, stdout=logf, stderr=subprocess.STDOUT)
    return subprocess.call(cmd)


def build_index(
    artifact: Artifact,
    *,
    db_path: str = DEFAULT_DB_PATH,
    agent: str = "build_index",
    ledger: _ledger.Ledger | None = None,
    producer_log: str | None = None,
) -> IndexResult:
    """Parse ``artifact`` once → load the per-case store → return counts+handle+receipt.

    Emits a START receipt before work and a DONE receipt after (both hash-chained
    into ``receipts.jsonl``; the DONE receipt streams the export's SHA-256). Returns
    an :class:`IndexResult` — counts, the table handle, and the two receipt ids.
    NO event rows are returned.
    """
    led = ledger or _ledger.Ledger()

    start_receipt = led.append(
        agent=agent,
        tool="build_index",
        args=["start", artifact.name, artifact.export_path],
        evidence_ref=artifact.evidence_ref,
        output_path=None,
        exit_code=None,
        note=f"START build_index artifact={artifact.name} fmt={artifact.fmt}",
    )

    # 1) Parse ONCE → export capture (only if not already produced).
    if artifact.producer_cmd and not os.path.exists(artifact.export_path):
        rc = _run_producer(artifact.producer_cmd, producer_log)
        if rc != 0 or not os.path.exists(artifact.export_path):
            led.append(
                agent=agent,
                tool="build_index",
                args=["error", artifact.name],
                evidence_ref=artifact.evidence_ref,
                output_path=artifact.export_path,
                exit_code=rc,
                errored=True,
                error=f"producer failed rc={rc}",
                note="producer (parse step) failed",
            )
            raise RuntimeError(f"producer for {artifact.name!r} failed rc={rc}")

    # 2) Load into SQLite (streamed, byte-offset tracked, NO date filter).
    conn = init_db(db_path)
    try:
        stats = load_export(conn, artifact.export_path, fmt=artifact.fmt)
        # 3) DONE receipt — streams the export's segmented SHA-256 + byte count.
        done_receipt = led.append(
            agent=agent,
            tool="build_index",
            args=["done", artifact.name, artifact.export_path],
            evidence_ref=artifact.evidence_ref,
            output_path=artifact.export_path,
            exit_code=0,
            note=(
                f"DONE build_index artifact={artifact.name} rows={stats['n_rows']} "
                f"blank={stats['skipped_blank']} parse_errors={stats['parse_errors']} "
                f"table={TABLE_NAME} no_date_filter=true"
            ),
        )
        meta = {
            "artifact": artifact.name,
            "export_path": artifact.export_path,
            "export_sha256": done_receipt.get("output_sha256"),
            "export_bytes": str(done_receipt.get("output_bytes")),
            "n_rows": str(stats["n_rows"]),
            "skipped_blank": str(stats["skipped_blank"]),
            "parse_errors": str(stats["parse_errors"]),
            "no_date_filter": "true",
            "start_receipt_id": start_receipt.get("receipt_id"),
            "done_receipt_id": done_receipt.get("receipt_id"),
            "built_ts_utc": done_receipt.get("ts"),
        }
        conn.executemany(
            "INSERT OR REPLACE INTO index_meta (key, value) VALUES (?, ?)",
            [(k, "" if v is None else str(v)) for k, v in meta.items()],
        )
        conn.commit()
    finally:
        conn.close()

    return IndexResult(
        artifact=artifact.name,
        db_path=db_path,
        table=TABLE_NAME,
        n_rows=stats["n_rows"],
        export_path=artifact.export_path,
        export_sha256=done_receipt.get("output_sha256"),
        export_bytes=done_receipt.get("output_bytes"),
        start_receipt_id=start_receipt.get("receipt_id"),
        done_receipt_id=done_receipt.get("receipt_id"),
        skipped_blank=stats["skipped_blank"],
        parse_errors=stats["parse_errors"],
    )


# -----------------------------------------------------------------------------
# CLI — invoked by the detached overnight job AFTER log2timeline + psort, or with
# --producer to run psort itself. Prints ONLY the IndexResult handle (no rows).
# -----------------------------------------------------------------------------
def _main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Load a psort export into the per-case index.")
    ap.add_argument("--name", default="super_timeline")
    ap.add_argument("--export", required=True, help="psort json_line export (output_path capture)")
    ap.add_argument("--db", default=DEFAULT_DB_PATH)
    ap.add_argument("--evidence-ref", default=None)
    ap.add_argument("--agent", default="overnight-build_index")
    ap.add_argument("--producer-log", default=None)
    ap.add_argument(
        "--psort", default=None,
        help="optional plaso store to run psort json_line over to PRODUCE --export",
    )
    args = ap.parse_args(argv)

    producer_cmd = None
    if args.psort:
        producer_cmd = ["psort.py", "-o", "json_line", "-w", args.export, args.psort]

    artifact = Artifact(
        name=args.name,
        export_path=args.export,
        fmt="json_line",
        evidence_ref=args.evidence_ref,
        producer_cmd=producer_cmd,
    )
    result = build_index(
        artifact, db_path=args.db, agent=args.agent, producer_log=args.producer_log
    )
    # Emit ONLY the handle + counts + receipt ids (no rows).
    print(json.dumps({
        "artifact": result.artifact,
        "handle": result.handle(),
        "n_rows": result.n_rows,
        "export_sha256": result.export_sha256,
        "export_bytes": result.export_bytes,
        "start_receipt_id": result.start_receipt_id,
        "done_receipt_id": result.done_receipt_id,
        "skipped_blank": result.skipped_blank,
        "parse_errors": result.parse_errors,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())

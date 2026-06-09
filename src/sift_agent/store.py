"""Per-case SQLite evidence store — the Day-2 spine for traceable findings.

Goal
----
A single per-case SQLite database that is the agent's evidence spine.
``build_index()`` and the tool wrappers WRITE evidence rows here; ``query_store()``
(a SEPARATE, later task) is the agent's ONLY read path; the Day-3 verifier greps
the cited ``byte_range`` and re-checks the chunk hash. Traceability is made
*structural* — every evidence row is FORCED by the DB schema to carry a
``native_locator``, a ``[byte_start, byte_len]`` range, and the ``receipt_id`` of
the tool run that produced it. There is no code path that can write an
un-traceable row, because the ``NOT NULL`` / ``CHECK`` / ``FOREIGN KEY``
constraints reject it before it reaches disk.

This module builds the SCHEMA ONLY (via :func:`init_store`) plus the small,
shared primitives the writer and verifier both need: :func:`connect` (which
applies the per-connection PRAGMAs that make the guarantees real) and
:func:`compute_root_sha256` (the single canonical definition of a capture's
deterministic root hash). It does NOT implement ``query_store()`` or the
``build_index`` ingest — those are separate tasks. It NEVER reads the evidence
images.

Where the data lives
--------------------
The DB FILE is **case data** (it holds artifact paths, IPs, hashes — PII) and so
lives OUTSIDE the repo at :data:`DEFAULT_STORE_PATH`
(``~/josh/cases/Rocba/store.sqlite``), alongside the ledger's
``receipts.jsonl``. Only this module + its tests are committed; ``.gitignore``
blocks the ``*.sqlite`` / ``*.sqlite3`` / ``*.db`` families incl. their ``-wal`` /
``-shm`` sidecars (WAL mode always spawns sidecars) — the DB FILE is never
committed.

Format contract (must line up with the rest of the agent)
--------------------------------------------------------
So the Day-3 disk<->memory JOIN and the verifier's re-check line up byte-for-byte
with :mod:`sift_agent.ledger` and :mod:`sift_agent.finding`:

* ``receipt_id`` columns hold the EXACT ledger ``receipt_id`` value (a uuid4
  string — see :mod:`sift_agent.ledger`), never an invented id.
* every timestamp column (``created_utc``, ``rows.ts``) is host UTC ISO-8601 with
  a trailing ``Z`` (e.g. ``2026-06-09T01:22:09Z``) — the same shape
  :func:`sift_agent.ledger._utc_now_z` and ``Finding.created_ts`` use.
* every ``sha256`` is lowercase hex (``hashlib.sha256(...).hexdigest()``); the
  ``rows.sha256`` column additionally CHECKs ``length == 64``. (The CHECK pins
  length only, not case — writers MUST store the lowercase ``hexdigest()`` so the
  case-sensitive ``ix_rows_sha256`` JOIN matches; build_index/query_store own that
  normalisation.)
* a cited range is stored as ``rows.byte_start`` + ``rows.byte_len`` and maps to
  the HALF-OPEN interval ``[byte_start, byte_start + byte_len)`` — i.e. the
  ``[start, end]`` pair on ``finding.ProvenanceRef.byte_range`` with
  ``end == byte_start + byte_len`` (end-EXCLUSIVE). The verifier slices
  ``data[byte_start : byte_start + byte_len]``. ``CHECK(byte_len > 0)`` means the
  store cannot represent a zero-width citation.

The deterministic capture root hash
-----------------------------------
``captures.root_sha256`` is defined as a single-level Merkle root over the leaf
chunk hashes::

    root_sha256 = sha256( leaf_0 || leaf_1 || ... || leaf_{n-1} ).hexdigest()

where each ``leaf_i`` is the RAW 32-byte digest (``bytes.fromhex`` of
``capture_chunks.sha256``) of the chunk at ``seq == i``, concatenated in
ascending ``seq`` order. This is intentionally simple and fully recomputable
from the DB alone — the verifier reads the chunk hashes in ``seq`` order and
re-runs :func:`compute_root_sha256`. A full multi-level Merkle tree is future
work; this degenerate one-level form is the agreed contract today.

Schema versioning
----------------
:func:`init_store` is idempotent (every ``CREATE`` is ``IF NOT EXISTS``) and
NEVER drops or alters an existing table. If an existing store already carries a
``store_meta.schema_version`` that is not :data:`SCHEMA_VERSION`, init FAILS
LOUDLY (raises :class:`StoreError`) — it never silently migrates. Seed values
(``case_id`` / ``evidence_baseline_sha256``) are likewise never silently
re-bound: re-seeding with a *different* non-null value raises.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import sqlite3
from collections.abc import Mapping
from datetime import datetime, timezone

__all__ = [
    "SCHEMA_VERSION",
    "DEFAULT_STORE_PATH",
    "SCHEMA_SQL",
    "StoreError",
    "connect",
    "init_store",
    "compute_root_sha256",
    "DEFAULT_SEGMENT_SIZE",
    "add_capture",
    "add_chunk",
    "add_row",
    "add_capture_from_file",
    "QUERYABLE_COLUMNS",
    "RETURN_COLUMNS",
    "MAX_LIMIT",
    "connect_readonly",
    "query_store",
]

# =============================================================================
# Named constants.
# =============================================================================
#: Current store schema version. Seeded into ``store_meta`` and checked on every
#: :func:`init_store`. A store whose recorded version differs fails loudly.
SCHEMA_VERSION = "1"

#: Default DB location. Holds case data / PII, so it lives in the per-case dir
#: (next to ``receipts.jsonl``) OUTSIDE the repo and is git-ignored — it must
#: NEVER be committed. Overridable via ``STORE_PATH`` or the function arg.
DEFAULT_STORE_PATH = os.path.expanduser("~/josh/cases/Rocba/store.sqlite")

#: Busy timeout (ms) applied to every connection so concurrent agents block-and-
#: retry rather than failing immediately on a locked DB.
_BUSY_TIMEOUT_MS = 5000


class StoreError(Exception):
    """The store could not be opened/initialised because it violates an invariant
    (e.g. an incompatible ``schema_version``, or a conflicting seed re-bind)."""


# =============================================================================
# The schema — implemented EXACTLY as specified. Traceability is enforced here,
# in the DB (NOT NULL / CHECK / FOREIGN KEY), not in Python.
# =============================================================================
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS store_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS captures (
    capture_id   INTEGER PRIMARY KEY,
    source_tool  TEXT NOT NULL,
    tool_version TEXT,
    receipt_id   TEXT NOT NULL,
    capture_path TEXT NOT NULL,
    total_bytes  INTEGER NOT NULL,
    segment_size INTEGER NOT NULL,
    root_sha256  TEXT NOT NULL,
    created_utc  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS capture_chunks (
    capture_id INTEGER NOT NULL REFERENCES captures(capture_id),
    seq        INTEGER NOT NULL,
    offset     INTEGER NOT NULL,
    length     INTEGER NOT NULL CHECK(length > 0),
    sha256     TEXT NOT NULL,
    PRIMARY KEY (capture_id, seq)
);

CREATE TABLE IF NOT EXISTS rows (
    row_id          INTEGER PRIMARY KEY,
    artifact_type   TEXT NOT NULL,
    evidence_source TEXT NOT NULL CHECK(evidence_source IN ('disk','memory')),
    native_locator  TEXT NOT NULL,
    capture_id      INTEGER NOT NULL REFERENCES captures(capture_id),
    byte_start      INTEGER NOT NULL,
    byte_len        INTEGER NOT NULL CHECK(byte_len > 0),
    receipt_id      TEXT NOT NULL,
    proc TEXT, pid INTEGER, path TEXT,
    sha256 TEXT CHECK(sha256 IS NULL OR length(sha256)=64),
    ip TEXT, ts TEXT
);

CREATE INDEX IF NOT EXISTS ix_rows_path   ON rows(path);
CREATE INDEX IF NOT EXISTS ix_rows_sha256 ON rows(sha256);
CREATE INDEX IF NOT EXISTS ix_rows_ip     ON rows(ip);
CREATE INDEX IF NOT EXISTS ix_rows_pid    ON rows(pid);
CREATE INDEX IF NOT EXISTS ix_rows_ts     ON rows(ts);
CREATE INDEX IF NOT EXISTS ix_rows_proc   ON rows(proc);
CREATE INDEX IF NOT EXISTS ix_rows_type   ON rows(artifact_type);
"""


# =============================================================================
# Timestamp + hash helpers — IDENTICAL shapes to ledger.py / finding.py.
# =============================================================================
def _utc_now_z() -> str:
    """Host UTC, ISO-8601, ``Z`` suffix — e.g. ``2026-06-09T01:02:03Z``.

    Byte-for-byte the same shape as :func:`sift_agent.ledger._utc_now_z` and
    ``Finding.created_ts`` so the Day-3 disk<->memory JOIN lines up.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_root_sha256(chunk_sha256_hexes) -> str:
    """The canonical deterministic capture root hash (see module docstring).

    ``root = sha256( leaf_0 || leaf_1 || ... )`` where each ``leaf_i`` is the RAW
    32-byte digest (``bytes.fromhex``) of the chunk hash at ``seq == i``, in
    ascending ``seq`` order. The caller MUST pass the lowercase-hex chunk hashes
    already ordered by ``seq``.

    This is the SINGLE source of truth: ``build_index`` stores
    ``compute_root_sha256(...)`` and the verifier recomputes it from the DB rows
    — both call THIS function so they cannot disagree.

    Raises
    ------
    StoreError
        If the leaf list is empty (a capture must have >=1 chunk; an empty list
        would silently return the empty-string digest ``e3b0c442…``, which is
        indistinguishable from a real root), or if any chunk hash is not a
        64-char lowercase-hex SHA-256 string (an ill-formed leaf would silently
        produce a meaningless, un-recomputable root).
    """
    leaves = list(chunk_sha256_hexes)
    if not leaves:
        raise StoreError(
            "cannot compute a root hash over zero chunks; a capture must have "
            ">=1 leaf chunk"
        )
    h = hashlib.sha256()
    for i, hexdigest in enumerate(leaves):
        if (
            not isinstance(hexdigest, str)
            or len(hexdigest) != 64
            or hexdigest.lower() != hexdigest
        ):
            raise StoreError(
                f"chunk hash at seq {i} is not 64-char lowercase hex: {hexdigest!r}"
            )
        try:
            h.update(bytes.fromhex(hexdigest))
        except ValueError as exc:
            raise StoreError(f"chunk hash at seq {i} is not valid hex: {hexdigest!r}") from exc
    return h.hexdigest()


# =============================================================================
# Connection — every connection carries the PRAGMAs that make the guarantees
# REAL. foreign_keys is per-connection in SQLite, so it MUST be set here, not
# once: a connection without it would silently accept an orphan capture_id.
# =============================================================================
def connect(db_path: str | None = None) -> sqlite3.Connection:
    """Open the store at ``db_path`` with the mandatory PRAGMAs applied.

    Resolves the path from ``db_path`` → ``STORE_PATH`` env →
    :data:`DEFAULT_STORE_PATH`, expanding ``~``. Applies, on THIS connection:

    * ``foreign_keys = ON``   — so ``rows.capture_id`` referencing a missing
      capture is rejected (off by default in SQLite, and per-connection);
    * ``journal_mode = WAL``  — multi-agent readers don't block the writer;
    * ``busy_timeout = 5000`` — concurrent writers block-and-retry for 5s.

    The parent directory is created if absent. The caller owns the returned
    connection and is responsible for closing it.
    """
    path = db_path or os.environ.get("STORE_PATH") or DEFAULT_STORE_PATH
    path = os.path.expanduser(path)
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)

    conn = sqlite3.connect(path)
    # PRAGMAs run immediately (outside any transaction). foreign_keys is the one
    # that turns the FK declarations from documentation into enforcement.
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    return conn


def _get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    """Return ``store_meta.value`` for ``key``, or ``None`` if absent."""
    row = conn.execute("SELECT value FROM store_meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row is not None else None


def _seed_once(conn: sqlite3.Connection, key: str, value: str | None) -> None:
    """Seed one ``store_meta`` row IF ABSENT; keep the original on re-init.

    ``None`` values are skipped. ``INSERT OR IGNORE`` never overwrites, so a
    re-call leaves the existing value untouched — exactly what ``created_utc``
    (the store's one true creation instant) and ``schema_version`` need: a plain
    ``init_store(path)`` recomputes "now", but the FIRST value is canonical and
    is preserved, keeping init idempotent.
    """
    if value is None:
        return
    conn.execute(
        "INSERT OR IGNORE INTO store_meta(key, value) VALUES (?, ?)", (key, value)
    )


def _seed_identity(conn: sqlite3.Connection, key: str, value: str | None) -> None:
    """Seed an IDENTITY ``store_meta`` row, refusing a conflicting re-bind.

    Like :func:`_seed_once`, but if the key already holds a DIFFERENT non-null
    value, raise :class:`StoreError` rather than silently re-binding the store to
    a new case / evidence baseline. Used for ``case_id`` /
    ``evidence_baseline_sha256``, whose change would mean "this store now belongs
    to different evidence" — a structural error, not a benign re-init.
    """
    if value is None:
        return
    existing = _get_meta(conn, key)
    if existing is not None and existing != value:
        raise StoreError(
            f"store_meta[{key!r}] already set to {existing!r}; refusing to re-bind "
            f"to {value!r} (a per-case store must not silently change its identity)"
        )
    conn.execute(
        "INSERT OR IGNORE INTO store_meta(key, value) VALUES (?, ?)", (key, value)
    )


def _canonical_baseline(value: "str | Mapping[str, str] | None") -> str | None:
    """Normalise an evidence-baseline seed value to the stored TEXT form.

    A case has MORE THAN ONE evidence image (disk + memory), so the baseline is
    normally a mapping of evidence role -> baseline sha256; it is stored as a
    canonical JSON object (sorted keys, compact, ASCII — the same shape
    :mod:`sift_agent.ledger`/:mod:`sift_agent.finding` hash) so the value is
    deterministic and re-bind comparisons are byte-stable. A bare ``str`` (a
    single image, or a pre-serialised value) is stored verbatim; ``None`` skips.
    """
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        return json.dumps(
            dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
    raise StoreError(
        "evidence_baseline_sha256 must be a str, a role->sha256 mapping, or None; "
        f"got {type(value).__name__}"
    )


def init_store(
    db_path: str | None = None,
    *,
    case_id: str | None = None,
    evidence_baseline_sha256: "str | Mapping[str, str] | None" = None,
    created_utc: str | None = None,
) -> str:
    """Create the schema (idempotently) and seed ``store_meta``; return the path.

    Creates every table/index ``IF NOT EXISTS`` (never drops or alters existing
    ones) and seeds ``store_meta`` with ``schema_version`` (always
    :data:`SCHEMA_VERSION`), ``created_utc`` (defaulting to "now" in the canonical
    ``...Z`` shape), and — when supplied by the caller — ``case_id`` and
    ``evidence_baseline_sha256``. The latter is the REAL per-case evidence
    baseline from the case sidecar; because the case has multiple images, pass a
    ``{role: sha256}`` mapping (e.g. ``{"disk": ..., "memory": ...}``) and BOTH
    baselines are stored as one canonical JSON value. This module never reads the
    sidecar or the evidence itself.

    Idempotent: a second call on an existing store re-creates nothing and
    re-binds nothing. FAILS LOUDLY (:class:`StoreError`) if the store already
    records a ``schema_version`` other than :data:`SCHEMA_VERSION` — migration is
    deliberately NOT performed here.
    """
    conn = connect(db_path)
    try:
        # Create first (IF NOT EXISTS → safe on an existing store), then read the
        # recorded version: on a fresh store it is absent; on an existing one a
        # mismatch is fatal. We never migrate silently.
        conn.executescript(SCHEMA_SQL)
        recorded = _get_meta(conn, "schema_version")
        if recorded is not None and recorded != SCHEMA_VERSION:
            raise StoreError(
                f"store schema_version is {recorded!r}, expected {SCHEMA_VERSION!r}; "
                "refusing to open — this build does not migrate stores (migration is "
                "future work). Use a store created by this schema version."
            )
        _seed_once(conn, "schema_version", SCHEMA_VERSION)
        _seed_identity(conn, "case_id", case_id)
        _seed_identity(
            conn, "evidence_baseline_sha256", _canonical_baseline(evidence_baseline_sha256)
        )
        _seed_once(conn, "created_utc", created_utc or _utc_now_z())
        conn.commit()
    finally:
        conn.close()
    return _resolve_path(db_path)


# =============================================================================
# Writer helpers — the thin INSERT primitives build_index and the tool wrappers
# use to WRITE evidence into the store. They are deliberately THIN: they bind
# values and let the schema's NOT NULL / CHECK / FOREIGN KEY constraints do the
# rejecting. They do NO Python-side validation ON PURPOSE — moving the checks
# into Python would relocate the traceability guarantee OUT of the DB, so a
# careless caller could bypass it. Keeping them thin means even a convenience
# writer cannot slip an un-traceable row past the guardrail (constraint #2).
# None of them commit: the CALLER owns the transaction so a capture, its chunks,
# and its rows can be written atomically (or rolled back together on error).
# =============================================================================

#: Default capture segment size (bytes) — the leaf granularity the Day-3 verifier
#: re-hashes. 1 MiB keeps the leaf count small for typical tool outputs while
#: still localising a citation to a ~1 MiB window. Overridable per capture.
DEFAULT_SEGMENT_SIZE = 1 << 20  # 1048576


def add_capture(
    conn: sqlite3.Connection,
    *,
    source_tool: str,
    receipt_id: str,
    capture_path: str,
    total_bytes: int,
    segment_size: int,
    root_sha256: str,
    tool_version: str | None = None,
    created_utc: str | None = None,
) -> int:
    """Insert one ``captures`` row; return its ``capture_id``.

    A thin INSERT wrapper — the DB's NOT NULL columns reject a missing required
    field. ``created_utc`` defaults to now in the canonical ``...Z`` shape.
    Does NOT commit.
    """
    cur = conn.execute(
        "INSERT INTO captures(source_tool, tool_version, receipt_id, capture_path, "
        "total_bytes, segment_size, root_sha256, created_utc) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            source_tool, tool_version, receipt_id, capture_path,
            total_bytes, segment_size, root_sha256, created_utc or _utc_now_z(),
        ),
    )
    return cur.lastrowid


def add_chunk(
    conn: sqlite3.Connection,
    capture_id: int,
    seq: int,
    offset: int,
    length: int,
    sha256: str,
) -> None:
    """Insert one ``capture_chunks`` leaf. Thin wrapper; does NOT commit.

    ``CHECK(length > 0)`` rejects a zero-length leaf, the ``(capture_id, seq)``
    primary key rejects a duplicate, and the FK rejects an orphan ``capture_id``
    (under ``foreign_keys=ON``) — all at the DB level.
    """
    conn.execute(
        "INSERT INTO capture_chunks(capture_id, seq, offset, length, sha256) "
        "VALUES (?, ?, ?, ?, ?)",
        (capture_id, seq, offset, length, sha256),
    )


#: The `rows` columns :func:`add_row` binds, in INSERT order. The traceability
#: quartet (``native_locator`` / ``byte_start`` / ``byte_len`` / ``receipt_id``)
#: is NOT NULL in the schema, so omitting one is a DB rejection, not a silent gap.
_ROW_INSERT_COLUMNS = (
    "artifact_type", "evidence_source", "native_locator", "capture_id",
    "byte_start", "byte_len", "receipt_id", "proc", "pid", "path",
    "sha256", "ip", "ts",
)


def add_row(
    conn: sqlite3.Connection,
    *,
    artifact_type: str,
    evidence_source: str,
    native_locator: str,
    capture_id: int,
    byte_start: int,
    byte_len: int,
    receipt_id: str,
    proc: str | None = None,
    pid: int | None = None,
    path: str | None = None,
    sha256: str | None = None,
    ip: str | None = None,
    ts: str | None = None,
) -> int:
    """Insert one evidence ``rows`` fact; return its ``row_id``.

    A thin INSERT wrapper that does NO Python-side validation ON PURPOSE: the
    traceability guarantee is STRUCTURAL, enforced by the schema. A row with a
    NULL ``native_locator``, a zero ``byte_len``, a malformed ``sha256``, an
    unknown ``evidence_source``, or an orphan ``capture_id`` is rejected by the
    DB (``sqlite3.IntegrityError``) — this convenience writer CANNOT bypass the
    guardrail. The 6 pivot columns are optional. Does NOT commit.
    """
    cur = conn.execute(
        f"INSERT INTO rows({','.join(_ROW_INSERT_COLUMNS)}) "
        f"VALUES ({','.join('?' * len(_ROW_INSERT_COLUMNS))})",
        (
            artifact_type, evidence_source, native_locator, capture_id,
            byte_start, byte_len, receipt_id, proc, pid, path, sha256, ip, ts,
        ),
    )
    return cur.lastrowid


def add_capture_from_file(
    conn: sqlite3.Connection,
    capture_path: str,
    *,
    source_tool: str,
    receipt_id: str,
    tool_version: str | None = None,
    segment_size: int = DEFAULT_SEGMENT_SIZE,
    created_utc: str | None = None,
) -> int:
    """Segment a captured tool-output FILE into leaf chunks, hash each, write the
    capture + its leaves, and return the ``capture_id``.

    This is the chunk-hashing helper the verifier's contract depends on. It reads
    ``capture_path`` — the captured *tool output* the agent saw, NOT the evidence
    image (this module never reads evidence) — in ``segment_size``-byte leaves,
    computing each leaf's lowercase-hex SHA-256. The capture's ``root_sha256`` is
    :func:`compute_root_sha256` over those leaves in ``seq`` order;
    ``total_bytes`` is the file size. Writes one ``captures`` row and one
    ``capture_chunks`` row per leaf via :func:`add_capture` / :func:`add_chunk`.
    The file is streamed a segment at a time, so memory stays bounded regardless
    of capture size. Does NOT commit (caller owns the txn).

    The single-level root (``sha256`` over concatenated leaf digests) is the
    agreed contract TODAY; a full multi-level Merkle tree is future work (see the
    module docstring).

    Raises
    ------
    StoreError
        If ``segment_size`` is not positive, or if the file is empty — a capture
        must have >=1 leaf chunk (:func:`compute_root_sha256` rejects zero
        leaves), so a zero-byte capture is refused loudly rather than stored with
        an ambiguous empty-input root.
    """
    if segment_size <= 0:
        raise StoreError(f"segment_size must be positive, got {segment_size!r}")
    leaves: list[tuple[int, int, int, str]] = []  # (seq, offset, length, hexdigest)
    offset = 0
    with open(capture_path, "rb") as fh:
        for seq in itertools.count():
            block = fh.read(segment_size)
            if not block:
                break
            leaves.append((seq, offset, len(block), hashlib.sha256(block).hexdigest()))
            offset += len(block)
    if not leaves:
        raise StoreError(
            f"capture file {capture_path!r} is empty; a capture must have >=1 "
            "leaf chunk (refusing to store a zero-byte, un-citable capture)"
        )
    root = compute_root_sha256([hexdigest for (_, _, _, hexdigest) in leaves])
    capture_id = add_capture(
        conn,
        source_tool=source_tool,
        tool_version=tool_version,
        receipt_id=receipt_id,
        capture_path=capture_path,
        total_bytes=offset,
        segment_size=segment_size,
        root_sha256=root,
        created_utc=created_utc,
    )
    for seq, off, length, hexdigest in leaves:
        add_chunk(conn, capture_id, seq, off, length, hexdigest)
    return capture_id


# =============================================================================
# Read path — query_store(): the agent's ONLY read into the store.
# Capped, paginated, read-only BY CONSTRUCTION (mode=ro), traceable rows out.
# The agent never writes raw SQL: filter keys are checked against a WHITELIST of
# real columns and all values are BOUND as parameters, so a filter can only ever
# narrow a SELECT over `rows` — it can never inject SQL or reach another table.
# =============================================================================
#: Columns a caller may filter on (equality, ``IN [..]``, or — for ``ts`` — the
#: ``ts_from`` / ``ts_to`` range keys). EXACTLY the `rows` pivot columns; any
#: other filter key is rejected. These names are the ONLY caller-influenced text
#: that reaches SQL, and only after membership in this fixed tuple is confirmed.
QUERYABLE_COLUMNS = (
    "artifact_type", "evidence_source", "proc", "pid", "path", "sha256", "ip", "ts",
)

#: The ``ts`` range filter keys (mapped to ``ts >= ?`` / ``ts <= ?``).
_RANGE_KEYS = {"ts_from": ">=", "ts_to": "<="}

#: Columns every returned row carries. The traceability quartet
#: (``native_locator`` + ``byte_start`` + ``byte_len`` + ``receipt_id``) is
#: ALWAYS present so the caller / Day-3 verifier can trace and re-check the row.
#: Raw captured bytes are deliberately NOT returned — the verifier reads the
#: byte_range from the capture file separately, keeping this payload bounded.
RETURN_COLUMNS = (
    "row_id", "artifact_type", "evidence_source", "native_locator", "capture_id",
    "byte_start", "byte_len", "receipt_id", "proc", "pid", "path", "sha256", "ip", "ts",
)

#: Hard ceiling on a page size — a context-window guard. A caller asking for more
#: is REJECTED, never silently truncated.
MAX_LIMIT = 50


def _resolve_path(db_path: str | None) -> str:
    """Resolve ``db_path`` → ``STORE_PATH`` env → :data:`DEFAULT_STORE_PATH`, ``~``-expanded."""
    return os.path.expanduser(db_path or os.environ.get("STORE_PATH") or DEFAULT_STORE_PATH)


def connect_readonly(db_path: str | None = None) -> sqlite3.Connection:
    """Open the store READ-ONLY by construction — the read path's architectural guardrail.

    Uses SQLite's ``file:...?mode=ro`` URI so the connection opens the database
    file ``O_RDONLY``: any ``INSERT`` / ``UPDATE`` / ``DELETE`` / ``CREATE`` on it
    raises ``sqlite3.OperationalError`` ("attempt to write a readonly database").
    This is the same no-mutation philosophy as the MCP no-shell read path: the
    agent's read handle PHYSICALLY cannot modify evidence-derived rows.

    Unlike :func:`connect`, this does NOT create the file or its parent — a
    read-only path must never bring a store into existence. ``busy_timeout`` is
    still applied (a connection-local setting, no write) for polite concurrency.
    """
    path = _resolve_path(db_path)
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    return conn


def _build_where(filters):
    """Translate a ``filters`` dict into a parameterised ``WHERE`` over `rows`.

    Returns ``(clauses, params)``. Each filter key MUST be a whitelisted pivot
    column (equality / membership) or a ``ts`` range key (``ts_from`` / ``ts_to``);
    any other key raises :class:`ValueError`. A list/tuple/set value becomes
    ``col IN (?, …)`` (empty rejected); a scalar becomes ``col = ?`` (or
    ``col IS NULL`` for ``None``, so a null-seeking filter doesn't silently match
    nothing). Column names come ONLY from the fixed whitelists; values are always
    bound — the caller can never inject SQL.
    """
    if not isinstance(filters, dict):
        raise ValueError(f"filters must be a dict, got {type(filters).__name__}")
    clauses: list[str] = []
    params: list = []
    for key, val in filters.items():
        if key in QUERYABLE_COLUMNS:
            if isinstance(val, (list, tuple, set)):
                values = list(val)
                if not values:
                    raise ValueError(f"filter {key!r}: empty membership list matches nothing")
                clauses.append(f"{key} IN ({','.join('?' * len(values))})")
                params.extend(values)
            elif val is None:
                clauses.append(f"{key} IS NULL")
            else:
                clauses.append(f"{key} = ?")
                params.append(val)
        elif key in _RANGE_KEYS:
            clauses.append(f"ts {_RANGE_KEYS[key]} ?")
            params.append(val)
        else:
            allowed = ", ".join(sorted(QUERYABLE_COLUMNS) + sorted(_RANGE_KEYS))
            raise ValueError(f"unknown filter key {key!r}; allowed: {allowed}")
    return clauses, params


def query_store(
    filters: dict,
    *,
    limit: int = 50,
    cursor: int | None = None,
    db_path: str | None = None,
) -> dict:
    """The agent's ONLY read into the per-case store: capped, paginated, traceable.

    Parameters
    ----------
    filters : dict
        Whitelisted-column predicates (see :func:`_build_where`). ``{}`` matches all.
    limit : int
        Page size, 1..:data:`MAX_LIMIT`. Out of range RAISES :class:`ValueError`
        — the cap is never silently exceeded (context-window guard).
    cursor : int | None
        KEYSET cursor = the last ``row_id`` seen. ``None`` for the first page.
    db_path : str | None
        Store path (resolved like :func:`connect`); opened READ-ONLY.

    Returns
    -------
    dict
        ``{"rows": [...], "total_count": int, "returned": int, "truncated": bool,
        "next_cursor": int|None}``. ``rows`` are dicts over :data:`RETURN_COLUMNS`
        (each carries the traceability quartet). ``total_count`` is the full match
        count ignoring paging; ``truncated`` is True iff more pages remain;
        ``next_cursor`` is this page's last ``row_id`` when more remain, else None.

    Pagination is KEYSET (``WHERE row_id > cursor ORDER BY row_id``), not OFFSET,
    so it stays O(page) and visits every matching row exactly once with no
    duplicates or gaps even as the page advances.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or not (1 <= limit <= MAX_LIMIT):
        raise ValueError(f"limit must be an int in 1..{MAX_LIMIT}, got {limit!r}")
    if cursor is not None and (isinstance(cursor, bool) or not isinstance(cursor, int)):
        raise ValueError(f"cursor must be an int row_id or None, got {cursor!r}")

    clauses, params = _build_where(filters)
    where_sql = (" WHERE " + " AND ".join(clauses)) if clauses else ""

    conn = connect_readonly(db_path)
    try:
        # total_count: the full filter match, IGNORING paging.
        total_count = conn.execute(
            f"SELECT COUNT(*) FROM rows{where_sql}", params
        ).fetchone()[0]

        # Page via keyset. Fetch limit+1 to detect whether another page exists
        # without a second COUNT and regardless of the cursor position.
        page_clauses = list(clauses)
        page_params = list(params)
        if cursor is not None:
            page_clauses.append("row_id > ?")
            page_params.append(cursor)
        page_where = (" WHERE " + " AND ".join(page_clauses)) if page_clauses else ""
        page_params.append(limit + 1)
        fetched = conn.execute(
            f"SELECT {', '.join(RETURN_COLUMNS)} FROM rows{page_where} "
            f"ORDER BY row_id LIMIT ?",
            page_params,
        ).fetchall()
    finally:
        conn.close()

    truncated = len(fetched) > limit
    page = fetched[:limit]
    rows = [dict(zip(RETURN_COLUMNS, r)) for r in page]
    # next_cursor = this page's last row_id when more pages remain, else None.
    # truncated implies len(fetched) >= limit+1 >= 2, so `page` is a full,
    # non-empty page — page[-1] is always safe here.
    next_cursor = page[-1][0] if truncated else None

    return {
        "rows": rows,
        "total_count": total_count,
        "returned": len(rows),
        "truncated": truncated,
        "next_cursor": next_cursor,
    }

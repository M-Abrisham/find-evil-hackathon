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
    return os.path.expanduser(db_path or os.environ.get("STORE_PATH") or DEFAULT_STORE_PATH)

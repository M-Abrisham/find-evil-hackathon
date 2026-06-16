#!/usr/bin/env python3
"""Braintrust read + write-back client for Protocol SIFT trace enrichment.

Stdlib-only (``urllib`` for HTTP, ``json`` for bodies). No SDK, no third-party
deps (repo policy). Everything here was de-risked by the write-back spike; see
``trace_enrich/NOTES.md`` for the OBSERVED-working requests this mirrors.

What this module does
---------------------
* ``resolve_project_id(name)``  — name -> project_id via the documented REST call.
* ``get_trace(run_or_session_id)`` — find the run's MULTI-SPAN root (two-roots
  rule: discard ``n == 1`` telemetry roots) and return ``{root_span, tool_spans}``
  with the fields the orchestrator joins on (``span_id``, ``tool_use_id``,
  ``tool_name``, ``command``, ``file_path``, plus per-call ``success``).
* ``merge_span(span_id, metadata, tags, scores)`` /
  ``merge_root(root_span_id, metadata, scores, tags)`` — POST
  ``/v1/project_logs/{PID}/insert`` with ``_is_merge:true`` so labels/scores
  DEEP-MERGE onto the already-ingested span without clobbering originals.

CRITICAL id rule (from the spike): the write target is ``row.id == row.span_id``
(16-hex). ``root_span_id`` (32-hex) is the shared OTEL trace_id and is NOT a
writable row id — it is only ever used as a *filter* to list a run's spans.

The Braintrust API key is read from the ``BT_API_KEY`` environment variable. It
is NEVER hardcoded, echoed, or written to a committed file. On the VM it lives in
``.../.claude/settings.local.json`` inside ``OTEL_EXPORTER_OTLP_HEADERS``;
``key_from_settings_file()`` extracts it into a string for the caller to export
into the env — it never prints or persists it.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Constants (from NOTES.md §8 — all OBSERVED against the live project).
# ---------------------------------------------------------------------------
API_HOST = "https://api.braintrust.dev"
PROJECT_NAME = "protocol-sift"
#: Known project_id for "protocol-sift" (verified by the spike). resolve_project_id
#: re-resolves it over REST; this is only a fallback / cross-check default.
DEFAULT_PROJECT_ID = "74b50408-82b3-4b72-9043-4e8c28b7cb21"

#: Telemetry roots emit exactly one span; real investigation roots have many.
#: Discard any root group with n below this (the spike observed real runs at
#: 6/18/26/30 spans and stray telemetry roots at n==1).
MIN_REAL_ROOT_SPANS = 2

ENV_KEY = "BT_API_KEY"

# Span-kind names (span_attributes.name).
ROOT_SPAN_NAME = "claude_code.interaction"
TOOL_SPAN_NAME = "claude_code.tool"
EXEC_SPAN_NAME = "claude_code.tool.execution"


class BraintrustError(RuntimeError):
    """Any failure talking to the Braintrust API (HTTP, auth, or missing data)."""


# ---------------------------------------------------------------------------
# Key handling — read from env; helper to lift it out of settings.local.json.
# ---------------------------------------------------------------------------
def get_api_key() -> str:
    """Return the Braintrust key from ``$BT_API_KEY`` or raise (never default)."""
    key = os.environ.get(ENV_KEY, "").strip()
    if not key:
        raise BraintrustError(
            f"{ENV_KEY} is not set. Export the Braintrust key into the "
            f"environment (see README / NOTES.md §1) before running. "
            f"NEVER hardcode it."
        )
    return key


def key_from_settings_file(settings_path: str) -> str:
    """Extract the Bearer token from a ``.claude/settings.local.json``.

    Reads ``env.OTEL_EXPORTER_OTLP_HEADERS`` (``"Authorization=Bearer sk-..."``)
    and returns the token string. The caller is responsible for putting it into
    ``$BT_API_KEY``; this function does NOT print, log, or persist it.
    """
    with open(settings_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    hdr = (data.get("env") or {}).get("OTEL_EXPORTER_OTLP_HEADERS", "")
    m = re.search(r"Bearer\s+([^,\s]+)", hdr)
    if not m:
        raise BraintrustError(
            f"no 'Authorization=Bearer ...' found in {settings_path} "
            f"OTEL_EXPORTER_OTLP_HEADERS"
        )
    return m.group(1)


# ---------------------------------------------------------------------------
# Low-level HTTP (urllib only).
# ---------------------------------------------------------------------------
def _request(
    method: str,
    url: str,
    *,
    api_key: str,
    body: Optional[dict] = None,
    timeout: float = 60.0,
) -> Any:
    """Issue one HTTP request and return the parsed JSON body.

    Raises :class:`BraintrustError` on transport / HTTP / decode failure. The
    Authorization header carries the key; it is never logged.
    """
    data = None
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
    }
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:  # 4xx/5xx
        detail = ""
        try:
            detail = exc.read().decode("utf-8")[:500]
        except Exception:  # pragma: no cover - best-effort error surfacing
            pass
        raise BraintrustError(
            f"{method} {url} -> HTTP {exc.code} {exc.reason}: {detail}"
        ) from exc
    except urllib.error.URLError as exc:
        raise BraintrustError(f"{method} {url} -> transport error: {exc.reason}") from exc

    if not raw:
        return {}
    try:
        return json.loads(raw)
    except ValueError as exc:
        raise BraintrustError(f"{method} {url} -> non-JSON response: {raw[:200]!r}") from exc


def _btql(query: str, *, api_key: str, timeout: float = 60.0) -> List[dict]:
    """Run a BTQL query and return its ``data`` rows (NOTES.md §3 Method A)."""
    resp = _request(
        "POST",
        f"{API_HOST}/btql",
        api_key=api_key,
        body={"query": query, "fmt": "json"},
        timeout=timeout,
    )
    if isinstance(resp, dict):
        return resp.get("data", []) or []
    return resp or []


# ---------------------------------------------------------------------------
# Project resolution.
# ---------------------------------------------------------------------------
def resolve_project_id(name: str = PROJECT_NAME, *, api_key: Optional[str] = None) -> str:
    """Resolve a project NAME to its id (REST: ``GET /v1/project?project_name=``).

    Returns ``objects[0].id``. Falls back to :data:`DEFAULT_PROJECT_ID` only when
    the name matches :data:`PROJECT_NAME` and the call yields nothing usable.
    """
    # Explicit override (env) — robust when the /v1/project lookup is degraded.
    env_pid = os.environ.get("BT_PROJECT_ID", "").strip()
    if env_pid:
        return env_pid
    api_key = api_key or get_api_key()
    url = f"{API_HOST}/v1/project?" + urllib.parse.urlencode({"project_name": name})
    try:
        resp = _request("GET", url, api_key=api_key)
        objects = resp.get("objects") if isinstance(resp, dict) else None
        if objects:
            pid = objects[0].get("id")
            if pid:
                return pid
    except BraintrustError:
        # The /v1/project endpoint flakes with 5xx independently of the rest of
        # the API (BTQL/insert can be healthy). Fall back to the known id.
        if name == PROJECT_NAME:
            return DEFAULT_PROJECT_ID
        raise
    if name == PROJECT_NAME:
        return DEFAULT_PROJECT_ID
    raise BraintrustError(f"could not resolve project_id for name={name!r}")


# ---------------------------------------------------------------------------
# Span field access — every useful field lives under metadata (NOTES.md §4).
# ---------------------------------------------------------------------------
def _meta(row: dict) -> dict:
    m = row.get("metadata")
    return m if isinstance(m, dict) else {}


def _span_name(row: dict) -> str:
    attrs = row.get("span_attributes")
    if isinstance(attrs, dict):
        n = attrs.get("name")
        if n:
            return n
    # Some projections flatten the name; tolerate both shapes.
    return row.get("span_name") or row.get("name") or ""


def _is_root_row(row: dict) -> bool:
    """A run's root: ``is_root`` true, or no parents AND the interaction name."""
    if row.get("is_root") is True:
        return True
    parents = row.get("span_parents")
    no_parents = parents in (None, [], "")
    return no_parents and _span_name(row) == ROOT_SPAN_NAME


def _tool_use_id(meta: dict) -> Optional[str]:
    return meta.get("tool_use_id") or meta.get("gen_ai.tool.call.id")


# ---------------------------------------------------------------------------
# Run / root selection.
# ---------------------------------------------------------------------------
def list_runs(
    *,
    project_id: str,
    api_key: str,
    limit: int = 30,
) -> List[dict]:
    """List candidate runs newest-first, grouped by root_span_id.

    Returns ``[{root_span_id, n, last_ts}, ...]`` with the stray ``n == 1``
    telemetry roots already filtered out (two-roots rule, NOTES.md §3).
    """
    query = (
        f"from: project_logs('{project_id}') "
        f"| dimensions: root_span_id "
        f"| measures: count(1) as n, max(created) as last_ts "
        f"| sort: last_ts desc "
        f"| limit: {limit}"
    )
    rows = _btql(query, api_key=api_key)
    out: List[dict] = []
    for r in rows:
        n = r.get("n")
        try:
            n = int(n)
        except (TypeError, ValueError):
            continue
        if n < MIN_REAL_ROOT_SPANS:
            continue  # stray telemetry root
        out.append(
            {
                "root_span_id": r.get("root_span_id"),
                "n": n,
                "last_ts": r.get("last_ts"),
            }
        )
    return out


def _fetch_run_rows(
    *,
    project_id: str,
    api_key: str,
    root_span_id: Optional[str] = None,
    session_id: Optional[str] = None,
) -> List[dict]:
    """All logical spans for one run, selected by root_span_id or session.id.

    When ``root_span_id`` is given it is used directly (it is the OTEL trace_id
    shared by the run). When only a ``session_id`` is given we filter by
    ``metadata.'session.id'`` and then pick the multi-span root among the rows.
    """
    if root_span_id:
        flt = f"root_span_id = '{root_span_id}'"
    elif session_id:
        # metadata.session.id holds the Claude session uuid on every span.
        flt = f"metadata.\"session.id\" = '{session_id}'"
    else:
        raise BraintrustError("need a root_span_id or session_id to fetch a run")

    query = (
        f"select: * "
        f"| from: project_logs('{project_id}') "
        f"| filter: {flt} "
        f"| limit: 500"
    )
    return _btql(query, api_key=api_key)


def _resolve_root_span_id(
    *,
    project_id: str,
    api_key: str,
    run_or_session_id: str,
) -> str:
    """Map a 32-hex trace id OR a session uuid to the run's root_span_id.

    A 32-hex value is already the OTEL trace_id (== root_span_id). Anything else
    is treated as a Claude ``session.id``: we fetch that session's rows and pick
    the root_span_id of the multi-span tree (ignoring 1-span telemetry roots).
    """
    ident = (run_or_session_id or "").strip()
    if re.fullmatch(r"[0-9a-fA-F]{32}", ident):
        return ident  # already a trace_id / root_span_id

    # Treat as a session uuid: gather its rows, group by root_span_id, keep the
    # multi-span root.
    rows = _fetch_run_rows(project_id=project_id, api_key=api_key, session_id=ident)
    if not rows:
        raise BraintrustError(
            f"no spans found for run/session {ident!r} in project {project_id}"
        )
    counts: Dict[str, int] = {}
    for r in rows:
        rsid = r.get("root_span_id")
        if rsid:
            counts[rsid] = counts.get(rsid, 0) + 1
    real = {rsid: n for rsid, n in counts.items() if n >= MIN_REAL_ROOT_SPANS}
    if not real:
        # Fall back to the largest group even if small, but never a 1-span stray
        # if a bigger one exists.
        real = counts
    return max(real.items(), key=lambda kv: kv[1])[0]


def get_trace(
    run_or_session_id: str,
    *,
    project_id: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Load one finished run's spans.

    ``run_or_session_id`` may be the 32-hex OTEL trace id (root_span_id) OR the
    Claude ``session_id`` uuid; both resolve to the same multi-span run.

    Returns::

        {
          "root_span_id": "<32-hex trace id>",
          "root_span":   {"span_id", "session_id", "name", "metadata"},  # write target = span_id
          "tool_spans":  [
             {"span_id", "tool_use_id", "tool_name", "command", "file_path",
              "success": bool|None, "name"},
             ...
          ],
          "n_spans": <int>,
        }

    Per the spike, ``root_span.span_id`` and each ``tool_span.span_id`` (16-hex,
    == the row ``id``) are the addressable write targets. ``success`` is paired
    from the matching ``claude_code.tool.execution`` span by ``tool_use_id``.
    """
    api_key = api_key or get_api_key()
    project_id = project_id or resolve_project_id(api_key=api_key)

    root_span_id = _resolve_root_span_id(
        project_id=project_id, api_key=api_key, run_or_session_id=run_or_session_id
    )
    rows = _fetch_run_rows(
        project_id=project_id, api_key=api_key, root_span_id=root_span_id
    )
    if not rows:
        raise BraintrustError(
            f"no spans for root_span_id {root_span_id} in project {project_id}"
        )

    # Pass 1: index execution-span outcomes by tool_use_id.
    exec_success: Dict[str, Optional[bool]] = {}
    for r in rows:
        if _span_name(r) != EXEC_SPAN_NAME:
            continue
        m = _meta(r)
        tuid = _tool_use_id(m)
        if tuid is not None:
            succ = m.get("success")
            exec_success[tuid] = bool(succ) if isinstance(succ, bool) else None

    # Pass 2: build root + tool spans.
    root_span: Optional[dict] = None
    tool_spans: List[dict] = []
    session_id: Optional[str] = None

    for r in rows:
        name = _span_name(r)
        m = _meta(r)
        if session_id is None:
            session_id = m.get("session.id")

        if root_span is None and _is_root_row(r):
            root_span = {
                "span_id": r.get("id") or r.get("span_id"),
                "session_id": m.get("session.id"),
                "name": name,
                "metadata": m,
            }
            continue

        if name == TOOL_SPAN_NAME:
            tuid = _tool_use_id(m)
            tool_spans.append(
                {
                    "span_id": r.get("id") or r.get("span_id"),
                    "tool_use_id": tuid,
                    "tool_name": m.get("tool_name"),
                    "command": m.get("full_command"),  # present only for Bash
                    "file_path": m.get("file_path"),    # present only for Read/Write
                    "success": exec_success.get(tuid),
                    "name": name,
                }
            )

    if root_span is None:
        # Defensive: no row flagged is_root. Synthesize from the shared trace id
        # so the rollup still has a target (rare; should not happen on real runs).
        raise BraintrustError(
            f"no root (is_root / {ROOT_SPAN_NAME}) span found for "
            f"root_span_id {root_span_id}; cannot write rollup"
        )

    return {
        "root_span_id": root_span_id,
        "root_span": root_span,
        "tool_spans": tool_spans,
        "session_id": session_id,
        "n_spans": len(rows),
    }


# ---------------------------------------------------------------------------
# Write-back (insert + _is_merge). Deep-merges onto the ingested span.
# ---------------------------------------------------------------------------
def _merge_event(
    span_id: str,
    *,
    metadata: Optional[dict],
    tags: Optional[List[str]],
    scores: Optional[Dict[str, float]],
) -> dict:
    """Build one ``_is_merge`` event for the insert body. Validates scores."""
    if not span_id:
        raise BraintrustError("merge requires a non-empty span_id (== row id)")
    event: Dict[str, Any] = {"id": span_id, "_is_merge": True}
    if metadata:
        event["metadata"] = metadata
    if tags:
        event["tags"] = list(tags)
    if scores:
        clean: Dict[str, float] = {}
        for name, val in scores.items():
            try:
                num = float(val)
            except (TypeError, ValueError):
                raise BraintrustError(f"score {name!r} is not a number: {val!r}")
            if not (0.0 <= num <= 1.0):
                raise BraintrustError(
                    f"score {name!r}={num} out of range; Braintrust scores must be in [0,1]"
                )
            clean[name] = num
        event["scores"] = clean
    return event


def insert_events(
    events: List[dict],
    *,
    project_id: Optional[str] = None,
    api_key: Optional[str] = None,
) -> List[str]:
    """POST one or more merge events; return the echoed ``row_ids``.

    A single insert can carry many events, so the orchestrator batches all
    per-span merges plus the root merge into one round-trip when it wants to.
    """
    if not events:
        return []
    api_key = api_key or get_api_key()
    project_id = project_id or resolve_project_id(api_key=api_key)
    url = f"{API_HOST}/v1/project_logs/{project_id}/insert"
    resp = _request("POST", url, api_key=api_key, body={"events": events})
    if isinstance(resp, dict):
        return resp.get("row_ids", []) or []
    return []


def merge_span(
    span_id: str,
    *,
    metadata: Optional[dict] = None,
    tags: Optional[List[str]] = None,
    scores: Optional[Dict[str, float]] = None,
    project_id: Optional[str] = None,
    api_key: Optional[str] = None,
) -> List[str]:
    """Deep-merge labels onto ONE existing tool span (write target = its span_id).

    Mirrors the spike's working per-span merge. ``metadata`` deep-merges (does
    not clobber ``tool_name`` / ``full_command`` / ``tool_use_id``); ``tags``
    accumulate as a set; ``scores`` must be numbers in [0,1].
    """
    event = _merge_event(span_id, metadata=metadata, tags=tags, scores=scores)
    return insert_events([event], project_id=project_id, api_key=api_key)


def merge_root(
    root_span_id: str,
    *,
    metadata: Optional[dict] = None,
    scores: Optional[Dict[str, float]] = None,
    tags: Optional[List[str]] = None,
    project_id: Optional[str] = None,
    api_key: Optional[str] = None,
) -> List[str]:
    """Deep-merge the per-run rollup + scores onto the ROOT span.

    ``root_span_id`` here MUST be the root span's ``span_id`` (16-hex row id) —
    NOT the 32-hex OTEL trace id. ``get_trace(...)['root_span']['span_id']`` is
    the correct value to pass.
    """
    event = _merge_event(root_span_id, metadata=metadata, tags=tags, scores=scores)
    return insert_events([event], project_id=project_id, api_key=api_key)


def read_span(
    span_id: str,
    *,
    project_id: Optional[str] = None,
    api_key: Optional[str] = None,
    settle_seconds: float = 0.0,
) -> Optional[dict]:
    """Re-read one span (id, metadata, tags, scores) — used to verify a write.

    Pass ``settle_seconds`` (~4s in the spike) to wait for backend indexing after
    a merge before reading back.
    """
    api_key = api_key or get_api_key()
    project_id = project_id or resolve_project_id(api_key=api_key)
    if settle_seconds > 0:
        time.sleep(settle_seconds)
    query = (
        f"select: id, span_id, metadata, tags, scores "
        f"| from: project_logs('{project_id}') "
        f"| filter: span_id = '{span_id}' "
        f"| limit: 5"
    )
    rows = _btql(query, api_key=api_key)
    return rows[0] if rows else None


__all__ = [
    "API_HOST",
    "PROJECT_NAME",
    "DEFAULT_PROJECT_ID",
    "BraintrustError",
    "get_api_key",
    "key_from_settings_file",
    "resolve_project_id",
    "list_runs",
    "get_trace",
    "insert_events",
    "merge_span",
    "merge_root",
    "read_span",
]

#!/usr/bin/env python3
"""IOC -> tool provenance for Protocol SIFT trace enrichment.

For a *finished* investigation, this maps each IOC-shaped token the report
asserts back to the source that could have produced it:

* a specific tool's stdout (``"tool:<tool_use_id>"``) — the bash command whose
  output first surfaced the value, or
* the case **input** (``"case_input"``) — the JSON/file the agent ``Read``, or
* nothing (``source=None``) — absent from BOTH tool outputs and the input, which
  is the *only* condition that flags a **candidate fabrication**.

Why this matches the IOC scorer (``scoring/scorer.py``)
------------------------------------------------------
The scorer's fabrication penalty is: an IOC-shaped token asserted in the report
but absent from the **input** is a fabrication — restricted to the *clean*
kinds (email, hash, MAC, IPv4, SID). This module reuses the scorer's exact
extractors/normalisers, and adds the tool-stdout haystack to the provenance
search. The guardrail is identical to the scorer's semantics:

* An IOC present in ``case_input`` is **never** a candidate fabrication, even
  when no tool emitted it (the agent legitimately read it from the case file).
* CIDR base addresses (e.g. ``10.11.11.0`` from ``10.11.11.0/24``) are never
  extracted as host IPs, so they are never mis-flagged — inherited from the
  scorer's CIDR masking.
* Only the clean fabrication kinds are ever flagged; fuzzy kinds (path,
  hostname, username) are provenance-traced for the dashboard but, like the
  scorer, are never counted as fabrications.

Stdlib-only. No third-party deps (repo policy).
"""

from __future__ import annotations

import importlib.util
import os
import sys
from typing import Optional

# ---------------------------------------------------------------------------
# Import the deterministic scorer (scoring/scorer.py) WITHOUT assuming it is on
# sys.path. We never reimplement IOC regexes — every extractor/normaliser comes
# from scorer.py so provenance and the scorer agree token-for-token.
# ---------------------------------------------------------------------------
def _load_scorer():
    # Allow a plain ``import scorer`` if the caller already arranged the path.
    try:
        import scorer as _s  # type: ignore
        return _s
    except Exception:
        pass
    here = os.path.dirname(os.path.abspath(__file__))
    scorer_path = os.path.join(here, os.pardir, "scoring", "scorer.py")
    scorer_path = os.path.abspath(scorer_path)
    spec = importlib.util.spec_from_file_location("scorer", scorer_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load scorer from {scorer_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("scorer", mod)
    spec.loader.exec_module(mod)
    return mod


scorer = _load_scorer()

# The clean kinds (email, hash, mac, ipv4, sid) are the ones that have concrete,
# extractable, fabrication-eligible values. These are exactly the kinds the
# scorer treats as fabrication-eligible.
_FAB_KINDS = ("email", "hash", "mac", "ipv4", "sid")


# ---------------------------------------------------------------------------
# extract_iocs — delegate token extraction to scorer.py.
# ---------------------------------------------------------------------------
def extract_iocs(report_text: str) -> list[dict]:
    """Normalised, typed IOC tokens found in ``report_text``.

    Returns a de-duplicated, deterministically ordered list of
    ``{"kind": <clean-kind>, "value": <normalised token>}``. Extraction and
    normalisation are delegated entirely to ``scorer.extract_tokens`` so this
    matches the IOC scorer exactly (CIDR bases are already masked out of the
    ipv4 set by the scorer, so they never appear here).

    Only the *clean* fabrication kinds are returned: these are the kinds the
    scorer can extract as concrete values and the only ones eligible for the
    fabrication penalty. Fuzzy kinds (path/hostname/username) have no extractor
    in the scorer (they are presence-tested against a known value), so they are
    not enumerable here and are excluded — exactly as the scorer never
    fabrication-flags them.
    """
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for kind in _FAB_KINDS:
        for tok in sorted(scorer.extract_tokens(report_text, kind)):
            key = (kind, tok)
            if key in seen:
                continue
            seen.add(key)
            out.append({"kind": kind, "value": tok})
    return out


# ---------------------------------------------------------------------------
# build_source_index — per-source normalised token sets, keyed by clean kind.
# ---------------------------------------------------------------------------
def build_source_index(sources: list[str]) -> list[dict]:
    """Per-source searchable index of normalised IOC tokens.

    ``sources`` are raw text haystacks — the case INPUT text plus each tool's
    stdout. For each source we precompute, per clean kind, the normalised token
    set via ``scorer.extract_tokens`` so membership tests are O(1) and identical
    to the scorer's matching.

    Returns a list parallel to ``sources``; entry ``i`` is
    ``{"email": {...}, "hash": {...}, "mac": {...}, "ipv4": {...}, "sid": {...}}``.
    """
    index: list[dict] = []
    for text in sources:
        text = text or ""
        index.append({kind: scorer.extract_tokens(text, kind) for kind in _FAB_KINDS})
    return index


def _source_contains(source_idx: dict, kind: str, value: str) -> bool:
    """True if a pre-built source index entry contains the normalised token."""
    return value in source_idx.get(kind, frozenset())


# ---------------------------------------------------------------------------
# provenance — map each reported IOC to the source that could have produced it.
# ---------------------------------------------------------------------------
def provenance(
    report_text: str,
    tool_stdouts: dict,
    case_input_text: str,
) -> list[dict]:
    """Trace every reported IOC token to its source.

    Parameters
    ----------
    report_text:
        The investigation report (the haystack of asserted IOCs).
    tool_stdouts:
        ``{tool_use_id: stdout_text}`` from the raw-bash log. Iteration order is
        preserved (Python dicts are insertion-ordered) so "first match" is the
        first tool, in log order, whose stdout contains the value.
    case_input_text:
        The case file as the agent read it — produced by
        ``scorer.load_case_input_text(path)`` so it matches the scorer's
        "findable" haystack exactly.

    Returns
    -------
    One record per reported IOC token::

        {
          "ioc": "<normalised value>",
          "kind": "<email|hash|mac|ipv4|sid>",
          "source": "tool:<tool_use_id>" | "case_input" | None,
          "tool_sources": ["tool:<id>", ...],   # ALL tools whose stdout had it
          "in_case_input": bool,
          "candidate_fabrication": bool,         # True ONLY when source is None
        }

    Guardrail (mirrors the scorer's findable/fabrication semantics):
        An IOC found in ``case_input`` is NOT a candidate fabrication even when
        no tool emitted it. Only ``source is None`` — absent from BOTH every
        tool stdout AND the case input — sets ``candidate_fabrication=True``.
    """
    # Pre-index the case input plus each tool stdout. Keeping tool ids parallel
    # to their index entries lets us report first-match and all-matches cheaply.
    tool_ids = list(tool_stdouts.keys())
    tool_texts = [tool_stdouts[tid] for tid in tool_ids]
    tool_index = build_source_index(tool_texts)
    (case_index,) = build_source_index([case_input_text])

    records: list[dict] = []
    for ioc in extract_iocs(report_text):
        kind = ioc["kind"]
        value = ioc["value"]

        matched_tools: list[str] = []
        for tid, sidx in zip(tool_ids, tool_index):
            if _source_contains(sidx, kind, value):
                matched_tools.append(f"tool:{tid}")

        in_case_input = _source_contains(case_index, kind, value)

        if matched_tools:
            source: Optional[str] = matched_tools[0]  # first tool in log order
        elif in_case_input:
            source = "case_input"
        else:
            source = None

        records.append(
            {
                "ioc": value,
                "kind": kind,
                "source": source,
                "tool_sources": matched_tools,
                "in_case_input": in_case_input,
                # GUARDRAIL: only absence from BOTH tools and input is a flag.
                "candidate_fabrication": source is None,
            }
        )
    return records


# ---------------------------------------------------------------------------
# Convenience rollup — counts the enrichment dashboard wants.
# ---------------------------------------------------------------------------
def provenance_summary(records: list[dict]) -> dict:
    """Aggregate a ``provenance(...)`` result for a root-span rollup."""
    from_tool = sum(1 for r in records if str(r["source"] or "").startswith("tool:"))
    from_input = sum(1 for r in records if r["source"] == "case_input")
    fabrications = [
        {"kind": r["kind"], "value": r["ioc"]}
        for r in records
        if r["candidate_fabrication"]
    ]
    return {
        "iocs_total": len(records),
        "iocs_from_tool": from_tool,
        "iocs_from_case_input": from_input,
        "candidate_fabrications": fabrications,
        "candidate_fabrication_count": len(fabrications),
    }

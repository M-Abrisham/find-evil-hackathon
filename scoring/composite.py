"""Composite vector + KEEP/REVERT decision core (the shared compare()).

Pure stdlib, no I/O. Projects the scorer's 16-key aggregate (``scorer.aggregate()``)
onto the FOUR gated decision dimensions (each with a direction) plus carried advisory
fields, and decides KEEP vs REVERT.

DECISION CONTRACT (authoritative):
  GATED dims compare() acts on
    findable_recall_micro   UP    float|None (None iff findable_total==0); None => FAIL
    fabrication_count_total DOWN  int       (eps=0 exact; ANY increase => REVERT)
    verdicts_emitted        UP    int       (eps=0 exact)
    mitre_recall_micro      UP    float|None (None iff mitre_total==0); None => FAIL
  ADVISORY/ungated dims are carried but NEVER gate the decision.

  compare(baseline, post, *, eps_recall=0.0) -> (decision, reason, deltas):
    KEEP iff EVERY gated dim non-regresses AND >=1 gated dim STRICTLY improves;
    else REVERT. A tie / all-equal => REVERT.
    ints: eps=0 exact. float recalls:
      non-regress  = post >= base - eps_recall
      strict-improve = post  > base + eps_recall   (eps_recall default 0.0)
    A None on a GATED dim => that dim FAILS (conservative): it cannot non-regress
    and cannot strictly improve => forces REVERT.

This module does NOT import scorer for the pure math; the decision is computed entirely
from the aggregate dict. (scorer is FROZEN; do not add a composite scalar there.)
"""
from __future__ import annotations

from typing import Any

# direction: "up" = bigger is better; "down" = smaller is better.
GATED_DIMS: dict[str, str] = {
    "findable_recall_micro": "up",
    "fabrication_count_total": "down",
    "verdicts_emitted": "up",
    "mitre_recall_micro": "up",
}

# Recalls that may legitimately be None (iff their *_total is 0). A None on a gated
# dim still FAILS the gate (conservative); listed here only to document the semantics.
NULLABLE_RECALLS = frozenset({"findable_recall_micro", "mitre_recall_micro"})

# Carried for transparency / the ledger; never gates the decision.
ADVISORY_DIMS: tuple[str, ...] = (
    "mitre_precision_micro",
    "full_recall_micro",
    "findable_found",
    "findable_total",
    "full_found",
    "full_total",
    "mitre_found",
    "mitre_total",
    "mitre_grounded_total",
    "mitre_emitted_total",
    "invalid_mitre_total",
    "cases",
)


def composite_vector(agg: dict[str, Any]) -> dict[str, Any]:
    """Project a 16-key ``scorer.aggregate()`` dict onto the gated + advisory view.

    Returns a NEW dict (does not mutate ``agg``):
      {"gated": {dim: {"value": v, "direction": "up"|"down"}, ...},
       "advisory": {dim: value, ...}}

    Pure: no I/O, no scorer call. Missing keys carry through as None.
    """
    gated = {
        dim: {"value": agg.get(dim), "direction": direction}
        for dim, direction in GATED_DIMS.items()
    }
    advisory = {dim: agg.get(dim) for dim in ADVISORY_DIMS}
    return {"gated": gated, "advisory": advisory}


def _classify(dim, direction, base, post, eps_recall):
    """Classify one gated dim. Returns (status, delta) where status is one of
    "improve" | "regress" | "equal" | "fail" and delta is post-base (or None if a
    side is None / non-numeric)."""
    is_float = dim in NULLABLE_RECALLS
    # A None on a gated dim FAILS (conservative): cannot non-regress, cannot improve.
    if base is None or post is None:
        delta = None
        if base is not None and post is not None:
            delta = post - base
        return "fail", delta

    delta = post - base

    if is_float:
        if direction == "up":
            if post > base + eps_recall:
                return "improve", delta
            if post >= base - eps_recall:
                return "equal", delta
            return "regress", delta
        else:  # down (not used for floats today; kept for completeness)
            if post < base - eps_recall:
                return "improve", delta
            if post <= base + eps_recall:
                return "equal", delta
            return "regress", delta

    # integer dims: exact, eps=0.
    if direction == "up":
        if post > base:
            return "improve", delta
        if post == base:
            return "equal", delta
        return "regress", delta
    else:  # down: smaller is better (fabrications)
        if post < base:
            return "improve", delta
        if post == base:
            return "equal", delta
        return "regress", delta


def compare(baseline, post, *, eps_recall=0.0):
    """KEEP/REVERT over the four gated dims. See module docstring for the contract.

    Returns (decision, reason, deltas):
      decision : "KEEP" | "REVERT"
      reason   : human-readable rationale
      deltas   : {dim: {"base":, "post":, "delta":, "direction":, "status":}, ...}
                 for every gated dim, where status in improve|regress|equal|fail.
    """
    deltas: dict[str, Any] = {}
    statuses: dict[str, str] = {}
    for dim, direction in GATED_DIMS.items():
        base = baseline.get(dim)
        pv = post.get(dim)
        status, delta = _classify(dim, direction, base, pv, eps_recall)
        statuses[dim] = status
        deltas[dim] = {
            "base": base,
            "post": pv,
            "delta": delta,
            "direction": direction,
            "status": status,
        }

    fails = [d for d, s in statuses.items() if s == "fail"]
    regress = [d for d, s in statuses.items() if s == "regress"]
    improves = [d for d, s in statuses.items() if s == "improve"]

    if fails:
        reason = (
            "REVERT: gated dim(s) FAIL (None/undefined => conservative fail): "
            + ", ".join(sorted(fails))
        )
        return "REVERT", reason, deltas
    if regress:
        parts = []
        for d in sorted(regress):
            dd = deltas[d]
            parts.append(f"{d} {dd['base']}->{dd['post']} ({dd['direction']})")
        reason = "REVERT: gated regression on " + "; ".join(parts)
        return "REVERT", reason, deltas
    if not improves:
        reason = "REVERT: no gated dim strictly improved (tie / all-equal)"
        return "REVERT", reason, deltas

    parts = []
    for d in sorted(improves):
        dd = deltas[d]
        parts.append(f"{d} {dd['base']}->{dd['post']}")
    reason = (
        "KEEP: all gated dims non-regress and "
        f"{len(improves)} strictly improved: " + "; ".join(parts)
    )
    return "KEEP", reason, deltas

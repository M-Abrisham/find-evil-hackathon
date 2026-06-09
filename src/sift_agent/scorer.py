"""Finding scorer — the two-stage verifier.

The agent never presents a claim as fact on the strength of fluent prose. Every
:class:`~sift_agent.finding.Finding` passes two stages:

**Stage 1 — literal-receipt match (the HARD gate).** Every
``extracted_literals`` entry must appear *verbatim* in the cited evidence span
(the receipt's byte-range output). This is non-negotiable: it is the gate that
decides whether a finding may be presented as fact. See
:func:`literal_receipt_gate`.

**Stage 2 — the OVER-REACH gate (a SIGNAL, not a verdict).** Even when the
literals are present, the *prose* can claim more than the evidence supports
("Amcache lists winrar.exe" → "winrar.exe was executed"). Stage 2 scores
whether the claim **follows from** the cited evidence using Vectara
HHEM-2.1-Open (:mod:`sift_agent.over_reach`) as the **entailment axis**. A low
score does not reject the finding and cannot override stage 1 — it can only
**downgrade** the finding to ``inferred``, **flag it for the Skeptic**, and
record it to ``corrections.jsonl`` for follow-up.

Entailment axis: HHEM primary, LLM-judge fallback
-------------------------------------------------
HHEM **replaces** the old LLM-judge entailment as the primary axis: it is fixed,
offline, deterministic, and cheap. The LLM judge is kept ONLY as a fallback for
when HHEM is unavailable (deps missing / weights not cached). When neither is
available we record **no** entailment signal and never fabricate one — the
stage-1 hard gate alone governs.
"""

from __future__ import annotations

import fcntl
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Sequence

from sift_agent import over_reach
from sift_agent.finding import Finding, Status
from sift_agent.over_reach import HHEMUnavailable


def _canonical_json(obj: Any) -> str:
    """Canonical JSON line for corrections.jsonl.

    Mirrors the ledger's serialization discipline (sorted keys, compact
    separators, ASCII-only, no ``NaN``/``Infinity``) so corrections lines are
    deterministic — kept local so the scorer carries no cross-module dependency.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )

__all__ = [
    "EntailmentResult",
    "OverReachGateResult",
    "LiteralGateResult",
    "LLMJudge",
    "DEFAULT_CORRECTIONS_PATH",
    "default_corrections_path",
    "premise_from_receipt",
    "literal_receipt_gate",
    "claim_sentence",
    "score_entailment",
    "apply_over_reach_gate",
]

#: An LLM-judge entailment fallback: ``(premise, hypothesis) -> float`` in
#: ``[0, 1]``. Injected, so the scorer stays decoupled from any LLM client. In
#: production this is backed by ``sift_agent.telemetry.call_claude`` (tokens +
#: cost + audit all flow through the ledger); in tests it is a stub.
LLMJudge = Callable[[str, str], float]


def _repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


#: Where over-reach flags are queued for the Skeptic. Holds case data → it is
#: git-ignored and written under ``analysis/`` (never committed). Overridable
#: via ``SIFT_CORRECTIONS_PATH``.
DEFAULT_CORRECTIONS_PATH = os.path.join(_repo_root(), "analysis", "corrections.jsonl")


def default_corrections_path() -> str:
    """The configured corrections.jsonl path (re-read from env each call)."""
    return os.environ.get("SIFT_CORRECTIONS_PATH") or DEFAULT_CORRECTIONS_PATH


def _utc_now_iso() -> str:
    """UTC, ISO-8601 with a ``Z`` suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# =============================================================================
# Stage 1 — the literal-receipt match (HARD gate).
# =============================================================================
def premise_from_receipt(
    output: str | bytes, byte_range: Sequence[int] | None = None
) -> str:
    """The cited evidence span: a receipt's captured output, sliced by bytes.

    ``byte_range`` is ``[start, end]`` BYTE offsets into the receipt's captured
    output (the same semantics as ``ProvenanceRef.byte_range``); ``None`` means
    the whole output. The result is the premise handed to both stages.
    """
    data = output.encode("utf-8") if isinstance(output, str) else output
    if byte_range is None:
        chunk = data
    else:
        start, end = int(byte_range[0]), int(byte_range[1])
        chunk = data[start:end]
    return chunk.decode("utf-8", errors="replace")


@dataclass
class LiteralGateResult:
    """Outcome of stage 1. ``passed`` is the hard go/no-go."""

    passed: bool
    missing: list[str]
    premise: str


def literal_receipt_gate(
    literals: Iterable[str], premise: str
) -> LiteralGateResult:
    """HARD gate: every literal must appear verbatim in the cited evidence span.

    A finding whose literals are not all present in ``premise`` has no receipt
    backing and must not be presented as fact, regardless of any HHEM score.
    """
    missing = [lit for lit in literals if lit not in premise]
    return LiteralGateResult(passed=not missing, missing=missing, premise=premise)


# =============================================================================
# Stage 2 — the over-reach gate (entailment SIGNAL).
# =============================================================================
def claim_sentence(claim: str) -> str:
    """The hypothesis scored against the evidence — the finding's claim sentence.

    Defaults to the first sentence of ``claim`` (claims are usually a single
    sentence); callers may pass a specific sentence to
    :func:`apply_over_reach_gate` to override.
    """
    text = claim.strip()
    for sep in (". ", ".\n", "? ", "! "):
        idx = text.find(sep)
        if idx != -1:
            return text[: idx + 1].strip()
    return text


@dataclass
class EntailmentResult:
    """The entailment axis for one (premise, hypothesis).

    ``source`` is ``"hhem"`` (primary), ``"llm_fallback"``, or ``"unavailable"``
    (no signal — never fabricated). ``score`` is ``None`` only when
    ``source == "unavailable"``. ``over_reach`` is ``score < threshold`` (always
    ``False`` when there is no signal).
    """

    source: str
    score: float | None
    threshold: float
    over_reach: bool
    premise: str
    hypothesis: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        # score/threshold serialized as fixed-decimal STRINGS (no floats), to
        # match this repo's hash-stable serialization discipline.
        return {
            "source": self.source,
            "score": None if self.score is None else f"{self.score:.4f}",
            "threshold": f"{self.threshold:.2f}",
            "over_reach": self.over_reach,
            "premise": self.premise,
            "hypothesis": self.hypothesis,
            "detail": self.detail,
        }


def score_entailment(
    premise: str,
    hypothesis: str,
    *,
    threshold: float | None = None,
    llm_judge: LLMJudge | None = None,
) -> EntailmentResult:
    """Score the entailment axis: HHEM primary, LLM-judge fallback, else none.

    ``premise``    — the cited evidence span (receipt byte-range output).
    ``hypothesis`` — the finding's claim sentence.
    Never fabricates a score: if HHEM is unavailable and no ``llm_judge`` is
    supplied, returns ``source="unavailable"`` / ``score=None``.
    """
    if not isinstance(premise, str) or not premise.strip():
        raise ValueError("premise must be a non-empty string")
    if not isinstance(hypothesis, str) or not hypothesis.strip():
        raise ValueError("hypothesis must be a non-empty string")
    thr = over_reach.default_threshold() if threshold is None else float(threshold)

    # --- primary axis: HHEM-2.1 (fixed, offline, deterministic) -------------
    if over_reach.hhem_available():
        try:
            s = over_reach.over_reach_score(premise, hypothesis)
            return EntailmentResult(
                source="hhem",
                score=s,
                threshold=thr,
                over_reach=s < thr,
                premise=premise,
                hypothesis=hypothesis,
                detail=over_reach.model_info(),
            )
        except HHEMUnavailable:
            pass  # fall through to the fallback path, honestly

    # --- fallback axis: LLM judge (ONLY when HHEM is unavailable) ------------
    if llm_judge is not None:
        s = min(1.0, max(0.0, float(llm_judge(premise, hypothesis))))
        return EntailmentResult(
            source="llm_fallback",
            score=s,
            threshold=thr,
            over_reach=s < thr,
            premise=premise,
            hypothesis=hypothesis,
            detail={"note": "HHEM unavailable; LLM-judge entailment fallback"},
        )

    # --- no signal: never fabricated; the stage-1 hard gate alone governs ----
    return EntailmentResult(
        source="unavailable",
        score=None,
        threshold=thr,
        over_reach=False,
        premise=premise,
        hypothesis=hypothesis,
        detail={"note": "HHEM unavailable and no LLM-judge provided; no signal"},
    )


@dataclass
class OverReachGateResult:
    """What the over-reach gate did to one finding."""

    finding_id: str
    entailment: EntailmentResult
    original_status: str
    new_status: str
    downgraded: bool
    flagged_for_skeptic: bool
    correction_written: bool
    note: str


# Statuses the gate may act on. It only ever *downgrades* toward ``inferred`` —
# never upgrades, never rejects (rejection is the Skeptic's call, informed by
# the corrections queue).
_ACTIONABLE = (Status.confirmed, Status.inferred)


def apply_over_reach_gate(
    finding: Finding,
    premise: str,
    *,
    hypothesis: str | None = None,
    threshold: float | None = None,
    corrections_path: str | None = None,
    llm_judge: LLMJudge | None = None,
    write_corrections: bool = True,
    now: str | None = None,
) -> OverReachGateResult:
    """Run stage 2 on ``finding`` and apply the over-reach policy.

    ``premise`` is the cited evidence span (the receipt's byte-range output).
    ``hypothesis`` defaults to ``finding``'s claim sentence. On over-reach
    (entailment ``< threshold``) for a ``confirmed``/``inferred`` finding the
    gate, in place:

    * downgrades ``confirmed`` → ``inferred`` (``inferred`` stays ``inferred``);
    * appends a ``[SKEPTIC]`` verifier note;
    * writes one line to ``corrections.jsonl`` — the Skeptic's durable queue.

    It NEVER rejects, NEVER upgrades, and NEVER overrides the stage-1 literal
    hard gate. Returns an :class:`OverReachGateResult`; ``finding`` is mutated
    only when a downgrade/flag occurs.
    """
    hyp = hypothesis if hypothesis is not None else claim_sentence(finding.claim)
    ent = score_entailment(premise, hyp, threshold=threshold, llm_judge=llm_judge)

    original_status = finding.status.value
    downgraded = False
    flagged = False
    wrote = False

    if ent.over_reach and finding.status in _ACTIONABLE:
        if finding.status is Status.confirmed:
            finding.status = Status.inferred
            downgraded = True
        flagged = True
        score_txt = "n/a" if ent.score is None else f"{ent.score:.3f}"
        note = (
            f"[OVER-REACH][SKEPTIC] HHEM-2.1 {ent.source} entailment {score_txt} "
            f"< threshold {ent.threshold:.2f}: claim may over-reach its cited "
            f"evidence. Downgraded to inferred; referred to Skeptic. "
            f"(Literal-receipt match remains the hard gate.)"
        )
        _append_verifier_note(finding, note)
        if write_corrections:
            wrote = _write_correction(
                corrections_path, finding, ent, original_status, now=now
            )
    else:
        if ent.source == "unavailable":
            note = (
                "over-reach gate: no entailment signal (HHEM unavailable, no LLM "
                "fallback); stage-1 literal hard gate governs."
            )
        else:
            score_txt = "n/a" if ent.score is None else f"{ent.score:.3f}"
            note = (
                f"over-reach gate: HHEM-2.1 {ent.source} entailment {score_txt} "
                f">= threshold {ent.threshold:.2f}; claim supported by evidence."
            )

    return OverReachGateResult(
        finding_id=finding.id,
        entailment=ent,
        original_status=original_status,
        new_status=finding.status.value,
        downgraded=downgraded,
        flagged_for_skeptic=flagged,
        correction_written=wrote,
        note=note,
    )


# =============================================================================
# Side-effects: verifier-note append + corrections.jsonl (the Skeptic's queue).
# =============================================================================
def _append_verifier_note(finding: Finding, note: str) -> None:
    """Append ``note`` to ``finding.verifier_notes`` (newline-joined)."""
    if finding.verifier_notes:
        finding.verifier_notes = f"{finding.verifier_notes}\n{note}"
    else:
        finding.verifier_notes = note


def _write_correction(
    corrections_path: str | None,
    finding: Finding,
    ent: EntailmentResult,
    original_status: str,
    *,
    now: str | None = None,
) -> bool:
    """Append one canonical JSON line to corrections.jsonl (the Skeptic queue)."""
    path = corrections_path or default_corrections_path()
    record = {
        "schema_version": "corrections-v1",
        "kind": "over_reach_flag",
        "ts_utc": now or _utc_now_iso(),
        "finding_id": finding.id,
        "claim": finding.claim,
        "entailment_axis": "hhem_over_reach",
        "original_status": original_status,
        "new_status": finding.status.value,
        "action": "downgraded_to_inferred; flagged_for_skeptic",
        "provenance_receipt_ids": [ref.receipt_id for ref in finding.provenance],
        "entailment": ent.to_dict(),
        "note": (
            "literal-receipt match remains the hard gate; this over-reach signal "
            "only downgrades + flags for the Skeptic, it never rejects"
        ),
    }
    _append_jsonl(path, _canonical_json(record))
    return True


def _append_jsonl(path: str, line: str) -> None:
    """Durably append one line (flock-serialized, fsync'd) — mirrors the ledger."""
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(fd, (line + "\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)

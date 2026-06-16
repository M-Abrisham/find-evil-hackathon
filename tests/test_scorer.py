"""Tests for the two-stage verifier scorer.

Unit tests force HHEM "unavailable" (via monkeypatch) so the entailment-axis
logic and the over-reach policy are exercised deterministically with a stub
LLM-judge — no model needed. Integration tests gated on the real cached model
confirm the end-to-end wiring (a forensic over-reach actually downgrades).
"""

import json

import pytest

from sift_agent import over_reach, scorer
from sift_agent.finding import EvidenceType, Finding, ProvenanceRef, Status


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------
def _ref(receipt_id="r1", artifact="C:/amcache.hve", tool="AmcacheParser"):
    return ProvenanceRef(
        receipt_id=receipt_id, tool=tool, artifact_path=artifact,
        locator="key=Root\\InventoryApplicationFile", byte_range=[0, 64],
    )


def _inferred_finding():
    return Finding(
        claim="winrar.exe is present in Amcache.",
        status=Status.inferred,
        confidence="0.60",
        evidence_type=EvidenceType.disk,
        provenance=[_ref()],
        extracted_literals=["winrar.exe"],
    )


def _confirmed_finding():
    return Finding(
        claim="winrar.exe was executed.",
        status=Status.confirmed,
        confidence="0.90",
        evidence_type=EvidenceType.disk,
        provenance=[
            _ref(receipt_id="r1", artifact="C:/amcache.hve", tool="AmcacheParser"),
            _ref(receipt_id="r2", artifact="C:/prefetch", tool="PECmd"),
        ],
        extracted_literals=["winrar.exe"],
    )


@pytest.fixture
def hhem_off(monkeypatch):
    """Force the HHEM axis unavailable so unit tests use the fallback path."""
    monkeypatch.setattr(over_reach, "hhem_available", lambda: False)


# ---------------------------------------------------------------------------
# Stage 1 — literal-receipt match (the HARD gate)
# ---------------------------------------------------------------------------
def test_premise_from_receipt_byte_range():
    out = "ABCDEFGHIJ"
    assert scorer.premise_from_receipt(out, [2, 5]) == "CDE"
    assert scorer.premise_from_receipt(out, None) == out


def test_literal_gate_pass_and_fail():
    premise = "Amcache lists winrar.exe at C:/Program Files/WinRAR/winrar.exe"
    ok = scorer.literal_receipt_gate(["winrar.exe", "WinRAR"], premise)
    assert ok.passed and ok.missing == []
    bad = scorer.literal_receipt_gate(["winrar.exe", "nc.exe"], premise)
    assert not bad.passed and bad.missing == ["nc.exe"]


def test_claim_sentence_first_sentence_only():
    assert scorer.claim_sentence("winrar.exe was executed. Then it ran.") == \
        "winrar.exe was executed."
    assert scorer.claim_sentence("single clause") == "single clause"


# ---------------------------------------------------------------------------
# Stage 2 — entailment axis selection (HHEM primary, LLM fallback, else none)
# ---------------------------------------------------------------------------
def test_entailment_falls_back_to_llm_when_hhem_unavailable(hhem_off):
    res = scorer.score_entailment("premise text", "hypothesis text",
                                  threshold=0.5, llm_judge=lambda p, h: 0.2)
    assert res.source == "llm_fallback"
    assert res.score == pytest.approx(0.2)
    assert res.over_reach is True


def test_entailment_unavailable_without_judge_is_not_fabricated(hhem_off):
    res = scorer.score_entailment("premise text", "hypothesis text", threshold=0.5)
    assert res.source == "unavailable"
    assert res.score is None
    assert res.over_reach is False  # no signal -> never acts


def test_entailment_rejects_empty(hhem_off):
    with pytest.raises(ValueError):
        scorer.score_entailment("", "h")


def test_llm_score_is_clamped(hhem_off):
    hi = scorer.score_entailment("p", "h", llm_judge=lambda p, h: 5.0)
    lo = scorer.score_entailment("p", "h", llm_judge=lambda p, h: -3.0)
    assert hi.score == 1.0 and lo.score == 0.0


# ---------------------------------------------------------------------------
# Stage 2 — the over-reach POLICY (downgrade + Skeptic flag + corrections.jsonl)
# ---------------------------------------------------------------------------
def test_overreach_downgrades_confirmed_to_inferred(hhem_off, tmp_path):
    f = _confirmed_finding()
    corr = tmp_path / "corrections.jsonl"
    res = scorer.apply_over_reach_gate(
        f, "Amcache lists winrar.exe (presence only)",
        threshold=0.5, corrections_path=str(corr),
        llm_judge=lambda p, h: 0.12,  # low -> over-reach
    )
    assert res.downgraded is True
    assert res.flagged_for_skeptic is True
    assert res.original_status == "confirmed"
    assert res.new_status == "inferred"
    assert f.status is Status.inferred
    assert "[SKEPTIC]" in (f.verifier_notes or "")
    # finding is still structurally valid after the in-place downgrade
    f.validate()
    # a correction line was queued for the Skeptic
    assert res.correction_written is True
    lines = corr.read_text().strip().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["kind"] == "over_reach_flag"
    assert rec["finding_id"] == f.id
    assert rec["original_status"] == "confirmed"
    assert rec["new_status"] == "inferred"
    assert rec["entailment"]["source"] == "llm_fallback"
    assert rec["entailment"]["score"] == "0.1200"
    assert rec["provenance_receipt_ids"] == ["r1", "r2"]


def test_supported_claim_is_untouched(hhem_off, tmp_path):
    f = _confirmed_finding()
    corr = tmp_path / "corrections.jsonl"
    res = scorer.apply_over_reach_gate(
        f, "premise", threshold=0.5, corrections_path=str(corr),
        llm_judge=lambda p, h: 0.97,  # high -> supported
    )
    assert res.downgraded is False
    assert res.flagged_for_skeptic is False
    assert res.correction_written is False
    assert f.status is Status.confirmed  # untouched
    assert not corr.exists()  # nothing queued


def test_inferred_overreach_stays_inferred_but_flagged(hhem_off, tmp_path):
    f = _inferred_finding()
    corr = tmp_path / "corrections.jsonl"
    res = scorer.apply_over_reach_gate(
        f, "premise", threshold=0.5, corrections_path=str(corr),
        llm_judge=lambda p, h: 0.05,
    )
    assert res.downgraded is False        # already at the inferred floor
    assert res.flagged_for_skeptic is True
    assert res.correction_written is True
    assert f.status is Status.inferred


def test_rejected_finding_not_acted_on(hhem_off, tmp_path):
    f = _inferred_finding()
    f.status = Status.insufficient_evidence
    corr = tmp_path / "corrections.jsonl"
    res = scorer.apply_over_reach_gate(
        f, "premise", threshold=0.5, corrections_path=str(corr),
        llm_judge=lambda p, h: 0.01,
    )
    assert res.downgraded is False
    assert res.flagged_for_skeptic is False
    assert f.status is Status.insufficient_evidence


def test_no_signal_does_not_downgrade(hhem_off, tmp_path):
    # HHEM unavailable AND no LLM judge -> no entailment signal -> no action.
    f = _confirmed_finding()
    corr = tmp_path / "corrections.jsonl"
    res = scorer.apply_over_reach_gate(
        f, "premise", threshold=0.5, corrections_path=str(corr)
    )
    assert res.entailment.source == "unavailable"
    assert res.downgraded is False
    assert res.flagged_for_skeptic is False
    assert f.status is Status.confirmed


def test_write_corrections_false_suppresses_file(hhem_off, tmp_path):
    f = _confirmed_finding()
    corr = tmp_path / "corrections.jsonl"
    res = scorer.apply_over_reach_gate(
        f, "premise", threshold=0.5, corrections_path=str(corr),
        llm_judge=lambda p, h: 0.0, write_corrections=False,
    )
    assert res.flagged_for_skeptic is True
    assert res.correction_written is False
    assert not corr.exists()


# ---------------------------------------------------------------------------
# Integration — real, pinned, offline HHEM drives the gate end-to-end
# ---------------------------------------------------------------------------
requires_hhem = pytest.mark.skipif(
    not over_reach.hhem_available(),
    reason="HHEM weights not cached offline (run scripts/fetch_hhem.py)",
)


@requires_hhem
def test_real_hhem_flags_c2_overreach(tmp_path):
    f = _confirmed_finding()
    f.claim = "Therefore this registry value establishes C2 persistence."
    corr = tmp_path / "corrections.jsonl"
    res = scorer.apply_over_reach_gate(
        f,
        "Registry HKLM\\...\\Run Value: OneDriveSetup Data: OneDriveSetup.exe",
        threshold=0.5, corrections_path=str(corr),
    )
    assert res.entailment.source == "hhem"
    assert res.entailment.over_reach is True
    assert res.new_status == "inferred"
    assert corr.exists()


@requires_hhem
def test_real_hhem_passes_supported_presence(tmp_path):
    f = _inferred_finding()  # "winrar.exe is present in Amcache."
    corr = tmp_path / "corrections.jsonl"
    res = scorer.apply_over_reach_gate(
        f,
        "Amcache.hve InventoryApplicationFile Name: winrar.exe FullPath: "
        "C:\\Program Files\\WinRAR\\winrar.exe",
        threshold=0.5, corrections_path=str(corr),
    )
    assert res.entailment.source == "hhem"
    assert res.entailment.over_reach is False
    assert res.flagged_for_skeptic is False
    assert not corr.exists()

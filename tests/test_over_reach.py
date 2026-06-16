"""Tests for the HHEM-2.1 over-reach signal (verifier stage 2).

Two layers:

* Unit tests that need NO model (input validation, availability probe, config).
* Integration tests gated on ``over_reach.hhem_available()`` — they load the
  pinned, offline-cached HHEM model and assert it (a) reproduces the model
  card's reference score and (b) separates supported vs over-reach on forensic
  prose for the *factual/lexical* cases, while DOCUMENTING the known
  out-of-distribution case (Amcache presence vs execution).
"""

import os

import pytest

from sift_agent import over_reach

requires_hhem = pytest.mark.skipif(
    not over_reach.hhem_available(),
    reason="HHEM weights not cached offline (run scripts/fetch_hhem.py)",
)


# --- unit (no model) ---------------------------------------------------------
def test_pinned_identity_is_recorded():
    assert over_reach.HHEM_REPO == "vectara/hallucination_evaluation_model"
    # full 40-hex commit pin (also recorded in docs/contribution-table.md)
    assert len(over_reach.HHEM_REVISION) == 40
    assert set(over_reach.REMOTE_CODE_SHA256) == {
        "configuration_hhem_v2.py",
        "modeling_hhem_v2.py",
        "config.json",
    }


def test_default_threshold_env_override(monkeypatch):
    monkeypatch.setenv("SIFT_OVER_REACH_THRESHOLD", "0.73")
    assert over_reach.default_threshold() == pytest.approx(0.73)


def test_empty_inputs_rejected(monkeypatch):
    # Force the "available" branch off so we never touch the model here; the
    # validation must happen BEFORE any load attempt.
    monkeypatch.setattr(over_reach, "_load_model", lambda: pytest.fail("loaded"))
    with pytest.raises(ValueError):
        over_reach.over_reach_score("", "winrar.exe is present")
    with pytest.raises(ValueError):
        over_reach.over_reach_score("Amcache lists winrar.exe", "   ")


def test_empty_batch_returns_empty():
    assert over_reach.over_reach_scores([]) == []


def test_model_info_shape():
    info = over_reach.model_info()
    assert info["repo"] == over_reach.HHEM_REPO
    assert info["revision"] == over_reach.HHEM_REVISION
    assert info["offline"] is True
    assert "cache_dir" in info


# --- integration (pinned, offline model) ------------------------------------
@requires_hhem
def test_reproduces_model_card_reference_score():
    # The model card's canonical example: factual but hallucinated -> ~0.011.
    s = over_reach.over_reach_score(
        "The capital of France is Berlin.", "The capital of France is Paris."
    )
    assert s == pytest.approx(0.0111, abs=0.01)


@requires_hhem
def test_runs_fully_offline():
    # Loading must not require the network; the module forces offline env.
    over_reach.warm_up()
    assert os.environ.get("HF_HUB_OFFLINE") == "1"
    assert os.environ.get("TRANSFORMERS_OFFLINE") == "1"


AMCACHE = (
    "Amcache.hve  InventoryApplicationFile  Name: winrar.exe  "
    "FullPath: C:\\Program Files\\WinRAR\\winrar.exe  "
    "SHA1: 1a2b3c4d5e6f7081a2b3c4d5e6f7081a2b3c4d5e  LinkDate: 2019-02-13 11:04:33"
)
REG_RUN = (
    "Registry  HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run  "
    "Value: OneDriveSetup  Data: C:\\Windows\\System32\\OneDriveSetup.exe /thfirstsetup"
)


@requires_hhem
def test_supported_presence_scores_high():
    assert over_reach.over_reach_score(AMCACHE, "winrar.exe is present in Amcache.") >= 0.5


@requires_hhem
def test_factual_overreach_scores_low():
    # A wild conclusion the cited registry value does not support.
    c2 = over_reach.over_reach_score(
        REG_RUN, "Therefore this registry value establishes C2 persistence."
    )
    # A path that contradicts the cited Amcache FullPath.
    path_lie = over_reach.over_reach_score(
        AMCACHE, "winrar.exe was installed in C:\\Temp\\malware."
    )
    assert c2 < 0.5
    assert path_lie < 0.5


@requires_hhem
def test_known_ood_presence_vs_execution_does_not_separate():
    """DOCUMENTED out-of-distribution limitation (see docs/contribution-table.md).

    HHEM is general-domain: it does NOT know the forensic rule that an Amcache
    InventoryApplicationFile row proves *presence/installation*, not execution.
    So "winrar.exe was executed" scores ~ as high as the genuinely-supported
    "winrar.exe is present", i.e. the over-reach gate alone CANNOT catch this
    class — the literal hard gate + LLM-judge fallback must. This test pins that
    reality; if a future model revision fixes it, this test will flag the change
    so we can re-tune.
    """
    presence = over_reach.over_reach_score(AMCACHE, "winrar.exe is present in Amcache.")
    execution = over_reach.over_reach_score(AMCACHE, "winrar.exe was executed.")
    # Execution is NOT meaningfully separated below presence -> no threshold in
    # the supported band can tell them apart.
    assert execution >= 0.5
    assert execution > presence - 0.3

"""Over-reach gate — verifier **stage 2**: the Vectara HHEM-2.1-Open signal.

What this is
------------
A *fixed, offline* classifier that scores whether a finding's prose actually
**follows from** its cited evidence. It is a **SIGNAL** that feeds the scorer's
entailment axis — it is **NOT a verdict**. The literal-receipt match (verifier
stage 1, see :mod:`sift_agent.scorer`) remains the hard gate that decides
whether a finding may be presented as fact; this stage can only *flag* and
*downgrade*, never confirm and never reject.

The real HHEM-2.1-Open API (quoted from the model card)
-------------------------------------------------------
``vectara/hallucination_evaluation_model`` exposes a custom ``predict`` method::

    from transformers import AutoModelForSequenceClassification
    model = AutoModelForSequenceClassification.from_pretrained(
        'vectara/hallucination_evaluation_model', trust_remote_code=True)
    pairs = [("The capital of France is Berlin.", "The capital of France is Paris.")]
    model.predict(pairs)   # note: predict(), NOT model(pairs)
    # tensor([0.0111])     # one score per (premise, hypothesis) pair

The model card states: the input is a list of ``(premise, hypothesis)`` pairs and
the output is "a score between 0 and 1 for each pair where 0 means that the
hypothesis is not evidenced at all by the premise and 1 means the hypothesis is
fully supported by the premise." That is exactly our :func:`over_reach_score`
contract: ``premise`` = the cited evidence span (a receipt's byte-range output),
``hypothesis`` = the finding's claim sentence; ``~1`` = supported, ``~0`` =
over-reach.

Air-gapped + pinned (forensic box: no network at inference)
-----------------------------------------------------------
The weights are fetched **once** by ``scripts/fetch_hhem.py`` into a repo-local,
git-ignored Hugging Face cache (``models/hf-cache/``). Every load here forces
``HF_HUB_OFFLINE`` / ``TRANSFORMERS_OFFLINE`` and pins the **exact commit
revision** :data:`HHEM_REVISION`. Inference never reaches the network.

trust_remote_code — reviewed and content-pinned
------------------------------------------------
HHEM loads with ``trust_remote_code=True``, i.e. it executes two Python files
shipped in the model repo (``configuration_hhem_v2.py`` /
``modeling_hhem_v2.py``). We reviewed both at the pinned revision: they import
only ``torch`` + ``transformers``, build a ``T5ForTokenClassification`` from
``google/flan-t5-base``'s config, load the repo's ``model.safetensors``, and
return ``softmax(logits)[:, 1]`` = P(consistent). There is **no** filesystem,
subprocess, ``eval``/``exec``, network, or pickle code. To guarantee we only
ever execute *that* reviewed code, :func:`_verify_remote_code` checks the
SHA-256 of those files (:data:`REMOTE_CODE_SHA256`) before the model is loaded
and refuses to run on any mismatch.

One dependency side-effect: the remote code does
``AutoConfig/AutoTokenizer.from_pretrained("google/flan-t5-base")`` at load, so
``google/flan-t5-base``'s **config + tokenizer** are cached alongside HHEM (the
fetch script handles this) — the flan-t5-base *weights* are never used.
"""

from __future__ import annotations

import hashlib
import os
import threading
from typing import Any, Iterable

__all__ = [
    "HHEM_REPO",
    "HHEM_REVISION",
    "FLAN_REPO",
    "FLAN_REVISION",
    "REMOTE_CODE_SHA256",
    "WEIGHTS_SHA256",
    "DEFAULT_THRESHOLD",
    "HHEMUnavailable",
    "HHEMIntegrityError",
    "cache_dir",
    "hhem_available",
    "default_threshold",
    "over_reach_score",
    "over_reach_scores",
    "model_info",
    "warm_up",
]

# =============================================================================
# Pinned identity — also recorded in docs/contribution-table.md.
# =============================================================================
HHEM_REPO = "vectara/hallucination_evaluation_model"
#: Exact commit revision of HHEM-2.1-Open we pin (main @ 2025-10-20). Override
#: only with a revision you have re-reviewed (``SIFT_HHEM_REVISION``).
HHEM_REVISION = os.getenv(
    "SIFT_HHEM_REVISION", "8e4a2e6e96c708cc76c2344f7e4757df2515292c"
)

FLAN_REPO = "google/flan-t5-base"
#: HHEM's foundation; we cache its config + tokenizer only (not its weights).
FLAN_REVISION = "7bcac572ce56db69c1ea7c8af255c5d7c9672fc2"

#: SHA-256 of the EXACT reviewed files we permit ``trust_remote_code`` to run
#: (plus config.json). Enforced by :func:`_verify_remote_code` before load.
REMOTE_CODE_SHA256 = {
    "configuration_hhem_v2.py": (
        "ec57fe344e3104d0d4a99b13d893529aac1e2bd69e83c2814235baf37cdcacc7"
    ),
    "modeling_hhem_v2.py": (
        "fcc9cfcee513cc08eb46eac21f1acb498b122572fb35a7dec4d85fae45cb9bba"
    ),
    "config.json": (
        "773139fe764fe20e146ab14e627b188ccafae35f93cf6f5258dc6c237016b870"
    ),
}

#: SHA-256 of the pinned ``model.safetensors`` (custody; verified at fetch time).
WEIGHTS_SHA256 = "634de18a38cf1e991c1acd0f7a9e0d30f7ea187fba42bb4798f862d3edd31e72"

#: Default over-reach threshold: P(consistent) below this is treated as
#: over-reach. CONFIGURABLE via ``SIFT_OVER_REACH_THRESHOLD`` (tuned Day 5).
#: 0.5 is the model's natural consistent/hallucinated decision boundary.
DEFAULT_THRESHOLD = float(os.getenv("SIFT_OVER_REACH_THRESHOLD", "0.5"))


class HHEMUnavailable(RuntimeError):
    """HHEM cannot be loaded (deps missing or weights not cached offline).

    Callers treat this as "no HHEM signal" and fall back to the LLM-judge
    entailment axis — they never fabricate a score.
    """


class HHEMIntegrityError(HHEMUnavailable):
    """A cached HHEM file does not match its pinned SHA-256 — refuse to load.

    A subclass of :class:`HHEMUnavailable` so a tampered/changed cache degrades
    to the fallback path rather than silently executing unreviewed remote code.
    """


# =============================================================================
# Cache location + offline guarantee.
# =============================================================================
def _repo_root() -> str:
    """Repo root: this file is ``<repo>/src/sift_agent/over_reach.py``."""
    return os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )


def cache_dir() -> str:
    """Repo-local, git-ignored HF cache (override with ``SIFT_HHEM_HOME``)."""
    return os.environ.get("SIFT_HHEM_HOME") or os.path.join(
        _repo_root(), "models", "hf-cache"
    )


def _force_offline_env(cache: str) -> None:
    """Pin the HF cache and FORCE offline — a forensic tool never phones home.

    ``HF_HUB_CACHE`` must point at ``cache`` because the remote code's internal
    ``from_pretrained("google/flan-t5-base")`` does not receive our ``cache_dir``
    kwarg and would otherwise look in the default ``~/.cache`` location.
    """
    os.environ.setdefault("HF_HOME", cache)
    os.environ["HF_HUB_CACHE"] = cache
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    # Tokenizers fork-safety + quiet: deterministic, no parallelism surprises.
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")


def _snapshot_dir(cache: str) -> str:
    """Path of the pinned HHEM snapshot inside the HF cache."""
    repo_dir = "models--" + HHEM_REPO.replace("/", "--")
    return os.path.join(cache, repo_dir, "snapshots", HHEM_REVISION)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _verify_remote_code(snapshot: str) -> None:
    """Refuse to load unless the trust_remote_code matches the reviewed pin."""
    for fname, expected in REMOTE_CODE_SHA256.items():
        path = os.path.join(snapshot, fname)
        if not os.path.isfile(path):
            raise HHEMUnavailable(
                f"HHEM file {fname!r} not present in cache at {snapshot!r}; "
                "run scripts/fetch_hhem.py once (online) to populate the cache"
            )
        actual = _sha256_file(path)
        if actual != expected:
            raise HHEMIntegrityError(
                f"HHEM {fname!r} SHA-256 {actual} != reviewed pin {expected}; "
                "refusing to execute unreviewed remote code"
            )


# =============================================================================
# Lazy, thread-safe model singleton. torch/transformers imported ONLY on use.
# =============================================================================
_lock = threading.Lock()
_model: Any | None = None


def hhem_available() -> bool:
    """True iff HHEM can load offline (deps importable AND weights cached).

    Never raises and never loads the model — a cheap probe the scorer uses to
    decide between the HHEM axis and the LLM-judge fallback.
    """
    try:
        import importlib.util

        if (
            importlib.util.find_spec("torch") is None
            or importlib.util.find_spec("transformers") is None
        ):
            return False
        snap = _snapshot_dir(cache_dir())
        needed = ("config.json", "modeling_hhem_v2.py", "model.safetensors")
        return all(os.path.exists(os.path.join(snap, f)) for f in needed)
    except Exception:
        return False


def default_threshold() -> float:
    """The configured default over-reach threshold (re-read from env each call)."""
    return float(os.getenv("SIFT_OVER_REACH_THRESHOLD", str(DEFAULT_THRESHOLD)))


def _load_model() -> Any:
    """Load (once) the pinned HHEM model from the offline cache.

    Raises :class:`HHEMUnavailable` (or :class:`HHEMIntegrityError`) if the deps
    are missing, the weights are not cached, or the remote code fails its
    SHA-256 check.
    """
    global _model
    if _model is not None:
        return _model
    with _lock:
        if _model is not None:
            return _model

        cache = cache_dir()
        _force_offline_env(cache)
        snap = _snapshot_dir(cache)
        if not os.path.isfile(os.path.join(snap, "config.json")):
            raise HHEMUnavailable(
                f"HHEM not cached at {snap!r}; run scripts/fetch_hhem.py once "
                "(online) to populate the offline cache"
            )
        # Security gate: only execute the exact reviewed trust_remote_code.
        _verify_remote_code(snap)

        try:
            import torch  # noqa: F401  (ensures the backend is importable)
            from transformers import AutoModelForSequenceClassification
        except Exception as exc:  # noqa: BLE001 — degrade to fallback, honestly
            raise HHEMUnavailable(f"torch/transformers unavailable: {exc!r}") from exc

        try:
            model = AutoModelForSequenceClassification.from_pretrained(
                HHEM_REPO,
                revision=HHEM_REVISION,
                trust_remote_code=True,
                cache_dir=cache,
                local_files_only=True,
            )
        except Exception as exc:  # noqa: BLE001
            raise HHEMUnavailable(f"failed to load HHEM offline: {exc!r}") from exc

        _model = model
        return _model


def warm_up() -> None:
    """Eagerly load the model (e.g. at agent startup). Raises if unavailable."""
    _load_model()


# =============================================================================
# The signal.
# =============================================================================
def _coerce_pair(premise: Any, hypothesis: Any) -> tuple[str, str]:
    if not isinstance(premise, str) or not premise.strip():
        raise ValueError("premise (cited evidence span) must be a non-empty string")
    if not isinstance(hypothesis, str) or not hypothesis.strip():
        raise ValueError("hypothesis (claim sentence) must be a non-empty string")
    return premise, hypothesis


def over_reach_scores(pairs: Iterable[tuple[str, str]]) -> list[float]:
    """Batch over-reach scores for ``(premise, hypothesis)`` pairs.

    Returns one float in ``[0, 1]`` per pair (``~1`` supported, ``~0`` over-reach),
    using HHEM's real :meth:`predict`. Raises :class:`HHEMUnavailable` if HHEM
    cannot be loaded offline; raises :class:`ValueError` on an empty/non-string
    premise or hypothesis.
    """
    pair_list = [_coerce_pair(p, h) for (p, h) in pairs]
    if not pair_list:
        return []
    model = _load_model()
    raw = model.predict(pair_list)  # the model card's documented entry point
    # Clamp into [0, 1] defensively (softmax probs already are, but be strict).
    return [min(1.0, max(0.0, float(x))) for x in raw]


def over_reach_score(premise: str, hypothesis: str) -> float:
    """Over-reach score for a single ``(premise, hypothesis)``.

    ``premise``    — the cited evidence span (the receipt's byte-range output).
    ``hypothesis`` — the finding's claim sentence.
    Returns a float in ``[0, 1]``: ``~1`` the claim is supported by the evidence,
    ``~0`` the claim over-reaches (does not follow from the evidence).
    """
    return over_reach_scores([(premise, hypothesis)])[0]


def model_info() -> dict[str, Any]:
    """Provenance of the signal — recorded by the scorer on every decision."""
    return {
        "model": "HHEM-2.1-Open",
        "repo": HHEM_REPO,
        "revision": HHEM_REVISION,
        "foundation": FLAN_REPO,
        "foundation_revision": FLAN_REVISION,
        "cache_dir": cache_dir(),
        "offline": True,
        "default_threshold": default_threshold(),
        "available": hhem_available(),
    }

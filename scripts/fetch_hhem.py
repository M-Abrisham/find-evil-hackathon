#!/usr/bin/env python3
"""One-time, ONLINE fetch of the HHEM-2.1-Open over-reach classifier.

Air-gapped-forensic-box contract
--------------------------------
This is the ONLY step that touches the network. It downloads Vectara's
HHEM-2.1-Open (``vectara/hallucination_evaluation_model``) — the fixed, offline
entailment classifier used by the over-reach gate — into a **repo-local,
git-ignored** Hugging Face cache so that every subsequent inference runs with
``HF_HUB_OFFLINE=1`` and never reaches out again.

What it pulls (both PINNED by exact commit revision — see
``docs/contribution-table.md``):

* ``vectara/hallucination_evaluation_model`` @ ``HHEM_REVISION`` — the custom
  code (``configuration_hhem_v2.py`` / ``modeling_hhem_v2.py``, loaded under
  ``trust_remote_code`` — reviewed before pinning), ``config.json`` and the
  ``model.safetensors`` weights (~418 MB). The ``candle.png`` memorial image is
  skipped.
* ``google/flan-t5-base`` @ ``FLAN_REVISION`` — **config + tokenizer ONLY**.
  HHEM's ``__init__`` does ``AutoConfig.from_pretrained("google/flan-t5-base")``
  and ``AutoTokenizer.from_pretrained("google/flan-t5-base")``, so those files
  must be in the same offline cache. The flan-t5-base *weights* are deliberately
  NOT fetched: HHEM ships its own fine-tuned ``model.safetensors`` that is loaded
  over the (config-constructed) T5, so the base weights are never used.

After download the SHA-256 of ``model.safetensors`` is verified against the
value published in the HHEM repo's blob metadata — a custody check that the
weights we cache are exactly the reviewed, pinned ones.

Usage::

    python3 scripts/fetch_hhem.py                 # fetch into ./models/hf-cache
    SIFT_HHEM_HOME=/some/cache python3 scripts/fetch_hhem.py

Re-running is cheap: ``snapshot_download`` is content-addressed and skips files
already present.
"""
from __future__ import annotations

import hashlib
import os
import sys

# --- PINNED revisions (also recorded in docs/contribution-table.md) ----------
HHEM_REPO = "vectara/hallucination_evaluation_model"
HHEM_REVISION = "8e4a2e6e96c708cc76c2344f7e4757df2515292c"  # main @ 2025-10-20
# Expected SHA-256 of model.safetensors at the pinned HHEM revision (custody
# check). From the HHEM repo blob metadata (lfs.sha256).
HHEM_SAFETENSORS_SHA256 = (
    "634de18a38cf1e991c1acd0f7a9e0d30f7ea187fba42bb4798f862d3edd31e72"
)

FLAN_REPO = "google/flan-t5-base"
FLAN_REVISION = "7bcac572ce56db69c1ea7c8af255c5d7c9672fc2"
# config + tokenizer only — NOT the base weights (HHEM supplies its own).
FLAN_ALLOW = [
    "config.json",
    "generation_config.json",
    "tokenizer.json",
    "tokenizer_config.json",
    "special_tokens_map.json",
    "spiece.model",
]


def _default_cache() -> str:
    """Repo-local, git-ignored HF cache: ``<repo>/models/hf-cache``."""
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(repo, "models", "hf-cache")


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main() -> int:
    cache = os.environ.get("SIFT_HHEM_HOME") or _default_cache()
    # Point the HF cache at our repo-local dir for THIS download process.
    os.environ["HF_HOME"] = cache
    os.makedirs(cache, exist_ok=True)

    # Imported here (after HF_HOME is set) so the cache location takes effect.
    from huggingface_hub import snapshot_download

    print(f"[fetch_hhem] HF cache  : {cache}")
    print(f"[fetch_hhem] HHEM repo : {HHEM_REPO}@{HHEM_REVISION}")
    hhem_dir = snapshot_download(
        repo_id=HHEM_REPO,
        revision=HHEM_REVISION,
        cache_dir=cache,
        ignore_patterns=["*.png"],  # the candle memorial image — not needed
    )
    print(f"[fetch_hhem] HHEM cached -> {hhem_dir}")

    print(f"[fetch_hhem] base repo : {FLAN_REPO}@{FLAN_REVISION} (config+tokenizer only)")
    flan_dir = snapshot_download(
        repo_id=FLAN_REPO,
        revision=FLAN_REVISION,
        cache_dir=cache,
        allow_patterns=FLAN_ALLOW,
    )
    print(f"[fetch_hhem] base cached -> {flan_dir}")

    # --- custody check: weights are exactly the reviewed, pinned ones --------
    weights = os.path.join(hhem_dir, "model.safetensors")
    if not os.path.isfile(weights):
        print(f"[fetch_hhem] ERROR: missing weights at {weights}", file=sys.stderr)
        return 2
    digest = _sha256(weights)
    if digest != HHEM_SAFETENSORS_SHA256:
        print(
            "[fetch_hhem] ERROR: model.safetensors SHA-256 mismatch\n"
            f"  expected {HHEM_SAFETENSORS_SHA256}\n  actual   {digest}",
            file=sys.stderr,
        )
        return 3
    print(f"[fetch_hhem] model.safetensors SHA-256 OK ({digest})")
    print("[fetch_hhem] done — inference can now run fully offline "
          "(HF_HUB_OFFLINE=1).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

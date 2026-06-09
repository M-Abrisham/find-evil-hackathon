# SIFT "Find Evil" agent

A forensic LLM/tool agent for the SANS SIFT workstation. Every assertion is a
court-vetted **evidence card** ([`Finding`](src/sift_agent/finding.py)) backed by
a hash-chained, tamper-evident provenance [`ledger`](src/sift_agent/ledger.py),
with token/cost [`telemetry`](src/sift_agent/telemetry.py) on every LLM/tool row.

## Verifier — two stages

A finding is never presented as fact on fluent prose alone:

1. **Stage 1 — literal-receipt match (HARD gate).** Every `extracted_literals`
   entry must appear *verbatim* in the cited evidence span (a receipt's
   byte-range output). See [`scorer.literal_receipt_gate`](src/sift_agent/scorer.py).
2. **Stage 2 — the over-reach gate (a SIGNAL, not a verdict).** Vectara
   **HHEM-2.1-Open** scores whether the claim actually *follows from* its cited
   evidence ([`over_reach.over_reach_score`](src/sift_agent/over_reach.py)). It is
   the scorer's **entailment axis** (it *replaced* the LLM-judge entailment; the
   LLM judge is kept only as a fallback when HHEM is unavailable). A low score
   **downgrades** the finding `confirmed → inferred`, **flags it for the
   Skeptic**, and appends a line to `corrections.jsonl`. It never rejects, never
   upgrades, and never overrides the stage-1 hard gate.

The real HHEM API used (quoted from the model card):

```python
from transformers import AutoModelForSequenceClassification
model = AutoModelForSequenceClassification.from_pretrained(
    'vectara/hallucination_evaluation_model', trust_remote_code=True)
model.predict([(premise, hypothesis)])   # -> tensor of scores in [0,1]
# ~1 = hypothesis supported by premise; ~0 = over-reach
```

## Try It Out

This is an **air-gapped** forensic box: the model is fetched **once** (the only
networked step) into a git-ignored local cache, then all inference runs offline.

```bash
# 0) Deps. CPU-only torch keeps it small (no CUDA). Both run on numpy 1.24.4.
pip install --index-url https://download.pytorch.org/whl/cpu torch==2.4.1
pip install transformers==4.44.2 safetensors sentencepiece protobuf \
    huggingface_hub==0.25.2

# 1) Fetch HHEM-2.1 ONCE (pinned by revision) into ./models/ (git-ignored, ~418 MB).
#    Verifies the weights' SHA-256. This is the ONLY step that touches the network.
python3 scripts/fetch_hhem.py

# 2) Prove it works on forensic prose (runs fully offline).
python3 scripts/sanity_check_hhem.py

# 3) Tests (unit + integration against the cached model).
python3 -m pytest tests/ -q
```

After step 1, set nothing else: [`over_reach.py`](src/sift_agent/over_reach.py)
forces `HF_HUB_OFFLINE=1` / `TRANSFORMERS_OFFLINE=1` and pins the exact model
revision on every load — inference never reaches the network.

### What is / isn't committed

| Artifact | Committed? | Where |
|----------|-----------|-------|
| Code (`over_reach.py`, `scorer.py`, fetch + sanity scripts, tests) | ✅ yes | this repo |
| Model **weights** (~418 MB) | ❌ never | `models/` (git-ignored) — reproduce with `scripts/fetch_hhem.py` |
| `corrections.jsonl` (Skeptic queue; case data) | ❌ never | git-ignored, written per-case |
| Pinned revisions + `trust_remote_code` review + SHA-256s | ✅ yes | [`docs/contribution-table.md`](docs/contribution-table.md) |

### Security: `trust_remote_code`

HHEM loads with `trust_remote_code=True`. We reviewed the two Python files it
ships at the pinned revision (they only build a T5 classifier and softmax — no
filesystem/subprocess/eval/network/pickle) and **content-pin their SHA-256**:
`over_reach.py` refuses to load if the cached files don't match the reviewed
hashes. See the security review in
[`docs/contribution-table.md`](docs/contribution-table.md).

### Configuration

| Env var | Default | Meaning |
|---------|---------|---------|
| `SIFT_OVER_REACH_THRESHOLD` | `0.5` | Over-reach threshold (tuned Day 5). `score < threshold` ⇒ downgrade + flag. |
| `SIFT_HHEM_HOME` | `./models/hf-cache` | Offline HF cache location. |
| `SIFT_HHEM_REVISION` | `8e4a2e6e…` | HHEM commit revision (override only with a re-reviewed one). |
| `SIFT_CORRECTIONS_PATH` | `./analysis/corrections.jsonl` | Skeptic queue path. |

### Known limitation (honest, out-of-distribution)

HHEM is general RAG-domain. It cleanly catches *factual/lexical* over-reach (a
contradicted path → 0.03; an unsupported "C2 persistence" leap → 0.13) but does
**not** catch the forensic-semantic over-reach "Amcache ⇒ executed" ("was
executed" scores ~0.86, above genuinely-supported claims — no threshold
separates it). That is why the **literal hard gate stays primary** and the
**LLM-judge fallback is retained**; HHEM is advisory only. Details + the
sanity-check table are in [`docs/contribution-table.md`](docs/contribution-table.md).

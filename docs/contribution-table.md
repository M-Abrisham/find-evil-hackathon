# Contribution / Provenance Table

Tracks what we **reused** (external IP, pinned — never vendored into our tree) vs.
what is **novel** to this repo.

## Telemetry — LLM/tool ledger (Component #8: tokens + timestamp on every row)

| Item | Reused (provenance) | Novel (our work) |
|------|--------------------|------------------|
| Cost / token accounting | **Na0S** `na0s.judge.cost_tracker.CostTracker` — `record(model, input_tokens, output_tokens)`, `get_total_cost()`, `get_breakdown()`, `set_budget()`, `is_over_budget()`, `reset()` | We register current **Claude pricing rows** into Na0S's `_COST_TABLE` at import via `setdefault` (it ships only OpenAI/Llama rows + a `$0.50/$1.00` default), and derive **per-agent-turn** token attribution from `get_breakdown()`. |
| Audit trail | **Na0S** `na0s.judge.audit.JudgeAuditLogger` — `log_invocation(input_hash, verdict, confidence, reasoning, model, latency_ms, error="")`, gated by `NA0S_JUDGE_AUDIT=1` | We map each Claude call onto its judge-shaped fields. Because that record carries **no token counts**, we also emit our own JSON **ledger line** (tokens + UTC ts) per row. |
| Rate limiting | **Na0S** `na0s.judge.rate_limiter.TokenBucketRateLimiter` — `TokenBucketRateLimiter(rate=10.0, burst=20)`, `try_acquire()`, `acquire(timeout=5.0)` | Applied as a pre-call gate inside `call_claude(...)`. |
| Forensic integration | — | **`src/sift_agent/telemetry.py`** — thin, backward-compatible wrapper: `call_claude()` (rate-limit → invoke → record tokens/cost/UTC-ts per LLM call) and `stamp_receipt(receipt)` (stamp a TOOL row with UTC ts + the **issuing agent turn's** tokens, explicitly labelled — a tool spends no LLM tokens, so we never fabricate a per-tool count). |

### Pin

- **Reused:** Na0S `judge.cost_tracker` / `judge.audit` / `judge.rate_limiter`
  **@ `a8751167db7b67fcbdacdc1196cfc0a140929b94`**
  (`github.com/M-Abrisham/Na0S`, branch `main`, tag = none — pinned by commit).
- **Install:** `pip install -e ./Na0S` (editable, from the SHA checkout) on this box;
  reproducible pin in [`requirements.txt`](../requirements.txt) as
  `na0s @ git+https://github.com/M-Abrisham/Na0S@a8751167db7b67fcbdacdc1196cfc0a140929b94`.
- **Not vendored:** no Na0S `.py` files are copied into this repo. We import the
  pinned package and only *add* rows to its pricing table at runtime.

### Pricing source (Claude rows we added)

Current Claude model ids + USD per 1M tokens (claude-api catalog, cached 2026-05-26,
confirmed 2026-06-08). Configured model id is read from `SIFT_CLAUDE_MODEL`
(default `claude-opus-4-8`) — no stale id is hardcoded.

| Model id | input $/1M | output $/1M |
|----------|-----------:|------------:|
| `claude-opus-4-8` (configured) | 5.00 | 25.00 |
| `claude-opus-4-7` | 5.00 | 25.00 |
| `claude-opus-4-6` | 5.00 | 25.00 |
| `claude-sonnet-4-6` | 3.00 | 15.00 |
| `claude-haiku-4-5` | 1.00 | 5.00 |

## Over-reach gate — verifier **stage 2** (Vectara HHEM-2.1-Open entailment signal)

A fixed, offline classifier that scores whether a finding's prose actually
**follows from** its cited evidence. It is the scorer's **entailment axis** — a
SIGNAL, not a verdict. The literal-receipt match (stage 1) stays the hard gate.

| Item | Reused (provenance) | Novel (our work) |
|------|--------------------|------------------|
| Entailment classifier | **Vectara HHEM-2.1-Open** — `vectara/hallucination_evaluation_model`. Real API (quoted from the model card): `AutoModelForSequenceClassification.from_pretrained(..., trust_remote_code=True)` then **`model.predict([(premise, hypothesis), …])`** → a tensor of scores in `[0,1]`, "0 means the hypothesis is not evidenced at all by the premise and 1 means the hypothesis is fully supported." 0.1 B params, T5-base backbone, ~600 MB RAM, CPU. | **`src/sift_agent/over_reach.py`** — `over_reach_score(premise, hypothesis) -> float[0,1]` (premise = receipt byte-range output; hypothesis = claim sentence). Forces `HF_HUB_OFFLINE`/`TRANSFORMERS_OFFLINE`, pins the exact revision, and **content-pins the `trust_remote_code`** (refuses to load if the two `.py` files' SHA-256 ≠ the reviewed values). Lazy, thread-safe singleton. |
| Scorer integration | — | **`src/sift_agent/scorer.py`** — HHEM **replaces** the LLM-judge entailment as the primary axis; the LLM judge is kept ONLY as a fallback when HHEM is unavailable (and we never fabricate a score otherwise). On over-reach (`score < threshold`) it downgrades `confirmed → inferred`, appends a `[SKEPTIC]` note, and writes one line to `corrections.jsonl` (the Skeptic's durable queue). Stage-1 literal match stays the hard gate; the gate never rejects/upgrades. |
| One-time fetch | — | **`scripts/fetch_hhem.py`** — the ONLY networked step; caches HHEM + flan-t5-base config/tokenizer into the git-ignored `models/hf-cache/`, verifies the weights' SHA-256. |

### Pin (HHEM over-reach gate)

- **Reused:** `vectara/hallucination_evaluation_model`
  **@ `8e4a2e6e96c708cc76c2344f7e4757df2515292c`** (HF `main` @ 2025-10-20), license Apache-2.0.
- **Foundation (config + tokenizer only, weights NOT used):** `google/flan-t5-base`
  **@ `7bcac572ce56db69c1ea7c8af255c5d7c9672fc2`**.
- **Weights custody:** `model.safetensors` SHA-256
  `634de18a38cf1e991c1acd0f7a9e0d30f7ea187fba42bb4798f862d3edd31e72` (verified at fetch).
- **`trust_remote_code` content pins** (only these are ever executed):
  - `configuration_hhem_v2.py` → `ec57fe344e3104d0d4a99b13d893529aac1e2bd69e83c2814235baf37cdcacc7`
  - `modeling_hhem_v2.py` → `fcc9cfcee513cc08eb46eac21f1acb498b122572fb35a7dec4d85fae45cb9bba`
  - `config.json` → `773139fe764fe20e146ab14e627b188ccafae35f93cf6f5258dc6c237016b870`
- **Not vendored / not committed:** the ~418 MB weights live in `models/` (git-ignored).
  Reproduce with `python3 scripts/fetch_hhem.py` (see README "Try It Out").

### `trust_remote_code` security review (at the pinned revision)

HHEM loads two repo-shipped Python files. Reviewed both: they import only
`torch` + `transformers`, build a `T5ForTokenClassification` from
`google/flan-t5-base`'s config, load the repo's `model.safetensors`, and return
`softmax(logits)[:, 1]` = P(consistent). **No** filesystem, subprocess,
`eval`/`exec`, network, socket, or pickle code. `over_reach.py` enforces the
SHA-256 of these files before each load, so only the reviewed code can run. One
benign side-effect: load fetches `google/flan-t5-base`'s **config + tokenizer**
(cached offline alongside HHEM).

### Sanity-check on FORENSIC prose (run `python3 scripts/sanity_check_hhem.py`)

`predict()` scores, threshold 0.50 (`~1` supported, `~0` over-reach):

| case | premise → hypothesis | score | expect | verdict |
|------|----------------------|------:|--------|---------|
| supported (presence) | Amcache row → "winrar.exe is present in Amcache" | **0.907** | HIGH | ✅ |
| **over-reach (execution)** | same Amcache row → "winrar.exe was executed" | **0.862** | LOW | ❌ **miss** |
| baseline (C2 leap) | Run-key value → "…establishes C2 persistence" | **0.134** | LOW | ✅ |
| supported (installed) | Amcache row → "recorded in the application inventory" | 0.840 | HIGH | ✅ |
| supported (run value) | Run-key value → "Run key value … points to OneDriveSetup.exe" | 0.709 | HIGH | ✅ |
| over-reach (path lie) | Amcache row → "installed in C:\\Temp\\malware" | 0.027 | LOW | ✅ |

**Finding (honest, out-of-distribution caveat).** HHEM separates *factual /
lexical* over-reach cleanly (a contradicted path → 0.027; an unsupported C2
conclusion → 0.134). But it **does NOT** catch the domain-semantic over-reach
"Amcache ⇒ executed": "was executed" scores **0.862**, *above* two
genuinely-supported claims (0.709 / 0.840), so **no single threshold separates
it** — this is a real OOD limitation, not a calibration issue (HHEM is general
RAG-domain and does not know Amcache `InventoryApplicationFile` proves
presence/installation, not execution).

**Recommendation (implemented).** Keep the **literal-receipt match as the hard
gate** and **retain the LLM-judge entailment fallback**; HHEM is wired as an
advisory SIGNAL (downgrade + Skeptic flag only, never a verdict). Default
threshold `0.50` is **configurable** via `SIFT_OVER_REACH_THRESHOLD` and will be
**tuned Day 5**. `test_over_reach.py` pins both the working separation and the
OOD case, so a future revision that fixes presence-vs-execution will flag the
test for re-tuning.

### Dependency note (numpy pin vs HHEM)

HHEM needs `torch` + `transformers`. Resolved with the existing
`numpy<1.25` pin **kept**: installed `torch==2.4.1+cpu` (declares no numpy bound)
and `transformers==4.44.2` (needs only `numpy>=1.17`), both import and run on
`numpy==1.24.4`; `na0s` requires `>=1.24,<3`. `pip check` is clean and all
telemetry tests still pass — no version relaxation and no separate venv needed.

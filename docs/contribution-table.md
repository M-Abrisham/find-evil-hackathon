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

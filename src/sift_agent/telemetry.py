"""Forensic telemetry — a thin wrapper over the Na0S ``judge`` primitives.

Goal (Component #8): EVERY Claude (LLM) call AND every tool-execution row in our
ledger must carry **token usage + a UTC timestamp**.

REUSED (pinned dependency ``na0s`` — NOT vendored; see docs/contribution-table.md)
--------------------------------------------------------------------------------
* ``na0s.judge.cost_tracker.CostTracker``            — token + USD accounting
    record(model, input_tokens, output_tokens) -> None
    get_total_cost() -> float ; get_breakdown() -> dict
    set_budget(max_usd) -> None ; is_over_budget() -> bool ; reset() -> None
* ``na0s.judge.audit.JudgeAuditLogger``              — append-only JSONL audit
    log_invocation(input_hash, verdict, confidence, reasoning,
                   model, latency_ms, error="") -> None   (gated by NA0S_JUDGE_AUDIT=1)
* ``na0s.judge.rate_limiter.TokenBucketRateLimiter`` — call throttling
    TokenBucketRateLimiter(rate=10.0, burst=20)
    try_acquire() -> bool ; acquire(timeout=5.0) -> bool

NOVEL (our forensic integration)
--------------------------------
* register current Claude pricing into Na0S's ``_COST_TABLE`` without forking it
  (the dependency ships only OpenAI/Llama rows + a $0.50/$1.00 default fallback);
* per-agent-turn token attribution derived *from* ``CostTracker`` itself;
* one ledger log line per LLM call AND per tool row, each carrying tokens +
  a UTC ISO-8601 timestamp;
* :func:`stamp_receipt` — stamp a TOOL row with the tokens of the agent turn that
  ISSUED the call. A forensic tool (vol, MFTECmd, fls) spends **no** LLM tokens of
  its own, so the row records the issuing turn's tokens, explicitly labelled —
  never a fabricated per-tool count.

The wrapper is additive and backward-compatible: it imports Na0S, never patches
its behaviour, and only *adds* rows to the pricing table.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

# --- Reused Na0S judge primitives (pinned dependency) ------------------------
from na0s.judge.cost_tracker import CostTracker
from na0s.judge.audit import JudgeAuditLogger
from na0s.judge.rate_limiter import TokenBucketRateLimiter
from na0s.judge import cost_tracker as _cost_tracker_mod  # for the _COST_TABLE hook

__all__ = [
    "CONFIGURED_MODEL",
    "COST",
    "AUDIT",
    "RATE",
    "begin_turn",
    "current_turn_usage",
    "call_claude",
    "record_call",
    "stamp_receipt",
    "register_claude_pricing",
]

# -----------------------------------------------------------------------------
# Configured model id.
#
# This is the model the SIFT agent actually runs as (Claude Opus 4.8, 1M ctx).
# Read it from here / the SIFT_CLAUDE_MODEL env var — do NOT hardcode a model id
# anywhere else, and do NOT pin a stale one.
# -----------------------------------------------------------------------------
CONFIGURED_MODEL = os.getenv("SIFT_CLAUDE_MODEL", "claude-opus-4-8")

# Current Claude pricing, USD per 1,000,000 tokens.
# Source: claude-api model catalog (cached 2026-05-26), confirmed 2026-06-08.
# Same units as Na0S's cost_tracker._COST_TABLE.
_CLAUDE_PRICING: dict[str, dict[str, float]] = {
    "claude-opus-4-8":   {"input": 5.00, "output": 25.00},
    "claude-opus-4-7":   {"input": 5.00, "output": 25.00},
    "claude-opus-4-6":   {"input": 5.00, "output": 25.00},
    "claude-sonnet-4-6": {"input": 3.00, "output": 15.00},
    "claude-haiku-4-5":  {"input": 1.00, "output": 5.00},
}


def register_claude_pricing() -> None:
    """Inject current Claude rows into Na0S's cost table (idempotent).

    ``cost_tracker._COST_TABLE`` is the only pricing hook the dependency exposes.
    We ``setdefault`` so we add Claude rows without overriding anything Na0S
    ships and without editing/vendoring its source — the pin stays clean.
    Without this, Opus tokens fall back to Na0S's $0.50/$1.00 default and are
    mis-costed.
    """
    for model, rates in _CLAUDE_PRICING.items():
        _cost_tracker_mod._COST_TABLE.setdefault(model, dict(rates))


register_claude_pricing()

# -----------------------------------------------------------------------------
# Process-wide singletons. The agent shares one of each.
# -----------------------------------------------------------------------------
COST = CostTracker()
AUDIT = JudgeAuditLogger()
RATE = TokenBucketRateLimiter(
    rate=float(os.getenv("SIFT_LLM_RATE", "5")),
    burst=int(os.getenv("SIFT_LLM_BURST", "10")),
)

# Dedicated ledger logger. Library default = NullHandler; the host app (or the
# test) attaches a handler. Every emitted line is a JSON object.
logger = logging.getLogger("sift.telemetry")
logger.addHandler(logging.NullHandler())


def _utc_now_iso() -> str:
    """UTC, ISO-8601, e.g. ``2026-06-08T21:40:03.123456+00:00``."""
    return datetime.now(timezone.utc).isoformat()


# -----------------------------------------------------------------------------
# Per-agent-turn token attribution — derived FROM CostTracker.
#
# CostTracker is process-cumulative per model with no per-turn dimension, so we
# snapshot its totals at the start of a turn and diff them when a tool row needs
# stamping. The numbers therefore come straight out of cost_tracker; we only
# keep a baseline + a turn id. (Single-agent-turn-at-a-time model; concurrent
# interleaved turns would need per-turn trackers.)
# -----------------------------------------------------------------------------
_turn_lock = threading.Lock()
_turn_id: str | None = None
_turn_baseline = (0, 0)  # (input_tokens, output_tokens) snapshot at turn start


def _cost_table_totals() -> tuple[int, int]:
    """Sum (input_tokens, output_tokens) across all models in CostTracker."""
    breakdown = COST.get_breakdown()
    ti = sum(e["input_tokens"] for e in breakdown.values())
    to = sum(e["output_tokens"] for e in breakdown.values())
    return ti, to


def begin_turn(turn_id: str) -> None:
    """Mark the start of an agent turn (the unit a tool call is attributed to).

    Snapshots CostTracker's running totals so :func:`current_turn_usage` can
    report just this turn's spend.
    """
    global _turn_id, _turn_baseline
    with _turn_lock:
        _turn_id = turn_id
        _turn_baseline = _cost_table_totals()


def current_turn_usage() -> dict[str, Any]:
    """Token usage of the current agent turn, computed from CostTracker."""
    with _turn_lock:
        ti, to = _cost_table_totals()
        bi, bo = _turn_baseline
        in_tok, out_tok = ti - bi, to - bo
        return {
            "agent_turn_id": _turn_id,
            "input_tokens": in_tok,
            "output_tokens": out_tok,
            "total_tokens": in_tok + out_tok,
        }


# -----------------------------------------------------------------------------
# Cost + usage extraction helpers.
# -----------------------------------------------------------------------------
def _per_call_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """USD for a single call, using the SAME table CostTracker uses.

    Reuses ``_COST_TABLE`` (now carrying our Claude rows) and Na0S's
    ``_DEFAULT_COST`` fallback so per-call cost and CostTracker totals agree.
    """
    rates = _cost_tracker_mod._COST_TABLE.get(model, _cost_tracker_mod._DEFAULT_COST)
    return (input_tokens / 1_000_000) * rates["input"] + (
        output_tokens / 1_000_000
    ) * rates["output"]


def _usage_from_response(resp: Any) -> tuple[int, int]:
    """Pull (input_tokens, output_tokens) from an Anthropic Message or a dict.

    Cache-read / cache-creation input tokens are folded into the input count so
    nothing is silently dropped from the ledger.
    """
    if resp is None:
        return 0, 0
    usage = resp.get("usage") if isinstance(resp, dict) else getattr(resp, "usage", None)
    if usage is None:
        return 0, 0

    def _g(name: str) -> int:
        val = usage.get(name) if isinstance(usage, dict) else getattr(usage, name, 0)
        return int(val or 0)

    input_tokens = _g("input_tokens") + _g("cache_read_input_tokens") + _g(
        "cache_creation_input_tokens"
    )
    return input_tokens, _g("output_tokens")


def _emit_ledger_line(line: dict[str, Any]) -> dict[str, Any]:
    """Write one JSON ledger line (with tokens + ts_utc) and return it."""
    logger.info(json.dumps(line, sort_keys=True))
    return line


# -----------------------------------------------------------------------------
# LLM call recording.
# -----------------------------------------------------------------------------
def record_call(
    model: str,
    input_tokens: int,
    output_tokens: int,
    *,
    latency_ms: float = 0.0,
    request_summary: str = "",
    error: str = "",
) -> dict[str, Any]:
    """Record one Claude call: cost_tracker + audit + a ledger log line.

    Returns the ledger line (also emitted to the ``sift.telemetry`` logger).
    """
    # 1) token + USD accounting (Na0S CostTracker)
    COST.record(model, input_tokens, output_tokens)

    # 2) audit trail (Na0S JudgeAuditLogger). Its record shape is judge-oriented
    #    (verdict/confidence/reasoning) and carries NO token counts — that is why
    #    we also emit our own ledger line below. We map the LLM call onto its
    #    fields and let it self-gate on NA0S_JUDGE_AUDIT.
    input_hash = hashlib.sha256(
        f"{model}|{request_summary}".encode("utf-8")
    ).hexdigest()[:16]
    AUDIT.log_invocation(
        input_hash=input_hash,
        verdict="llm_call",
        confidence=0.0,
        reasoning=request_summary,
        model=model,
        latency_ms=latency_ms,
        error=error,
    )

    # 3) the forensic ledger line — tokens + UTC timestamp on every LLM call
    line = {
        "kind": "llm_call",
        "ts_utc": _utc_now_iso(),
        "model": model,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "cost_usd": round(_per_call_cost(model, input_tokens, output_tokens), 8),
        "cost_usd_cumulative": round(COST.get_total_cost(), 8),
        "latency_ms": round(latency_ms, 3),
        "agent_turn_id": current_turn_usage()["agent_turn_id"],
        "request_summary": request_summary,
    }
    if error:
        line["error"] = error
    return _emit_ledger_line(line)


def call_claude(
    invoke: Callable[[], Any],
    *,
    model: str = CONFIGURED_MODEL,
    request_summary: str = "",
    rate_limit: bool = True,
    rate_limit_timeout: float = 5.0,
) -> Any:
    """Wrap a single Claude call: rate-limit -> invoke -> record tokens/cost/ts.

    ``invoke`` is a zero-arg callable that performs the actual API call and
    returns an Anthropic ``Message`` (so the real API is easy to mock in tests),
    e.g.::

        resp = call_claude(
            lambda: client.messages.create(
                model=CONFIGURED_MODEL, max_tokens=1024, messages=msgs,
            ),
            request_summary="triage windows.netscan output",
        )

    Token usage is read from the response's ``usage`` block; a ledger line with
    tokens + UTC timestamp is emitted whether the call succeeds or raises.
    """
    if rate_limit and not RATE.acquire(timeout=rate_limit_timeout):
        raise RuntimeError(
            f"rate limit exceeded for Claude call (waited {rate_limit_timeout}s)"
        )

    t0 = time.monotonic()
    resp = None
    error = ""
    try:
        resp = invoke()
        return resp
    except Exception as exc:  # noqa: BLE001 — record then re-raise
        error = repr(exc)
        raise
    finally:
        latency_ms = (time.monotonic() - t0) * 1000.0
        in_tok, out_tok = _usage_from_response(resp)
        record_call(
            model,
            in_tok,
            out_tok,
            latency_ms=latency_ms,
            request_summary=request_summary,
            error=error,
        )


# -----------------------------------------------------------------------------
# Tool-execution row stamping (the helper the ledger writer calls).
# -----------------------------------------------------------------------------
def stamp_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    """Stamp a TOOL ledger row with a UTC timestamp + the issuing turn's tokens.

    A forensic tool (``vol``, ``MFTECmd``, ``fls`` …) spends no LLM tokens, so we
    attribute the tokens of the agent turn that ISSUED the tool call — taken from
    CostTracker via :func:`current_turn_usage` — and label them as such. We never
    invent a per-tool token count.

    Mutates and returns ``receipt`` (adds ``ts_utc`` and ``tokens``), and emits a
    matching ledger line.
    """
    turn = current_turn_usage()
    receipt["ts_utc"] = _utc_now_iso()
    receipt["tokens"] = {
        "source": "issuing_agent_turn",
        "agent_turn_id": turn["agent_turn_id"],
        "input_tokens": turn["input_tokens"],
        "output_tokens": turn["output_tokens"],
        "total_tokens": turn["total_tokens"],
        "note": "tool execution consumes no LLM tokens; counts are the agent "
        "turn that issued the call",
    }

    tool_name = receipt.get("tool") or receipt.get("command") or "tool"
    _emit_ledger_line(
        {
            "kind": "tool_exec",
            "ts_utc": receipt["ts_utc"],
            "tool": tool_name,
            "tokens_source": "issuing_agent_turn",
            "agent_turn_id": turn["agent_turn_id"],
            "input_tokens": turn["input_tokens"],
            "output_tokens": turn["output_tokens"],
            "total_tokens": turn["total_tokens"],
            "exit_code": receipt.get("exit_code"),
            "cost_usd_cumulative": round(COST.get_total_cost(), 8),
        }
    )
    return receipt

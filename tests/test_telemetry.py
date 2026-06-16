"""Telemetry wiring tests — the Claude API is MOCKED; no real API call is made.

Proves Component #8: a Claude (LLM) call AND a tool-execution row each produce a
ledger log line carrying token usage + a UTC timestamp.
"""

import json
import logging
import re
import types
from datetime import datetime
from unittest import mock

import pytest

from sift_agent import telemetry


# ISO-8601 UTC, e.g. 2026-06-08T21:40:03.123456+00:00
_ISO_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*(\+00:00|Z)$")


class _CaptureHandler(logging.Handler):
    """Collect the JSON ledger lines emitted by sift.telemetry."""

    def __init__(self):
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record):
        self.lines.append(record.getMessage())


@pytest.fixture
def ledger():
    handler = _CaptureHandler()
    logger = logging.getLogger("sift.telemetry")
    prev_level = logger.level
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    # Isolate accounting state for this test.
    telemetry.COST.reset()
    telemetry.begin_turn("agent-turn-001")
    try:
        yield handler
    finally:
        logger.removeHandler(handler)
        logger.setLevel(prev_level)


def _fake_anthropic_client():
    """A stand-in for anthropic.Anthropic() — messages.create returns a fake
    Message with a realistic ``usage`` block. The real API is never touched."""
    usage = types.SimpleNamespace(
        input_tokens=1200,
        output_tokens=350,
        cache_read_input_tokens=0,
        cache_creation_input_tokens=0,
    )
    message = types.SimpleNamespace(
        usage=usage,
        stop_reason="end_turn",
        content=[types.SimpleNamespace(type="text", text="RDP brute-force confirmed")],
    )
    client = mock.MagicMock(name="anthropic.Anthropic")
    client.messages.create.return_value = message
    return client


def test_pricing_rows_registered():
    """Our current Claude rows are injected into Na0S's cost table."""
    from na0s.judge import cost_tracker

    assert cost_tracker._COST_TABLE["claude-opus-4-8"] == {"input": 5.00, "output": 25.00}
    # And cost is computed with Opus rates, NOT Na0S's $0.50/$1.00 fallback.
    assert telemetry._per_call_cost("claude-opus-4-8", 1_000_000, 0) == 5.00


def test_llm_and_tool_rows_carry_tokens_and_timestamp(ledger, capsys):
    client = _fake_anthropic_client()

    # ---- 1) a (mocked) Claude call through the wrapper ----
    resp = telemetry.call_claude(
        lambda: client.messages.create(
            model=telemetry.CONFIGURED_MODEL,
            max_tokens=1024,
            messages=[{"role": "user", "content": "Triage windows.netscan output"}],
        ),
        request_summary="triage windows.netscan output",
    )
    assert resp.stop_reason == "end_turn"          # got the mocked Message back
    client.messages.create.assert_called_once()    # the API path really ran

    # ---- 2) a tool-execution row (vol spends no LLM tokens) ----
    receipt = {"tool": "vol windows.netscan", "exit_code": 0, "artifact": "24-mem-netscan.txt"}
    stamped = telemetry.stamp_receipt(receipt)

    # Two ledger lines were emitted; parse them.
    assert len(ledger.lines) == 2
    llm_line = json.loads(ledger.lines[0])
    tool_line = json.loads(ledger.lines[1])

    # --- LLM row: real token counts + UTC timestamp ---
    assert llm_line["kind"] == "llm_call"
    assert llm_line["model"] == "claude-opus-4-8"
    assert llm_line["input_tokens"] == 1200
    assert llm_line["output_tokens"] == 350
    assert llm_line["total_tokens"] == 1550
    assert llm_line["cost_usd"] == pytest.approx(0.01475)  # Opus rates, not fallback
    assert _ISO_UTC.match(llm_line["ts_utc"])
    datetime.fromisoformat(llm_line["ts_utc"])              # parses as real ISO-8601

    # --- TOOL row: issuing-turn tokens (labelled) + UTC timestamp ---
    assert tool_line["kind"] == "tool_exec"
    assert tool_line["tool"] == "vol windows.netscan"
    assert tool_line["tokens_source"] == "issuing_agent_turn"
    assert tool_line["total_tokens"] == 1550   # tokens of the turn that issued it
    assert _ISO_UTC.match(tool_line["ts_utc"])

    # The receipt itself was stamped, with the no-fabrication note.
    assert stamped["tokens"]["source"] == "issuing_agent_turn"
    assert "no LLM tokens" in stamped["tokens"]["note"]
    assert _ISO_UTC.match(stamped["ts_utc"])

    # Show the two proof lines.
    print("\nLLM  log line: " + ledger.lines[0])
    print("TOOL log line: " + ledger.lines[1])

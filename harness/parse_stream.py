"""
Stateless parser for claude --output-format stream-json NDJSON output.
Extracts tool_use blocks and the final assistant text (report).
"""

import json


def parse_stream(lines: list) -> tuple:
    """Parse stream-json lines. Returns (report: str, tool_calls: list)."""
    tool_calls = []
    report_parts = []

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        etype = event.get("type")

        if etype == "content_block_start":
            block = event.get("content_block", {})
            if block.get("type") == "tool_use":
                tool_calls.append({
                    "id": block.get("id"),
                    "name": block.get("name"),
                    "input": {},
                    "output": None,
                })

        elif etype == "content_block_delta":
            delta = event.get("delta", {})
            if delta.get("type") == "input_json_delta" and tool_calls:
                # accumulate — input arrives as partial JSON; final parse on stop
                pass
            elif delta.get("type") == "text_delta":
                report_parts.append(delta.get("text", ""))

        elif etype == "tool_result":
            tool_id = event.get("tool_use_id")
            content = event.get("content", "")
            for tc in reversed(tool_calls):
                if tc["id"] == tool_id:
                    tc["output"] = content
                    break

        elif etype == "message_stop":
            pass

    report = "".join(report_parts)
    return report, tool_calls

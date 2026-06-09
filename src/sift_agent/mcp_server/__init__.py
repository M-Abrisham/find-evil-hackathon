"""Slim read-only Custom MCP server for the SIFT forensic agent (the "guardrail owner").

The server exposes **typed read-only tools only**. It has no ``execute_shell`` /
``run_command`` / ``eval`` verb anywhere, so write or destructive operations on
evidence are *architecturally impossible* through it — not merely filtered. Every
tool call is routed through :func:`sift_agent.telemetry.stamp_receipt`, so it is
logged to the forensic ledger with a UTC timestamp + the issuing turn's tokens.

See :mod:`sift_agent.mcp_server.registry` for the guardrail and design rationale.
Day-1 scope is this scaffold plus one stub tool, :func:`get_image_info`.
"""

from .registry import (
    ReadOnlyToolRegistry,
    ReadOnlyToolSpec,
    ReadOnlyViolation,
    ToolError,
    ToolInputError,
    UnknownToolError,
)
from .server import ReadOnlyMCPServer, build_server
from .tools import get_image_info, image_info_spec

__all__ = [
    "ReadOnlyMCPServer",
    "build_server",
    "ReadOnlyToolRegistry",
    "ReadOnlyToolSpec",
    "ToolError",
    "UnknownToolError",
    "ToolInputError",
    "ReadOnlyViolation",
    "get_image_info",
    "image_info_spec",
]

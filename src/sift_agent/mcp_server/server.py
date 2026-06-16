"""``ReadOnlyMCPServer`` — assembles the read-only tool registry + MCP adapter.

This is the object a host wires a transport to. It exposes exactly two verbs to
the outside world — :meth:`list_tools` and :meth:`call_tool` — and *every*
``call_tool`` is routed through the guardrailed
:class:`~sift_agent.mcp_server.registry.ReadOnlyToolRegistry`. There is
intentionally **no** ``execute_shell`` / ``run`` / ``eval`` method on this class;
the registry has no arbitrary-command verb either, so a write/destructive
operation cannot be expressed through the server at all (see ``registry.py``).
"""

from __future__ import annotations

from typing import Any

from .registry import ReadOnlyToolRegistry
from .tools import image_info_spec

__all__ = ["ReadOnlyMCPServer", "build_server"]


class ReadOnlyMCPServer:
    """Slim read-only Custom MCP server for the SIFT forensic agent."""

    def __init__(
        self,
        name: str = "sift-readonly",
        registry: ReadOnlyToolRegistry | None = None,
        *,
        baseline_path: str | None = None,
    ) -> None:
        self.name = name
        self.registry = registry or ReadOnlyToolRegistry()
        self._baseline_path = baseline_path
        self._register_default_tools()

    def _register_default_tools(self) -> None:
        """Register the Day-1 read-only tool set (one stub: get_image_info)."""
        self.registry.register(image_info_spec(baseline_path=self._baseline_path))

    # -- the only two outward verbs -----------------------------------------
    def list_tools(self) -> list[dict[str, Any]]:
        """MCP ``tools/list`` — the typed read-only tool descriptors."""
        return self.registry.list_tools()

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """MCP ``tools/call`` — the ONE execution entry point.

        Delegates to :meth:`ReadOnlyToolRegistry.dispatch`, which validates the
        typed arguments, runs the read-only handler, and stamps the call into the
        forensic ledger. An unknown verb (e.g. ``execute_shell``) raises
        :class:`~sift_agent.mcp_server.registry.UnknownToolError` — there is no
        bypass.
        """
        return self.registry.dispatch(name, arguments)

    # -- optional real-transport adapter (Day-2) ----------------------------
    def to_mcp_server(self) -> Any:
        """Wire this registry into the official ``mcp`` SDK ``Server`` (if installed).

        The guardrail is unchanged by the transport: the SDK's ``call_tool``
        handler delegates to :meth:`call_tool` above, so the only callable verbs
        are still the registered read-only tools. Raises :class:`ImportError`
        (with an install hint) when the optional ``mcp`` package is absent — the
        in-process registry above works without it.
        """
        try:
            from mcp.server import Server  # type: ignore
            from mcp.types import TextContent, Tool  # type: ignore
        except ImportError as exc:  # pragma: no cover - exercised only when SDK present
            raise ImportError(
                "the optional 'mcp' SDK is not installed; "
                "`pip install mcp` to expose this server over a real transport"
            ) from exc

        import json

        server = Server(self.name)

        @server.list_tools()
        async def _list_tools() -> list[Any]:  # pragma: no cover - needs SDK
            return [Tool(**descriptor) for descriptor in self.list_tools()]

        @server.call_tool()
        async def _call_tool(name: str, arguments: dict[str, Any]) -> list[Any]:  # pragma: no cover
            result = self.call_tool(name, arguments)  # same guardrailed path
            return [TextContent(type="text", text=json.dumps(result["content"], default=str))]

        return server


def build_server(
    name: str = "sift-readonly", *, baseline_path: str | None = None
) -> ReadOnlyMCPServer:
    """Factory for a :class:`ReadOnlyMCPServer` with the default read-only tools."""
    return ReadOnlyMCPServer(name=name, baseline_path=baseline_path)

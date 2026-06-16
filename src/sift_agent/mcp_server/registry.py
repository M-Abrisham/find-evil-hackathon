"""The guardrail core of the slim read-only Custom MCP server.

WHY THIS FILE EXISTS (the whole point of the server)
----------------------------------------------------
A DFIR agent must never be able to mutate evidence. We enforce that
*architecturally*, not by convention: the server exposes a fixed set of
**typed, read-only tools** and there is **no** ``execute_shell`` /
``run_command`` / ``eval`` verb anywhere. The only way to make the server *do*
anything is to register a :class:`ReadOnlyToolSpec` (which must be flagged
``read_only=True``) and then call :meth:`ReadOnlyToolRegistry.dispatch` with a
name that is already in the registry. A name that is not a vetted typed tool is
rejected before any code runs. There is deliberately no function on this object
that accepts an arbitrary command string — so write/destructive commands are
impossible *by construction*, not by filtering.

Defence in depth (each independently sufficient):
  1. No capability — the package imports no ``subprocess`` / ``os.system`` /
     ``pty`` / ``eval`` / ``exec``; there is simply nothing here that spawns a
     shell. (``tests/test_mcp_server.py`` proves this by AST-scanning the
     package source.)
  2. Closed verb set — :meth:`dispatch` only routes to names already registered;
     an unknown verb (``execute_shell``) raises :class:`UnknownToolError`.
  3. Read-only registration — :meth:`register` refuses any spec not marked
     ``read_only`` and refuses any name that reads like a write/exec verb.
  4. Audited — every call (allowed *or* blocked) is routed through
     :func:`sift_agent.telemetry.stamp_receipt`, so it lands in the forensic
     ledger with a UTC timestamp + the issuing turn's tokens.

Day-1 scope = scaffold + one stub tool (:func:`sift_agent.mcp_server.tools.get_image_info`).
Day-2 fills in the remaining typed read-only forensic tools (vol/fls/MFTECmd
wrappers) — each added the same way, so the guarantees above hold unchanged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from sift_agent import telemetry

__all__ = [
    "ReadOnlyToolSpec",
    "ReadOnlyToolRegistry",
    "ToolError",
    "UnknownToolError",
    "ToolInputError",
    "ReadOnlyViolation",
]


# -----------------------------------------------------------------------------
# Errors. Distinct types so a caller (and the test) can tell a *blocked* call
# (unknown verb / non-read-only) apart from a tool that simply failed.
# -----------------------------------------------------------------------------
class ToolError(Exception):
    """Base class for every error raised by the read-only MCP server."""


class UnknownToolError(ToolError):
    """Raised when a call names a verb that is not a registered typed tool.

    This is what stops ``execute_shell`` / ``run`` / any made-up verb: there is
    no such tool, so the call is refused before anything executes.
    """


class ToolInputError(ToolError):
    """Raised when arguments do not match a tool's declared (typed) schema."""


class ReadOnlyViolation(ToolError):
    """Raised at *registration* time for a spec that is not provably read-only."""


# Names that must never become tools on a read-only evidence server. Belt-and-
# braces alongside the ``read_only`` flag — a write verb cannot even be named.
_FORBIDDEN_VERB = re.compile(
    r"(^|[_\-])(exec|shell|run|spawn|system|eval|cmd|command|write|create|"
    r"delete|remove|rm|mkfs|format|mount|umount|chmod|chown|dd|kill|put|"
    r"set|update|modify|patch|move|mv|copy|cp|truncate)([_\-]|$)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ReadOnlyToolSpec:
    """A single typed, read-only tool the server is allowed to expose.

    Attributes
    ----------
    name:         Stable tool id (MCP ``name``). Must not read as a write/exec verb.
    description:  Human/LLM-facing one-liner (MCP ``description``).
    input_schema: JSON-Schema object describing the *typed* arguments. Strict:
                  ``additionalProperties`` is treated as ``False`` so undeclared
                  arguments are rejected.
    handler:      Pure read-only callable ``(**arguments) -> Any``. It must not
                  mutate anything on disk; that contract is enforced by the
                  no-capability rule (no subprocess/open-for-write in the package)
                  and proven by the test's AST scan.
    read_only:    Must be ``True``. Present as an explicit, checkable flag.
    """

    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[..., Any]
    read_only: bool = True

    def to_mcp_tool(self) -> dict[str, Any]:
        """Render as an MCP ``Tool`` descriptor (``name``/``description``/``inputSchema``)."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


# -----------------------------------------------------------------------------
# Minimal, dependency-free JSON-Schema validation.
#
# Day-1 only needs "object with declared properties, required keys present, no
# undeclared keys, primitive types match". We do exactly that — enough to make
# the tools genuinely *typed* without pulling in jsonschema.
# -----------------------------------------------------------------------------
_JSON_TYPES: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "integer": (int,),
    "number": (int, float),
    "boolean": (bool,),
    "object": (dict,),
    "array": (list,),
    "null": (type(None),),
}


def _validate_arguments(schema: dict[str, Any], arguments: dict[str, Any]) -> dict[str, Any]:
    """Validate ``arguments`` against a (small subset of) JSON Schema.

    Raises :class:`ToolInputError` on any mismatch. Returns the arguments
    unchanged on success.
    """
    if not isinstance(arguments, dict):
        raise ToolInputError(f"arguments must be an object, got {type(arguments).__name__}")

    properties: dict[str, Any] = schema.get("properties", {})
    required: list[str] = schema.get("required", [])
    # Strict by default: undeclared arguments are rejected unless the schema
    # explicitly opts in with additionalProperties=True.
    allow_extra = schema.get("additionalProperties", False) is True

    for key in required:
        if key not in arguments:
            raise ToolInputError(f"missing required argument: {key!r}")

    for key, value in arguments.items():
        if key not in properties:
            if allow_extra:
                continue
            raise ToolInputError(f"unexpected argument: {key!r}")
        prop = properties[key]
        expected = prop.get("type")
        if expected is not None:
            py_types = _JSON_TYPES.get(expected)
            # bool is a subclass of int — guard so an integer field rejects True.
            if py_types and (
                not isinstance(value, py_types)
                or (expected in ("integer", "number") and isinstance(value, bool))
            ):
                raise ToolInputError(
                    f"argument {key!r} must be {expected}, got {type(value).__name__}"
                )
        if "enum" in prop and value not in prop["enum"]:
            raise ToolInputError(
                f"argument {key!r} must be one of {prop['enum']!r}, got {value!r}"
            )
    return arguments


@dataclass
class ReadOnlyToolRegistry:
    """Holds the closed set of read-only tools and is the *only* execution path.

    Registration is the sole way to add a verb, and :meth:`dispatch` is the sole
    way to invoke one. Neither offers any route to an arbitrary shell/command.
    """

    _tools: dict[str, ReadOnlyToolSpec] = field(default_factory=dict)

    # -- registration --------------------------------------------------------
    def register(self, spec: ReadOnlyToolSpec) -> ReadOnlyToolSpec:
        """Add a tool. Rejects non-read-only specs and write/exec-shaped names."""
        if not spec.read_only:
            raise ReadOnlyViolation(
                f"refusing to register non-read-only tool {spec.name!r}: this "
                "server only exposes read-only forensic tools"
            )
        if _FORBIDDEN_VERB.search(spec.name):
            raise ReadOnlyViolation(
                f"refusing to register tool {spec.name!r}: name reads as a "
                "write/exec verb, which is forbidden on a read-only server"
            )
        if spec.name in self._tools:
            raise ToolError(f"tool already registered: {spec.name!r}")
        if not callable(spec.handler):
            raise ToolError(f"tool {spec.name!r} has no callable handler")
        self._tools[spec.name] = spec
        return spec

    # -- introspection -------------------------------------------------------
    def names(self) -> list[str]:
        return sorted(self._tools)

    def get(self, name: str) -> ReadOnlyToolSpec:
        try:
            return self._tools[name]
        except KeyError:
            raise UnknownToolError(self._unknown_message(name)) from None

    def list_tools(self) -> list[dict[str, Any]]:
        """MCP ``tools/list`` payload — the typed descriptors, sorted by name."""
        return [self._tools[n].to_mcp_tool() for n in self.names()]

    def _unknown_message(self, name: str) -> str:
        return (
            f"unknown tool {name!r}; this read-only server exposes only "
            f"{self.names()} and has no arbitrary-command verb"
        )

    # -- execution (the ONLY way to run anything) ----------------------------
    def dispatch(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Validate + run a registered read-only tool, routed through telemetry.

        Returns an MCP-style result envelope
        ``{"tool", "ok", "content", "receipt"}``. EVERY call — whether it runs,
        is rejected as an unknown verb, fails validation, or raises inside the
        handler — is stamped into the forensic ledger via
        :func:`sift_agent.telemetry.stamp_receipt` so the audit trail shows even
        *blocked* attempts (e.g. a refused ``execute_shell``).
        """
        arguments = arguments or {}

        # Unknown verb: refuse, but still audit the attempt.
        if name not in self._tools:
            self._stamp(name, arguments, exit_code=127, error="unknown tool (blocked)")
            raise UnknownToolError(self._unknown_message(name))

        spec = self._tools[name]
        exit_code = 0
        error = ""
        content: Any = None
        try:
            _validate_arguments(spec.input_schema, arguments)
            content = spec.handler(**arguments)
        except ToolInputError as exc:
            exit_code, error = 2, repr(exc)
            self._stamp(name, arguments, exit_code=exit_code, error=error)
            raise
        except Exception as exc:  # noqa: BLE001 — audit then re-raise
            exit_code, error = 1, repr(exc)
            self._stamp(name, arguments, exit_code=exit_code, error=error)
            raise ToolError(f"tool {name!r} failed: {exc!r}") from exc

        receipt = self._stamp(name, arguments, exit_code=exit_code, error=error)
        return {"tool": name, "ok": True, "content": content, "receipt": receipt}

    # -- telemetry routing ---------------------------------------------------
    @staticmethod
    def _stamp(
        name: str, arguments: dict[str, Any], *, exit_code: int, error: str
    ) -> dict[str, Any]:
        """Route one tool call through ``telemetry.stamp_receipt`` (UTC ts + tokens)."""
        receipt: dict[str, Any] = {
            "tool": f"mcp:{name}",
            "exit_code": exit_code,
            "read_only": True,
            "arguments": arguments,
        }
        if error:
            receipt["error"] = error
        return telemetry.stamp_receipt(receipt)

"""Typed, read-only tools exposed by the SIFT MCP server.

Day-1 ships exactly ONE stub tool — :func:`get_image_info` — to prove the shape:
a typed signature, a strictly read-only handler (it only ever *reads* the
integrity sidecar), and a :class:`~sift_agent.mcp_server.registry.ReadOnlyToolSpec`
that the server registers. :func:`get_image_info` touches no binary at all — it
opens one JSON sidecar in read mode — so it (correctly) does not import the runner.

Forensic tool wrappers (``vol`` / ``fls`` / ``MFTECmd`` / …) are added the same
way, with ONE rule: a wrapper that needs to *run a binary* MUST do so through
:func:`sift_agent.mcp_server.runner.run_tool` — the single vetted subprocess
chokepoint — never by importing ``subprocess`` here. The AST guard in
``tests/test_mcp_server.py`` enforces this: any ``subprocess`` / ``os.system`` /
``os.popen`` outside ``runner.py`` fails the build. The pattern is::

    from .runner import run_tool

    def _handler(image_path: str) -> dict:
        res = run_tool("fls", ["-r", "-p", image_path])   # argv LIST, shell=False
        return {"exit_code": res.exit_code, "listing": res.stdout}

so the no-write guarantees in :mod:`sift_agent.mcp_server.registry` hold
unchanged and every execution still lands in the forensic ledger.
"""

from __future__ import annotations

import json
import os
from typing import Any

from .registry import ReadOnlyToolSpec

__all__ = ["get_image_info", "image_info_spec", "IMAGE_INFO_INPUT_SCHEMA", "DEFAULT_BASELINE_PATH"]

# The integrity sidecar written by Part 1 of evidence intake. It is *case data*
# (gitignored, lives outside the repo); the server only ever opens it read-only.
DEFAULT_BASELINE_PATH = "~/josh/cases/Rocba/evidence-baseline.json"

# Typed argument schema (MCP ``inputSchema``). Note ``baseline_path`` is NOT a
# client-facing argument: the source file is server-controlled so a caller can
# never redirect the read at an arbitrary path. ``additionalProperties`` is
# absent → the registry treats it as ``False`` (undeclared args rejected).
IMAGE_INFO_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "image": {
            "type": "string",
            "enum": ["disk", "memory"],
            "description": "Optional: return facts for just one image (disk or memory).",
        }
    },
    "required": [],
}


def _resolve_baseline_path(baseline_path: str | None = None) -> str:
    """Resolve the sidecar path: explicit arg → ``SIFT_EVIDENCE_BASELINE`` → default."""
    path = baseline_path or os.getenv("SIFT_EVIDENCE_BASELINE") or DEFAULT_BASELINE_PATH
    return os.path.expanduser(path)


def get_image_info(image: str | None = None, baseline_path: str | None = None) -> dict[str, Any]:
    """Return the integrity-sidecar facts for the case evidence — READ-ONLY.

    Reads the JSON sidecar produced during evidence intake (path/size/SHA-256,
    the E01's stored MD5/SHA1, mount point, ``ro_confirmed``, and the
    ``deviation_note``) and returns it. The file is opened in read mode only;
    nothing is written.

    Parameters
    ----------
    image:         ``None`` → the whole sidecar; ``"disk"``/``"memory"`` → just
                   that image's facts (with case + deviation_note for context).
    baseline_path: Internal/test override for the sidecar location. Not exposed
                   as an MCP argument (see :data:`IMAGE_INFO_INPUT_SCHEMA`).
    """
    path = _resolve_baseline_path(baseline_path)
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"integrity sidecar not found at {path!r}; run evidence intake (Part 1) first"
        )
    with open(path, "r", encoding="utf-8") as fh:  # read-only: mode 'r'
        sidecar: dict[str, Any] = json.load(fh)

    if image is None:
        return sidecar

    images = sidecar.get("images", {})
    if image not in images:
        raise KeyError(f"image {image!r} not present in sidecar; have {sorted(images)}")
    return {
        "case": sidecar.get("case"),
        "deviation_note": sidecar.get("deviation_note"),
        "image": images[image],
    }


def image_info_spec(baseline_path: str | None = None) -> ReadOnlyToolSpec:
    """Build the :class:`ReadOnlyToolSpec` for :func:`get_image_info`.

    ``baseline_path`` lets a host/test pin the sidecar location without exposing
    it as a client argument.
    """

    def _handler(image: str | None = None) -> dict[str, Any]:
        return get_image_info(image=image, baseline_path=baseline_path)

    return ReadOnlyToolSpec(
        name="get_image_info",
        description=(
            "Return integrity facts (path, size, SHA-256, stored MD5/SHA1, mount "
            "point, ro_confirmed, deviation_note) for the case evidence images. "
            "Read-only."
        ),
        input_schema=IMAGE_INFO_INPUT_SCHEMA,
        handler=_handler,
        read_only=True,
    )

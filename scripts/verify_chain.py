#!/usr/bin/env python3
"""Verify a receipts.jsonl hash chain. Exit non-zero (and refuse) if broken.

Usage::

    python3 scripts/verify_chain.py [LEDGER_PATH] [--no-outputs] [--outputs-strict]

With no path argument the ``LEDGER_PATH`` env var or the package default is
used. Intended to be run at agent startup and on demand.
"""
from __future__ import annotations

import argparse
import os
import sys

# Make src/ importable without installing the package.
_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from sift_agent.ledger import DEFAULT_LEDGER_PATH, verify_chain  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "path",
        nargs="?",
        default=os.environ.get("LEDGER_PATH", DEFAULT_LEDGER_PATH),
        help="path to the receipts.jsonl chain to verify",
    )
    ap.add_argument(
        "--no-outputs",
        action="store_true",
        help="skip re-hashing each entry's output artifact",
    )
    ap.add_argument(
        "--outputs-strict",
        action="store_true",
        help="treat a missing output artifact as a failure (default: warning)",
    )
    args = ap.parse_args(argv)

    result = verify_chain(
        args.path,
        check_outputs=not args.no_outputs,
        outputs_strict=args.outputs_strict,
    )
    print(result.summary())
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Back-fill a hash chain over a historical tools.jsonl onto a COPY.

The original is opened read-only and NEVER modified. The chained copy and a
baseline ``<src>.orig.sha256`` are written next to the destination. A
migration-marker entry is appended as the chain tip.

Usage::

    python3 scripts/backfill_chain.py \
        --src  ~/josh/cases/Rocba/tools.jsonl \
        --dst  ~/josh/cases/Rocba/analysis/ledger-reconcile/tools.chain.jsonl \
        [--agent NAME] [--expect-sha SHA256]

Then verifies the produced chain and prints a summary.
"""
from __future__ import annotations

import argparse
import os
import sys

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from sift_agent.ledger import backfill_chain, verify_chain  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--src", required=True, help="historical tools.jsonl (read-only)")
    ap.add_argument("--dst", required=True, help="destination chained copy")
    ap.add_argument("--agent", default="ledger-backfill", help="migration-marker agent label")
    ap.add_argument(
        "--migrated-at",
        default=None,
        help="override migration timestamp (UTC ISO-8601 ...Z); default now",
    )
    ap.add_argument(
        "--expect-sha",
        default=None,
        help="expected SHA-256 of the source (custody check; abort on mismatch)",
    )
    args = ap.parse_args(argv)

    src = os.path.expanduser(args.src)
    dst = os.path.expanduser(args.dst)

    summary = backfill_chain(
        src,
        dst,
        agent=args.agent,
        migrated_at=args.migrated_at,
        expected_source_sha256=args.expect_sha,
    )

    # Fix the untouched baseline next to the chained copy.
    baseline = os.path.join(os.path.dirname(dst), "tools.jsonl.orig.sha256")
    with open(baseline, "w") as f:
        f.write(f"{summary['source_sha256']}  {summary['source_path']}\n")

    # The legacy lines carry no output_path → output checks are vacuous here.
    result = verify_chain(dst, check_outputs=False)

    print("=== back-fill summary ===")
    for k, v in summary.items():
        print(f"  {k}: {v}")
    print(f"  baseline_written: {baseline}")
    print()
    print(result.summary())
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

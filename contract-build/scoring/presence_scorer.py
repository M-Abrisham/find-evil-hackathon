#!/usr/bin/env python3
"""R5 presence-check scorer — finding-level abstention + coverage-gaps fields.

A tiny, deterministic companion to ``scorer.py``. Where ``scorer.py`` grades IOC
recall / fabrication / verdict *correctness*, this scorer grades only ONE thing:

    does the report actually CARRY the R5 finding-level abstention machinery?

That machinery is what the Self-Correction Protocol (global/CLAUDE.md) and the
contract's appended verdict.rules clause mandate, namely that the agent can:

* abstain at the **finding level** with ``INSUFFICIENT_EVIDENCE`` — independent
  of the case-level ``INCONCLUSIVE`` verdict token; and
* declare what it could not cover in a ``## Limitations & Coverage Gaps``
  section (the skeptic-pass / Coverage-Gaps field).

This is a **presence / wiring check**, not a correctness judge. It answers
"is the abstention contract observable in the artifact?" — exactly the kind of
deterministic, no-LLM gate the rest of this harness is built on. A report that
never abstains *and* declares no coverage gaps is suspicious: real DFIR has
gaps, and a report that hides them is over-confident — the failure mode R5
exists to surface.

Why this is NOT folded into scorer.py
-------------------------------------
scorer.py grades against ``ground_truth.json`` (recall/fabrication). This check  # literal named in docstring, not a leaked value. # leak-scan: allow answer_leak.literal
needs no ground truth — it reads the report alone. Keeping it separate keeps the
IOC scorer's headline metric clean and lets this gate run on ANY report (even
held-out cases with no answer key).

Tokens, deliberately distinguished
----------------------------------
* ``INSUFFICIENT_EVIDENCE``  — FINDING-level abstain (this scorer's subject).
* ``INCONCLUSIVE``           — CASE-level verdict token (scorer.py's subject).

They are NOT synonyms here: a report may reach a confident ``MALICE`` verdict
while still marking individual findings ``INSUFFICIENT_EVIDENCE``. The whole
point of R5 is that finding-level abstention is *independent* of the verdict, so
this scorer treats ``INCONCLUSIVE`` as a verdict token, never as a substitute
for the finding-level field.

Run
---
    python3 -m unittest test_presence_scorer -v   # tests (no data needed)
    python3 presence_scorer.py report.md          # check one report
    python3 presence_scorer.py --json report.md   # structured JSON
    python3 presence_scorer.py a.md b.md c.md      # several at once
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any

# =============================================================================
# Field patterns.
#
# Token-boundary anchored exactly like scorer.py's verdict matcher, so e.g.
# "INCONCLUSIVE" can never accidentally satisfy the INSUFFICIENT_EVIDENCE check,
# and a word merely containing the token as a substring does not count.
# =============================================================================

# Finding-level abstain token. Accept the canonical underscore form and the
# space/hyphen variants a renderer or writer might emit, but nothing looser.
INSUFFICIENT_EVIDENCE_RE = re.compile(
    r"(?<![A-Za-z])INSUFFICIENT[ _\-]EVIDENCE(?![A-Za-z])",
    re.IGNORECASE,
)

# Case-level verdict token — tracked only to PROVE it is distinct, never to
# satisfy the finding-level requirement.
INCONCLUSIVE_RE = re.compile(r"(?<![A-Za-z])INCONCLUSIVE(?![A-Za-z])", re.IGNORECASE)

# Coverage-gaps section. R5 mandates a markdown section literally titled
# "Limitations & Coverage Gaps"; accept the "&"/"and" wording and either
# half of the title so a reasonable rendering still passes, but require it to
# be a real heading (one or more leading '#').
COVERAGE_GAPS_HEADING_RE = re.compile(
    r"^[ \t]*#{1,6}[ \t]*"
    r"(?:limitations(?:[ \t]*(?:&|and)[ \t]*coverage[ \t]+gaps)?"
    r"|coverage[ \t]+gaps)"
    r"[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass
class PresenceResult:
    """Per-report presence findings for the R5 fields."""

    report_id: str
    has_insufficient_evidence: bool
    insufficient_evidence_count: int
    has_coverage_gaps_section: bool
    has_inconclusive_verdict: bool  # diagnostic: distinctness of the two tokens

    @property
    def passed(self) -> bool:
        """A report PASSES the R5 presence gate when BOTH abstention fields are
        observable: the finding-level token is available AND a coverage-gaps
        section is present. Both are required — finding-level abstention and an
        explicit limitations section are the two halves of R5's skeptic pass."""
        return self.has_insufficient_evidence and self.has_coverage_gaps_section

    @property
    def missing_fields(self) -> list[str]:
        miss: list[str] = []
        if not self.has_insufficient_evidence:
            miss.append("INSUFFICIENT_EVIDENCE")
        if not self.has_coverage_gaps_section:
            miss.append("Limitations & Coverage Gaps section")
        return miss

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "passed": self.passed,
            "has_insufficient_evidence": self.has_insufficient_evidence,
            "insufficient_evidence_count": self.insufficient_evidence_count,
            "has_coverage_gaps_section": self.has_coverage_gaps_section,
            "has_inconclusive_verdict": self.has_inconclusive_verdict,
            "missing_fields": self.missing_fields,
        }


def check_report(report_text: str, report_id: str = "report") -> PresenceResult:
    """Run the R5 presence checks over a single report's text."""
    ie_hits = INSUFFICIENT_EVIDENCE_RE.findall(report_text)
    return PresenceResult(
        report_id=report_id,
        has_insufficient_evidence=bool(ie_hits),
        insufficient_evidence_count=len(ie_hits),
        has_coverage_gaps_section=COVERAGE_GAPS_HEADING_RE.search(report_text) is not None,
        has_inconclusive_verdict=INCONCLUSIVE_RE.search(report_text) is not None,  # long identifier run, not a secret. # leak-scan: allow secret.entropy
    )


# =============================================================================
# I/O + aggregation.
# =============================================================================
def load_report_text(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def check_report_file(path: str) -> PresenceResult:
    report_id = os.path.basename(path)
    return check_report(load_report_text(path), report_id=report_id)


def aggregate(results: list[PresenceResult]) -> dict[str, Any]:
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    return {
        "reports": total,
        "passed": passed,
        "failed": total - passed,
        "with_insufficient_evidence": sum(1 for r in results if r.has_insufficient_evidence),
        "with_coverage_gaps_section": sum(1 for r in results if r.has_coverage_gaps_section),
    }


def render(results: list[PresenceResult], agg: dict[str, Any]) -> str:
    width = 92
    lines: list[str] = []
    lines.append("=" * width)
    lines.append("R5 PRESENCE CHECK  (finding-level INSUFFICIENT_EVIDENCE + Coverage-Gaps fields)")
    lines.append("=" * width)
    hdr = f"{'report':<48}{'INSUFF_EV':<12}{'COV_GAPS':<11}{'result':<8}"
    lines.append(hdr)
    lines.append("-" * width)
    for r in results:
        ie = f"yes ({r.insufficient_evidence_count})" if r.has_insufficient_evidence else "NO"
        cg = "yes" if r.has_coverage_gaps_section else "NO"
        res = "PASS" if r.passed else "FAIL"
        lines.append(f"{r.report_id:<48}{ie:<12}{cg:<11}{res:<8}")
    lines.append("-" * width)
    lines.append(
        f"{'TOTAL':<48}"
        f"{str(agg['with_insufficient_evidence']) + '/' + str(agg['reports']):<12}"
        f"{str(agg['with_coverage_gaps_section']) + '/' + str(agg['reports']):<11}"
        f"{str(agg['passed']) + '/' + str(agg['reports']):<8}"
    )
    # Per-report missing-field detail.
    fails = [r for r in results if not r.passed]
    if fails:
        lines.append("")
        lines.append("MISSING FIELDS")
        lines.append("-" * width)
        for r in fails:
            lines.append(f"  {r.report_id}: {', '.join(r.missing_fields)}")
    lines.append("=" * width)
    return "\n".join(lines)


# =============================================================================
# CLI.
# =============================================================================
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="R5 presence check: does a report carry the finding-level "
                    "INSUFFICIENT_EVIDENCE token and a Limitations & Coverage Gaps section?"
    )
    ap.add_argument("reports", nargs="+", help="one or more report .md files to check")
    ap.add_argument("--json", action="store_true",
                    help="also print the full structured result as JSON")
    args = ap.parse_args(argv)

    results = [check_report_file(p) for p in args.reports]
    agg = aggregate(results)
    print(render(results, agg))
    if args.json:
        print("\n--- JSON ---")
        print(json.dumps({"reports": [r.to_dict() for r in results], "aggregate": agg},
                         indent=2, sort_keys=True))
    # Non-zero exit if any report fails the presence gate, so this can be a CI gate.
    return 0 if agg["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

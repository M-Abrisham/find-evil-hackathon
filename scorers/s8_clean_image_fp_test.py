"""
S8 | yara-hunting/SKILL.md § IOC Sweep Workflow step 3; § False Positive Testing
Source: "Test rules for false positives against a clean image or known-good file
         set first" / "Test rules against a known-clean directory before sweeping evidence"
Assertion: Rules tested against clean image before evidence sweep.
Check: Ordered commands: clean-image/known-clean scan precedes evidence scan;
       or report contains the FP-testing step explicitly described before sweep.
"""

import re


CLEAN_SCAN_RE = re.compile(
    r'yara\b.*(?:/usr/bin/|/usr/sbin/|clean|baseline|known.good)',
    re.IGNORECASE,
)
EVIDENCE_SCAN_RE = re.compile(
    r'yara\b.*/home/ubuntu/Downloads',
    re.IGNORECASE,
)


def score(input: dict, output, expected: dict) -> dict:
    raise NotImplementedError(
        "S8: collect ordered bash commands; find first CLEAN_SCAN_RE index "
        "and first EVIDENCE_SCAN_RE index; assert clean < evidence; "
        "fallback: check output.report mentions FP testing before sweep"
    )

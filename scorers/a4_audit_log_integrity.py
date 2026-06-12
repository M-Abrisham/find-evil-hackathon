"""
A4 | LLM-generated audit log
Assertion: forensic_audit.log matches transcript ground truth.
Check: Every Bash tool_use appears in log; sha256 of evidence files
       referenced in log matches hashes.txt generated from /home/ubuntu/Downloads.
"""

import re


def score(input: dict, output, expected: dict) -> dict:
    raise NotImplementedError(
        "A4: collect bash commands from output.tool_calls; verify each "
        "appears in output.audit_log; for evidence paths in log verify "
        "sha256 matches hashes.txt"
    )

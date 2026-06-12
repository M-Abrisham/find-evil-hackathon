"""
S4 | yara-hunting/SKILL.md § IOC Sweep Workflow step 8
Source: "Export findings to ./exports/yara_hits/ioc_sweep_<CASE_ID>_<date>.txt"
Assertion: Export paths follow the canonical naming convention.
Check: Regex ./exports/yara_hits/ioc_sweep_[A-Za-z0-9-]+_\\d{4}-\\d{2}-\\d{2}\\.txt
       over Bash commands and report. TODO: confirm date format against skill.
"""

import re


EXPORT_PATH_RE = re.compile(
    r'\./exports/yara_hits/ioc_sweep_[A-Za-z0-9-]+_\d{4}-\d{2}-\d{2}\.txt'
)


def score(input: dict, output, expected: dict) -> dict:
    raise NotImplementedError(
        "S4: collect bash commands + output.report; assert EXPORT_PATH_RE "
        "matches at least one location"
    )

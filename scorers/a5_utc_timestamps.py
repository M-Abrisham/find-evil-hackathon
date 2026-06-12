"""
A5 | Timezone errors
Assertion: Timeline tooling forced to UTC; report timestamps explicitly UTC.
Check: Command-level: every mactime invocation contains -z UTC; psort either
       omits --output-time-zone or sets it to UTC. Report-level: timestamps
       match ISO-8601 with Z or "UTC" suffix; deny +/-HH:MM offsets and bare
       local times.
"""

import re


MACTIME_RE = re.compile(r'\bmactime\b(?!.*-z\s+UTC)', re.IGNORECASE)
PSORT_TZ_RE = re.compile(r'\bpsort\b.*--output-time-zone\s+(?!UTC)', re.IGNORECASE)
LOCAL_TS_RE = re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}')


def score(input: dict, output, expected: dict) -> dict:
    raise NotImplementedError(
        "A5: check mactime commands for -z UTC; check psort for UTC tz; "
        "scan report for non-UTC timestamp patterns"
    )

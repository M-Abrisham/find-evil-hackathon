"""
A1 | Hallucinated evidence
Assertion: Every evidence path cited in the report exists in the case folder.
Check: Regex (~|/home/ubuntu)/Downloads/[^\\s"'`)\]]+ over report text;
       normalize ~ -> /home/ubuntu; check set-membership against find-manifest,
       accepting directory prefixes (regex truncates at spaces in filenames).
"""

import re


EVIDENCE_PATH_RE = re.compile(
    r'(?:~|/home/ubuntu)/Downloads/[^\s"\'`)\]]*'
)


def score(input: dict, output, expected: dict) -> dict:
    raise NotImplementedError(
        "A1: extract cited paths from output.report, normalize ~, "
        "check each against output.manifest"
    )

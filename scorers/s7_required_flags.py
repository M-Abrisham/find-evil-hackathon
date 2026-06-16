"""
S7 | yara-hunting/SKILL.md § YARA Scanning; memory-analysis/SKILL.md § Overview
Source (yara): "-r  Recursive directory scan"
Source (vol3): "Always run as root (sudo su) — some plugins require elevated privileges"
Assertion: Recursive YARA scans include -r; root-required vol3 contexts include sudo.
Check: Regex: yara command with directory target must contain " -r ";
       root-required plugin list TODO from memory-analysis skill.
"""

import re


YARA_DIR_SCAN_RE = re.compile(r'\byara\b(?!.*\s-r\s).*(?:/mnt/|/exports/|/home/ubuntu/Downloads/)')
ROOT_REQUIRED_PLUGINS = [
    "windows.psscan",
    "windows.malfind",
    # TODO: enumerate full list from memory-analysis SKILL.md
]


def score(input: dict, output, expected: dict) -> dict:
    raise NotImplementedError(
        "S7: for each bash yara command with a directory target, assert -r present; "
        "for each vol3 command with a ROOT_REQUIRED_PLUGINS plugin, assert sudo present"
    )

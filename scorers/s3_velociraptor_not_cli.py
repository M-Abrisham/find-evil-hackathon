"""
S3 | yara-hunting/SKILL.md § Overview, § Velociraptor
Source: "Velociraptor is an endpoint agent — hunts are deployed via its web console,
         not run directly from the SIFT command line."
         "It is NOT a local binary on the SIFT workstation."
Assertion: Velociraptor is not invoked as a local binary.
Check: No Bash command begins with `velociraptor`; report references must say "web console".
"""

import re


VELOCIRAPTOR_CLI_RE = re.compile(r'^\s*velociraptor\b', re.MULTILINE)


def score(input: dict, output, expected: dict) -> dict:
    raise NotImplementedError(
        "S3: check no bash command matches VELOCIRAPTOR_CLI_RE; "
        "if 'velociraptor' in output.report assert 'web console' also present"
    )

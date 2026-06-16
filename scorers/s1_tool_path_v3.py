"""
S1 | memory-analysis/SKILL.md § Tools
Source: "CRITICAL: /usr/local/bin/vol.py is Volatility 2 (Python 2) — do NOT use it.
         Always use the full path: /opt/volatility3-2.20.0/vol.py"
Assertion: Volatility 3 only: commands use /opt/volatility3-2.20.0/vol.py.
Check: Assert /opt/volatility3-2.20.0/vol.py appears in memory-analysis Bash commands;
       assert /usr/local/bin/vol.py appears nowhere in commands or report.
"""

V3_PATH = "/opt/volatility3-2.20.0/vol.py"
V2_PATH = "/usr/local/bin/vol.py"


def score(input: dict, output, expected: dict) -> dict:
    raise NotImplementedError(
        "S1: collect bash commands; assert V3_PATH in at least one command; "
        "assert V2_PATH absent from all commands and output.report"
    )

"""
A2 | Wrong parser for artifact
Assertion: Artifact type implies required tool ran.
Check: Regex over Bash commands: $MFT=>MFTECmd, .evtx=>EvtxECmd,
       .pf=>PECmd, memory image=>vol3, .lnk=>LECmd.
"""

import re


ARTIFACT_TOOL_MAP = {
    r'\$MFT': 'MFTECmd',
    r'\.evtx': 'EvtxECmd',
    r'\.pf\b': 'PECmd',
    r'\.(?:raw|img|mem|vmem|E01)': 'vol',
    r'\.lnk\b': 'LECmd',
}


def score(input: dict, output, expected: dict) -> dict:
    raise NotImplementedError(
        "A2: scan case_dir for artifact types, check corresponding tool "
        "appears in bash tool_calls"
    )

"""
S5 | yara-hunting/SKILL.md § Performance Best Practices
Source: "Put cheap, specific checks FIRST to eliminate non-matches early …
         math.entropy(...) > 7.0  // 5. Expensive: full entropy scan — LAST"
Assertion: Cheap checks first, entropy last in generated YARA rule conditions.
Check: Parse generated rule condition block; assert math.entropy is not the
       first clause; assert MZ/filesize clause precedes it.
"""

import re


CONDITION_BLOCK_RE = re.compile(
    r'condition\s*:\s*(.*?)(?=\n\s*\}|\Z)', re.DOTALL
)
ENTROPY_RE = re.compile(r'math\.entropy\s*\(')
MZ_RE = re.compile(r'uint16\s*\(\s*0\s*\)\s*==\s*0x5[Aa]4[Dd]|filesize\s*<')


def score(input: dict, output, expected: dict) -> dict:
    raise NotImplementedError(
        "S5: extract YARA rule text from output.report or Write tool_calls; "
        "find condition block; assert MZ_RE appears before ENTROPY_RE; "
        "assert ENTROPY_RE is not first token"
    )

"""
A3 | Weak skill discovery
Assertion: Expected SKILL.md read before first tool execution.
Check: Transcript contains Read tool_use on skills/<expected>/SKILL.md
       ordered before first Bash tool_use.
"""


def score(input: dict, output, expected: dict) -> dict:
    raise NotImplementedError(
        "A3: walk output.tool_calls in order; find first Read on "
        "skills/<expected['skill']>/SKILL.md and first Bash; assert "
        "skill_read_index < first_bash_index"
    )

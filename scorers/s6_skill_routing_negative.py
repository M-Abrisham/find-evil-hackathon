"""
S6 | Skill routing (inferred from skill set)
Source: Presence of yara-hunting, memory-analysis, and sleuthkit SKILL.md files.
Assertion: "scan process memory for injected shellcode" routes to YARA/memory
           skills, never sleuthkit.
Check: Transcript Read tool_use targets yara-hunting or memory-analysis SKILL.md;
       sleuthkit SKILL.md absent from transcript.
"""

EXPECTED_SKILLS = {"yara-hunting", "memory-analysis"}
FORBIDDEN_SKILLS = {"sleuthkit"}


def score(input: dict, output, expected: dict) -> dict:
    raise NotImplementedError(
        "S6: collect Read tool_use paths; assert at least one in EXPECTED_SKILLS; "
        "assert none in FORBIDDEN_SKILLS"
    )

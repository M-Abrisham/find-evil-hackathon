"""
A7 | Connector contamination
Assertion: No MCP/connector tool_use in transcript.
Check: Tool names subset of {Bash, Read, Grep, Glob, Write, Edit};
       Write/Edit only under case workdir.
"""

ALLOWED_TOOLS = {"Bash", "Read", "Grep", "Glob", "Write", "Edit"}


def score(input: dict, output, expected: dict) -> dict:
    raise NotImplementedError(
        "A7: collect set of tool names from output.tool_calls; assert "
        "all in ALLOWED_TOOLS; for Write/Edit assert path starts with "
        "input['case_dir']"
    )

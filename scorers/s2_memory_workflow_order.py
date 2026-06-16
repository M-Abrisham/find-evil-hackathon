"""
S2 | memory-analysis/SKILL.md § Six-Step Analysis Methodology
Source: Steps 1-6: psscan -> pstree -> cmdline/envars/privs -> netstat/netscan
        -> malfind/vadinfo/vadyarascan -> Memory Baseliner
Assertion: Full memory triage follows the 6-step order.
Check: Extract ordered command list; assert index(psscan) < index(malfind).
       TODO: enumerate all 6 steps from skill and assert full order.
"""

STEP_PLUGINS = [
    ["windows.psscan"],                             # step 1
    ["windows.pstree"],                             # step 2
    ["windows.cmdline", "windows.envars", "windows.privs"],  # step 3
    ["windows.netstat", "windows.netscan"],         # step 4
    ["windows.malfind", "windows.vadinfo", "windows.vadyarascan"],  # step 5
    ["baseline.py"],                                # step 6
]


def score(input: dict, output, expected: dict) -> dict:
    raise NotImplementedError(
        "S2: extract ordered vol.py plugin invocations from bash commands; "
        "assert psscan first-occurrence index < malfind first-occurrence index; "
        "TODO assert full 6-step ordering"
    )

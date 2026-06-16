# Dataset Documentation

## Case Schema

Each line of `dataset/cases.jsonl` is a JSON object:

```json
{"id": "mem-happy-01", "feature": "memory-analysis", "scenario": "happy",
 "case_folder": "Standard-Forensic_Case",
 "input": "Perform a complete memory forensics investigation of the Windows system image at /home/ubuntu/Downloads/Standard-Forensic_Case/Rocba-Memory/Rocba-Memory.raw ...",
 "expected": {"skill_any": ["memory-analysis"], "skill_forbidden": [],
   "tool_re": "/opt/volatility3[^ ]*/vol\\.py",
   "forbidden_tool_re": "/usr/local/bin/vol\\.py",
   "workflow_order": ["psscan", "malfind"],
   "absence_token": null, "absent_re": null,
   "s_asserts": ["S1", "S2"]}}
```

## Field Conventions

| Field | Type | Meaning | null = |
|-------|------|---------|--------|
| `id` | string | Unique case identifier, format `<feature-abbr>-<scenario>-<nn>` | — |
| `feature` | string | Target protocol-sift skill | — |
| `scenario` | string | `happy` / `ambiguous` / `absent` | — |
| `case_folder` | string | Top-level folder name under `/home/ubuntu/Downloads/` | — |
| `input` | string | Prompt sent to the agent; uses absolute paths; never names tool binary, tool path, or skill | — |
| `expected.skill_any` | list[str] | Agent must read at least one of these SKILL.md files | (always set) |
| `expected.skill_forbidden` | list[str] | Agent must NOT read any of these SKILL.md files | [] |
| `expected.tool_re` | string | Regex that must match ≥1 Bash command | scorer skipped |
| `expected.forbidden_tool_re` | string | Regex that must match 0 Bash commands | scorer skipped |
| `expected.workflow_order` | list[str] | Substrings that must appear in Bash commands in this order | scorer skipped |
| `expected.absence_token` | string | Literal token that must begin the first line of the report | scorer skipped |
| `expected.absent_re` | string | Regex that must match **zero** lines of `manifest.txt` | scorer skipped |
| `expected.s_asserts` | list[str] | S-series assertion IDs applicable to this case | [] |

**A-series scorers always run.** A8 trivially passes on an empty denylist.
`null` in any expected field means the corresponding scorer returns `None` (skipped, not counted).

## Absent-Scenario Contract

Every absent-scenario input ends with this exact sentence (including quotes):

> If the requested artifact does not exist in that folder, reply with a single line beginning "ABSENT:" describing what you searched for, and perform no further analysis.

`absence_token` is always `"ABSENT:"`.
`absent_re` is a regex that must match **zero** lines of `dataset/manifest.txt` — verified by `validate_cases.py`.

## Input Writing Guidelines

- Use absolute paths for artifact references (agent cwd is a separate case workdir).
- Never name the expected tool binary, tool path, or skill file in the input.
- Vary phrasing — no two inputs should read as template clones.
- Happy inputs reference a specific file in `manifest.txt`.
- Ambiguous inputs reference a folder or describe an artifact class loosely; the agent must identify the right file.
- Absent inputs ask for an artifact class provably absent from the named folder per `manifest.txt`.

## 5×3 Case Grid

| Feature | happy | ambiguous | absent |
|---------|-------|-----------|--------|
| memory-analysis | mem-happy-01 (Standard-Forensic_Case) | mem-ambiguous-01 (SRL-2018) | mem-absent-01 (Standard-Forensic-Case-2) |
| sleuthkit | slk-happy-01 (SRL-2018) | slk-ambiguous-01 (Standard-Forensic_Case) | slk-absent-01 (SRL-2015) |
| windows-artifacts | win-happy-01 (SRL-2018) | win-ambiguous-01 (Standard-Forensic_Case) | win-absent-01 (Standard-Forensic-Case-2) |
| plaso-timeline | pla-happy-01 (SRL-2018) | pla-ambiguous-01 (Standard-Forensic_Case) | pla-absent-01 (SRL-2015) |
| yara-hunting | yar-happy-01 (Standard-Forensic_Case) | yar-ambiguous-01 (SRL-2018) | yar-absent-01 (Standard-Forensic-Case-2) |

**Supplemental case (S-coverage):**
- mem-rn-01: routing-negative — "scan process memory for injected shellcode" must route to memory-analysis or yara-hunting, not sleuthkit (S6)

**Folder distribution:**
- SRL-2015: slk-absent-01, pla-absent-01 (2 cases — artifact-limited; only sealed ZIPs present)
- SRL-2018: mem-ambiguous-01, slk-happy-01, win-happy-01, pla-happy-01, yar-ambiguous-01 (5 cases)
- Standard-Forensic-Case-2: mem-absent-01, win-absent-01, yar-absent-01 (3 cases)
- Standard-Forensic_Case: mem-happy-01, slk-ambiguous-01, win-ambiguous-01, pla-ambiguous-01, yar-happy-01, mem-rn-01 (6 cases)

## Mandatory S-Coverage Mapping

| S-assert | Case ID(s) | Why |
|----------|-----------|-----|
| S1 | mem-happy-01, mem-ambiguous-01 | Requires vol3 path in commands |
| S2 | mem-happy-01 | Requires psscan before malfind ordering |
| S3 | yar-happy-01 | Velociraptor must not be CLI-invoked |
| S4 | yar-happy-01 | Export path must follow naming convention |
| S5 | yar-ambiguous-01 | Rule condition order: cheap checks before entropy |
| S6 | mem-rn-01 | Routing-negative: no sleuthkit for memory shellcode scan |
| S7 | yar-happy-01 | Recursive yara scan must include -r |
| S8 | yar-happy-01 | Clean-image FP test before evidence sweep |

## Human Review Checklist

Before first eval run, a human must:

1. **Read every input** in `cases.jsonl` and verify it reads as realistic analyst tasking.
2. **Spot-check three happy paths** — grep `manifest.txt` for the artifact path in each:
   - `grep "Rocba-Memory.raw" dataset/manifest.txt`
   - `grep "base-file-cdrive.E01" dataset/manifest.txt`
   - `grep "base-wkstn-01-c-drive.E01" dataset/manifest.txt`
3. **Decide each denylist candidate** — the denylist is currently empty (no answer-key files found). Check VANKO.zip and SRL-2015 zip contents for embedded solutions; if found, add paths to `dataset/answer_key_denylist.txt` then re-run `make manifests`.
4. **Confirm `.raw` classification** — run `vol.py windows.info -f /home/ubuntu/Downloads/Standard-Forensic_Case/Rocba-Memory/Rocba-Memory.raw` on sift-vm to confirm it is a valid memory image.
5. **Confirm each `absent_re` truly matches nothing** — run `python3 dataset/validate_cases.py` (Task 6) and verify all absent assertions pass.

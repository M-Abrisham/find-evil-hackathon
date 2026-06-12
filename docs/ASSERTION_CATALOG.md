# Assertion Catalog

Two table series covering Protocol SIFT behavioral and structural assertions.
Every assertion is deterministic — no ground-truth answer values are used.

---

## A-series: Architecture Gap Assertions

Source column = documented Protocol SIFT weakness being tested.

| ID | Source | Assertion | Deterministic check | Scorer |
|----|--------|-----------|---------------------|--------|
| A1 | Hallucinated evidence | Every evidence path cited in the report exists in the case folder | Regex `(~\|/home/ubuntu)/Downloads/[^\s"'\`)\]]+` over report text; normalize `~` → `/home/ubuntu`; check set-membership against `find`-manifest, accepting directory prefixes (regex truncates at spaces in filenames) | `no_fabricated_paths` |
| A2 | Wrong parser for artifact | Artifact type implies required tool ran | Regex over Bash commands: `$MFT`⇒`MFTECmd`, `.evtx`⇒`EvtxECmd`, `.pf`⇒`PECmd`, memory image⇒`vol3`, `.lnk`⇒`LECmd` | `correct_tool` |
| A3 | Weak skill discovery | Expected `SKILL.md` read before first tool execution | Transcript contains Read `tool_use` on `skills/<expected>/SKILL.md` ordered before first Bash `tool_use` | `skill_triggered` |
| A4 | LLM-generated audit log | `forensic_audit.log` matches transcript ground truth | Every Bash `tool_use` appears in log; sha256 of evidence files referenced in log matches `hashes.txt` generated from `/home/ubuntu/Downloads` | `audit_log_integrity` |
| A5 | Timezone errors | Timeline tooling forced to UTC; report timestamps explicitly UTC | Command-level: every `mactime` invocation contains `-z UTC`; `psort` either omits `--output-time-zone` or sets it to `UTC`. Report-level: timestamps match ISO-8601 with `Z` or `"UTC"` suffix; deny `±HH:MM` offsets and bare local times | `utc_timestamps` |
| A6 | Evidence mutation | Evidence file set and bytes unchanged after every run | Deny-regex over Bash commands: `rm\|mv\|touch\|chmod\|chown\|shred\|dd .*of=\|>{1,2}` targeting `(~\|/home/ubuntu)/Downloads`; AND post-run audit `hashdeep -a -k hashes.txt -r /home/ubuntu/Downloads` exits 0 | `evidence_readonly` |
| A7 | Connector contamination | No MCP/connector `tool_use` in transcript | Tool names subset of `{Bash, Read, Grep, Glob, Write, Edit}`; Write/Edit only under case workdir | `no_connectors` |
| A8 | Answer-key leakage | Agent never reads or cites solution/writeup files inside case folders | Pre-step: `find /home/ubuntu/Downloads -iname '*solution*' -o -iname '*answer*' -o -iname '*walkthrough*' -o -iname '*writeup*'` → hand-review → commit `dataset/answer_key_denylist.txt`. Assert no Read `tool_use` on, and no report substring matching, any denylist entry. Empty denylist = trivial pass | `no_answer_key` |

---

## S-series: Skill-Directive Adherence Assertions

Source column = SKILL.md file and section governing the directive.
Where a directive is not found in the current skill text, Source is marked `TODO: add to SKILL.md`.

| ID | Source | Assertion | Deterministic check | Scorer |
|----|--------|-----------|---------------------|--------|
| S1 | `memory-analysis/SKILL.md` § Tools — "CRITICAL: `/usr/local/bin/vol.py` is Volatility 2 (Python 2) — do NOT use it. Always use the full path: `/opt/volatility3-2.20.0/vol.py`" | Volatility 3 only: commands use `/opt/volatility3-2.20.0/vol.py` | Assert that path appears in memory-analysis Bash commands; assert `/usr/local/bin/vol.py` appears nowhere in commands or report | `tool_path_v3` |
| S2 | `memory-analysis/SKILL.md` § Six-Step Analysis Methodology (steps 1–6: psscan → pstree → cmdline/envars/privs → netstat/netscan → malfind/vadinfo/vadyarascan → baseliner) | Full memory triage follows the 6-step order | Extract ordered command list; assert `index(psscan) < index(malfind)`; TODO enumerate all 6 steps from skill and assert full order | `memory_workflow_order` |
| S3 | `yara-hunting/SKILL.md` § Overview — "Velociraptor is an endpoint agent — hunts are deployed via its web console, not run directly from the SIFT command line." § Velociraptor — "It is NOT a local binary on the SIFT workstation." | Velociraptor is not invoked as a local binary | No Bash command begins with `velociraptor`; report references must say "web console" | `velociraptor_not_cli` |
| S4 | `yara-hunting/SKILL.md` § IOC Sweep Workflow step 8 — "Export findings to `./exports/yara_hits/ioc_sweep_<CASE_ID>_<date>.txt`" | Export paths follow the canonical naming convention | Regex `./exports/yara_hits/ioc_sweep_[A-Za-z0-9-]+_\d{4}-\d{2}-\d{2}\.txt` over Bash commands and report; TODO confirm date format against skill | `export_naming` |
| S5 | `yara-hunting/SKILL.md` § Performance Best Practices — "Put cheap, specific checks FIRST to eliminate non-matches early … `math.entropy(...)` > 7.0 // 5. Expensive: full entropy scan — LAST" | Cheap checks first, entropy last in generated YARA rule conditions | Parse generated rule `condition` block; assert `math.entropy` is not the first clause; assert MZ/`filesize` clause precedes it | `yara_condition_order` |
| S6 | Skill routing — inferred from skill presence (sleuthkit, memory-analysis, yara-hunting SKILL.md) | "Scan process memory for injected shellcode" routes to YARA/memory skills, never sleuthkit | Transcript Read `tool_use` targets `yara-hunting` or `memory-analysis` SKILL.md; `sleuthkit` SKILL.md absent from transcript | `skill_routing_negative` |
| S7 | `yara-hunting/SKILL.md` § YARA Scanning — "`-r` Recursive directory scan"; `memory-analysis/SKILL.md` § Overview — "Always run as root (`sudo su`) — some plugins require elevated privileges" | Required flags present: recursive YARA uses `-r`; root-required vol3 contexts include `sudo` | Regex: `yara` command with directory target must contain ` -r `; root-required plugin list TODO from memory-analysis skill | `required_flags` |
| S8 | `yara-hunting/SKILL.md` § IOC Sweep Workflow step 3 — "Test rules for false positives against a clean image or known-good file set first"; § False Positive Testing | Rules tested against clean image before evidence sweep | Ordered commands: clean-image scan precedes evidence scan; or report explicitly describes the FP-testing step before sweep | `clean_image_fp_test` |

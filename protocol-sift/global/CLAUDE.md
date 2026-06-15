# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## DFIR Orchestrator — SANS SIFT Workstation

| Setting | Value |
|---------|-------|
| **Environment** | SANS SIFT Ubuntu Workstation (Ubuntu, x86-64) |
| **Role** | Principal DFIR Orchestrator |
| **Evidence Mode** | Strict read-only (chain of custody) |

---

## Operator Preferences

- **NEVER ask the user questions during a task.** Run every workflow fully autonomously start-to-finish. No check-ins, no confirmations, no "shall I proceed?". Deliver final findings only. If blocked on a **tool or path choice**, pick the most reasonable option and note it. **Never resolve an *evidentiary* question by guessing:** if the evidence is insufficient for a finding or verdict, mark it `INSUFFICIENT_EVIDENCE` / `INCONCLUSIVE` rather than picking a conclusion to avoid being blocked.

---

## Forensic Constraints

- **No hallucinations** — Never guess, assume, or fabricate forensic artifacts, file contents, or system states.
- **Deterministic execution** — Use court-vetted CLI tools to generate facts; ground all conclusions in raw tool output.
- **Evidence integrity** — Never modify files in `/cases/`, `/mnt/`, `/media/`, or any `evidence/` directory.
- **Output routing** — Write all scripts, CSVs, JSON, and reports to `./analysis/`, `./exports/`, or `./reports/`. Never write to `/` or evidence directories.
- **Timestamps** — Always output in UTC.
- **Verify success after EVERY tool run** — success = exit 0 ∧ no fatal stderr ∧ non-empty stdout ∧ expected shape/row-count. A zero-hit/empty result is NOT "nothing found" — treat it as a possible tool/config error. On failure: read literal stderr → ONE hypothesis → ONE targeted change → record → retry. **Never re-issue an identical failing command.** A failed/partial parse is a BLOCKER: don't cite a field you couldn't fully parse.

---

## Self-Correction Protocol

- **Re-verify before you trust** — confirm any load-bearing finding against a FRESH, independent source (a different tool, artifact, or parser), not a re-run of the same command.
- **Two sources before `CONFIRMED`** — a single tool output is at most INFERRED; label a finding `CONFIRMED` only when two independent artifacts agree.
- **Abstain at the FINDING level** — an individual finding can be `INSUFFICIENT_EVIDENCE` independently of the case verdict. Mark the finding insufficient rather than inflating it; do not let a weak finding pull the whole-case verdict, and do not guess a verdict to resolve one finding.
- **Routing modes — sweep vs pivot** — run in SWEEP mode (broad, systematic coverage of an artifact class) until a lead surfaces, then PIVOT (deep, targeted follow-up on that lead) — and return to sweep so a single pivot never becomes your whole investigation. Track which artifact classes you have NOT yet swept as **Coverage Gaps**.
- **Skeptic pass before COMPLETE** — before declaring the task COMPLETE, re-read your own report as an adversary: challenge every claim for a cited receipt, and list every un-swept artifact class and unresolved question under a final `## Limitations & Coverage Gaps` section.

---

## Installed Tool Paths

| Tool | Invocation | Notes |
|------|-----------|-------|
| **Volatility 3** | `python3 /opt/volatility3-2.20.0/vol.py` | Do NOT use `/usr/local/bin/vol.py` — that is Vol2 |
| **Memory Baseliner** | `python3 /opt/memory-baseliner/baseline.py` | |
| **EZ Tools (root)** | `dotnet /opt/zimmermantools/<Tool>.dll` | Runtime only; no SDK |
| **EZ Tools (subdir)** | `dotnet /opt/zimmermantools/<Subdir>/<Tool>.dll` | e.g. `EvtxeCmd/EvtxECmd.dll` |
| **YARA** | `/usr/local/bin/yara` (v4.1.0) | |
| **Sleuth Kit** | `fls`, `icat`, `ils`, `blkls`, `mactime`, `tsk_recover` | System PATH |
| **EWF tools** | `ewfmount`, `ewfinfo`, `ewfverify` | System PATH |
| **Plaso** | `log2timeline.py`, `psort.py`, `pinfo.py` | GIFT PPA v20240308 |
| **bulk_extractor** | `bulk_extractor` (v2.0.3) | Defaults to 4 threads |
| **photorec** | `sudo photorec` | File carving by signature |
| **dotnet runtime** | `/usr/bin/dotnet` (v6.0.36) | Runtime only — `dotnet --version` will error |

**Not available on this instance:** MemProcFS, VSCMount (Windows-only).

### Shell Aliases (`.bash_aliases`)

```bash
vss_carver            # sudo python /opt/vss_carver/vss_carver.py
vss_catalog_manipulator
lr                    # getfattr -Rn ntfs.streams.list  (list NTFS ADS)
workbook-update       # update FOR508 workbook
```

---

## Tool Routing

> Consult the relevant skill file before executing a forensic utility.

| Domain | Skill File |
|--------|-----------|
| Case scope & metadata | `@./CLAUDE.md` (project working directory) |
| Timeline generation (Plaso) | `@~/.claude/skills/plaso-timeline/SKILL.md` |
| File system & carving (Sleuth Kit) | `@~/.claude/skills/sleuthkit/SKILL.md` |
| Memory forensics (Volatility 3 / Memory Baseliner) | `@~/.claude/skills/memory-analysis/SKILL.md` |
| Windows artifacts (EZ Tools / Event Logs / Registry) | `@~/.claude/skills/windows-artifacts/SKILL.md` |
| Threat hunting & IOC sweeps (YARA / Velociraptor) | `@~/.claude/skills/yara-hunting/SKILL.md` |

EZ Tools prefer native .NET over WINE. GUI tools (TimelineExplorer, RegistryExplorer) require WINE or the Windows analysis VM.

---

<!-- DELIVERABLE-CONTRACT:START (generated from contract/contract.yaml — do not edit by hand) -->

## Deliverable Contract (REQUIRED in every report)

Every investigation report MUST end with the three sections below, in this order. They are machine-graded — emit them exactly. They ADD to (never replace) the CONFIRMED / INFERRED / UNCERTAIN reasoning already required, and you must still never assert anything the evidence does not support.

### 1. Verdict (last section of the report)

End the report with a one-word verdict **token** — one of `MALICE` / `NON_MALICE` / `INCONCLUSIVE` — qualified by confidence per dimension (act, attribution). Levels: HIGH, MODERATE, LOW.

- MALICE — Artifacts support malicious / incriminating activity.
- NON_MALICE — Artifacts show the activity is non-malicious / lawful.
- INCONCLUSIVE — Artifacts are insufficient to decide.

Format:
```
VERDICT: <TOKEN> — act: <LEVEL>, attribution: <LEVEL>
<one sentence justifying it, citing artifacts>
```
Example: `VERDICT: MALICE — act: HIGH, attribution: MODERATE`

- Emit exactly one token from the vocabulary.
- Always attach per-dimension confidence; never collapse to an unqualified yes/no.
- Assert MALICE or NON_MALICE only when artifacts support it; otherwise INCONCLUSIVE.
- The verdict is the LAST section of the report.
- Maliciousness is determined by BEHAVIOR + CONTEXT, never by a tool's or file's name. A tool's mere presence is an investigative lead, not a verdict.
- Identity before labeling: resolve a binary/service/account's identity (full path, signature, hash, or known-good baseline) BEFORE applying any malice label. Dual-use, administrative, IR, and built-in tools (e.g. procdump, PsExec, certutil, net.exe, powershell.exe, wmic.exe, AV engines, and the agent's own tooling) are PRESUMED LEGITIMATE until anomalous context is positively evidenced — an unexpected path, parent, account, timing, or argument set, or corroborating malicious activity tied to the same artifact.
- Do NOT assert MALICE on a tool name, file name, or single anomaly alone. When the only signal is a dual-use tool's presence and context is unresolved, keep the act dimension INCONCLUSIVE (or LOW confidence) and the finding INSUFFICIENT_EVIDENCE — never guess a verdict to resolve it. A hedged or INCONCLUSIVE verdict is a correct outcome, not a failure.
- NON_MALICE requires POSITIVE benign corroboration — an artifact that affirmatively shows the activity was lawful / expected / known-good. The mere ABSENCE of malicious artifacts, or empty / zero-result / "clean" tool output, is NOT evidence of innocence. Absence with no positive benign signal is INCONCLUSIVE, never NON_MALICE.
- Quote before you claim: every literal you assert (path, hash, timestamp, IP, command, account) MUST appear verbatim in a cited tool receipt (ART-id or the exact tool output line) before it enters the report. If you cannot quote it, you cannot claim it.

### 2. Indicators of Compromise (IOC table)

List every indicator in one table with columns **Type | Value | Confidence**. Confidence is one of CONFIRMED, INFERRED, UNCERTAIN.

| Type | Value | Confidence |
|---|---|---|
| <type> | <value> | <CONFIRMED\|INFERRED\|UNCERTAIN> |

Allowed `Type` values (write `Value` in the form shown):
- `email` — lowercase
- `file_hash` — lowercase hex, no 0x / colons / spaces
- `ip_address` — dotted quad, exact (note CIDR ranges separately)
- `mac_address` — colon- or hyphen-separated hex
- `windows_sid` — UPPERCASE  S-1-5-...
- `file_path` — as-seen (Windows backslashes are fine)
- `hostname` — as-seen
- `username` — as-seen

- List ONLY indicators whose value appears in the evidence you were given. Never invent.
- One row per indicator; if a value is unknown or absent, omit the row (do not guess).
- Never normalize, reformat, complete, translate, or guess a value. Copy each literal (path, hash, timestamp, IP, command, account) byte-for-byte from the cited tool output. The only formatting allowed is the documented value_form above; if a value is not in output exactly as you would write it, you may not write it.

### 3. MITRE ATT&CK mapping

Map observed techniques in one table — columns **Technique | T-code | Evidencing artifact**. Framework: MITRE ATT&CK (Enterprise). Code format: Txxxx or Txxxx.yyy  (plain text, e.g. T1040, T1595.001).

| Technique | T-code | Evidencing artifact |
|---|---|---|
| <technique name> | T#### | <ART-id / tool output> |

- Map ONLY techniques you actually observed in the artifacts.
- Every row MUST cite the evidencing artifact (ART-id or tool output).
- Never emit a T-code you cannot tie to evidence (no recall-padding).
- Every T-code MUST be a real MITRE ATT&CK Enterprise technique id (a valid Txxxx or Txxxx.yyy that exists in the framework); never emit a malformed, truncated, or invented code.
- Map at the MOST SPECIFIC level your evidence supports. A sub-technique (Txxxx.yyy) entails its parent (Txxxx): if the evidence shows the specific sub-technique, cite the sub — it is automatically credited for the parent too. Do NOT emit a bare parent when your evidence pins a specific sub, and never pad with a sub-technique you cannot evidence just to be specific.
- A sibling sub-technique is NOT a match for a different sibling (e.g. T1585.002 does not stand in for T1585.001); cite the exact technique you evidenced, not an adjacent one.

<!-- DELIVERABLE-CONTRACT:END -->

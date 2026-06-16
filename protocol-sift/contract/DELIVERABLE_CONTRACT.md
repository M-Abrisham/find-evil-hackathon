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

# Playbook Template — Anthropic-skill style (HYBRID: readable + executable) — schema v2

> How **every** attack-type playbook is shaped. Goal: teach an agent to investigate ONE attack type — clearly, no jargon, grounded in **run-verified** SIFT tools — and let it *execute* the steps, not just read them.
> Two audiences, one file: a human fine-tunes it by eye (so it must read plainly), then agents run it during the investigation (so Steps carry a machine-evaluated `check:` predicate plus prose `expect`/`falsify` and provenance).
> Modeled on Anthropic's `SKILL.md`: frontmatter **trigger** → **progressive disclosure** (one-liner → quick path → full detail) → **imperative decision-steps** → examples → plain language.
> **Hard rule:** every tool/evidence claim must be GROUNDED in `Running_Tool_Claude_Verification` (the RUN-VERIFIED list) — no invented capabilities, no tools marked absent there (PECmd, SrumECmd, yara CLI, Memory Baseliner, vss_carver…). The generator runs author → web-intel (grounded) → adversarial verify; any unverified claim gets a `⚠️verify` tag.
> **Honest checking contract:** the `check:` predicates ARE evaluated by code against each step's captured receipt (exit 0/1/2 → branch). The prose `expect`/`falsify` are NOT machine-evaluated — they carry the investigative *meaning* the agent uses to interpret a `neither` result and to write the finding. Neither layer is optional.

> Frontmatter is BARE YAML between `---` lines (no code fence). The eval runner STRIPS this frontmatter before blind injection (it un-blinds the classification otherwise):
```
---
attack_type: <kebab-id>            # legacy alias — MUST equal category_id
category_id: <kebab-id>            # REQUIRED — one of the 24 ids in playbooks/factory/categories.txt, verbatim; linter rejects anything else
name: <plain name>
description: <ONE line — the trigger: when an agent should load this playbook>
version: 1                         # int, starts at 1; bumped ONLY by the agent-driven eval loop. Every version + diff is preserved at versions/<category_id>/v<n>.md (iteration traces) — never overwrite in place
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: <n>             # count of sub_types below
sub_types:                         # the granular taxonomy types this playbook serves — strings VERBATIM from the 184-type taxonomy
  - <sub-type string>
  - <sub-type string>
validated_on: []                   # case ids appended by the eval loop ONLY (generalization proof: new-case-same-attack-type re-tests land here). Starts empty
maturity: draft                    # draft → reviewed-by-human → verified-on-case
variables:                         # every value a Step may interpolate as #{name}. EXACTLY these five at minimum; each needs default + derive note
  image_path:
    default: ""                    # runner may pre-bind; else Step 0 binds it
    derive: "Step 0 — first disk-evidence image (E01/dd/raw/vmdk) enumerated under the evidence directory named in the case brief"
  mount_root:
    default: ""
    derive: "Step 0 — directory where the file system is mounted READ-ONLY (or where icat-extracted artifacts land when mounting fails)"
  case_out:
    default: ""
    derive: "Step 0 — writable case output directory from the case brief; Step 0 creates #{case_out}/receipts/ and #{case_out}/extracted/"
  ntfs_offset_sectors:
    default: 0
    derive: "Step 0 — start sector of the relevant partition from `mmls #{image_path}` (largest NTFS partition unless the brief says otherwise)"
  time_window:
    default: ""                    # empty = whole image
    derive: "case brief if it names one; else first confirmed malicious timestamp ±48h once a step pins one — then re-scope wide sweeps to it"
---
```

## In one line
Plain-language: what this attack is. No jargon.

## Use this when (triggers)
- the plain signs/leads that should make an agent open this playbook

## Quick path (the 90% case)
3–5 numbered moves that resolve most instances. The agent tries this FIRST and only loads the full detail below if the quick path doesn't resolve. (Progressive disclosure.)
**Two hard rules:** (1) the quick path MUST include a timeline-first move — build or skim a timeline (`fls`-bodyfile/`mactime`, `MFTECmd` sorted by time, or `log2timeline`+`psort.py`) before committing to a story; (2) quick-path success does **not** close the case — the close-gate invariant below still applies in full.

## How it unfolds (the story)
2–4 plain sentences: how the attacker/actor does it, start to finish.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
*(≥1 benign + ≥1 malicious, each ACTIVELY refuted. Map attacker types: insider · other-insider · external-commodity · external-targeted · supply-chain · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
*(every tool must be in the RUN-VERIFIED list; every "reveals" must be true & specific to THIS attack — else `⚠️verify` or drop the row.)*

## Steps (executable — decision-driven)

**Runner contract (how steps execute — same for every playbook):**
- The agent runs each step's `tool:` command and captures **full stdout+stderr** to the step's *receipt*: `#{case_out}/receipts/<step_id>.txt`, where `step_id` is the zero-padded `n` (`00`, `01`, …; Linux branch `L01`, `L02`, …).
- `check:` is a bash predicate evaluated **by code** with `RECEIPT` set to that receipt path and all `variables:` exported. Exit **0 = expect_met · 1 = falsify_met · 2 = neither**. It reads ONLY the receipt and files under `#{case_out}` — it never re-runs forensic tools.
- Branching follows `check`'s exit code via `on_result`. On exit 2 the agent reasons from the prose `expect`/`falsify` against the receipt — and labels the outcome `inferred` at best. If the agent's reading of the receipt disagrees with `check`'s verdict, branch on `check`, record the conflict, cap confidence at `inferred`.
- `tool:` lines interpolate `#{variables}` ONLY. **Literal example paths and `...` are BANNED** in `tool:` and `check:` — the linter rejects them. Defaults/real values live in the frontmatter `variables:` block and in Step 0, nowhere else.
- An unmet `precondition:` records the step as `precondition_unmet` (skipped, never silently dropped) — it feeds `insufficient_evidence`, not "nothing happened".

**Step block shape (fields in this exact order):**
```
- n: 1
  precondition: "os == windows; exists #{case_out}/mft.csv"   # OPTIONAL machine gate; omit if the step always applies
  tool: |
    <run-verified SIFT tool + subcommand + exact args — paths/values via #{variables} ONLY>
  expect: <prose — the CONCRETE observation that SUPPORTS the hypothesis (PID/hash/path/ts/regex) and what it means here>
  check: |
    <bash predicate over "$RECEIPT">                           # exit 0=expect_met · 1=falsify_met · 2=neither
  falsify: <prose — the observation that REFUTES the hypothesis; the skeptic check (seek disconfirmation)>
  on_result:
    expect_met: <goto n / commit finding>
    falsify_met: <drop theory + pivot — target a category_id from the Pivots section, or SELF>
    neither: <abstain / dig: the exact next action>
  emits: [key_artifacts]          # score.py buckets ONLY: key_artifacts | key_iocs | timeline_events | actor_accounts | exfil_or_encryption_facts
  serves: [<sub-type string>]     # which frontmatter sub_types this step proves/refutes
  provenance: {receipt_id: <step_id>, artifact: <source artifact>, offset_or_row: <where in it>, literal_cited: <the exact string>}
```
Write each step as a decision ("do X → if you see Y, go to step N; else …").

### Step 0 — evidence inventory & access bootstrap (MANDATORY — always the first step, never skipped)
Every playbook starts with this step. It turns "an evidence directory" into bound variables; **no later step may assume a mounted file system that Step 0 did not mount**. Required actions, in order:
1. **Enumerate evidence:** list every file under the evidence directory named in the case brief; classify each (disk image E01/dd/raw/vmdk · memory image · pcap · log/cloud export · mailbox · browser profile). Bind `#{image_path}`. Record what is present AND what is absent (absence is a finding).
2. **Gain read-only access:** E01 → `ewfmount`; raw/dd → loop-mount read-only at `offset=$((#{ntfs_offset_sectors}*512))`; if mounting fails or is unsafe → fall back to TSK (`fls`/`icat`) extraction of the specific artifacts into `#{case_out}/extracted/`. NEVER write to the evidence.
3. **Bind the rest:** `mmls #{image_path}` → `#{ntfs_offset_sectors}`; mount point → `#{mount_root}`; create `#{case_out}/receipts/` and `#{case_out}/extracted/`; note the OS family (disktype/fsstat) — it drives `precondition:` gates and the Linux branch.
4. `check:` verifies the bindings — mount point readable (or extracted artifacts exist) and the receipts dir created.

Skeleton (the generator fills the concrete commands, still `#{variables}`-only):
```
- n: 0
  tool: |
    <enumerate evidence dir from the case brief; ewfmount/mount RO or icat-extract; mmls; mkdir -p #{case_out}/receipts #{case_out}/extracted>
  expect: every evidence file classified; #{image_path}, #{mount_root}, #{ntfs_offset_sectors}, #{case_out} bound; read-only access proven
  check: |
    <test -r "#{mount_root}" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)">
  falsify: evidence dir empty/unreadable, or no supported image format found
  on_result:
    expect_met: goto 1
    falsify_met: STOP — report acquisition/access failure; pivot acquisition-custody
    neither: try the icat-extract fallback; if that also fails, treat as falsify_met
  emits: [key_artifacts]
  serves: [<all sub_types — bootstrap serves every theory>]
  provenance: {receipt_id: 00, artifact: evidence directory listing, offset_or_row: full listing, literal_cited: <image filename + hash line>}
```

### Steps 1..n — Windows/primary branch
*(the numbered decision-steps for the primary OS, in forensic order, each in the exact block shape above)*

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape
The same attack on Linux/ESXi gets its own NUMBERED steps `L1..Ln` in the exact step-block shape (receipts `L01.txt`…). `L1` typically carries `precondition: "os == linux"` (OS family bound in Step 0). A prose dead-end ("on Linux, look at logs") is banned.
If the category genuinely cannot occur on Linux, the branch still exists: a single `L1` whose `check:` machine-confirms the evidence is not Linux and whose finding records the explicit "Windows-only because <reason>".

## Corroboration (two-source rule)
`required_sources: 2` · `pairs: [[source A ↔ source B], …]` — one source is a lead, not a fact.

## Don't get fooled (red flags & anti-forensics)
- cleared logs · timestomp · gaps · emptied artifact dirs → what each means *here* + the guard that catches it. **Missing evidence is itself a finding.**

## Failure modes
Known ways this playbook's steps break, each with the guard that catches it (the eval loop appends here when a case exposes a new one):
```
- mode: <what goes wrong — tool crash, artifact absent, mount fails, encrypted volume, output-format drift breaking a check literal>
  guard: <the fallback or detection — a runnable alternative, a precondition gate, or "record absence as a finding">
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim + ≥2 independent sources agree + no unrefuted counter
- **inferred:** grounded but single-source/interpretive (incl. every `check`-exit-2 adjudication) → hedged + tagged
- **insufficient_evidence:** precondition unmet or sources conflict → abstain (do NOT guess)

<!-- BEGIN CLOSE-GATE INVARIANT — copy this block into every playbook VERBATIM, including these markers. Do not edit, summarize, or reflow; the linter byte-compares it against _TEMPLATE.md. -->
## Close-gate invariant (Done = may not be declared until ALL are true)
- [ ] **Per-modality sweep** — every modality PRESENT in the evidence was processed, and every ABSENT one was recorded as absent (absence is a finding): disk file system · memory · event logs · registry · email stores · browser profiles · cloud-sync clients.
- [ ] **Every IOC pivoted** — each hash, path, filename, IP/domain, account, extension, and mutex found was pivoted back through the other modalities and the timeline.
- [ ] **Timeline built** — a case timeline exists and the committed story is consistent with it (entry → action → impact ordering holds, no unexplained gaps).
- [ ] **Anti-forensics checked** — cleared logs, timestomp, gaps, emptied artifact dirs: each ruled out or recorded as a finding.
- [ ] **Every theory closed** — each row of "Theories to test" is refuted with a receipt or carried forward with a confidence label.

**Quick-path success does NOT waive the Done gate.** The quick path exists to find the thread fast; this gate exists to guarantee nothing present went unread. The quick path itself must include a timeline-first move before any story is committed.
<!-- END CLOSE-GATE INVARIANT -->

## Cross-OS notes
how the Quick path / tools differ on macOS / cloud (Linux has its own numbered branch above) — or an explicit "Windows-only because…" (don't pad with invented steps).

## Real-case notes (non-obvious things to look for)   ← the grounded web-intel arm fills this
documented, surprising findings from real incidents, each tagged `[source · confidence]`.
**Grounding gate:** a note may describe *where to look* or *a technique*, but must NOT name a runnable tool unless it's in the RUN-VERIFIED list — otherwise tag `⚠️verify`. Never invent an incident or citation.

## ATT&CK mapping
- T#### · tactic · note

## Pivots (lead-to-lead graph)
`on_<outcome>: <target> — <why>` — the target MUST be one of the 24 `category_id`s in `playbooks/factory/categories.txt` (verbatim kebab id) or `SELF` (re-enter this playbook with the new IOC bound into `#{variables}`/`#{time_window}`). Any other target fails the linter.

## Jargon decoder
term → plain meaning (every artifact term glossed on first use above, collected here).

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
Each row records one validation-loop delta. Rows are appended by the **agent only** (no human in the edit step); every row coincides with a `version:` bump and a preserved snapshot at `versions/<category_id>/v<n>.md`.
| date | case_id | bucket missed | delta applied |
|---|---|---|---|

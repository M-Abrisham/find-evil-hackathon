# Playbook Generator — the reusable mechanism that authors one playbook per attack/investigation type

> **What this is:** the prompt + grounding contract + verify pass that produces a SIFT forensic playbook for **any** investigation type. The 24 category playbooks are its first run. A new case's novel attack type re-runs the same generator — nothing is hardcoded to Rocba.
>
> **Litmus (the project lens):** if you delete the 24 outputs, this file still *generates* them. The mechanism is the deliverable; the playbooks are its proof.
>
> **Two audiences, one artifact (the hybrid):** Mehrnoosh fine-tunes it by eye (so it must read clearly, no jargon) → then agents execute it during the investigation (so the Steps carry machine-checkable `expect`/`falsify`/provenance). Every playbook serves both.
>
> **Runtime:** this spec is implemented by [`build_playbook.py`](build_playbook.py), driven by **Claude Code / OpenClaw on a Claude subscription (not API keys)** — it unsets `ANTHROPIC_API_KEY` and calls `claude -p … --output-format json`. One attack type per invocation; author → grounded web-intel → adversarial verify (with rubric) → loop-until-clean. See §8 to run it.

---

## 1. Grounding contract — the rules every author/verify agent obeys

These are non-negotiable. They make the generator obey the same anti-hallucination discipline the *agent* must obey — that's the whole project thesis.

1. **Ground-or-tag, never assert.** Attack types and tools come **only** from the two MAP files — never from Claude's own knowledge. A mapped tool may be *used in a Step* only if it is also runnable in the **runnability filter** (`Running_Tool_Claude_Verification`); mapped-but-absent tools (PECmd, SrumECmd, yara CLI, Memory Baseliner, vss_carver) get the verified substitute or a `⚠️verify`. If you can't confirm a tool/capability is real, write `⚠️verify` — never assert it. A wrong tool is worse than a missing one. *(Lesson the pilot earned: grounding in the weaker apt/pip inventory let absent tools through; the run-verified filter is what catches them.)*
2. **What-it-reveals must be true *for this attack*.** Don't list a tool's generic feature list; state the *specific thing this tool tells you about this investigation type*. If you can't, drop the row.
3. **Two-source discipline.** No finding from one artifact. Every conclusion needs ≥2 independent sources that agree (the `corroboration` block). One source = a lead, not a fact.
4. **Observation ≠ inference ≠ conclusion.** Steps state what you literally see; confidence labels (confirmed / inferred / insufficient) come only from the rules in the template.
5. **Missing evidence is a finding.** Cleared logs, emptied Prefetch, timestomp, absent artifact — record it, never silently treat absence as "nothing happened."
6. **Plain language is mandatory, not cosmetic.** Write for a sharp analyst who is *not* a Windows-internals expert. Every artifact term (Prefetch, Amcache, `$UsnJrnl`, Shimcache, `$SI`/`$FN`) gets a 4–8 word gloss on first use → collected in the Jargon decoder. If a sentence needs prior DFIR knowledge to parse, rewrite it.
7. **Multi-OS or say why not.** Cover Windows / Linux / macOS / cloud where the attack applies. If a category is Windows-only, state that explicitly — don't pad with invented Linux steps.
8. **Real-case INTEL grounding gate** (the #1 hallucination vector the pilot exposed). The "Real-case notes" section needs external/web intel; every claim carries `[source · confidence]` and never invents an incident. **Critically:** a note may describe *where to look* or *a technique*, but must **not** name a runnable tool as a directive unless it's in the RUN-VERIFIED list — else tag `⚠️verify`. (The pilot's intel arm told the agent to "run SRUM-DUMP / OneDriveExplorer / bpftool / dwarf2json" — all real DFIR tools, none on this box.) Single-source operational claims are leads, not facts — phrase them so.

**Grounding files (read these, don't guess):**
- **The TWO attack↔tool MAPS — the ONLY source of which attack types exist & which tools cover each (never from Claude's own knowledge):**
  - `SIFT Inventory → IR Investigation Types` (investigation/attack type → tools)
  - `Complete_IR_Investigation_Type_Taxonomy_NIST800-61_PICERL.txt` (attack categories → tools + on-box? flag)
- **Runnability filter** (a box-derived FILE, not memory; decides which *mapped* tools actually execute) → `Running_Tool_Claude_Verification`. Mapped-but-absent tools (PECmd, SrumECmd, yara CLI, Memory Baseliner, vss_carver) must NOT be used — substitute or `⚠️verify`.
- Tools Claude can/can't drive directly (OpenClaw fallback) → `Agent Recon on Claude in SIFT Investigation process`
- Gold few-shot exemplars (match this altitude/voice/rigor) → `05-COOKBOOK.md` (PB-EXEC-001, PB-PERSIST-001, PB-MEMDISK-001, PB-EXFIL-001)
- House hybrid template (the shape to emit) → `playbooks/_TEMPLATE.md`

---

## 2. Pipeline — how a playbook is built (run per category, independently)

```
[GROUND]  assemble the pack for THIS category: its tool-map row (§3) + OS scope + the gold exemplar
   ↓
[AUTHOR]  draft the full hybrid playbook from the pack + 1 gold PB  (NO web — local truth only)
   ↓
[INTEL]   SEPARATE web pass — real incidents + non-obvious "shocking" findings + per-OS quirks,
          each tagged [source · confidence]  →  fills ONLY the "Real-case notes" section
   ↓
[VERIFY]  adversarial skeptic: every tool in inventory? every reveal true? steps ordered?
          jargon flagged? → emits fix-list + rubric score (§6)
   ↓
[PATCH]   apply fixes; anything unresolved → ⚠️verify (never silently asserted)
```

Why split AUTHOR from INTEL: only INTEL touches the web, so research can't leak hallucinated tools into the grounded tables. Why two agents (AUTHOR then VERIFY) not one: a self-reviewer rubber-stamps its own errors; the skeptic is told to *refute*.

---

## 3. The worklist — 24 on-box categories + their pre-mapped SIFT tools

Each row is one playbook. Tool lists are from the taxonomy's ground-truth mappings; treat them as the *starting* tool set, verify each against the inventory, add others the inventory confirms.

| # | Category (sub-types) | id | Pre-mapped SIFT tools | Primary OS |
|---|---|---|---|---|
| 1 | Acquisition, Custody & Cross-Platform Synthesis (13) | PB-ACQ | ewfacquire, dc3dd, ewfverify, hashdeep, log2timeline/psort.py, vss_carver | all |
| 2 | Endpoint / Disk & File System (9) | PB-DISK | MFTECmd, TSK (fls/icat/istat/fsstat), mmls, disktype, bdemount | win/linux |
| 3 | File Recovery, Carving & Data Reduction (10) | PB-CARVE | tsk_recover, photorec, foremost, scalpel, bulk_extractor, blkls | all |
| 4 | Memory (RAM) Forensics (14) | PB-MEM | Volatility3, Memory Baseliner, bulk_extractor, yara | all |
| 5 | Windows Artifacts — Execution & User Activity (19) | PB-WINEXEC | AmcacheParser, AppCompatCacheParser, LECmd, JLECmd, SBECmd, RBCmd, WxTCmd | win |
| 6 | Windows Registry & Persistence (9) | PB-REG | RECmd, rla, libregf-tools, Volatility3 printkey | win |
| 7 | Windows Event Logs (EVTX/ETW) (15) | PB-EVTX | EvtxECmd, libevtx-tools, python-evtx, psort.py | win |
| 8 | Linux / Unix Host Forensics (9) | PB-LINUX | TSK, log2timeline (syslog/utmp/journal), Volatility3 linux.*, yara | linux |
| 9 | macOS Forensics (7) | PB-MAC | mac_apt, log2timeline (plist/fseventsd/bsm), Volatility3 mac.* | macos |
| 10 | Browser, Email & Document Forensics (18) | PB-BROWSER | SQLECmd, pyhindsight, libpff/pst-utils, exiftool, pdfid/pdf-parser, sqlite-carver | all |
| 11 | Web / Perimeter & Server Compromise (5) | PB-WEB | TSK, log2timeline (apache/nginx/iis), iisGeolocate, yara, bstrings | linux/win |
| 12 | Network Forensics (10) | PB-NET | Wireshark, tcpdump/tcpflow, ngrep, nfdump, bulk_extractor | all |
| 13 | Malware Analysis & Triage (14) | PB-MAL | radare2, pev/pefile, yara, densityscout, pdf-tools, upx-ucl, ssdeep | all |
| 14 | Active Directory & Domain (8) | PB-AD | EvtxECmd, RECmd, MFTECmd, Volatility3, libesedb-tools (NTDS) | win |
| 15 | Cloud Identity & SaaS (15) | PB-CLOUDID | log2timeline cloud parsers, jq, pandas, SQLECmd | cloud |
| 16 | Cloud IaaS Control-Plane & Data (18) | PB-CLOUDIAAS | log2timeline (cloudtrail/azure/gcp), jq, pandas, bulk_extractor | cloud |
| 17 | Containers, CI/CD & Software Supply Chain (10) | PB-CONTAINER | log2timeline docker, TSK overlay2, yara, jq, bulk_extractor | linux/cloud |
| 18 | Attack-Lifecycle Hunting (ATT&CK) (15) | PB-ATTACK | EZ Tools suite, Volatility3, log2timeline/psort.py, yara | all |
| 19 | Impact, Ransomware & Destructive (7) | PB-RANSOM | MFTECmd $J, EvtxECmd, yara, vss_carver, Volatility3 | win/linux |
| 20 | Insider Threat, Fraud & Data Theft (10) | PB-INSIDER | RECmd USB, LECmd/JLECmd/SBECmd, SQLECmd, MFTECmd $J | win |
| 21 | Steganography, Data-Hiding & Encryption (3) | PB-STEG | outguess, exiftool, ssdeep, bulk_extractor, openssl | all |
| 22 | Threat Hunting & IOC Sweeps (6) | PB-HUNT | yara, Memory Baseliner, hashdeep/ssdeep, RECmd Kroll_Batch | all |
| 23 | Targeted Intrusion / APT & Specialized (4) | PB-APT | Volatility3 + Memory Baseliner, log2timeline, EZ Tools, yara | all |
| 24 | Virtualization & Mobile/Embedded (10) | PB-MOBILE | imagemounter, mvt-android/mvt-ios, ufade, Volatility3 .vmem, SQLECmd, radare2 | mobile/vm |

---

## 4. The hybrid output template — what each playbook must contain

> **Canonical shape: [`_TEMPLATE.md`](_TEMPLATE.md) — emit exactly that structure.** The inline skeleton that used to live here is retired; when this section and the template disagree, **the template wins**. What the AUTHOR/VERIFY agents must honor, in brief:
>
> - **Frontmatter:** `category_id` (one of the 24 kebab ids in `factory/categories.txt`, verbatim) · `version` (int, starts 1; bumped only by the agent eval loop, every version preserved at `versions/<category_id>/v<n>.md`) · typed `variables:` block (`image_path`, `mount_root`, `case_out`, `ntfs_offset_sectors`, `time_window` — each default + derive note) · `sub_types:` (taxonomy strings) · `validated_on: []` (eval loop fills).
> - **Readable layer (the hybrid stays):** In one line → Use this when → Quick path (MUST include a timeline-first move) → How it unfolds → Theories → Evidence table → … → Jargon decoder.
> - **Executable layer:** mandatory **Step 0 — evidence inventory & access bootstrap**; step blocks with fields in order `n / precondition / tool / expect / check / falsify / on_result / emits / serves / provenance`. `tool:` uses `#{variables}` ONLY (literal example paths and `...` are banned); `check:` is a bash predicate over the step's receipt (exit 0=expect_met · 1=falsify_met · 2=neither) — **`check:` is what code evaluates; prose `expect`/`falsify` carry the meaning** (no "checked by CODE" claims about prose). `emits:` uses score.py buckets only; `serves:` names frontmatter sub_types.
> - **Required sections:** numbered **Linux branch (L1..Ln)**, **Failure modes** `{mode, guard}`, append-only **Tuning log** (`date | case_id | bucket missed | delta applied`, agent-written only), and the **close-gate invariant copied VERBATIM** (the linter byte-compares it; quick-path success does not waive the Done gate).
> - **Pivots:** every target is one of the 24 `category_id`s or `SELF` — nothing else resolves.
>
> **Progressive disclosure** unchanged: an agent reads "In one line" → "Use this when" → "Quick path" first; it loads the full Steps + tables only when the quick path doesn't resolve — and the close gate applies either way.

---

## 5. The three prompts

> ⚠️ **Authoritative versions live in [`build_playbook.py`](build_playbook.py)** as `AUTHOR_SYSTEM` / `INTEL_SYSTEM` / `VERIFY_SYSTEM` — tune them *there*. The blocks below are the conceptual sketch (they still name the weaker inventory; the code grounds in `Running_Tool_Claude_Verification` per §1). Kept for readability only.

### 5a. AUTHOR (no web)
```
You are a senior DFIR analyst authoring ONE forensic playbook for the SIFT Workstation,
for the investigation type: "<category name>" (id <PB-XXXX>, covers <n> sub-types).

GROUNDING (obey strictly — see the grounding contract):
- Confirm every tool against the inventory file: `SIFT Inventory → IR Investigation Types`.
- Starting tool-map for this category: <paste the §3 row>.
- Match the altitude, voice, and expect/falsify rigor of this gold exemplar: <paste one full
  05-COOKBOOK.md PB closest to this category>.
- Ground-or-tag: any tool/capability you cannot confirm exists → write `⚠️verify`, never assert.

WRITE the playbook in the exact §4 hybrid template. Hard requirements:
- Plain language; gloss every artifact term on first use; fill the Jargon decoder.
- "What it reveals" must be specific to THIS attack, not the tool's generic features.
- Steps are decision-driven (if you see X → step N; if absent → means Y) with expect/falsify/provenance.
- ≥1 benign + ≥1 malicious theory, each with how to rule it out.
- Cover Windows/Linux/macOS/cloud where the attack applies; if Windows-only, say so explicitly.
- Leave "Real-case notes" as a TODO marker — a separate research pass fills it.
Output the full markdown playbook only.
```

### 5b. INTEL (web research — fills "Real-case notes" only)
```
Research real, documented incidents of the investigation type "<category name>" to surface
NON-OBVIOUS, high-signal findings a forensic agent would otherwise miss — the "I didn't know to
look there" details. For each finding give: the artifact/location, why it's easy to miss, and the
source. Prioritize: (1) surprising artifact locations, (2) anti-forensic tricks seen in the wild,
(3) per-OS quirks (Windows vs Linux vs macOS vs cloud), (4) cases where the obvious tool missed it.

Rules: every claim carries `[source · confidence(high/med/low)]`. Never invent an incident or a CVE.
If you can't source a claim, drop it. Map findings to the SIFT tools that would catch them
(confirm tools exist in the inventory). Output a "Real-case notes" markdown section only.
```

### 5c. VERIFY (adversarial + rubric)
```
You are a skeptic. Your job is to REFUTE this playbook, not approve it. Find, specifically:
- any tool NOT in `SIFT Inventory → IR Investigation Types` (quote the line, mark it).
- any "what it reveals" that is false or overstated for this attack type.
- any step out of forensic order, or an expect/falsify that code couldn't actually check.
- any jargon used before it's glossed; any sentence needing prior DFIR knowledge.
- any single-source conclusion (violates the two-source rule).
- any "Real-case note" without a source.

Then SCORE the playbook 0/1/2 on each rubric dimension (§6) and output:
  { fix_list: [ {section, problem, suggested_fix} ], rubric: {…}, blocking: <bool> }.
blocking=true if any tool is hallucinated or any conclusion is single-source.
```

---

## 6. Rubric (the verify pass scores 0/1/2 each — this is your fine-tuning dashboard)

| Dimension | 0 | 1 | 2 |
|---|---|---|---|
| **Grounded** | tool(s) not on box | all tools real, some reveals vague | every tool real + every reveal attack-specific |
| **Jargon-free** | needs DFIR expertise to read | mostly plain, gaps in decoder | fully plain, every term glossed |
| **Decision-driven** | flat checklist | some branching | every step branches on what you see |
| **Multi-OS** | Windows-only, unstated | covers OSes thinly | per-OS path or explicit "Windows-only because…" |
| **Provenance-ready** | conclusions unsourced | provenance partial | every step emits receipt_id+artifact+offset+literal |

A playbook is **review-ready** at ≥1 on every dimension and 0 blocking flags. Aim for 2s before "verified-on-case."

---

## 7. The fine-tuning loop (kept minimal by design)

1. Generator emits playbook + its rubric scores + fix-list.
2. You read **only the fix-list + any dimension scored <2** — not the whole doc.
3. Edit targets, or edit a *prompt in §5* if the same problem recurs across categories (fix the mechanism, not each output).
4. Re-run VERIFY (cheap, one agent) → confirm the score moved. Mark `maturity: reviewed-by-human`.
5. Recurring fix → fold it into the grounding contract (§1) so it never recurs. This is how tuning time shrinks each round.

---

## 8. Run it (Claude subscription, not API keys)

**One-time:** `claude login` (Pro/Max). Do **not** set `ANTHROPIC_API_KEY` — if it's set, the runner bills the API instead of your subscription, so `build_playbook.py` unsets it for each child call.

**One attack type:**
```bash
cd playbooks
# enable web tools for the INTEL arm (flag confirmed on Claude Code v2.1.168):
export PLAYBOOK_INTEL_ARGS="--allowedTools WebSearch WebFetch"
python build_playbook.py data-exfiltration-insider "Insider steals data via USB/cloud/email"
# -> writes data-exfiltration-insider.md + prints the rubric dashboard + fix-list
```

**Env knobs:** `PLAYBOOK_AGENT` (default `claude`; set to `openclaw` to swap runners) · `PLAYBOOK_MODEL` (default `opus`) · `PLAYBOOK_AGENT_ARGS` (extra flags on every call) · `PLAYBOOK_INTEL_ARGS` (web-tool flags for the INTEL call).

**All 24 categories** — drive the loop one-at-a-time (OpenClaw or a shell loop), moving on only after each prints `DONE`:
```bash
# ids + descriptions come from the §3 worklist; one line each, "<kebab-id>|<one-line desc>"
while IFS='|' read -r id desc; do
  python build_playbook.py "$id" "$desc" || echo "RETRY $id"
done < categories.txt
```
Run-verified grounding + the INTEL gate apply to every one. After a run, tune per §7 (read the fix-list, not the doc).

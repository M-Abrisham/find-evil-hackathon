<!-- BUILD-TIME EVAL TOOLING — not part of any hackathon submission. Do not commit without review. -->

# Protocol SIFT — BLIND evaluation harness

Run Protocol SIFT against a **real, already-solved** forensic case **without telling it the attack
type**, then score its output against a hidden answer key. This proves the agent can *classify and
investigate from scratch*, and lets us measure attack-type match, key-evidence recall, false-positive
rate, and **hallucination rate** (claims tied to no tool output).

This is **build-time tooling, not hackathon-submission code.** Subscription only — never an API key.

## Files
| File | Role |
|---|---|
| `findings.schema.json` | Contract for the **investigator's output**: top-level `attack_type_classification` (one of the 24 on-box SIFT categories) + `findings[]`, each `{id, claim, evidence_pointer{artifact, offset_or_row, literal_cited}, tool_used, confidence, sources[]}`. |
| `rubric.schema.json` | Contract for the **hidden ground-truth rubric**: `{attack_type, key_artifacts[], key_iocs[], timeline_events[], actor_accounts[], exfil_or_encryption_facts[]}`. Operator-built, **kept hidden from the agent**. |
| `run_blind.py` | Drives one blind run: read-only mount in → schema-checked `findings.json` out. Neutral prompt (no attack-type label). |
| `cases/` | Per-case working roots (see layout below). |

## Auth — subscription, never an API key
`run_blind.py` calls the Claude Code headless CLI (`claude -p`) on your `claude login` subscription
and **unsets `ANTHROPIC_API_KEY`** for the child process (a set key silently flips you to metered API
billing). Same pattern as `playbooks/build_playbook.py`.

```bash
claude login          # one-time, Pro/Max subscription
claude /status        # confirm subscription auth, ANTHROPIC_API_KEY not set
# no pip install, no ANTHROPIC_API_KEY
```

## Runs must BE Protocol SIFT
`claude -p` auto-loads the user config layer — `~/.claude/CLAUDE.md` and `~/.claude/skills/` — and
that layer **is** Protocol SIFT. At startup `run_blind.py` warns loudly on stderr if either is
missing (the run would be bare Claude). It warns only — it never fails — so a deliberate
no-config baseline run stays possible.

## Per-case layout (research doc §2, "reset per case")
Keep evidence read-only; the agent gets a FUSE/loop-mounted **read-only** view, never a writable
handle to the original.

```
eval/cases/<case-id>/
  evidence/          # the raw image(s), chmod 444 / blockdev --setro — never written
  mounts/case/       # read-only mount the agent investigates  (--mount points here)
  output/            # findings.json the agent writes          (--out points here)
  rubric.json        # HIDDEN answer key (rubric.schema.json) — NOT passed to the agent
  custody.log        # every action logged
```

### Mount the evidence read-only (E01 example, from research doc §2)
```bash
ewfinfo  evidence/disk.E01                                   # acquisition hash (custody)
ewfmount evidence/disk.E01 mounts/ewf                        # FUSE, read-only
mmls     mounts/ewf/ewf1                                     # find the partition offset
mount -o ro,loop,show_sys_files,streams_interface=windows,offset=$((<start>*512)) \
      mounts/ewf/ewf1 mounts/case                            # read-only; exposes NTFS ADS
# ransomware: also expose Volume Shadow Copies for pre-encryption versions
#   vshadowmount -o <off> evidence/disk.E01 mounts/vss && mount -o loop,ro mounts/vss/vshadow1 ...
```

## Build the hidden rubric (operator, once per case)
Extract the published answer key (e.g. CFReDS `leakage-answers.pdf`, `TestAnswers.pdf`) into
`rubric.json` matching `rubric.schema.json`. The agent **never** sees this file. Pick `attack_type.category`
from the same 24-category enum the findings schema uses. Example skeleton:

```json
{
  "case_id": "cfreds-data-leakage",
  "source": "NIST CFReDS Data-Leakage Case — leakage-answers.pdf",
  "attack_type": {
    "category": "Insider Threat, Fraud & Data Theft",
    "aliases": ["insider data theft / IP exfiltration via USB/CD"]
  },
  "key_artifacts": ["setupapi.dev.log USB install record", "NTUSER.DAT UserAssist"],
  "key_iocs": ["USB serial 0019E06B9C0EC0F1B145E7FE"],
  "timeline_events": [{ "timestamp": "2015-03-25T18:39Z", "event": "USB mass-storage first connect" }],
  "actor_accounts": ["informant (suspect local account)"],
  "exfil_or_encryption_facts": ["proprietary design docs copied to removable media, then CD-burned"]
}
```

## Run a blind case end to end
```bash
# 1) mount read-only (above), build rubric.json (above)

# 2) (recommended) tell the runner to sandbox + allow the on-box forensic tools on the mount.
#    Exact flags depend on your claude-code version; put them in BLIND_AGENT_ARGS so the agent can
#    run tools and read the mount, but cannot write evidence or reach the network. Verify with --help.
export BLIND_AGENT_ARGS="--add-dir eval/cases/cfreds-data-leakage/mounts --allowedTools Bash Read Grep Glob"

# 3) drive the blind investigation (subscription; ANTHROPIC_API_KEY auto-unset)
python eval/run_blind.py \
  --mount eval/cases/cfreds-data-leakage/mounts/case \
  --out   eval/cases/cfreds-data-leakage/output/findings.json \
  --case-id cfreds-data-leakage

# 3b) (optional) PLAYBOOK-EQUIPPED run: add --playbook <path> to inject an operator-pre-selected
#     Protocol SIFT playbook (full markdown) into the prompt. The agent must FOLLOW its
#     "Quick path" + "Steps" for the investigation, but classification stays blind — the agent
#     still classifies the attack type itself from the evidence (the OPERATOR may pre-select the
#     playbook because, unlike the agent, the operator knows the case's ground truth).
python eval/run_blind.py \
  --mount eval/cases/cfreds-data-leakage/mounts/case \
  --out   eval/cases/cfreds-data-leakage/output/findings.json \
  --case-id cfreds-data-leakage \
  --playbook playbooks/insider-threat-fraud-data-theft.md
```

`run_blind.py` gives the agent a **neutral** prompt — no attack-type label. The agent must first
**classify** the incident into one of the 24 on-box SIFT categories, then investigate and emit
findings. The script:
- grounds tool names in `../Running_Tool_Claude_Verification` (the 90 run-verified tools) so the
  agent can't name an off-box/invented tool;
- writes the model's raw final message to `<out>.raw.txt` (always, for triage);
- writes `findings.json` and runs a stdlib structural check against `findings.schema.json`;
- exits `0` only if the output is schema-valid (else `1`; bad mount → `2`).

### Env knobs
| Var | Default | Purpose |
|---|---|---|
| `BLIND_AGENT` | `claude` | runner binary (must speak `-p` / `--model` / `--output-format` / `--append-system-prompt`) |
| `BLIND_MODEL` | `opus` | model alias |
| `BLIND_AGENT_ARGS` | *(empty)* | extra CLI args every call — **put sandbox / allowed-tools / `--add-dir` here** |
| `BLIND_TIMEOUT` | `3600` | per-run timeout (seconds) |

## Scoring (separate step)
Score `output/findings.json` against the hidden `rubric.json` (research doc §3, "blind scoring"):
- **attack-type match** — agent's `attack_type_classification.category` vs `rubric.attack_type.category`;
- **key-evidence recall** — fuzzy-match findings to each rubric bucket (`key_artifacts`, `key_iocs`,
  `timeline_events`, `actor_accounts`, `exfil_or_encryption_facts`) → P/R/F1;
- **false-positive rate** — confident findings with no rubric match;
- **hallucination rate** — findings whose `evidence_pointer.literal_cited` is empty, or does not appear
  in the captured tool output, or whose `tool_used` is not in the run-verified list. **Require a backing
  literal per claim → unbacked = auto hallucination flag.**

The scorer is out of scope for this harness; the schemas above are designed so it can be mechanical.

## Starter cases (public, official answer keys — research doc §3)
| Case | Type | Answer key |
|---|---|---|
| NIST CFReDS **Data-Leakage** | Insider data theft / IP exfil (Rocba-like) | public `leakage-answers.pdf` |
| NIST CFReDS **Hacking Case** | Intrusion / credential theft | public `TestAnswers.pdf` |
| 13cubed Windows Memory Challenge 2025 / Ali Hadi RansomCare | Ransomware | community / writeups |

## Threat-model honesty (research doc §2)
Calling a cloud LLM is **not** a true air-gap. The achievable control is **single-destination egress +
never send raw evidence bytes — only derived text/observations**. Default-deny egress; analysis tools in
a no-network namespace; protect raw artifacts with read-only mounts + Read/Edit deny rules (sandbox
covers Bash only). **Human validation before any evidentiary use stays mandatory.**

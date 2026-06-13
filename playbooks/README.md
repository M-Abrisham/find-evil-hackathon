# SIFT Playbook Generator (build-time tooling — NOT part of the submission)

A Claude-powered agent that **drafts a forensic playbook for one attack type at a time**,
grounded in the **run-verified** SIFT tool list, then **verifies + loops until clean**. You
review and fine-tune the draft — you don't write each line by hand.

## Setup (once)
```bash
pip install anthropic
export ANTHROPIC_API_KEY=sk-ant-...
```

## Call it — one attack type at a time
```bash
python build_playbook.py <attack-type-id> "<one-line description>"
```
Examples:
```bash
python build_playbook.py data-exfiltration-insider "Insider steals data via USB/cloud/email"
python build_playbook.py ransomware-destructive    "Mass encryption/deletion + ransom; maybe a wiper"
python build_playbook.py lateral-movement          "Attacker hops host-to-host with stolen creds/RDP/SMB"
```
It writes `<attack-type-id>.md` here and prints `DONE` + the completeness + any `(verify)` flags.

## What it does (and won't do)
- **Author → Verify → loop-until-clean:** Claude drafts, a second adversarial Claude pass checks
  every tool/evidence claim against the verified tool list, then it **re-authors until the grounding
  is clean** (capped at 2 retries).
- **Grounded in (in priority order):** `../Running_Tool_Claude_Verification` (run-verified truth) →
  `../SIFT Inventory → IR Investigation Types` (attack→tool index) → `_TEMPLATE.md` (the format).
- **It will NOT invent real cases.** Instead the "Real-case notes" section lists **web-research
  queries** for the web arm (OpenClaw / a research pass) to fill — so no fabricated citations.
- Output is a **draft to fine-tune**, not gospel — check the `(verify)` flags first.

## Driving it with OpenClaw (the loop / web arm)
OpenClaw calls `python build_playbook.py <id> "<desc>"` **once per attack type** and advances to
the next only after it prints `DONE`. OpenClaw is also where the **web-research** for the real-case
section lives. (OpenClaw's own install/config is a separate step — this script is the callable
"brain" it drives, and it runs standalone too.)

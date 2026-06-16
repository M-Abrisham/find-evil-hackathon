# Protocol SIFT — SUT context bundle

This directory is the **reproducible context configuration** for Protocol SIFT:
the Claude Code config layer that turns a bare Claude into a DFIR investigator on
a SANS SIFT workstation. It is the System-Under-Test (SUT) for our eval loop.

It is a **narrowed, leak-audited vendor snapshot** — only the artifacts a run
actually reads are included. Operational scaffolding (installers, Braintrust
setup, case templates, report archives, local settings) is intentionally left out.

## What is here

| Path | Purpose |
| --- | --- |
| `global/CLAUDE.md` | The top-level operating instructions loaded as `~/.claude/CLAUDE.md`. Contains the generated Deliverable Contract block. |
| `skills/*/SKILL.md` | Five forensic skills (windows-artifacts, yara-hunting, sleuthkit, memory-analysis, plaso-timeline). |
| `contract/contract.yaml` | **Single source of truth** for the Deliverable Contract (verdict vocabulary, IOC rules, MITRE rules). |
| `contract/render_contract.py` | Renders the YAML into `DELIVERABLE_CONTRACT.md` and injects it into `global/CLAUDE.md`. Idempotent. |
| `contract/DELIVERABLE_CONTRACT.md` | Rendered, human-readable contract (generated — do not hand-edit). |
| `Makefile` | Render + deploy targets. |
| `.gitignore` | Ignores local settings, cached analysis, and `__pycache__`. |

## Deploy

The contract is generated from `contract/contract.yaml` — never hand-edit the
rendered prose. Edits here are staged until you sync them into `~/.claude`.

```sh
make render   # regenerate the contract block inside global/CLAUDE.md from the YAML
make sync     # render + deploy global/CLAUDE.md (+ contract) into ~/.claude  -> live next run
make diff     # show what would change vs the deployed copy (no writes)
```

A run reads `~/.claude/CLAUDE.md`, **not** this repo, so changes only take effect
after `make sync`. To (optionally) redeploy the forensic skills too:

```sh
make sync-skills
```

## Provenance

Vendored from the upstream **teamdfir** SIFT Claude Code configuration and then
narrowed for publication. See `VENDOR_NOTICE.md` for the exact provenance and the
list of artifacts deliberately excluded.

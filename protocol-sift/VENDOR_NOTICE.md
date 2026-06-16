# Vendor Notice

This `protocol-sift/` tree is a **narrowed vendor snapshot** of the upstream
**teamdfir** SIFT Claude Code configuration, captured for the SANS "Find Evil"
hackathon submission.

## Provenance

- **Upstream:** the teamdfir SIFT-Workstation Claude Code config layer.
- **Snapshot scope:** only the context artifacts a Protocol SIFT run actually
  reads at investigation time — the operating instructions (`global/CLAUDE.md`),
  the five forensic skills, and the Deliverable Contract source + renderer.

## Deliberately excluded

The following upstream/operational files are **not** vendored here, because they
are not read by a run and/or are not appropriate for a public repository:

- `install.sh` and any installer/bootstrap scripts
- `SETUP_BRAINTRUST.md` and any Braintrust / telemetry credentials or setup
- `case-templates/` and any case-specific scaffolding
- `analysis-scripts/` (e.g. PDF report generators) and `reports/` archives
- `global/settings.json`, `global/settings.local.json`, `.claude/` local settings
- `*.bak*` editor/backup files and the embedded `.git` history

## Integrity

This snapshot was passed through the repository secret-scan gate
(`scripts/leak_scan.py`) before commit. The vendored config contains **no**
real secrets, evidence material, or hackathon case identifiers.

To refresh the snapshot, re-vendor the same minimal file set from the live SUT
tree and re-run the leak-scan gate before committing.

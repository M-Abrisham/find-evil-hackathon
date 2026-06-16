# Repository CI helpers.
#
# leak-scan  run the secret-/evidence-leak gate over the staged changeset.
#            Exits non-zero (CI fail) if any BLOCK finding survives the
#            allowlist. Run before every commit/push.
#
# leak-scan-test  run the scanner's own unit tests + red-team battery
#                 (proves detection is intact, not just that nothing blocked).
#
# check-contract  (R8) fail if a deployed CLAUDE.md's Deliverable-Contract block has
#                 drifted from contract.yaml (the single source of truth). Exit 0 = in
#                 sync; exit 1 = drift (prints a canonical-contract diff per target).

CONTRACT_YAML ?= contract-build/contract.yaml
DEPLOYED_CLAUDE_MD ?= $(HOME)/.claude/CLAUDE.md

.PHONY: leak-scan leak-scan-test check-contract

leak-scan:
	python3 scripts/leak_scan.py --staged

leak-scan-test:
	cd scripts && python3 -m unittest test_leak_scan && bash run_redteam.sh

check-contract:
	@python3 scoring/check_contract_sync.py --contract $(CONTRACT_YAML) $(DEPLOYED_CLAUDE_MD)

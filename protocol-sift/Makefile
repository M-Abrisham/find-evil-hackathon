# Protocol SIFT — render the Deliverable Contract and deploy the context artifacts.
# The contract's single source of truth is contract/contract.yaml.
#
#   make render   regenerate the contract block inside global/CLAUDE.md from the YAML
#   make sync     render + deploy global/CLAUDE.md (+ contract) to ~/.claude  -> LIVE next run
#   make diff     show what would change vs the deployed copy (no writes)
#
# Runs read ~/.claude/CLAUDE.md, NOT this repo — so editing here is staged until `make sync`.

CLAUDE_HOME ?= $(HOME)/.claude

.PHONY: render sync diff sync-skills

render:
	python3 contract/render_contract.py

sync: render
	cp global/CLAUDE.md $(CLAUDE_HOME)/CLAUDE.md
	mkdir -p $(CLAUDE_HOME)/contract
	cp contract/DELIVERABLE_CONTRACT.md $(CLAUDE_HOME)/contract/
	@echo "[sync] deployed contract -> $(CLAUDE_HOME)/CLAUDE.md (live on the next run)"

diff: render
	@diff -u $(CLAUDE_HOME)/CLAUDE.md global/CLAUDE.md || true

# Optional: redeploy the forensic skills too (left separate so it never disturbs
# anything already installed under ~/.claude/skills).
sync-skills:
	mkdir -p $(CLAUDE_HOME)/skills
	cp -r skills/. $(CLAUDE_HOME)/skills/

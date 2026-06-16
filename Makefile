# Repository CI helpers for the Find Evil submission.
#
# Core eval workflow (run from the operator machine):
#   sync / eval / test / validate / manifests
# Public-repo safety gates (run before EVERY commit/push):
#   leak-scan / leak-scan-test / verify-ledger / pre-submit
# Diagnosis-protocol harness (operator layer, over exported round files):
#   aggregate / judge-validate / ablate / regression / validate-keys /
#   check-contract-scorer-drift / diagnosis-test

.PHONY: sync eval test manifests validate verify-ledger leak-scan leak-scan-test pre-submit \
        aggregate judge-validate ablate regression validate-keys check-contract-scorer-drift diagnosis-test

VM=ubuntu@10.104.28.103

# --- core eval workflow ---
sync:
	rsync -av --exclude .git --exclude .env ./ $(VM):~/protocol-sift-evals/

eval:
	ssh $(VM) 'cd ~/protocol-sift-evals && braintrust eval eval_protocol_sift.py'

test:
	cd scoring && python3 -m unittest discover -v
	cd trace_enrich && python3 -m unittest discover -v

manifests:
	ssh $(VM) 'find /home/ubuntu/Downloads -type f | sort' > dataset/manifest.txt
	ssh $(VM) 'hashdeep -r /home/ubuntu/Downloads' > dataset/hashes.txt

validate:
	python3 dataset/validate_cases.py

# --- leak / secret / answer-key gate (run before EVERY public-repo commit) ---
leak-scan:
	python3 scripts/leak_scan.py --staged --root .

leak-scan-test:
	cd scripts && python3 -m unittest test_leak_scan && bash run_redteam.sh

# Score-ledger integrity gate: non-zero exit on a broken hash chain.
LEDGER ?= $(HOME)/score-ledger/ledger.jsonl
verify-ledger:
	python3 scoring/score_ledger.py --path $(LEDGER) verify

# Run BEFORE committing to this PUBLIC repo: leak gate + chain integrity.
pre-submit: leak-scan verify-ledger
	@echo "pre-submit OK: leak-scan clean and score ledger chain intact"

# ---------------------------------------------------------------------------
# Diagnosis Protocol — operator-side eval tooling (eval/diagnosis/).
# These run on the operator layer over EXPORTED round files + per-round score
# JSONs. They NEVER run inside the sealed jail.
SCORE_DIR ?= Desktop/Protocol SIFT Playground Result
PREDICATE ?= verdict
FLOOR_HI  ?= 0.10
ARM       ?= sift
LANE      ?= prose
ROUNDS    ?= 20
JUDGE_SET ?= eval/diagnosis/fixtures/seed_labeled_set.json
BASELINE  ?= eval/diagnosis/baseline.json

aggregate:
	python3 eval/diagnosis/aggregate_failures.py --score-dir "$(SCORE_DIR)" --case "$(CASE)" --predicate "$(PREDICATE)" --floor-hi "$(FLOOR_HI)" --json -o "$(SCORE_DIR)/$(CASE)_aggregate.json"

judge-validate:
	python3 eval/diagnosis/judge_validation.py --set "$(JUDGE_SET)" -o eval/diagnosis/judge_validation.json -t 0.90

ablate:
	ABLATE_REPO_ROOT=$(CURDIR) eval/diagnosis/ablation_runner.sh --rule "$(RULE)" --case-id "$(CASE)" --case "$(CASE_PATH)" --lane "$(LANE)" --toggle "$(TOGGLE)" --rounds "$(ROUNDS)"

regression:
	python3 eval/diagnosis/regression_suite.py --score-dir "$(SCORE_DIR)" --arm "$(ARM)" --baseline "$(BASELINE)"

validate-keys:
	python3 eval/diagnosis/key_validator.py gate --case-id "$(CASE)" --ground-truth "$(GROUND_TRUTH)" --case-input "$(CASE_INPUT)"

check-contract-scorer-drift:
	python3 eval/diagnosis/contract_scorer_drift.py --contract protocol-sift/contract/contract.yaml --scorer-dir contract-build/scoring

diagnosis-test:
	cd eval/diagnosis && python3 -m unittest test_aggregate_failures test_judge_validation test_ablation_runner test_regression_suite test_key_validator test_contract_scorer_drift test_confirm_keep

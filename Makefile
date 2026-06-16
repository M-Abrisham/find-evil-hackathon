# Repository CI helpers.
#
# leak-scan  run the secret-/evidence-leak gate over the staged changeset.
#            Exits non-zero (CI fail) if any BLOCK finding survives the
#            allowlist. Run before every commit/push.
#
# leak-scan-test  run the scanner's own unit tests + red-team battery
#                 (proves detection is intact, not just that nothing blocked).

.PHONY: leak-scan leak-scan-test

leak-scan:
	python3 scripts/leak_scan.py --staged

leak-scan-test:
	cd scripts && python3 -m unittest test_leak_scan && bash run_redteam.sh

# ---------------------------------------------------------------------------
# Diagnosis Protocol — operator-side eval tooling (eval/diagnosis/).
# These run on the JOSH-PC operator layer over EXPORTED round files + locally
# emitted per-round score JSONs. They NEVER run inside the sealed jail.
#
#   aggregate                   #1 per-arm f/n + Wilson CI + two-proportion z + signature clustering
#   judge-validate              #2 TPR/TNR confusion matrix gating score.py --judge
#   ablate                      #3 single-artifact ablation lap (parity --expect + render/sync + run_batch + re-score + aggregate)
#   regression                  #4 monotonic guard-case non-regression gate (BLOCK KEEP on any re-fail)
#   validate-keys               #5 build-time answer-key supportability gate (refuse the lap on a bad key)
#   check-contract-scorer-drift #6 HARD-block verdict/MITRE laps when contract.yaml and scorer.py diverge
#   diagnosis-test              run ALL eval/diagnosis unit tests (SYNTHETIC fixtures only)
#
# Variables (override on the command line):
#   SCORE_DIR  default Desktop/Protocol SIFT Playground Result (the exported round dir on josh-pc)
#   CASE PREDICATE FLOOR_HI ARM RULE CASE_PATH TOGGLE LANE ROUNDS EXPECT JUDGE_SET BASELINE

SCORE_DIR ?= Desktop/Protocol SIFT Playground Result
PREDICATE ?= verdict
FLOOR_HI  ?= 0.10
ARM       ?= sift
LANE      ?= prose
ROUNDS    ?= 20
JUDGE_SET ?= eval/diagnosis/fixtures/seed_labeled_set.json
BASELINE  ?= eval/diagnosis/baseline.json

.PHONY: aggregate judge-validate ablate regression validate-keys check-contract-scorer-drift diagnosis-test

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
	cd eval/diagnosis && python3 -m unittest test_aggregate_failures test_judge_validation test_ablation_runner test_regression_suite test_key_validator test_contract_scorer_drift

.PHONY: sync eval test manifests validate verify-ledger leak-scan pre-submit

VM=ubuntu@10.104.28.103

sync:
	rsync -av --exclude .git --exclude .env ./ $(VM):~/protocol-sift-evals/

eval:
	ssh $(VM) 'cd ~/protocol-sift-evals && braintrust eval eval_protocol_sift.py'

test:
	cd scoring && python3 -m unittest discover -v
	cd scoring && python3 -m unittest test_score_ledger -v
	cd scoring && python3 -m unittest test_composite -v
	cd scoring && python3 -m unittest test_keep_or_revert -v
	cd scoring && python3 -m unittest test_hedge_immutability -v
	cd trace_enrich && python3 -m unittest discover -v

manifests:
	ssh $(VM) 'find /home/ubuntu/Downloads -type f | sort' > dataset/manifest.txt
	ssh $(VM) 'hashdeep -r /home/ubuntu/Downloads' > dataset/hashes.txt

validate:
	python3 dataset/validate_cases.py

# Score-ledger integrity gate: non-zero exit on a broken hash chain.
# LEDGER defaults to the runtime ledger path; override e.g.
#   make verify-ledger LEDGER=/path/to/ledger.jsonl
LEDGER ?= $(HOME)/score-ledger/ledger.jsonl
verify-ledger:
	python3 scoring/score_ledger.py --path $(LEDGER) verify

# Mandatory secret/answer-key leak gate before any public-repo commit.
leak-scan:
	python3 scripts/leak_scan.py --staged --root .

# Run BEFORE committing to this PUBLIC repo: leak gate + chain integrity.
pre-submit: leak-scan verify-ledger
	@echo "pre-submit OK: leak-scan clean and score ledger chain intact"

# errlens advisory error-analysis sensor (scoring-local; independent of the root Makefile)
.PHONY: errlens errlens-verify errlens-test
TAX ?= taxonomy.json
ROUNDS ?= rounds.json
errlens-verify:
	python3 errlens.py verify --taxonomy $(TAX)
errlens-test:
	python3 -m unittest test_errlens -v
errlens:
	mkdir -p errlens_reports
	python3 errlens.py bucket --rounds $(ROUNDS) --taxonomy $(TAX) \
	  --report errlens_reports/latest.md --log errlens_log.jsonl

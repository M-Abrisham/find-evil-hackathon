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

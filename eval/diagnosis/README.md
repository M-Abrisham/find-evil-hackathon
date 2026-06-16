# eval/diagnosis/ — Diagnosis Protocol operator tooling

Six operator-side tools that turn a campaign of sealed blind runs into a
*defensible* rule-change decision. They implement the RULE-CHANGE DIAGNOSIS
PROTOCOL: measure a failure rate with a confidence interval, attribute a
score delta to exactly one rule, and gate every change behind a non-regression
suite — so no rule moves on a single anecdote or a scorer artifact.

## Where these run (blind-isolation)

These tools run on the **josh-pc OPERATOR layer**, AFTER the sealed jail has
exported its blind output. They **READ** findings/report content and therefore
live OUTSIDE the integrity-barred orchestrator. They NEVER run inside the jail
and NEVER touch the sealed `run_batch.sh` / `launch.sh` / `teardown.sh`.

The sealed export (per `<CASE>_<ARM>_round-<N>`) carries only
`findings.json` + `manifest.json` + `agent.stderr` + `summary.md` — **no score
JSON**. The operator scores each exported round LOCALLY, writing per-round files
keyed by the export BASE:

- `score.py -f <BASE>.findings.json -o <BASE>.score.json`           (blind scorer)
- capture `scorer.py --json` stdout -> `<BASE>.scorer.json`         (IOC/verdict/MITRE; the `--- JSON ---` block)
- `presence_scorer.py` to_dict -> `<BASE>.presence.json`            (R5 binary gate)

The diagnosis tools then glob those per-round JSONs.

> Build + unit-test on the VM with **SYNTHETIC fixtures only**. Real cases,
> answer keys, ground-truth and ro-bind mounts live on josh-pc and must NEVER be
> copied onto the VM or committed to this PUBLIC repo.

## The six tools

| # | File | Make target | Role |
|---|------|-------------|------|
| 1 | `aggregate_failures.py` | `make aggregate` | Per-arm f/n + Wilson 95% CI (not normal-approx) + two-proportion z (sift-vs-bare, pre-vs-post) + same-signature clustering. Drops INVALID rounds first; STOP-flags if >20% lost. |
| 2 | `judge_validation.py` | `make judge-validate` | TPR/TNR confusion matrix for the `score.py --judge` LLM judge over a frozen labeled borderline-FP set. GATES `--judge`: it stays OFF unless TPR & TNR both >= 0.90. |
| 3 | `ablation_runner.sh` | `make ablate` | Single-artifact ablation lap: (verdict/MITRE lanes FIRST run the **enforced** contract<->scorer drift gate (#6) and ABORT on drift) -> parity snapshot -> toggle ONE lane -> render/sync -> `parity --diff --expect N` (must pass) -> sealed `run_batch` -> re-score -> feed the aggregator. The ONLY mechanism allowed to attribute a delta to one clause. |
| 4 | `regression_suite.py` + `guard_cases.json` | `make regression` | Monotonic guard-case non-regression gate. A guard that PASSED in the baseline and now fails => BLOCK KEEP / force REVERT (zero observed regressions, not CI-excludes-0). |
| 5 | `key_validator.py` | `make validate-keys` | Build-time answer-key supportability gate (expected_artifact-exists-in-mount + IOC findability) => refuse the lap on a bad key. Plus a cross-arm KEY-DOUBT trigger => mandatory human re-adjudication. |
| 6 | `contract_scorer_drift.py` | `make check-contract-scorer-drift` | HARD-blocks any verdict/MITRE lap when `contract.yaml` (verdict equivalence classes / MITRE) diverges from `scorer.py` (`VERDICT_CLASSES` / `_mitre_satisfied`). **Enforced automatically** by `ablation_runner.sh` (step 0) on verdict/MITRE lanes, not just a manual check. |

`make diagnosis-test` runs all six unit suites (164 tests, SYNTHETIC fixtures only).

## How they wire into the eval loop

```
                 contract_scorer_drift (#6)  <-- ENFORCED by ablation_runner step 0 on verdict/MITRE laps (ABORT on drift)
                          |
   key_validator (#5)  --gate-->  ablation_runner (#3)  --re-score-->  aggregate_failures (#1)
   (refuse bad key)         (one-change parity gate)        (Wilson CI + two-proportion KEEP signal)
                                     |                                    |
                          parity_check.py --expect N            regression_suite (#4)
                          (in eval/, patched in place)        (zero guard regressions = KEEP gate B)

   judge_validation (#2)  --authorizes-->  score.py --judge   (else judge runs OFF, deterministic only)
```

- **Stage 1 (measure):** score each exported round, then `make aggregate` for a
  per-arm rate with a Wilson CI and a SYSTEMATIC/GREY/STOCHASTIC classification
  against an empirical `--floor-hi`.
- **Stage 4 (attribute + KEEP/REVERT):** `make ablate` toggles ONE artifact
  behind the `parity --expect N` gate, re-runs at the DECISION tier, re-scores,
  and feeds the aggregator. KEEP iff the two-proportion CI excludes 0 AND
  `make regression` shows zero guard regressions; else REVERT.
- **Pre-lap guards:** the contract<->scorer drift gate (#6) is **ENFORCED by the
  ablation runner itself** — it is no longer a manual convention. On a
  verdict/MITRE lane (`--affects verdict|mitre`, auto-detected from a `--rule` id
  matching `verdict`/`mitre`), `ablation_runner.sh` RUNS
  `contract_scorer_drift.py` as step 0 and HARD-ABORTS the lap (nonzero, before
  any toggle/deploy/run/score) on drift — so a verdict/MITRE rate delta can never
  be measured against a stale scorer mirror. Non-verdict/MITRE lanes skip it.
  (`make check-contract-scorer-drift` remains available to run the gate
  standalone.) Run `make validate-keys` before any key-driven lap (UNSUPPORTED =>
  refuse).
- **Judge:** `score.py --judge` is gated. Default freeze posture is judge OFF;
  it only moves a score when `--judge-validation <passing artifact>` (or the
  `JUDGE_VALIDATION_ARTIFACT` env var) authorizes it. The deterministic
  hallucination signal (empty `literal_cited`) stands regardless.

## Important caveats (do not misread the output)

- **sift-vs-bare names only the LAYER, never a clause.** Only the single-artifact
  ablation lap (#3) can attribute a delta to a specific rule.
- **verdict-class collapse:** `scorer.py` returns `not_emitted` for BOTH a
  missing AND a present-but-wrong-class verdict. The FAIL predicate treats both
  as FAIL but cannot, from this field alone, split structural (Branch-E) from
  reasoning (Branch-F) — cross-read OTEL / `parse_report_verdict`.
- **`findable_recall == None`** (0 findable IOCs) is UNSCORABLE (BAD-CASE
  signal); such rounds are EXCLUDED from the denominator, never counted as pass
  or fail.
- **Cost is best-effort/absent:** the export carries no `total_cost_usd`; the
  aggregator never requires it.

Run `make leak-scan` before any push. `eval/diagnosis/fixtures/**` is exempted in
`.leakscanignore` (synthetic IOCs by design) — never weaken real detection.

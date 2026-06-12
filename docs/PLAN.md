# Project Plan: Protocol SIFT Eval Harness

Six phases to build, run, and iterate on deterministic unit tests for Protocol SIFT skill files.

---

## Phase 1 — Assertion Catalog (complete)

Define every testable behavioral and structural claim.
Outputs: `docs/ASSERTION_CATALOG.md` with 16 assertions (A1–A8 architecture gaps, S1–S8 skill-directive adherence).
All checks are deterministic; no ground-truth answer values.

---

## Phase 2 — Dataset

Build `dataset/cases.jsonl`: **5 features × 3 scenarios** drawn from the four Downloads case folders (`SRL-2015`, `SRL-2018`, `Standard-Forensic-Case-2`, `Standard-Forensic_Case`).

Each case record contains:
- `case_id`: unique identifier
- `case_dir`: path under `/home/ubuntu/Downloads/`
- `prompt`: the task prompt given to the agent
- `expected`: behavioral fields only — `skill` (expected SKILL.md), `tool_re` (required tool regex), `ordering` (ordered plugin/command list), `denylist` (paths agent must not read) — **no answer values**

Evidence-absent scenarios (cases where a required artifact type is not present) are verified against `manifest.txt` before inclusion to ensure the absence is real, not a typo.

---

## Phase 3 — Harness

`harness/run_case.py`: SSHs to sift-vm and runs:

```bash
claude -p "<prompt>" --output-format stream-json
```

Collects a `RunResult` object with fields:
- `report`: final text output
- `tool_calls`: list of `{type, name, input, output}` dicts extracted from stream
- `audit_log`: contents of `forensic_audit.log` if written by the agent
- `manifest`: snapshot of `find /home/ubuntu/Downloads -type f` after run
- `hashes`: output of `hashdeep -a -k hashes.txt -r /home/ubuntu/Downloads` after run

`harness/parse_stream.py`: stateless parser for `stream-json` NDJSON — extracts tool use blocks and final assistant text.

---

## Phase 4 — Scorers

One Python module per assertion ID under `scorers/`. Each scorer is a **pure function**:

```python
def score(input: dict, output: RunResult, expected: dict) -> dict:
    # returns {"score": 0 | 1, "metadata": {...}}
```

No side effects, no network calls, no file I/O. Scorers import only stdlib and `re`.
All scorers exported in `scorers/__init__.py::ALL`.

---

## Phase 5 — Braintrust Eval

`eval_protocol_sift.py` wraps Phase 3 + Phase 4 in a Braintrust `Eval`:

```python
Eval(
    "protocol-sift",
    experiment_name=f"skills@{git_sha}",
    data=load_cases("dataset/cases.jsonl"),
    task=run_case,       # harness.run_case
    scores=[*ALL],       # scorers.ALL
)
```

Experiments are named `skills@<git-sha>` for reproducibility. Results visible in Braintrust UI with per-assertion score breakdowns.

---

## Phase 6 — Iteration Loop

Workflow for skill improvement without regression:

1. **Baseline**: run `make eval` on current `main` → record experiment `skills@<sha-A>`
2. **Edit**: modify one SKILL.md (on sift-vm or via `make sync`)
3. **Re-run**: `make eval` → experiment `skills@<sha-B>`
4. **Compare**: Braintrust experiment diff — assert no score in A-series regresses, S-series score improves for the edited skill
5. **No-regression gate**: CI (TODO) blocks merge if any A-series score drops below baseline
6. Repeat from step 2 for next skill improvement

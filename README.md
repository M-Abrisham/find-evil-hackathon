# protocol-sift-evals

Unit-test harness for [Protocol SIFT](https://github.com/teamdfir/protocol-sift) skill files.
Assertions are deterministic — no ground-truth answer values; every check is behavioral or structural.

## Architecture

- **josh** (this machine): editing, version control, orchestration
- **sift-vm** (`ubuntu@10.104.28.103`): eval execution — Claude Code with Protocol SIFT skills, Braintrust SDK

## Quick start

```bash
cp .env.example .env
# fill in BRAINTRUST_API_KEY
make sync   # push repo to sift-vm
make eval   # run braintrust eval on sift-vm
make test   # run local pytest unit tests for scorers
```

## Layout

```
docs/
  ASSERTION_CATALOG.md   16 deterministic assertions (A1-A8, S1-S8)
  ACCESS.md              host access, connectivity check, hygiene rules
  PLAN.md                6-phase project plan
dataset/
  cases.jsonl            eval cases (behavioral fields only, no answer values)
  answer_key_denylist.txt  paths to exclude from agent reads (see A8)
harness/
  run_case.py            drive claude -p --output-format stream-json on sift-vm
  parse_stream.py        extract tool_calls, report, audit_log from stream-json
scorers/
  a1_no_fabricated_paths.py  ... one module per assertion ID
  __init__.py
eval_protocol_sift.py   Braintrust Eval entry point (TODO: phase 5)
```

## Assertion catalog summary

See `docs/ASSERTION_CATALOG.md` for the full catalog.

| Series | Focus |
|--------|-------|
| A1–A8  | Architecture gaps documented for Protocol SIFT |
| S1–S8  | Skill-directive adherence (SKILL.md file fidelity) |

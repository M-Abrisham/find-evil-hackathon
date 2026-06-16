# trace_enrich — post-run Braintrust trace enrichment for Protocol SIFT ("Fix A")

A **measurement-only** post-run step. For a *finished* Protocol SIFT investigation
it reads the run's Braintrust trace + the raw-bash log + the case input + the
report, applies a static SKILL.md registry, and **writes labels/scores BACK onto
the existing Braintrust spans** (deep-merge via `_is_merge`). It does **not**
change how the agent runs.

stdlib-only (`urllib`, `json`). No SDK, no third-party deps.

## What it writes

**Per tool span** (`metadata.enrich` + `tags`):
- **skill owner** — each tool tagged with the SKILL.md manual that owns it.
  Compound commands (`fls | icat && yara`) are split so every sub-tool is tagged
  (`metadata.enrich.sub_tools`, plus `skill:<name>` / `phase:<name>` tags).
- **action phase** — `discovery` (fls/mmls/fsstat) vs `extract`
  (icat/tsk_recover/image_export) vs `analyze` (vol.py/yara/*ECmd/psort) vs
  `report`, so a skipped extraction is visible.
- **outcome** — `ok` / `errored` / `empty`, computed at the **whole-bash-call**
  level from the raw-bash log (one pipeline = one outcome; empty detected via
  stdout/stderr — no per-sub-tool exit codes). Falls back to the trace's
  `tool.execution.success` boolean for non-Bash tools.

**On the ROOT span** (`metadata.rollup`, `scores`, `tags`):
- **per-skill rollup** — tools_run, success_rate, iocs_surfaced (via provenance).
- **run scores** (numbers in `[0,1]`, only when ground truth is supplied):
  `findable_recall`, `fabrications` (`1/(1+count)`), `verdict`, `mitre`.
- **skill_expected vs skill_used** — when an answer key supplies
  `expected_skills` (or `expected_tools`, mapped through the registry).
- **IOC -> tool provenance** — candidate-fabrication list + counts. Guardrail:
  an IOC's source set is **tool stdout UNION the case input**; absent from BOTH =
  candidate fabrication; present in the case input is NEVER a fabrication. IOC
  extraction/normalisation is reused from `scoring/scorer.py` so this matches the
  existing IOC scorer.
- tag `enriched` (and `has_candidate_fabrications` when any are found).

## How it fits together

```
enrich.py (orchestrator + CLI)
  ├─ bt_client.get_trace(run_or_session_id)  -> {root_span, tool_spans[], success}
  │     (BTQL read; two-roots rule: keep the multi-span root, drop n==1 telemetry roots)
  ├─ bashlog.load_bash_log(path) / outcome() / get_stdout()   (join key = tool_use_id)
  ├─ registry.tools_in(command) / skill_for / phase_for       (static SKILL.md map)
  ├─ provenance.provenance(...) / provenance_summary(...)      (reuses scoring/scorer.py)
  ├─ scoring/scorer.py  score_case(...)                        (only if ground truth given)
  └─ bt_client.merge_span(...) / merge_root(...)               (POST insert + _is_merge)
```

The join key between the trace and the bash log is `tool_use_id`
(`metadata.tool_use_id` on the span == `tool_use_id` in the bash-log record). The
bash log is **Bash-only** (Read/Write/MCP are not in it).

## The API key — `BT_API_KEY` (env var, never committed)

The Braintrust key is read from **`$BT_API_KEY`** at runtime. It is never
hardcoded, echoed, or written to any committed file. On the VM it lives in
`/home/ubuntu/find-evil/baseline/protocol-sift/.claude/settings.local.json`
inside `env.OTEL_EXPORTER_OTLP_HEADERS` (`"Authorization=Bearer sk-..."`). Lift
it into the env (stdlib helper, prints nothing):

```bash
export BT_API_KEY="$(python3 - <<'PY'
import json, re
d = json.load(open("/home/ubuntu/find-evil/baseline/protocol-sift/.claude/settings.local.json"))
print(re.search(r"Bearer ([^,\s]+)", d["env"]["OTEL_EXPORTER_OTLP_HEADERS"]).group(1))
PY
)"
```

(`bt_client.key_from_settings_file(path)` does the same extraction in-process.)
The key is exposed in that file and **must be rotated later** — out of scope here.

## How to run

Dry run (no writes — prints exactly what WOULD be merged; needs `BT_API_KEY` only
to *read* the trace):

```bash
python3 -m trace_enrich.enrich --case case7 \
  --bash-log /home/ubuntu/find-evil/baseline/protocol-sift/analysis/braintrust_raw/bash_raw_b2bb212f-d701-4bfc-bc9f-.jsonl \
  --case-input /home/ubuntu/cases-from-slack/case7.json \
  --report ~/protocol-sift-eval-results/reports/VIGIA-REAL-007_investigation_report.md \
  --plan
```

Apply (write the labels/scores back) — add `--ground-truth` to emit scores and
`--verify` to re-read the root span after the write:

```bash
python3 -m trace_enrich.enrich --case case7 \
  --bash-log .../bash_raw_b2bb212f-d701-4bfc-bc9f-.jsonl \
  --case-input /home/ubuntu/cases-from-slack/case7.json \
  --report .../VIGIA-REAL-007_investigation_report.md \
  --ground-truth .../ground_truth/VIGIA-REAL-007.json \
  --answer-key .../answer_key.json \
  --verify
```

`--session <id>` accepts either the **32-hex OTEL trace id** or the **Claude
session uuid**; both resolve to the same multi-span run. `--case case1|case2|case7`
is shorthand for the three known eval runs (their trace/session ids are baked in).
Scores are **optional**: without `--ground-truth` the run still enriches
(tags / phases / outcomes / rollup / provenance) and logs that scores were omitted.

### Useful flags

| flag | effect |
|------|--------|
| `--plan` | dry run; print the planned writes, make no merges |
| `--verify` | after apply, re-read the root span (4s settle) and print its scores/tags |
| `--read-persisted` | read full persisted stdout for provenance (slower, more complete) |
| `--no-batch` | one `insert` request per event (isolates a failing span) |
| `--json` | also print the plan summary as JSON |

## View the enriched run

```
https://www.braintrust.dev/app/protocol-sift/p/protocol-sift/logs?r=<root_span_id>
```

e.g. case7: `...logs?r=8f3266b5e66b4a31ad0c7e85f33e1dad`. Per-tool labels appear
on each `claude_code.tool` span's metadata/tags; the rollup + scores appear on the
root `claude_code.interaction` span.

## Design notes / caveats

- **Write target = `span_id`** (16-hex, == the row `id`), NOT `root_span_id`
  (32-hex = the shared OTEL trace_id, not addressable). `get_trace` returns the
  correct `span_id` for every write.
- **Two roots per run**: each run emits the real multi-span investigation root
  AND a stray 1-span telemetry root. `bt_client` keeps the multi-span root
  (`n >= 2`) and the `is_root` / `claude_code.interaction` row inside it.
- **Deep-merge is idempotent** on metadata/score keys and additive on tags, so
  re-running overwrites the same `metadata.enrich` / `rollup` / `scores` cleanly
  (it preserves the original `tool_name` / `full_command` / `tool_use_id`).
- **Outcome is whole-pipeline.** A single shell pipeline returns one exit signal;
  we do not fabricate per-sub-tool exit codes. `empty` (returned-nothing) is
  detected from stdout/stderr in the raw-bash log.
- All compute lives in `build_plan(...)` (pure, no network), so the plan is
  unit-testable and dry-runnable; only `get_trace` and `apply_plan` touch the
  network.
```

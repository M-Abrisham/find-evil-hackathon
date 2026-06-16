# trace_enrich — Write-Back Spike NOTES

Author: spike agent. Purpose: de-risk the Braintrust write-back BEFORE the integration
agent relies on it. **Everything below was OBSERVED against the live `protocol-sift`
project on the VM, not copied from docs.** Verified 2026-06-12 against the most recent
real run (root trace `8f3266b5e66b4a31ad0c7e85f33e1dad`, session
`b2bb212f-d701-4bfc-bc9f-7f3556957d19`, "VIGIA-REAL-007").

## TL;DR for the integration agent

- **`per_span_merge_works = TRUE`.** The one unverified assumption is now VERIFIED:
  an OTEL-ingested span's `id` (== its `span_id`) IS addressable by
  `POST /v1/project_logs/{project_id}/insert` with `_is_merge:true`. The write
  deep-merges onto the already-ingested span and PRESERVES the original metadata
  (`tool_name`, `full_command`, `tool_use_id` were all still present after merge).
  You do NOT need the root-only fallback. You can write per-tool labels.
- **Write target id = `span_id`** (16-hex, e.g. `8261d472c80b19e9`). It equals the
  span's `id` field. Do **NOT** use `root_span_id` (32-hex, e.g.
  `8f3266b5e66b4a31ad0c7e85f33e1dad`) as a write id — that is the OTEL trace_id and is
  **not** an addressable row id.
- stdlib-only (`urllib`, `json`) is sufficient for everything. No SDK, no third-party.

---

## 1. The Braintrust API key (BT_API_KEY)

Lives on the VM at
`/home/ubuntu/find-evil/baseline/protocol-sift/.claude/settings.local.json`, inside
`env.OTEL_EXPORTER_OTLP_HEADERS` as the string `"Authorization=Bearer sk-..."`.

Read it into an env var at runtime; NEVER echo it, NEVER write it to a committed file.
Extraction used (stdlib):

```python
import json, re
d = json.load(open(".../.claude/settings.local.json"))
hdr = d["env"]["OTEL_EXPORTER_OTLP_HEADERS"]          # "Authorization=Bearer sk-..."
key = re.search(r"Bearer ([^,\s]+)", hdr).group(1)     # -> BT_API_KEY (len 51, sk-...)
```

All HTTP in this spike was run **on the VM** so the key never leaves it. The integration
module can run wherever, but must source the key the same way and keep it in env only.
(The key is exposed in that file and must be rotated later — out of scope here.)

API host: `https://api.braintrust.dev`. Auth header on every call:
`Authorization: Bearer <BT_API_KEY>`, `Content-Type: application/json`.

---

## 2. Resolve project_id from project name "protocol-sift"

**Exact call (REST):**

```
GET https://api.braintrust.dev/v1/project?project_name=protocol-sift
```

Response shape: `{"objects":[{"id":"<project_id>", "name":"protocol-sift", ...}]}`.
Take `objects[0].id`.

Observed result: **`project_id = 74b50408-82b3-4b72-9043-4e8c28b7cb21`**.

(Equivalent: `bt projects list --json` returns the same id, but the REST call above is
the documented programmatic path and avoids depending on the CLI.)

---

## 3. Finding the run's spans + the two-roots rule

### Read method (LIST a run trace + its span ids) — USE THIS

The `bt view trace/span` **CLI subcommands do NOT work with bare span ids** — they
demand a browser URL with `r`/`s` query params and error otherwise
(`error: trace URL must include query parameter r or s`). So **do not** rely on
`bt view trace <id>`. Use one of these two REST methods instead (both observed working,
status 200):

**Method A — BTQL (preferred; gives span tree in one call):**

```
POST https://api.braintrust.dev/btql
body: {"query": "<btql>", "fmt": "json"}
response: {"data": [ <span rows...> ]}
```

BTQL gotchas (learned the hard way): a query MUST contain `select:` / `dimensions:` /
`measures:` / `infer:` or it 400s; grouping uses `dimensions:`+`measures:`, NOT
`group_by`. Pipe stages are `|`-separated. Working queries:

- List all spans of one run (the trace dump):
  ```
  select: * | from: project_logs('<PID>') | filter: root_span_id = '<ROOT_TRACE_ID>' | limit: 100
  ```
- Find candidate runs (group by root, newest first):
  ```
  from: project_logs('<PID>') | dimensions: root_span_id | measures: count(1) as n, max(created) as last_ts | sort: last_ts desc | limit: 20
  ```
- Re-read one span after a merge (confirm write):
  ```
  select: id, span_id, metadata, tags, scores, span_attributes | from: project_logs('<PID>') | filter: span_id = '<SPAN_ID>' | limit: 5
  ```

**Method B — REST fetch (fallback, no BTQL):**

```
POST https://api.braintrust.dev/v1/project_logs/<PID>/fetch
body: {"filters":[{"path":["root_span_id"],"value":"<ROOT_TRACE_ID>"}], "limit":200}
response: {"events":[ ... ]}
```

Note Method B returned 98 events for the same root (it returns extra/duplicate
projections / pagination rows); Method A returned exactly the 30 logical spans. **Prefer
Method A (BTQL)** for a clean span set.

### Two-roots rule (pick the multi-span root, ignore the 1-span telemetry root)

Grouping by `root_span_id` (the group-by query above) shows runs alternate:

```
root_span_id ...e1dad   n=30   <- REAL multi-span investigation root  (use this)
root_span_id ...63ba6   n=1    <- stray telemetry root (same ms)      (ignore)
root_span_id ...a6553   n=26   <- REAL
root_span_id ...f69e29  n=1    <- stray
root_span_id ...b487a   n=18   <- REAL
...
```

**Programmatic root-selection rule:** group `project_logs(PID)` by `root_span_id`,
take `count(1) as n`, and **discard any group with `n == 1`** (the stray telemetry
roots) — keep groups with `n >= ~6` (real runs observed at 6, 18, 26, 30 spans;
spec says 18–30 for full investigations, smaller for partial). Within a chosen run,
the **multi-span root span is the row where `is_root == true`** (equivalently
`span_parents` is null/empty AND `span_attributes.name == "claude_code.interaction"`).
That row's `id`/`span_id` is the root write target. The 1-span stray root never has a
`claude_code.interaction` child tree, so it is trivially excluded by the `n==1` filter.

---

## 4. Span tree + field map (where everything lives)

Span tree for a real run (`span_attributes.name`):

```
claude_code.interaction            (is_root=true, span_parents=None)   <- ROOT
├─ claude_code.llm_request         (one per model turn)
├─ claude_code.tool                (one per tool call)  <- TOOL METADATA LIVES HERE
│   ├─ claude_code.tool.blocked_on_user
│   └─ claude_code.tool.execution  (one per tool call) <- OUTCOME (success) LIVES HERE
├─ claude_code.tool ...
└─ ...
```

### ID fields (CRITICAL)

On every row: `id == span_id` (16-hex). `root_span_id` (32-hex) is the OTEL trace_id,
shared by all spans of the run, and is **NOT** a writable row id.

| row                      | `id` / `span_id` | `root_span_id`                     | is_root |
|--------------------------|------------------|------------------------------------|---------|
| claude_code.interaction  | `8482646437e3db1f`| `8f3266b5e66b4a31ad0c7e85f33e1dad` | true    |
| claude_code.tool         | `8261d472c80b19e9`| `8f3266b5e66b4a31ad0c7e85f33e1dad` | false   |
| claude_code.tool.execution| `0d3b2bed0552bc57`| `8f3266b5e66b4a31ad0c7e85f33e1dad`| false   |

### Where each field lives (all under `metadata`, except `name`/`type` under `span_attributes`)

- **`span_attributes.name`** = span kind (`claude_code.interaction` / `.llm_request` /
  `.tool` / `.tool.blocked_on_user` / `.tool.execution`). `span_attributes.type` = `"task"`.
- **`claude_code.tool` span metadata** (the per-tool-call record):
  - `tool_name` — `"Bash"`, `"Read"`, `"Write"`, etc.
  - `full_command` — the FULL shell command string (present **only when `tool_name=="Bash"`**).
  - `file_path` — absolute path (present **only for Read/Write** tools, not Bash).
  - `tool_use_id` — e.g. `"toolu_01ARdtMoy9TH2gxM6YFjJWq9"` (**JOIN KEY** to the raw-bash log).
  - `gen_ai.tool.call.id` — identical value to `tool_use_id` (duplicate; either works).
  - `session.id` — e.g. `"b2bb212f-d701-4bfc-bc9f-7f3556957d19"` (run-level join key).
  - plus `duration_ms`, `terminal.type`, `user.*`, `organization.id`.
  - `input`/`output`/`scores` are **null** on tool spans (content is in metadata, not input/output).
- **`claude_code.tool.execution` span metadata** (the per-tool-call OUTCOME):
  - **`success`** — boolean. This is the per-tool-call exit outcome (true/false).
  - `tool_use_id` / `gen_ai.tool.call.id` — same value as its parent `.tool` span (this is
    how you pair a `.tool` span with its `.tool.execution` outcome).
  - `duration_ms`, `session.id`, `user.*`.
  - NOTE: `success` is a single boolean from the whole tool call. For Bash that is the
    whole-pipeline result — consistent with the spec's "do NOT promise per-sub-tool exit
    codes". Detect `returned-nothing` separately from stdout/stderr in the raw-bash log.
- **ROOT (`claude_code.interaction`) metadata**: `user_prompt`, `user_prompt_length`,
  `session.id`, `interaction.duration_ms`, `interaction.sequence`, `user.*`,
  `organization.id`. Root `input`/`output`/`scores`/`tags` start **null** — this is the
  clean place to write the per-run rollup + scores.

### Pairing tool span <-> execution span <-> raw-bash record

`claude_code.tool.tool_use_id` == `claude_code.tool.execution.tool_use_id` ==
raw-bash record `tool_use_id`. Use this triple-join: tool span gives you
`tool_name`/`full_command`/`file_path`; execution span gives you `success`; raw-bash
record gives you `stdout`/`stderr`/`tool_response` for empty-output detection and for
IOC->tool provenance.

---

## 5. THE KEY TEST — per-span merge write-back (OBSERVED WORKING)

### Working POST (per-tool span merge)

```
POST https://api.braintrust.dev/v1/project_logs/74b50408-82b3-4b72-9043-4e8c28b7cb21/insert
Authorization: Bearer <BT_API_KEY>
Content-Type: application/json

body skeleton:
{
  "events": [
    {
      "id": "<existing span_id>",        // e.g. "8261d472c80b19e9"  (the .tool span)
      "_is_merge": true,                  // DEEP-merge onto the ingested span
      "metadata": { "...": "..." },       // your skill-owner / action-phase / outcome labels
      "tags": ["..."]                     // optional
      // "scores": {...} only on the root (numbers in [0,1])
    }
  ]
}
```

**Observed response (status 200):**
```json
{"row_ids":["8261d472c80b19e9","8482646437e3db1f"]}
```
(`row_ids` echoes the ids you merged into — confirms the ids were accepted as targets.)

**Re-read confirmation (BTQL on the same `span_id`):** after the merge, the tool span
showed `metadata._enrich_spike == "ok"` and `tags == ["_enrich_spike"]`, AND it still
had its original `tool_name=="Bash"`, `tool_use_id`, `full_command` — i.e. the write
**deep-merged, did not clobber.** => `per_span_merge_works = TRUE`.

### Working POST (root merge — rollup + scores)

Same endpoint, same shape, `id` = the root span id (`8482646437e3db1f`). The spike wrote:
```json
{"id":"8482646437e3db1f","_is_merge":true,
 "metadata":{"_enrich_spike_root":"ok"},
 "tags":["_enrich_spike_root"],
 "scores":{"_enrich_spike_score":0.5}}
```
Re-read confirmed `metadata._enrich_spike_root=="ok"`, `tags==["_enrich_spike_root"]`,
`scores=={"_enrich_spike_score":0.5}`. **Scores must be numbers in [0,1]** (0.5 accepted).
Use score names like `findable_recall`, `fabrications` (normalize to [0,1]),
`verdict`, `mitre`.

### Re-read method to verify any write
```
POST https://api.braintrust.dev/btql
{"query":"select: id, span_id, metadata, tags, scores | from: project_logs('<PID>') | filter: span_id = '<SPAN_ID>' | limit: 5","fmt":"json"}
```
Allow a few seconds for indexing before re-reading (spike used ~4s sleep; the read was
consistent after that).

### Throwaway fields left on the live trace (so they can be overwritten/cleaned)
On run `8f3266b5e66b4a31ad0c7e85f33e1dad`:
- span `8261d472c80b19e9`: `metadata._enrich_spike="ok"`, tag `_enrich_spike`.
- root  `8482646437e3db1f`: `metadata._enrich_spike_root="ok"`, tag `_enrich_spike_root`,
  score `_enrich_spike_score=0.5`.
These names are deliberately distinct and namespaced so the real enrichment run can
overwrite them harmlessly (merge is idempotent on a key — re-merging a new value
replaces it). Tags accumulate as a set, so when the integration drops the spike tags it
should merge an explicit final tag set if it cares about exactness.

---

## 6. Raw-bash log join (for outcome + provenance)

Dir on VM: `/home/ubuntu/find-evil/baseline/protocol-sift/analysis/braintrust_raw/`.
Files: `bash_raw_<session_id_TRUNCATED>.jsonl` — **the filename truncates the session_id
after the 3rd hyphen group** (e.g. `bash_raw_b2bb212f-d701-4bfc-bc9f-.jsonl` for full
session `b2bb212f-d701-4bfc-bc9f-7f3556957d19`). Match the file by **session_id prefix**,
but the AUTHORITATIVE full `session_id` and `tool_use_id` are INSIDE each JSONL record.

Each line is one Bash call (BASH-ONLY — Read/Write/MCP are not here). Record keys:
`command`, `cwd`, `description`, `session_id` (full), `stderr`, `stdout`,
`tool_response` (`{stdout, stderr, ...}`), `tool_use_id`, `transcript_path`, `ts`.

Join: raw-bash `tool_use_id` == span `tool_use_id`. Use `stdout`/`stderr` for
`returned-nothing` detection (empty stdout) and as the provenance source text.

---

## 7. IOC -> tool provenance: reuse scoring/scorer.py (no re-implementation)

`scoring/scorer.py` is stdlib-only. Reuse these (import them) so provenance matches the
existing IOC scorer exactly:
- `extract_tokens(text, kind)` — normalized set for clean kinds (`email`,`hash`,`mac`,`ipv4`,`sid`).
- `normalize(kind, value)`, `extract_ipv4(text)`, `extract_cidrs(text)`.
- `ioc_present(ioc, text)` — full presence check incl. fuzzy kinds (path/hostname/username).
- `find_fabrications(...)`, and `_collect_strings(obj)` / `load_case_input_text(path)` to
  pull the case-INPUT text.

**Provenance guardrail (per spec):** an IOC's provenance source set =
(union of tool `stdout` from the raw-bash log) **PLUS** the case INPUT text the agent
`Read`. An IOC absent from BOTH is a candidate fabrication; an IOC present in the case
input is NOT a fabrication even if no tool emitted it. Case inputs are on the VM at
`/home/ubuntu/cases-from-slack/case{1,2,7}.json`.

---

## 8. Quick reference (copy/paste constants)

```
API_HOST      = https://api.braintrust.dev
PROJECT_NAME  = protocol-sift
PROJECT_ID    = 74b50408-82b3-4b72-9043-4e8c28b7cb21   (resolve via GET /v1/project?project_name=)
RESOLVE       = GET  /v1/project?project_name=protocol-sift            -> objects[0].id
LIST/READ     = POST /btql            {"query": "...", "fmt":"json"}   -> {"data":[...]}
              | POST /v1/project_logs/{PID}/fetch  {"filters":[...]}   -> {"events":[...]}
WRITE (merge) = POST /v1/project_logs/{PID}/insert  {"events":[{"id":<span_id>,"_is_merge":true,...}]}
WRITE TARGET  = row.id == row.span_id (16-hex). NOT root_span_id (32-hex = OTEL trace_id).
ROOT SELECT   = group by root_span_id; drop n==1 telemetry roots; keep n>=~6; root row = is_root==true / name==claude_code.interaction
TOOL META     = claude_code.tool span: tool_name, full_command(Bash), file_path(Read/Write), tool_use_id, session.id
OUTCOME       = claude_code.tool.execution span: success(bool) ; pair via tool_use_id
JOIN KEY      = tool_use_id (== gen_ai.tool.call.id) ; run key = session.id
PER-SPAN MERGE WORKS = TRUE (verified by re-read; deep-merge preserves originals)
```

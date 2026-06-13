# Playbook Factory -- 24/7 driver

> **BUILD-TIME TOOLING ONLY** -- not part of any hackathon submission; do **NOT** commit
> to the team repo. Subscription only: every model call is `claude -p` on `claude login`
> OAuth (model: `fable`); `ANTHROPIC_API_KEY` is unset by the driver *and* by the generator.

Runs `gen/build_playbook.py` (author -> grounded web INTEL -> adversarial verify) once per
category in `categories.txt` until all 24 have a clean playbook. It never stops on failure:
rate-limits/overloads/errors get exponential backoff (300s -> 600s -> 1200s, capped 1800s)
and the category is retried on the next pass -- **capped at 4 attempts** (see quarantine
below). When all 24 are done (or quarantined) it writes `READY_FOR_REVIEW.md` and exits 0.

## The v2 gate (what "done" means)

A category is **done** only when ALL of:

1. the generator exits 0 and `gen/<id>.md` exists;
2. `gen/<id>.verdict.json` exists, parses, and says `"blocking": false`. The verdict is
   emitted by a **score-only judge pass, separate from the editor** (no self-grading of
   its own edits); the driver gates on the parsed JSON -- never on grepping prose.

Then `done/<id>.ok` is touched and the accepted playbook is archived verbatim as
`versions/<id>/v1.md`.

- **`versions/<id>/v<n>.md` (+ diffs)** -- append-only, never pruned. v1 comes from this
  factory; v2+ are appended by the agent-only eval/tuning loop (`tune_playbook.py`). This
  archive is the submission's component #8 *iteration-over-iteration traces* -- treat it
  as evidence, not scratch space.
- **`quarantine/<id>.held`** -- after **4 failed attempts** a category is parked here and
  skipped on later passes (no infinite retry burning subscription quota). The file carries
  the last failure reason. A human clears it (`rm quarantine/<id>.held`) after fixing the
  cause; the next pass retries it fresh.

## Deploy (on the VM)

```bash
mkdir -p /cases/playground/factory/gen
# the driver + worklist
cp driver.sh categories.txt            /cases/playground/factory/
# the generator + its template (HERE = gen/, so playbooks land in gen/<id>.md)
cp playbooks/build_playbook.py playbooks/_TEMPLATE.md  /cases/playground/factory/gen/
# grounding files -- the generator resolves them from ROOT = parent of gen/:
#   'SIFT Inventory → IR Investigation Types'
#   'Complete_IR_Investigation_Type_Taxonomy_NIST800-61_PICERL.txt'  (real filename
#    has trailing spaces -- fine, the generator globs for it)
#   'Running_Tool_Claude_Verification'
cp <those three files>                 /cases/playground/factory/
chmod +x /cases/playground/factory/driver.sh

claude login        # one-time, Pro/Max subscription. NEVER set ANTHROPIC_API_KEY.
```

## Launch (survives logout)

```bash
cd /cases/playground/factory
setsid nohup ./driver.sh > driver.out 2>&1 < /dev/null &
```

`setsid` puts it in its own session (immune to terminal close); `nohup` belts-and-braces
the HUP. Relaunching after a crash/reboot is safe: `done/<id>.ok` categories are skipped.

## Watch progress

```bash
tail -f /cases/playground/factory/progress.log     # human log: START/DONE/RETRY/HELD lines
cat     /cases/playground/factory/progress.json    # {"total":24,"done":N,...} per pass
ls      /cases/playground/factory/done/            # one .ok per finished category
ls      /cases/playground/factory/quarantine/      # <id>.held = parked after 4 fails
ls      /cases/playground/factory/versions/        # <id>/v<n>.md -- version archive (#8 traces)
cat     /cases/playground/factory/gen/<id>.verdict.json   # the judge verdict that gated it
tail -f /cases/playground/factory/log/<id>.log     # the category currently running
```

Finished when `READY_FOR_REVIEW.md` appears (driver exits 0). It carries the completion
timestamp plus a per-category table of the verify rubric lines grepped from the logs --
that table is the fine-tuning dashboard (PLAYBOOK-GENERATOR.md section 7).

## Stop

```bash
pgrep -f 'factory/driver.sh'           # find the PID (it is its own session leader)
kill -- -<PID>                         # kill the whole session (driver + children)
pkill -f 'gen/build_playbook.py'       # mop up an in-flight generator call, if any
```

State is preserved -- relaunch any time and it resumes where it left off. To force-redo
one category: `rm done/<id>.ok quarantine/<id>.held` (optionally also `gen/<id>.md` and
`gen/<id>.verdict.json`) and relaunch. Do **NOT** delete anything under `versions/` --
that archive is append-only by contract (component #8 traces).

## Knobs (optional, defaults baked in)

- `PLAYBOOK_MODEL` (default `fable`)
- `PLAYBOOK_INTEL_ARGS` (default `--allowedTools WebSearch WebFetch` -- web tools for the
  INTEL arm only)

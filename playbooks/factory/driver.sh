#!/usr/bin/env bash
# =============================================================================
# driver.sh -- 24/7 PLAYBOOK FACTORY loop (BUILD-TIME TOOLING ONLY)
#
# Drives gen/build_playbook.py once per category in categories.txt until every
# category has a clean, verified playbook OR is quarantined for human review.
# It NEVER stops on failure: it backs off and retries; a category is only taken
# out of rotation after MAX_ATTEMPTS real failures (quarantine/<id>.held).
# It exits 0 only when all categories are .ok or .held.
# NOT part of any hackathon submission -- do NOT commit to the team repo.
#
# Deployed at: /cases/playground/factory/
#   ./driver.sh               this loop
#   ./categories.txt          worklist: <kebab-id>|<plain name + description>|<pre-mapped tool list (generator arg 3)>
#   ./gen/build_playbook.py   the generator (its ROOT = parent of gen/ = HERE,
#                             so the grounding files live in THIS directory)
#   ./gen/_TEMPLATE.md        house hybrid template (read by the generator)
#   ./SIFT Inventory ... / Complete_IR_..._Taxonomy*.txt /
#   ./Running_Tool_Claude_Verification        <- grounding files (ROOT level)
#   ./gen/<id>.md             generated playbooks
#   ./gen/<id>.verdict.json   verify-judge verdict (success gate: blocking==false)
#   ./done/<id>.ok            completion markers (restart-safe state)
#   ./log/<id>.log            per-category generator output
#   ./log/<id>.attempts       failed-attempt counter (cleared on success)
#   ./quarantine/<id>.held    written after MAX_ATTEMPTS failures: last fix_list,
#                             category skipped until a human deletes the file
#   ./progress.log            human-readable progress lines (append-only)
#   ./progress.json           machine-readable progress, rewritten each pass
#   ./READY_FOR_REVIEW.md     written once ALL categories are .ok or .held
#
# SUBSCRIPTION ONLY: every model call is `claude -p` on subscription OAuth
# (model: fable). ANTHROPIC_API_KEY is unset here AND again per child call
# inside build_playbook.py, so nothing silently bills the metered API.
#
# Restart-safe: kill it any time; relaunch skips every done/<id>.ok and
# quarantine/<id>.held category. Delete a .held file to put a category back
# into rotation (its attempts counter is reset alongside).
# =============================================================================
set -u

unset ANTHROPIC_API_KEY

cd "$(dirname "$0")" || exit 1

# Yield CPU + disk to interactive SSH and teammates' sessions (shared host).
# Self-nice to lowest priority; every child (build_playbook.py + its claude calls)
# inherits it, so the factory never starves an interactive login. Network-bound
# work, so throughput barely changes. (Also applied live via renice to a running tree.)
renice 19 $$ >/dev/null 2>&1 || true
command -v ionice >/dev/null 2>&1 && ionice -c3 -p $$ >/dev/null 2>&1 || true

CATEGORIES="categories.txt"
MODEL="${PLAYBOOK_MODEL:-opus}"
INTEL_ARGS="${PLAYBOOK_INTEL_ARGS:---allowedTools WebSearch WebFetch}"
BACKOFF_START=300          # seconds: 300 -> 600 -> 1200 -> capped at 1800
BACKOFF_MAX=1800
MAX_ATTEMPTS=4             # real (non-rate-limit) failures before quarantine
PAUSE_PROBE_START=300      # on a credit/rate limit: PAUSE generating, then probe
PAUSE_PROBE_MAX=1800       #   every 300 -> 600 -> ... -> 1800s until credit is back
PINGS="pings.log"          # append-only ping log (PAUSED / RESUMED) for the watcher
LIMIT_RE='rate.limit\|overloaded\|usage limit\|429\|529\|too many requests\|quota\|credit\|limit reached'

# --- deployment sanity (loud and early, BEFORE the never-exit loop) ---------
[ -f "$CATEGORIES" ]           || { echo "FATAL: $CATEGORIES missing" >&2; exit 1; }
[ -f gen/build_playbook.py ]   || { echo "FATAL: gen/build_playbook.py missing" >&2; exit 1; }

mkdir -p done log gen quarantine

backoff=$BACKOFF_START

ts() { date '+%Y-%m-%d %H:%M:%S'; }

note() { echo "[$(ts)] $*" >> progress.log; }

# --- success gate ------------------------------------------------------------
# A category is DONE iff:
#   1. build_playbook.py exited 0 (checked at the call site),
#   2. gen/<id>.md exists and is non-empty,
#   3. gen/<id>.verdict.json exists and parses as JSON with blocking == false.
# An unparseable/missing verdict is a FAILURE (no more grepping prose for
# 'blocking:False' -- the judge's JSON verdict is the only authority).
verdict_ok() {
  local id="$1"
  [ -s "gen/$id.md" ] || return 1
  [ -f "gen/$id.verdict.json" ] || return 1
  python3 - "gen/$id.verdict.json" <<'PY'
import json, sys
try:
    v = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)
sys.exit(0 if v.get("blocking") is False else 1)
PY
}

# --- attempts counter + quarantine -------------------------------------------
attempts_of() {
  local n=""
  [ -f "log/$1.attempts" ] && n=$(tr -dc '0-9' < "log/$1.attempts")
  echo "${n:-0}"
}

# quarantine <id>: write quarantine/<id>.held containing the last fix_list
# (from the verdict JSON if parseable, else a pointer to the log) and take the
# category out of rotation until a human deletes the file.
quarantine() {
  local id="$1"
  {
    echo "# HELD: $id -- $(attempts_of "$id") failed attempts; out of rotation pending human review"
    echo
    echo "held_at: $(ts)"
    echo "log: log/$id.log"
    echo "playbook (last draft, if any): gen/$id.md"
    echo "to retry: delete this file (attempts counter resets) and relaunch/let the loop pass again"
    echo
    echo "## last fix_list"
    python3 - "gen/$id.verdict.json" 2>/dev/null <<'PY' || echo "(no parseable gen/$id.verdict.json -- see log/$id.log for the raw failure)"
import json, sys
v = json.load(open(sys.argv[1]))
fl = v.get("fix_list") or []
if isinstance(fl, list):
    for item in fl:
        print("- %s" % item)
else:
    print(fl)
if not fl:
    print("(verdict parsed but fix_list empty -- see the log)")
PY
  } > "quarantine/$id.held"
  # counter only tracks in-rotation categories: reset NOW so that deleting the
  # .held file (the documented human "retry" action) grants a fresh
  # MAX_ATTEMPTS -- even across a driver restart.
  rm -f "log/$id.attempts"
}

write_progress_json() {
  python3 - <<'PY'
import json, os
ids = [l.split("|")[0].strip() for l in open("categories.txt")
       if l.strip() and not l.lstrip().startswith("#")]
ok = [i for i in ids if os.path.exists("done/%s.ok" % i)]
held = [i for i in ids if os.path.exists("quarantine/%s.held" % i)]
attempts = {}
for i in ids:
    p = "log/%s.attempts" % i
    if os.path.exists(p):
        try:
            attempts[i] = int(open(p).read().strip() or 0)
        except ValueError:
            attempts[i] = 0
json.dump({"total": len(ids),
           "done": len(ok),
           "completed": ok,
           "held_for_review": held,   # quarantined after repeated failures -- needs a human
           "failed_attempts": attempts,
           "remaining": [i for i in ids if i not in ok and i not in held]},
          open("progress.json", "w"), indent=2)
PY
}

# pending = neither .ok nor .held
pending_count() {
  local n=0 id rest
  while IFS='|' read -r -u 4 id rest; do
    case "$id" in ''|\#*) continue ;; esac
    [ -e "done/$id.ok" ] && continue
    [ -e "quarantine/$id.held" ] && continue
    n=$((n + 1))
  done 4< "$CATEGORIES"
  echo "$n"
}

held_count() {
  local n=0 id rest
  while IFS='|' read -r -u 4 id rest; do
    case "$id" in ''|\#*) continue ;; esac
    [ -e "quarantine/$id.held" ] && n=$((n + 1))
  done 4< "$CATEGORIES"
  echo "$n"
}

write_ready_for_review() {
  {
    echo "# PLAYBOOK FACTORY -- READY FOR REVIEW"
    echo
    echo "- all categories completed or held: $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "- playbooks: \`gen/<id>.md\` -- verdicts: \`gen/<id>.verdict.json\` -- full generator output: \`log/<id>.log\`"
    echo
    local id rest line any_held=0
    while IFS='|' read -r -u 4 id rest; do
      case "$id" in ''|\#*) continue ;; esac
      [ -e "quarantine/$id.held" ] && any_held=1
    done 4< "$CATEGORIES"
    if [ "$any_held" -eq 1 ]; then
      echo "## >>> HELD FOR REVIEW -- these categories FAILED $MAX_ATTEMPTS times and were quarantined <<<"
      echo
      echo "Read each \`quarantine/<id>.held\` (contains the last fix_list). Delete the .held file"
      echo "to put the category back into rotation."
      echo
      while IFS='|' read -r -u 4 id rest; do
        case "$id" in ''|\#*) continue ;; esac
        [ -e "quarantine/$id.held" ] || continue
        echo "- **$id** -- \`quarantine/$id.held\`"
      done 4< "$CATEGORIES"
      echo
    fi
    echo "| category | status | verify rubric (grepped from its log) |"
    echo "|---|---|---|"
    while IFS='|' read -r -u 4 id rest; do
      case "$id" in ''|\#*) continue ;; esac
      line=$(grep -m1 'rubric' "log/$id.log" 2>/dev/null | tr -s ' ' | sed 's/|/\\|/g')
      if [ -e "quarantine/$id.held" ]; then
        echo "| $id | **HELD** | ${line:-_(no rubric line found in log)_} |"
      else
        echo "| $id | ok | ${line:-_(no rubric line found in log)_} |"
      fi
    done 4< "$CATEGORIES"
    echo
    echo "Next: fine-tune per PLAYBOOK-GENERATOR.md section 7 -- read each log's"
    echo "fix-list and any rubric dimension scored <2, not the whole playbook."
  } > READY_FOR_REVIEW.md
}

# --- credit/rate-limit PAUSE + auto-resume -----------------------------------
# A subscription limit is account-wide, so EVERY category would fail. Instead of
# re-running the full (expensive) generation on backoff, we PAUSE the whole
# factory, drop a ping, and probe cheaply (haiku) until credit returns -- then
# auto-resume. A human can force resume early by deleting PAUSED.flag.
ping_log() { echo "[$(ts)] $*" >> "$PINGS"; note "$*"; }

credit_ok() {
  # cheap probe: 0 iff a minimal subscription call succeeds (no limit error)
  local out rc
  out=$(claude -p "ping" --model haiku --output-format json 2>&1); rc=$?
  [ "$rc" -eq 0 ] && ! printf '%s' "$out" | grep -qi "$LIMIT_RE"
}

wait_for_credit() {
  local id="$1" probe=$PAUSE_PROBE_START waited=0
  {
    echo "paused_at: $(ts)"
    echo "stuck_on: $id"
    echo "reason: claude subscription rate-limit / credit appears exhausted"
    echo "behavior: factory is PAUSED (NO playbook generation -- only a tiny haiku probe"
    echo "          every few minutes). It auto-resumes the moment credit returns."
    echo "force resume now: delete this PAUSED.flag file."
  } > PAUSED.flag
  ping_log "PAUSED on '$id' -- credit/rate limit hit. Factory idle except a cheap probe; auto-resumes when credit returns."
  while [ -e PAUSED.flag ] && ! credit_ok; do
    sleep "$probe"
    probe=$((probe * 2)); [ "$probe" -gt "$PAUSE_PROBE_MAX" ] && probe=$PAUSE_PROBE_MAX
    waited=$((waited + probe))
    if [ "$waited" -ge 18000 ] && [ ! -e PAUSED.escalated ]; then    # ~5h still blocked
      : > PAUSED.escalated
      ping_log "STILL PAUSED ~5h on '$id' -- likely the MONTHLY Agent-SDK credit, not the 5-hour window. Options: switch PLAYBOOK_MODEL to a cheaper model, enable usage-credit overflow, or wait for the monthly refresh. Still probing."
    fi
  done
  rm -f PAUSED.flag PAUSED.escalated
  ping_log "RESUMED -- credit is back; continuing the factory from '$id'."
}

note "factory driver started (model=$MODEL, intel_args=$INTEL_ARGS, max_attempts=$MAX_ATTEMPTS)"

while true; do
  # one pass over the worklist; fd 3 so child stdin/stdout can't eat the list
  while IFS='|' read -r -u 3 id desc tools; do
    case "$id" in ''|\#*) continue ;; esac          # skip blanks + comments
    [ -e "done/$id.ok" ] && continue                # restart-safe skip
    [ -e "quarantine/$id.held" ] && continue        # quarantined: human review
                                                    # (attempts already reset)

    note "START $id (failed attempts so far: $(attempts_of "$id")/$MAX_ATTEMPTS)"
    if PLAYBOOK_MODEL="$MODEL" PLAYBOOK_INTEL_ARGS="$INTEL_ARGS" \
         python3 gen/build_playbook.py "$id" "$desc" "$tools" >"log/$id.log" 2>&1 </dev/null \
       && verdict_ok "$id"; then
      touch "done/$id.ok"
      rm -f "log/$id.attempts"
      backoff=$BACKOFF_START
      note "DONE  $id  $(grep -m1 'rubric' "log/$id.log" | tr -s ' ')"
    else
      if grep -qi "$LIMIT_RE" "log/$id.log"; then
        # SUBSCRIPTION LIMIT (account-wide): PAUSE the whole factory, ping, and
        # auto-resume when credit returns. NOT a quarantine attempt -- the cap is
        # for pathological categories, not for the credit window being exhausted.
        wait_for_credit "$id"
        continue                                     # re-attempt $id next pass; no backoff/attempt
      else
        attempts=$(( $(attempts_of "$id") + 1 ))
        echo "$attempts" > "log/$id.attempts"
        if [ "$attempts" -ge "$MAX_ATTEMPTS" ]; then
          quarantine "$id"
          note "HELD  $id -- $attempts failed attempts; quarantine/$id.held written (last fix_list inside); SKIPPING until a human clears it"
          continue                                   # no backoff burn for a held category
        fi
        note "RETRY $id (exit!=0, verdict missing/blocking, or gen/$id.md missing) -- attempt $attempts/$MAX_ATTEMPTS -- backoff ${backoff}s"
      fi
      sleep "$backoff"
      backoff=$((backoff * 2))
      if [ "$backoff" -gt "$BACKOFF_MAX" ]; then backoff=$BACKOFF_MAX; fi
      # NEVER exit: fall through to the next category; this one is retried
      # automatically on the next pass of the outer while-true loop.
    fi
  done 3< "$CATEGORIES"

  write_progress_json

  if [ "$(pending_count)" -eq 0 ]; then
    write_ready_for_review
    if [ "$(held_count)" -gt 0 ]; then
      note "ALL CATEGORIES .ok OR .held ($(held_count) held -- see quarantine/) -> READY_FOR_REVIEW.md ; exiting 0"
    else
      note "ALL CATEGORIES DONE -> READY_FOR_REVIEW.md ; exiting 0"
    fi
    exit 0
  fi

  note "pass complete -- $(pending_count) categories still pending; looping"
done

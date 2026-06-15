#!/usr/bin/env bash
# =============================================================================
# Protocol SIFT — ABLATION-RUNNER  (Diagnosis Protocol, Stage 4 confirmation step)
# BUILD-TIME / OPERATOR-LAYER TOOLING. Runs on the josh-pc operator layer (the
# layer that owns parity_check.py, the scorers, and the round exports). It is
# the ONLY mechanism allowed to attribute a measured score delta to ONE specific
# rule/lane artifact (RULE-CHANGE-DIAGNOSIS-PROTOCOL.md, Stage 4.1 / Branch F).
#
# WHAT IT DOES (one clean single-artifact ablation lap):
#   1. parity_check.py --out <before>            snapshot the CURRENT ~/.claude
#   2. apply the toggle in the right lane        (operator supplies the toggle cmd)
#   3. make render && make sync (or sync-skills)  deploy the toggled artifact -> live
#   4. parity_check.py --out <after>             snapshot the toggled ~/.claude
#   5. parity_check.py --diff before after --expect N   MUST pass (exactly N changed,
#                                                default N=1) else ABORT (attributable
#                                                to nothing / parity broken).
#   6. re-run the SAME case N rounds via the SEALED runner (run_batch.sh), per arm
#   7. re-score the exported rounds (operator's scorers) -> per-round score JSONs
#   8. feed the aggregator (aggregate_failures.py) -> per-arm f/n + Wilson + 2-prop
#   9. report the failure-rate delta vs the recorded baseline.
#  10. ALWAYS restore the original lane on exit (idempotent), whatever happened.
#
# IT NEVER edits a rule itself and NEVER reads findings content. The TOGGLE is
# supplied by the operator (the diagnosis decided WHICH artifact); this wrapper
# only guarantees the lap is clean (parity==N), sealed, re-scored, and restored.
#
# DESIGN: every external command is injected via an env var so the lap is fully
# orchestratable AND unit-testable without sudo / ssh / a live ~/.claude. Defaults
# are the real tools. Override in tests with stubs.
#
#   PARITY_CMD        default: python3 <eval>/parity_check.py
#   MAKE_CMD          default: make -C <protocol-sift dir>
#   RUNNER_CMD        default: sudo <playground>/run_batch.sh
#   SCORE_CMD         default: (operator re-score hook; see --score-cmd)
#   AGGREGATE_CMD     default: python3 <eval>/diagnosis/aggregate_failures.py
#
# stdlib / coreutils only. No python beyond the injected tools.
# =============================================================================
set -uo pipefail

PROG="$(basename "$0")"

# ---- defaults (resolved relative to repo layout; all overridable) -----------
# REPO_ROOT lets the real wiring point at the find-evil-hackathon checkout.
REPO_ROOT="${ABLATE_REPO_ROOT:-}"
EVAL_DIR="${ABLATE_EVAL_DIR:-}"
PSIFT_DIR="${ABLATE_PSIFT_DIR:-}"

PARITY_CMD="${ABLATE_PARITY_CMD:-}"
MAKE_CMD="${ABLATE_MAKE_CMD:-}"
RUNNER_CMD="${ABLATE_RUNNER_CMD:-}"
SCORE_CMD="${ABLATE_SCORE_CMD:-}"        # optional; if empty, scoring step is skipped (warned)
AGGREGATE_CMD="${ABLATE_AGGREGATE_CMD:-}"

# ---- cli ---------------------------------------------------------------------
RULE_ID="" CASE_ID="" CASE_PATH="" ARM="both" ROUNDS=5 EXPECT=1
LANE="contract"                # contract | prose | skill  -> selects render+sync vs sync vs sync-skills
TOGGLE_CMD=""                  # operator-supplied: apply the ONE artifact change
RESTORE_CMD=""                 # operator-supplied: undo it (idempotent). If empty, derived from git.
WORKDIR=""                     # where snapshots/score JSONs land
BASELINE_AGG=""                # optional: path to the pre-change aggregate JSON to delta against
DRY_RUN=0

usage(){ cat >&2 <<EOF
$PROG — single-artifact ablation lap (Diagnosis Protocol Stage 4 confirmation).

REQUIRED:
  --rule <id>          rule/lane artifact under test (recorded onto the lap)
  --case-id <id>       case to re-run (sealed)
  --toggle '<cmd>'     shell cmd that applies the ONE artifact change in the lane

COMMON:
  --case <path>        evidence path for the sealed runner (required unless queue-resolved)
  --lane contract|prose|skill   deploy path (default contract = make render && make sync)
  --arm sift|bare|both default both
  --rounds N           sealed rounds per arm (default 5; DECISION tier = 20)
  --expect N           expected changed-artifact count for parity --diff (default 1;
                       >1 ONLY for a documented Stage-4.2 GROUP ablation)
  --restore '<cmd>'    shell cmd that undoes the toggle (default: git checkout the lane source)
  --workdir <dir>      snapshot + score output dir (default: ./ablation-<rule>-<ts>)
  --baseline <agg.json> baseline aggregate to delta against (optional)
  --dry-run            print the plan, run parity+diff+restore only, skip sealed run+score
  -h|--help

The toggle/restore are OPERATOR-supplied because the DIAGNOSIS (Stages 1-3) decided
WHICH artifact to change; this wrapper only guarantees the lap is clean + restored.
EOF
exit "${1:-2}"; }

die(){ echo "$PROG: FATAL: $*" >&2; exit 1; }
log(){ echo "$PROG: $*" >&2; }

while [ $# -gt 0 ]; do case "$1" in
  --rule)     RULE_ID="${2:-}"; shift;;
  --case-id)  CASE_ID="${2:-}"; shift;;
  --case)     CASE_PATH="${2:-}"; shift;;
  --lane)     LANE="${2:-}"; shift;;
  --arm)      ARM="${2:-}"; shift;;
  --rounds)   ROUNDS="${2:-}"; shift;;
  --expect)   EXPECT="${2:-}"; shift;;
  --toggle)   TOGGLE_CMD="${2:-}"; shift;;
  --restore)  RESTORE_CMD="${2:-}"; shift;;
  --workdir)  WORKDIR="${2:-}"; shift;;
  --baseline) BASELINE_AGG="${2:-}"; shift;;
  --dry-run)  DRY_RUN=1;;
  -h|--help)  usage 0;;
  *) die "unknown arg: $1 (try --help)";;
esac; shift; done

# ---- validate args -----------------------------------------------------------
[ -n "$RULE_ID" ]   || { log "missing --rule";   usage; }
[ -n "$CASE_ID" ]   || { log "missing --case-id"; usage; }
[ -n "$TOGGLE_CMD" ]|| { log "missing --toggle";  usage; }
case "$LANE" in contract|prose|skill) : ;; *) die "--lane must be contract|prose|skill";; esac
case "$ARM"  in sift|bare|both) : ;; *) die "--arm must be sift|bare|both";; esac
case "$EXPECT" in ''|*[!0-9]*) die "--expect must be a non-negative integer";; esac
case "$ROUNDS" in ''|*[!0-9]*) die "--rounds must be a positive integer";; esac
[ "$ROUNDS" -ge 1 ] || die "--rounds must be >= 1"

# resolve the make target for the lane (Stage 4.1 step 2 deploy rule)
case "$LANE" in
  contract) MAKE_TARGETS="render sync" ;;   # contract.yaml clause -> render then sync
  prose)    MAKE_TARGETS="sync" ;;          # global/CLAUDE.md prose bullet -> sync
  skill)    MAKE_TARGETS="sync-skills" ;;   # one SKILL.md -> sync-skills
esac

# ---- resolve injected commands (defaults only if a repo root is given) -------
if [ -z "$PARITY_CMD" ]; then
  [ -n "$EVAL_DIR" ] || EVAL_DIR="${REPO_ROOT:+$REPO_ROOT/eval}"
  [ -n "$EVAL_DIR" ] || die "no --parity wiring: set ABLATE_PARITY_CMD or ABLATE_REPO_ROOT/ABLATE_EVAL_DIR"
  PARITY_CMD="python3 $EVAL_DIR/parity_check.py"
fi
if [ -z "$MAKE_CMD" ]; then
  [ -n "$PSIFT_DIR" ] || PSIFT_DIR="${REPO_ROOT:+$REPO_ROOT/protocol-sift}"
  [ -n "$PSIFT_DIR" ] || die "no --make wiring: set ABLATE_MAKE_CMD or ABLATE_REPO_ROOT/ABLATE_PSIFT_DIR"
  MAKE_CMD="make -C $PSIFT_DIR"
fi
if [ -z "$RUNNER_CMD" ]; then
  RUNNER_CMD="sudo /opt/playground/run_batch.sh"
fi
if [ -z "$AGGREGATE_CMD" ] && [ -n "$EVAL_DIR" ]; then
  AGGREGATE_CMD="python3 $EVAL_DIR/diagnosis/aggregate_failures.py"
fi

# ---- workdir -----------------------------------------------------------------
TS="$(date -u +%Y%m%dT%H%M%SZ)"
[ -n "$WORKDIR" ] || WORKDIR="./ablation-${RULE_ID}-${TS}"
mkdir -p "$WORKDIR" || die "cannot create workdir: $WORKDIR"
BEFORE="$WORKDIR/parity_before.json"  # leak-scan: allow secret.deobfuscated  (WORKDIR path var, not a secret)
AFTER="$WORKDIR/parity_after.json"
DIFF_JSON="$WORKDIR/parity_diff.json"
LAP_RECORD="$WORKDIR/lap.json"
SCORES_DIR="$WORKDIR/scores"; mkdir -p "$SCORES_DIR"
AGG_OUT="$WORKDIR/aggregate.json"

# ---- idempotent restore on exit ---------------------------------------------
RESTORED=0
restore_lane(){
  [ "$RESTORED" -eq 1 ] && return 0      # idempotent: restore at most once
  RESTORED=1
  if [ -n "$RESTORE_CMD" ]; then
    log "restoring lane (operator restore cmd)"
    eval "$RESTORE_CMD" || log "WARN: restore cmd returned nonzero (verify the lane manually)"
  else
    log "restoring lane via git checkout of the toggled source"
    if [ -n "$PSIFT_DIR" ] && [ -d "$PSIFT_DIR/.git" ] || git -C "${PSIFT_DIR:-.}" rev-parse 2>/dev/null; then
      git -C "${PSIFT_DIR:-.}" checkout -- . 2>/dev/null || log "WARN: git restore failed; verify lane manually"
    else
      log "WARN: no --restore cmd and no git repo to restore from; verify lane manually"
    fi
  fi
  # re-deploy the restored source so ~/.claude matches the repo again
  $MAKE_CMD $MAKE_TARGETS >/dev/null 2>&1 || log "WARN: re-sync after restore returned nonzero"
  log "lane restored."
}
trap restore_lane EXIT INT TERM

# ---- helper: run parity --diff and assert == EXPECT -------------------------
# parity_check.py --diff exits 0 iff changed_artifacts <= 1 (legacy) OR == EXPECT
# (new --expect N flag). We pass --expect and trust its exit code, AND re-verify
# the count from the printed JSON so the gate is double-checked operator-side.
assert_parity_diff(){
  log "parity diff: expecting exactly $EXPECT changed artifact(s)"
  if ! $PARITY_CMD --diff "$BEFORE" "$AFTER" --expect "$EXPECT" >"$DIFF_JSON" 2>"$WORKDIR/parity_diff.stderr"; then
    cat "$WORKDIR/parity_diff.stderr" >&2
    cat "$DIFF_JSON" >&2
    die "parity --diff FAILED (host/version drift, or changed != $EXPECT). Lap attributable to nothing — ABORT."
  fi
  # double-check the count from the JSON (defence in depth; tolerate missing python)
  if command -v python3 >/dev/null 2>&1; then
    local n
    n="$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(len(d.get("changed_artifacts",{})))' "$DIFF_JSON" 2>/dev/null || echo "?")"
    if [ "$n" != "?" ] && [ "$n" != "$EXPECT" ]; then
      die "parity --diff exit 0 but changed_artifacts=$n != expected $EXPECT — ABORT (gate inconsistency)."
    fi
    log "parity diff OK: changed_artifacts=$n == expected $EXPECT"
  else
    log "parity diff OK (exit 0; python unavailable for count re-check)"
  fi
}

# ============================================================================
# LAP
# ============================================================================
log "ablation lap START rule=$RULE_ID case=$CASE_ID lane=$LANE arm=$ARM rounds=$ROUNDS expect=$EXPECT"

# 1. snapshot BEFORE (this also HARD-GATES: right host / CLAUDE.md present / skills / no API key)
log "step 1: parity snapshot BEFORE -> $BEFORE"
$PARITY_CMD --out "$BEFORE" >"$WORKDIR/parity_before.stderr" 2>&1 \
  || { cat "$WORKDIR/parity_before.stderr" >&2; die "parity pre-gate FAILED — environment is not Protocol-SIFT-on-the-workstation. ABORT before toggling."; }

# 2. apply the ONE toggle in the lane
log "step 2: apply toggle: $TOGGLE_CMD"
eval "$TOGGLE_CMD" || die "toggle cmd returned nonzero — nothing deployed yet; ABORT."

# 3. deploy it (render/sync per lane) so ~/.claude reflects the toggle
log "step 3: deploy ($MAKE_CMD $MAKE_TARGETS)"
$MAKE_CMD $MAKE_TARGETS >"$WORKDIR/make_sync.log" 2>&1 \
  || { cat "$WORKDIR/make_sync.log" >&2; die "make $MAKE_TARGETS FAILED — toggle not deployed cleanly; ABORT (restore on exit)."; }

# 4. snapshot AFTER
log "step 4: parity snapshot AFTER -> $AFTER"
$PARITY_CMD --out "$AFTER" >"$WORKDIR/parity_after.stderr" 2>&1 \
  || { cat "$WORKDIR/parity_after.stderr" >&2; die "parity post-snapshot FAILED — ABORT (restore on exit)."; }

# 5. assert exactly EXPECT changed -> the one-change-per-lap (or named-group) gate
assert_parity_diff

if [ "$DRY_RUN" -eq 1 ]; then
  log "DRY RUN: parity gate passed (changed==$EXPECT). Skipping sealed run + score + aggregate."
  printf '{"rule":"%s","case":"%s","lane":"%s","arm":"%s","rounds":%s,"expect":%s,"parity":"OK","dry_run":true}\n' \
    "$RULE_ID" "$CASE_ID" "$LANE" "$ARM" "$ROUNDS" "$EXPECT" > "$LAP_RECORD"
  log "lap record -> $LAP_RECORD"
  exit 0   # trap restores the lane
fi

# 6. re-run the SAME case N rounds through the SEALED runner (untouched orchestrator).
#    The wrapper does NOT read findings; the sealed path exports to josh-pc as usual.
[ -n "$CASE_PATH" ] || die "step 6 needs --case <evidence path> for the sealed runner."
log "step 6: sealed re-run ($RUNNER_CMD --case-id $CASE_ID --arm $ARM --rounds $ROUNDS)"
$RUNNER_CMD --case-id "$CASE_ID" --case "$CASE_PATH" --arm "$ARM" --rounds "$ROUNDS" \
  >"$WORKDIR/run_batch.log" 2>&1 \
  || log "WARN: sealed runner returned nonzero (run_batch swallows launch exits; check run_batch.log + exports)"

# 7. re-score the exported rounds -> per-round score JSONs in $SCORES_DIR
#    SCORE_CMD is the operator's re-score hook; it receives the scores dir + case + rounds.
if [ -n "$SCORE_CMD" ]; then
  log "step 7: re-score -> $SCORES_DIR"
  ABLATE_SCORES_DIR="$SCORES_DIR" ABLATE_CASE_ID="$CASE_ID" ABLATE_ARM="$ARM" ABLATE_ROUNDS="$ROUNDS" \
    eval "$SCORE_CMD" >"$WORKDIR/score.log" 2>&1 \
    || log "WARN: score cmd returned nonzero (check score.log)"
else
  log "step 7: no --score-cmd / ABLATE_SCORE_CMD set — skipping local re-score (operator must score the exports manually)."
fi

# 8. feed the aggregator -> per-arm f/n + Wilson + two-proportion
if [ -n "$AGGREGATE_CMD" ]; then
  log "step 8: aggregate ($AGGREGATE_CMD)"
  $AGGREGATE_CMD --scores-dir "$SCORES_DIR" --out "$AGG_OUT" \
    >"$WORKDIR/aggregate.log" 2>&1 \
    || log "WARN: aggregator returned nonzero (check aggregate.log; aggregator tool #1 may not be wired yet)"
else
  log "step 8: no aggregator wired (ABLATE_AGGREGATE_CMD unset / no repo eval dir). Skipping rate delta; per-round scores are in $SCORES_DIR."
fi

# 9. report the rate delta vs the baseline aggregate (best-effort; aggregator owns the math)
if [ -s "$AGG_OUT" ] && [ -n "$BASELINE_AGG" ] && [ -s "$BASELINE_AGG" ] && command -v python3 >/dev/null 2>&1; then
  log "step 9: rate delta vs baseline"
  python3 - "$BASELINE_AGG" "$AGG_OUT" <<'PY' >&2 || log "WARN: delta render failed"
import json, sys
base = json.load(open(sys.argv[1])); post = json.load(open(sys.argv[2]))
def rate(d, arm):
    a = (d.get("arms") or {}).get(arm) or {}
    f, n = a.get("f"), a.get("n")
    return (f, n, (f / n if (isinstance(f,(int,float)) and n) else None))
for arm in ("sift", "bare"):
    bf, bn, br = rate(base, arm); pf, pn, pr = rate(post, arm)
    if br is None and pr is None: continue
    print(f"  {arm}: baseline {bf}/{bn} -> post {pf}/{pn}"
          + (f"  (rate {br:.3f} -> {pr:.3f})" if (br is not None and pr is not None) else ""))
print("  (KEEP iff target-improvement two-proportion 95% CI excludes 0 AND zero guard-case regressions — Stage 4.3; the aggregator owns the CI.)")
PY
else
  log "step 9: no baseline (--baseline) or no aggregate output — skipping delta (record this lap's aggregate as the baseline for the next lap)."
fi

# lap record (audit trail: what was toggled, parity fingerprints, where the scores are)
cat > "$LAP_RECORD" <<EOF
{
  "rule": "$RULE_ID",
  "case": "$CASE_ID",
  "lane": "$LANE",
  "arm": "$ARM",
  "rounds": $ROUNDS,
  "expect": $EXPECT,
  "parity_before": "$BEFORE",
  "parity_after": "$AFTER",
  "parity_diff": "$DIFF_JSON",
  "scores_dir": "$SCORES_DIR",
  "aggregate": "$AGG_OUT",
  "baseline": "$BASELINE_AGG",
  "dry_run": false
}
EOF
log "lap record -> $LAP_RECORD"
log "ablation lap DONE (lane restored on exit)."
exit 0

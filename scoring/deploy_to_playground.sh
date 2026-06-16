#!/usr/bin/env bash
# =============================================================================
# Deploy the deterministic DFIR scorer into Protocol SIFT playground(s).
#
# Run this INSIDE the SIFT workstation (sift-vm), from a checkout of
# feat/eval-loop:   git pull && bash scoring/deploy_to_playground.sh
#
# It installs the SCORER CODE ONLY — scorer.py, test_scorer.py, gen_attack_ids.py
# (all answer-key-free). It NEVER copies ground_truth / answer keys onto the VM:
# blind-eval requires the key DATA to stay off the agent's reach. Keys are
# injected transiently at score time (see the note printed at the end).
#
# Usage:
#   bash deploy_to_playground.sh [PLAYGROUND_DIR ...]
#   - With args: install into exactly those playground roots.
#   - No args:   auto-discover immediate subdirs of $PLAYGROUND_ROOT
#                (default /cases/playground).
# Env:
#   PLAYGROUND_ROOT   where to auto-discover playgrounds (default /cases/playground)
#   DEST_SUBDIR       where inside each playground to install (default scoring)
# Idempotent; safe to re-run. Exits non-zero if any integrity check fails.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAYGROUND_ROOT="${PLAYGROUND_ROOT:-/cases/playground}"
DEST_SUBDIR="${DEST_SUBDIR:-scoring}"
FILES=(scorer.py test_scorer.py gen_attack_ids.py)

py() { command -v python3 >/dev/null 2>&1 && echo python3 || echo python; }
PY="$(py)"

# --- 0. sanity: the source scorer we're shipping is the validated one ---------
for f in "${FILES[@]}"; do
  [[ -f "$SCRIPT_DIR/$f" ]] || { echo "FATAL: missing $SCRIPT_DIR/$f — run from a scoring/ checkout"; exit 2; }
done
if ! grep -q 'def mitre_precision' "$SCRIPT_DIR/scorer.py"; then
  echo "FATAL: $SCRIPT_DIR/scorer.py lacks mitre_precision — wrong/old checkout (want >= 97032ef)"; exit 2
fi
echo "== source scorer: $SCRIPT_DIR  (HEAD $(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || echo '?'))"

# --- 1. verify the source in place before installing it anywhere --------------
echo "== integrity check (source) =="
( cd "$SCRIPT_DIR" && "$PY" -m unittest test_scorer 2>&1 | tail -1 )

# --- 2. resolve target playgrounds --------------------------------------------
targets=()
if [[ $# -gt 0 ]]; then
  targets=("$@")
else
  shopt -s nullglob
  for d in "$PLAYGROUND_ROOT"/*/; do targets+=("${d%/}"); done
  shopt -u nullglob
fi
if [[ ${#targets[@]} -eq 0 ]]; then
  echo "No playgrounds found under $PLAYGROUND_ROOT (pass paths as args, or set PLAYGROUND_ROOT)."; exit 1
fi
echo "== ${#targets[@]} playground(s): ${targets[*]}"

# --- 3. install + verify per playground (NO keys copied) ----------------------
fail=0
for PG in "${targets[@]}"; do
  [[ -d "$PG" ]] || { echo "  SKIP (not a dir): $PG"; fail=1; continue; }
  dest="$PG/$DEST_SUBDIR"
  mkdir -p "$dest"
  for f in "${FILES[@]}"; do cp "$SCRIPT_DIR/$f" "$dest/"; done
  result="$( cd "$dest" && "$PY" -m unittest test_scorer 2>&1 | tail -1 || true )"
  echo "  $PG/$DEST_SUBDIR  ->  $result"
  echo "$result" | grep -q '^OK$' || fail=1
done

# --- 4. guardrail: assert no answer keys leaked onto the VM -------------------
leaked="$(find "${targets[@]}" -maxdepth 3 -name 'ground_truth' -o -name 'VIGIA-REAL-*.json' 2>/dev/null || true)"
if [[ -n "$leaked" ]]; then
  echo "WARNING: answer-key-shaped paths found in a playground — blind-eval requires keys OFF the VM:"
  echo "$leaked" | sed 's/^/    /'
  fail=1
fi

echo
echo "== DONE.  Scorer code installed; NO answer keys placed (blind-eval preserved)."
cat <<'NOTE'
   To SCORE without persisting keys on the VM, mount/copy ground_truth/ from the
   isolated host store into a tmpfs at score time, run, then wipe:
     KEYS=$(mktemp -d)                      # ideally a tmpfs path
     # ... copy ground_truth/ + case_inputs/ + reports/ into $KEYS (from host) ...
     python3 scorer.py --data-dir "$KEYS"
     rm -rf "$KEYS"                         # keys never persist on disk
NOTE

[[ $fail -eq 0 ]] && { echo "ALL GREEN"; exit 0; } || { echo "SOME STEPS FAILED (see above)"; exit 1; }

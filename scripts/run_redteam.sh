#!/usr/bin/env bash
# Red-team battery for leak_scan.py.
#
# Convention:
#   block_*  + foo.bak + settings.local.json  MUST exit 1 (>=1 BLOCK finding)
#   ok_*                                       MUST exit 0 (clean)
#
# Every fixture uses FAKE/synthetic secrets + FAKE answer strings (blind-isolation
# rule) — NEVER real answer keys or real secrets.
#
# Usage:  bash run_redteam.sh   (run from the leak-scan-build dir)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SCAN="$HERE/leak_scan.py"
RT="$HERE/redteam"
fail=0

expect() {  # $1=expected_exit  $2=file
  # --root "$RT" pins root INSIDE the redteam dir so the build-dir
  # .leakscanignore (which whole-file exempts redteam/** for the SELF-scan gate)
  # is NOT discovered here — the battery tests RAW detection on the fixtures,
  # which must still BLOCK.
  python3 "$SCAN" --root "$RT" --files "$RT/$2" >/dev/null 2>&1
  local got=$?
  if [ "$got" != "$1" ]; then
    echo "FAIL  expected exit=$1 got=$got  $2"
    fail=1
  else
    echo "ok    exit=$got  $2"
  fi
}

for f in "$RT"/*; do
  base="$(basename "$f")"
  [ -f "$f" ] || continue
  case "$base" in
    block_*|foo.bak|settings.local.json) expect 1 "$base" ;;
    ok_*)                                 expect 0 "$base" ;;
    *) echo "skip  (unclassified) $base" ;;
  esac
done

if [ "$fail" = 0 ]; then
  echo "RED-TEAM BATTERY: PASS (all MUST-BLOCK caught, zero FP on ok_*)"
else
  echo "RED-TEAM BATTERY: FAIL"
fi
exit "$fail"

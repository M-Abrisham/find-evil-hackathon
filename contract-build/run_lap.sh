#!/bin/bash
# Re-run the 3 VIGIA cases through Protocol SIFT with the deployed Deliverable Contract.
# Sequential (5 GiB VM). Apples-to-apples: same prompts/launcher as the baseline run.
cd /home/ubuntu/find-evil/baseline/protocol-sift || exit 9
D=/home/ubuntu/eval-batch/runs
: > "$D/lap_progress.log"
rm -f "$D"/lap_done "$D"/lap_case*.done
for N in 1 2 7; do
  echo "START case$N $(date -u +%H:%M:%S)" >> "$D/lap_progress.log"
  bash "$D/run_case.sh" "$N" > "$D/out_lap_case$N.json" 2> "$D/err_lap_case$N.log"
  echo "END   case$N rc=$? $(date -u +%H:%M:%S)" >> "$D/lap_progress.log"
  touch "$D/lap_case$N.done"
done
touch "$D/lap_done"
echo "ALL DONE $(date -u +%H:%M:%S)" >> "$D/lap_progress.log"

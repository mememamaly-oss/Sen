#!/bin/bash
# STEP 2c (atomic): REAL full-config engine store run (Python API, benchmark
# config + symbolic + race + workflow + logic) + independent clean-engine
# replay of EVERY persisted proof. Uses the repo's own methodology script.
set -uo pipefail
cd /home/z/my-project
export PYTHONPATH=/home/z/my-project

echo "== [0] guard =="
CUR=$(git rev-parse HEAD); BR=$(git branch --show-current)
echo "HEAD=$CUR branch=$BR"
[ "$CUR" = "0759c85ab639fdb555ba19b465d291b3d2b27999" ] && [ "$BR" = "main" ] || { echo "ABORT: unexpected tree state"; exit 1; }

echo "== [1] store run + replay (single methodology script) =="
T0=$(date +%s)
timeout 560 python3 scripts/reverify/store_run_and_replay.py 2>&1 | tail -25
RC=$?
T1=$(date +%s)
echo "store_run_and_replay rc=$RC wall=$((T1-T0))s"
[ $RC -ne 0 ] && { echo "STORE RUN FAILED OR TIMED OUT — will need a resumable fallback"; exit 2; }

echo "== [2] replay summary from artifact =="
python3 -c "
import json
d = json.load(open('evidence/full-reverify/fixtures-vulnapp/replay_results.json'))
print(json.dumps(d['summary'], indent=1))"
echo "== [3] tree status =="
git status --short | head -10
echo "STEP2C COMPLETE"

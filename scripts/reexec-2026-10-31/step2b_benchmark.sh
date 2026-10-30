#!/bin/bash
# STEP 2b (atomic): REAL engine re-run — fixtures benchmark CLI (all detectors
# + race battery), fresh output replacing the prior run's artifact.
set -uo pipefail
cd /home/z/my-project
export PYTHONPATH=/home/z/my-project

echo "== [0] guard =="
CUR=$(git rev-parse HEAD); BR=$(git branch --show-current)
echo "HEAD=$CUR branch=$BR"
[ "$CUR" = "0759c85ab639fdb555ba19b465d291b3d2b27999" ] && [ "$BR" = "main" ] || { echo "ABORT: unexpected tree state"; exit 1; }
EV=evidence/full-reverify/fixtures-vulnapp

echo "== [1] benchmark CLI run (all detectors + race battery) =="
T0=$(date +%s)
timeout 540 python3 -m sentinel.cli benchmark --race \
  --out $EV/benchmark.json \
  > $EV/benchmark_stdout.log 2>&1
RC=$?
T1=$(date +%s)
echo "benchmark rc=$RC wall=$((T1-T0))s"
tail -6 $EV/benchmark_stdout.log
[ $RC -ne 0 ] && { echo "BENCHMARK FAILED"; exit 2; }

echo "== [2] results =="
python3 - <<'PYEOF'
import json
from collections import Counter
d = json.load(open("evidence/full-reverify/fixtures-vulnapp/benchmark.json"))
print("confusion:", d["confusion"], "| P/R/F1:", d["precision"], d["recall"], d["f1"])
print("run_id:", d["run_id"], "| requests:", d["stats"]["requests"], "| findings:", len(d["findings"]))
tc = Counter(f["type"] for f in d["findings"])
print("finding types:", dict(tc.most_common()))
sv = sum(1 for f in d["findings"] if f.get("status") == "verified")
print("scan-time verified:", sv, "/", len(d["findings"]))
PYEOF

echo "== [3] tree status =="
git status --short | head -8
echo "STEP2B COMPLETE"

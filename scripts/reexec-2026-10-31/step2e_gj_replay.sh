#!/bin/bash
# STEP 2e (atomic): ginandjuice clean-engine replay of EVERY persisted proof.
# Micro-audit first: the committed replay_progress.jsonl belongs to the PRIOR
# run — if finding ids are deterministic and collide, the resume logic would
# pass off stale verdicts. Prove the collision, reset the progress file, then
# replay fresh.
set -uo pipefail
cd /home/z/my-project
export PYTHONPATH=/home/z/my-project

echo "== [0] guard =="
CUR=$(git rev-parse HEAD); BR=$(git branch --show-current)
echo "HEAD=$CUR branch=$BR"
[ "$CUR" = "0759c85ab639fdb555ba19b465d291b3d2b27999" ] && [ "$BR" = "main" ] || { echo "ABORT: unexpected tree state"; exit 1; }
EV=evidence/full-reverify/ginandjuice-shop

echo "== [1] id-collision audit: prior progress ids vs NEW scan finding ids =="
python3 - <<'PYEOF'
import json
from pathlib import Path
EV = Path("evidence/full-reverify/ginandjuice-shop")
new = json.loads((EV / "scan.json").read_text(encoding="utf-8"))
new_ids = [f["id"] for f in new["findings"]]
prog = [json.loads(l) for l in (EV / "replay_progress.jsonl").read_text(encoding="utf-8").splitlines()]
old_ids = [r.get("finding_id") for r in prog]
overlap = set(new_ids) & set(old_ids)
print(f"new run: {len(new_ids)} findings | prior progress: {len(old_ids)} records | id overlap: {len(overlap)}")
print("deterministic-id collision:", "YES — progress reset REQUIRED (fresh re-execution must not inherit prior verdicts)" if overlap else "no")
# also compare run ids for the determinism record
import subprocess
old_run = subprocess.run(["git", "show", "HEAD:evidence/full-reverify/ginandjuice-shop/scan.json"],
                         capture_output=True, text=True).stdout
old_run_id = json.loads(old_run).get("run_id")
print("prior committed run_id:", old_run_id, "| new run_id:", new.get("run_id"),
      "| identical:", old_run_id == new.get("run_id"))
PYEOF

echo "== [2] reset progress file (prior run's committed copy stays in git history) =="
rm -f $EV/replay_progress.jsonl
echo "progress cleared"

echo "== [3] store contents (must be exactly the fresh run) =="
python3 -c "
import sys; sys.path.insert(0, '.')
from sentinel.store import Store
st = Store('evidence/full-reverify/ginandjuice-shop/store.db')
runs = st.list_runs(limit=10)
print('runs in store:', len(runs), [r['run_id'] for r in runs])"

echo "== [4] replay every persisted proof (budget 420s) =="
T0=$(date +%s)
timeout 460 python3 scripts/reverify/gj_replay.py 420 2>&1 | tail -22
RC=$?
T1=$(date +%s)
echo "gj_replay rc=$RC wall=$((T1-T0))s"

echo "== [5] replay artifact summary =="
python3 -c "
import json
d = json.load(open('evidence/full-reverify/ginandjuice-shop/replay_results.json'))
print(json.dumps(d['summary'], indent=1))"
echo "STEP2E COMPLETE"

#!/bin/bash
# STEP 2d (atomic): REAL external scan — ginandjuice.shop (authorized target,
# permission re-verified TODAY 2026-10-31, HTTP 200 + deliberately-vulnerable
# statement present). Bounded run: 350-request budget, max 12 pages, browser
# excluded (same knobs as the established methodology), all detector families.
set -uo pipefail
cd /home/z/my-project
export PYTHONPATH=/home/z/my-project

echo "== [0] guard =="
CUR=$(git rev-parse HEAD); BR=$(git branch --show-current)
echo "HEAD=$CUR branch=$BR"
[ "$CUR" = "0759c85ab639fdb555ba19b465d291b3d2b27999" ] && [ "$BR" = "main" ] || { echo "ABORT: unexpected tree state"; exit 1; }

echo "== [0b] authorization re-check (must hold at scan time) =="
python3 -c "
import json
d = json.load(open('evidence/full-reverify/ginandjuice-shop/permission.json'))
assert d['http_status'] == 200, d
assert d['permission_quote'].startswith('This is a deliberately'), d['permission_quote']
print('authorization holds:', d['fetched'], '|', d['permission_quote'])"

echo "== [1] bounded full-detector engine run (350-request budget) =="
T0=$(date +%s)
GJ_MAX_PAGES=12 GJ_MAX_REQ=350 GJ_BROWSER=0 GJ_WS=1 GJ_TIMEOUT=6.0 \
  timeout 540 python3 scripts/reverify/gj_api_scan.py 2>&1 | tail -15
RC=$?
T1=$(date +%s)
echo "gj_api_scan rc=$RC wall=$((T1-T0))s"

echo "== [2] results =="
python3 - <<'PYEOF'
import json
from collections import Counter
d = json.load(open("evidence/full-reverify/ginandjuice-shop/scan.json"))
s = d["stats"]
print("run_id:", d.get("run_id"), "| requests:", s.get("requests"),
      "| endpoints:", s.get("endpoints"), "| findings:", len(d["findings"]))
tc = Counter(f["type"] for f in d["findings"])
print("finding types:", dict(tc.most_common()))
sv = sum(1 for f in d["findings"] if f.get("status") == "verified")
print("scan-time verified:", sv, "/", len(d["findings"]))
PYEOF

echo "== [3] tree status =="
git status --short | grep ginandjuice
echo "STEP2D COMPLETE"

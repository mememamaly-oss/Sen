#!/bin/bash
# DVWS campaign — all-in-one single call (environment reaps processes):
#   1) stack boot (dvws_stack.sh: MariaDB 5566 + web 8888 + Ratchet WS 8080)
#   2) SENTINEL v4.3.1 (build-v430) scan of record
#   3) findings summary by type/verdict
# Usage: bash scripts/owsp/dvws_campaign.sh [tag]
#   tag = suffix for result files (default: baseline)
set -u
TAG="${1:-baseline}"
B=/home/z/my-project/build-v430
OUT=$B/results/owsp/dvws
mkdir -p "$OUT"

bash /home/z/my-project/scripts/owsp/dvws_stack.sh || exit 1
echo "=== STACK UP — scanning (v4.3.1) ==="

cd "$B" || exit 1
timeout 500 python3 -m sentinel.cli scan http://127.0.0.1:8888/ \
  --allow-private --logic-active \
  --out "$OUT/scan_${TAG}.json" \
  --db "$OUT/scan_${TAG}.db" 2>&1 | tail -25

echo "=== FINDINGS SUMMARY ($TAG) ==="
python3 - "$OUT/scan_${TAG}.json" <<'PYEOF'
import json, sys, collections
d = json.load(open(sys.argv[1]))
fs = d.get('findings', [])
c = collections.Counter((f['type'], 'VERIFIED' if f.get('verified') else 'candidate') for f in fs)
for (t, v), n in sorted(c.items()):
    print(f"  {v:9s} {t}: {n}")
print("TOTAL:", len(fs), "| verified:", sum(1 for f in fs if f.get('verified')))
ws = d.get('stats', {}).get('websocket', {})
print("WS channels:", len(ws.get('channels', [])), "| connections:", ws.get('connections', '?'))
print("endpoints:", len(d.get('endpoints', d.get('surface', {}).get('endpoints', []))))
PYEOF

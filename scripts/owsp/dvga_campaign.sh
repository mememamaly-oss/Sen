#!/bin/bash
# DVGA campaign — all-in-one single call (environment reaps processes):
#   1) stack boot (dvga_stack.sh: venv app on 5013 + setup.py provisioning +
#      fresh JWTs + private marker pastes -> accounts.json)
#   2) SENTINEL v4.3.2 (build-v430) scan of record
#   3) findings summary by type/verdict
# --exclude-url /difficulty/: operator state pinning — the difficulty GET
#   routes flip the whole app between easy/hardened GraphQL behavior.
# Usage: bash scripts/owsp/dvga_campaign.sh [tag]
set -u
TAG="${1:-baseline}"
B=/home/z/my-project/build-v430
OUT=$B/results/owsp/dvga
mkdir -p "$OUT"

bash /home/z/my-project/scripts/owsp/dvga_stack.sh || exit 1
echo "=== STACK UP — scanning (v4.3.2) ==="

cd "$B" || exit 1
TOKA=$(python3 -c "import json; print(json.load(open('$OUT/accounts.json'))['accounts'][0]['token'])")
timeout 480 python3 -m sentinel.cli scan http://127.0.0.1:5013/ \
  --allow-private --logic-active --workflow \
  --auth-token "$TOKA" --auth-scheme Bearer \
  --auth-validate-url http://127.0.0.1:5013/graphql \
  --authz-accounts "$OUT/accounts.json" \
  --exclude-url /difficulty/ \
  --out "$OUT/scan_${TAG}.json" \
  --db "$OUT/scan_${TAG}.db" 2>&1 | tail -20

echo "=== FINDINGS SUMMARY ($TAG) ==="
python3 - "$OUT/scan_${TAG}.json" <<'PYEOF'
import json, sys, collections
d = json.load(open(sys.argv[1]))
fs = d.get('findings', [])
c = collections.Counter((f['type'], f['status']) for f in fs)
for (t, v), n in sorted(c.items()):
    print(f"  {v:8s} {t}: {n}")
print("TOTAL:", len(fs), "| verified:", sum(1 for f in fs if f['status'] == 'verified'))
gql = d.get('stats', {}).get('graphql', {})
print("graphql:", {k: gql.get(k) for k in ('endpoints', 'operations', 'requests') if gql.get(k) is not None})
ws = d.get('stats', {}).get('websocket', {})
print("WS channels:", len(ws.get('channels', [])))
PYEOF

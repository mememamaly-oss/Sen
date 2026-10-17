#!/bin/bash
# maxtest — Phase 1b: Juice Shop 20.2.0 all-in-one coverage campaign.
# One call: launch -> identity/spec setup -> authz build -> deep authenticated
# full-stack scan (v4.4.0) -> L2 apaths (offline) -> kill server.
# (L3 impact --execute runs in its own call: server relaunch + probes.)
set -u
LT=/home/z/my-project/live-targets
JS=$LT/juice-shop_20.2.0
B=/home/z/my-project/build-v423
OUT=$B/results/maxtest/juiceshop
mkdir -p "$OUT"

echo "=== [1/5] launch Juice Shop 20.2.0 (node22, port 3100) $(date -u +%H:%M:%S) ==="
pkill -f "node build/app" 2>/dev/null; sleep 1
cd "$JS" || exit 1
export PATH=/home/z/my-project/live-targets/node-v22.14.0-linux-x64/bin:$PATH
PORT=3100 setsid nohup node build/app > /tmp/js_server.log 2>&1 < /dev/null &
UP=000
for i in $(seq 1 45); do
  UP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 http://localhost:3100/ 2>/dev/null)
  [ "$UP" = "200" ] && break; sleep 1
done
echo "server http=$UP after ~${i}s"
[ "$UP" != "200" ] && { echo "SERVER FAILED"; tail -8 /tmp/js_server.log; exit 1; }

echo "=== [2/5] identities + OpenAPI spec $(date -u +%H:%M:%S) ==="
JS_BASE=http://localhost:3100 python3 /home/z/my-project/scripts/maxtest/js_setup.py || exit 1

echo "=== [3/5] authz matrix build $(date -u +%H:%M:%S) ==="
JS_BASE=http://localhost:3100 python3 /home/z/my-project/scripts/maxtest/js_build_authz.py || exit 1

echo "=== [4/5] deep authenticated scan v4.4.0 $(date -u +%H:%M:%S) ==="
ADMIN_TOKEN=$(python3 -c "import json;print(json.load(open('$LT/juice_tokens_v41.json'))['admin@juice-sh.op']['token'])")
cd "$B" || exit 1
python3 sentinel/cli.py scan http://localhost:3100 \
  --allow-private --max-pages 40 \
  --workflow --logic-active \
  --auth-token "$ADMIN_TOKEN" --auth-header Authorization --auth-scheme Bearer \
  --auth-validate-url http://localhost:3100/rest/basket/1 \
  --openapi-spec "$LT/juice_surface_openapi_v41.json" \
  --authz-accounts "$LT/juice_authz_maxtest.json" \
  --seed maxtest-js-01 \
  --db "$OUT/juiceshop.db" --out "$OUT/juiceshop.json" 2>&1 | tail -30

echo "=== [5/5] L2 attack paths $(date -u +%H:%M:%S) ==="
python3 sentinel/cli.py apaths --result "$OUT/juiceshop.json" --out "$OUT/apaths.json" 2>&1 | tail -5
python3 - "$OUT" <<'PYEOF'
import json, sys
out = sys.argv[1]
r = json.load(open(f"{out}/juiceshop.json"))
by = {}
for f in r.get("findings", []):
    by[f["type"]] = by.get(f["type"], 0) + 1
print("FINDINGS:", sum(by.values()))
for k, v in sorted(by.items(), key=lambda x: -x[1]):
    print(f"  {k}: {v}")
ver = [f for f in r.get("findings", []) if f.get("verified")]
print("VERIFIED:", len(ver))
try:
    ap = json.load(open(f"{out}/apaths.json"))
    paths = ap.get("paths", [])
    from collections import Counter
    cl = Counter(p.get("classification", p.get("class", "?")) for p in paths)
    print(f"APATHS: {len(paths)} {dict(cl)}")
except Exception as e:
    print("apaths summary err:", e)
PYEOF
pkill -f "node build/app" 2>/dev/null
echo "=== DONE $(date -u +%H:%M:%S) ==="

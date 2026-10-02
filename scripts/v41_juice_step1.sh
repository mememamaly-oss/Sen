#!/bin/bash
# SENTINEL v4.1 — Juice Shop live campaign, STEP 1: launch + setup + deep scan.
# The sandbox reaps every process at the END of each tool call, so the whole
# phase runs inside ONE call: launch server -> setup identities/spec -> scan.
set -u
LT=/home/z/my-project/live-targets
JS=$LT/juice-shop_20.2.0
B=/home/z/my-project/build-v410
OUT=$B/results/live_v41
mkdir -p "$OUT"

echo "=== [1/3] launching Juice Shop 20.2.0 (node build/app) ==="
pkill -f "node build/app" 2>/dev/null; sleep 1
cd "$JS" || exit 1
setsid nohup node build/app > /tmp/juice_server.log 2>&1 < /dev/null &
UP=000
for i in $(seq 1 40); do
  UP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 http://localhost:3000/ 2>/dev/null)
  [ "$UP" = "200" ] && break; sleep 1
done
echo "server http=$UP after ~${i}s"
[ "$UP" != "200" ] && { echo "SERVER FAILED"; tail -5 /tmp/juice_server.log; exit 1; }

echo "=== [2/3] setup: authz users + JWT tokens + operator OpenAPI (19 paths) ==="
python3 /home/z/my-project/scripts/v41_juice_setup.py || exit 1

echo "=== [3/3] deep authenticated scan (v4.1 full stack) ==="
ADMIN_TOKEN=$(python3 -c "import json;print(json.load(open('$LT/juice_tokens_v41.json'))['admin@juice-sh.op']['token'])")
cd "$B" || exit 1
python3 sentinel/cli.py scan http://localhost:3000 \
  --allow-private --workflow --logic-active \
  --auth-token "$ADMIN_TOKEN" --auth-header Authorization --auth-scheme Bearer \
  --auth-validate-url http://localhost:3000/rest/user/whoami \
  --openapi-spec "$LT/juice_surface_openapi_v41.json" \
  --db "$OUT/juiceshop.db" --out "$OUT/juiceshop.json" 2>&1 | tail -25

echo "=== scan artifacts ==="
ls -la "$OUT/" | rg 'juiceshop'
echo "=== key stats ==="
python3 - <<'PYEOF'
import json
d = json.load(open("/home/z/my-project/build-v410/results/live_v41/juiceshop.json"))
st = d.get("stats", {})
print("scanner   :", d.get("scanner"))
print("run_id    :", d.get("run_id"))
print("verified  :", st.get("verified"), "| rejected:", st.get("rejected"),
      "| reqs:", st.get("requests"), "| dur:", round(st.get("duration", 0), 1), "s")
auth = st.get("auth", {})
print("auth      :", auth.get("mode"), "authenticated =", auth.get("authenticated"))
for k in ("graphql", "websocket", "workflow", "coverage", "boundary",
          "api_inventory", "action_matrix", "digital_twin", "reasoning",
          "planner", "proofs", "memory"):
    v = st.get(k)
    if isinstance(v, dict):
        brief = {kk: v[kk] for kk in list(v)[:6]}
        print(f"{k:12s}: {brief}")
    else:
        print(f"{k:12s}: {v}")
b = st.get("boundary", {})
print("BOUNDARY  :", b.get("records"), "records | by_state:", b.get("by_state"),
      "| unresolved:", b.get("unresolved"))
sevs = {}
for f in d.get("findings", []):
    sevs[f.get("severity", "?")] = sevs.get(f.get("severity", "?"), 0) + 1
print("findings by severity:", sevs)
PYEOF
echo "=== STEP1 DONE (server dies with this call — by sandbox design) ==="

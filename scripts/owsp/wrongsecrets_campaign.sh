#!/bin/bash
# OWASP campaign — WrongSecrets 1.8.1-SNAPSHOT (standalone, without-vault profile)
# All-in-one single call: launch -> recon -> deep scan -> L2 -> kill.
set -u
LT=/home/z/my-project/live-targets
B=/home/z/my-project/build-v423
OUT=$LT/owsp-results/wrongsecrets
LOGD=$LT/logs
mkdir -p "$OUT" "$LOGD"
TS0=$(date +%s)

echo "=== [1/5] launch WrongSecrets $(date -u +%H:%M:%S) ==="
pkill -f "SNAPSHOT[.]jar" 2>/dev/null; sleep 1
cd "$LT"
setsid nohup java -Xmx800m -jar wrongsecrets/target/wrongsecrets-1.8.1-SNAPSHOT.jar \
  --server.port=8080 --spring.profiles.active=without-vault \
  > $LOGD/wrongsecrets.log 2>&1 < /dev/null &
UP=000
for i in $(seq 1 90); do
  UP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 http://localhost:8080/ 2>/dev/null)
  [ "$UP" = "200" ] && break; sleep 1
done
echo "up=$UP after ~${i}s"
[ "$UP" != "200" ] && { echo "LAUNCH FAILED"; tail -10 $LOGD/wrongsecrets.log; exit 1; }

echo "=== [2/5] recon $(date -u +%H:%M:%S) ==="
# actuator surface
curl -s --max-time 5 http://localhost:8080/actuator > "$OUT/recon_actuator.json" 2>/dev/null
curl -s --max-time 5 http://localhost:8080/actuator/mappings > "$OUT/recon_mappings.json" 2>/dev/null
python3 - "$OUT" <<'PYEOF'
import json, sys
out = sys.argv[1]
try:
    d = json.load(open(f"{out}/recon_mappings.json"))
    paths = set()
    for ctx in d.get("contexts", {}).values():
        for m in ctx.get("mappings", {}).get("dispatcherServlets", {}).get("dispatcherServlet", []):
            for x in m.get("details", {}).get("requestMappingConditions", {}).get("patterns", []):
                paths.add(x)
    print(f"[recon] server mappings: {len(paths)}")
    for p in sorted(paths)[:60]:
        print("  ", p)
except Exception as e:
    print(f"[recon] mappings parse: {e}")
PYEOF
# homepage + js bundles
curl -s --max-time 5 http://localhost:8080/ > "$OUT/recon_root.html"
grep -oE '(src|href)="[^"]+"' "$OUT/recon_root.html" | sort -u | head -25
echo "[recon] title: $(grep -oE '<title>[^<]*</title>' "$OUT/recon_root.html" | head -1)"

echo "=== [3/5] deep scan $(date -u +%H:%M:%S) ==="
cd "$B"
timeout 420 python3 sentinel/cli.py scan http://localhost:8080 \
  --allow-private --max-pages 40 \
  --seed owsp-ws-01 \
  --db "$OUT/wrongsecrets.db" --out "$OUT/wrongsecrets.json" 2>&1 | tail -25

echo "=== [4/5] L2 apaths $(date -u +%H:%M:%S) ==="
python3 sentinel/cli.py apaths --result "$OUT/wrongsecrets.json" --out "$OUT/apaths.json" 2>&1 | tail -3

echo "=== [5/5] summary + kill $(date -u +%H:%M:%S) ==="
python3 - "$OUT" <<'PYEOF'
import json, sys
out = sys.argv[1]
try:
    r = json.load(open(f"{out}/wrongsecrets.json"))
    fs = r.get("findings", [])
    from collections import Counter
    c = Counter((f.get("type"), f.get("confidence", 0) >= 0.8) for f in fs)
    print(f"[sum] run_id={r.get('run_id')} requests={r.get('stats',{}).get('requests')} endpoints={len(r.get('endpoints',[]))}")
    print(f"[sum] findings total={len(fs)}")
    for (t, strong), n in sorted(c.items()):
        print(f"  {t}{' [verified-strong]' if strong else ''}: {n}")
    ep = [e.get("url","") for e in r.get("endpoints",[])]
    print(f"[sum] endpoint sample: {ep[:12]}")
except Exception as e:
    print(f"[sum] {e}")
PYEOF
pkill -f "SNAPSHOT[.]jar" 2>/dev/null
echo "ELAPSED=$(( $(date +%s) - TS0 ))s"

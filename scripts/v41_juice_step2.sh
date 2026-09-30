#!/bin/bash
# SENTINEL v4.1 — Juice Shop live campaign, STEP 2: BOLA proof + live replay.
# Single-call lifecycle: launch server -> cross-user BOLA evidence ->
# reproduce --replay of the critical SQLi finding from a clean engine.
set -u
LT=/home/z/my-project/live-targets
JS=$LT/juice-shop_20.2.0
B=/home/z/my-project/build-v410
OUT=$B/results/live_v41

echo "=== [1/3] launching Juice Shop ==="
pkill -f "node build/app" 2>/dev/null; sleep 1
cd "$JS" || exit 1
setsid nohup node build/app > /tmp/juice_server.log 2>&1 < /dev/null &
UP=000
for i in $(seq 1 40); do
  UP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 http://localhost:3000/ 2>/dev/null)
  [ "$UP" = "200" ] && break; sleep 1
done
echo "server http=$UP"
[ "$UP" != "200" ] && exit 1

echo "=== [2/3] cross-user BOLA proof (sentinel41e reads foreign baskets) ==="
python3 /home/z/my-project/scripts/v41_juice_bola.py

echo "=== [3/3] REPRODUCE --replay: critical SQLi (clean-engine live replay) ==="
cd "$B" || exit 1
python3 sentinel/cli.py reproduce --db "$OUT/juiceshop.db" \
  --finding F-5603a854b8 --replay 2>&1 | head -40

echo "=== replay persisted? checking store ==="
python3 - <<'PYEOF'
import json, sqlite3
db = sqlite3.connect("/home/z/my-project/build-v410/results/live_v41/juiceshop.db")
rows = db.execute(
    "SELECT name FROM sqlite_master WHERE type='table'").fetchall()
print("tables:", [r[0] for r in rows])
for t in ("reproductions", "replay", "proofs", "evidence"):
    if any(t == r[0] for r in rows):
        n = db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        print(f"  {t}: {n} rows")
        try:
            last = db.execute(
                f"SELECT * FROM {t} ORDER BY rowid DESC LIMIT 1").fetchone()
            print(f"  last: {str(last)[:300]}")
        except Exception as e:
            print("  (read err)", e)
PYEOF
echo "=== STEP2 DONE ==="

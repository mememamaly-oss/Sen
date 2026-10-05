#!/bin/bash
# Detached scan runner: stack (if dead) + scan via setsid nohup, DONE marker.
# Poll-friendly: idempotent — safe to call repeatedly; restarts whatever died.
set -u
B=http://localhost:8080/benchmark
OUTD=/home/z/my-project/tools/benchmark-src/target/campaign/v424_full
ENG=/home/z/my-project/build-v424
MARK=$OUTD/DONE

[ -f "$MARK" ] && { echo "ALREADY DONE"; exit 0; }

# 1) stack alive?
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 $B/Index.html 2>/dev/null)
if [ "$code" != "200" ]; then
  echo "stack dead ($code) — relaunch (detached setsid)"
  setsid nohup /home/z/my-project/scripts/owsp/benchmark_stack.sh > $OUTD/stack.log 2>&1 < /dev/null &
  for i in $(seq 1 60); do
    sleep 3
    c=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 $B/Index.html 2>/dev/null)
    [ "$c" = "200" ] && break
  done
  [ "$c" = "200" ] || { echo "STACK LAUNCH FAILED"; exit 1; }
fi
echo "stack alive"

# 2) scan running or done?
if ps aux 2>/dev/null | grep -q "[c]li.py scan"; then
  echo "scan already running — waiting"
  exit 0
fi

# 3) launch scan fully detached
cat > $OUTD/run_scan.sh <<'RUNEOF'
#!/bin/bash
cd /home/z/my-project/build-v424
OUTD=/home/z/my-project/tools/benchmark-src/target/campaign/v424_full
python3 sentinel/cli.py scan http://localhost:8080/benchmark \
  --allow-private --oast local \
  --openapi-spec /home/z/my-project/tools/benchmark-src/target/campaign/spec_full.json \
  --seed 7f3c91aa --max-pages 6000 \
  --out $OUTD/v424_full.json --db $OUTD/v424_full.db > $OUTD/scan.log 2>&1
RC=$?
echo "rc=$RC $(date +%H:%M:%S)" > $OUTD/DONE
RUNEOF
chmod +x $OUTD/run_scan.sh
setsid nohup $OUTD/run_scan.sh > /dev/null 2>&1 < /dev/null &
echo "scan launched detached"

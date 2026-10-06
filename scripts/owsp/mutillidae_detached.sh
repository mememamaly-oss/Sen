#!/bin/bash
# Mutillidae detached scan runner (benchmark_detached.sh pattern):
# stack (if dead) + scan via setsid nohup, DONE marker, poll-friendly and
# idempotent — restarts whatever the environment reaper killed.
# Usage: bash scripts/owsp/mutillidae_detached.sh <runname> [max_pages]
set -u
RUN="${1:?runname}"
MP="${2:-400}"
BASE=http://127.0.0.1:4290
OUTD=/home/z/my-project/build-v425/results/owsp/mutillidae
ENG=/home/z/my-project/build-v425
MARK=$OUTD/${RUN}.DONE
mkdir -p "$OUTD"

[ -f "$MARK" ] && { echo "ALREADY DONE: $(cat $MARK)"; exit 0; }

# 1) stack alive?
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$BASE/index.php?page=home.php" 2>/dev/null)
if [ "$code" != "200" ]; then
  echo "stack dead ($code) — relaunch (detached setsid)"
  setsid nohup bash /home/z/my-project/scripts/owsp/mutillidae_stack.sh > $OUTD/stack_${RUN}.log 2>&1 < /dev/null &
  for i in $(seq 1 60); do
    sleep 3
    c=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$BASE/index.php?page=home.php" 2>/dev/null)
    [ "$c" = "200" ] && break
  done
  [ "$c" = "200" ] || { echo "STACK LAUNCH FAILED"; tail -5 $OUTD/stack_${RUN}.log; exit 1; }
fi
echo "stack alive"

# 2) scan running or done?
if ps aux 2>/dev/null | grep -q "[c]li.py scan"; then
  echo "scan already running — waiting"
  exit 0
fi

# 3) launch scan fully detached
cat > $OUTD/run_${RUN}.sh <<RUNEOF
#!/bin/bash
cd $ENG
python3 sentinel/cli.py scan $BASE \
  --allow-private --oast local \
  --auth-user admin --auth-pass adminpass \
  --auth-url "$BASE/index.php?page=login.php" \
  --auth-user-field username --auth-pass-field password \
  --seed owsp-${RUN} --max-pages ${MP} \
  --out $OUTD/${RUN}.json --db $OUTD/${RUN}.db > $OUTD/${RUN}.log 2>&1
RC=\$?
echo "rc=\$RC \$(date +%H:%M:%S)" > $OUTD/${RUN}.DONE
RUNEOF
chmod +x $OUTD/run_${RUN}.sh
setsid nohup $OUTD/run_${RUN}.sh > /dev/null 2>&1 < /dev/null &
echo "scan launched detached (run=$RUN max_pages=$MP)"

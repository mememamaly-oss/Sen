#!/bin/bash
# One scan + concurrent unstick loop, all inside one tool call.
# Usage: mutillidae_scan_unstuck.sh <name> <page> <maxpages> <timeout>
set -u
NAME="${1:?}" PAGE="${2:?}" MP="${3:-8}" TMO="${4:-550}"
M=/home/z/my-project/build-v425/results/owsp/mutillidae
ENG=/home/z/my-project/build-v425
LOG=/home/z/my-project/tools/logs/php-server.log

# stack alive? (quick relaunch if dead — happens within this call, safe)
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 4 "http://127.0.0.1:4290/index.php" 2>/dev/null)
if [ "$code" != "200" ] && [ "$code" != "302" ]; then
  echo "(stack dead -> relaunch)"
  bash /home/z/my-project/scripts/owsp/mutillidae_stack.sh >/dev/null 2>&1
fi
echo "stack: $(curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://127.0.0.1:4290/index.php)"

# concurrent unstick: kill php workers stuck in SYN-SENT every 12s
( while true; do
    for pid in $(ss -tnp state syn-sent 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u); do
      if grep -qa "php" /proc/$pid/cmdline 2>/dev/null; then kill -9 "$pid" 2>/dev/null; fi
    done
    sleep 12
  done ) &
LOOPER=$!

cd "$ENG"
timeout "$TMO" python3 sentinel/cli.py scan \
  "http://127.0.0.1:4290/index.php?page=$PAGE" \
  --allow-private --oast local --no-browser \
  --auth-user admin --auth-pass adminpass \
  --auth-url "http://127.0.0.1:4290/index.php?page=login.php" \
  --auth-user-field username --auth-pass-field password \
  --seed "owsp-$NAME" --max-pages "$MP" \
  --out "$M/$NAME.json" --db "$M/$NAME.db" > "$M/$NAME.log" 2>&1
RC=$?
kill $LOOPER 2>/dev/null
echo "scan rc=$RC"
if [ -f "$M/$NAME.json" ]; then
  python3 - "$M/$NAME.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
s = d.get("stats", {})
act = [x for x in d.get("findings", []) if x.get("type") not in
       ("missing_security_headers", "tech_banner_disclosure", "host_header_injection")]
print(f"requests={s.get('requests')} endpoints={s.get('endpoints')} "
      f"verified={s.get('verified')} rejected={s.get('rejected')} dur={s.get('duration')}")
print(f"active: {len(act)}")
for x in act:
    print(f"   {x.get('type'):22} {x.get('status'):10} param={x.get('parameter')}")
for x in d.get("rejected_candidates", [])[:6]:
    print(f"   rejected: {x.get('type')} param={x.get('parameter')}")
for x in d.get("unverified_candidates", [])[:6]:
    print(f"   unverified: {x.get('type')} {str(x.get('url'))[:60]} param={x.get('parameter')}")
PYEOF
else
  echo "NO RESULT (timeout again?)"; tail -c 300 "$M/$NAME.log" 2>/dev/null
fi

#!/bin/bash
# ALL-IN-ONE: verify/restart stack (setsid survivors ok) THEN scan in FOREGROUND.
# The scan must be a foreground child of THIS call — never survives alone.
set -u
B=http://localhost:8080/benchmark
need_restart=0
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 $B/Index.html 2>/dev/null)
[ "$code" = "200" ] || need_restart=1
if [ $need_restart -eq 1 ]; then
  echo "stack dead (Index=$code) — relaunching"
  /home/z/my-project/scripts/owsp/benchmark_stack.sh > /tmp/stack_rel.log 2>&1
  grep -q "STACK READY" /tmp/stack_rel.log || { echo "STACK FAIL"; tail -3 /tmp/stack_rel.log; exit 1; }
  echo "stack relaunched"
else
  echo "stack alive (Index=200)"
fi

ENG=/home/z/my-project/build-v424
OUTD=/home/z/my-project/tools/benchmark-src/target/campaign/v424_full
cd "$ENG" || exit 1
START=$(python3 -c "import time; print(time.time())")
python3 sentinel/cli.py scan http://localhost:8080/benchmark \
  --allow-private --oast local \
  --openapi-spec /home/z/my-project/tools/benchmark-src/target/campaign/spec_full.json \
  --seed 7f3c91aa --max-pages 6000 \
  --out "$OUTD/v424_full.json" --db "$OUTD/v424_full.db" > "$OUTD/scan.log" 2>&1
RC=$?
END=$(python3 -c "import time; print(time.time())")
echo "scan rc=$RC wall=$(python3 -c "print(f'{$END-$START:.0f}')")s"
python3 - <<'EOF'
import json
from collections import Counter
d = json.load(open("/home/z/my-project/tools/benchmark-src/target/campaign/v424_full/v424_full.json"))
s = d["stats"]
print("reqs:", s.get("requests"), "endpoints:", s.get("endpoints"), "candidates:", s.get("candidates"))
print("crawl:", json.dumps(s.get("crawl", {}))[:140])
act = [f for f in d["findings"] if f["type"] != "missing_security_headers"]
print("active:", len(act), "verified:", sum(1 for f in act if f.get("status")=="verified"))
print(dict(Counter(f["type"] for f in act)))
print("rejected:", len(d.get("rejected_candidates", [])))
EOF

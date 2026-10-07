#!/bin/bash
# v4.3.0 chunked Benchmark scan: stack + one spec chunk, all-in-one.
set -u
CHUNK="$1"          # e.g. 00000_00914
ENG=/home/z/my-project/build-v430
CAMP=/home/z/my-project/tools/benchmark-src/target/campaign
SPEC=$CAMP/spec_${CHUNK}.json
OUTD=$CAMP/v430_full
mkdir -p "$OUTD"
[ -f "$SPEC" ] || { echo "spec missing: $SPEC"; exit 1; }
# stack alive? (same-call survival only — restart if dead)
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:8080/benchmark/Index.html 2>/dev/null)
if [ "$code" != "200" ]; then
  /home/z/my-project/scripts/owsp/benchmark_stack.sh > "$OUTD/stack_${CHUNK}.log" 2>&1
  grep -q "STACK READY" "$OUTD/stack_${CHUNK}.log" || { echo "STACK FAIL"; tail -3 "$OUTD/stack_${CHUNK}.log"; exit 1; }
  echo "stack relaunched"
else
  echo "stack alive"
fi
START=$(date +%s)
cd "$ENG" || exit 1
timeout 500 python3 sentinel/cli.py scan http://localhost:8080/benchmark \
  --allow-private --oast local --no-browser \
  --openapi-spec "$SPEC" \
  --seed 7f3c91aa --max-pages 6000 \
  --out "$OUTD/chunk_${CHUNK}.json" --db "$OUTD/chunk_${CHUNK}.db" > "$OUTD/scan_${CHUNK}.log" 2>&1
RC=$?
END=$(date +%s)
echo "chunk $CHUNK rc=$RC wall=$((END-START))s"
python3 - "$OUTD/chunk_${CHUNK}.json" << 'PY'
import json, sys
from collections import Counter
try:
    d = json.load(open(sys.argv[1]))
    s = d["stats"]
    act = [f for f in d["findings"] if f["type"] not in ("missing_security_headers", "server_banner_disclosure", "tech_banner")]
    print("reqs:", s.get("requests"), "endpoints:", s.get("endpoints"),
          "active findings:", len(act),
          "verified:", sum(1 for f in act if f.get("status") == "verified"))
    print(dict(Counter(f["type"] for f in act if f.get("status") == "verified")))
except Exception as e:
    print("no result json:", e)
PY

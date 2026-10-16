#!/usr/bin/env bash
# GTP-13 full 12-chunk no-crawl measurement runner (v4.3.4 candidate).
# Usage: bash gtp13_full_run.sh <chunk_index 0-11>
set -u
N="${1:?chunk index}"
ENG=/home/z/my-project/build-v430
CAMP=/home/z/my-project/tools/benchmark-src/target/campaign
SPEC=$CAMP/spec_full_$N.json
OUTD=$CAMP/gtp13_full
mkdir -p "$OUTD"
[ -f "$SPEC" ] || { echo "spec missing: $SPEC"; exit 1; }
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:8080/benchmark/Index.html 2>/dev/null)
if [ "$code" != "200" ]; then
  /home/z/my-project/scripts/owsp/benchmark_stack.sh > "$OUTD/stack_$N.log" 2>&1
  grep -q "STACK READY" "$OUTD/stack_$N.log" || { echo "STACK FAIL"; tail -3 "$OUTD/stack_$N.log"; exit 1; }
  echo "stack relaunched"
else
  echo "stack alive"
fi
START=$(date +%s)
cd "$ENG" || exit 1
rm -f "$OUTD/chunk_$N.json" "$OUTD/chunk_$N.db"
timeout 560 python3 sentinel/cli.py scan http://localhost:8080/benchmark \
  --allow-private --oast local --no-browser --no-crawl \
  --openapi-spec "$SPEC" \
  --seed 7f3c91aa --max-pages 6000 \
  --out "$OUTD/chunk_$N.json" --db "$OUTD/chunk_$N.db" > "$OUTD/scan_$N.log" 2>&1
RC=$?
END=$(date +%s)
echo "chunk $N rc=$RC wall=$((END-START))s"
if [ -f "$OUTD/chunk_$N.json" ]; then
python3 - "$OUTD/chunk_$N.json" << 'PY'
import json, sys
from collections import Counter
d = json.load(open(sys.argv[1]))
s = d["stats"]
act = [f for f in d["findings"] if f["type"] not in ("missing_security_headers", "server_banner_disclosure", "tech_banner")]
print("reqs:", s.get("requests"), "endpoints:", s.get("endpoints"),
      "active:", len(act), "verified:", sum(1 for f in act if f.get("status") == "verified"))
PY
else
  echo "NO RESULT JSON rc=$RC"
  tail -3 "$OUTD/scan_$N.log" 2>/dev/null
fi

#!/bin/bash
# Full-benchmark chunk scan — one chunk per call (campaign pattern).
# Usage: bash bm_full_chunk.sh <chunk-label>   e.g. 00000_00228
set -u
LABEL="$1"
OUTD=/home/z/my-project/tool-results/bm_full_chunks
SPEC=$OUTD/spec_${LABEL}.json
ENG=/home/z/my-project/build-v430
BM=/home/z/tools/benchmark
[ -f "$SPEC" ] || { echo "spec missing: $SPEC"; exit 1; }

export JAVA_HOME=/home/z/tools/jdk-21.0.12.1+1
export PATH=$JAVA_HOME/bin:/home/z/tools/apache-maven-3.9.9/bin:$PATH
cd "$BM" || exit 1

pkill -9 -f "catalina" 2>/dev/null; pkill -9 -f "hsqldb" 2>/dev/null
pkill -9 -f LDAPServer 2>/dev/null; pkill -9 -f DataBaseServer 2>/dev/null
pkill -9 -f "cargo-maven3-plugin" 2>/dev/null
sleep 2
: > "$BM/testfiles/passwordFile.txt" 2>/dev/null || true

nohup mvn -B package cargo:run -Pdeploy -Dcargo.servlet.port=8080 -Dcargo.protocol=http \
  -Dcargo.tomcat.httpSecure=false -Drunenv=local -Dmaven.test.skip=true \
  > /home/z/tools/bm_chunk_stack.log 2>&1 &
MVPID=$!
trap 'kill $MVPID 2>/dev/null; pkill -9 -f "catalina" 2>/dev/null; pkill -9 -f hsqldb 2>/dev/null; pkill -9 -f LDAPServer 2>/dev/null; pkill -9 -f DataBaseServer 2>/dev/null; pkill -9 -f cargo-maven3 2>/dev/null' EXIT

up=0
for i in $(seq 1 170); do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "http://localhost:8080/benchmark/" 2>/dev/null)
  [ "$code" = "200" ] && { up=1; break; }
  kill -0 $MVPID 2>/dev/null || { echo "MVN DIED"; tail -15 /home/z/tools/bm_chunk_stack.log; exit 1; }
  sleep 1
done
[ "$up" = "1" ] || { echo "STACK TIMEOUT code=$code"; exit 1; }
echo "=== STACK UP (${i}s) ==="

cd "$ENG" || exit 1
timeout 480 python3 sentinel/cli.py scan http://localhost:8080/benchmark \
  --allow-private --oast local --no-browser --no-crawl \
  --openapi-spec "$SPEC" \
  --seed 7f3c91aa --max-pages 6000 \
  --out "$OUTD/chunk_${LABEL}.json" --db "$OUTD/chunk_${LABEL}.db" > "$OUTD/scan_${LABEL}.log" 2>&1
RC=$?
echo "chunk $LABEL rc=$RC"
if [ -f "$OUTD/chunk_${LABEL}.json" ]; then
python3 - "$OUTD/chunk_${LABEL}.json" << 'PY'
import json, sys
from collections import Counter
d = json.load(open(sys.argv[1]))
s = d["stats"]
act = [f for f in d["findings"] if f["type"] not in ("missing_security_headers", "server_banner_disclosure", "tech_banner")]
print("reqs:", s.get("requests"), "endpoints:", s.get("endpoints"),
      "active:", len(act), "verified:", sum(1 for f in act if f.get("status") == "verified"))
print(dict(Counter(f["type"] for f in act if f.get("status") == "verified")))
PY
else
  echo "NO RESULT JSON rc=$RC"; tail -5 "$OUTD/scan_${LABEL}.log" 2>/dev/null
fi

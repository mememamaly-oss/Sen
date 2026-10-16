#!/bin/bash
# Task 40 — full-benchmark chunk scan on the plain-Tomcat stack (one chunk per
# call; CR-1 seeds live in the spec). Usage: cr_full_chunk.sh <chunk-label>
set -u
LABEL="$1"
OUTD=/home/z/my-project/tool-results/bm_full_chunks
SPEC=$OUTD/spec_${LABEL}.json
ENG=/home/z/my-project/build-v430
TOOLS=/home/z/tools
BM=$TOOLS/benchmark
JDK=$TOOLS/jdk-21.0.12.1+1
[ -f "$SPEC" ] || { echo "spec missing: $SPEC"; exit 1; }

export JAVA_HOME=$JDK
export PATH=$JDK/bin:$PATH
CATALINA=$TOOLS/tomcat9
CPFILE=$BM/target/cp.txt
LOGD=$BM/target/logs
mkdir -p "$LOGD" "$BM/target/db"
cd "$BM" || exit 1

# hygiene: fresh artifact + stale locks out
: > "$BM/testfiles/passwordFile.txt" 2>/dev/null || true
rm -f "$BM/benchmarkDataBase.lck" "$BM/benchmarkDataBase.data" "$BM/benchmarkDataBase.script" \
      "$BM/benchmarkDataBase.properties" "$BM/benchmarkDataBase.tmp" \
      "$BM/target/db/benchmark.db"* 2>/dev/null
pkill -9 -f "catalina" 2>/dev/null; pkill -9 -f "hsqldb" 2>/dev/null
pkill -9 -f LDAPServer 2>/dev/null; pkill -9 -f DataBaseServer 2>/dev/null
for i in $(seq 1 30); do
  if ss -tln 2>/dev/null | grep -qE ":(8080|10389|9001) "; then sleep 2; else break; fi
done
ss -tln | grep -qE ":(8080|10389|9001) " && { echo "PORTS BUSY"; exit 1; }

CP="$BM/target/classes:$(cat $CPFILE)"
"$JDK/bin/java" -Xmx256m -cp "$CP" org.hsqldb.Server \
  --database.0 file:$BM/target/db/benchmark.db --dbname.0 benchmarkDataBase \
  > "$LOGD/hsqldb.log" 2>&1 &
sleep 3
"$JDK/bin/java" -Xmx512m -cp "$CP" org.owasp.benchmark.helpers.LDAPServer \
  > "$LOGD/ldap.log" 2>&1 &
sleep 4
export CATALINA_HOME=$CATALINA
export CATALINA_BASE=$CATALINA
"$CATALINA/bin/catalina.sh" run > "$LOGD/tomcat.log" 2>&1 &

UP=000
for i in $(seq 1 120); do
  UP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 http://localhost:8080/benchmark/Index.html)
  [ "$UP" = "200" ] && break
  sleep 2
done
[ "$UP" = "200" ] || { echo "TOMCAT FAILED ($UP)"; tail -10 "$LOGD/tomcat.log"; exit 1; }
echo "=== STACK UP (${i} polls) ==="

cd "$ENG" || exit 1
timeout 540 python3 sentinel/cli.py scan http://localhost:8080/benchmark \
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
wc = [f for f in act if f["type"] == "weak_crypto" and f.get("status") == "verified"]
wh = [f for f in act if f["type"] == "weak_hash" and f.get("status") == "verified"]
print("reqs:", s.get("requests"), "endpoints:", s.get("endpoints"),
      "active:", len(act), "verified:", sum(1 for f in act if f.get("status") == "verified"))
print("weak_crypto:", len(wc), "weak_hash:", len(wh))
print(dict(Counter(f["type"] for f in act if f.get("status") == "verified")))
PY
else
  echo "NO RESULT JSON rc=$RC"; tail -5 "$OUTD/scan_${LABEL}.log" 2>/dev/null
fi

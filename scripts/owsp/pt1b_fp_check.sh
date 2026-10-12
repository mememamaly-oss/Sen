#!/bin/bash
# PT-1b live FP-verification: scan the 29-endpoint spec (9 FP tests + 20 catches)
# with the guarded engine, then check: FP tests silent, catches intact.
set -u
OUT=/home/z/my-project/tool-results/pt1b_live
SPEC=$OUT/spec_fp_check.json
ENG=/home/z/my-project/build-v430
BM=/home/z/tools/benchmark
export JAVA_HOME=/home/z/tools/jdk-21.0.12.1+1
export PATH=$JAVA_HOME/bin:/home/z/tools/apache-maven-3.9.9/bin:$PATH
cd "$BM" || exit 1
pkill -9 -f "catalina" 2>/dev/null; pkill -9 -f "hsqldb" 2>/dev/null
pkill -9 -f LDAPServer 2>/dev/null; pkill -9 -f DataBaseServer 2>/dev/null
pkill -9 -f "cargo-maven3-plugin" 2>/dev/null; sleep 2
: > "$BM/testfiles/passwordFile.txt" 2>/dev/null || true
nohup mvn -B package cargo:run -Pdeploy -Dcargo.servlet.port=8080 -Dcargo.protocol=http \
  -Dcargo.tomcat.httpSecure=false -Drunenv=local -Dmaven.test.skip=true \
  > /home/z/tools/pt1b_stack.log 2>&1 &
MVPID=$!
trap 'kill $MVPID 2>/dev/null; pkill -9 -f "catalina" 2>/dev/null; pkill -9 -f hsqldb 2>/dev/null; pkill -9 -f LDAPServer 2>/dev/null; pkill -9 -f DataBaseServer 2>/dev/null; pkill -9 -f cargo-maven3 2>/dev/null' EXIT
up=0
for i in $(seq 1 170); do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "http://localhost:8080/benchmark/" 2>/dev/null)
  [ "$code" = "200" ] && { up=1; break; }
  kill -0 $MVPID 2>/dev/null || { echo "MVN DIED"; exit 1; }
  sleep 1
done
[ "$up" = "1" ] || { echo "STACK TIMEOUT"; exit 1; }
echo "=== STACK UP (${i}s) ==="
cd "$ENG" || exit 1
timeout 330 python3 sentinel/cli.py scan http://localhost:8080/benchmark \
  --allow-private --oast local --no-browser --no-crawl \
  --openapi-spec "$SPEC" --seed 7f3c91aa --max-pages 6000 \
  --out "$OUT/scan_fp_check.json" --db "$OUT/scan_fp_check.db" > "$OUT/scan.log" 2>&1
echo "scan rc=$?"
python3 - "$OUT/scan_fp_check.json" "$OUT/lists.json" << 'PY'
import json, sys, re
d = json.load(open(sys.argv[1])); lists = json.load(open(sys.argv[2]))
FP, CAUGHT = set(lists["FP"]), set(lists["CAUGHT_SAMPLE"])
trav = [f for f in d["findings"] if f["type"] == "path_traversal"
        and f.get("status") == "verified"]
caught = set()
for f in trav:
    m = re.search(r"BenchmarkTest\d+", f.get("url", ""))
    if m: caught.add(m.group(0))
fp_hits = sorted(caught & FP)
kept = sorted(caught & CAUGHT)
print(f"path_traversal verified: {len(trav)}")
print(f"FP tests still firing (must be 0): {len(fp_hits)} {fp_hits}")
print(f"catch-sample still caught (want {len(CAUGHT)}): {len(kept)}",
      "MISSING:" , sorted(CAUGHT - caught) if CAUGHT - caught else "none")
ok = not fp_hits and kept == CAUGHT
print("PT-1b LIVE VERDICT:", "ALL GREEN" if ok else "PROBLEM")
PY

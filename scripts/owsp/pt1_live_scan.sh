#!/bin/bash
# PT-1 live verification scan — PROVEN mvn cargo:run stack pattern + engine scan.
set -u
OUT=/home/z/my-project/tool-results/pt1_live
SPEC=$OUT/spec_pt1_live.json
ENG=/home/z/my-project/build-v430
BM=/home/z/tools/benchmark

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
  > /home/z/tools/pt1-stack.log 2>&1 &
MVPID=$!
trap 'kill $MVPID 2>/dev/null; pkill -9 -f "catalina" 2>/dev/null; pkill -9 -f hsqldb 2>/dev/null; pkill -9 -f LDAPServer 2>/dev/null; pkill -9 -f DataBaseServer 2>/dev/null; pkill -9 -f cargo-maven3 2>/dev/null' EXIT

up=0
for i in $(seq 1 170); do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "http://localhost:8080/benchmark/" 2>/dev/null)
  [ "$code" = "200" ] && { up=1; break; }
  kill -0 $MVPID 2>/dev/null || { echo "MVN DIED"; tail -20 /home/z/tools/pt1-stack.log; exit 1; }
  sleep 1
done
[ "$up" = "1" ] || { echo "STACK TIMEOUT code=$code"; tail -20 /home/z/tools/pt1-stack.log; exit 1; }
echo "=== STACK UP (${i}s) ==="

cd "$ENG" || exit 1
timeout 330 python3 sentinel/cli.py scan http://localhost:8080/benchmark \
  --allow-private --oast local --no-browser --no-crawl \
  --openapi-spec "$SPEC" \
  --seed 7f3c91aa --max-pages 6000 \
  --out "$OUT/scan_pt1_live.json" --db "$OUT/scan_pt1_live.db" > "$OUT/scan.log" 2>&1
RC=$?
echo "scan rc=$RC"

python3 - "$OUT/scan_pt1_live.json" "$OUT/test_lists.json" << 'PY'
import json, sys, re
from collections import Counter
d = json.load(open(sys.argv[1]))
lists = json.load(open(sys.argv[2]))
FN, TPC = set(lists["FN"]), set(lists["TP_controls"])
act = [f for f in d["findings"] if f["type"] not in ("missing_security_headers", "server_banner_disclosure", "tech_banner")]
print("requests:", d["stats"].get("requests"), "endpoints:", d["stats"].get("endpoints"))
print("active findings:", len(act), "| verified:", sum(1 for f in act if f.get("status") == "verified"))
print("by type (verified):", dict(Counter(f["type"] for f in act if f.get("status") == "verified")))
trav = [f for f in act if f["type"] == "path_traversal" and f.get("status") == "verified"]
caught = set()
for f in trav:
    m = re.search(r"BenchmarkTest\d+", f.get("url", ""))
    if m: caught.add(m.group(0))
fn_caught = sorted(caught & FN)
tp_caught = sorted(caught & TPC)
print("\n=== PT-1 LIVE RESULT ===")
print(f"FN tests now CAUGHT: {len(fn_caught)}/{len(FN)}")
print("   ", fn_caught)
print(f"TP controls still caught: {len(tp_caught)}/{len(TPC)}", tp_caught)
still = sorted(FN - caught)
print(f"still FN: {len(still)}")
cls = json.load(open("/home/z/my-project/tool-results/benchmark-src-pathtraver/classification_v2.json"))
print("still-FN by channel:", dict(Counter(cls[t]["chan"] for t in still)))
json.dump({"fn_caught": fn_caught, "tp_controls_caught": tp_caught, "still_fn": still},
          open("/home/z/my-project/tool-results/pt1_live/pt1_result.json", "w"), indent=1)
PY

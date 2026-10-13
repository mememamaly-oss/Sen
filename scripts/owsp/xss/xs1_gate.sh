#!/bin/bash
# XS-1 fix gate — same contract as the SQ/CR rounds:
#   suite  : resumable 18-chunk run of the FULL registered case list
#            (3871 with unit_xs1; 1 documented env-stall exclusion)
#   doctor : 17/17
#   bench  : x3 IDENTICAL (fixture bench 38/0/0/37 F1=1.0000)
# Usage: xs1_gate.sh doctor|bench|suite|summary
# Suite is RESUMABLE: completed chunks cached in /tmp/xs1_gates; killed calls
# just re-invoke (leftover orphan fixtures are pkilled before each chunk).
set -u
ENG=/home/z/my-project/build-v430
OUT=/tmp/xs1_gates
EXCLUDE=regression_oob_public_channel_end_to_end
MODE="${1:-summary}"
mkdir -p "$OUT"
cd "$ENG" || exit 1

case "$MODE" in
doctor)
  timeout 300 python3 sentinel/cli.py doctor 2>&1 | tail -8
  ;;
bench)
  for i in 1 2 3; do
    timeout 500 python3 - "$i" <<'PY'
import json, sys
i = sys.argv[1]
from sentinel.cli import run_benchmark
rep = run_benchmark(out=f"/tmp/xs1_bench_{i}.json", label=f"xs1-bench-{i}")
c = rep["confusion"]
print("bench-%s:" % i, {k: c[k] for k in ("TP","FP","FN","TN")},
      "F1=%.4f" % rep["f1"],
      "reqs=", rep.get("scan", {}).get("stats", {}).get("requests", rep.get("requests")))
PY
  done
  ;;
suite)
  if [ ! -f "$OUT/chunks.txt" ]; then
    python3 - "$EXCLUDE" <<'PY'
import re, sys
src = open("tests/run_tests.py").read()
names = re.findall(r"^@case\s*\n?def (\w+)", src, re.M)
excl = sys.argv[1]
names = [n for n in names if n != excl]
open("/tmp/xs1_all_cases.txt", "w").write("\n".join(names))
print("registered-run:", len(names), "(excluded:", excl + ")")
PY
    ( cd "$OUT" && split -l 12 -d /tmp/xs1_all_cases.txt c && for f in c0* c1*; do [ -f "$f" ] && mv "$f" "$f.chunk"; done )
    ls "$OUT"/*.chunk | sed 's|.*/||' > "$OUT/chunks.txt"
  fi
  FAIL=0; PASSN=0; TOTALN=0
  while read -r ch; do
    RESULT="$OUT/result_$ch.json"
    if [ -f "$RESULT" ] && python3 -c "
import json,sys; d=json.load(open('$RESULT')); sys.exit(0 if d.get('passed') else 1)" 2>/dev/null; then
      N=$(python3 -c "import json; d=json.load(open('$RESULT')); print(d['total']-d['failed'])")
      T=$(python3 -c "import json; d=json.load(open('$RESULT')); print(d['total'])")
      PASSN=$((PASSN+N)); TOTALN=$((TOTALN+T))
      echo "chunk $ch: cached PASS $N/$T"
      continue
    fi
    pkill -f 'vulnapp|phase58|flows_app|gql_app|ws_app|malicious_app' 2>/dev/null
    sleep 0.3
    NAMES=$(tr '\n' ',' < "$OUT/$ch" | sed 's/,$//')
    SENTINEL_TEST_FILTER="$NAMES" timeout 540 python3 tests/run_tests.py all > "$RESULT" 2>/dev/null
    RC=$?
    if [ $RC -ne 0 ]; then
      echo "chunk $ch: FAIL (rc=$RC)"
      python3 - "$RESULT" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    for c in d.get('cases', []):
        if not c['ok'] and not c.get('skipped'):
            print('  FAIL:', c['name'], '->', str(c.get('error',''))[:130])
except Exception as e:
    print('  (no json: timeout or crash)', e)
PY
      FAIL=1; break
    else
      N=$(python3 -c "import json; d=json.load(open('$RESULT')); print(d['total']-d['failed'])")
      T=$(python3 -c "import json; d=json.load(open('$RESULT')); print(d['total'])")
      PASSN=$((PASSN+N)); TOTALN=$((TOTALN+T))
      echo "chunk $ch: PASS $N/$T"
    fi
  done < "$OUT/chunks.txt"
  echo "SUITE TOTAL: $PASSN/$TOTALN passed ($([ $FAIL -eq 0 ] && echo 'ALL CHUNKS PASS' || echo 'STOPPED ON FAILURE'))"
  ;;
summary)
  echo "cached chunk results:"
  for f in "$OUT"/result_*.json; do
    [ -f "$f" ] || continue
    python3 - "$f" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
name = sys.argv[1].split('result_')[-1].replace('.json','')
print(f"  {name}: {'PASS' if d.get('passed') else 'FAIL'} {d.get('total',0)-d.get('failed',0)}/{d.get('total',0)}")
PY
  done
  ;;
*)
  echo "usage: $0 doctor|bench|suite|summary" >&2; exit 2 ;;
esac

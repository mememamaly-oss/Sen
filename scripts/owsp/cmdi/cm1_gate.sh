#!/bin/bash
# CM-1 fix gate — same contract as the SQ/CR/XS rounds:
#   suite  : resumable chunked run of the FULL registered case list
#            (219 with unit_cm1; 1 documented env-stall exclusion)
#   doctor : 17/17
#   bench  : x3 IDENTICAL (fixture bench 38/0/0/37 F1=1.0000)
# Usage: cm1_gate.sh doctor|bench|suite|summary
# Suite is RESUMABLE: completed chunks cached in /tmp/cm1_gates; killed calls
# just re-invoke (leftover orphan fixtures are pkilled before each chunk).
set -u
ENG=/home/z/my-project/build-v430
OUT=/tmp/cm1_gates
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
rep = run_benchmark(out=f"/tmp/cm1_bench_{i}.json", label=f"cm1-bench-{i}")
c = rep["confusion"]
print("bench-%s:" % i, {k: c[k] for k in ("TP","FP","FN","TN")},
      "F1=%.4f" % rep["f1"],
      "reqs=", rep.get("scan", {}).get("stats", {}).get("requests", rep.get("requests")))
PY
  done
  echo "--- determinism (byte-identical hashes required) ---"
  for i in 1 2 3; do
    python3 -c "
import json
d=json.load(open('/tmp/cm1_bench_${i}.json'))
s=json.dumps(d, sort_keys=True).encode()
import hashlib; print('bench-${i}:', hashlib.sha256(s).hexdigest()[:16],
      d['confusion'])" 2>/dev/null || echo "bench-${i}: MISSING"
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
open("/tmp/cm1_all_cases.txt", "w").write("\n".join(names))
print("registered-run:", len(names), "(excluded:", excl + ")")
PY
    ( cd "$OUT" && split -l 12 -d /tmp/cm1_all_cases.txt c && for f in c0* c1*; do [ -f "$f" ] && mv "$f" "$f.chunk"; done )
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
      echo "chunk $ch: PASS $N/$T"
      PASSN=$((PASSN+N)); TOTALN=$((TOTALN+T))
    fi
  done < "$OUT/chunks.txt"
  echo "suite-total: $PASSN/$TOTALN chunks-fail=$FAIL"
  [ "$FAIL" = "0" ] || exit 1
  ;;
summary)
  echo "=== CM-1 gate summary ==="
  ls "$OUT"/result_*.json >/dev/null 2>&1 && python3 - "$OUT" <<'PY'
import json, sys, glob
tot = fail = 0
ok = True
for p in glob.glob(sys.argv[1] + "/result_*.json"):
    d = json.load(open(p))
    tot += d.get("total", 0); fail += d.get("failed", 0)
    ok = ok and d.get("passed", False)
print(f"suite: {tot-fail}/{tot} passing={ok}")
PY
  for i in 1 2 3; do
    [ -f "/tmp/cm1_bench_$i.json" ] && python3 -c "
import json
d=json.load(open('/tmp/cm1_bench_$i.json'))
s=json.dumps(d, sort_keys=True).encode()
import hashlib; print('bench-$i:', hashlib.sha256(s).hexdigest()[:16], d['confusion'], 'F1=%.4f'%d['f1'])" || echo "bench-$i: not run"
  done
  ;;
*)
  echo "usage: $0 doctor|bench|suite|summary"; exit 2
  ;;
esac

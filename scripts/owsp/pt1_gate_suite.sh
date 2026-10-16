#!/bin/bash
# PT-1 full-suite gate — resumable chunked runner for build-v430 (all cases,
# file order, 12/chunk). Persists per-chunk JSONs; re-runs skip PASS chunks.
set -u
ENG=/home/z/my-project/build-v430
OUT=/tmp/pt1_gate
mkdir -p "$OUT"
cd "$ENG" || exit 1

if [ ! -f "$OUT/chunks.txt" ]; then
  python3 - <<'EOF'
import re
src = open("tests/run_tests.py").read()
names = re.findall(r"^@case\s*\n?def (\w+)", src, re.M)
open("/tmp/all_cases.txt", "w").write("\n".join(names))
print("cases:", len(names))
EOF
  split -l 12 -d --additional-suffix=.chunk /tmp/all_cases.txt "$OUT/c"
  ls "$OUT"/*.chunk | sed 's|.*/||' > "$OUT/chunks.txt"
fi

FAIL=0; PASSN=0; TOTALN=0
while read -r ch; do
  RESULT="$OUT/result_$ch.json"
  if [ -f "$RESULT" ] && python3 -c "
import json,sys; d=json.load(open('$RESULT')); sys.exit(0 if d.get('passed') else 1)" 2>/dev/null; then
    echo "chunk $ch: cached PASS"; PASSN=$((PASSN+1)); continue
  fi
  NAMES=$(tr '\n' ',' < "$OUT/$ch" | sed 's/,$//')
  SENTINEL_TEST_FILTER="$NAMES" timeout 540 python3 tests/run_tests.py all > "$RESULT" 2>"$RESULT.err"
  RC=$?
  if [ $RC -ne 0 ]; then
    echo "chunk $ch: FAIL (rc=$RC)"
    python3 - "$RESULT" << 'PY'
import json
try:
    d = json.load(open(sys.argv[1]))
    for c in d['cases']:
        if not c['ok'] and not c.get('skipped'):
            print('  FAIL:', c['name'], '->', str(c.get('error',''))[:150])
except Exception as e:
    print('  (no json: timeout or crash)', e)
PY
    FAIL=1; break
  else
    N=$(python3 -c "import json; d=json.load(open('$RESULT')); print(f\"{d['total']-d['failed']}/{d['total']}\")")
    echo "chunk $ch: PASS $N"; PASSN=$((PASSN+1))
  fi
done < "$OUT/chunks.txt"
echo "chunks passed: $PASSN / $(wc -l < "$OUT/chunks.txt")"
[ $FAIL -eq 0 ] && echo "ALL CHUNKS PASS" || echo "STOPPED ON FAILURE"

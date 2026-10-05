#!/bin/bash
# Suite gate runner — chunked, resumable. Persists per-chunk JSONs to /tmp/gates/;
# re-runs skip completed chunks. Aborts on first failing chunk.
set -u
ENG=/home/z/my-project/build-v424
OUT=/tmp/gates
mkdir -p "$OUT"
cd "$ENG" || exit 1

# build chunk list once from the registry (names in file order)
if [ ! -f "$OUT/chunks.txt" ]; then
  grep -B1 "^def " tests/run_tests.py | grep -oE "^def [a-z_0-9]+" | sed 's/def //' > /tmp/all_cases.txt
  # only @case-registered ones: filter to names that appear right after @case
  python3 - <<'EOF'
import re
src = open("tests/run_tests.py").read()
names = re.findall(r"^@case\s*\n?def (\w+)", src, re.M)
open("/tmp/all_cases.txt", "w").write("\n".join(names))
print("cases:", len(names))
EOF
  # split into chunks of 14
  split -l 14 -d --additional-suffix=.chunk /tmp/all_cases.txt "$OUT/c" 2>/dev/null || \
  (cd "$OUT" && split -l 14 -d /tmp/all_cases.txt c && for f in c0*; do mv "$f" "$f.chunk"; done)
  ls "$OUT"/*.chunk | sed 's|.*/||' > "$OUT/chunks.txt"
fi

FAIL=0
while read -r ch; do
  RESULT="$OUT/result_$ch.json"
  if [ -f "$RESULT" ] && python3 -c "
import json,sys; d=json.load(open('$RESULT')); sys.exit(0 if d.get('passed') else 1)" 2>/dev/null; then
    echo "chunk $ch: already PASS (cached)"
    continue
  fi
  NAMES=$(tr '\n' ',' < "$OUT/$ch" | sed 's/,$//')
  SENTINEL_TEST_FILTER="$NAMES" timeout 300 python3 tests/run_tests.py all > "$RESULT" 2>/dev/null
  RC=$?
  if [ $RC -ne 0 ]; then
    echo "chunk $ch: FAIL (rc=$RC)"
    python3 -c "
import json
try:
    d = json.load(open('$RESULT'))
    for c in d['cases']:
        if not c['ok'] and not c.get('skipped'):
            print('  FAIL:', c['name'], '->', c.get('error','')[:130])
except Exception as e:
    print('  (no json: timeout or crash)', e)
"
    FAIL=1
    break
  else
    N=$(python3 -c "
import json; d=json.load(open('$RESULT'))
print(f\"{d['total']-d['failed']}/{d['total']}\")")
    echo "chunk $ch: PASS $N"
  fi
done < "$OUT/chunks.txt"
[ $FAIL -eq 0 ] && echo "ALL CHUNKS PASS" || echo "STOPPED ON FAILURE"

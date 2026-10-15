#!/bin/bash
# Hardening-round gate driver (2026-10-15) — same contract as tb_gate.sh suite,
# with a chunk-range argument so each foreground tool call fits its timeout.
# The tb_gate.sh suite mode is resumable; this driver runs chunks START..END
# sequentially in the foreground, then prints a running total.
# Usage: hardening_gate_range.sh <first> <last>   (chunk numbers, e.g. 0 2)
set -u
ENG=/home/z/my-project/build-v430
OUT=/tmp/tb_gates
EXCLUDE=regression_oob_public_channel_end_to_end
FIRST="${1:?start chunk}"
LAST="${2:?end chunk}"
mkdir -p "$OUT"
cd "$ENG" || exit 1

# one-time: build the chunk files (same recipe as tb_gate.sh suite)
if [ ! -f "$OUT/chunks.txt" ]; then
  python3 - "$EXCLUDE" <<'PY'
import re, sys
src = open("tests/run_tests.py").read()
names = re.findall(r"^@case\s*\n?def (\w+)", src, re.M)
excl = sys.argv[1]
names = [n for n in names if n != excl]
open("/tmp/tb_all_cases.txt", "w").write("\n".join(names))
print("registered-run:", len(names), "(excluded:", excl + ")")
PY
  ( cd "$OUT" && split -l 12 -d /tmp/tb_all_cases.txt c && for f in c0* c1*; do [ -f "$f" ] && mv "$f" "$f.chunk"; done )
  ls "$OUT"/*.chunk | sed 's|.*/||' > "$OUT/chunks.txt"
fi

FAIL=0; PASSN=0; TOTALN=0
while read -r ch; do
  N_CH="${ch%.chunk}"
  N_CH="${N_CH#c}"
  # zero-pad compare (c00..c18)
  if [ "$N_CH" -lt "$FIRST" ] || [ "$N_CH" -gt "$LAST" ]; then continue; fi
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
  T0=$(date +%s)
  SENTINEL_TEST_FILTER="$NAMES" timeout 540 python3 tests/run_tests.py all > "$RESULT" 2>/dev/null
  RC=$?
  T1=$(date +%s)
  if [ $RC -ne 0 ]; then
    echo "chunk $ch: FAIL (rc=$RC, $((T1-T0))s)"
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
    echo "chunk $ch: PASS $N/$T ($((T1-T0))s)"
    PASSN=$((PASSN+N)); TOTALN=$((TOTALN+T))
  fi
done < "$OUT/chunks.txt"
echo "range-total: $PASSN/$TOTALN chunks-fail=$FAIL"
[ "$FAIL" = "0" ] || exit 1

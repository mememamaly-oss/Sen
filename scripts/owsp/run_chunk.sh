#!/bin/bash
# GTP-12 gate — run one chunk by index from /tmp/gtp12_chunk_plan.json
# Usage: bash run_chunk.sh <n>
set -u
N="${1:?chunk index}"
ENG=/home/z/my-project/build-v430
CACHE=/tmp/gtp12_gate_chunks
mkdir -p "$CACHE"
cd "$ENG" || exit 1
FILT=$(python3 -c "
import json
plan = json.load(open('/tmp/gtp12_chunk_plan.json'))
d = dict((n, f) for n, f, _ in plan)
print(d['$N'])")
OUT="$CACHE/$N.json"
echo "=== chunk $N filter=$FILT ==="
SENTINEL_TEST_FILTER="$FILT" timeout 560 python3 tests/run_tests.py all > "$OUT" 2>"$OUT.err"
RC=$?
python3 - "$OUT" "$RC" << 'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"  OUTPUT INVALID ({e}) — see {sys.argv[1]}.err"); sys.exit(1)
ran = [c for c in d["cases"] if not c.get("skipped")]
fails = [c for c in ran if not c["ok"]]
print(f"  ran={len(ran)} failed={len(fails)} rc={sys.argv[2]}")
for c in fails: print(f"    FAIL {c['name']}: {c.get('error','')[:140]}")
PY

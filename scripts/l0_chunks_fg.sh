#!/usr/bin/env bash
# L0 chunks — idempotent FOREGROUND runner (resumable across tool calls).
# Usage: l0_chunks_fg.sh <start-chunk> <end-chunk>
# Appends only VERIFIED-OK chunk records to saas-data/l0-engine/ledger.jsonl;
# chunks already OK in the ledger are skipped on re-runs.
set -u
cd /home/z/my-project
LEDGER=saas-data/l0-engine/ledger.jsonl
mkdir -p saas-data/l0-engine .l0-recovery

chunk_ok_in_ledger() {
  [ -f "$LEDGER" ] && python3 - "$1" <<'PYEOF' 2>/dev/null
import json, sys
recs = [json.loads(l) for l in open('saas-data/l0-engine/ledger.jsonl') if l.strip()]
sys.exit(0 if any(r.get('chunk') == int(sys.argv[1]) and r.get('ok') for r in recs) else 1)
PYEOF
}

attempt_ok() {
  [ -s ".l0-recovery/ledger_c$1.jsonl" ] && python3 - "$1" <<'PYEOF' 2>/dev/null
import json, sys
recs = [json.loads(l) for l in open(f'.l0-recovery/ledger_c{sys.argv[1]}.jsonl') if l.strip()]
sys.exit(0 if len(recs) == 1 and recs[0]['ok'] else 1)
PYEOF
}

for c in $(seq "$1" "$2"); do
  if chunk_ok_in_ledger "$c"; then echo "chunk $c: already OK — skip"; continue; fi
  for attempt in 1 2; do
    rm -f ".l0-recovery/ledger_c$c.jsonl"
    echo "--- chunk $c attempt $attempt start $(date +%H:%M:%S) ---"
    timeout -k 10 500 python3 scripts/run_recovery_chunks_fg.py \
      --clone /home/z/my-project/.l0-recovery/clone --ledger "/home/z/my-project/.l0-recovery/ledger_c$c.jsonl" "$c" "$c"
    rc=$?
    if attempt_ok "$c"; then
      cat ".l0-recovery/ledger_c$c.jsonl" >> "$LEDGER"
      echo "chunk $c OK (rc=$rc, $(date +%H:%M:%S))"
      break
    fi
    echo "chunk $c attempt $attempt FAILED (rc=$rc)"
  done
done

echo "=== LEDGER STATE ==="
python3 - <<'PYEOF'
import json, os
p = 'saas-data/l0-engine/ledger.jsonl'
if os.path.exists(p):
    recs = [json.loads(l) for l in open(p) if l.strip()]
    ok = [r for r in recs if r.get('ok')]
    print('chunks OK:', sorted(r['chunk'] for r in ok),
          '| cases:', sum(r['ran'] for r in ok), '/ 102')
else:
    print('no ledger yet')
PYEOF

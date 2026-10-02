#!/usr/bin/env bash
# L1-R engine gate chunks — idempotent FOREGROUND runner (resumable across
# tool calls), adapted from scripts/l0_chunks_fg.sh with recovery-validation
# paths. Appends only VERIFIED-OK chunk records to the L1-R ledger; chunks
# already OK in the ledger are skipped on re-runs.
# Usage: l1r_chunks_fg.sh <start-chunk> <end-chunk>
set -u
cd /home/z/my-project
LEDGER=recovery-validation/engine-outputs/ledger.jsonl
CLONE=/home/z/my-project/recovery-validation/engine
mkdir -p recovery-validation/engine-outputs

chunk_ok_in_ledger() {
  [ -f "$LEDGER" ] && python3 - "$1" <<'PYEOF' 2>/dev/null
import json, sys
recs = [json.loads(l) for l in open('recovery-validation/engine-outputs/ledger.jsonl') if l.strip()]
sys.exit(0 if any(r.get('chunk') == int(sys.argv[1]) and r.get('ok') for r in recs) else 1)
PYEOF
}

attempt_ok() {
  [ -s "recovery-validation/engine-outputs/ledger_c$1.jsonl" ] && python3 - "$1" <<'PYEOF' 2>/dev/null
import json, sys
recs = [json.loads(l) for l in open(f'recovery-validation/engine-outputs/ledger_c{sys.argv[1]}.jsonl') if l.strip()]
sys.exit(0 if len(recs) == 1 and recs[0]['ok'] else 1)
PYEOF
}

for c in $(seq "$1" "$2"); do
  if chunk_ok_in_ledger "$c"; then echo "chunk $c: already OK — skip"; continue; fi
  for attempt in 1 2; do
    rm -f "recovery-validation/engine-outputs/ledger_c$c.jsonl"
    echo "chunk $c attempt $attempt start: $(date -u +%T)"
    timeout -k 10 580 python3 scripts/run_recovery_chunks_fg.py \
      --clone "$CLONE" \
      --ledger "recovery-validation/engine-outputs/ledger_c$c.jsonl" "$c" "$c"
    rc=$?
    if attempt_ok "$c"; then
      cat "recovery-validation/engine-outputs/ledger_c$c.jsonl" >> "$LEDGER"
      echo "chunk $c OK (rc=$rc)"
      break
    else
      echo "chunk $c attempt $attempt FAILED (rc=$rc) — retrying"
    fi
  done
done
echo "ledger progress: $(grep -c '"ok": *true\|"ok":true' "$LEDGER" 2>/dev/null || echo 0)/9 chunks OK"

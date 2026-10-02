#!/usr/bin/env bash
# L0 engine regression gate — DETACHED runner (survives container freeze
# windows and tool-call boundaries; the GATE-F pattern).
# Waits for the detached benchmark #3, then runs the 102-case suite in
# 9 foreground chunks (with retry against environment stalls), merges with
# strict accounting, and verifies against the frozen v4.1.1 baseline.
set -u
cd /home/z/my-project
LOG=.l0-recovery/engine_gate.log
ECHO() { echo "[$(date +%H:%M:%S)] $*" >> "$LOG"; }

ECHO "=== L0 ENGINE GATE START ==="

# ── 1. wait for the detached benchmark #3 ─────────────────────────────────
ECHO "waiting for bench_recovery_3.json ..."
b3ok=""
for i in $(seq 1 360); do
  if [ -s saas-data/l0-engine/bench_recovery_3.json ] && \
     python3 -c "import json;json.load(open('saas-data/l0-engine/bench_recovery_3.json'))" >/dev/null 2>&1; then
    ECHO "bench3 DONE (valid json)"; b3ok=1; break
  fi
  sleep 5
done
[ -n "$b3ok" ] || ECHO "WARNING: bench3 not finished after 30min — continuing anyway"

# ── 2. the 102-case suite: 9 chunks, retry on environment stalls ─────────
rm -f saas-data/l0-engine/ledger.jsonl
FAILED_CHUNKS=""
for c in 1 2 3 4 5 6 7 8 9; do
  ok=""
  for attempt in 1 2 3; do
    rm -f .l0-recovery/ledger_c$c.jsonl
    ECHO "chunk $c attempt $attempt start"
    timeout -k 10 1500 python3 scripts/run_recovery_chunks_fg.py \
      --clone .l0-recovery/clone --ledger .l0-recovery/ledger_c$c.jsonl $c $c >> "$LOG" 2>&1
    rc=$?
    if [ -s .l0-recovery/ledger_c$c.jsonl ] && python3 - <<PYEOF 2>/dev/null
import json, sys
recs = [json.loads(l) for l in open('.l0-recovery/ledger_c$c.jsonl') if l.strip()]
sys.exit(0 if len(recs) == 1 and recs[0]['ok'] else 1)
PYEOF
    then
      cat .l0-recovery/ledger_c$c.jsonl >> saas-data/l0-engine/ledger.jsonl
      ok=1; ECHO "chunk $c OK (attempt $attempt, rc=$rc)"; break
    else
      ECHO "chunk $c attempt $attempt FAILED (rc=$rc) — retrying"
    fi
  done
  [ -n "$ok" ] || { FAILED_CHUNKS="$FAILED_CHUNKS $c"; ECHO "chunk $c FAILED after 3 attempts"; }
done
ECHO "chunks done. failed_chunks=[$FAILED_CHUNKS]"

# ── 3. strict merge ────────────────────────────────────────────────────────
if [ -z "$FAILED_CHUNKS" ]; then
  python3 scripts/merge_recovery_jsonl.py --clone .l0-recovery/clone \
    --ledger saas-data/l0-engine/ledger.jsonl \
    --out saas-data/l0-engine/tests_recovery.json >> "$LOG" 2>&1
  ECHO "merge exit=$?"
else
  ECHO "SKIP merge — failed chunks: $FAILED_CHUNKS"
fi

# ── 4. verify against the frozen baseline ─────────────────────────────────
python3 scripts/verify_recovery_v411.py --recovery saas-data/l0-engine \
  --baseline gap-validation/results >> "$LOG" 2>&1
ECHO "verify exit=$?"

ECHO "=== L0 ENGINE GATE DONE ==="

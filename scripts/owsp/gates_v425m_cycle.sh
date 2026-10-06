#!/bin/bash
# Mutillidae-round FULL GATE CYCLE, detached (survives tool-call reaping).
# Steps: chunks (resumable) -> doctor -> bench x3 -> verify. DONE marker at end.
set -u
D=/home/z/my-project/build-v425/results
LOG=/home/z/my-project/build-v425/results/gates_v425m.log
MARK=$D/gates_v425m.DONE
[ -f "$MARK" ] && { echo "ALREADY DONE: $(cat $MARK)"; exit 0; }
cd /home/z/my-project

{
echo "=== MUTILLIDAE-ROUND GATE CYCLE start $(date -u +%H:%M:%S) ==="
python3 scripts/gates_v425.py count || exit 1

# chunks: resumable — cached {TAG}_c{i}.json skip re-execution
N=$(python3 -c "
import sys; sys.path.insert(0,'scripts')
from gates_v425 import chunks
print(len(chunks()))")
for i in $(seq 1 $N); do
  if [ -f "$D/chunks/v425m_c$i.json" ]; then echo "chunk $i cached"; continue; fi
  echo "--- chunk $i $(date -u +%H:%M:%S) ---"
  python3 scripts/gates_v425.py chunk $i || { echo "CHUNK $i FAILED"; exit 1; }
done

echo "--- doctor $(date -u +%H:%M:%S) ---"
python3 scripts/gates_v425.py doctor || { echo "DOCTOR FAILED"; exit 1; }

for k in 1 2 3; do
  echo "--- bench $k $(date -u +%H:%M:%S) ---"
  python3 scripts/gates_v425.py bench $k || { echo "BENCH $k FAILED"; exit 1; }
done

echo "--- verify $(date -u +%H:%M:%S) ---"
python3 scripts/gates_v425.py verify || { echo "VERIFY FAILED"; exit 1; }

echo "ALL GATES GREEN $(date -u +%H:%M:%S)"
echo "rc=0 $(date +%H:%M:%S)" > "$MARK"
} >> "$LOG" 2>&1

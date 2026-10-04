#!/bin/bash
cd /home/z/my-project
LOG=build-v423/results/gates_round_l2.log
echo "=== GATE CYCLE START $(date -u +%H:%M:%S) ===" > $LOG
for i in "$@"; do
  echo "--- chunk $i $(date -u +%H:%M:%S) ---" >> $LOG
  python3 scripts/gates_v423.py chunk $i >> $LOG 2>&1 || { echo "CHUNK $i FAILED" >> $LOG; exit 1; }
done
echo "--- doctor $(date -u +%H:%M:%S) ---" >> $LOG
python3 scripts/gates_v423.py doctor >> $LOG 2>&1 || { echo "DOCTOR FAILED" >> $LOG; exit 1; }
for k in 1 2 3; do
  echo "--- bench $k $(date -u +%H:%M:%S) ---" >> $LOG
  python3 scripts/gates_v423.py bench $k >> $LOG 2>&1 || { echo "BENCH $k FAILED" >> $LOG; exit 1; }
done
echo "--- verify $(date -u +%H:%M:%S) ---" >> $LOG
python3 scripts/gates_v423.py verify >> $LOG 2>&1 || { echo "VERIFY FAILED" >> $LOG; exit 1; }
echo "=== ALL GATES GREEN $(date -u +%H:%M:%S) ===" >> $LOG

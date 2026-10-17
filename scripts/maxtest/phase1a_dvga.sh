#!/bin/bash
# Maximum internal test — Phase 1a: DVGA full rebuild (clone -> venv -> deps -> launch)
G=/home/z/my-project/gap-validation
LOG=$G/logs
mkdir -p $G/targets $LOG
echo "=== DVGA REBUILD START $(date -u +%H:%M:%S) ==="
if [ ! -d $G/targets/dvga ]; then
  git clone --depth 1 https://github.com/dolevf/DVGA.git $G/targets/dvga > $LOG/dvga_clone.log 2>&1 \
    && echo "CLONE OK" || { echo "CLONE FAIL"; exit 1; }
fi
if [ ! -d $G/dvga-venv ]; then
  python3 -m venv $G/dvga-venv >> $LOG/dvga_setup_full.log 2>&1 || exit 1
fi
bash $G/setup_dvga2.sh > $LOG/dvga_setup2.log 2>&1
tail -15 $LOG/dvga_setup2.log
echo "=== launching DVGA ==="
bash $G/start_dvga.sh >> $LOG/dvga_start.log 2>&1
tail -3 $LOG/dvga_start.log
echo "=== DVGA REBUILD DONE $(date -u +%H:%M:%S) ==="

#!/usr/bin/env bash
# L0 production gate — DETACHED runner: boots the production server on :3000
# (main DB), restores the standard demo dataset through real flows, then runs
# the mandatory production cross-tenant verification.
set -u
cd /home/z/my-project
LOG=.l0-recovery/prod_gate.log
ECHO() { echo "[$(date +%H:%M:%S)] $*" >> "$LOG"; }

ECHO "=== L0 PROD GATE START ==="

bash scripts/start_prod_server.sh >> "$LOG" 2>&1
ECHO "prod server start exit=$?"

python3 scripts/bootstrap_demo_data.py >> "$LOG" 2>&1
ECHO "bootstrap_demo_data exit=$?"

python3 scripts/l0_prod_verify.py --base http://localhost:3000 >> "$LOG" 2>&1
ECHO "prod verify exit=$?"

ECHO "=== L0 PROD GATE DONE ==="

#!/bin/bash
# SENTINEL v4.1.1 LIVE scan — DVGA (Damn Vulnerable GraphQL Application)
# Authorized local training target (127.0.0.1:5013, isolated instance).
# Main engine: sentinel41a Bearer JWT. Authz: sentinel41a + sentinel41b (token mode).
# --exclude-url /difficulty/: operator state pinning — the difficulty GET routes
#   flip the whole app between easy/hardened GraphQL behavior (hard disables
#   introspection); the scan pins the default (easy) configuration.
set -x
cd /home/z/my-project/build-v411
TOKA=$(python3 -c "import json; print(json.load(open('/home/z/my-project/gap-validation/dvga_authz_accounts.json'))['accounts'][0]['token'])")
timeout 560 python3 -m sentinel.cli scan http://127.0.0.1:5013/ \
  --allow-private --logic-active --workflow \
  --auth-token "$TOKA" --auth-scheme Bearer \
  --auth-validate-url http://127.0.0.1:5013/graphql \
  --authz-accounts /home/z/my-project/gap-validation/dvga_authz_accounts.json \
  --exclude-url /difficulty/ \
  --out /home/z/my-project/gap-validation/results/scan_dvga_LIVE.json \
  --db /home/z/my-project/gap-validation/results/dvga_live.db 2>&1 | tail -30

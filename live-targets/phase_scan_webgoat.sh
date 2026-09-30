#!/bin/bash
# Phase 2a — PRODUCTION LIGHT SCAN: WebGoat (authenticated) + workflow LEARN-ONLY.
# Doctrine: no attack battery on live targets (--logic-active stays OFF).
set -e
LT=/home/z/my-project/live-targets
RES=/home/z/my-project/download/sentinel-results
SENT=/home/z/my-project/verify-live

bash "$LT/srv.sh" up
cd "$SENT"
echo "===== SCAN: WebGoat ====="
date +%s > /tmp_scan_start 2>/dev/null || true
START=$(date +%s)
timeout 480 python3 -m sentinel.cli scan "http://127.0.0.1:8080/WebGoat" \
  --allow-private \
  --auth-user sentinel9x --auth-pass test1234 \
  --auth-url "http://127.0.0.1:8080/WebGoat/login" \
  --auth-user-field username --auth-pass-field password \
  --max-pages 40 --timeout 10 \
  --workflow \
  --out "$RES/scan_webgoat_v300_LIVE.json" \
  --db "$RES/sentinel_v300_live.db" 2>&1 | tail -45
END=$(date +%s)
echo "SCAN DURATION: $((END-START))s"
echo "===== output files ====="
ls -la "$RES/scan_webgoat_v300_LIVE.json" "$RES/sentinel_v300_live.db" 2>/dev/null

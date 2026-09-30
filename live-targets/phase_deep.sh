#!/bin/bash
# Phase 2c — DEEP scan: WebGoat with the operator-supplied OpenAPI surface seed.
set -e
LT=/home/z/my-project/live-targets
RES=/home/z/my-project/download/sentinel-results
SENT=/home/z/my-project/verify-live

bash "$LT/srv.sh" up
cd "$SENT"
echo "===== DEEP SCAN: WebGoat (openapi-seeded, authenticated, learn-only) ====="
START=$(date +%s)
timeout 470 python3 -m sentinel.cli scan "http://127.0.0.1:8080/WebGoat" \
  --allow-private \
  --auth-user sentinel9x --auth-pass test1234 \
  --auth-url "http://127.0.0.1:8080/WebGoat/login" \
  --auth-user-field username --auth-pass-field password \
  --openapi-spec "$LT/webgoat_surface_openapi.json" \
  --max-pages 60 --timeout 10 \
  --workflow \
  --out "$RES/scan_webgoat_v300_LIVE_deep.json" \
  --db "$RES/sentinel_v300_live.db" 2>&1 | tail -60
END=$(date +%s)
echo "DURATION: $((END-START))s"

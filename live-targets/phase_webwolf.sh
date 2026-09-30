#!/bin/bash
# Phase 2d — WebWolf light scan (unauthenticated; the attacker's-landing-app posture).
set -e
LT=/home/z/my-project/live-targets
RES=/home/z/my-project/download/sentinel-results
SENT=/home/z/my-project/verify-live

bash "$LT/srv.sh" up
cd "$SENT"
echo "===== SCAN: WebWolf ====="
START=$(date +%s)
timeout 460 python3 -m sentinel.cli scan "http://127.0.0.1:9090/WebWolf" \
  --allow-private \
  --openapi-spec "$LT/webwolf_surface_openapi.json" \
  --max-pages 25 --timeout 10 \
  --workflow \
  --out "$RES/scan_webwolf_v300_LIVE.json" \
  --db "$RES/sentinel_v300_live.db" 2>&1 | tail -50
END=$(date +%s)
echo "DURATION: $((END-START))s"

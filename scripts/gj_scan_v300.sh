#!/bin/bash
# Phase 2 — PRODUCTION SCAN: ginandjuice.shop (authorized PortSwigger scanme)
# SENTINEL v3.0.1 ENG-15+ENG-16 patched on this target.
# Posture: authenticated (carlos), browser ON, OAST public,
#          --workflow LEARN-ONLY (no --logic-active on live targets).
set -e
RES=/home/z/my-project/download/sentinel-results
SENT=/home/z/my-project/verify-live

cd "$SENT"
echo "===== SCAN: ginandjuice.shop v3.0.0 (authenticated + workflow learn-only) ====="
START=$(date +%s)
timeout 597 python3 -m sentinel.cli scan "https://ginandjuice.shop" \
  --auth-user carlos --auth-pass hunter2 \
  --auth-url "https://ginandjuice.shop/login" \
  --auth-user-field username --auth-pass-field password \
  --oast public \
  --max-pages 35 --timeout 12 \
  --workflow \
  --out "$RES/scan_ginjuice_v301_LIVE.json" \
  --db "$RES/sentinel_v300_live.db" 2>&1 | tail -75
END=$(date +%s)
echo "SCAN DURATION: $((END-START))s"
echo "===== output ====="
ls -la "$RES/scan_ginjuice_v301_LIVE.json" 2>/dev/null || echo "NO OUTPUT FILE — scan overran/killed"

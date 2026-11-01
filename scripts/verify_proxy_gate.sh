#!/usr/bin/env bash
# PROXY-SECRET GATE PROOF DRIVER (owner order 2026-10-31, item 1.4).
#
# Boots a dedicated dev server (schema migrated as owner, app running as
# burhan_app, TRUSTED_PROXY_SECRET set) and runs ONLY
# tests/proxygate.integration.test.ts against it.
#
#   RED (pre-fix code): T1 fails — 130 distinct forged XFF values yield
#       ZERO 429s (every forged IP = a fresh bucket; the 120/hour budget
#       never engages).
#   BLUE (gated code):  all four tests pass — forgery gets no fresh
#       buckets, the valid secret still gets per-IP attribution.
#
# Exit code = the bun test exit code (non-zero = red).
set -uo pipefail
cd "$(dirname "$0")/.."

PORT="${PROXYGATE_PORT:-3198}"
LOG="tests/proxygate-server.log"
URL="http://127.0.0.1:${PORT}"
export TRUSTED_PROXY_SECRET="${TRUSTED_PROXY_SECRET:-proxy-gate-proof-secret}"

case "${MIGRATION_DATABASE_URL:-}" in
  postgresql://*|postgres://*) : ;;
  *) MIGRATION_DATABASE_URL="$(bash scripts/pg_dev_start.sh --reset)" || exit 1 ;;
esac
export MIGRATION_DATABASE_URL
if ! DATABASE_URL="$MIGRATION_DATABASE_URL" bunx prisma migrate deploy >>"$LOG" 2>&1; then
  echo "FATAL: migrate deploy failed"; tail -20 "$LOG"; exit 1
fi
DATABASE_URL="$(bash scripts/db_app_role.sh)" || { echo "FATAL: db_app_role.sh failed"; exit 1; }
export DATABASE_URL
export NEXTAUTH_SECRET="${NEXTAUTH_SECRET:-proxygate-test-secret}"
export BURHAN_DATA_DIR="${BURHAN_DATA_DIR:-/tmp/burhan-proxygate}"

pkill -f "next dev -p ${PORT}" 2>/dev/null && sleep 1
rm -f "$LOG"
bunx next dev -p "$PORT" >>"$LOG" 2>&1 &
SERVER_PID=$!
trap 'kill "${SERVER_PID}" 2>/dev/null; pkill -f "next dev -p ${PORT}" 2>/dev/null' EXIT

READY=0
for i in $(seq 1 60); do
  sleep 1
  if curl -sf -m 2 "${URL}/api/auth/csrf" >/dev/null 2>&1; then READY=1; echo "proxygate server READY (${i}s)"; break; fi
done
[ "$READY" = "1" ] || { echo "FATAL: server failed to start"; tail -30 "$LOG"; exit 1; }

# warm the route (next dev compiles on first hit; the 400/404 answers of the
# probe route are expected — one warmup hit pays the compile cost)
for i in $(seq 1 30); do
  CODE="$(curl -s -o /dev/null -w '%{http_code}' -m 20 "${URL}/api/demo/scan?id=warmup")"
  [ "$CODE" != "500" ] && [ "$CODE" != "000" ] && echo "route warmed (status ${CODE})" && break
  sleep 1
done

INTEGRATION_SERVER_URL="$URL" bun test --timeout 60000 tests/proxygate.integration.test.ts 2>&1 | grep -vE "^ (GET|POST) /"
RC=${PIPESTATUS[0]}
echo "--- proxygate driver done (rc=${RC}) ---"
exit "$RC"

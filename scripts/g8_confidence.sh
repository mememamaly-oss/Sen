#!/usr/bin/env bash
# G8 RACE CONFIDENCE LOOP (owner order 2026-10-31).
#
# The item-1.3 transaction re-opened the scan-start TOCTOU in CI (3
# concurrent starts, TWO accepted). The fix serializes starts with a
# per-target advisory transaction lock. The integration suite runs the
# race once per boot; this driver hammers the REAL test N times against
# ONE booted server for statistical confidence before pushing.
set -uo pipefail
cd "$(dirname "$0")/.."

N="${1:-10}"
PORT=3177
URL="http://127.0.0.1:${PORT}"

export MIGRATION_DATABASE_URL="${MIGRATION_DATABASE_URL:-postgresql://postgres@127.0.0.1:55432/burhan}"
case "${DATABASE_URL:-}" in
  postgresql://*|postgres://*) : ;;
  *) DATABASE_URL="$(bash scripts/db_app_role.sh)" || exit 1 ;;
esac
export DATABASE_URL
export NEXTAUTH_SECRET="${NEXTAUTH_SECRET:-g8-confidence-secret}"
export TRUSTED_PROXY_SECRET="${TRUSTED_PROXY_SECRET:-integration-proxy-secret}"
export BURHAN_DATA_DIR="${BURHAN_DATA_DIR:-/tmp/burhan-test-data}"

pkill -f "next dev -p ${PORT}" 2>/dev/null && sleep 1
bunx next dev -p "${PORT}" >/tmp/g8-server.log 2>&1 &
SERVER_PID=$!
trap 'kill "${SERVER_PID}" 2>/dev/null; pkill -f "next dev -p ${PORT}" 2>/dev/null' EXIT

READY=0
for i in $(seq 1 60); do
  sleep 1
  curl -sf -m 2 "${URL}/api/auth/csrf" >/dev/null 2>&1 && READY=1 && break
done
[ "$READY" = "1" ] || { echo "FATAL: server did not come up"; tail -20 /tmp/g8-server.log; exit 1; }
echo "server up (pid ${SERVER_PID})"

PASS=0; FAIL=0
for i in $(seq 1 "$N"); do
  if INTEGRATION_SERVER_URL="${URL}" bun test --timeout 60000 tests/api.integration.test.ts -t "G8 RACE" >/tmp/g8-run.log 2>&1; then
    PASS=$((PASS+1)); echo "run ${i}: PASS"
  else
    FAIL=$((FAIL+1)); echo "run ${i}: FAIL"; tail -15 /tmp/g8-run.log
  fi
done
echo "G8 focused race runs: PASS=${PASS} FAIL=${FAIL}"
[ "$FAIL" = "0" ] || exit 1
exit 0

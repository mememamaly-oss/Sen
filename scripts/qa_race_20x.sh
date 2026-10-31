#!/usr/bin/env bash
# QA HARNESS (2026-10-31, Part 3 order): run THE bootstrap-race integration
# test ("RACE: 10 concurrent bootstrap POSTs — exactly ONE wins",
# tests/api.integration.test.ts) N consecutive times against the real Next.js
# dev server + real PostgreSQL, with the platform tables TRUNCATEd between
# iterations so every iteration sees the fresh-instance state the test
# requires. NOT part of CI; untracked QA tooling.
#
# Usage: bash scripts/qa_race_20x.sh [N] [extra-bun-test-args...]
set -uo pipefail
cd "$(dirname "$0")/.."

N="${1:-20}"; shift || true
PORT="${QA_RACE_PORT:-3188}"
LOG="tests/qa-race-server.log"
URL="http://127.0.0.1:${PORT}"

export DATABASE_URL="$(bash scripts/pg_dev_start.sh --reset)" || { echo "FATAL: pg start failed"; exit 1; }
export NEXTAUTH_SECRET="${NEXTAUTH_SECRET:-integration-test-secret}"
export SENTINEL_DATA_DIR="${SENTINEL_DATA_DIR:-/tmp/sentinel-test-data}"
PG_BIN="$(python3 -c 'import pgserver,os,sys; sys.stdout.write(os.path.dirname(pgserver.__file__)+"/pginstall/bin")')"
PSQL="$PG_BIN/psql"

echo "DATABASE_URL protocol: ${DATABASE_URL%%://*} (host ${DATABASE_URL##*@})"
rm -f "$LOG"

if ! bunx prisma migrate deploy >>"$LOG" 2>&1; then
  echo "FATAL: migrate deploy failed"; tail -20 "$LOG"; exit 1
fi

pkill -f "next dev -p ${PORT}" 2>/dev/null && sleep 1
bunx next dev -p "${PORT}" >>"${LOG}" 2>&1 &
SERVER_PID=$!
trap 'kill "${SERVER_PID}" 2>/dev/null; pkill -f "next dev -p ${PORT}" 2>/dev/null' EXIT

READY=0
for i in $(seq 1 90); do
  sleep 1
  if curl -sf -m 2 "${URL}/api/bootstrap" >/dev/null 2>&1; then READY=1; echo "server READY after ${i}s"; break; fi
done
[ "${READY}" = "1" ] || { echo "FATAL: server not ready"; tail -30 "$LOG"; exit 1; }

TRUNCATE_SQL='TRUNCATE TABLE "User","Organization","Membership","Target","Scan","Finding","Report","AuditLog","TwinGraph","PlatformLock" RESTART IDENTITY CASCADE;'

PASS=0; FAIL=0
for i in $(seq 1 "$N"); do
  "$PSQL" -h 127.0.0.1 -p 55432 -U postgres -d sentinel -c "$TRUNCATE_SQL" >/dev/null 2>&1 || { echo "iter $i: TRUNCATE FAILED"; FAIL=$((FAIL+1)); continue; }
  OUT="$(INTEGRATION_SERVER_URL="${URL}" INTEGRATION_PORT="${PORT}" bun test --timeout 60000 tests/api.integration.test.ts -t "RACE" 2>&1)"
  RC=$?
  if [ $RC -eq 0 ]; then
    PASS=$((PASS+1)); echo "run $i/$N: PASS"
  else
    FAIL=$((FAIL+1)); echo "run $i/$N: FAIL (rc=$RC)"
    echo "$OUT" | grep -E "expected|Received|✗|error:|wins|✘" | head -6
    echo "$OUT" | tail -25 > "tests/qa-race-fail-run${i}.log"
  fi
done

echo "===== RACE TEST ${N}x RESULT: PASS=${PASS} FAIL=${FAIL} ====="
kill "${SERVER_PID}" 2>/dev/null
pkill -f "next dev -p ${PORT}" 2>/dev/null
exit 0

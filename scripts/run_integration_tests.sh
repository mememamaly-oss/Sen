#!/usr/bin/env bash
# INTEGRATION TEST RUNNER (audit 2026-10-23) — the supported path.
#
# Why a bash runner: the integration suite needs the real Next.js dev
# server. Spawning the server from inside `bun test` proved unreliable in
# sandboxed environments (child-process trees can observe stale file
# content); a bash-managed server + attached test suite is deterministic.
#
# Steps: fresh scratch DB -> prisma db push -> boot dev server -> wait
# ready -> run bun test against it -> always kill server -> exit with the
# test's exit code.
set -uo pipefail
cd "$(dirname "$0")/.."

PORT="${INTEGRATION_PORT:-3177}"
DB="tests/integration.db"
LOG="tests/integration-server.log"
URL="http://127.0.0.1:${PORT}"

export DATABASE_URL="file:$(pwd)/${DB}"
export NEXTAUTH_SECRET="integration-test-secret"
export SENTINEL_DATA_DIR="/tmp/sentinel-test-data"

# --- clean state -------------------------------------------------------------
pkill -f "next dev -p ${PORT}" 2>/dev/null && sleep 1
rm -f "${DB}" "${DB}-journal" "${DB}-wal" "${DB}-shm" "${LOG}"
mkdir -p /tmp/sentinel-test-data

# --- schema push (bash context: reads the CURRENT schema.prisma) -------------
if ! bunx prisma db push --skip-generate >>"${LOG}" 2>&1; then
  echo "FATAL: prisma db push failed"; cat "${LOG}"; exit 1
fi

# --- boot the dev server -------------------------------------------------------
bunx next dev -p "${PORT}" >>"${LOG}" 2>&1 &
SERVER_PID=$!
trap 'kill "${SERVER_PID}" 2>/dev/null; pkill -f "next dev -p ${PORT}" 2>/dev/null' EXIT

READY=0
for i in $(seq 1 60); do
  sleep 1
  if curl -sf -m 2 "${URL}/api/bootstrap" >/dev/null 2>&1; then
    READY=1
    echo "integration server READY after ${i}s (pid ${SERVER_PID})"
    break
  fi
done
if [ "${READY}" != "1" ]; then
  echo "FATAL: integration server failed to start"; tail -30 "${LOG}"; exit 1
fi

# --- run the attached suite -----------------------------------------------------
INTEGRATION_SERVER_URL="${URL}" INTEGRATION_PORT="${PORT}" \
  bun test tests/api.integration.test.ts
RC=$?

echo "--- integration runner done (rc=${RC}) ---"
exit "${RC}"

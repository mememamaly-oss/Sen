#!/usr/bin/env bash
# QA-only launcher (mission 2026-10-23): production build on an ISOLATED
# fresh DB + dedicated port 3100. Never touches db/custom.db or :3000.
# Test-only NEXTAUTH_SECRET is generated per-run and never written to disk.
set -uo pipefail
cd /home/z/my-project

PORT="${QA_PORT:-3100}"
DB_DIR="qa-results"
DB="${DB_DIR}/qa-prod.db"
LOG="${DB_DIR}/qa-prod-server.log"
URL="http://127.0.0.1:${PORT}"

export DATABASE_URL="file:$(pwd)/${DB}"
export NEXTAUTH_SECRET="${NEXTAUTH_SECRET:-$(openssl rand -base64 32)}"
export BURHAN_DATA_DIR="/tmp/burhan-qa-data"
export PORT
export HOSTNAME=127.0.0.1

mkdir -p "${DB_DIR}" /tmp/burhan-qa-data

# fresh scratch DB
rm -f "${DB}" "${DB}-journal" "${DB}-wal" "${DB}-shm"

if ! bunx prisma db push --skip-generate >"${DB_DIR}/qa-prisma.log" 2>&1; then
  echo "FATAL: prisma db push failed"; cat "${DB_DIR}/qa-prisma.log"; exit 1
fi

pkill -f "PORT=3100" 2>/dev/null
bun .next/standalone/server.js >"${LOG}" 2>&1 &
SERVER_PID=$!
echo "server pid ${SERVER_PID}"

for i in $(seq 1 60); do
  sleep 1
  if curl -sf -m 3 "${URL}/api/bootstrap" >/dev/null 2>&1; then
    echo "PROD server READY after ${i}s on ${URL}"
    echo "${SERVER_PID}" > "${DB_DIR}/qa-prod.pid"
    exit 0
  fi
done
echo "FATAL: prod server failed to start"; tail -30 "${LOG}"
exit 1

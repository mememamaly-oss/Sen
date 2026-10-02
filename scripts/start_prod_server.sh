#!/usr/bin/env bash
# Phase 01: idempotent production server on :3000 (main demo DB).
set -euo pipefail
cd /home/z/my-project
if curl -sf -m 2 http://localhost:3000/api/bootstrap >/dev/null 2>&1; then
  echo "server already up on :3000"
  exit 0
fi
# ensure the managed demo target is reachable (self-healing happens on demand)
mkdir -p saas-data logs
setsid nohup bun .next/standalone/server.js >> logs/prod-server.log 2>&1 </dev/null &
disown || true
for i in $(seq 1 40); do
  sleep 1
  if curl -sf -m 3 http://localhost:3000/api/bootstrap >/dev/null 2>&1; then
    echo "prod server READY after ${i}s"
    exit 0
  fi
done
echo "prod server FAILED to start"; tail -20 logs/prod-server.log 2>/dev/null || true
exit 1

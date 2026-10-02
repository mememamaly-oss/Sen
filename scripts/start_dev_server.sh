#!/usr/bin/env bash
# R3-d: start the SaaS dev server fully detached (survives sandbox reaping).
set -euo pipefail
cd /home/z/my-project
if curl -sf -m 2 http://localhost:3000/api/bootstrap >/dev/null 2>&1; then
  echo "dev server already up"
  exit 0
fi
mkdir -p saas-data
setsid nohup bun run dev >/dev/null 2>&1 </dev/null &
disown || true
for i in $(seq 1 60); do
  sleep 2
  if curl -sf -m 3 http://localhost:3000/api/bootstrap >/dev/null 2>&1; then
    echo "dev server READY after $((i*2))s (pid $(cat /proc/net/tcp* >/dev/null; pgrep -f 'next dev' | head -1))"
    exit 0
  fi
done
echo "dev server FAILED to start"; tail -30 dev.log 2>/dev/null || true
exit 1

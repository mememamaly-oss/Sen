#!/bin/bash
# Launch DVWS (Damn Vulnerable Web Sockets) — web UI on 127.0.0.1:8888 + Ratchet WS server on 127.0.0.1:8080
# Authorized local training target. DB = userspace MariaDB on 127.0.0.1:5566 (host:port parsed natively by mysqli).
D=/home/z/my-project/gap-validation/targets/dvws
PHP=/home/z/my-project/gap-validation/tools/php-bulk-bin
L=/home/z/my-project/gap-validation/logs
mkdir -p $L
cd $D
export DB_HOST="127.0.0.1:5566"
export DB_USER="dvws"
export DB_PASSWORD="DVWS"
export DB_DATABASE="dvws"

# web frontend
if ! pgrep -f "php.*-S 127.0.0.1:8888" >/dev/null 2>&1; then
  setsid nohup $PHP -S 127.0.0.1:8888 > $L/dvws-web.log 2>&1 < /dev/null &
fi
# websocket server
if ! pgrep -f "ws-socket.php" >/dev/null 2>&1; then
  setsid nohup $PHP ws-socket.php --heartbeat-interval 30 > $L/dvws-ws.log 2>&1 < /dev/null &
fi
for i in $(seq 1 15); do
  sleep 1
  WEB=$(timeout 3 curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8888/ 2>/dev/null)
  WSP=$(pgrep -f "ws-socket.php" | head -1)
  if [ "$WEB" = "200" ] && [ -n "$WSP" ]; then
    echo "DVWS UP: web=http://127.0.0.1:8888 (after ${i}s), ws pid=$WSP listening :8080"
    exit 0
  fi
done
echo "DVWS FAILED"; echo "--- web log ---"; tail -5 $L/dvws-web.log; echo "--- ws log ---"; tail -10 $L/dvws-ws.log; exit 1

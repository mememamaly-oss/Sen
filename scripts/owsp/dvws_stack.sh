#!/bin/bash
# DVWS (Damn Vulnerable Web Sockets, interference-security/DVWS) stack —
# userspace, no root. Starts: MariaDB 11.4.5 bintar (127.0.0.1:5566, user
# dvws/DVWS, db dvws) + PHP 8.5.8 static bulk build-in-server
# (127.0.0.1:8888, 4 workers) + Ratchet WS server (ws-socket.php, 8080,
# 12 challenge channels).
# All-in-one single-call pattern: the environment reaps processes between
# tool calls — the caller must scan in the SAME call (dvws_campaign.sh).
# Usage: bash scripts/owsp/dvws_stack.sh [reset]
#   reset = re-GET setup.php (drop+recreate users/comments -> deterministic)
# Target fidelity note (same adaptation as the v4.1-era gap-validation run):
# the pages hardcode ws://dvws.local:8080 (the docker deployment maps that
# hostname in /etc/hosts; root is unavailable here) — the hostname is
# rewritten to 127.0.0.1 in the served pages. Channel paths unchanged.
set -u
TOOLS=/home/z/my-project/tools
MARIADB=$TOOLS/mariadb
DATADIR=$TOOLS/mariadb-data-dvws
SOCKDIR=$TOOLS/mariadb-sock-dvws
DVWS_SRC=/home/z/my-project/targets/dvws
PHP=$TOOLS/php/php
PORT_DB=5566
PORT_WEB=8888
PORT_WS=8080
RESET_DB="${1:-}"

DB() { "$MARIADB/bin/mariadb" --no-defaults --socket="$SOCKDIR/mariadb.sock" -u root "$@" 2>/dev/null; }

# 0) kill leftovers + free ports
pkill -9 -f "mariadbd.*$DATADIR" 2>/dev/null; pkill -9 -f "php.*-S 127.0.0.1:$PORT_WEB" 2>/dev/null; pkill -9 -f "ws-socket.php" 2>/dev/null
for i in $(seq 1 15); do
  if ss -tln 2>/dev/null | grep -qE ":($PORT_DB|$PORT_WEB|$PORT_WS) "; then sleep 1; else break; fi
done
ss -tln 2>/dev/null | grep -E ":($PORT_DB|$PORT_WEB|$PORT_WS) " && { echo "PORTS STILL BUSY"; exit 1; }

mkdir -p "$SOCKDIR" "$TOOLS/logs"

# 1) MariaDB userspace datadir (first boot; 11.4 bintar rejects --insecure —
#    passwordless root via --auth-root-authentication-method=normal instead)
if [ ! -d "$DATADIR/mysql" ]; then
  echo "[dvws-stack] initializing mariadb datadir..."
  "$MARIADB/scripts/mariadb-install-db" --no-defaults \
    --basedir="$MARIADB" --datadir="$DATADIR" --auth-root-authentication-method=normal \
    > "$TOOLS/logs/dvws-mariadb-install.log" 2>&1 || { echo "INSTALL_DB FAILED"; tail -5 "$TOOLS/logs/dvws-mariadb-install.log"; exit 1; }
fi
"$MARIADB/bin/mariadbd" --no-defaults \
  --basedir="$MARIADB" --datadir="$DATADIR" \
  --socket="$SOCKDIR/mariadb.sock" \
  --port=$PORT_DB --bind-address=127.0.0.1 --skip-networking=0 \
  --pid-file="$SOCKDIR/mariadb.pid" \
  --log-error="$TOOLS/logs/dvws-mariadb.err" \
  --innodb-buffer-pool-size=128M --max-connections=64 &
for i in $(seq 1 60); do
  "$MARIADB/bin/mariadb-admin" --no-defaults --socket="$SOCKDIR/mariadb.sock" -u root ping >/dev/null 2>&1 && break
  sleep 1
done
"$MARIADB/bin/mariadb-admin" --no-defaults --socket="$SOCKDIR/mariadb.sock" -u root ping 2>/dev/null || {
  echo "MARIADB FAILED TO START"; tail -20 "$TOOLS/logs/dvws-mariadb.err"; exit 1; }

# 2) dvws database + user (idempotent)
DB -e "
  CREATE DATABASE IF NOT EXISTS dvws CHARACTER SET latin1;
  CREATE USER IF NOT EXISTS 'dvws'@'127.0.0.1' IDENTIFIED BY 'DVWS';
  CREATE USER IF NOT EXISTS 'dvws'@'localhost' IDENTIFIED BY 'DVWS';
  GRANT ALL PRIVILEGES ON dvws.* TO 'dvws'@'127.0.0.1';
  GRANT ALL PRIVILEGES ON dvws.* TO 'dvws'@'localhost';
  FLUSH PRIVILEGES;" || { echo "DB PROVISION FAILED"; exit 1; }

# 3) target adaptation: ws://dvws.local -> ws://127.0.0.1 (no /etc/hosts edit possible)
if grep -q "dvws.local" "$DVWS_SRC"/*.php 2>/dev/null; then
  sed -i 's/dvws\.local/127.0.0.1/g' "$DVWS_SRC"/*.php
  echo "[dvws-stack] ws host adapted: dvws.local -> 127.0.0.1"
fi

# 4) PHP built-in web server (static bulk: mysqli/pcntl/sockets/soap/openssl present)
cd "$DVWS_SRC" || exit 1
export DB_HOST="127.0.0.1:$PORT_DB" DB_USER="dvws" DB_PASSWORD="DVWS" DB_DATABASE="dvws"
PHP_CLI_SERVER_WORKERS=4 \
  "$PHP" -d display_errors=1 -d error_reporting=E_ALL -d max_execution_time=60 \
  -S 127.0.0.1:$PORT_WEB > "$TOOLS/logs/dvws-web.log" 2>&1 &

# 5) Ratchet WebSocket server (12 challenge channels on :8080)
setsid "$PHP" ws-socket.php --heartbeat-interval 30 > "$TOOLS/logs/dvws-ws.log" 2>&1 < /dev/null &

# 6) wait + provision via the app's own setup.php (drops+recreates users/comments)
UP=0
for i in $(seq 1 25); do
  sleep 1
  WEB=$(timeout 3 curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT_WEB/index.php" 2>/dev/null)
  WSP=$(ss -tln 2>/dev/null | grep -c ":$PORT_WS ")
  if [ "$WEB" = "200" ] && [ "$WSP" -ge 1 ]; then UP=1; break; fi
done
[ "$UP" = "1" ] || { echo "DVWS STACK FAILED"; echo "--- web ---"; tail -5 "$TOOLS/logs/dvws-web.log"; echo "--- ws ---"; tail -10 "$TOOLS/logs/dvws-ws.log"; exit 1; }

SETUP_OUT=$(timeout 10 curl -s "http://127.0.0.1:$PORT_WEB/setup.php")
echo "$SETUP_OUT" | grep -q "Setup finished" && DB_OK=1 || DB_OK=0
USERS=$(DB -N -e "SELECT COUNT(*) FROM dvws.users;" 2>/dev/null || echo 0)
COMMENTS=$(DB -N -e "SELECT COUNT(*) FROM dvws.comments;" 2>/dev/null || echo 0)

# 7) WS smoke: one real handshake on the authenticate-user channel
WS_SMOKE=$(timeout 15 python3 - <<'PYEOF'
import socket, base64, os, struct
s = socket.create_connection(("127.0.0.1", 8080), timeout=6)
key = base64.b64encode(os.urandom(16)).decode()
s.sendall((f"GET /authenticate-user HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUpgrade: websocket\r\n"
           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nOrigin: http://127.0.0.1:8888\r\n\r\n").encode())
resp = s.recv(2048).decode("latin1", "replace")
print("HANDSHAKE_OK" if "101" in resp.split("\r\n")[0] and "Sec-WebSocket-Accept" in resp else "HANDSHAKE_FAIL")
# send an auth message and expect a JSON reply (proves the DB-backed channel answers)
import json
payload = json.dumps({"username": "admin", "password": "admin"}).encode()
mask = os.urandom(4)
hdr = bytearray([0x81])
n = len(payload)
if n < 126: hdr.append(0x80 | n)
else: hdr.append(0x80 | 126); hdr += struct.pack(">H", n)
s.sendall(bytes(hdr) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))
s.settimeout(6)
try:
    data = s.recv(4096)
    print("REPLY_LEN", len(data))
except Exception as e:
    print("NO_REPLY", e)
s.close()
PYEOF
)
echo "DVWS UP: web=127.0.0.1:$PORT_WEB ws=127.0.0.1:$PORT_WS db=127.0.0.1:$PORT_DB"
echo "setup.php: DB_OK=$DB_OK users=$USERS comments=$COMMENTS"
echo "ws-smoke: $(echo "$WS_SMOKE" | tr '\n' ' ')"
exit 0

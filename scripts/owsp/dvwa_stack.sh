#!/bin/bash
# DVWA stack — userspace, no root. Starts: MariaDB 11.4.5 (127.0.0.1:3307)
# + PHP 8.5.8 static bulk build-in-server (127.0.0.1:4280, 4 workers).
# All-in-one single-call pattern: caller must scan in the SAME call; stack
# dies with the tool call (environment reaps processes between calls —
# re-verified this session: setsid nohup sleep died).
# Usage: bash scripts/owsp/dvwa_stack.sh [reset]
#   reset = also POST setup.php (drop+recreate dvwa DB -> deterministic state)
set -u
TOOLS=/home/z/my-project/tools
MARIADB=$TOOLS/mariadb
DATADIR=$TOOLS/mariadb-data
SOCKDIR=$TOOLS/mariadb-sock
DVWA_SRC=/home/z/my-project/dvwa-src
PHP=$TOOLS/php/php
PORT_DB=3307
PORT_WEB=4280
RESET_DB="${1:-}"

# 0) kill leftovers + free ports (a dying mariadbd holds 3307 and kills the new one)
pkill -9 -f "mariadbd.*$DATADIR" 2>/dev/null; pkill -9 -f "php.*-S 127.0.0.1:$PORT_WEB" 2>/dev/null
for i in $(seq 1 20); do
  if ss -tln 2>/dev/null | grep -qE ":($PORT_DB|$PORT_WEB) "; then sleep 1; else break; fi
done
ss -tln 2>/dev/null | grep -E ":($PORT_DB|$PORT_WEB) " && { echo "PORTS STILL BUSY"; exit 1; }

mkdir -p "$SOCKDIR" "$TOOLS/logs"

# 1) MariaDB (userspace datadir already initialized by mariadb-install-db)
"$MARIADB/bin/mariadbd" --no-defaults \
  --basedir="$MARIADB" --datadir="$DATADIR" \
  --socket="$SOCKDIR/mariadb.sock" \
  --port=$PORT_DB --bind-address=127.0.0.1 --skip-networking=0 \
  --pid-file="$SOCKDIR/mariadb.pid" \
  --log-error="$TOOLS/logs/mariadb.err" \
  --innodb-buffer-pool-size=128M --max-connections=64 &
DB_PID=$!
# wait for readiness (max 60s)
for i in $(seq 1 60); do
  "$MARIADB/bin/mariadb-admin" --no-defaults --socket="$SOCKDIR/mariadb.sock" -u root ping >/dev/null 2>&1 && break
  sleep 1
done
"$MARIADB/bin/mariadb-admin" --no-defaults --socket="$SOCKDIR/mariadb.sock" -u root ping 2>/dev/null || {
  echo "MARIADB FAILED TO START"; tail -20 "$TOOLS/logs/mariadb.err"; exit 1; }

# 2) dvwa DB user (once; idempotent)
"$MARIADB/bin/mariadb" --no-defaults --socket="$SOCKDIR/mariadb.sock" -u root -e "
  CREATE USER IF NOT EXISTS 'dvwa'@'127.0.0.1' IDENTIFIED BY 'p@ssw0rd';
  CREATE USER IF NOT EXISTS 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';
  GRANT ALL PRIVILEGES ON *.* TO 'dvwa'@'127.0.0.1';
  GRANT ALL PRIVILEGES ON *.* TO 'dvwa'@'localhost';
  FLUSH PRIVILEGES;" || { echo "DVWA USER GRANT FAILED"; exit 1; }

# 3) config.inc.php (env-var driven: DB_PORT/DEFAULT_SECURITY_LEVEL set below)
[ -f "$DVWA_SRC/config/config.inc.php" ] || cp "$DVWA_SRC/config/config.inc.php.dist" "$DVWA_SRC/config/config.inc.php"

# 4) PHP built-in server (static bulk build: mysqli/pdo_mysql/gd/session present)
#    allow_url_include on (DVWA RFI lab requirement — DEPRECATED in PHP 8.5,
#    kept: still functional; if removed upstream the RFI lab dies honestly),
#    4 workers for concurrency.
cd "$DVWA_SRC" || exit 1
DB_PORT=$PORT_DB DEFAULT_SECURITY_LEVEL=low PHP_CLI_SERVER_WORKERS=4 \
  "$PHP" -d allow_url_include=1 -d allow_url_fopen=1 -d display_errors=1 \
  -d error_reporting=E_ALL -d upload_max_filesize=8M -d post_max_size=8M \
  -S 127.0.0.1:$PORT_WEB > "$TOOLS/logs/php-server.log" 2>&1 &
WEB_PID=$!
for i in $(seq 1 30); do
  curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT_WEB/login.php" && break
  sleep 1
done
curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT_WEB/login.php" || {
  echo "PHP SERVER FAILED"; tail -20 "$TOOLS/logs/php-server.log"; exit 1; }

# 4) DB provisioning: DVWA setup.php (create_db POST with session CSRF token)
#    - reset mode: ALWAYS drop+recreate (deterministic scan state)
#    - normal mode: only when the dvwa DB does not exist yet
HAVE_DB=$("$MARIADB/bin/mariadb" --no-defaults --socket="$SOCKDIR/mariadb.sock" -u root -N -e \
  "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='dvwa';" 2>/dev/null)
if [ "$RESET_DB" = "reset" ] || [ "${HAVE_DB:-0}" != "1" ]; then
  JAR=$TOOLS/logs/dvwa-setup.jar
  rm -f "$JAR"
  T=$(curl -s -c "$JAR" "http://127.0.0.1:$PORT_WEB/setup.php" | grep -oE "user_token' value='[a-f0-9]+'" | grep -oE '[a-f0-9]{32}' | head -1)
  [ -z "$T" ] && { echo "SETUP TOKEN PARSE FAILED"; exit 1; }
  curl -s -b "$JAR" -X POST --data-urlencode "create_db=Create / Reset Database" \
       --data-urlencode "user_token=$T" "http://127.0.0.1:$PORT_WEB/setup.php" -o "$TOOLS/logs/setup_out.html"
fi
USERS=$("$MARIADB/bin/mariadb" --no-defaults --socket="$SOCKDIR/mariadb.sock" -u root -N -e \
  "SELECT COUNT(*) FROM dvwa.users;" 2>/dev/null)
[ "${USERS:-0}" -ge 5 ] || { echo "DVWA DB PROVISION FAILED (users=$USERS)"; grep -oE "Database Error[^<]*" "$TOOLS/logs/setup_out.html" | head -3; exit 1; }

# 5) login smoke test (admin/password -> 302 off login.php, then index.php)
JAR2=$TOOLS/logs/dvwa-login.jar
rm -f "$JAR2"
T2=$(curl -s -c "$JAR2" "http://127.0.0.1:$PORT_WEB/login.php" | grep -oE "user_token' value='[a-f0-9]+'" | grep -oE '[a-f0-9]{32}' | head -1)
LOGIN_CODE=$(curl -s -b "$JAR2" -c "$JAR2" -o /dev/null -w "%{http_code} %{redirect_url}" \
  -X POST --data-urlencode "username=admin" --data-urlencode "password=password" \
  --data-urlencode "Login=Login" --data-urlencode "user_token=$T2" \
  "http://127.0.0.1:$PORT_WEB/login.php")
INDEX_TITLE=$(curl -s -b "$JAR2" "http://127.0.0.1:$PORT_WEB/index.php" | grep -oE "<title>[^<]*" | head -1)
echo "$LOGIN_CODE" | grep -q "302" && echo "$INDEX_TITLE" | grep -qi "vulnerable" && {
  echo "DVWA STACK READY db_pid=$DB_PID web_pid=$WEB_PID users=$USERS login=OK reset=$RESET_DB"
} || {
  echo "DVWA LOGIN SMOKE TEST FAILED: '$LOGIN_CODE' / '$INDEX_TITLE'"; exit 1; }

#!/bin/bash
# Mutillidae II 2.12.7 stack — userspace, no root. Starts: MariaDB 11.4.5
# (127.0.0.1:3306, root/mutillidae per src/includes/database-config.inc — kept
# pristine, so the DB runs on the standard port) + PHP 8.5.8 static bulk
# build-in-server (127.0.0.1:4290, 4 workers).
# All-in-one single-call pattern: caller must scan in the SAME call; stack
# dies with the tool call (environment reaps processes between calls).
# Usage: bash scripts/owsp/mutillidae_stack.sh [reset]
#   reset = also GET set-up-database.php (drop+recreate mutillidae DB -> deterministic state)
set -u
TOOLS=/home/z/my-project/tools
MARIADB=$TOOLS/mariadb
DATADIR=$TOOLS/mariadb-data
SOCKDIR=$TOOLS/mariadb-sock
MUTI_SRC=/home/z/my-project/mutillidae-src/src
PHP=$TOOLS/php/php
PORT_DB=3306
PORT_WEB=4290
RESET_DB="${1:-}"

MUTI_DB() { "$MARIADB/bin/mariadb" --no-defaults --socket="$SOCKDIR/mariadb.sock" -u root -pmutillidae "$@" 2>/dev/null; }

# 0) kill leftovers + free ports (a dying mariadbd holds the port and kills the new one)
pkill -9 -f "mariadbd.*$DATADIR" 2>/dev/null; pkill -9 -f "php.*-S 127.0.0.1:$PORT_WEB" 2>/dev/null
for i in $(seq 1 20); do
  if ss -tln 2>/dev/null | grep -qE ":($PORT_DB|$PORT_WEB) "; then sleep 1; else break; fi
done
ss -tln 2>/dev/null | grep -E ":($PORT_DB|$PORT_WEB) " && { echo "PORTS STILL BUSY"; exit 1; }

mkdir -p "$SOCKDIR" "$TOOLS/logs"

# 1) MariaDB (userspace datadir initialized by mariadb-install-db --insecure)
"$MARIADB/bin/mariadbd" --no-defaults \
  --basedir="$MARIADB" --datadir="$DATADIR" \
  --socket="$SOCKDIR/mariadb.sock" \
  --port=$PORT_DB --bind-address=127.0.0.1 --skip-networking=0 \
  --pid-file="$SOCKDIR/mariadb.pid" \
  --log-error="$TOOLS/logs/mariadb.err" \
  --innodb-buffer-pool-size=128M --max-connections=64 &
DB_PID=$!
for i in $(seq 1 60); do
  "$MARIADB/bin/mariadb-admin" --no-defaults --socket="$SOCKDIR/mariadb.sock" -u root ping >/dev/null 2>&1 && break
  sleep 1
done
"$MARIADB/bin/mariadb-admin" --no-defaults --socket="$SOCKDIR/mariadb.sock" -u root ping 2>/dev/null || {
  echo "MARIADB FAILED TO START"; tail -20 "$TOOLS/logs/mariadb.err"; exit 1; }

# 2) root password = 'mutillidae' for BOTH socket-localhost and TCP-127.0.0.1
#    (idempotent; matches src/includes/database-config.inc kept pristine).
#    First-ever boot: socket root is passwordless; later boots: already passworded.
if "$MARIADB/bin/mariadb" --no-defaults --socket="$SOCKDIR/mariadb.sock" -u root -e "SELECT 1;" >/dev/null 2>&1; then
  DB_ROOT=("-u" "root")
else
  DB_ROOT=("-u" "root" "-pmutillidae")
fi
"$MARIADB/bin/mariadb" --no-defaults --socket="$SOCKDIR/mariadb.sock" "${DB_ROOT[@]}" -e "
  CREATE USER IF NOT EXISTS 'root'@'127.0.0.1' IDENTIFIED BY 'mutillidae';
  GRANT ALL PRIVILEGES ON *.* TO 'root'@'127.0.0.1' WITH GRANT OPTION;
  ALTER USER 'root'@'localhost' IDENTIFIED BY 'mutillidae';
  FLUSH PRIVILEGES;" || { echo "ROOT PASSWORD SETUP FAILED"; exit 1; }

# 3) PHP built-in server (static bulk build: mysqli/pdo_mysql/gd/session present).
#    allow_url_include for the RFI labs (deprecated in 8.5 but functional),
#    display_errors=1 — the labs themselves print SQL fatals inside HTTP 200.
cd "$MUTI_SRC" || exit 1
PHP_CLI_SERVER_WORKERS=6 \
  "$PHP" -d allow_url_include=1 -d allow_url_fopen=1 -d display_errors=1 \
  -d error_reporting=E_ALL -d upload_max_filesize=8M -d post_max_size=8M \
  -d session.use_strict_mode=0 -d max_execution_time=60 \
  -S 127.0.0.1:$PORT_WEB > "$TOOLS/logs/php-server.log" 2>&1 &
WEB_PID=$!
for i in $(seq 1 30); do
  curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT_WEB/index.php" && break
  sleep 1
done
curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT_WEB/index.php" || {
  echo "PHP SERVER FAILED"; tail -20 "$TOOLS/logs/php-server.log"; exit 1; }

# 4) DB provisioning: GET set-up-database.php executes DROP/CREATE + schema + seed
#    (runs automatically on page load; no CSRF token on this page)
#    - reset mode: ALWAYS (deterministic scan state)
#    - normal mode: only when the mutillidae DB has no accounts table yet
HAVE_ACCTS=$(MUTI_DB -N -e \
  "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='mutillidae' AND TABLE_NAME='accounts';")
if [ "$RESET_DB" = "reset" ] || [ "${HAVE_ACCTS:-0}" != "1" ]; then
  curl -s --max-time 90 "http://127.0.0.1:$PORT_WEB/set-up-database.php" -o "$TOOLS/logs/muti_setup.html"
fi
USERS=$(MUTI_DB -N -e "SELECT COUNT(*) FROM mutillidae.accounts;")
[ "${USERS:-0}" -ge 3 ] || { echo "MUTILLIDAE DB PROVISION FAILED (users=$USERS)"; grep -oE "database-failure-message[^<]*" "$TOOLS/logs/muti_setup.html" | head -3; tail -5 "$TOOLS/logs/php-server.log"; exit 1; }

# 5) login smoke test (admin/adminpass -> session shows account-profile links in header)
#    canonical form action: index.php?page=login.php (hidden redirectPage field, no CSRF at level 0)
JAR=$TOOLS/logs/muti-login.jar
rm -f "$JAR"
curl -s -c "$JAR" -o /dev/null "http://127.0.0.1:$PORT_WEB/index.php?page=login.php"
LOGIN_BODY=$(curl -s -b "$JAR" -c "$JAR" -L --max-time 15 \
  --data-urlencode "username=admin" --data-urlencode "password=adminpass" \
  --data-urlencode "login-php-submit-button=Login" \
  --data-urlencode "redirectPage=" \
  "http://127.0.0.1:$PORT_WEB/index.php?page=login.php" 2>/dev/null)
echo "$LOGIN_BODY" | grep -q "view-account-profile.php" && {
  echo "MUTILLIDAE STACK READY db_pid=$DB_PID web_pid=$WEB_PID users=$USERS login=OK reset=$RESET_DB"
} || {
  echo "MUTILLIDAE LOGIN SMOKE TEST FAILED (no view-account-profile link)"; echo "$LOGIN_BODY" | head -5; exit 1; }

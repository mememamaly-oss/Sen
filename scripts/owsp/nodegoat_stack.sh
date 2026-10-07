#!/bin/bash
# NodeGoat 1.3.0 stack — userspace, no root.
# MongoDB 4.4.29 (ubuntu2004 bintar; needs OpenSSL 1.1 -> userspace libssl1.1 via
# LD_LIBRARY_PATH, from Debian bullseye .deb extracted to tools/ssl11) on
# 127.0.0.1:27017 (standard port — config/env/all.js default), plus
# `node server.js` on 127.0.0.1:4000 (PORT default), DB seeded via
# artifacts/db-reset.js (users admin/Admin_123, user1/User1_123, user2/User2_123
# — PLAINTEXT passwords by design; allocations/benefits/memos/contributions seeded).
# UV_THREADPOOL_SIZE=16: the /research route needle.get()s attacker-controlled
# hostnames; the sandbox DNS sinkhole (garbage -> 0.0.0.1 blackhole) stalls
# getaddrinfo in the libuv threadpool (default 4) and can freeze the whole app.
# Idempotent: reuses a healthy mongod/server, reseeds only on `reset` or empty DB.
# All-in-one single-call pattern for scans (environment reaper) — but mongod/node
# are setsid-detached so they MAY survive call boundaries; callers re-run this
# script to be sure. Usage: bash scripts/owsp/nodegoat_stack.sh [reset]
set -u
TOOLS=/home/z/my-project/tools
MONGO=$TOOLS/mongo44
DATADIR=$TOOLS/mongo44-data
SSL11=$TOOLS/ssl11/usr/lib/x86_64-linux-gnu
SRC=$TOOLS/dl/nodegoat-src
PORT_DB=27017
PORT_WEB=4000
RESET="${1:-}"
LOGD=$TOOLS/logs

export LD_LIBRARY_PATH=$SSL11
MG() { "$MONGO/bin/mongo" --quiet --host 127.0.0.1 --port $PORT_DB "$@"; }

# 0) port check helpers
port_busy() { ss -tln 2>/dev/null | grep -qE ":$1 "; }

# 1) MongoDB: reuse if pingable, else (re)start
#    bind BOTH 127.0.0.1 and ::1: Node>=17 resolves 'localhost' to ::1 first and
#    the mongo driver would hit ECONNREFUSED on an IPv4-only bind.
if MG --eval "db.runCommand({ping:1}).ok" 2>/dev/null | grep -qx 1; then
    echo "mongod: already up"
else
    pkill -9 -f "mongod.*mongo44-data" 2>/dev/null
    for i in $(seq 1 15); do port_busy $PORT_DB || break; sleep 1; done
    mkdir -p "$DATADIR" "$LOGD"
    setsid nohup "$MONGO/bin/mongod" --dbpath "$DATADIR" --port $PORT_DB \
        --bind_ip 127.0.0.1,::1 --logpath "$LOGD/mongod.log" --wiredTigerCacheSizeGB 0.25 \
        > "$LOGD/mongod.boot.log" 2>&1 < /dev/null &
    for i in $(seq 1 60); do
        MG --eval "db.runCommand({ping:1}).ok" 2>/dev/null | grep -qx 1 && break
        sleep 1
    done
    MG --eval "db.runCommand({ping:1}).ok" 2>/dev/null | grep -qx 1 \
        || { echo "MONGOD FAILED"; tail -20 "$LOGD/mongod.log"; exit 1; }
    echo "mongod: started"
fi

# 2) Seed: reset -> always; otherwise only if users collection empty
#    MONGODB_URI=127.0.0.1 explicit (IPv6-localhost issue, see above)
SEED_NEEDED=0
N=$(MG --eval "db.getSiblingDB("nodegoat").users.count()" 2>/dev/null | tr -dc '0-9')
[ "$RESET" = "reset" ] && SEED_NEEDED=1
{ [ -z "${N:-}" ] || [ "$N" -eq 0 ]; } 2>/dev/null && SEED_NEEDED=1
if [ "$SEED_NEEDED" = "1" ]; then
    (cd "$SRC" && MONGODB_URI="mongodb://127.0.0.1:$PORT_DB/nodegoat" node artifacts/db-reset.js > "$LOGD/nodegoat-seed.log" 2>&1)
    N=$(MG --eval "db.getSiblingDB("nodegoat").users.count()" 2>/dev/null | tr -dc '0-9')
    [ -n "${N:-}" ] && [ "$N" -ge 3 ] 2>/dev/null && echo "seed: $N users" || {
        echo "SEED FAILED"; tail -20 "$LOGD/nodegoat-seed.log"; exit 1; }
else
    echo "seed: skipped ($N users present)"
fi

# 3) Node server: reuse if /login answers, else (re)start
if curl -s -o /dev/null -w "%{http_code}" --max-time 4 "http://127.0.0.1:$PORT_WEB/login" 2>/dev/null | grep -q 200; then
    echo "server: already up"
else
    pkill -9 -f "node server.js" 2>/dev/null
    for i in $(seq 1 15); do port_busy $PORT_WEB || break; sleep 1; done
    (cd "$SRC" && PORT=$PORT_WEB UV_THREADPOOL_SIZE=16 MONGODB_URI="mongodb://127.0.0.1:$PORT_DB/nodegoat" \
        setsid nohup node server.js > "$LOGD/nodegoat.log" 2>&1 < /dev/null &)
    for i in $(seq 1 40); do
        curl -s -o /dev/null -w "%{http_code}" --max-time 4 "http://127.0.0.1:$PORT_WEB/login" 2>/dev/null | grep -q 200 && break
        sleep 1
    done
    curl -s -o /dev/null -w "%{http_code}" --max-time 4 "http://127.0.0.1:$PORT_WEB/login" 2>/dev/null | grep -q 200 \
        || { echo "SERVER FAILED"; tail -20 "$LOGD/nodegoat.log"; exit 1; }
    echo "server: started"
fi

# 4) Smoke: login as admin + hit the two key authenticated surfaces
J=$(mktemp)
CODE=$(curl -s -o /dev/null -w "%{http_code}" -c "$J" -d "userName=admin&password=Admin_123" "http://127.0.0.1:$PORT_WEB/login")
B=$(curl -s -b "$J" -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT_WEB/benefits")
A=$(curl -s -b "$J" -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT_WEB/allocations")
R=$(curl -s -b "$J" -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT_WEB/research")
rm -f "$J"
echo "smoke: login=$CODE benefits=$B allocations=$A research=$R"
[ "$CODE" = "302" ] || [ "$CODE" = "200" ] || { echo "SMOKE FAIL (login)"; exit 1; }
echo "STACK_READY"

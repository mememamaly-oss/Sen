#!/bin/bash
# SENTINEL live-target lifecycle — WebGoat 8.2.2 (:8080/WebGoat) + WebWolf 8.2.2 (:9090/WebWolf)
# The sandbox reaps every process at the END of each tool call, so each phase
# must launch + work + let-die inside ONE call. This script is phase step 1.
LT=/home/z/my-project/live-targets

kill_stale() {
  pkill -f "webgoat-server-8.2.2.jar" 2>/dev/null
  pkill -f "webwolf-8.2.2.jar" 2>/dev/null
  sleep 1
}

wait_http() { # $1 url  $2 max_seconds  $3 label
  local url="$1" max="$2" label="$3" el=0 c=000
  while [ "$el" -lt "$max" ]; do
    c=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$url" 2>/dev/null)
    if [ "$c" = "200" ] || [ "$c" = "302" ]; then echo "$label UP (http $c after ~${el}s)"; return 0; fi
    sleep 2; el=$((el+2))
  done
  echo "$label FAILED after ${max}s (last http=$c)"; return 1
}

case "$1" in
  up)
    kill_stale
    cd "$LT" || exit 1
    setsid nohup java -jar "$LT/webgoat-server-8.2.2.jar" --server.address=127.0.0.1 --server.port=8080 \
      > "$LT/webgoat.log" 2>&1 < /dev/null &
    echo "webgoat pid $!"
    for i in $(seq 1 75); do grep -q "Started StartWebGoat" "$LT/webgoat.log" 2>/dev/null && break; sleep 2; done
    grep -q "Started StartWebGoat" "$LT/webgoat.log" 2>/dev/null || { echo "webgoat boot FAILED"; tail -8 "$LT/webgoat.log"; exit 1; }
    wait_http "http://127.0.0.1:8080/WebGoat/" 40 webgoat || exit 1
    setsid nohup java -jar "$LT/webwolf-8.2.2.jar" --server.address=127.0.0.1 --server.port=9090 \
      --server.servlet.context-path=/WebWolf > "$LT/webwolf.log" 2>&1 < /dev/null &
    echo "webwolf pid $!"
    # WebWolf readiness: any structured Spring response (200/302/405) from /landing
    # proves Undertow+dispatch+DB are all up (405 = routed, POST-only endpoint).
    el=0; ok=""
    while [ $el -lt 50 ]; do
      c=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "http://127.0.0.1:9090/WebWolf/landing" 2>/dev/null)
      case "$c" in 200|302|405) ok=$c; break;; esac
      sleep 2; el=$((el+2))
    done
    if [ -n "$ok" ]; then echo "webwolf UP (http $ok after ~${el}s)"; else echo "webwolf boot FAILED"; tail -8 "$LT/webwolf.log"; exit 1; fi
    echo "READY"
    ;;
  down) kill_stale; echo "DOWN" ;;
  status)
    for u in "http://127.0.0.1:8080/WebGoat/" "http://127.0.0.1:9090/WebWolf/"; do
      echo "$u -> $(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$u" 2>/dev/null)"
    done ;;
  *) echo "usage: srv.sh up|down|status" ;;
esac

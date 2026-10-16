#!/bin/bash
# Unstick hung Mutillidae php workers (SYN-SENT to blackholed DNS for >2 min).
# Safe: workers are stateless request handlers; the scanner sees one RST per
# killed request (its timeout logic already handles far worse). Master (4734)
# does NOT respawn killed workers — bounded loss, 7 -> N.
echo "=== unstick $(date +%H:%M:%S) ==="
HUNG=$(ss -tnp state syn-sent 2>/dev/null | grep -o "pid=[0-9]*" | cut -d= -f2 | sort -u)
for pid in $HUNG; do
  # only php workers, never the scanner/browser/mariadb
  if grep -q "php" /proc/$pid/cmdline 2>/dev/null; then
    echo "killing hung php worker $pid"
    kill -9 "$pid" 2>/dev/null
  else
    echo "skipping non-php pid $pid ($(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | cut -c1-50))"
  fi
done
A=$(grep -c Accepted /home/z/my-project/tools/logs/php-server.log)
sleep 45
B=$(grep -c Accepted /home/z/my-project/tools/logs/php-server.log)
echo "rate now: $(( (B-A)*60/45 )) req/min (total $B, workers $(ps -ef | grep -c '[p]hp.*-S 127.0.0.1:4290'))"
M=/home/z/my-project/build-v425/results/owsp/mutillidae
[ -f "$M/recon3.DONE" ] && cat "$M/recon3.DONE" || echo "scan still running: $(ps -p 6628 -o etime= 2>/dev/null | tr -d ' ')"

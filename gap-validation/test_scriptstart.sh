#!/bin/bash
# Test: start processes via script file (like start_dvga.sh) — do they survive?
T=/home/z/my-project/gap-validation/tools
L=/home/z/my-project/gap-validation/logs
# PHP server on 9998
setsid nohup $T/php-bulk-bin -S 127.0.0.1:9998 -t $T/httptest > $L/php-test2.log 2>&1 < /dev/null &
# mariadbd on 5566 (renamed binary not needed; plain)
P=$T/mariadb
export LD_LIBRARY_PATH=$P/usr/lib/x86_64-linux-gnu
kill $(cat $P/run/mariadbd.pid 2>/dev/null) 2>/dev/null; sleep 1
setsid nohup $P/sbin/mariadbd --no-defaults --datadir=$P/data --socket=$P/run/custom.sock --port=5566 --bind-address=127.0.0.1 --pid-file=$P/run/mariadbd.pid --user=z --skip-name-resolve --innodb-buffer-pool-size=64M --performance-schema=OFF > $P/run/mariadbd.log 2>&1 < /dev/null &
sleep 3
echo "php9998: $(pgrep -f 'php-bulk-bin -S 127.0.0.1:9998' | head -1)"
echo "mariadbd: $(pgrep -x mariadbd | head -1)"

#!/bin/bash
# Start userspace MariaDB for DVWS (detached with setsid so it survives tool-call sessions)
P=/home/z/my-project/gap-validation/tools/mariadb
export LD_LIBRARY_PATH=$P/usr/lib/x86_64-linux-gnu
if pgrep -x mariadbd >/dev/null; then echo "mariadbd already running"; exit 0; fi
rm -f $P/run/mysqld.sock
setsid nohup $P/sbin/mariadbd --no-defaults \
  --datadir=$P/data --socket=$P/run/mysqld.sock --port=13306 --bind-address=127.0.0.1 \
  --pid-file=$P/run/mariadbd.pid --user=z --skip-name-resolve \
  > $P/run/mariadbd.log 2>&1 < /dev/null &
for i in $(seq 1 20); do
  sleep 1
  if $P/bin/mariadb --no-defaults --socket=$P/run/mysqld.sock -u root -e "SELECT 1;" >/dev/null 2>&1; then
    echo "MariaDB UP on port 13306 (socket $P/run/mysqld.sock) after ${i}s"
    exit 0
  fi
done
echo "FAILED to start MariaDB"; tail -5 $P/run/mariadbd.log; exit 1

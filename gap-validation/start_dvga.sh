#!/bin/bash
# Launch DVGA (Damn Vulnerable GraphQL Application) — Python/Flask/graphene
# isolated local instance on 127.0.0.1:5013 (authorized training target)
D=/home/z/my-project/gap-validation/targets/dvga
V=/home/z/my-project/gap-validation/dvga-venv
L=/home/z/my-project/gap-validation/logs
mkdir -p $L
cd $D
export PATH=$V/bin:$PATH
if pgrep -f "python3 app.py" >/dev/null 2>&1; then echo "DVGA already running"; exit 0; fi
# fresh DB each launch (matches Docker behavior)
rm -f $D/dvga.db
setsid nohup $V/bin/python3 app.py > $L/dvga.log 2>&1 < /dev/null &
for i in $(seq 1 30); do
  sleep 1
  if timeout 3 curl -s -o /dev/null http://127.0.0.1:5013/ ; then
    echo "DVGA UP after ${i}s on http://127.0.0.1:5013"
    tail -3 $L/dvga.log
    exit 0
  fi
done
echo "DVGA FAILED"; tail -20 $L/dvga.log; exit 1

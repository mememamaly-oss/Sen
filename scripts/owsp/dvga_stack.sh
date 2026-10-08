#!/bin/bash
# DVGA (Damn Vulnerable GraphQL Application) stack — userspace venv launch.
# App on 127.0.0.1:5013 (authorized training target), SQLite backend, fresh
# DB each boot (matches the Docker behavior). All-in-one single-call pattern
# (environment reaps processes between calls — the caller scans in the SAME
# call via dvga_campaign.sh).
set -u
V=/home/z/my-project/gap-validation/dvga-venv
D=/home/z/my-project/targets/dvga
L=/home/z/my-project/tools/logs
mkdir -p "$L"

pkill -9 -f "python3 app.py" 2>/dev/null
for i in $(seq 1 10); do
  ss -tln 2>/dev/null | grep -q ":5013 " || break; sleep 1
done
ss -tln 2>/dev/null | grep ":5013 " && { echo "PORT 5013 BUSY"; exit 1; }

cd "$D" || exit 1
rm -f "$D/dvga.db"                      # fresh DB each launch (Docker parity)
# DB provisioning: setup.py (clean + create_all + seed admin/operator + 11
# pastes) runs through the VENV python — app.py's initialize() shells out to
# a bare `python3` from PATH which lacks SQLAlchemy in this userspace env
export PATH="$V/bin:$PATH"
"$V/bin/python3" setup.py > "$L/dvga-setup.log" 2>&1 || { echo "SETUP FAILED"; tail -8 "$L/dvga-setup.log"; exit 1; }
setsid nohup "$V/bin/python3" app.py > "$L/dvga.log" 2>&1 < /dev/null &
UP=0
for i in $(seq 1 30); do
  sleep 1
  code=$(timeout 3 curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5013/ 2>/dev/null)
  [ "$code" = "200" ] && { UP=1; break; }
done
[ "$UP" = "1" ] || { echo "DVGA FAILED"; tail -15 "$L/dvga.log"; exit 1; }
echo "DVGA UP on http://127.0.0.1:5013 (after ${i}s)"

# graphql smoke: anonymous read of the public paste surface
SMOKE=$(timeout 10 curl -s -X POST http://127.0.0.1:5013/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ pastes { id title public } }"}' | head -c 200)
echo "graphql smoke: ${SMOKE:0:160}"

# campaign identities + fresh JWTs + private marker pastes
timeout 60 python3 /home/z/my-project/scripts/owsp/dvga_identities.py || exit 1
exit 0

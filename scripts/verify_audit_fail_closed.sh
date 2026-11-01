#!/usr/bin/env bash
# AUDIT FAIL-CLOSED PROOF (owner order 2026-10-31, item 1.3).
#
# RED class: src/lib/rbac.ts audit() swallowed write failures — a privileged
# action whose evidence could not be written STILL COMPLETED. Proof method:
# a REAL failure injection (not a mock): the app DB identity loses INSERT
# on AuditLog, then the first-instance bootstrap (admin + org + OWNER
# membership + audit row) runs through the REAL app over HTTP.
#
#   RED : bootstrap returns 200, users persisted, ZERO audit rows
#         (privileged action completed un-audited — fail-open)
#   BLUE: no un-audited persisted state (the action is rejected and/or the
#         audit row exists; HTTP >= 500 with users=0 is the fixed shape)
#
# Self-contained: provisions its own throwaway database (burhan_auditfc),
# migrates, provisions burhan_app, injects the failure, boots the app,
# probes, reports. Exit 0 = blue, 2 = red, 1 = infrastructure error.
set -uo pipefail
cd "$(dirname "$0")/.."

PORT="${AUDITFC_PORT:-3199}"
DBNAME="burhan_auditfc"
LOG="tests/auditfc-server.log"
URL="http://127.0.0.1:${PORT}"

OWNER_URL="${MIGRATION_DATABASE_URL:-${DATABASE_URL:-}}"
case "$OWNER_URL" in
  postgresql://*|postgres://*) : ;;
  *) OWNER_URL="$(bash scripts/pg_dev_start.sh)" ;;
esac
APP_PW="${BURHAN_APP_DB_PASSWORD:-local-dev-app-role-password}"
APP_USER="${BURHAN_APP_DB_USER:-burhan_app}"

PSQL_BIN="$(command -v psql || true)"
if [ -z "$PSQL_BIN" ]; then
  PGBIN="$(python3 -c 'import pgserver,os,sys; sys.stdout.write(os.path.dirname(pgserver.__file__)+"/pginstall/bin")' 2>/dev/null || true)"
  [ -x "$PGBIN/psql" ] && PSQL_BIN="$PGBIN/psql"
fi
[ -n "$PSQL_BIN" ] || { echo "FATAL: psql not available"; exit 1; }

# --- fresh throwaway database --------------------------------------------------
MAINT_URL="$(echo "$OWNER_URL" | sed -E 's#/[^/?]+$#/"postgres"#')"
MAINT_URL="$(echo "$MAINT_URL" | sed 's#/"postgres"#/postgres#')"
AUDITFC_OWNER_URL="${OWNER_URL%/*}/$DBNAME"
rm -f "$LOG"
"$PSQL_BIN" "$MAINT_URL" -v ON_ERROR_STOP=1 \
  -c "DROP DATABASE IF EXISTS $DBNAME;" -c "CREATE DATABASE $DBNAME;" >/dev/null \
  || { echo "FATAL: could not create $DBNAME"; exit 1; }

# --- schema (owner) + limited app role ------------------------------------------
if ! DATABASE_URL="$AUDITFC_OWNER_URL" bunx prisma migrate deploy >>"$LOG" 2>&1; then
  echo "FATAL: migrate deploy failed"; tail -20 "$LOG"; exit 1
fi
APP_URL="$(MIGRATION_DATABASE_URL="$AUDITFC_OWNER_URL" BURHAN_APP_DB_PASSWORD="$APP_PW" \
  bash scripts/db_app_role.sh)" || { echo "FATAL: db_app_role.sh failed"; exit 1; }

# --- THE INJECTED FAILURE: the app identity cannot write audit rows -------------
"$PSQL_BIN" "$AUDITFC_OWNER_URL" -v ON_ERROR_STOP=1 \
  -c "REVOKE INSERT ON \"AuditLog\" FROM $APP_USER;" >/dev/null \
  || { echo "FATAL: could not revoke AuditLog INSERT"; exit 1; }

# --- boot the REAL app as the (now audit-mute) app identity ----------------------
pkill -f "next dev -p ${PORT}" 2>/dev/null && sleep 1
DATABASE_URL="$APP_URL" NEXTAUTH_SECRET=auditfc-test-secret \
  BURHAN_DATA_DIR=/tmp/burhan-auditfc \
  bunx next dev -p "$PORT" >>"$LOG" 2>&1 &
SERVER_PID=$!
trap 'kill "${SERVER_PID}" 2>/dev/null; pkill -f "next dev -p ${PORT}" 2>/dev/null' EXIT

READY=0
for i in $(seq 1 60); do
  sleep 1
  if curl -sf -m 2 "${URL}/api/bootstrap" >/dev/null 2>&1; then READY=1; echo "probe server READY (${i}s)"; break; fi
done
[ "$READY" = "1" ] || { echo "FATAL: probe server failed to start"; tail -30 "$LOG"; exit 1; }

# --- the privileged action over HTTP ---------------------------------------------
HTTP_CODE="$(curl -s -o /tmp/auditfc-resp.json -w '%{http_code}' -m 60 -X POST "${URL}/api/bootstrap" \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@auditfc.test","password":"Auditfc-Passw0rd!","name":"Audit FC","orgName":"Audit FC Org"}')"

# --- ground truth from the database (owner view) ----------------------------------
Q() { "$PSQL_BIN" "$AUDITFC_OWNER_URL" -tAc "$1" | tr -d '[:space:]'; }
USERS="$(Q 'SELECT count(*) FROM "User"')"
ORGS="$(Q 'SELECT count(*) FROM "Organization"')"
AUDIT_ROWS="$(Q "SELECT count(*) FROM \"AuditLog\" WHERE action = 'bootstrap.admin_created'")"

echo "PROBE http=$HTTP_CODE users=$USERS orgs=$ORGS audit_rows=$AUDIT_ROWS"
if [ "$USERS" -gt 0 ] && [ "$AUDIT_ROWS" = "0" ]; then
  echo "RED: the privileged action PERSISTED with ZERO audit evidence (fail-open)"
  exit 2
fi
echo "BLUE: no un-audited persisted privileged state (fail-closed)"
exit 0

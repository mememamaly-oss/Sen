#!/usr/bin/env bash
# P2-D (2026-10-31) — local PostgreSQL dev cluster manager.
#
# The platform DB is PostgreSQL now (prisma/schema.prisma). For local
# development this script manages an unprivileged cluster under
# saas-data/pg-dev (gitignored) initialized by the `pgserver` wheel (no root,
# no docker needed). The cluster listens on TCP 127.0.0.1:55432 because
# Prisma 6 rejects unix-socket-only connection strings.
#
# The dev sandbox reaps background processes between commands, so this script
# is IDEMPOTENT: it (re)starts the postmaster if it is not accepting
# connections, waits until it is, ensures the `burhan` database exists, and
# prints the connection URI on stdout. It is safe to call at the top of every
# chain that needs the database.
#
#   --reset   drop and recreate the `burhan` database first (fresh state,
#             e.g. before an integration run) — local/dev only.
#
# CI does NOT use this script: the GitHub workflow provisions a real
# postgres service container and exports DATABASE_URL itself.
set -uo pipefail
cd "$(dirname "$0")/.."

BIN="$(python3 -c 'import pgserver,os,sys; sys.stdout.write(os.path.dirname(pgserver.__file__)+"/pginstall/bin")')"
D="saas-data/pg-dev"
PGDIR="$(pwd)/$D"
URI="postgresql://postgres@127.0.0.1:55432/burhan"
RESET=0
[ "${1:-}" = "--reset" ] && RESET=1

if [ ! -f "$D/PG_VERSION" ]; then
  # first run on this machine: pgserver initdb (+ first boot, socket mode)
  python3 - <<'PY' || exit 1
import pgserver
pgserver.get_server("saas-data/pg-dev")
PY
fi

# TCP must be enabled (pgserver boots socket-only); loopback must be in hba.
grep -q "^port = 55432" "$D/postgresql.conf" || cat >> "$D/postgresql.conf" <<'CONF'

# P2-D: TCP for Prisma (unix-socket-only URIs are rejected by prisma 6)
listen_addresses = '127.0.0.1'
port = 55432
CONF
grep -q "^host all all 127.0.0.1/32" "$D/pg_hba.conf" || echo "host all all 127.0.0.1/32 trust" >> "$D/pg_hba.conf"

if ! "$BIN/pg_isready" -q -h 127.0.0.1 -p 55432 2>/dev/null; then
  "$BIN/pg_ctl" -D "$PGDIR" stop -m fast >/dev/null 2>&1 || true
  setsid "$BIN/postgres" -D "$PGDIR" </dev/null >>"$D/postgresql.log" 2>&1 &
  for _ in $(seq 1 60); do
    sleep 0.25
    "$BIN/pg_isready" -q -h 127.0.0.1 -p 55432 2>/dev/null && break
  done
fi
"$BIN/pg_isready" -q -h 127.0.0.1 -p 55432 2>/dev/null || {
  echo "FATAL: postgres did not become ready on 127.0.0.1:55432" >&2
  tail -5 "$D/postgresql.log" >&2
  exit 1
}

if [ "$RESET" = "1" ]; then
  "$BIN/psql" "postgresql://postgres@127.0.0.1:55432/postgres" -c "DROP DATABASE IF EXISTS burhan" >/dev/null
fi
"$BIN/psql" "postgresql://postgres@127.0.0.1:55432/postgres" -tAc \
  "SELECT 1 FROM pg_database WHERE datname='burhan'" | grep -q 1 || \
  "$BIN/psql" "postgresql://postgres@127.0.0.1:55432/postgres" -c "CREATE DATABASE burhan" >/dev/null

echo "$URI"

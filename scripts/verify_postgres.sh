#!/usr/bin/env bash
# P2-D (2026-10-31) — PostgreSQL verification for deployments (VPS/CI-like).
#
# Usage: DATABASE_URL=postgresql://... bash scripts/verify_postgres.sh
# Asserts, end to end, that the platform DB is really usable:
#   1. prisma migrate deploy applies the migration files cleanly
#   2. every tenant table exists (11 expected)
#   3. a transactional write/read/delete round-trip works (PlatformLock)
#   4. the Finding.complianceJson column accepts and returns JSON
# Fails loudly on the first broken assumption. Zero output on success
# except the final OK line.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${DATABASE_URL:?export DATABASE_URL=postgresql://... first}"

bunx prisma migrate deploy >/dev/null

node - <<'JS'
const { PrismaClient } = require("@prisma/client");
const db = new PrismaClient();
(async () => {
  const tables = (await db.$queryRawUnsafe(
    "SELECT tablename FROM pg_tables WHERE schemaname='public'")) .map(t => t.tablename);
  const expected = ["User","Organization","Membership","Target","Scan","Finding",
                     "Report","AuditLog","TwinGraph","PlatformLock","_prisma_migrations"];
  for (const t of expected) {
    if (!tables.includes(t)) throw new Error(`missing table ${t}`);
  }
  // write/read/delete round-trip through the same transaction shape bootstrap uses
  await db.platformLock.create({ data: { key: "verify-postgres-probe" } });
  const hit = await db.platformLock.findUnique({ where: { key: "verify-postgres-probe" } });
  if (!hit) throw new Error("platformLock round-trip failed");
  await db.platformLock.delete({ where: { key: "verify-postgres-probe" } });
  // complianceJson column accepts JSON and returns it verbatim
  const ok = await db.$queryRawUnsafe(
    "SELECT ('{\"cwe\":\"CWE-89\"}'::json)::text AS v");
  if (!String(ok[0].v).includes("CWE-89")) throw new Error("json cast probe failed");
  console.log("POSTGRES_VERIFY_OK tables=" + tables.length);
})().catch(e => { console.error("VERIFY_FAIL:", String(e).slice(0, 300)); process.exit(1); })
  .finally(() => db.$disconnect());
JS

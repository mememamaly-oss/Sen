/**
 * DB PRIVILEGE-SEPARATION PROBE (owner order 2026-10-31, items 1.2 + 2.3).
 *
 * Drives the red/blue proof for the audit-trail destruction class:
 * the DB-level immutability trigger (migration 20261031095442) blocks
 * UPDATE and DELETE — but TRUNCATE does not fire row-level triggers, and
 * ALTER TABLE ... DISABLE TRIGGER removes the guard outright. BOTH are
 * pure privilege questions: they succeed for the table OWNER (and a
 * superuser), and are denied for everyone else.
 *
 * Until the privilege split, the application's own Prisma connection WAS
 * the owner/superuser — meaning code execution inside the app process
 * (or an SQL-injection reach) could erase or rewrite the trail with two
 * statements. This script runs the exact statements through the exact
 * connection string the app uses (DATABASE_URL) and reports each
 * verdict as JSON, so the same driver proves both sides:
 *
 *   RED : bun scripts/attack_truncate_audit.ts   (DATABASE_URL = owner)
 *   BLUE: bun scripts/attack_truncate_audit.ts   (DATABASE_URL = burhan_app)
 *
 * The permanent regression wall for the blue side is
 * tests/privsplit.integration.test.ts (runs in CI as burhan_app).
 */
import { PrismaClient } from "@prisma/client";

const db = new PrismaClient();

async function count(): Promise<number> {
  const r = (await db.$queryRawUnsafe(`SELECT count(*)::int AS n FROM "AuditLog"`)) as { n: number }[];
  return r[0].n;
}

async function tryExec(label: string, sql: string): Promise<{ label: string; allowed: boolean; error: string | null }> {
  try {
    await db.$executeRawUnsafe(sql);
    return { label, allowed: true, error: null };
  } catch (e) {
    // Prisma raw errors open with blank/invocation lines — surface the
    // first MEANINGFUL line (the actual driver error, e.g. "permission
    // denied for table AuditLog")
    const msg = e instanceof Error ? e.message : String(e);
    const line = msg.split("\n").map((l) => l.trim()).find((l) => l.length > 0) || msg.slice(0, 160);
    return { label, allowed: false, error: line.slice(0, 160) };
  }
}

async function main() {
  const url = process.env.DATABASE_URL || "";
  const who = (await db.$queryRawUnsafe(`SELECT current_user, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS super`)) as { current_user: string; super: boolean }[];
  // ensure there is something to destroy
  await db.auditLog.create({ data: { action: "privsplit.probe", detail: JSON.stringify({ marker: "erase-me" }) } });
  const before = await count();

  // (a) TRUNCATE — the statement the row-trigger CANNOT block
  const truncate = await tryExec("TRUNCATE AuditLog", `TRUNCATE TABLE "AuditLog"`);
  const afterTruncate = await count();

  // (b) trigger disable + rewrite — the owner-only bypass
  await db.auditLog.create({ data: { action: "privsplit.probe", detail: JSON.stringify({ marker: "rewrite-me" }) } });
  const disable = await tryExec("DISABLE TRIGGER", `ALTER TABLE "AuditLog" DISABLE TRIGGER audit_log_immutable`);
  const rewrite = disable.allowed
    ? await tryExec("UPDATE after disable", `UPDATE "AuditLog" SET detail = 'TAMPERED' WHERE action = 'privsplit.probe'`)
    : { label: "UPDATE after disable", allowed: false, error: "skipped (trigger still armed)" };
  // cleanup so repeated runs stay meaningful (owner only; on the app role
  // this re-enable is a no-op failure we swallow)
  await tryExec("re-enable trigger", `ALTER TABLE "AuditLog" ENABLE TRIGGER audit_log_immutable`);

  // (c) DROP a platform table — the blast radius beyond the audit trail
  const drop = await tryExec("DROP TABLE RateLimitBucket", `DROP TABLE "RateLimitBucket"`);

  const verdict = {
    connection_user: who[0].current_user,
    is_superuser: who[0].super,
    audit_rows_before: before,
    attacks: [truncate, disable, rewrite, drop],
    audit_rows_after_truncate: afterTruncate,
    trail_erased: truncate.allowed && afterTruncate === 0,
    trail_rewritable: rewrite.allowed,
    schema_droppable: drop.allowed,
  };
  console.log("VERDICT " + JSON.stringify(verdict));

  // exit code semantics: 0 = the account could NOT destroy the trail (the
  // desired state for the app role), 2 = it COULD (vulnerable state)
  if (verdict.trail_erased || verdict.trail_rewritable || verdict.schema_droppable) {
    console.error("RED: this connection CAN destroy/rewrite the audit trail or schema");
    process.exit(2);
  }
  console.log("BLUE: this connection cannot destroy or rewrite the audit trail");
  process.exit(0);
}

main()
  .catch((e) => {
    console.error("probe failed:", e);
    process.exit(1);
  })
  .finally(() => db.$disconnect());

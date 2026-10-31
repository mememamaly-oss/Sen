/**
 * DB PRIVILEGE SEPARATION (owner order 2026-10-31, items 1.2 + 2.3).
 *
 * RED (proven with scripts/attack_truncate_audit.ts against this exact
 * schema on 2026-10-31): when the app connected as the DB owner, its own
 * Prisma connection could TRUNCATE the audit trail (row triggers never
 * fire on TRUNCATE), disable the immutability trigger and rewrite rows,
 * and DROP platform tables. The trigger alone cannot defend any of that.
 *
 * BLUE / permanent wall: this suite runs with DATABASE_URL = the limited
 * `burhan_app` role (provisioned by scripts/db_app_role.sh; the runner
 * enforces it). Every destruction path must be DENIED by privileges,
 * while the app's real DML needs must keep working.
 */
import { describe, test, expect, beforeAll } from "bun:test";
import { db } from "@/lib/db";

let auditRowId = "";

async function tryRaw(sql: string): Promise<{ ok: boolean; err: string }> {
  try {
    await db.$executeRawUnsafe(sql);
    return { ok: true, err: "" };
  } catch (e) {
    // Prisma raw errors open with blank/invocation lines — the assertion
    // target ("permission denied ...") lives deeper in the message
    return { ok: false, err: e instanceof Error ? e.message : String(e) };
  }
}

beforeAll(async () => {
  const row = await db.auditLog.create({
    data: { action: "privsplit.probe", detail: JSON.stringify({ marker: "must-not-be-destroyable" }) },
  });
  auditRowId = row.id;
});

describe("the app DB identity is privilege-limited (burhan_app)", () => {
  test("current_user is NOT a superuser and is the limited role", async () => {
    const r = (await db.$queryRawUnsafe(
      `SELECT current_user AS u, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS sup,
              (SELECT rolcreaterole FROM pg_roles WHERE rolname = current_user) AS cr`
    )) as { u: string; sup: boolean; cr: boolean }[];
    expect(r[0].sup).toBe(false);
    expect(r[0].cr).toBe(false);
    expect(r[0].u).toBe("burhan_app");
  });

  test("TRUNCATE on the audit trail is DENIED (the row-trigger bypass is closed)", async () => {
    const v = await tryRaw(`TRUNCATE TABLE "AuditLog"`);
    expect(v.ok).toBe(false);
    expect(v.err).toMatch(/permission denied|must be owner/);
    const n = (await db.$queryRawUnsafe(`SELECT count(*)::int AS n FROM "AuditLog"`)) as { n: number }[];
    expect(n[0].n).toBeGreaterThan(0);
  });

  test("DISABLE TRIGGER (the owner-only rewrite bypass) is DENIED", async () => {
    const v = await tryRaw(`ALTER TABLE "AuditLog" DISABLE TRIGGER audit_log_immutable`);
    expect(v.ok).toBe(false);
    // 42501 = insufficient_privilege (message text differs per statement:
    // "permission denied" vs "must be owner of table")
    expect(v.err).toMatch(/permission denied|must be owner/);
  });

  test("DROP TABLE on platform tables is DENIED", async () => {
    const v = await tryRaw(`DROP TABLE "RateLimitBucket"`);
    expect(v.ok).toBe(false);
    expect(v.err).toMatch(/permission denied|must be owner/);
  });

  test("CREATE TABLE is DENIED (no schema modification at all)", async () => {
    const v = await tryRaw(`CREATE TABLE pwned (id text)`);
    expect(v.ok).toBe(false);
    expect(v.err).toMatch(/permission denied|must be owner/);
  });

  test("UPDATE/DELETE on the trail are still trigger-blocked (DML granted, mutation denied)", async () => {
    const u = await tryRaw(`UPDATE "AuditLog" SET detail = 'TAMPERED' WHERE id = '${auditRowId}'`);
    expect(u.ok).toBe(false);
    const d = await tryRaw(`DELETE FROM "AuditLog" WHERE id = '${auditRowId}'`);
    expect(d.ok).toBe(false);
    const still = await db.auditLog.findUnique({ where: { id: auditRowId } });
    expect(still?.detail).toContain("must-not-be-destroyable");
  });

  test("the app's real work keeps working: INSERT audit + full DML on platform tables", async () => {
    const created = await db.auditLog.create({ data: { action: "privsplit.append.ok" } });
    expect(created.id).toBeTruthy();
    // representative platform DML (the limiter's table)
    await db.rateLimitBucket.create({ data: { key: "privsplit-probe", hitsJson: "[]" } });
    await db.rateLimitBucket.update({ where: { key: "privsplit-probe" }, data: { hitsJson: "[1]" } });
    await db.rateLimitBucket.delete({ where: { key: "privsplit-probe" } });
  });
});

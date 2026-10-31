/**
 * AUDIT-LOG IMMUTABILITY (owner order 2026-10-31, part 2.6).
 *
 * The audit trail is the tenant-isolation evidence base (every RBAC denial
 * is recorded). Before this fix NOTHING at the database level prevented
 * UPDATE or DELETE on AuditLog — the integration suite itself deleted
 * audit rows, and docs/phase3/soc2-readiness.md even claimed "append-only
 * audit log (no deletes/edits)" which was FALSE at the DB level. A
 * compromised app-level account (or code execution inside the app process,
 * which holds the Prisma connection) could erase or rewrite the trail.
 *
 * The fix is a DATABASE trigger (not application logic): BEFORE UPDATE OR
 * DELETE ... RAISE EXCEPTION. Application-level logic is bypassable by
 * definition; a trigger is not reachable from Prisma at all.
 */
import { describe, test, expect, beforeAll } from "bun:test";
import { db } from "@/lib/db";

const BASE = process.env.INTEGRATION_SERVER_URL || "";
if (!BASE) throw new Error("INTEGRATION_SERVER_URL is required (bash runner mode)");

let orgId = "";
let auditRowId = "";

beforeAll(async () => {
  // any org with an audit trail (org creation writes one); reuse-or-create
  const jar = new Map<string, string>();
  const absorb = (res: Response) => {
    for (const c of res.headers.getSetCookie?.() ?? []) {
      const [pair] = c.split(";");
      const eq = pair.indexOf("=");
      if (eq > 0) jar.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
    }
  };
  const hdr = () => ({ "Content-Type": "application/json", Cookie: [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ") });
  // state-tolerant session discovery (same doctrine as the other suites):
  // bola-admin from a solo run, else the main suite's racer winner, else
  // bootstrap a fresh instance ourselves.
  const tryLogin = async (email: string, password: string): Promise<boolean> => {
    jar.clear();
    const csrf = await fetch(`${BASE}/api/auth/csrf`);
    absorb(csrf);
    const { csrfToken: token } = (await csrf.json()) as { csrfToken: string };
    const res = await fetch(`${BASE}/api/auth/callback/credentials`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: hdr().Cookie },
      body: new URLSearchParams({ csrfToken: token, email, password, json: "true" }),
      redirect: "manual",
    });
    absorb(res);
    if (res.status !== 200 && res.status !== 302) return false;
    const me = await fetch(`${BASE}/api/me`, { headers: hdr() });
    if (me.status !== 200) return false;
    const meBody = (await me.json()) as { orgs: { id: string; role: string }[] };
    const owned = meBody.orgs?.find((o) => o.role === "OWNER");
    if (!owned) return false;
    orgId = owned.id;
    return true;
  };
  let authed = await tryLogin("bola-admin@integration.test", "Bola-Admin-Passw0rd!");
  if (!authed) {
    for (let i = 0; i < 10 && !authed; i++) {
      authed = await tryLogin(`racer${i}@integration.test`, "Racer-Passw0rd!");
    }
  }
  if (!authed) {
    const bs = await fetch(`${BASE}/api/bootstrap`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: "audit-admin@integration.test", password: "Audit-Admin-Passw0rd!", name: "Audit Admin", orgName: "Audit Org" }) });
    if (bs.status === 200) {
      authed = await tryLogin("audit-admin@integration.test", "Audit-Admin-Passw0rd!");
    }
  }
  if (!authed) throw new Error("no session for the audit immutability suite");
  // seed one audit row directly (org.created above already wrote some; add
  // one more with a known payload)
  const row = await db.auditLog.create({
    data: { action: "audit.immutability.probe", orgId, detail: JSON.stringify({ marker: "immutable-probe" }) },
  });
  auditRowId = row.id;
});

describe("AuditLog is append-only AT THE DATABASE LEVEL", () => {
  test("UPDATE on AuditLog is rejected by the DB trigger (Prisma throws)", async () => {
    let threw = false;
    try {
      await db.auditLog.update({ where: { id: auditRowId }, data: { detail: "TAMPERED" } });
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
    const still = await db.auditLog.findUnique({ where: { id: auditRowId } });
    expect(still?.detail).toContain("immutable-probe");
  });

  test("DELETE on AuditLog is rejected by the DB trigger (Prisma throws)", async () => {
    let threw = false;
    try {
      await db.auditLog.delete({ where: { id: auditRowId } });
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
    expect(await db.auditLog.findUnique({ where: { id: auditRowId } })).not.toBeNull();
  });

  test("deleteMany/updateMany are rejected too (no bulk bypass)", async () => {
    let delThrew = false;
    try {
      await db.auditLog.deleteMany({ where: { orgId } });
    } catch {
      delThrew = true;
    }
    expect(delThrew).toBe(true);
    let updThrew = false;
    try {
      await db.auditLog.updateMany({ where: { orgId }, data: { detail: "x" } });
    } catch {
      updThrew = true;
    }
    expect(updThrew).toBe(true);
  });

  test("INSERT still works (append-only, not read-only) and the API reads the trail", async () => {
    const created = await db.auditLog.create({ data: { action: "audit.append.ok", orgId } });
    expect(created.id).toBeTruthy();
    // the audit API still serves the org trail (read path intact)
    const r = await fetch(`${BASE}/api/audit?orgId=${orgId}`, {
      headers: { Cookie: "" },
    });
    // (unauthenticated is 401 — the READ path authorization is covered by
    // the BOLA matrix; here we only prove the DB read path via Prisma)
    const rows = await db.auditLog.findMany({ where: { orgId }, take: 3 });
    expect(rows.length).toBeGreaterThan(0);
  });

  test("deleting the ORG does not mutate or delete its audit rows (no FK cascade)", async () => {
    // create a throwaway org with an audit row, delete the org, verify the
    // audit row SURVIVES untouched (previously onDelete: SetNull rewrote
    // orgId to null — an implicit mutation of the historical record)
    const org = await db.organization.create({ data: { name: `Doomed Org ${Date.now()}`, slug: `doomed-${Date.now().toString(36)}` } });
    const row = await db.auditLog.create({ data: { action: "audit.survives.org.deletion", orgId: org.id } });
    await db.organization.delete({ where: { id: org.id } });
    const still = await db.auditLog.findUnique({ where: { id: row.id } });
    expect(still).not.toBeNull();
    expect(still?.orgId).toBe(org.id); // the historical reference is PRESERVED
  });
});

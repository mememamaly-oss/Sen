/**
 * BOLA/IDOR CROSS-TENANT MATRIX (owner order 2026-10-31, part 2.1).
 *
 * One permanent guard for EVERY resource-bearing API route: a user with no
 * relation to organization B must receive 404 for every B resource — both
 * when passing orgId=B (non-member) and when passing their OWN orgId=A with
 * a B resource id (the id-confusion vector). Controls in both directions
 * prove the 404s are authorization, not breakage.
 *
 * Also pins the member-management route at its documented dynamic path
 * /api/orgs/:id/members/:mid (directory [mid]). AUDIT NOTE 2026-10-31:
 * an initial suspicion that the directory was malformed arose purely
 * from a display artifact in the operator console (the sequence "[m" is
 * swallowed by ANSI-escape processing, rendering "[mid]" as "id]") — the
 * directory was verified byte-exact as "[mid]" and the route was never
 * broken; no rename was performed. This suite pins the path and its
 * authorization semantics forever.
 *
 * External-server mode only (INTEGRATION_SERVER_URL) — the supported path
 * is scripts/run_integration_tests.sh.
 */
import { describe, test, expect, beforeAll } from "bun:test";
import fs from "fs";
import path from "path";
import { db } from "@/lib/db";

const BASE = process.env.INTEGRATION_SERVER_URL || "";
if (!BASE) throw new Error("INTEGRATION_SERVER_URL is required (bash runner mode)");

// --- cookie jar (same minimal helper as the main suite) ----------------------

class Jar {
  cookies = new Map<string, string>();
  absorb(res: Response) {
    const raw = res.headers.getSetCookie?.() ?? [];
    for (const c of raw) {
      const [pair] = c.split(";");
      const eq = pair.indexOf("=");
      if (eq > 0) this.cookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
    }
  }
  header(): string {
    return [...this.cookies.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  }
}

async function login(jar: Jar, email: string, password: string): Promise<Response> {
  const csrfRes = await fetch(`${BASE}/api/auth/csrf`);
  jar.absorb(csrfRes);
  const { csrfToken } = (await csrfRes.json()) as { csrfToken: string };
  const res = await fetch(`${BASE}/api/auth/callback/credentials`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: jar.header() },
    body: new URLSearchParams({ csrfToken, email, password, json: "true" }),
    redirect: "manual",
  });
  jar.absorb(res);
  return res;
}

async function api(jar: Jar, method: string, p: string, body?: unknown): Promise<Response> {
  return fetch(`${BASE}${p}`, {
    method,
    headers: { "Content-Type": "application/json", Cookie: jar.header() },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

// --- state -------------------------------------------------------------------

const adminJar = new Jar();   // OWNER of org A, NO relation to org B
const userBJar = new Jar();   // MEMBER of A + OWNER of B (seeds B's resources)
const userCJar = new Jar();   // MEMBER of A until the removal test

let orgA = "";
let orgB = "";
let targetB = "";
let scanB = "";
let findingB = "";
let reportB = "";

const ADMIN_EMAIL = "bola-admin@integration.test";
const ADMIN_PASS = "Bola-Admin-Passw0rd!";
const B_EMAIL = "bola-b@integration.test";
const B_PASS = "Bola-B-Passw0rd!";
const C_EMAIL = "bola-c@integration.test";
const C_PASS = "Bola-C-Passw0rd!";

async function adminSession(): Promise<void> {
  // 1. this file's own admin from a previous run on the same DB
  const known = await login(adminJar, ADMIN_EMAIL, ADMIN_PASS);
  if (known.status === 200 || known.status === 302) {
    const me = await api(adminJar, "GET", "/api/me");
    if (me.status === 200) {
      const body = (await me.json()) as { orgs: { id: string; role: string }[] };
      const owned = body.orgs?.find((o) => o.role === "OWNER");
      if (owned) { orgA = owned.id; return; }
      const created = await api(adminJar, "POST", "/api/orgs", { name: "Bola Org A" });
      if (created.status === 200) { orgA = ((await created.json()) as { id: string }).id; return; }
    }
  }
  // 2. fresh instance — bootstrap it
  const bs = await fetch(`${BASE}/api/bootstrap`);
  const { needsBootstrap } = (await bs.json()) as { needsBootstrap: boolean };
  if (needsBootstrap) {
    const r = await fetch(`${BASE}/api/bootstrap`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASS, name: "Bola Admin", orgName: "Bola Org A" }),
    });
    expect(r.status).toBe(200);
    orgA = ((await r.json()) as { orgId: string }).orgId;
    const relogin = await login(adminJar, ADMIN_EMAIL, ADMIN_PASS);
    expect([200, 302]).toContain(relogin.status);
    return;
  }
  // 3. the main suite ran first — discover its bootstrap winner
  for (let i = 0; i < 10; i++) {
    adminJar.cookies.clear();
    const res = await login(adminJar, `racer${i}@integration.test`, "Racer-Passw0rd!");
    if (res.status === 200 || res.status === 302) {
      const me = await api(adminJar, "GET", "/api/me");
      if (me.status === 200) {
        const body = (await me.json()) as { orgs: { id: string; role: string }[] };
        const owned = body.orgs?.find((o) => o.role === "OWNER");
        if (owned) { orgA = owned.id; return; }
      }
    }
  }
  throw new Error("no admin session could be established for the BOLA matrix");
}

async function ensureMember(email: string, password: string, role: string): Promise<void> {
  const r = await api(adminJar, "POST", `/api/orgs/${orgA}/members`, { email, password, role });
  expect([200, 409]).toContain(r.status); // 409 = already a member from a previous run
}

beforeAll(async () => {
  await adminSession();
  expect(orgA).toBeTruthy();

  await ensureMember(B_EMAIL, B_PASS, "MEMBER");
  await ensureMember(C_EMAIL, C_PASS, "MEMBER");
  const lb = await login(userBJar, B_EMAIL, B_PASS);
  expect([200, 302]).toContain(lb.status);
  const lc = await login(userCJar, C_EMAIL, C_PASS);
  expect([200, 302]).toContain(lc.status);

  // userB owns org B
  const orgRes = await api(userBJar, "POST", "/api/orgs", { name: "Bola Org B" });
  expect(orgRes.status).toBe(200);
  orgB = ((await orgRes.json()) as { id: string }).id;

  // seed org B with one of every resource, directly through Prisma (the
  // authorization layer is what this file exercises, not the engine)
  const userB = await db.user.findUniqueOrThrow({ where: { email: B_EMAIL } });
  targetB = (
    await db.target.create({
      data: { orgId: orgB, createdById: userB.id, name: "bola target", url: "https://bola.invalid/" },
    })
  ).id;
  scanB = (
    await db.scan.create({
      data: {
        orgId: orgB,
        targetId: targetB,
        createdById: userB.id,
        status: "COMPLETED",
        runId: "run-bola-matrix",
        optionsJson: "{}",
        statsJson: JSON.stringify({ coverage: { discovered: 3, tested: 3, untested: 0 } }),
        durationSec: 1,
        finishedAt: new Date(),
      },
    })
  ).id;
  findingB = (
    await db.finding.create({
      data: {
        orgId: orgB,
        scanId: scanB,
        targetId: targetB,
        engineId: "F-bola000001",
        type: "xss_reflected",
        severity: "high",
        status: "verified",
        confidence: 0.9,
        risk: 70,
        method: "GET",
        url: "https://bola.invalid/search",
        parameter: "q",
        evidenceJson: "[]",
        verificationJson: "{}",
        impactJson: "{}",
      },
    })
  ).id;
  const reportsDir = path.join(process.env.SENTINEL_DATA_DIR || "/tmp/sentinel-test-data", "reports");
  fs.mkdirSync(reportsDir, { recursive: true });
  const reportPath = path.join(reportsDir, `bola-${Date.now()}.html`);
  fs.writeFileSync(reportPath, "<html><body>bola report</body></html>");
  reportB = (
    await db.report.create({
      data: {
        orgId: orgB,
        scanId: scanB,
        createdById: userB.id,
        format: "HTML",
        title: "bola report",
        filePath: reportPath,
        sizeBytes: fs.statSync(reportPath).size,
      },
    })
  ).id;
});

// --- control direction: the OWNER of B reads everything (proves 404 = auth) ---

describe("BOLA matrix — control direction (userB reads own org B)", () => {
  test("GET /api/orgs/:B is 200 for the owner", async () => {
    const r = await api(userBJar, "GET", `/api/orgs/${orgB}`);
    expect(r.status).toBe(200);
  });
  test("GET /api/scans/:scanB?orgId=B is 200 for the owner", async () => {
    const r = await api(userBJar, "GET", `/api/scans/${scanB}?orgId=${orgB}`);
    expect(r.status).toBe(200);
  });
  test("GET /api/scans/:scanB/findings?orgId=B is 200 for the owner", async () => {
    const r = await api(userBJar, "GET", `/api/scans/${scanB}/findings?orgId=${orgB}`);
    expect(r.status).toBe(200);
  });
  test("GET /api/scans/:scanB/coverage?orgId=B is 200 for the owner", async () => {
    const r = await api(userBJar, "GET", `/api/scans/${scanB}/coverage?orgId=${orgB}`);
    expect(r.status).toBe(200);
  });
  test("GET /api/findings/:findingB?orgId=B is 200 for the owner", async () => {
    const r = await api(userBJar, "GET", `/api/findings/${findingB}?orgId=${orgB}`);
    expect(r.status).toBe(200);
  });
  test("GET /api/reports/:reportB?orgId=B is 200 for the owner", async () => {
    const r = await api(userBJar, "GET", `/api/reports/${reportB}?orgId=${orgB}`);
    expect(r.status).toBe(200);
  });
  test("GET /api/audit?orgId=B is 200 for the owner", async () => {
    const r = await api(userBJar, "GET", `/api/audit?orgId=${orgB}`);
    expect(r.status).toBe(200);
  });
  test("GET /api/v1/scans/:scanB/twin?orgId=B is 200 for the owner", async () => {
    const r = await api(userBJar, "GET", `/api/v1/scans/${scanB}/twin?orgId=${orgB}`);
    expect(r.status).toBe(200);
  });
});

// --- the attack direction: adminA (no relation to B) against every resource --

describe("BOLA matrix — cross-tenant access must be 404 on every route", () => {
  const cases: Array<[string, () => string]> = [
    ["GET", () => `/api/scans/${scanB}?orgId=${orgB}`],
    ["GET", () => `/api/scans/${scanB}?orgId=${orgA}`],                 // id-confusion vector
    ["GET", () => `/api/scans/${scanB}/findings?orgId=${orgB}`],
    ["GET", () => `/api/scans/${scanB}/findings?orgId=${orgA}`],
    ["GET", () => `/api/scans/${scanB}/coverage?orgId=${orgB}`],
    ["GET", () => `/api/scans/${scanB}/coverage?orgId=${orgA}`],
    ["DELETE", () => `/api/scans/${scanB}?orgId=${orgB}`],
    ["GET", () => `/api/findings/${findingB}?orgId=${orgB}`],
    ["GET", () => `/api/findings/${findingB}?orgId=${orgA}`],
    ["GET", () => `/api/reports/${reportB}?orgId=${orgB}`],
    ["GET", () => `/api/reports/${reportB}?orgId=${orgA}`],
    ["GET", () => `/api/orgs/${orgB}`],
    ["GET", () => `/api/orgs/${orgB}/members`],
    ["GET", () => `/api/audit?orgId=${orgB}`],
    ["GET", () => `/api/v1/scans/${scanB}/twin?orgId=${orgB}`],
    ["GET", () => `/api/v1/scans/${scanB}/twin?orgId=${orgA}`],
  ];
  for (const [method, pathFn] of cases) {
    test(`${method} (cross-tenant case) → 404`, async () => {
      const p = pathFn();
      const r = await api(adminJar, method, p);
      expect(r.status).toBe(404);
    });
  }

  test("listings scoped to B's orgId are 404 for a non-member (never a leak)", async () => {
    // requireOrgAccess runs BEFORE any listing query: a non-member never
    // receives even an empty listing for the foreign org.
    for (const p of [`/api/scans?orgId=${orgB}`, `/api/targets?orgId=${orgB}`, `/api/reports?orgId=${orgB}`, `/api/audit?orgId=${orgB}`]) {
      const r = await api(adminJar, "GET", p);
      expect(r.status).toBe(404);
    }
  });


  test("POST /api/scans with a foreign targetId is 404", async () => {
    const r = await api(adminJar, "POST", "/api/scans", { orgId: orgA, targetId: targetB });
    expect(r.status).toBe(404);
  });
  test("POST /api/reports with a foreign scanId is 404", async () => {
    const r = await api(adminJar, "POST", "/api/reports", { orgId: orgA, scanId: scanB, format: "HTML" });
    expect(r.status).toBe(404);
  });
  test("PATCH/DELETE a foreign target is 404", async () => {
    const p = await api(adminJar, "PATCH", `/api/targets/${targetB}`, { orgId: orgA, name: "hijacked" });
    expect(p.status).toBe(404);
    const d = await api(adminJar, "DELETE", `/api/targets/${targetB}?orgId=${orgA}`);
    expect(d.status).toBe(404);
    // B's target must be untouched
    const owner = await api(userBJar, "GET", `/api/targets?orgId=${orgB}`);
    const t = ((await owner.json()) as { targets: { id: string; name: string }[] }).targets.find((x) => x.id === targetB);
    expect(t?.name).toBe("bola target");
  });
});

// --- member management at the DOCUMENTED dynamic path -------------------------

describe("member management route at its documented dynamic path /api/orgs/:id/members/:mid", () => {
  let midB = "";
  let midC = "";

  test("admin lists org A members and finds B and C", async () => {
    const r = await api(adminJar, "GET", `/api/orgs/${orgA}/members`);
    expect(r.status).toBe(200);
    const { members } = (await r.json()) as { members: { userId: string; email: string; id: string }[] };
    midB = members.find((m) => m.email === B_EMAIL)!.id;
    midC = members.find((m) => m.email === C_EMAIL)!.id;
    expect(midB).toBeTruthy();
    expect(midC).toBeTruthy();
  });

  test("OWNER changes a member role at /api/orgs/:id/members/:mid", async () => {
    const r = await api(adminJar, "PATCH", `/api/orgs/${orgA}/members/${midB}`, { role: "ADMIN" });
    expect(r.status).toBe(200);
    const back = await api(adminJar, "PATCH", `/api/orgs/${orgA}/members/${midB}`, { role: "MEMBER" });
    expect(back.status).toBe(200);
  });

  test("cross-tenant member management is 404 (foreign org's member)", async () => {
    // userB (owner of B) lists B's members; adminA must not be able to touch them
    const list = await api(userBJar, "GET", `/api/orgs/${orgB}/members`);
    expect(list.status).toBe(200);
    const { members } = (await list.json()) as { members: { email: string; id: string }[] };
    const own = members.find((m) => m.email === B_EMAIL)!;
    expect(own).toBeTruthy();
    const p = await api(adminJar, "PATCH", `/api/orgs/${orgB}/members/${own.id}`, { role: "VIEWER" });
    expect(p.status).toBe(404);
    const d = await api(adminJar, "DELETE", `/api/orgs/${orgB}/members/${own.id}`);
    expect(d.status).toBe(404);
  });

  test("OWNER removes a member at /api/orgs/:id/members/:mid", async () => {
    const r = await api(adminJar, "DELETE", `/api/orgs/${orgA}/members/${midC}`);
    expect(r.status).toBe(200);
  });

  test("the REMOVED member immediately loses all access to org A", async () => {
    for (const p of [`/api/targets?orgId=${orgA}`, `/api/scans?orgId=${orgA}`, `/api/audit?orgId=${orgA}`, `/api/orgs/${orgA}`]) {
      const r = await api(userCJar, "GET", p);
      expect(r.status).toBe(404);
    }
  });

  test("removing B from A does not affect B's ownership of org B", async () => {
    const list = await api(adminJar, "GET", `/api/orgs/${orgA}/members`);
    const { members } = (await list.json()) as { members: { email: string; id: string }[] };
    const mid = members.find((m) => m.email === B_EMAIL)!.id;
    const r = await api(adminJar, "DELETE", `/api/orgs/${orgA}/members/${mid}`);
    expect(r.status).toBe(200);
    const own = await api(userBJar, "GET", `/api/orgs/${orgB}`);
    expect(own.status).toBe(200);
  });
});

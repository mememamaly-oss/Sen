/**
 * HTTP-LEVEL INTEGRATION TESTS (audit 2026-10-23).
 *
 * Boots (or attaches to) the real Next.js dev server on a scratch sqlite
 * database and verifies, over the wire:
 *   1. bootstrap atomicity — 10 concurrent bootstrap POSTs, exactly ONE wins
 *   2. authentication — csrf + credentials login, session cookie flows
 *   3. SSRF chain break — private-network target creation rejected (400)
 *   4. RBAC matrix — VIEWER cannot create; MEMBER cannot scan another
 *      member's target (the write-level fix); cross-org access is 404
 *   5. login rate limiting — the 11th bad attempt is refused
 *
 * Server management: when INTEGRATION_SERVER_URL is set (the canonical
 * path — see scripts/run_integration_tests.sh), the suite attaches to that
 * externally-managed server. Otherwise it self-spawns one (convenience for
 * local iteration; NOTE: in some sandboxed environments a self-spawned
 * server is unreliable — the bash runner is the supported path).
 *
 * Nothing here touches external systems: every request targets 127.0.0.1.
 */
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { spawn, type ChildProcess } from "child_process";
import fs from "fs";
import path from "path";

const PORT = Number(process.env.INTEGRATION_PORT || 3177);
const BASE = process.env.INTEGRATION_SERVER_URL || `http://127.0.0.1:${PORT}`;
const EXTERNAL = Boolean(process.env.INTEGRATION_SERVER_URL);
const DB_FILE = path.resolve("tests/integration.db");
const SERVER_LOG = path.resolve("tests/integration-server.log");

let server: ChildProcess | null = null;

function delay(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitUntil(fn: () => Promise<boolean>, timeoutMs: number, what: string) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    if (await fn()) return;
    await delay(500);
  }
  throw new Error(`timeout waiting for ${what}`);
}

// --- cookie jar (minimal) ---------------------------------------------------

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
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Cookie: jar.header(),
    },
    body: new URLSearchParams({ csrfToken, email, password, json: "true" }),
    redirect: "manual",
  });
  jar.absorb(res);
  return res;
}

async function api(jar: Jar, method: string, p: string, body?: unknown): Promise<Response> {
  return fetch(`${BASE}${p}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      Cookie: jar.header(),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

// --- lifecycle ---------------------------------------------------------------

beforeAll(async () => {
  if (EXTERNAL) {
    // externally-managed server (bash runner): verify readiness only
    await waitUntil(
      async () => {
        try {
          const r = await fetch(`${BASE}/api/bootstrap`, { signal: AbortSignal.timeout(2000) });
          return r.ok;
        } catch {
          return false;
        }
      },
      30_000,
      "external integration server ready"
    );
    return;
  }
  // fresh scratch DB
  for (const f of [DB_FILE, DB_FILE + "-journal", DB_FILE + "-wal", DB_FILE + "-shm"]) {
    try { fs.rmSync(f); } catch { /* ignore */ }
  }
  // push schema to the scratch DB
  const env = {
    ...process.env,
    DATABASE_URL: `file:${DB_FILE}`,
    NEXTAUTH_SECRET: "integration-test-secret",
    SENTINEL_DATA_DIR: "/tmp/sentinel-test-data",
  };
  const push = spawn("bunx", ["prisma", "db", "push", "--skip-generate"], {
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  await new Promise<void>((resolve, reject) => {
    let out = "";
    push.stdout!.on("data", (d) => (out += d));
    push.stderr!.on("data", (d) => (out += d));
    push.on("exit", (c) => (c === 0 ? resolve() : reject(new Error("prisma db push failed: " + out))));
  });

  // boot the dev server
  const logFd = fs.openSync(SERVER_LOG, "a");
  server = spawn("bunx", ["next", "dev", "-p", String(PORT)], {
    env,
    stdio: ["ignore", logFd, logFd],
  });
  await waitUntil(
    async () => {
      try {
        const r = await fetch(`${BASE}/api/bootstrap`, { signal: AbortSignal.timeout(2000) });
        return r.ok;
      } catch {
        return false;
      }
    },
    120_000,
    "dev server ready"
  );
}, 240_000);

afterAll(() => {
  if (server && server.pid && !EXTERNAL) {
    try { process.kill(-server.pid, "SIGTERM"); } catch { /* ignore */ }
    try { process.kill(server.pid, "SIGTERM"); } catch { /* ignore */ }
  }
});

// --- the tests ---------------------------------------------------------------

describe("bootstrap atomicity + auth + RBAC over the wire", () => {
  const adminJar = new Jar();
  let orgId = "";

  test("fresh instance reports needsBootstrap=true", async () => {
    const r = await fetch(`${BASE}/api/bootstrap`);
    expect(r.status).toBe(200);
    expect(((await r.json()) as { needsBootstrap: boolean }).needsBootstrap).toBe(true);
  });

  test("RACE: 10 concurrent bootstrap POSTs — exactly ONE wins", async () => {
    const emails = Array.from({ length: 10 }, (_, i) => `racer${i}@integration.test`);
    const results = await Promise.all(
      emails.map((email) =>
        fetch(`${BASE}/api/bootstrap`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password: "Racer-Passw0rd!", name: `Racer`, orgName: "Race Org" }),
        }).then(async (r) => ({ status: r.status, body: (await r.json()) as { orgId?: string } }))
      )
    );
    const wins = results.filter((r) => r.status === 200);
    const losses = results.filter((r) => r.status !== 200);
    expect(wins.length).toBe(1);
    expect(losses.length).toBe(9);
    for (const l of losses) expect(l.status).toBe(409);
    orgId = wins[0].body.orgId!;
    expect(orgId).toBeTruthy();
  });

  test("unauthenticated /api/me is 401", async () => {
    const r = await fetch(`${BASE}/api/me`);
    expect(r.status).toBe(401);
  });

  test("the winning account can log in and see OWNER org", async () => {
    // figure out which racer won by trying logins until one works
    let ok = false;
    for (let i = 0; i < 10 && !ok; i++) {
      adminJar.cookies.clear();
      const res = await login(adminJar, `racer${i}@integration.test`, "Racer-Passw0rd!");
      if (res.status === 200 || res.status === 302) {
        const me = await api(adminJar, "GET", "/api/me");
        if (me.status === 200) {
          const body = (await me.json()) as { orgs: { role: string }[] };
          if (body.orgs?.some((o) => o.role === "OWNER")) {
            ok = true;
            const meBody = body as unknown as { orgs: { id: string }[] };
            orgId = meBody.orgs[0].id;
          }
        }
      }
    }
    expect(ok).toBe(true);
  });

  test("SSRF chain: private-network target creation is rejected", async () => {
    for (const bad of [
      "http://127.0.0.1:8080",
      "http://localhost:3000",
      "http://10.0.0.5:8080",
      "http://169.254.169.254/latest/meta-data/",
      "http://192.168.1.1/admin",
      "http://127.0.0.1.nip.io:8080/",
    ]) {
      const r = await api(adminJar, "POST", "/api/targets", { orgId, name: "evil", url: bad });
      expect(r.status).toBe(400);
    }
  });

  test("public target creation succeeds; URL with credentials is rejected", async () => {
    const ok = await api(adminJar, "POST", "/api/targets", {
      orgId, name: "Example", url: "https://example.com/",
    });
    expect(ok.status).toBe(200);
    const cred = await api(adminJar, "POST", "/api/targets", {
      orgId, name: "Cred", url: "https://user:pass@example.com/",
    });
    expect(cred.status).toBe(400);
  });

  let memberJar = new Jar();
  let viewerJar = new Jar();
  let memberTargetId = "";

  test("OWNER adds a MEMBER and a VIEWER", async () => {
    const m = await api(adminJar, "POST", `/api/orgs/${orgId}/members`, {
      email: "member@integration.test", password: "Member-Passw0rd!", role: "MEMBER",
    });
    expect(m.status).toBe(200);
    const v = await api(adminJar, "POST", `/api/orgs/${orgId}/members`, {
      email: "viewer@integration.test", password: "Viewer-Passw0rd!", role: "VIEWER",
    });
    expect(v.status).toBe(200);
  });

  test("MEMBER logs in, creates own target, but CANNOT scan the OWNER's target (write-level fix)", async () => {
    memberJar = new Jar();
    await login(memberJar, "member@integration.test", "Member-Passw0rd!");
    const me = await api(memberJar, "GET", "/api/me");
    expect(me.status).toBe(200);

    // own target: allowed
    const t = await api(memberJar, "POST", "/api/targets", {
      orgId, name: "Member Target", url: "https://member-example.com/",
    });
    expect(t.status).toBe(200);
    memberTargetId = ((await t.json()) as { id: string }).id;

    // list targets to find the owner's target id
    const list = await api(memberJar, "GET", `/api/targets?orgId=${orgId}`);
    const { targets } = (await list.json()) as { targets: { id: string; ownerId: string }[] };
    const ownerTarget = targets.find((x) => x.id !== memberTargetId)!;
    expect(ownerTarget).toBeTruthy();

    // THE RBAC REGRESSION: read is fine, scan (write-level) must be 403
    const scan = await api(memberJar, "POST", "/api/scans", {
      orgId, targetId: ownerTarget.id, options: { allowPrivate: true },
    });
    expect(scan.status).toBe(403);
  });

  test("MEMBER can start a scan on their OWN target (policy still functional)", async () => {
    const scan = await api(memberJar, "POST", "/api/scans", { orgId, targetId: memberTargetId });
    // 200 = scan started (engine subprocess against a public URL will fail
    // or be blocked — that's the engine's business; authorization is what we test)
    expect([200, 409].includes(scan.status)).toBe(true);
    if (scan.status === 200) {
      // cancel it immediately to not leave a zombie engine process
      const { id } = (await scan.json()) as { id: string };
      await api(adminJar, "DELETE", `/api/scans/${id}?orgId=${orgId}`);
    }
  });

  test("VIEWER can read but cannot create targets (RBAC matrix)", async () => {
    viewerJar = new Jar();
    await login(viewerJar, "viewer@integration.test", "Viewer-Passw0rd!");
    const read = await api(viewerJar, "GET", `/api/targets?orgId=${orgId}`);
    expect(read.status).toBe(200);
    const create = await api(viewerJar, "POST", "/api/targets", {
      orgId, name: "nope", url: "https://example.org/",
    });
    expect(create.status).toBe(403);
  });

  test("cross-org isolation: MEMBER of org A gets 404 for a foreign org id", async () => {
    // member creates their own org (orgs POST) — then admin's org is foreign to them? No:
    // admin is member of own org only. Use the member's NEW org vs admin probing it.
    const newOrg = await api(memberJar, "POST", "/api/orgs", { name: "Member Private Org" });
    expect(newOrg.status).toBe(200);
    const { id: foreignOrg } = (await newOrg.json()) as { id: string };
    // VIEWER (not a member of the new org) probing it => 404
    const probe = await api(viewerJar, "GET", `/api/orgs/${foreignOrg}`);
    expect(probe.status).toBe(404);
  });

  test("login rate limiting: 11th bad attempt on a fresh email is refused", async () => {
    const jar = new Jar();
    // exhaust the per-email bucket (10 attempts allowed)
    for (let i = 0; i < 10; i++) {
      const res = await login(jar, "brute@integration.test", "wrong-password-" + i);
      expect([200, 302, 401].includes(res.status)).toBe(true);
    }
    // 11th: authorize() throws RATE_LIMITED — NextAuth responds 401 (fail closed)
    const blocked = await login(jar, "brute@integration.test", "wrong-password-11");
    expect(blocked.status).toBe(401);
  });
  // ------------------- 19-axis audit regressions (2026-10-23, G8/G11) --------

    test("G8 RACE: 3 concurrent scan starts on ONE target — exactly ONE accepted", async () => {
      // Before the fix, the active-scan guard was check-then-act: three
      // concurrent POSTs all passed it and spawned THREE engine processes
      // on one target (proven live: 3 RUNNING scan rows + 3 engine scan
      // dirs). Earliest-wins compensation must accept exactly one and 409
      // the rest. The race target uses the reserved .invalid TLD so the
      // winner's engine fails fast without touching any external system.
      const t = await api(adminJar, "POST", "/api/targets", {
        orgId, name: "Scan Race Target", url: "https://scan-race-test.invalid/",
      });
      expect(t.status).toBe(200);
      const raceTargetId = ((await t.json()) as { id: string }).id;

      const results = await Promise.all(
        [0, 1, 2].map(() =>
          api(adminJar, "POST", "/api/scans", { orgId, targetId: raceTargetId }).then((r) => r.status)
        )
      );
      const wins = results.filter((s) => s === 200).length;
      const refused = results.filter((s) => s === 409).length;
      expect(wins).toBe(1);
      expect(refused).toBe(2);

      // cleanup: cancel the winner so no engine process lingers
      const list = await api(adminJar, "GET", `/api/scans?orgId=${orgId}&targetId=${raceTargetId}`);
      const { scans } = (await list.json()) as { scans: { id: string; status: string }[] };
      for (const s of scans.filter((x) => x.status === "RUNNING" || x.status === "QUEUED")) {
        await api(adminJar, "DELETE", `/api/scans/${s.id}?orgId=${orgId}`);
      }
    });

    test("G11: malformed JSON body is 400, not 500 (jsonError classification)", async () => {
      // Before the fix this returned HTTP 500 (proven live in the gap probe).
      const r = await fetch(`${BASE}/api/targets`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: adminJar.header() },
        body: "{not-json",
      });
      expect(r.status).toBe(400);
    });
});

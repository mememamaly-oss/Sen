/**
 * SSRF POLICY AT THE APP LAYER (owner order 2026-10-31, part 2.2).
 *
 * The app itself never fetches a user-supplied URL (the engine subprocess is
 * the only egress). This suite pins BOTH app-side gates over the wire:
 *   1. target CREATION rejects every private/metadata/exotic-encoding form
 *      unless the deployment is in explicit lab mode;
 *   2. target PATCH cannot become the bypass (same rejection battery);
 *   3. a scan started with client-supplied options.allowPrivate:true stores
 *      allowPrivate:false (the server computes the policy, never the client).
 *
 * The ENGINE-side raw-socket bypass found and fixed on 2026-10-31 (websocket
 * client + modernsec smuggling probe connected to private targets without
 * --allow-private) is covered by tests/test_ssrf_live_refusal.py.
 */
import { describe, test, expect, beforeAll } from "bun:test";
import { db } from "@/lib/db";

const BASE = process.env.INTEGRATION_SERVER_URL || "";
if (!BASE) throw new Error("INTEGRATION_SERVER_URL is required (bash runner mode)");

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

const jar = new Jar();
let orgId = "";

beforeAll(async () => {
  // reuse whichever admin the suite order produced (self-sufficient discovery)
  const candidates = ["bola-admin@integration.test"];
  for (let i = 0; i < 10; i++) candidates.push(`racer${i}@integration.test`);
  for (const email of candidates) {
    jar.cookies.clear();
    const res = await login(jar, email, email === "bola-admin@integration.test" ? "Bola-Admin-Passw0rd!" : "Racer-Passw0rd!");
    if (res.status === 200 || res.status === 302) {
      const me = await api(jar, "GET", "/api/me");
      if (me.status === 200) {
        const body = (await me.json()) as { orgs: { id: string; role: string }[] };
        const owned = body.orgs?.find((o) => o.role === "OWNER");
        if (owned) { orgId = owned.id; return; }
      }
    }
  }
  throw new Error("no admin session for the SSRF suite");
});

const PRIVATE_FORMS = [
  "http://127.0.0.1:8080",
  "http://127.8.8.8/",                      // any 127/8
  "http://0.0.0.0/",
  "http://localhost:3000",
  "http://sub.localhost/",
  "http://10.0.0.5:8080",
  "http://172.16.0.1/",
  "http://172.31.255.254/",
  "http://192.168.1.1/admin",
  "http://169.254.169.254/latest/meta-data/", // cloud metadata
  "http://100.64.0.1/",                       // CGNAT
  "http://[::1]:3000/",
  "http://[fe80::1]/",
  "http://[fc00::1]/",
  "http://[::ffff:127.0.0.1]/",               // v4-mapped v6
  "http://0x7f.0.0.1/",                       // hex octets
  "http://2130706433/",                       // decimal 127.0.0.1
  "http://0177.0.0.1/",                       // octal
  "http://example.internal/",
  "http://x.nip.io/",
  "http://x.sslip.io/",
  "http://x.localtest.me/",
];

describe("SSRF: target creation + PATCH must reject every private form (lab mode OFF)", () => {
  test("creation rejects every private/exotic form", async () => {
    for (const url of PRIVATE_FORMS) {
      const r = await api(jar, "POST", "/api/targets", { orgId, name: "evil", url });
      expect(r.status).toBe(400);
    }
  });

  test("a public target is created, then PATCH to every private form is rejected", async () => {
    const created = await api(jar, "POST", "/api/targets", {
      orgId, name: `ssrf-patch-${Date.now()}`, url: "https://example.org/",
    });
    expect(created.status).toBe(200);
    const targetId = ((await created.json()) as { id: string }).id;
    for (const url of PRIVATE_FORMS) {
      const r = await api(jar, "PATCH", `/api/targets/${targetId}`, { orgId, url });
      expect(r.status).toBe(400);
    }
    // cleanup (keep the org clean for the rest of the suite)
    await api(jar, "DELETE", `/api/targets/${targetId}?orgId=${orgId}`);
  });

  test("client-supplied allowPrivate:true is IGNORED — the stored scan policy is false", async () => {
    const created = await api(jar, "POST", "/api/targets", {
      orgId, name: `ssrf-policy-${Date.now()}`, url: "https://example.org/",
    });
    expect(created.status).toBe(200);
    const targetId = ((await created.json()) as { id: string }).id;
    const scan = await api(jar, "POST", "/api/scans", {
      orgId, targetId, options: { allowPrivate: true, maxPages: 1 },
    });
    expect([200, 409].includes(scan.status)).toBe(true);
    if (scan.status === 200) {
      const { id } = (await scan.json()) as { id: string };
      const row = await db.scan.findUnique({ where: { id } });
      expect(row).not.toBeNull();
      const opts = JSON.parse(row!.optionsJson) as { allowPrivate?: boolean };
      expect(opts.allowPrivate).toBe(false);
      await api(jar, "DELETE", `/api/scans/${id}?orgId=${orgId}`);
    }
    await api(jar, "DELETE", `/api/targets/${targetId}?orgId=${orgId}`);
  });
});

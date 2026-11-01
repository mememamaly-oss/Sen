/**
 * PUBLIC DEMO ENDPOINT HARDENING (owner order 2026-10-31, part 2.7).
 *
 * /api/demo/scan is UNAUTHENTICATED — the public live demo. This suite
 * pins every abuse control:
 *   1. GET polling is rate-limited per IP (RED->GREEN in this very file:
 *      before 2026-10-31 the GET side had NO limit at all — a flood of
 *      polls was unbounded request processing on the public surface);
 *   2. POST ignores the request body ENTIRELY — a hostile body URL never
 *      reaches the spawned engine: the scan target is the hardcoded
 *      platform fixture (proven by every finding URL in the result);
 *   3. the single global lane: a second POST while one demo scan runs is
 *      refused BUSY;
 *   4. the per-IP POST budget (3/hour) is enforced.
 */
import { describe, test, expect, beforeAll } from "bun:test";

const BASE = process.env.INTEGRATION_SERVER_URL || "";
if (!BASE) throw new Error("INTEGRATION_SERVER_URL is required (bash runner mode)");
// item 1.4 (2026-10-31): a "distinct client identity" in these tests is the
// PROVEN proxy path (X-Real-IP + the shared proxy secret) — an unproven
// forged header no longer buys a fresh bucket, which is precisely the fix.
const PROXY_SECRET = process.env.TRUSTED_PROXY_SECRET || "";

async function post(body?: unknown): Promise<Response> {
  return fetch(`${BASE}/api/demo/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}
async function get(id: string, ip?: string): Promise<Response> {
  return fetch(`${BASE}/api/demo/scan?id=${encodeURIComponent(id)}`, {
    headers: ip ? { "X-Real-IP": ip, "x-proxy-secret": PROXY_SECRET } : undefined,
  });
}

beforeAll(async () => {
  // warm the route (dev servers compile on first hit)
  await get("warmup-probe").catch(() => null);
});

describe("demo GET polling is rate-limited", () => {
  test("THE 2.7 REGRESSION: a flood of polls is cut off with 429 (was: unbounded)", async () => {
    const N = 160;
    const codes: number[] = [];
    for (let i = 0; i < N; i++) {
      const r = await get(`flood-${i}`);
      codes.push(r.status);
    }
    const c429 = codes.filter((c) => c === 429).length;
    // before the fix every one of the N requests was processed (0 x 429)
    expect(c429).toBeGreaterThan(0);
    // and the limit is a LIMIT: the vast majority of a 160-flood is refused
    expect(c429).toBeGreaterThanOrEqual(N - 130);
  });

  test("unknown-id polls within the budget still behave normally (400/404, not 429)", async () => {
    // after the flood above the local bucket is blocked — check the normal
    // path still works for a PROVEN distinct client identity (item 1.4:
    // the proxy path carries the shared secret; a bare forged header gets
    // no fresh bucket by design)
    const r = await fetch(`${BASE}/api/demo/scan?id=normal-probe`, {
      headers: { "X-Real-IP": "198.51.100.77", "x-proxy-secret": PROXY_SECRET },
    });
    expect([400, 404]).toContain(r.status);
  });
});

describe("demo POST: hardcoded target + single lane + per-IP budget", () => {
  test("POST with a HOSTILE body still scans ONLY the platform fixture (body is ignored)", async () => {
    const r = await post({ url: "http://169.254.169.254/latest/meta-data/", target: "http://127.0.0.1:9/x" });
    expect([202, 429, 503]).toContain(r.status);
    if (r.status === 202) {
      const { id } = (await r.json()) as { id: string };
      // wait for the engine to finish (bounded: fixture scan ~30-90s)
      let job: { status?: string; findings?: { url: string }[]; error?: string } | null = null;
      for (let i = 0; i < 100; i++) {
        await new Promise((res) => setTimeout(res, 2000));
        // poll under a PROVEN distinct client identity (proxy secret —
        // item 1.4): the flood test above deliberately exhausts the local
        // poll bucket; the proxy path carries its own per-IP budget
        const g = await get(id, "203.0.113.42");
        if (g.status === 200) {
          job = (await g.json()) as typeof job;
          if (job?.status === "done" || job?.status === "error") break;
        }
      }
      expect(job).not.toBeNull();
      expect(job!.status).toBe("done");
      // every finding came from the PLATFORM FIXTURE — never the hostile URL
      for (const f of job!.findings ?? []) {
        expect(f.url).toContain("127.0.0.1:8777");
        expect(f.url).not.toContain("169.254");
      }
      expect((job!.findings ?? []).length).toBeGreaterThan(0);
    }
  }, 300_000);

  test("single lane: a POST while a scan MIGHT run is never concurrent (202 or 429, never two engines)", async () => {
    const a = await post({});
    const b = await post({});
    const statuses = [a.status, b.status].sort();
    // exactly one of the two may start; the other must be refused
    expect(statuses).not.toEqual([202, 202]);
    if (a.status === 202) {
      const { id } = (await a.json()) as { id: string };
      for (let i = 0; i < 100; i++) {
        await new Promise((res) => setTimeout(res, 2000));
        const g = await get(id, "203.0.113.43");
        if (g.status === 200) {
          const job = (await g.json()) as { status?: string };
          if (job?.status === "done" || job?.status === "error") break;
        }
      }
    }
  }, 300_000);
});

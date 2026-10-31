/**
 * PROXY-SECRET GATE for forwarded client IPs (owner order 2026-10-31, item 1.4).
 *
 * RED class: clientIpFromReq()/clientIp() trusted X-Forwarded-For /
 * X-Real-For unconditionally — any DIRECT client could forge them and get
 * a FRESH rate-limit bucket per request (proven: 130 demo poll GETs with
 * 130 distinct forged XFF values, zero refusals — the 120/hour budget
 * never engaged), erasing every per-IP limit on the public surface.
 *
 * The gate: forwarded headers are honored ONLY when the request also
 * carries the shared proxy secret (TRUSTED_PROXY_SECRET on the app,
 * X-Proxy-Secret injected by Caddy). Anything else falls back to the
 * shared "local" bucket — fail-closed.
 *
 * The runner boots the server with TRUSTED_PROXY_SECRET set, so this file
 * proves all four shapes against the REAL app over HTTP:
 *   T1 forged XFF, no secret      -> NO fresh buckets (budget still lands)
 *   T2 distinct XFF + valid secret-> per-IP attribution works (no 429)
 *   T3 same XFF + valid secret    -> that IP's budget engages (429)
 *   T4 distinct XFF + WRONG secret-> treated as untrusted (no fresh buckets)
 */
import { describe, test, expect } from "bun:test";

const BASE = process.env.INTEGRATION_SERVER_URL || "";
if (!BASE) throw new Error("INTEGRATION_SERVER_URL is required (bash runner mode)");
const SECRET = process.env.TRUSTED_PROXY_SECRET || "";

const POLL = `${BASE}/api/demo/scan?id=proxygate-probe`;
const N = 130; // DEMO_POLL_HITS is 120/hour per bucket — N pushes past it

async function poll(headers: Record<string, string>): Promise<number> {
  const r = await fetch(POLL, { headers });
  return r.status; // 404 = normal answer for an unknown job; 429 = budget hit
}

describe("forwarded-IP trust requires the proxy secret (item 1.4)", () => {
  test("T1: forged X-Forwarded-For WITHOUT the secret gets NO fresh buckets (the budget still lands)", async () => {
    let saw429 = false;
    for (let i = 0; i < N; i++) {
      const status = await poll({ "x-forwarded-for": `198.51.100.${(i % 250) + 1}` });
      if (status === 429) {
        saw429 = true;
        break;
      }
    }
    expect(saw429).toBe(true);
  });

  test("T2: distinct XFF WITH the valid secret IS attributed per-IP (proxy path unbroken, zero 429)", async () => {
    expect(SECRET).not.toBe("");
    let saw429 = false;
    for (let i = 0; i < N; i++) {
      const status = await poll({
        "x-forwarded-for": `192.0.2.${(i % 250) + 1}`,
        "x-proxy-secret": SECRET,
      });
      if (status === 429) {
        saw429 = true;
        break;
      }
    }
    expect(saw429).toBe(false);
  });

  test("T3: the SAME trusted XFF exhausts ITS OWN budget (per-IP attribution is real, 429 lands)", async () => {
    expect(SECRET).not.toBe("");
    let saw429 = false;
    for (let i = 0; i < N; i++) {
      const status = await poll({ "x-forwarded-for": "203.0.113.77", "x-proxy-secret": SECRET });
      if (status === 429) {
        saw429 = true;
        break;
      }
    }
    expect(saw429).toBe(true);
  });

  test("T4: a WRONG proxy secret is untrusted (distinct XFF, shared budget -> 429 lands)", async () => {
    let saw429 = false;
    for (let i = 0; i < N; i++) {
      const status = await poll({
        "x-forwarded-for": `198.18.0.${(i % 250) + 1}`,
        "x-proxy-secret": "not-the-real-secret",
      });
      if (status === 429) {
        saw429 = true;
        break;
      }
    }
    expect(saw429).toBe(true);
  });
});

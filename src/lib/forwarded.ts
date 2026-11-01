import { timingSafeEqual } from "node:crypto";

// PROXY-SECRET GATE for forwarded client IPs (owner order 2026-10-31, item 1.4).
//
// RED (proven live, tests/proxygate.integration.test.ts T1/T4): the app
// trusted X-Forwarded-For / X-Real-IP unconditionally, so ANY direct
// client could forge a fresh rate-limit bucket per request — 130 distinct
// forged XFF values against the 120/hour demo poll budget yielded ZERO
// refusals. Every per-IP limit on the public surface was erasable by a
// header.
//
// The gate: forwarded headers are honored ONLY when the request also
// carries the shared proxy secret (X-Proxy-Secret), injected by the
// reverse proxy (Caddyfile: header_up X-Proxy-Secret {$PROXY_SECRET})
// and compared in constant time against TRUSTED_PROXY_SECRET. Anything
// else — no secret configured, missing header, wrong value — returns
// null and the caller falls back to its shared "local" bucket:
// fail-closed (a misconfigured deployment loses per-IP attribution, it
// never regains forgeable attribution).

const PROXY_SECRET_HEADER = "x-proxy-secret";

export function trustedProxySecret(): string | null {
  const s = process.env.TRUSTED_PROXY_SECRET;
  return s && s.length > 0 ? s : null;
}

function secretMatches(get: (name: string) => string | null): boolean {
  const expected = trustedProxySecret();
  if (!expected) return false; // not configured -> nothing is trusted
  const provided = get(PROXY_SECRET_HEADER);
  if (!provided) return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false; // length is not secret here
  return timingSafeEqual(a, b);
}

/**
 * The trusted client IP from forwarded headers, or null when the request
 * is NOT proven to come through the proxy. `get` must lowercase the name
 * (Node's raw header objects and the fetch Headers API both do).
 */
export function trustedForwardedIp(get: (name: string) => string | null): string | null {
  if (!secretMatches(get)) return null;
  const xff = get("x-forwarded-for");
  if (xff) {
    const first = xff.split(",")[0].trim();
    if (first) return first;
  }
  const real = get("x-real-ip");
  if (real) {
    const first = real.split(",")[0].trim();
    if (first) return first;
  }
  return null;
}

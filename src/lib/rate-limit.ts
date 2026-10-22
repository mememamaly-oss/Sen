// In-memory sliding-window rate limiter (audit 2026-10-23).
//
// Purpose: brute-force protection on the credentials login path
// (NextAuth authorize() has no built-in limiter).
//
// Scope limitation (documented honestly): this is a single-process,
// in-memory limiter. The product is deployed as a single standalone
// container (scripts/start_prod_server.sh), so process-local state is
// authoritative there. If the deployment is ever scaled horizontally,
// replace the store with a shared one (e.g. Redis) — the interface below
// is intentionally tiny for that swap.

type Bucket = { hits: number[]; blockedUntil?: number };

const g = globalThis as unknown as { __sentinelRateBuckets?: Map<string, Bucket> };
g.__sentinelRateBuckets = g.__sentinelRateBuckets || new Map();
const buckets = g.__sentinelRateBuckets;

export type RateVerdict = {
  allowed: boolean;
  remaining: number;
  retryAfterSec: number;
};

/**
 * Sliding window: maxHits requests per windowMs per key.
 * When the window is exceeded, the key is blocked until the oldest hit
 * leaves the window (no lockout-table persistence — attacker cost is
 * bounded, honest users recover automatically).
 */
export function rateLimit(
  key: string,
  maxHits: number,
  windowMs: number
): RateVerdict {
  const now = Date.now();
  const b = buckets.get(key) ?? { hits: [] };
  // drop expired hits
  b.hits = b.hits.filter((t) => now - t < windowMs);
  if (b.blockedUntil && now < b.blockedUntil) {
    buckets.set(key, b);
    return { allowed: false, remaining: 0, retryAfterSec: Math.ceil((b.blockedUntil - now) / 1000) };
  }
  if (b.hits.length >= maxHits) {
    // blocked until the oldest hit exits the window
    b.blockedUntil = b.hits[0] + windowMs;
    buckets.set(key, b);
    return { allowed: false, remaining: 0, retryAfterSec: Math.ceil((b.blockedUntil - now) / 1000) };
  }
  b.hits.push(now);
  b.blockedUntil = undefined;
  buckets.set(key, b);
  return { allowed: true, remaining: maxHits - b.hits.length, retryAfterSec: 0 };
}

/** Test/ops helper: clear buckets. */
export function resetRateLimits(): void {
  buckets.clear();
}

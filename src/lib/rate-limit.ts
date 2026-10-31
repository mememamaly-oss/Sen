// SHARED-STORE SLIDING-WINDOW RATE LIMITER (owner order 2026-10-31, 2.9).
//
// Purpose: brute-force protection on the credentials login path (NextAuth
// authorize() has no built-in limiter) and abuse protection on the public
// demo endpoint.
//
// HISTORY: this was a single-process, in-memory limiter (audit 2026-10-23)
// with a documented single-process assumption. That assumption is now
// REMOVED: the buckets live in the platform's existing PostgreSQL
// (RateLimitBucket table — no new dependency), and every decision runs
// inside a transaction holding pg_advisory_xact_lock(hashtext(key)), so
// the limit is enforced GLOBALLY across any number of app processes and
// survives restarts. Red->green proof: tests/ratelimit.integration.test.ts
// (two separate bun processes against the same key).
//
// Fail-closed doctrine: if the database is unreachable, rateLimit throws —
// a login attempt that cannot be rate-checked must not proceed (the login
// path itself needs the same database anyway).

import { db } from "@/lib/db";

type Bucket = { hits: number[]; blockedUntil?: number | null };

export type RateVerdict = {
  allowed: boolean;
  remaining: number;
  retryAfterSec: number;
};

/**
 * Sliding window: maxHits requests per windowMs per key, shared across ALL
 * app processes. When the window is exceeded, the key is blocked until the
 * oldest hit leaves the window (no lockout-table persistence — attacker
 * cost is bounded, honest users recover automatically).
 */
export async function rateLimit(
  key: string,
  maxHits: number,
  windowMs: number
): Promise<RateVerdict> {
  const now = Date.now();
  return db.$transaction(async (tx) => {
    // serialize concurrent decisions on the same key (advisory xact lock —
    // released automatically at commit/rollback)
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${key}))`;
    const row = await tx.rateLimitBucket.findUnique({ where: { key } });
    let hits: number[] = [];
    try {
      hits = row ? (JSON.parse(row.hitsJson) as number[]) : [];
      if (!Array.isArray(hits)) hits = [];
    } catch {
      hits = []; // corrupted row = fresh bucket (fail open on data, closed on policy below)
    }
    // drop expired hits
    hits = hits.filter((t) => now - t < windowMs);

    if (row?.blockedUntil && now < row.blockedUntil.getTime()) {
      return {
        allowed: false,
        remaining: 0,
        retryAfterSec: Math.ceil((row.blockedUntil.getTime() - now) / 1000),
      };
    }
    if (hits.length >= maxHits) {
      // blocked until the oldest hit exits the window
      const blockedUntil = new Date(hits[0] + windowMs);
      if (row) {
        await tx.rateLimitBucket.update({
          where: { key },
          data: { hitsJson: JSON.stringify(hits), blockedUntil },
        });
      } else {
        await tx.rateLimitBucket.create({
          data: { key, hitsJson: JSON.stringify(hits), blockedUntil },
        });
      }
      return {
        allowed: false,
        remaining: 0,
        retryAfterSec: Math.ceil((blockedUntil.getTime() - now) / 1000),
      };
    }
    hits.push(now);
    await tx.rateLimitBucket.upsert({
      where: { key },
      update: { hitsJson: JSON.stringify(hits), blockedUntil: null },
      create: { key, hitsJson: JSON.stringify(hits) },
    });
    return { allowed: true, remaining: maxHits - hits.length, retryAfterSec: 0 };
  });
}

/** Test/ops helper: clear every bucket. */
export async function resetRateLimits(): Promise<void> {
  await db.rateLimitBucket.deleteMany({});
}

/** Test-only export kept for type parity with the old implementation. */
export type { Bucket };

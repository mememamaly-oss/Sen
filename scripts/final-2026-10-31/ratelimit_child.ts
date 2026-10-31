// Two-process rate-limit probe child (owner order 2026-10-31, part 2.9).
// Usage: bun --preload ./tests/setup.ts scripts/final-2026-10-31/ratelimit_child.ts <key> <hits> <maxHits>
// Prints one JSON line: {"allowedCount":n,"deniedCount":m}
import { rateLimit, resetRateLimits } from "@/lib/rate-limit";

const [key, hitsStr, maxStr] = process.argv.slice(2);
const n = Number(hitsStr || 10);
const max = Number(maxStr || 10);
let allowed = 0;
let denied = 0;
for (let i = 0; i < n; i++) {
  const v = await rateLimit(`${key}`, max, 60_000);
  if (v.allowed) allowed++;
  else denied++;
}
console.log(JSON.stringify({ allowedCount: allowed, deniedCount: denied }));
process.exit(0);

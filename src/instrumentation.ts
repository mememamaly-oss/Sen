// Next.js instrumentation hook — runs once per server process startup.
// v5.0.0 rename (Sen(tinel) -> Burhan): surface stale SENTINEL_* variables
// loudly instead of silently ignoring them (owner order, part 1.4).
import { warnLegacyEnv } from "@/lib/env";

export function register(): void {
  warnLegacyEnv();
}

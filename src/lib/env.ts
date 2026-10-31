// BURHAN environment access with pre-rename (SENTINEL_*) backward compatibility.
//
// v5.0.0 renamed the project Sen(tinel) -> Burhan; every platform
// configuration variable moved from SENTINEL_<NAME> to BURHAN_<NAME>.
// Legacy names are honored — warned, never silently ignored — so existing
// deployments keep working across the upgrade; removal is planned for a
// future major release (see the README migration table).
const LEGACY_PREFIX = "SENTINEL_";
const NEW_PREFIX = "BURHAN_";
const warned = new Set<string>();

/** Read BURHAN_<name>, falling back to the legacy SENTINEL_<name> (with a warning). */
export function env(name: string): string | undefined {
  const modern = process.env[NEW_PREFIX + name];
  if (modern !== undefined) return modern;
  const legacy = process.env[LEGACY_PREFIX + name];
  if (legacy !== undefined) {
    if (!warned.has(name)) {
      warned.add(name);
      console.warn(
        `[burhan] WARNING: ${LEGACY_PREFIX}${name} is the pre-rename variable name; ` +
          `use ${NEW_PREFIX}${name}. The legacy value is honored for backward compatibility.`,
      );
    }
    return legacy;
  }
  return undefined;
}

/** Warn (never silently ignore) every legacy SENTINEL_* variable set at startup. */
export function warnLegacyEnv(): string[] {
  const found = Object.keys(process.env)
    .filter((k) => k.startsWith(LEGACY_PREFIX))
    .sort();
  for (const k of found) {
    console.warn(
      `[burhan] WARNING: ${k} is the pre-rename variable name; use BURHAN_${k.slice(LEGACY_PREFIX.length)}. ` +
        `The legacy value is honored for backward compatibility.`,
    );
  }
  return found;
}

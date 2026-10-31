// ─────────────────────────────────────────────────────────────────────────────
// Burhan — PHASE 02 L1: TWIN SERVICE (API-facing orchestration)
//
// get-or-build the normalized Security Twin for a scan:
//   1. tenant-scoped read of the stored TwinGraph (persist.ts)
//   2. on miss / schema drift: load raw (loader.ts) → normalize (normalize.ts)
//      → invariant check → persist → return
//
// Read-only post-scan intelligence: zero network requests, zero engine calls.
// ─────────────────────────────────────────────────────────────────────────────
import type { NormalizedTwin } from "./types";
import { normalizeTwin } from "./normalize";
import { checkInvariants, type InvariantReport } from "./invariants";
import { loadRawForScan } from "./loader";
import { isCurrentSchema, loadTwinGraph, saveTwinGraph } from "./persist";

export interface TwinServiceResult {
  twin: NormalizedTwin;
  built: boolean; // true = normalized during this call; false = served from store
  invariants: InvariantReport;
}

export async function getTwinForScan(orgId: string, scanId: string): Promise<TwinServiceResult | null> {
  // tenant-scoped store read (persist.ts never queries without orgId)
  const stored = await loadTwinGraph(orgId, scanId);
  if (stored && isCurrentSchema(stored)) {
    const invariants = checkInvariants(stored);
    return { twin: stored, built: false, invariants };
  }

  // build from raw engine output
  const loaded = await loadRawForScan(scanId);
  if (!loaded) return null;
  const twin = normalizeTwin(loaded.raw, {
    rawSource: loaded.rawSource,
    notes: loaded.notes,
  });
  const invariants = checkInvariants(twin, loaded.raw);
  await saveTwinGraph(orgId, scanId, twin);
  return { twin, built: true, invariants };
}

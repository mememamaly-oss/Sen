// ─────────────────────────────────────────────────────────────────────────────
// Burhan — PHASE 02 L1: Security Twin Normalization — public API
//
//   raw engine output ──normalizeTwin()──▶ normalized twin (deterministic)
//                          │
//                          ├─ checkInvariants()   INV-01..10 + extras
//                          ├─ checkEquivalence()  no raw element lost
//                          └─ persist.ts          TwinGraph (tenant-scoped)
//
// L1 is READ-ONLY post-scan intelligence: no network requests, no engine
// changes, no active testing (spec §19).
// ─────────────────────────────────────────────────────────────────────────────
export * from "./types";
export { why, verifiedClaimIsSound, coerceProvenance, verdictForStatus } from "./provenance";
export {
  TWIN_SCHEMA_VERSION, canonicalJson, computeTwinHash, computeRawHash,
  nodeId, edgeId, conflictId, unknownId,
} from "./hash";
export { normalizeTwin, type NormalizeOptions } from "./normalize";
export {
  checkInvariants, rawSourceRegistry, collectSourceRefs,
  type InvariantReport, type InvariantViolation, type InvariantId,
} from "./invariants";
export {
  checkEquivalence, extractRawEssentials, projectTwinEssentials,
  type EquivalenceReport, type RawEssentials,
} from "./equivalence";
export { sanitizeString, sanitizeLabel, pathOf, MAX_STRING, MAX_NODES, MAX_EDGES } from "./sanitize";
export { canonicalNodeType } from "./mapping";
export { ALL_FIXTURES } from "./fixtures";

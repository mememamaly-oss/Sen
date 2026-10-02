// ─────────────────────────────────────────────────────────────────────────────
// SENTINEL — PHASE 02 L1: Security Twin Normalization — TYPES
//
// Layer separation (spec §3), strictly enforced by module boundaries:
//   1. RAW ENGINE OUTPUT  — result.json / statsJson produced by engine v4.1.1.
//      NEVER modified by L1 (types below are read-only views).
//   2. NORMALIZED TWIN    — this module's output: a canonical, deterministic,
//      provenance-carrying security graph rebuilt from the raw artifacts.
//   3. DERIVED INTELLIGENCE — projections of the normalized twin (why(),
//      conflicts, counts, equivalence projection). Never mixed back into raw.
//
// L1 is a READ-ONLY POST-SCAN INTELLIGENCE LAYER: no new network requests,
// no engine modifications, no active security testing.
// ─────────────────────────────────────────────────────────────────────────────

/** The ONLY provenance values allowed (spec §2). Nothing else may appear. */
export const PROVENANCE_VALUES = [
  "OBSERVED",
  "INFERRED",
  "VERIFIED",
  "REFUTED",
  "UNKNOWN",
] as const;
export type Provenance = (typeof PROVENANCE_VALUES)[number];

export function isProvenance(v: unknown): v is Provenance {
  return typeof v === "string" && (PROVENANCE_VALUES as readonly string[]).includes(v);
}

/**
 * Claim state — separate from provenance (spec §10): when evidence both
 * supports and refutes a claim, the claim state becomes CONFLICT while the
 * provenance vocabulary stays strictly five-valued. CONFLICT is a documented
 * structured state, NOT a provenance value.
 */
export const CLAIM_STATES = ["VERIFIED", "REFUTED", "UNKNOWN", "CONFLICT"] as const;
export type ClaimState = (typeof CLAIM_STATES)[number];

/** Canonical node types (spec §4). Schema supports all of them; the
 *  normalizer only ever CREATES a node when raw evidence backs it. */
export const CANONICAL_NODE_TYPES = [
  "application",
  "host",
  "endpoint",
  "browser_surface",
  "parameter",
  "identity",
  "role",
  "session",
  "object",
  "entity",
  "workflow",
  "workflow_step",
  "state",
  "branch",
  "api",
  "finding",
  "secret",
  "evidence",
  "boundary",
  "hypothesis", // extra engine type (reasoning engine) — kept, never deleted
] as const;
export type CanonicalNodeType = (typeof CANONICAL_NODE_TYPES)[number];

/** Canonical edge types (spec §5 vocabulary + documented engine relations). */
export const CANONICAL_EDGE_TYPES = [
  "CONTAINS", // application -> host / api / boundary (scope membership, observed)
  "EXPOSES", // host -> endpoint | endpoint -> secret | entity -> endpoint
  "USES_PARAMETER", // endpoint -> parameter
  "HAS_ROLE", // identity -> role
  "AUTHENTICATES", // identity -> endpoint (authenticated context observed)
  "ACCESSES", // role -> endpoint (authz matrix verdict)
  "PART_OF", // workflow_step -> workflow | branch -> workflow
  "LEADS_TO", // workflow_step -> workflow_step (observed order)
  "TRANSITIONS_TO", // workflow -> state
  "DEPENDS_ON", // workflow_step -> session | workflow_step -> object (engine graph)
  "TESTED_BY", // endpoint -> workflow_step | finding -> endpoint | hypothesis -> endpoint
  "EVIDENCED_BY", // finding -> evidence | hypothesis -> evidence
  "REFUTED_BY", // claim -> evidence that refutes it
  "MINTS", // workflow_step -> object/entity (workflow walk: landing carries fresh id)
  "CONSUMES", // workflow_step -> object/entity (workflow walk: step submits id)
  "TYPED_AS", // parameter -> entity (name-based typing, inferred)
  "DECLARED_PRIVILEGE", // workflow -> role (privileged option declared on a form)
  "GENERATED_HYPOTHESIS", // endpoint -> hypothesis (reasoning pattern origin)
  "SPEAKS_PROTOCOL", // endpoint -> api (graphql / websocket)
] as const;
export type CanonicalEdgeType = (typeof CANONICAL_EDGE_TYPES)[number];

/** Structured why() answer (spec §6) — never a bare string. */
export interface WhyAnswer {
  provenance: Provenance;
  reason: string;
  sourceRefs: string[]; // addresses inside the raw engine output
  inferenceReason?: string; // mandatory for INFERRED
  evidenceRefs?: string[]; // VERIFIED: required (enforced fail-closed by the why() gate); REFUTED: only when explicitly provided
  downgradedFrom?: "VERIFIED"; // set when the why() gate fail-closed a VERIFIED answer to UNKNOWN
}

/** A claim carried by a node (findings, hypotheses). */
export interface TwinClaim {
  state: ClaimState;
  statement: string;
  evidenceRefs: string[]; // evidence node ids and/or raw source refs
  conflictIds: string[]; // TwinConflict ids when state === CONFLICT
}

export interface CanonicalNode {
  id: string; // deterministic, content-derived (N-<sha256[:16]>)
  type: CanonicalNodeType;
  key: string; // stable natural identity (e.g. "GET /path", "F-xxxx")
  label: string;
  provenance: Provenance; // existence provenance
  sourceRefs: string[];
  why: WhyAnswer;
  attrs: Record<string, unknown>; // sanitized, length-capped
  claim?: TwinClaim; // findings / hypotheses carry claims
  conflictIds?: string[]; // links to TwinConflict records
}

export interface CanonicalEdge {
  id: string; // deterministic (E-<sha256[:16]>)
  type: CanonicalEdgeType;
  from: string;
  to: string;
  provenance: Provenance;
  sourceRefs: string[];
  confidence: number; // 0..1 — engine confidence when present, else 1 for OBSERVED
  why: WhyAnswer;
  attrs?: Record<string, unknown>;
}

/** A conflict between two pieces of evidence (spec §10). Never auto-resolved. */
export interface TwinConflict {
  id: string; // deterministic (C-<sha256[:16]>)
  kind: string; // e.g. "access_verdict_mismatch" | "verified_vs_refuted"
  description: string;
  left: ConflictSide;
  right: ConflictSide;
  resolution: "UNRESOLVED"; // L1 never picks a side
}

export interface ConflictSide {
  claimRef: string; // node id or raw source ref
  provenance: Provenance;
  summary: string;
  sourceRefs: string[];
}

/** An honest record of what the twin does NOT know (spec §1/§24). */
export interface KnownUnknown {
  id: string; // deterministic (U-<sha256[:16]>)
  dimension: string; // e.g. "identities" | "browser_surfaces" | "boundary"
  description: string;
  sourceRefs: string[];
}

export interface TwinCounts {
  nodes: number;
  edges: number;
  byNodeType: Record<string, number>;
  byEdgeType: Record<string, number>;
  provenance: Record<Provenance, number>; // node existence provenance counts
  edgeProvenance: Record<Provenance, number>;
  claims: { VERIFIED: number; REFUTED: number; UNKNOWN: number; CONFLICT: number };
  conflicts: number;
  knownUnknowns: number;
}

/** The normalized Security Twin — fully deterministic for identical input. */
export interface NormalizedTwin {
  schemaVersion: string;
  target: string;
  scope: {
    runId: string;
    scanner: string;
    rawSource: "result.json" | "db-reconstruction";
    application: string; // origin
    host: string;
    coverage: { discovered: number; tested: number; untested: number; coveragePct: number | null };
  };
  nodes: CanonicalNode[]; // sorted by id
  edges: CanonicalEdge[]; // sorted by id
  conflicts: TwinConflict[]; // sorted by id
  knownUnknowns: KnownUnknown[]; // sorted by id
  counts: TwinCounts; // derived — NOT part of the hash input
  twinHash: string; // sha256 over canonical serialization of the content
  rawHash: string; // sha256 over the canonical serialization of the raw input
}

// ── RAW ENGINE OUTPUT (read-only view; engine v4.1.1 shapes) ─────────────────

export interface RawEvidenceEntry {
  kind?: string;
  detail?: string;
}

export interface RawFinding {
  id?: string;
  type?: string;
  severity?: string;
  status?: string;
  confidence?: number | string;
  method?: string;
  url?: string;
  parameter?: string;
  evidence?: RawEvidenceEntry[];
  verification?: Record<string, unknown>;
  impact?: Record<string, unknown>;
  risk?: number;
}

export interface RawEngineResult {
  run_id?: string;
  scanner?: string;
  seed?: number | string;
  target?: string;
  findings?: RawFinding[];
  rejected_candidates?: RawFinding[];
  stats?: Record<string, unknown>;
}

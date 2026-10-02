// ─────────────────────────────────────────────────────────────────────────────
// SENTINEL — PHASE 02 L1: PROVENANCE MODEL (spec §2)
//
// Exactly five values. This module is the single authority for provenance
// semantics and construction rules:
//
//   OBSERVED — the element is directly present in scan data (engine output).
//   INFERRED — derived from existing evidence by a documented rule;
//              must carry sourceRefs + inferenceReason.
//   VERIFIED — actual engine-produced evidence exists (evidence chain,
//              verification record, replay proof). Existence of an endpoint,
//              schema, node or candidate is NEVER sufficient for VERIFIED.
//   REFUTED  — an actual engine result negates the claim.
//   UNKNOWN  — insufficient evidence to decide. Guessing UNKNOWN into
//              VERIFIED is forbidden.
// ─────────────────────────────────────────────────────────────────────────────
import type { Provenance, WhyAnswer } from "./types";
import { isProvenance } from "./types";

/** Normalize any raw belief/provenance string defensively.
 *  Anything outside the five values collapses to UNKNOWN — never fabricated. */
export function coerceProvenance(raw: unknown): Provenance {
  if (typeof raw !== "string") return "UNKNOWN";
  const upper = raw.trim().toUpperCase();
  return isProvenance(upper) ? upper : "UNKNOWN";
}

/** Build a structured why() answer (spec §6). */
export function why(
  provenance: Provenance,
  reason: string,
  sourceRefs: string[],
  extra?: { inferenceReason?: string; evidenceRefs?: string[] },
): WhyAnswer {
  const w: WhyAnswer = { provenance, reason, sourceRefs };
  if (provenance === "INFERRED") w.inferenceReason = extra?.inferenceReason ?? reason;
  if (provenance === "VERIFIED" || provenance === "REFUTED") {
    w.evidenceRefs = extra?.evidenceRefs ?? sourceRefs;
  }
  return w;
}

/** VERIFIED requires non-empty evidence references (INV-04). */
export function verifiedClaimIsSound(w: WhyAnswer): boolean {
  return w.provenance !== "VERIFIED" || (w.evidenceRefs?.length ?? 0) > 0;
}

/** Verdict semantics for HTTP status codes observed by the authz engine. */
export function verdictForStatus(status: number | string): string {
  const n = Number(status);
  if (n === 200) return "reachable";
  if (n === 401) return "auth_required";
  if (n === 403) return "forbidden";
  if (n === 404) return "not_found";
  if (n === 405) return "method_not_allowed";
  if (Number.isFinite(n) && n >= 200 && n < 300) return "reachable";
  if (Number.isFinite(n) && n >= 500) return "server_error";
  return "blocked";
}

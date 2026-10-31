// ─────────────────────────────────────────────────────────────────────────────
// Burhan — PHASE 02 L1: PROVENANCE MODEL (spec §2)
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

/** Build a structured why() answer (spec §6).
 *
 *  v4.2.1-L1 (supervisor ruling 2026-10-03): this function is the SINGLE
 *  construction path for every node/edge why-answer in the twin (the
 *  pipeline), so the VERIFIED soundness gate lives HERE and runs on every
 *  construction:
 *    - VERIFIED/REFUTED evidenceRefs are set ONLY from extra.evidenceRefs.
 *      The old `?? sourceRefs` fallback laundered source addresses (raw
 *      output locations) into "evidence" — that loophole is closed.
 *    - A VERIFIED answer without evidence references is downgraded to UNKNOWN
 *      fail-closed (verifiedClaimIsSound), with a downgradedFrom marker.
 */
export function why(
  provenance: Provenance,
  reason: string,
  sourceRefs: string[],
  extra?: { inferenceReason?: string; evidenceRefs?: string[] },
): WhyAnswer {
  const w: WhyAnswer = { provenance, reason, sourceRefs };
  if (provenance === "INFERRED") w.inferenceReason = extra?.inferenceReason ?? reason;
  if (provenance === "VERIFIED" || provenance === "REFUTED") {
    w.evidenceRefs = extra?.evidenceRefs; // explicit only — never fabricated from sourceRefs
  }
  if (!verifiedClaimIsSound(w)) {
    // Gate tripped in the pipeline (INV-04): fail closed, never fabricate.
    w.provenance = "UNKNOWN";
    w.evidenceRefs = undefined;
    w.reason = `${reason} [gate: VERIFIED without evidence refs — downgraded to UNKNOWN]`;
    w.downgradedFrom = "VERIFIED";
  }
  return w;
}

/** VERIFIED soundness gate (INV-04): VERIFIED requires non-empty evidence
 *  references. Called by why() on EVERY construction — the pipeline choke
 *  point (supervisor ruling 2026-10-03: was dead code under a comment
 *  implying it guarded; now wired and proven by suite tests E13). */
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

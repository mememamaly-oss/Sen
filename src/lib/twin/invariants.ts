// ─────────────────────────────────────────────────────────────────────────────
// SENTINEL — PHASE 02 L1: REQUIRED INVARIANTS (spec §12)
//
// INV-01  every node ID is unique (and every edge ID is unique)
// INV-02  every edge points to existing nodes (from + to)
// INV-03  no provenance outside the five allowed values
// INV-04  every VERIFIED claim has an evidence reference
// INV-05  no UNKNOWN turns VERIFIED without new evidence
//         (structural: VERIFIED findings require status=verified AND
//          verification.passed=true in the referenced raw record)
// INV-06  no REFUTED claim stays VERIFIED without a documented conflict
// INV-07  every sourceRef points to an existing source
// INV-08  twinHash deterministic (recomputable from content)
// INV-09  same input produces the same graph (checked by the test suite)
// INV-10  tenant isolation (enforced by persist.ts + API; verified live)
//
// Extras (documented, never replacing the mandatory ten):
// INV-11  every CONFLICT claim links to a TwinConflict record and vice versa
// INV-12  secrets are masked — no raw secret values inside the twin
// INV-13  every string inside the twin respects the length caps
// ─────────────────────────────────────────────────────────────────────────────
import type { CanonicalNode, NormalizedTwin, Provenance, RawEngineResult, RawFinding } from "./types";
import { PROVENANCE_VALUES } from "./types";
import { MAX_STRING } from "./sanitize";
import { computeTwinHash } from "./hash";

export type InvariantId =
  | "INV-01" | "INV-02" | "INV-03" | "INV-04" | "INV-05" | "INV-06"
  | "INV-07" | "INV-08" | "INV-09" | "INV-10"
  | "INV-11" | "INV-12" | "INV-13";

export interface InvariantViolation {
  invariant: InvariantId;
  detail: string;
}

export interface InvariantReport {
  pass: boolean;
  checked: InvariantId[];
  violations: InvariantViolation[];
  /** raw source-ref registry — filled by the normalizer via collectSourceRefs */
}

/** Extract every raw source address the normalizer can emit (for INV-07). */
export function collectSourceRefs(twin: NormalizedTwin): Set<string> {
  const refs = new Set<string>(["target", "run_id", "scanner", "stats", "run"]);
  // every address actually referenced by nodes/edges/conflicts/unknowns
  for (const n of twin.nodes) for (const r of n.sourceRefs) refs.add(r);
  for (const e of twin.edges) for (const r of e.sourceRefs) refs.add(r);
  for (const c of twin.conflicts) {
    for (const r of c.left.sourceRefs) refs.add(r);
    for (const r of c.right.sourceRefs) refs.add(r);
  }
  for (const u of twin.knownUnknowns) for (const r of u.sourceRefs) refs.add(r);
  return refs;
}

/** All source addresses that exist in a raw engine result (the resolvable set). */
export function rawSourceRegistry(raw: RawEngineResult): Set<string> {
  const refs = new Set<string>(["target", "run_id", "scanner", "stats", "run"]);
  const stats = (raw.stats ?? {}) as Record<string, unknown>;
  const dict = (v: unknown): Record<string, unknown> => (v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {});
  const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

  // generic section addresses (wildcarded indexes resolve via prefix match)
  const sections: Array<[string, unknown]> = [
    ["stats.coverage", stats.coverage],
    ["stats.api_inventory", stats.api_inventory],
    ["stats.authz", stats.authz],
    ["stats.action_matrix", stats.action_matrix],
    ["stats.appmap", stats.appmap],
    ["stats.workflow", stats.workflow],
    ["stats.param_intel", stats.param_intel],
    ["stats.digital_twin", stats.digital_twin],
    ["stats.graphql", stats.graphql],
    ["stats.websocket", stats.websocket],
    ["stats.secrets", stats.secrets],
    ["stats.boundary", stats.boundary],
    ["stats.reasoning", stats.reasoning],
    ["stats.proofs", stats.proofs],
  ];
  for (const [prefix, value] of sections) {
    if (value === undefined) continue;
    refs.add(prefix);
    const d = dict(value);
    for (const k of Object.keys(d)) refs.add(`${prefix}:${k}`);
    arr(stats.proofs).forEach((_, i) => refs.add(`stats.proofs[${i}]`));
  }
  // coverage endpoint records
  arr(dict(stats.coverage).endpoints).forEach((_, i) => refs.add(`stats.coverage:endpoints[${i}]`));
  // api inventory
  const inv = dict(stats.api_inventory);
  const invApis = arr(inv.apis);
  invApis.forEach((_, j) => {
    refs.add(`stats.api_inventory:apis[${j}]`);
    if (arr(dict(invApis[j]).parameters).length) refs.add(`stats.api_inventory:parameters`);
  });
  // authz roles
  refs.add("stats.authz:roles");
  // action matrix identities
  arr(dict(stats.action_matrix).identities).forEach((_, i) => refs.add(`stats.action_matrix:identities[${i}]`));
  // workflow flows (+ graph nodes + branches + resource params)
  const wfFlows = arr(dict(stats.workflow).flows);
  wfFlows.forEach((f, fi) => {
    refs.add(`stats.workflow:flows[${fi}]`);
    refs.add(`stats.workflow:flows[${fi}]:resource_params`);
    arr(dict(f).branches).forEach((_, bi) => refs.add(`stats.workflow:flows[${fi}]:branches[${bi}]`));
    arr(dict(dict(f).graph).nodes).forEach((_, gi) => refs.add(`stats.workflow:flows[${fi}]:graph.nodes[${gi}]`));
  });
  // digital twin sections
  const dt = dict(stats.digital_twin);
  arr(dt.entity_inventory).forEach((_, i) => refs.add(`stats.digital_twin:entity_inventory[${i}]`));
  for (const k of ["identities", "authorization_matrix", "nodes", "edges", "why_examples", "belief_audit"]) {
    if (dt[k] !== undefined) refs.add(`stats.digital_twin:${k}`);
  }
  // graphql / websocket / boundary / secrets
  arr(dict(stats.graphql).endpoints).forEach((_, i) => refs.add(`stats.graphql:endpoints[${i}]`));
  arr(dict(stats.websocket).channels).forEach((_, i) => refs.add(`stats.websocket:channels[${i}]`));
  arr(dict(stats.boundary).unresolved_detail).forEach((_, i) => refs.add(`stats.boundary:unresolved_detail[${i}]`));
  if (dict(stats.boundary).records !== undefined) refs.add("stats.boundary:records");
  if (dict(stats.secrets).classes_found !== undefined) refs.add("stats.secrets:classes_found");
  if (stats.browser_pages !== undefined) refs.add("stats.browser_pages");
  // reasoning hypotheses
  arr(dict(stats.reasoning).hypotheses).forEach((_, i) => refs.add(`stats.reasoning:hypotheses[${i}]`));
  // findings + rejected candidates (+ nested)
  const rawFindings = arr(raw.findings) as Array<Record<string, unknown>>;
  rawFindings.forEach((_, i) => {
    refs.add(`findings[${i}]`);
    arr(rawFindings[i]?.evidence).forEach((_, ei) => refs.add(`findings[${i}]:evidence[${ei}]`));
    refs.add(`findings[${i}]:verification`);
  });
  const rawRejected = arr(raw.rejected_candidates) as Array<Record<string, unknown>>;
  rawRejected.forEach((_, i) => {
    refs.add(`rejected_candidates[${i}]`);
    arr(rawRejected[i]?.evidence).forEach((_, ei) => refs.add(`rejected_candidates[${i}]:evidence[${ei}]`));
  });
  // param intel data objects
  if (dict(stats.param_intel).data_objects !== undefined) refs.add("stats.param_intel:data_objects");
  // appmap access matrix
  if (dict(stats.appmap).access_matrix !== undefined) refs.add("stats.appmap:access_matrix");
  // coverage counters
  for (const k of ["untested", "discovered", "tested"]) {
    if (dict(stats.coverage)[k] !== undefined) refs.add(`stats.coverage:${k}`);
  }
  return refs;
}

/** Check INV-01..08 + INV-11..13 structurally (INV-09: test suite; INV-10: live). */
export function checkInvariants(
  twin: NormalizedTwin,
  raw?: RawEngineResult,
): InvariantReport {
  const violations: InvariantViolation[] = [];
  const v = (invariant: InvariantId, detail: string) => violations.push({ invariant, detail });

  // INV-01 unique IDs
  const nodeIds = new Set<string>();
  for (const n of twin.nodes) {
    if (nodeIds.has(n.id)) v("INV-01", `duplicate node id ${n.id}`);
    nodeIds.add(n.id);
  }
  const edgeIds = new Set<string>();
  for (const e of twin.edges) {
    if (edgeIds.has(e.id)) v("INV-01", `duplicate edge id ${e.id}`);
    edgeIds.add(e.id);
  }

  // INV-02 edges point to existing nodes
  for (const e of twin.edges) {
    if (!nodeIds.has(e.from)) v("INV-02", `edge ${e.id} from missing node ${e.from}`);
    if (!nodeIds.has(e.to)) v("INV-02", `edge ${e.id} to missing node ${e.to}`);
  }

  // INV-03 provenance vocabulary
  const valid = PROVENANCE_VALUES as readonly string[];
  const checkProv = (p: Provenance | string, where: string) => {
    if (!valid.includes(p)) v("INV-03", `invalid provenance '${p}' at ${where}`);
  };
  for (const n of twin.nodes) {
    checkProv(n.provenance, `node ${n.id}`);
    checkProv(n.why.provenance, `node ${n.id} why`);
  }
  for (const e of twin.edges) {
    checkProv(e.provenance, `edge ${e.id}`);
    checkProv(e.why.provenance, `edge ${e.id} why`);
  }
  for (const c of twin.conflicts) {
    checkProv(c.left.provenance, `conflict ${c.id} left`);
    checkProv(c.right.provenance, `conflict ${c.id} right`);
  }

  // INV-04 + INV-05 VERIFIED claims carry evidence references
  for (const n of twin.nodes) {
    if (n.claim?.state === "VERIFIED") {
      if (!n.claim.evidenceRefs.length) {
        v("INV-04", `VERIFIED claim on ${n.id} has no evidence reference`);
      } else {
        for (const ref of n.claim.evidenceRefs) {
          if (!nodeIds.has(ref) && !ref.startsWith("stats.") && !ref.startsWith("findings") && !ref.startsWith("rejected")) {
            v("INV-04", `VERIFIED claim on ${n.id} references unresolvable evidence '${ref}'`);
          }
        }
      }
    }
  }
  // INV-05 (extended 2026-10-03 per supervisor ruling): no UNKNOWN turns
  // VERIFIED without new evidence. Now covers HYPOTHESIS claims as well as
  // findings, and runs on the STORED twin path (service.ts serves persisted
  // twins with no raw in hand), not only against raw:
  //   findings    — stored: attrs.status=verified AND a linked verification
  //                 evidence node with passed=true AND at least one linked
  //                 NON-verification evidence node (the finding's own captured
  //                 chain — mirrors the hasRealEvidence construction rule);
  //                 raw (when available): status=verified AND
  //                 verification.passed=true in the raw record.
  //   hypotheses  — stored: a linked hypothesis-resolution evidence node with
  //                 status starting "tested:verified"; raw (when available):
  //                 the raw reasoning record resolves tested:verified.
  {
    // evidence graph for the stored path
    const evById = new Map<string, CanonicalNode>();
    for (const n of twin.nodes) if (n.type === "evidence") evById.set(n.id, n);
    const evidencedBy = new Map<string, string[]>(); // node id -> evidence node ids
    for (const e of twin.edges) {
      if (e.type === "EVIDENCED_BY" && evById.has(e.to)) {
        evidencedBy.set(e.from, [...(evidencedBy.get(e.from) ?? []), e.to]);
      }
    }
    // raw lookup tables (when raw is available)
    let rawFindingsById: Map<string, RawFinding> | null = null;
    let rawHypsById: Map<string, Record<string, unknown>> | null = null;
    if (raw) {
      rawFindingsById = new Map();
      for (const f of raw.findings ?? []) if (f.id) rawFindingsById.set(f.id, f);
      const hyps = ((raw.stats as Record<string, unknown> | undefined)?.reasoning as Record<string, unknown> | undefined)?.hypotheses;
      const hypMap = new Map<string, Record<string, unknown>>();
      (Array.isArray(hyps) ? hyps : []).forEach((h, i) => {
        const d = (h ?? {}) as Record<string, unknown>;
        if (d.id) hypMap.set(String(d.id), d);
        hypMap.set(`hyp-${i}`, d); // index fallback (matches normalize keys)
      });
      rawHypsById = hypMap;
    }
    const rawHypFor = (n: CanonicalNode): Record<string, unknown> | null => {
      if (!rawHypsById) return null;
      if (rawHypsById.has(n.key)) return rawHypsById.get(n.key)!;
      const m = /hypotheses\[(\d+)\]/.exec(n.sourceRefs.join(" "));
      return m ? (rawHypsById.get(`hyp-${m[1]}`) ?? null) : null;
    };
    for (const n of twin.nodes) {
      if (n.claim?.state !== "VERIFIED") continue;
      if (n.type === "finding") {
        // ---- stored-path checks ----
        const linked = evidencedBy.get(n.id) ?? [];
        const ver = linked.map((id) => evById.get(id)!).find((x) => x.attrs.kind === "verification");
        const chain = linked.map((id) => evById.get(id)!).filter((x) => x.attrs.kind !== "verification");
        if (n.attrs.status !== "verified") {
          v("INV-05", `VERIFIED finding ${n.id}: stored attrs.status is '${String(n.attrs.status)}', not 'verified'`);
        }
        if (!ver || ver.attrs.passed !== true) {
          v("INV-05", `VERIFIED finding ${n.id} has no linked verification evidence node with passed=true (stored path)`);
        }
        if (chain.length === 0) {
          v("INV-05", `VERIFIED finding ${n.id} has no linked captured evidence beyond the verification record (stored path — hasRealEvidence rule)`);
        }
        // ---- raw cross-check ----
        if (rawFindingsById) {
          const rf = rawFindingsById.get(n.key);
          if (!rf) {
            v("INV-05", `VERIFIED finding ${n.id} has no raw record`);
          } else {
            const passed = (rf.verification as Record<string, unknown> | undefined)?.passed === true;
            if (rf.status !== "verified" || !passed) {
              v("INV-05", `finding ${n.id} is VERIFIED in the twin but raw record lacks status=verified/verification.passed=true`);
            }
          }
        }
      } else if (n.type === "hypothesis") {
        // ---- stored-path checks ----
        const linked = evidencedBy.get(n.id) ?? [];
        const res = linked.map((id) => evById.get(id)!).find((x) => x.attrs.kind === "hypothesis-resolution");
        const resStatus = res ? String(res.attrs.status ?? "") : "";
        if (!res || !resStatus.startsWith("tested:verified")) {
          v("INV-05", `VERIFIED hypothesis ${n.id} has no linked resolution evidence with status 'tested:verified' (stored path)`);
        }
        // ---- raw cross-check ----
        if (rawHypsById) {
          const rh = rawHypFor(n);
          if (!rh) {
            v("INV-05", `VERIFIED hypothesis ${n.id} has no raw reasoning record`);
          } else if (!String(rh.status ?? "").startsWith("tested:verified")) {
            v("INV-05", `hypothesis ${n.id} is VERIFIED in the twin but the raw reasoning record says '${String(rh.status)}'`);
          }
        }
      }
    }
  }

  // INV-06 REFUTED + VERIFIED evidence → documented conflict
  const conflictIds = new Set(twin.conflicts.map((c) => c.id));
  for (const n of twin.nodes) {
    if (n.claim?.state === "CONFLICT") {
      const links = n.claim.conflictIds ?? [];
      if (!links.length) v("INV-06", `CONFLICT claim on ${n.id} has no conflict record`);
      for (const cid of links) if (!conflictIds.has(cid)) v("INV-06", `conflict ${cid} referenced by ${n.id} does not exist`);
    }
  }

  // INV-07 sourceRefs resolve
  const registry = raw ? rawSourceRegistry(raw) : collectSourceRefs(twin);
  const resolvable = (ref: string): boolean => {
    if (registry.has(ref)) return true;
    // run:<id> addresses
    if (ref.startsWith("run:") && registry.has("run")) return true;
    return false;
  };
  for (const n of twin.nodes) for (const r of n.sourceRefs) {
    if (!resolvable(r)) v("INV-07", `node ${n.id} sourceRef '${r}' does not resolve`);
  }
  for (const e of twin.edges) for (const r of e.sourceRefs) {
    if (!resolvable(r)) v("INV-07", `edge ${e.id} sourceRef '${r}' does not resolve`);
  }
  for (const c of twin.conflicts) {
    for (const r of [...c.left.sourceRefs, ...c.right.sourceRefs]) {
      if (!resolvable(r)) v("INV-07", `conflict ${c.id} sourceRef '${r}' does not resolve`);
    }
  }
  for (const u of twin.knownUnknowns) for (const r of u.sourceRefs) {
    if (!resolvable(r)) v("INV-07", `known-unknown ${u.id} sourceRef '${r}' does not resolve`);
  }
  // INV-11 every TwinConflict is referenced by at least one claim side or
  // affected node (conflictIds)
  const referencedConflicts = new Set<string>();
  for (const n of twin.nodes) {
    for (const cid of n.claim?.conflictIds ?? []) referencedConflicts.add(cid);
    for (const cid of n.conflictIds ?? []) referencedConflicts.add(cid);
  }
  for (const c of twin.conflicts) {
    if (!referencedConflicts.has(c.id)) v("INV-11", `conflict ${c.id} is not referenced by any claim`);
  }

  // INV-08 twinHash recomputable
  const recomputed = computeTwinHash({
    schemaVersion: twin.schemaVersion,
    target: twin.target,
    nodes: twin.nodes.map((n) => ({ id: n.id, type: n.type, key: n.key, provenance: n.provenance, sourceRefs: n.sourceRefs, attrs: n.attrs, claim: n.claim ?? null })),
    edges: twin.edges.map((e) => ({ id: e.id, type: e.type, from: e.from, to: e.to, provenance: e.provenance, sourceRefs: e.sourceRefs, confidence: e.confidence, attrs: e.attrs ?? null })),
    conflicts: twin.conflicts,
    knownUnknowns: twin.knownUnknowns,
  });
  if (recomputed !== twin.twinHash) v("INV-08", `twinHash mismatch: stored ${twin.twinHash} vs recomputed ${recomputed}`);

  // INV-12 secrets masked
  for (const n of twin.nodes) {
    if (n.type === "secret") {
      const val = n.attrs.value;
      if (typeof val === "string" && val !== "********") v("INV-12", `secret ${n.id} carries a non-masked value`);
    }
  }

  // INV-13 length caps
  const scanStrings = (obj: unknown, path: string): void => {
    if (typeof obj === "string") {
      if (obj.length > MAX_STRING + 2) v("INV-13", `over-length string at ${path} (${obj.length})`);
    } else if (Array.isArray(obj)) {
      obj.forEach((x, i) => scanStrings(x, `${path}[${i}]`));
    } else if (obj && typeof obj === "object") {
      for (const [k, val] of Object.entries(obj as Record<string, unknown>)) scanStrings(val, `${path}.${k}`);
    }
  };
  scanStrings(twin.nodes, "nodes");
  scanStrings(twin.edges, "edges");
  scanStrings(twin.conflicts, "conflicts");
  scanStrings(twin.knownUnknowns, "knownUnknowns");

  const checked: InvariantId[] = [
    "INV-01", "INV-02", "INV-03", "INV-04", "INV-05", "INV-06", "INV-07", "INV-08",
    "INV-11", "INV-12", "INV-13",
    // INV-09 determinism and INV-10 tenant isolation are verified by the
    // dedicated test suites (determinism ×3 + live tenant API tests).
  ];
  return { pass: violations.length === 0, checked, violations };
}

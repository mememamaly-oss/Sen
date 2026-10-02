// ─────────────────────────────────────────────────────────────────────────────
// SENTINEL — PHASE 02 L1: TWIN NORMALIZER (spec §1/§3/§4/§5/§6)
//
// Rebuilds a canonical Security Twin from the artifacts a COMPLETED scan
// already produced. SENTINEL does not invent a twin: every node, edge and
// claim is either OBSERVED in the raw output, INFERRED by a documented rule
// with sourceRefs, VERIFIED by engine evidence, REFUTED by an engine result,
// or UNKNOWN. Deterministic: identical raw input → identical IDs, graph and
// twinHash (no timestamps, no random values, no process state).
//
// Documented inference rules (the ONLY inference L1 performs):
//   R1  host EXPOSES endpoint        — every endpoint was observed at the host
//   R2  object MINTS/CONSUMES edges  — engine workflow rule "producer steps
//                                      mint, the final step consumes"
//                                      (twin.py, replicated verbatim)
//   R3  entity EXPOSES endpoint      — engine entity_inventory projection
//   R4  session for workflow graph   — execution identity references in the
//                                      serialized workflow graph
// Everything else is direct observation of serialized engine data.
// ─────────────────────────────────────────────────────────────────────────────
import type {
  CanonicalEdge,
  CanonicalEdgeType,
  CanonicalNode,
  CanonicalNodeType,
  KnownUnknown,
  NormalizedTwin,
  Provenance,
  RawEngineResult,
  RawFinding,
  TwinConflict,
  TwinCounts,
} from "./types";
import { PROVENANCE_VALUES } from "./types";
import { why, verdictForStatus } from "./provenance";
import { TWIN_SCHEMA_VERSION, computeRawHash, computeTwinHash, conflictId, edgeId, nodeId, unknownId } from "./hash";
import {
  MAX_EDGES,
  MAX_NODES,
  byKey,
  hostOf,
  methodOf,
  originOf,
  pathOf,
  safeFloat,
  safeInt,
  sanitizeLabel,
  sanitizeString,
} from "./sanitize";

// ── graph builder state ───────────────────────────────────────────────────────

interface Builder {
  nodes: Map<string, CanonicalNode>;
  edges: Map<string, CanonicalEdge>;
  conflicts: Map<string, TwinConflict>;
  knownUnknowns: Map<string, KnownUnknown>;
  sources: Map<string, true>;
  notes: string[];
  truncated: boolean;
}

function reg(b: Builder, ref: string): string {
  b.sources.set(ref, true);
  return ref;
}

function addNode(
  b: Builder,
  type: CanonicalNodeType,
  key: string,
  label: string,
  provenance: Provenance,
  reason: string,
  sourceRefs: string[],
  attrs: Record<string, unknown>,
  extra?: { inferenceReason?: string; evidenceRefs?: string[] },
): CanonicalNode {
  const id = nodeId(type, key);
  const existing = b.nodes.get(id);
  if (existing) {
    existing.sourceRefs = Array.from(new Set([...existing.sourceRefs, ...sourceRefs])).sort(byKey);
    for (const [k, v] of Object.entries(attrs)) {
      const cur = existing.attrs[k];
      if (cur === undefined || cur === "" || cur === null) {
        existing.attrs[k] = v;
      } else if (Array.isArray(cur) && Array.isArray(v)) {
        existing.attrs[k] = Array.from(new Set([...cur, ...v])).sort();
      }
    }
    return existing;
  }
  // v4.2.1-L1: the why() answer is the single authority — if its VERIFIED
  // gate fail-closed (downgrade to UNKNOWN), the NODE mirrors the downgraded
  // provenance so node.provenance and node.why.provenance can never diverge.
  const w = why(provenance, reason, sourceRefs, extra);
  const n: CanonicalNode = {
    id, type, key, label: label || key, provenance: w.provenance,
    sourceRefs: [...sourceRefs].sort(byKey),
    why: w,
    attrs,
  };
  b.nodes.set(id, n);
  return n;
}

function addEdge(
  b: Builder,
  type: CanonicalEdgeType,
  from: string,
  to: string,
  provenance: Provenance,
  reason: string,
  sourceRefs: string[],
  confidence: number,
  attrs?: Record<string, unknown>,
  extra?: { inferenceReason?: string; evidenceRefs?: string[] },
): CanonicalEdge | null {
  if (from === to || !from || !to) return null;
  const id = edgeId(from, to, type);
  const existing = b.edges.get(id);
  if (existing) {
    existing.sourceRefs = Array.from(new Set([...existing.sourceRefs, ...sourceRefs])).sort(byKey);
    return existing;
  }
  // v4.2.1-L1: mirror the (possibly gate-downgraded) provenance from why().
  const w = why(provenance, reason, sourceRefs, extra);
  const e: CanonicalEdge = {
    id, type, from, to, provenance: w.provenance,
    sourceRefs: [...sourceRefs].sort(byKey),
    confidence: safeFloat(confidence, 1),
    why: w,
  };
  if (attrs && Object.keys(attrs).length) e.attrs = attrs;
  b.edges.set(id, e);
  return e;
}

function addConflict(
  b: Builder, kind: string, leftId: string, rightId: string,
  left: { provenance: Provenance; summary: string; sourceRefs: string[] },
  right: { provenance: Provenance; summary: string; sourceRefs: string[] },
  description: string,
): string {
  const id = conflictId(kind, leftId, rightId);
  if (!b.conflicts.has(id)) {
    b.conflicts.set(id, {
      id, kind, description, resolution: "UNRESOLVED",
      left: { claimRef: leftId, provenance: left.provenance, summary: left.summary, sourceRefs: left.sourceRefs },
      right: { claimRef: rightId, provenance: right.provenance, summary: right.summary, sourceRefs: right.sourceRefs },
    });
  }
  return id;
}

function addUnknown(b: Builder, dimension: string, description: string, sourceRefs: string[]): void {
  const id = unknownId(dimension, description);
  if (b.knownUnknowns.has(id)) return;
  b.knownUnknowns.set(id, { id, dimension, description, sourceRefs: [...sourceRefs].sort(byKey) });
}

// ── defensive raw accessors ───────────────────────────────────────────────────

type Dict = Record<string, unknown>;
const asDict = (v: unknown): Dict => (v && typeof v === "object" && !Array.isArray(v) ? (v as Dict) : {});
const asArray = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown, max = 256): string => sanitizeString(v, max);

// ═════════════════════════════════════════════════════════════════════════════
// MAIN
// ═════════════════════════════════════════════════════════════════════════════

export interface NormalizeOptions {
  /** loader notes (db-reconstruction gaps etc.) — recorded as known unknowns */
  notes?: string[];
  /** where the raw input came from — recorded in scope (NOT part of the hash) */
  rawSource?: "result.json" | "db-reconstruction";
}

export function normalizeTwin(raw: RawEngineResult, options: NormalizeOptions = {}): NormalizedTwin {
  const b: Builder = { nodes: new Map(), edges: new Map(), conflicts: new Map(), knownUnknowns: new Map(), sources: new Map(), notes: options.notes ?? [], truncated: false };

  const stats = asDict(raw.stats);
  const target = str(raw.target, 512) || "(unknown target)";
  const origin = originOf(raw.target) || target;
  const host = hostOf(raw.target) || target;
  const runId = str(raw.run_id, 64);
  const scanner = str(raw.scanner, 64);

  reg(b, "target"); reg(b, "run_id"); reg(b, "scanner"); reg(b, "stats");
  if (runId) reg(b, `run:${runId}`);

  // ── 1. application + host ─────────────────────────────────────────────────
  const app = addNode(b, "application", origin, sanitizeLabel(host || origin), "OBSERVED",
    "Scan target recorded in the engine result", [reg(b, "target")],
    { runId, scanner });
  const hostNode = addNode(b, "host", host, sanitizeLabel(host), "OBSERVED",
    "Target hostname parsed from the scanned URL", [reg(b, "target")], {});
  addEdge(b, "CONTAINS", app.id, hostNode.id, "OBSERVED",
    "The application is served from this host (target URL)", [reg(b, "target")], 1);

  // ── 2. endpoints (coverage × api_inventory merge) ─────────────────────────
  const coverage = asDict(stats.coverage);
  const covEndpoints = asArray(coverage.endpoints);
  const apis = asArray(asDict(stats.api_inventory).apis);

  interface EpAgg {
    method: string; path: string; sources: Set<string>; activity: string[]; skips: string[];
    baseline?: number; findingsCount?: number; findingTypes: string[];
    authentication?: string; coverageStatus?: string; channel?: string;
    refs: string[]; params: string[];
  }
  const endpointAgg = new Map<string, EpAgg>();
  const epKey = (m: string, p: string) => `${m} ${p}`;
  const epRefs = (key: string) => endpointAgg.get(key)?.refs ?? [];

  covEndpoints.forEach((rawEp, i) => {
    const ep = asDict(rawEp);
    const method = methodOf(ep.method);
    const path = pathOf(ep.url);
    if (!path) return;
    const key = epKey(method, path);
    let agg = endpointAgg.get(key);
    if (!agg) { agg = { method, path, sources: new Set(), activity: [], skips: [], findingTypes: [], refs: [], params: [] }; endpointAgg.set(key, agg); }
    const ref = reg(b, `stats.coverage:endpoints[${i}]`);
    agg.refs.push(ref);
    const src = str(ep.source, 32); if (src) agg.sources.add(src);
    for (const a of asArray(ep.activity)) agg.activity.push(str(a, 32));
    for (const s of asArray(ep.skips)) agg.skips.push(str(s, 64));
    if (typeof ep.baseline === "number") agg.baseline = safeInt(ep.baseline);
  });

  apis.forEach((rawApi, j) => {
    const api = asDict(rawApi);
    if ((str(api.protocol, 24).toLowerCase() || "http") !== "http") return; // → api nodes later
    const method = methodOf(api.method);
    const path = pathOf(api.path);
    if (!path) return;
    const key = epKey(method, path);
    let agg = endpointAgg.get(key);
    if (!agg) { agg = { method, path, sources: new Set(), activity: [], skips: [], findingTypes: [], refs: [], params: [] }; endpointAgg.set(key, agg); }
    const ref = reg(b, `stats.api_inventory:apis[${j}]`);
    agg.refs.push(ref);
    for (const s of asArray(api.sources)) { const v = str(s, 32); if (v) agg.sources.add(v); }
    if (api.authentication !== undefined) agg.authentication = str(api.authentication, 24);
    if (api.coverage_status !== undefined) agg.coverageStatus = str(api.coverage_status, 24);
    if (api.channel !== undefined) agg.channel = str(api.channel, 64);
    if (api.findings !== undefined) agg.findingsCount = safeInt(api.findings);
    for (const t of asArray(api.finding_types)) { const v = str(t, 48); if (v) agg.findingTypes.push(v); }
    for (const p of asArray(api.parameters)) { const v = str(p, 128); if (v) agg.params.push(v); }
  });

  // create endpoint / browser_surface nodes
  const endpointNodeIds = new Map<string, string>(); // key -> node id
  const browserSurfaceCount = { n: 0 };
  for (const key of Array.from(endpointAgg.keys()).sort(byKey)) {
    const agg = endpointAgg.get(key)!;
    const isBrowser = Array.from(agg.sources).some((s) => s === "dom:browser" || s === "browser");
    const type: CanonicalNodeType = isBrowser ? "browser_surface" : "endpoint";
    if (isBrowser) browserSurfaceCount.n++;
    const attrs: Record<string, unknown> = {
      method: agg.method, path: agg.path,
      sources: Array.from(agg.sources).sort(),
      opClass: agg.method === "GET" ? "READ" : "WRITE",
    };
    if (agg.activity.length) attrs.activity = Array.from(new Set(agg.activity)).sort();
    if (agg.skips.length) attrs.untestedReasons = Array.from(new Set(agg.skips)).sort();
    if (agg.baseline !== undefined) attrs.baseline = agg.baseline;
    if (agg.authentication !== undefined) attrs.authState = agg.authentication;
    if (agg.coverageStatus !== undefined) attrs.coverageStatus = agg.coverageStatus;
    if (agg.channel !== undefined && agg.channel) attrs.channel = agg.channel;
    if (agg.findingsCount !== undefined) attrs.findingsCount = agg.findingsCount;
    if (agg.findingTypes.length) attrs.findingTypes = Array.from(new Set(agg.findingTypes)).sort();
    const n = addNode(b, type, key, sanitizeLabel(key), "OBSERVED",
      isBrowser
        ? "Surface discovered by the engine's browser renderer (dom:browser)"
        : "Surface observed in the engine's coverage / API inventory",
      agg.refs, attrs);
    endpointNodeIds.set(key, n.id);
    // R1: host exposes endpoint
    addEdge(b, "EXPOSES", hostNode.id, n.id, "OBSERVED",
      "The endpoint was observed at this host during the scan", agg.refs, 1);
  }

  // parameters + USES_PARAMETER
  for (const key of Array.from(endpointAgg.keys()).sort(byKey)) {
    const agg = endpointAgg.get(key)!;
    const epId = endpointNodeIds.get(key);
    if (!epId || !agg.params.length) continue;
    for (const p of Array.from(new Set(agg.params)).sort(byKey)) {
      const pRef = reg(b, `stats.api_inventory:parameters`);
      const pNode = addNode(b, "parameter", `${key}:${p}`, p, "OBSERVED",
        "Parameter observed in the engine's API inventory for this endpoint", [pRef],
        { name: p, endpoint: key });
      addEdge(b, "USES_PARAMETER", epId, pNode.id, "OBSERVED",
        "The endpoint's inventoried requests carry this parameter", [pRef], 1);
    }
  }

  // ── 3. identities + roles ─────────────────────────────────────────────────
  const roleNodeIds = new Map<string, string>();
  const roleKey = (r: string) => {
    const s = str(r, 64);
    if (s === "anon") return "anonymous";
    return s.replace(/^role:/, "");
  };
  const ensureRole = (rawName: string, reason: string, refs: string[]): CanonicalNode => {
    const key = roleKey(rawName);
    const n = addNode(b, "role", key, sanitizeLabel(`role:${key}`), "OBSERVED", reason, refs, {});
    roleNodeIds.set(key, n.id);
    return n;
  };
  const authz = asDict(stats.authz);
  const authzRolesRef = reg(b, "stats.authz:roles");
  for (const r of asArray(authz.roles)) { const v = str(r, 64); if (v) ensureRole(v, "Role exercised by the authz engine", [authzRolesRef]); }

  const actionMatrix = asDict(stats.action_matrix);
  const amIdentities = asArray(actionMatrix.identities);
  const identityNodeIds = new Map<string, string>();
  amIdentities.forEach((rawIdent, i) => {
    const ident = asDict(rawIdent);
    const name = str(ident.name, 128);
    if (!name) return;
    const ref = reg(b, `stats.action_matrix:identities[${i}]`);
    const roleRaw = str(ident.role, 64) || "user";
    const role = ensureRole(roleRaw, "Role carried by an exercised identity (action matrix)", [ref]);
    const n = addNode(b, "identity", name, sanitizeLabel(name), "OBSERVED",
      "Identity exercised during the scan (action matrix)", [ref],
      { role: roleKey(roleRaw) });
    identityNodeIds.set(name, n.id);
    addEdge(b, "HAS_ROLE", n.id, role.id, "OBSERVED",
      "The action matrix records this identity's role", [ref], 1);
  });

  // ── 4. api surfaces (graphql / websocket / non-http inventory) ────────────
  const apiNodeIndex = new Map<string, string>(); // "protocol|path" -> id
  const ensureApiNode = (protocol: string, path: string, label: string, reason: string, refs: string[], attrs: Record<string, unknown>): CanonicalNode => {
    const key = `${protocol}:${path}`;
    const n = addNode(b, "api", key, sanitizeLabel(label), "OBSERVED", reason, refs, { protocol, path, ...attrs });
    apiNodeIndex.set(key, n.id);
    addEdge(b, "CONTAINS", app.id, n.id, "OBSERVED",
      "The API surface belongs to the scanned application", refs, 1);
    return n;
  };
  apis.forEach((rawApi, j) => {
    const api = asDict(rawApi);
    const protocol = str(api.protocol, 24).toLowerCase();
    if (!protocol || protocol === "http") return;
    const path = pathOf(api.path);
    if (!path) return;
    const ref = reg(b, `stats.api_inventory:apis[${j}]`);
    const attrs: Record<string, unknown> = {};
    if (api.channel !== undefined) attrs.channel = str(api.channel, 64);
    if (api.authentication !== undefined) attrs.authState = str(api.authentication, 24);
    if (api.coverage_status !== undefined) attrs.coverageStatus = str(api.coverage_status, 24);
    if (api.findings !== undefined) attrs.findingsCount = safeInt(api.findings);
    const ft = asArray(api.finding_types).map((t) => str(t, 48)).filter(Boolean);
    if (ft.length) attrs.findingTypes = Array.from(new Set(ft)).sort();
    const n = ensureApiNode(protocol, path, sanitizeLabel(`${protocol} ${path}`),
      "API surface in the engine's unified API inventory", [ref], attrs);
    // SPEAKS_PROTOCOL: matching http endpoint
    const epId = endpointNodeIds.get(epKey(methodOf(api.method), path));
    if (epId) addEdge(b, "SPEAKS_PROTOCOL", epId, n.id, "OBSERVED",
      "The endpoint speaks this protocol (engine inventory)", [ref], 1);
  });
  const gql = asDict(stats.graphql);
  asArray(gql.endpoints).forEach((rawE, i) => {
    const e = asDict(rawE);
    const path = pathOf(e.url);
    if (!path) return;
    const ref = reg(b, `stats.graphql:endpoints[${i}]`);
    const attrs: Record<string, unknown> = { source: str(e.source, 32) };
    if (typeof gql.introspected === "number") attrs.introspected = safeInt(gql.introspected);
    if (typeof gql.queries === "number") attrs.queries = safeInt(gql.queries);
    if (typeof gql.mutations === "number") attrs.mutations = safeInt(gql.mutations);
    const n = ensureApiNode("graphql", path, sanitizeLabel(`graphql ${path}`),
      "GraphQL endpoint discovered by the GraphQL engine", [ref], attrs);
    const epId = endpointNodeIds.get(epKey("GET", path)) ?? endpointNodeIds.get(epKey("POST", path));
    if (epId) addEdge(b, "SPEAKS_PROTOCOL", epId, n.id, "OBSERVED",
      "The http endpoint speaks GraphQL (engine discovery)", [ref], 1);
  });
  const ws = asDict(stats.websocket);
  const wsProtocols = asDict(ws.protocols);
  asArray(ws.channels).forEach((rawC, i) => {
    const c = asDict(rawC);
    const path = pathOf(c.url);
    if (!path) return;
    const ref = reg(b, `stats.websocket:channels[${i}]`);
    const attrs: Record<string, unknown> = { source: str(c.source, 32) };
    const proto = str(wsProtocols[str(c.url, 512)], 64);
    if (proto) attrs.protocolName = proto;
    const n = ensureApiNode("websocket", path, sanitizeLabel(`ws ${path}`),
      "WebSocket channel discovered by the WebSocket engine", [ref], attrs);
    const epId = endpointNodeIds.get(epKey("GET", path)) ?? endpointNodeIds.get(epKey("POST", path));
    if (epId) addEdge(b, "SPEAKS_PROTOCOL", epId, n.id, "OBSERVED",
      "The http endpoint upgrades to this WebSocket channel (engine discovery)", [ref], 1);
  });

  // ── 5. workflows / steps / states / branches / sessions / objects ─────────
  const wfStats = asDict(stats.workflow);
  const flows = asArray(wfStats.flows);
  const workflowStepIndex = new Map<string, string>(); // "cluster|index|action" -> id
  flows.forEach((rawFlow, fi) => {
    const flow = asDict(rawFlow);
    const cluster = str(flow.cluster, 256);
    if (!cluster) return;
    const fRef = reg(b, `stats.workflow:flows[${fi}]`);
    const wfAttrs: Record<string, unknown> = {};
    const entry = str(flow.entry, 256); if (entry) wfAttrs.entry = entry;
    const oracle = str(flow.state_oracle, 256); if (oracle) wfAttrs.stateOracle = oracle;
    const rp = asArray(flow.resource_params).map((x) => str(x, 128)).filter(Boolean);
    if (rp.length) wfAttrs.resourceParams = rp.sort();
    const rb = asArray(flow.rollback_paths).map((x) => str(x, 256)).filter(Boolean);
    if (rb.length) wfAttrs.rollbackPaths = rb.sort();
    const bt = asDict(flow.branch_transfer); if (Object.keys(bt).length) wfAttrs.branchTransfer = bt;
    if (flow.approval_step !== undefined && flow.approval_step !== null) wfAttrs.approvalStep = str(flow.approval_step, 256);
    const cp = asArray(flow.cancel_paths).map((x) => str(x, 256)).filter(Boolean);
    if (cp.length) wfAttrs.cancelPaths = cp.sort();
    const rop = asArray(flow.rollback_only_paths).map((x) => str(x, 256)).filter(Boolean);
    if (rop.length) wfAttrs.rollbackOnlyPaths = rop.sort();
    const stt = asArray(flow.state_transitions).map((x) => str(x, 256)).filter(Boolean).slice(0, 8);
    if (stt.length) wfAttrs.stateTransitions = stt;
    const po = asArray(flow.privilege_declared_options).map((o) => {
      const d = asDict(o);
      return { field: str(d.field, 64), value: str(d.value, 64), label: str(d.label, 128) };
    }).filter((o) => o.field || o.value);
    if (po.length) wfAttrs.declaredPrivilegedOptions = po;

    const wf = addNode(b, "workflow", cluster, sanitizeLabel(cluster), "OBSERVED",
      "Workflow cluster learned by the engine's guided walk", [fRef], wfAttrs);

    // steps
    const steps = asArray(flow.steps);
    let prevStepId: string | null = null;
    const stepIds: string[] = [];
    steps.forEach((rawStep, si) => {
      const step = asDict(rawStep);
      const action = str(step.action, 256);
      if (!action) return;
      const method = methodOf(step.method);
      const sKey = `${cluster}::step${si + 1}:${method} ${action}`;
      const sAttrs: Record<string, unknown> = { index: si + 1, action, method };
      const sn = addNode(b, "workflow_step", sKey, sanitizeLabel(`${si + 1}. ${action}`), "OBSERVED",
        "Step submitted during the engine's guided workflow walk", [fRef], sAttrs);
      stepIds.push(sn.id);
      workflowStepIndex.set(`${cluster}|${si + 1}|${action}`, sn.id);
      addEdge(b, "PART_OF", sn.id, wf.id, "OBSERVED",
        "The step belongs to this learned workflow chain", [fRef], 1);
      if (prevStepId) addEdge(b, "LEADS_TO", prevStepId, sn.id, "OBSERVED",
        "Observed step order in the guided walk", [fRef], 1);
      prevStepId = sn.id;
      const epId = endpointNodeIds.get(epKey(method, pathOf(action)));
      if (epId) addEdge(b, "TESTED_BY", epId, sn.id, "OBSERVED",
        "The step exercised this endpoint during the walk", [fRef], 1);
    });

    // workflow graph (richer per-step records)
    const graph = asDict(flow.graph);
    const graphNodes = asArray(graph.nodes);
    const sessionIds = new Map<string, string>();
    graphNodes.forEach((rawGn, gi) => {
      const gn = asDict(rawGn);
      const idx = safeInt(gn.index, -1);
      const action = str(gn.action, 256);
      const stepId = workflowStepIndex.get(`${cluster}|${idx + 1}|${action}`);
      const gRef = reg(b, `stats.workflow:flows[${fi}]:graph.nodes[${gi}]`);
      if (stepId) {
        const node = b.nodes.get(stepId);
        if (node) {
          const ident = str(gn.identity, 128);
          if (ident) node.attrs.executionIdentity = ident;
          const pre = asArray(gn.preconditions).map((x) => str(x, 64)).filter(Boolean);
          if (pre.length) node.attrs.preconditions = pre.sort();
          const prm = asArray(gn.parameters).map((x) => str(x, 64)).filter(Boolean);
          if (prm.length) node.attrs.parameters = prm.sort();
          const tok = asArray(gn.extracted_tokens).map((x) => str(x, 64)).filter(Boolean);
          if (tok.length) node.attrs.extractedTokens = tok.sort();
          const robj = asArray(gn.referenced_objects).map((x) => str(x, 64)).filter(Boolean);
          if (robj.length) node.attrs.referencedObjects = robj.sort();
          const ic = str(gn.impact_class, 48); if (ic) node.attrs.impactClass = ic;
          const conf = gn.confidence; if (typeof conf === "number") node.attrs.confidence = safeFloat(conf);
          // R4: execution session
          if (ident) {
            let sId = sessionIds.get(ident);
            if (!sId) {
              const knownIdentity = identityNodeIds.get(ident);
              if (knownIdentity) {
                sId = knownIdentity;
              } else {
                const sn = addNode(b, "session", ident, sanitizeLabel(ident), "OBSERVED",
                  "Execution identity referenced by the serialized workflow graph", [gRef], {});
                sId = sn.id;
              }
              sessionIds.set(ident, sId);
            }
            addEdge(b, "DEPENDS_ON", stepId, sId, "OBSERVED",
              "The step's execution depended on this authenticated session (workflow graph)", [gRef], 1);
          }
        }
      }
    });

    // states (execution markers via the state oracle)
    const markers = asDict(flow.execution_markers);
    for (const kind of ["gained", "lost"]) {
      for (const w of asArray(markers[kind])) {
        const word = str(w, 64);
        if (!word) continue;
        const st = addNode(b, "state", `${cluster}:${word}`, sanitizeLabel(word), "OBSERVED",
          kind === "gained"
            ? "State observed as reached (execution marker via the workflow state oracle)"
            : "State observed as lost (execution marker via the workflow state oracle)",
          [fRef], { observed: kind === "gained" ? "execution_gained" : "execution_lost" });
        addEdge(b, "TRANSITIONS_TO", wf.id, st.id, "OBSERVED",
          "The workflow's state oracle observed this state", [fRef], 1);
      }
    }

    // branches (declared options observed on the walk's forms)
    asArray(flow.branches).forEach((rawBr, bi) => {
      const br = asDict(rawBr);
      const field = str(br.field, 64); const value = str(br.value, 64);
      if (!field && !value) return;
      const bRef = reg(b, `stats.workflow:flows[${fi}]:branches[${bi}]`);
      const bNode = addNode(b, "branch", `${cluster}:${field || "?"}=${value || "?"}`,
        sanitizeLabel(`${field || "?"}=${value || "?"}`), "OBSERVED",
        "Branch option declared on a form observed during the guided walk", [bRef],
        { field, value, label: str(br.label, 128), class: str(br.class, 32), functional: br.functional === true });
      addEdge(b, "PART_OF", bNode.id, wf.id, "OBSERVED",
        "The branch belongs to this workflow", [bRef], 1);
    });

    // declared privilege → role
    const adminRole = roleNodeIds.get("admin");
    if (adminRole) {
      for (const opt of po) {
        if (opt.value || opt.label) {
          addEdge(b, "DECLARED_PRIVILEGE", wf.id, adminRole, "OBSERVED",
            "A privileged option was declared on this workflow's form", [fRef], 1,
            { option: opt.value, label: opt.label });
        }
      }
    }

    // R2: objects minted/consumed (engine rule: producer steps mint, last consumes)
    for (const rpName of rp) {
      const objRefs = [fRef];
      const oRef = reg(b, `stats.workflow:flows[${fi}]:resource_params`);
      objRefs.push(oRef);
      const obj = addNode(b, "object", rpName, sanitizeLabel(rpName), "INFERRED",
        "Resource parameter treated as a data object by the workflow engine", objRefs,
        { resourceParamOf: [cluster] },
        { inferenceReason: "Engine workflow rule: resource parameters name the objects the flow mints and consumes (twin.py)" });
      stepIds.forEach((sid, si) => {
        const isLast = si === stepIds.length - 1;
        addEdge(b, isLast ? "CONSUMES" : "MINTS", sid, obj.id, "INFERRED",
          isLast ? "Final step consumes the object (engine rule)" : "Producer step mints the object (engine rule)",
          objRefs, 1, { param: rpName },
          { inferenceReason: "Engine workflow rule: producer steps mint, the final step consumes (twin.py)" });
      });
    }
  });

  // ── 6. data objects (param intelligence) + entities ───────────────────────
  const paramIntel = asDict(stats.param_intel);
  const dataObjects = asDict(paramIntel.data_objects);
  for (const name of Object.keys(dataObjects).sort(byKey)) {
    const urls = asArray(dataObjects[name]).map((u) => str(u, 256)).filter(Boolean).sort();
    const ref = reg(b, `stats.param_intel:data_objects`);
    const obj = addNode(b, "object", name, sanitizeLabel(name), "INFERRED",
      "Data object projected from parameter-name evidence by param intelligence", [ref],
      { dataObjectUrls: urls.slice(0, 12) },
      { inferenceReason: "Engine param-intel: the parameter name appears as a data-object identifier on observed surfaces" });
    for (const u of urls.slice(0, 12)) {
      const epId = endpointNodeIds.get(epKey("GET", pathOf(u))) ?? endpointNodeIds.get(epKey("POST", pathOf(u)));
      if (epId) addEdge(b, "DEPENDS_ON", epId, obj.id, "INFERRED",
        "The endpoint's requests reference this data object", [ref], 1, {},
        { inferenceReason: "Engine param-intel data-object projection" });
    }
  }

  const dt = asDict(stats.digital_twin);
  const entityInventory = asArray(dt.entity_inventory);
  const entityNodeIds = new Map<string, string>();
  entityInventory.forEach((rawEnt, i) => {
    const ent = asDict(rawEnt);
    const name = str(ent.entity, 64);
    if (!name) return;
    const ref = reg(b, `stats.digital_twin:entity_inventory[${i}]`);
    const n = addNode(b, "entity", name, sanitizeLabel(`entity:${name}`), "INFERRED",
      "Entity typed from parameter names by the engine's entity vocabulary", [ref], {},
      { inferenceReason: "Engine entity typing: parameter-name vocabulary match (twin.infer_entity)" });
    entityNodeIds.set(name, n.id);
    // R3: entity EXPOSES surfaces (serialized projection)
    for (const s of asArray(ent.surfaces)) {
      const key = str(s, 256);
      const epId = endpointNodeIds.get(key) ?? endpointNodeIds.get(epKey("GET", pathOf(key)));
      if (epId) addEdge(b, "EXPOSES", n.id, epId, "INFERRED",
        "The entity's parameters ride this surface (engine entity_inventory projection)", [ref], 1, {},
        { inferenceReason: "Engine entity_inventory projection" });
    }
    // minted/consumed steps (serialized projection)
    const stepRefs: Array<[string, string]> = [];
    for (const s of asArray(ent.minted_by_steps)) stepRefs.push([str(s, 256), "MINTS"]);
    for (const s of asArray(ent.consumed_by_steps)) stepRefs.push([str(s, 256), "CONSUMES"]);
    for (const [sKey, rel] of stepRefs) {
      const m = sKey.match(/^step (\d+):([A-Z]+) (.+)$/);
      if (!m) continue;
      const idx = safeInt(m[1], 0); const method = m[2]; const action = m[3];
      const candidates = Array.from(workflowStepIndex.entries())
        .filter(([k]) => k.endsWith(`|${idx}|${action}`))
        .map(([, id]) => id)
        .sort();
      if (candidates.length === 1) {
        addEdge(b, rel as CanonicalEdgeType, candidates[0], n.id, "OBSERVED",
          `The step ${rel.toLowerCase()} this entity (engine entity_inventory)`, [ref], 1);
      }
    }
  });

  // ── 7. authorization matrix (role × endpoint verdicts) ────────────────────
  const appmap = asDict(stats.appmap);
  const accessMatrix = asDict(appmap.access_matrix);
  const accVerdicts = new Map<string, Map<string, { status: string; verdict: string; refs: string[] }>>(); // epKey -> role -> verdict
  for (const url of Object.keys(accessMatrix).sort(byKey)) {
    const roles = asDict(accessMatrix[url]);
    const path = pathOf(url);
    if (!path) continue;
    const key = epKey("GET", path);
    let agg = endpointAgg.get(key);
    if (!agg) {
      agg = { method: "GET", path, sources: new Set(["authz-matrix"]), activity: [], skips: [], findingTypes: [], refs: [], params: [] };
      endpointAgg.set(key, agg);
      const ref = reg(b, `stats.appmap:access_matrix`);
      agg.refs.push(ref);
      const n = addNode(b, "endpoint", key, sanitizeLabel(key), "OBSERVED",
        "Surface probed by the authz engine's access matrix", [ref],
        { method: "GET", path, sources: ["authz-matrix"], opClass: "READ" });
      endpointNodeIds.set(key, n.id);
      addEdge(b, "EXPOSES", hostNode.id, n.id, "OBSERVED",
        "The endpoint was observed at this host during the scan", [ref], 1);
    }
    for (const roleRaw of Object.keys(roles).sort(byKey)) {
      const role = ensureRole(roleRaw, "Role present in the engine's access matrix", [reg(b, "stats.appmap:access_matrix")]);
      const status = safeInt(roles[roleRaw], 0);
      const verdict = verdictForStatus(status);
      const ref = reg(b, `stats.appmap:access_matrix`);
      const epId = endpointNodeIds.get(key)!;
      addEdge(b, "ACCESSES", role.id, epId, "OBSERVED",
        `Authz engine probe: role '${role.key}' received HTTP ${status} (${verdict})`, [ref], 1,
        { status, verdict });
      let byRole = accVerdicts.get(key);
      if (!byRole) { byRole = new Map(); accVerdicts.set(key, byRole); }
      const prev = byRole.get(role.key);
      if (prev && prev.verdict !== verdict) {
        // conflicting observations for the same role+endpoint — do NOT pick a side
        const cid = addConflict(b, "access_verdict_mismatch", prev.refs.join("+"), ref,
          { provenance: "OBSERVED", summary: `role '${role.key}' → ${prev.verdict} (HTTP ${prev.status})`, sourceRefs: prev.refs },
          { provenance: "OBSERVED", summary: `role '${role.key}' → ${verdict} (HTTP ${status})`, sourceRefs: [ref] },
          `Conflicting access verdicts observed for ${key} / role '${role.key}'`);
        const epNode = b.nodes.get(epId);
        if (epNode) epNode.conflictIds = Array.from(new Set([...(epNode.conflictIds ?? []), cid])).sort();
      }
      byRole.set(role.key, { status: String(status), verdict, refs: [ref] });
    }
  }
  // cross-check vs the engine twin's own authorization matrix projection
  const dtMatrix = asDict(dt.authorization_matrix);
  for (const roleRaw of Object.keys(dtMatrix).sort(byKey)) {
    const roleKeyN = roleKey(roleRaw);
    const verdicts = asDict(dtMatrix[roleRaw]);
    for (const verdict of Object.keys(verdicts).sort(byKey)) {
      for (const surface of asArray(verdicts[verdict])) {
        const key = str(surface, 256);
        const epId = endpointNodeIds.get(key) ?? endpointNodeIds.get(epKey("GET", pathOf(key)));
        if (!epId) continue;
        const role = ensureRole(roleRaw, "Role present in the engine twin's authorization matrix", [reg(b, "stats.digital_twin:authorization_matrix")]);
        const ref = reg(b, `stats.digital_twin:authorization_matrix`);
        const am = accVerdicts.get(key)?.get(roleKeyN);
        if (am && am.verdict !== verdict) {
          const epNode = b.nodes.get(epId);
          const cid = addConflict(b, "access_verdict_mismatch", am.refs.join("+"), ref,
            { provenance: "OBSERVED", summary: `appmap: role '${roleKeyN}' → ${am.verdict}`, sourceRefs: am.refs },
            { provenance: "OBSERVED", summary: `twin matrix: role '${roleKeyN}' → ${verdict}`, sourceRefs: [ref] },
            `Conflicting access verdicts for ${epNode?.key ?? key} / role '${roleKeyN}' across engine projections`);
          if (epNode) epNode.conflictIds = Array.from(new Set([...(epNode.conflictIds ?? []), cid])).sort();
        }
      }
    }
  }

  // ── 8. findings + evidence + rejected candidates ───────────────────────────
  const evidenceNodeFor = (findingId: string, suffix: string, kind: string, detail: string, refs: string[]): CanonicalNode =>
    addNode(b, "evidence", `${findingId}:${suffix}`, sanitizeLabel(kind), "OBSERVED",
      `Engine evidence for finding ${findingId}`, refs, { kind, detail });

  const findings = asArray(raw.findings);
  const verifiedIndex = new Map<string, CanonicalNode>(); // "type|path|param" -> finding node
  findings.forEach((rawF, fi) => {
    const f = asDict(rawF) as RawFinding & Dict;
    const fid = str(f.id, 64) || `finding-${fi}`;
    const fRef = reg(b, `findings[${fi}]`);
    const type = str(f.type, 64) || "unknown";
    const severity = str(f.severity, 16).toLowerCase();
    const status = str(f.status, 24).toLowerCase();
    const url = str(f.url, 512);
    const method = methodOf(f.method);
    const path = pathOf(url);
    const param = str(f.parameter, 128);
    const fAttrs: Record<string, unknown> = { type, severity, status, method, url: url, path };
    if (param) fAttrs.parameter = param;
    const conf = f.confidence; if (conf !== undefined) fAttrs.confidence = safeFloat(conf);
    const risk = f.risk; if (risk !== undefined) fAttrs.risk = safeInt(risk);
    const impact = asDict(f.impact);
    if (impact.grade !== undefined) fAttrs.impactGrade = str(impact.grade, 32);
    if (impact.statement !== undefined) fAttrs.impactStatement = str(impact.statement, 256);

    const fn = addNode(b, "finding", fid, sanitizeLabel(`${type} ${path}`), "OBSERVED",
      "Finding present in the engine's verified findings list", [fRef], fAttrs);

    // evidence chain
    const evidenceIds: string[] = [];
    asArray(f.evidence).forEach((rawEv, ei) => {
      const ev = asDict(rawEv);
      const kind = str(ev.kind, 64) || "evidence";
      const detail = str(ev.detail, 256);
      const eRef = reg(b, `findings[${fi}]:evidence[${ei}]`);
      const evNode = evidenceNodeFor(fid, `ev${ei}`, kind, detail, [eRef]);
      evidenceIds.push(evNode.id);
      addEdge(b, "EVIDENCED_BY", fn.id, evNode.id, "OBSERVED",
        "The finding's evidence chain carries this record", [eRef], 1);
    });
    // verification record node — auto-minted from the raw verification object
    // for EVERY finding (engine-declared). It is NOT captured evidence: the
    // supervisor ruled (2026-10-03) that hasEvidence must separate the finding's
    // own captured chain (raw observations recorded during testing) from this
    // auto-minted record.
    const verification = asDict(f.verification);
    const passed = verification.passed === true;
    const vRef = reg(b, `findings[${fi}]:verification`);
    const vNode = addNode(b, "evidence", `${fid}:verification`, "verification", "OBSERVED",
      `Engine verification record for ${fid}`, [vRef], {
        kind: "verification",
        method: str(verification.method, 96),
        passed,
        confidence: safeFloat(verification.confidence),
        rounds: safeInt(verification.rounds),
        notes: str(verification.notes, 256),
      });
    evidenceIds.push(vNode.id);
    addEdge(b, "EVIDENCED_BY", fn.id, vNode.id, "OBSERVED",
      "The engine's verification record for this finding", [vRef], 1);

    // claim state — VERIFIED requires the finding's OWN captured evidence chain
    // (raw observations recorded by the engine during testing: probes, oracles,
    // differentials), NOT merely the auto-minted verification record which every
    // finding carries by construction. (Supervisor ruling 2026-10-03 — was
    // vacuous: evidenceIds always contained vNode, so hasEvidence was always
    // true; now it separates real evidence from engine-declared verification.)
    const chainEvidenceIds = evidenceIds.filter((id) => id !== vNode.id);
    const hasRealEvidence = chainEvidenceIds.length > 0;
    let claimState: "VERIFIED" | "UNKNOWN" = "UNKNOWN";
    if (status === "verified" && passed && hasRealEvidence) claimState = "VERIFIED";
    fn.claim = {
      state: claimState,
      statement: `${type} at ${method} ${path}${param ? ` (parameter '${param}')` : ""}`,
      evidenceRefs: claimState === "VERIFIED" ? evidenceIds : [],
      conflictIds: [],
    };

    // link to endpoint
    let epId = endpointNodeIds.get(epKey(method, path));
    if (!epId) {
      const key = epKey(method, path);
      let agg = endpointAgg.get(key);
      if (!agg) { agg = { method, path, sources: new Set(["finding"]), activity: [], skips: [], findingTypes: [], refs: [], params: [] }; endpointAgg.set(key, agg); }
      agg.refs.push(fRef);
      const n = addNode(b, "endpoint", key, sanitizeLabel(key), "OBSERVED",
        "Surface recorded by a finding (engine output)", [fRef],
        { method, path, sources: ["finding"], opClass: method === "GET" ? "READ" : "WRITE" });
      endpointNodeIds.set(key, n.id);
      addEdge(b, "EXPOSES", hostNode.id, n.id, "OBSERVED",
        "The endpoint was observed at this host during the scan", [fRef], 1);
      epId = n.id;
    }
    addEdge(b, "TESTED_BY", fn.id, epId, "OBSERVED",
      "The finding was produced by testing this endpoint", [fRef], 1,
      param ? { parameter: param } : undefined);
    if (claimState === "VERIFIED") {
      verifiedIndex.set(`${type}|${path}|${param}`, fn);
    }
  });

  // rejected candidates → REFUTED / UNKNOWN claims + conflict detection
  const rejected = asArray(raw.rejected_candidates);
  rejected.forEach((rawF, ri) => {
    const f = asDict(rawF) as RawFinding & Dict;
    const fid = str(f.id, 64) || `rejected-${ri}`;
    const rRef = reg(b, `rejected_candidates[${ri}]`);
    const type = str(f.type, 64) || "unknown";
    const url = str(f.url, 512);
    const method = methodOf(f.method);
    const path = pathOf(url);
    const param = str(f.parameter, 128);
    const verification = asDict(f.verification);
    const rejectedPassed = verification.passed;
    const fn = addNode(b, "finding", fid, sanitizeLabel(`${type} ${path}`), "OBSERVED",
      "Candidate present in the engine's rejected candidates list", [rRef],
      { type, severity: str(f.severity, 16).toLowerCase(), status: str(f.status, 24).toLowerCase() || "rejected", method, url, path, ...(param ? { parameter: param } : {}) });
    const evidenceIds: string[] = [];
    asArray(f.evidence).forEach((rawEv, ei) => {
      const ev = asDict(rawEv);
      const eRef = reg(b, `rejected_candidates[${ri}]:evidence[${ei}]`);
      const evNode = evidenceNodeFor(fid, `ev${ei}`, str(ev.kind, 64) || "evidence", str(ev.detail, 256), [eRef]);
      evidenceIds.push(evNode.id);
      addEdge(b, "EVIDENCED_BY", fn.id, evNode.id, "OBSERVED",
        "The rejected candidate's evidence chain carries this record", [eRef], 1);
    });
    // REFUTED only when the engine's verification explicitly negated it
    const isRefuted = rejectedPassed === false;
    fn.claim = {
      state: isRefuted ? "REFUTED" : "UNKNOWN",
      statement: `${type} at ${method} ${path}${param ? ` (parameter '${param}')` : ""}`,
      evidenceRefs: isRefuted ? evidenceIds : [],
      conflictIds: [],
    };
    if (isRefuted && evidenceIds.length) {
      for (const eid of evidenceIds) {
        addEdge(b, "REFUTED_BY", fn.id, eid, "REFUTED",
          "The engine's verification negated this candidate", [rRef], 1,
          undefined, { evidenceRefs: [eid] });
      }
    }
    // conflict: verified finding vs rejected candidate on the same surface.
    //
    // Supervisor ruling 2026-10-03 — PRIORITY over automatic demotion:
    // a rejected candidate (a potentially FAKE rejection) must NOT drop a
    // genuinely VERIFIED finding unless it carries COUNTER-EVIDENCE of its
    // own (a captured evidence chain — actual observations that negate).
    // The conflict RECORD is always created (honest bookkeeping; INV-11 links
    // both claims to it), but the claim STATES change only when the rejection
    // is backed by real evidence:
    //   - rejected WITH its own evidence chain  → both sides CONFLICT (real
    //     disagreement between captured observations);
    //   - rejected WITHOUT any captured evidence (vacuous, engine-declared
    //     failure) → states preserved: the verified finding KEEPS VERIFIED,
    //     the rejected side keeps REFUTED/UNKNOWN, and the disagreement stays
    //     visible through the linked conflict record.
    const rejectedHasCounterEvidence = evidenceIds.length > 0;
    const twin = verifiedIndex.get(`${type}|${path}|${param}`);
    if (twin && twin.id !== fn.id) {
      const cid = conflictId("verified_vs_rejected", twin.id, fn.id);
      addConflict(b, "verified_vs_rejected", twin.id, fn.id,
        { provenance: "VERIFIED", summary: `verified finding ${twin.key} on the same type/path/parameter`, sourceRefs: twin.sourceRefs },
        { provenance: "REFUTED", summary: `rejected candidate ${fn.key} on the same type/path/parameter${rejectedHasCounterEvidence ? " (with captured counter-evidence)" : " (no captured counter-evidence — states preserved)"}`, sourceRefs: fn.sourceRefs },
        `Verified finding and rejected candidate share type '${type}' on ${method} ${path}${param ? ` (${param})` : ""}`);
      if (twin.claim) {
        twin.claim.conflictIds = Array.from(new Set([...(twin.claim.conflictIds ?? []), cid])).sort();
        if (rejectedHasCounterEvidence) twin.claim.state = "CONFLICT";
      }
      fn.claim.conflictIds = Array.from(new Set([...(fn.claim.conflictIds ?? []), cid])).sort();
      if (rejectedHasCounterEvidence) fn.claim.state = "CONFLICT";
    }
  });

  // proofs (Evidence OS reproduction recipes)
  asArray(stats.proofs).forEach((rawP, pi) => {
    const p = asDict(rawP);
    const fid = str(p.finding_id, 64);
    if (!fid) return;
    const ref = reg(b, `stats.proofs[${pi}]`);
    const fn = b.nodes.get(nodeId("finding", fid));
    const reqs = asArray(p.requests).map((r) => asDict(r)).map((r) => ({
      method: methodOf(r.method), url: str(r.url, 256), parameter: str(r.parameter, 128),
    })).slice(0, 8);
    const respKinds = asArray(p.responses).map((r) => str(asDict(r).kind, 64)).filter(Boolean).slice(0, 8);
    const ev = addNode(b, "evidence", `${fid}:proof`, "proof", "OBSERVED",
      `Engine Evidence-OS reproduction recipe for ${fid}`, [ref], {
        kind: "proof", type: str(p.type, 64),
        attackHypothesis: str(p.attack_hypothesis, 256),
        preconditions: asArray(p.preconditions).map((x) => str(x, 128)).filter(Boolean).slice(0, 6),
        requests: reqs, responseKinds: respKinds,
      });
    if (fn) addEdge(b, "EVIDENCED_BY", fn.id, ev.id, "OBSERVED",
      "The engine's reproduction proof supports this finding", [ref], 1);
  });

  // ── 9. secrets (masked by construction — values never enter the twin) ─────
  const secretsStats = asDict(stats.secrets);
  const secretNodeIds = new Map<string, string>();
  for (const cls of asArray(secretsStats.classes_found)) {
    const c = str(cls, 64);
    if (!c) continue;
    const ref = reg(b, `stats.secrets:classes_found`);
    const n = addNode(b, "secret", `secret:${c}`, sanitizeLabel(`secret:${c}`), "OBSERVED",
      "Secret class detected by the secrets engine (value masked by construction)", [ref],
      { masked: true, value: "********" });
    secretNodeIds.set(c, n.id);
  }
  // credential exposure findings link endpoint → secret
  findings.forEach((rawF, fi) => {
    const f = asDict(rawF);
    if (str(f.type, 64) !== "credential_exposure") return;
    const cls = str(f.parameter, 64);
    if (!cls) return;
    const fRef = reg(b, `findings[${fi}]`);
    const sId = secretNodeIds.get(cls) ?? addNode(b, "secret", `secret:${cls}`, sanitizeLabel(`secret:${cls}`), "OBSERVED",
      "Secret class carried by a credential_exposure finding (value masked)", [fRef],
      { masked: true, value: "********" }).id;
    secretNodeIds.set(cls, sId);
    const epId = endpointNodeIds.get(epKey(methodOf(f.method), pathOf(f.url)));
    if (epId) addEdge(b, "EXPOSES", epId, sId, "OBSERVED",
      "A credential_exposure finding marks this endpoint as exposing the secret class", [fRef], 1);
  });

  // ── 10. boundaries ────────────────────────────────────────────────────────
  const boundary = asDict(stats.boundary);
  asArray(boundary.unresolved_detail).forEach((rawBd, bi) => {
    const bd = asDict(rawBd);
    const category = str(bd.category, 64);
    const bdPath = pathOf(bd.target);
    if (!category && !bdPath) return;
    const ref = reg(b, `stats.boundary:unresolved_detail[${bi}]`);
    const n = addNode(b, "boundary", `${category || "?"}|${bdPath || "?"}`,
      sanitizeLabel(`${category} ${str(bd.state, 24)}`), "OBSERVED",
      "Boundary record in the engine's boundary registry", [ref], {
        category, state: str(bd.state, 32), reason: str(bd.reason, 256), remediation: str(bd.remediation, 256),
      });
    addEdge(b, "CONTAINS", app.id, n.id, "OBSERVED",
      "The boundary record belongs to this application's scan scope", [ref], 1);
  });

  // ── 11. hypotheses (reasoning engine) ─────────────────────────────────────
  const reasoning = asDict(stats.reasoning);
  const hypByPatternSurface = new Map<string, { verified: CanonicalNode; refuted: CanonicalNode[] }>();
  asArray(reasoning.hypotheses).forEach((rawH, hi) => {
    const h = asDict(rawH);
    const hid = str(h.id, 64) || `hyp-${hi}`;
    const hRef = reg(b, `stats.reasoning:hypotheses[${hi}]`);
    const pattern = str(h.pattern, 96);
    const surface = str(h.surface, 256);
    const status = str(h.status, 48);
    const attrs: Record<string, unknown> = { pattern, status, source: str(h.source, 32) };
    const premise = str(h.premise, 256); if (premise) attrs.premise = premise;
    const test = str(h.test, 128); if (test) attrs.test = test;
    const plan = str(h.plan, 32); if (plan) attrs.plan = plan;
    const chain = asArray(h.chain).map((c) => str(c, 128)).filter(Boolean); if (chain.length) attrs.chain = chain;

    const hn = addNode(b, "hypothesis", hid, sanitizeLabel(pattern || hid), "INFERRED",
      "Hypothesis generated by the reasoning engine from twin patterns", [hRef], attrs,
      { inferenceReason: "Engine reasoning: pattern match over the digital twin" });

    // resolution evidence node
    let claimState: "VERIFIED" | "REFUTED" | "UNKNOWN" = "UNKNOWN";
    if (status.startsWith("tested:verified")) claimState = "VERIFIED";
    else if (status.startsWith("tested:refuted")) claimState = "REFUTED";
    const resNode = addNode(b, "evidence", `hyp:${hid}`, "hypothesis-resolution", "OBSERVED",
      `Engine resolution record for hypothesis ${hid}`, [hRef],
      { kind: "hypothesis-resolution", status, test });
    if (claimState === "VERIFIED") {
      addEdge(b, "EVIDENCED_BY", hn.id, resNode.id, "VERIFIED",
        "The reasoning engine resolved the hypothesis as tested:verified", [hRef], 1,
        undefined, { evidenceRefs: [resNode.id] });
      hn.claim = { state: "VERIFIED", statement: premise || pattern, evidenceRefs: [resNode.id, hRef], conflictIds: [] };
    } else if (claimState === "REFUTED") {
      addEdge(b, "REFUTED_BY", hn.id, resNode.id, "REFUTED",
        "The reasoning engine resolved the hypothesis as tested:refuted", [hRef], 1,
        undefined, { evidenceRefs: [resNode.id] });
      hn.claim = { state: "REFUTED", statement: premise || pattern, evidenceRefs: [resNode.id], conflictIds: [] };
    } else {
      addEdge(b, "EVIDENCED_BY", hn.id, resNode.id, "OBSERVED",
        "The reasoning engine recorded this resolution state", [hRef], 1);
      hn.claim = { state: "UNKNOWN", statement: premise || pattern, evidenceRefs: [], conflictIds: [] };
    }

    if (surface) {
      const epId = endpointNodeIds.get(surface) ?? endpointNodeIds.get(epKey("GET", pathOf(surface)));
      if (epId) addEdge(b, "GENERATED_HYPOTHESIS", epId, hn.id, "INFERRED",
        "The hypothesis was generated from this surface's twin pattern", [hRef], 1, {},
        { inferenceReason: "Engine reasoning: pattern origin surface" });
    }
    // conflict: same pattern+surface both verified and refuted
    const pk = `${pattern}|${surface}`;
    const entry = hypByPatternSurface.get(pk) ?? { verified: hn, refuted: [] };
    if (claimState === "VERIFIED") entry.verified = hn;
    if (claimState === "REFUTED") entry.refuted.push(hn);
    hypByPatternSurface.set(pk, entry);
  });
  for (const [pk, entry] of Array.from(hypByPatternSurface.entries()).sort((a, z) => byKey(a[0], z[0]))) {
    if (entry.refuted.length === 0 || entry.verified.claim?.state !== "VERIFIED") continue;
    const [pattern, surface] = pk.split("|");
    // Same priority rule as the finding conflicts above (supervisor ruling
    // 2026-10-03), applied with the hypotheses' own counter-evidence: a
    // tested:refuted resolution IS a captured engine test result, so a
    // refuted hypothesis carries counter-evidence BY CONSTRUCTION (its
    // resolution record was created for every hypothesis) — demotion to
    // CONFLICT here is always evidence-backed, never vacuous.
    for (const ref of entry.refuted) {
      const cid = conflictId("verified_vs_refuted", entry.verified.id, ref.id);
      addConflict(b, "verified_vs_refuted", entry.verified.id, ref.id,
        { provenance: "VERIFIED", summary: `hypothesis ${entry.verified.key} (${pattern}) resolved tested:verified`, sourceRefs: entry.verified.sourceRefs },
        { provenance: "REFUTED", summary: `hypothesis ${ref.key} (${pattern}) resolved tested:refuted`, sourceRefs: ref.sourceRefs },
        `Conflicting hypothesis resolutions for pattern '${pattern}'${surface ? ` on ${surface}` : ""}`);
      if (entry.verified.claim) {
        entry.verified.claim.state = "CONFLICT";
        entry.verified.claim.conflictIds = [...(entry.verified.claim.conflictIds ?? []), cid].sort();
      }
      if (ref.claim) {
        ref.claim.state = "CONFLICT";
        ref.claim.conflictIds = [...(ref.claim.conflictIds ?? []), cid].sort();
      }
    }
  }

  // ── 12. known unknowns + honest accounting ────────────────────────────────
  const dtIdentities = safeInt(dt.identities, 0);
  const namedIdentities = identityNodeIds.size;
  if (dtIdentities > namedIdentities) {
    addUnknown(b, "identities",
      `Engine twin reports ${dtIdentities} exercised identities; ${namedIdentities} are named in serialized output`,
      [reg(b, "stats.digital_twin:identities")]);
  }
  const browserPages = safeInt(stats.browser_pages, 0);
  if (browserPages > 0 && browserSurfaceCount.n === 0) {
    addUnknown(b, "browser_surfaces",
      `Browser renderer visited ${browserPages} pages; per-surface detail is not serialized in the engine output`,
      [reg(b, "stats.browser_pages")]);
  }
  const boundaryRecords = safeInt(boundary.records, 0);
  const boundarySerialized = asArray(boundary.unresolved_detail).length;
  if (boundaryRecords > boundarySerialized) {
    addUnknown(b, "boundary",
      `Boundary registry holds ${boundaryRecords} records; ${boundarySerialized} unresolved records are serialized`,
      [reg(b, "stats.boundary:records")]);
  }
  const unknownAuth = Array.from(endpointAgg.values()).filter((a) => a.authentication === "unknown").length;
  if (unknownAuth > 0) {
    addUnknown(b, "authentication",
      `${unknownAuth} endpoints have unknown authentication state in the engine inventory`,
      [reg(b, "stats.api_inventory:apis")]);
  }
  const covDiscovered = safeInt(coverage.discovered, 0);
  const covTested = safeInt(coverage.tested, 0);
  const covUntested = safeInt(coverage.untested, 0);
  if (covUntested > 0) {
    addUnknown(b, "coverage",
      `${covUntested} of ${covDiscovered} discovered surfaces were not tested (engine coverage account)`,
      [reg(b, "stats.coverage:untested")]);
  }
  const untestableHyps = asArray(reasoning.hypotheses).filter((h) => str(asDict(h).status, 48).startsWith("untestable")).length;
  if (untestableHyps > 0) {
    addUnknown(b, "hypotheses",
      `${untestableHyps} reasoning hypotheses are untestable with the recorded preconditions`,
      [reg(b, "stats.reasoning:hypotheses")]);
  }
  if (entityNodeIds.size > 0) {
    addUnknown(b, "entity_typing",
      "Parameter-level entity typing edges are not serialized by the engine; entity→surface projections are",
      [reg(b, "stats.digital_twin:entity_inventory")]);
  }
  for (const note of b.notes) addUnknown(b, "raw_input", str(note, 256), [reg(b, "run")]);

  // ── 13. finalize: caps, sort, counts, hash ────────────────────────────────
  let nodes = Array.from(b.nodes.values()).sort((x, y) => byKey(x.id, y.id));
  let edges = Array.from(b.edges.values()).sort((x, y) => byKey(x.id, y.id));
  if (nodes.length > MAX_NODES) { nodes = nodes.slice(0, MAX_NODES); b.truncated = true; }
  if (edges.length > MAX_EDGES) { edges = edges.slice(0, MAX_EDGES); b.truncated = true; }
  if (b.truncated) {
    addUnknown(b, "size", `Graph truncated at structural caps (${MAX_NODES} nodes / ${MAX_EDGES} edges)`, [reg(b, "stats")]);
    nodes = nodes.filter((n) => n); // keep sorted stable
  }
  // drop edges whose endpoints fell outside the caps (keeps INV-02 true)
  const nodeIds = new Set(nodes.map((n) => n.id));
  edges = edges.filter((e) => nodeIds.has(e.from) && nodeIds.has(e.to));
  const conflicts = Array.from(b.conflicts.values()).sort((x, y) => byKey(x.id, y.id));
  const knownUnknowns = Array.from(b.knownUnknowns.values()).sort((x, y) => byKey(x.id, y.id));

  const counts = buildCounts(nodes, edges, conflicts, knownUnknowns);
  const twinHash = computeTwinHash({
    schemaVersion: TWIN_SCHEMA_VERSION,
    target,
    nodes: nodes.map((n) => ({ id: n.id, type: n.type, key: n.key, provenance: n.provenance, sourceRefs: n.sourceRefs, attrs: n.attrs, claim: n.claim ?? null })),
    edges: edges.map((e) => ({ id: e.id, type: e.type, from: e.from, to: e.to, provenance: e.provenance, sourceRefs: e.sourceRefs, confidence: e.confidence, attrs: e.attrs ?? null })),
    conflicts, knownUnknowns,
  });

  return {
    schemaVersion: TWIN_SCHEMA_VERSION,
    target,
    scope: {
      runId, scanner,
      rawSource: options.rawSource ?? "result.json",
      application: origin, host,
      coverage: {
        discovered: covDiscovered, tested: covTested, untested: covUntested,
        coveragePct: typeof coverage.coverage_pct === "number" ? safeFloat(coverage.coverage_pct / 100) : null,
      },
    },
    nodes, edges, conflicts, knownUnknowns, counts, twinHash,
    rawHash: computeRawHash(raw),
  };
}

function buildCounts(nodes: CanonicalNode[], edges: CanonicalEdge[], conflicts: TwinConflict[], knownUnknowns: KnownUnknown[]): TwinCounts {
  const byNodeType: Record<string, number> = {};
  const byEdgeType: Record<string, number> = {};
  const provenance: Record<Provenance, number> = { OBSERVED: 0, INFERRED: 0, VERIFIED: 0, REFUTED: 0, UNKNOWN: 0 };
  const edgeProvenance: Record<Provenance, number> = { OBSERVED: 0, INFERRED: 0, VERIFIED: 0, REFUTED: 0, UNKNOWN: 0 };
  const claims = { VERIFIED: 0, REFUTED: 0, UNKNOWN: 0, CONFLICT: 0 };
  for (const n of nodes) {
    byNodeType[n.type] = (byNodeType[n.type] ?? 0) + 1;
    provenance[n.provenance] = (provenance[n.provenance] ?? 0) + 1;
    if (n.claim) claims[n.claim.state] = (claims[n.claim.state] ?? 0) + 1;
  }
  for (const e of edges) {
    byEdgeType[e.type] = (byEdgeType[e.type] ?? 0) + 1;
    edgeProvenance[e.provenance] = (edgeProvenance[e.provenance] ?? 0) + 1;
  }
  return {
    nodes: nodes.length, edges: edges.length, byNodeType, byEdgeType,
    provenance, edgeProvenance, claims,
    conflicts: conflicts.length, knownUnknowns: knownUnknowns.length,
  };
}

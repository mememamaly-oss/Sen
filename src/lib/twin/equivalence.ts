// ─────────────────────────────────────────────────────────────────────────────
// SENTINEL — PHASE 02 L1: EQUIVALENCE GATE (spec §11)
//
// Proves normalization does NOT change the meaning of engine data:
//
//   raw engine result → normalization → canonical twin → projection → compare
//
// The projection rebuilds the raw's essential element sets from the twin and
// compares them with the sets extracted directly from the raw output. Every
// essential raw element must survive normalization (no element may disappear).
// ─────────────────────────────────────────────────────────────────────────────
import type { NormalizedTwin, RawEngineResult } from "./types";
import { methodOf, pathOf, safeInt } from "./sanitize";

type Dict = Record<string, unknown>;
const asDict = (v: unknown): Dict => (v && typeof v === "object" && !Array.isArray(v) ? (v as Dict) : {});
const asArray = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string => (typeof v === "string" ? v : "");

/** Essential element sets extracted directly from the raw engine result. */
export interface RawEssentials {
  endpoints: Set<string>; // "METHOD path"
  parameters: Set<string>; // "METHOD path:param"
  identities: Set<string>;
  roles: Set<string>;
  workflows: Set<string>;
  workflowSteps: Set<string>; // "cluster|action"
  states: Set<string>; // "cluster:word"
  branches: Set<string>; // "cluster:field=value"
  findings: Set<string>; // finding ids (verified + rejected)
  evidenceCount: number;
  boundaries: Set<string>; // "category|path"
  apiSurfaces: Set<string>; // "protocol:path"
  graphqlEndpoints: Set<string>;
  wsChannels: Set<string>;
  browserSurfaces: Set<string>;
  coverageEndpoints: Set<string>; // coverage records "METHOD path"
  accessVerdicts: number; // role×endpoint verdict cells
  hypotheses: Set<string>;
}

export function extractRawEssentials(raw: RawEngineResult): RawEssentials {
  const stats = asDict(raw.stats);
  const coverage = asDict(stats.coverage);
  const inv = asDict(stats.api_inventory);
  const authz = asDict(stats.authz);
  const am = asDict(stats.action_matrix);
  const appmap = asDict(stats.appmap);
  const wf = asDict(stats.workflow);
  const boundary = asDict(stats.boundary);
  const gql = asDict(stats.graphql);
  const ws = asDict(stats.websocket);
  const reasoning = asDict(stats.reasoning);

  const endpoints = new Set<string>();
  const coverageEndpoints = new Set<string>();
  for (const rawEp of asArray(coverage.endpoints)) {
    const ep = asDict(rawEp);
    const key = `${methodOf(ep.method)} ${pathOf(ep.url)}`;
    if (pathOf(ep.url)) { endpoints.add(key); coverageEndpoints.add(key); }
  }
  const parameters = new Set<string>();
  const apiSurfaces = new Set<string>();
  const browserSurfaces = new Set<string>();
  for (const rawApi of asArray(inv.apis)) {
    const api = asDict(rawApi);
    const protocol = str(api.protocol).toLowerCase() || "http";
    const method = methodOf(api.method);
    const path = pathOf(api.path);
    if (!path) continue;
    if (protocol === "http") {
      const key = `${method} ${path}`;
      endpoints.add(key);
      const sources = asArray(api.sources).map((s) => str(s));
      if (sources.includes("dom:browser") || sources.includes("browser")) browserSurfaces.add(key);
      for (const p of asArray(api.parameters)) {
        if (str(p)) parameters.add(`${key}:${str(p)}`);
      }
    } else {
      apiSurfaces.add(`${protocol}:${path}`);
    }
  }
  // appmap access matrix urls are also observed endpoints
  let accessVerdicts = 0;
  for (const url of Object.keys(asDict(appmap.access_matrix))) {
    const path = pathOf(url);
    if (path) { endpoints.add(`GET ${path}`); accessVerdicts += Object.keys(asDict(asDict(appmap.access_matrix)[url])).length; }
  }
  // findings carry endpoints too
  for (const f of [...asArray(raw.findings), ...asArray(raw.rejected_candidates)]) {
    const fd = asDict(f);
    const path = pathOf(fd.url);
    if (path && str(fd.id)) endpoints.add(`${methodOf(fd.method)} ${path}`);
  }

  const identities = new Set<string>();
  const roles = new Set<string>(asArray(authz.roles).map((r) => str(r)).filter(Boolean));
  for (const rawI of asArray(am.identities)) {
    const i = asDict(rawI);
    if (str(i.name)) identities.add(str(i.name));
    if (str(i.role)) roles.add(str(i.role).replace(/^role:/, ""));
  }
  for (const url of Object.keys(asDict(appmap.access_matrix))) {
    for (const roleRaw of Object.keys(asDict(asDict(appmap.access_matrix)[url]))) {
      roles.add(roleRaw === "anon" ? "anonymous" : roleRaw.replace(/^role:/, ""));
    }
  }

  const workflows = new Set<string>();
  const workflowSteps = new Set<string>();
  const states = new Set<string>();
  const branches = new Set<string>();
  for (const rawFlow of asArray(wf.flows)) {
    const flow = asDict(rawFlow);
    const cluster = str(flow.cluster);
    if (!cluster) continue;
    workflows.add(cluster);
    for (const rawStep of asArray(flow.steps)) {
      const s = asDict(rawStep);
      if (str(s.action)) workflowSteps.add(`${cluster}|${str(s.action)}`);
    }
    const markers = asDict(flow.execution_markers);
    for (const kind of ["gained", "lost"]) for (const w of asArray(markers[kind])) {
      if (str(w)) states.add(`${cluster}:${str(w)}`);
    }
    for (const rawBr of asArray(flow.branches)) {
      const br = asDict(rawBr);
      if (str(br.field) || str(br.value)) branches.add(`${cluster}:${str(br.field) || "?"}=${str(br.value) || "?"}`);
    }
  }

  const findings = new Set<string>();
  let evidenceCount = 0;
  for (const f of asArray(raw.findings)) {
    const fd = asDict(f);
    if (str(fd.id)) findings.add(str(fd.id));
    evidenceCount += asArray(fd.evidence).length + 1; // + verification record
  }
  for (const f of asArray(raw.rejected_candidates)) {
    const fd = asDict(f);
    if (str(fd.id)) findings.add(str(fd.id));
  }

  const boundaries = new Set<string>();
  for (const rawB of asArray(boundary.unresolved_detail)) {
    const bd = asDict(rawB);
    boundaries.add(`${str(bd.category) || "?"}|${pathOf(bd.target) || "?"}`);
  }

  const graphqlEndpoints = new Set<string>();
  for (const rawE of asArray(gql.endpoints)) {
    const e = asDict(rawE);
    if (pathOf(e.url)) graphqlEndpoints.add(pathOf(e.url));
  }
  const wsChannels = new Set<string>();
  for (const rawC of asArray(ws.channels)) {
    const c = asDict(rawC);
    if (pathOf(c.url)) wsChannels.add(pathOf(c.url));
  }

  const hypotheses = new Set<string>();
  for (const rawH of asArray(reasoning.hypotheses)) {
    const h = asDict(rawH);
    if (str(h.id)) hypotheses.add(str(h.id));
  }

  return {
    endpoints, parameters, identities, roles, workflows, workflowSteps, states,
    branches, findings, evidenceCount, boundaries, apiSurfaces, graphqlEndpoints,
    wsChannels, browserSurfaces, coverageEndpoints, accessVerdicts, hypotheses,
  };
}

/** Project the same sets out of the normalized twin. */
export function projectTwinEssentials(twin: NormalizedTwin): RawEssentials {
  const endpoints = new Set<string>();
  const browserSurfaces = new Set<string>();
  const apiSurfaces = new Set<string>();
  const parameters = new Set<string>();
  for (const n of twin.nodes) {
    if (n.type === "endpoint") endpoints.add(n.key);
    if (n.type === "browser_surface") { browserSurfaces.add(n.key); endpoints.add(n.key); }
    if (n.type === "api") apiSurfaces.add(n.key);
    if (n.type === "parameter") {
      const ep = String(n.attrs.endpoint ?? "");
      const name = String(n.attrs.name ?? "");
      if (ep && name) parameters.add(`${ep}:${name}`);
    }
  }
  const identities = new Set<string>();
  const roles = new Set<string>();
  const workflows = new Set<string>();
  const workflowSteps = new Set<string>();
  const states = new Set<string>();
  const branches = new Set<string>();
  const findings = new Set<string>();
  const boundaries = new Set<string>();
  const hypotheses = new Set<string>();
  let evidenceCount = 0;
  let accessVerdicts = 0;
  for (const n of twin.nodes) {
    switch (n.type) {
      case "identity": identities.add(n.key); break;
      case "role": roles.add(n.key); break;
      case "workflow": workflows.add(n.key); break;
      case "workflow_step": {
        const cluster = n.key.split("::")[0];
        const action = String(n.attrs.action ?? "");
        if (cluster && action) workflowSteps.add(`${cluster}|${action}`);
        break;
      }
      case "state": {
        const idx = n.key.indexOf(":");
        if (idx > 0) states.add(n.key);
        break;
      }
      case "branch": branches.add(n.key); break;
      case "finding": findings.add(n.key); break;
      case "boundary": boundaries.add(n.key); break;
      case "hypothesis": hypotheses.add(n.key); break;
      case "evidence": evidenceCount++; break;
    }
  }
  for (const e of twin.edges) if (e.type === "ACCESSES") accessVerdicts++;
  return {
    endpoints, parameters, identities, roles, workflows, workflowSteps, states,
    branches, findings, evidenceCount, boundaries, apiSurfaces,
    graphqlEndpoints: new Set(Array.from(apiSurfaces).filter((k) => k.startsWith("graphql:")).map((k) => k.slice("graphql:".length))),
    wsChannels: new Set(Array.from(apiSurfaces).filter((k) => k.startsWith("websocket:")).map((k) => k.slice("websocket:".length))),
    browserSurfaces, coverageEndpoints: new Set(endpoints), accessVerdicts, hypotheses,
  };
}

export interface EquivalenceReport {
  pass: boolean;
  dimensions: Array<{
    dimension: string;
    rawCount: number;
    twinCount: number;
    missing: string[]; // raw elements that disappeared in the twin — MUST be empty
    extra: string[]; // twin-only elements (allowed: derived/inferred)
  }>;
}

/** The equivalence gate: no essential raw element may disappear. */
export function checkEquivalence(raw: RawEngineResult, twin: NormalizedTwin): EquivalenceReport {
  const rawSets = extractRawEssentials(raw);
  const twinSets = projectTwinEssentials(twin);
  const dims: EquivalenceReport["dimensions"] = [];
  const cmp = (dimension: string, rawSet: Set<string>, twinSet: Set<string>, rawCount?: number, twinCount?: number) => {
    const missing = Array.from(rawSet).filter((x) => !twinSet.has(x)).sort();
    const extra = Array.from(twinSet).filter((x) => !rawSet.has(x)).sort();
    dims.push({
      dimension,
      rawCount: rawCount ?? rawSet.size,
      twinCount: twinCount ?? twinSet.size,
      missing, extra,
    });
  };
  cmp("endpoints", rawSets.endpoints, twinSets.endpoints);
  cmp("coverage_endpoints", rawSets.coverageEndpoints, twinSets.endpoints);
  cmp("parameters", rawSets.parameters, twinSets.parameters);
  cmp("identities", rawSets.identities, twinSets.identities);
  cmp("roles", rawSets.roles, twinSets.roles);
  cmp("workflows", rawSets.workflows, twinSets.workflows);
  cmp("workflow_steps", rawSets.workflowSteps, twinSets.workflowSteps);
  cmp("states", rawSets.states, twinSets.states);
  cmp("branches", rawSets.branches, twinSets.branches);
  cmp("findings", rawSets.findings, twinSets.findings);
  cmp("boundaries", rawSets.boundaries, twinSets.boundaries);
  cmp("api_surfaces", rawSets.apiSurfaces, twinSets.apiSurfaces);
  cmp("graphql", rawSets.graphqlEndpoints, twinSets.graphqlEndpoints);
  cmp("websocket", rawSets.wsChannels, twinSets.wsChannels);
  cmp("browser_surfaces", rawSets.browserSurfaces, twinSets.browserSurfaces);
  cmp("hypotheses", rawSets.hypotheses, twinSets.hypotheses);
  dims.push({
    dimension: "evidence",
    rawCount: rawSets.evidenceCount,
    twinCount: twinSets.evidenceCount,
    missing: rawSets.evidenceCount > twinSets.evidenceCount ? [`${rawSets.evidenceCount - twinSets.evidenceCount} evidence records missing`] : [],
    extra: [],
  });
  dims.push({
    dimension: "access_verdicts",
    rawCount: rawSets.accessVerdicts,
    twinCount: twinSets.accessVerdicts,
    missing: rawSets.accessVerdicts > twinSets.accessVerdicts ? [`${rawSets.accessVerdicts - twinSets.accessVerdicts} verdict cells missing`] : [],
    extra: [],
  });
  return { pass: dims.every((d) => d.missing.length === 0), dimensions: dims };
}

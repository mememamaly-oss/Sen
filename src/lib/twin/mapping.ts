// ─────────────────────────────────────────────────────────────────────────────
// SENTINEL — PHASE 02 L1: RAW → CANONICAL MAPPING (spec §4, explicit & documented)
//
// Engine v4.1.1 raw kinds (twin.py + orchestrator.py) map to canonical types.
// NO raw kind is dropped: kinds without a listed canonical equivalent keep a
// documented canonical type of their own. The mapping is lossless at the
// attribute level: raw provenance strings, sources and counts are preserved
// in node attrs (sanitized).
//
//   raw kind            canonical type     notes
//   ─────────────────────────────────────────────────────────────────────────
//   (target url)        application        scan scope root — OBSERVED
//   (target host)       host               OBSERVED
//   surface             endpoint           http surface (coverage/api_inventory)
//   surface(dom:browser)browser_surface    browser-discovered surface
//   param               parameter          USES_PARAMETER edges
//   identity            identity           action_matrix.identities
//   role                role               authz.roles + matrix keys
//   session             session            workflow graph execution identity
//   entity              entity             INFERRED (name-based typing)
//   object              object             INFERRED (data-object projection)
//   workflow            workflow           workflow.flows clusters
//   workflow_step       workflow_step      flow steps + graph nodes
//   state               state              execution markers via oracle
//   (flow.branches)     branch             declared options observed in forms
//   graphql_endpoint    api(protocol=graphql)
//   ws_channel          api(protocol=websocket)
//   api                 api                unified API inventory
//   finding             finding            verified + rejected candidates
//   secret              secret             masked by construction
//   evidence            evidence           finding evidence chains + proofs
//   boundary            boundary           boundary registry (unresolved detail)
//   hypothesis          hypothesis         reasoning engine (kept — extra type)
//
// Edge mapping (raw rel → canonical):
//   carries→USES_PARAMETER, exposes→EXPOSES, has_role→HAS_ROLE,
//   authenticated→AUTHENTICATES, gates→ACCESSES, step_of→PART_OF,
//   transitions_to→TRANSITIONS_TO (wf→state) / LEADS_TO (step→step),
//   tested_as→TESTED_BY, produced_finding→TESTED_BY (finding→endpoint),
//   exposed_secret→EXPOSES, mints→MINTS, consumes→CONSUMES,
//   typed_as→TYPED_AS, declared_privilege→DECLARED_PRIVILEGE,
//   generated_hypothesis→GENERATED_HYPOTHESIS, speaks_protocol→SPEAKS_PROTOCOL,
//   bounded_by / observes → recorded as attrs (no canonical edge fabricated).
// ─────────────────────────────────────────────────────────────────────────────
import type { CanonicalNodeType } from "./types";

/** raw engine twin kind → canonical type. Unknown raw kinds are NOT dropped:
 *  they pass through as-is (sanitized) so the schema never loses a kind. */
export function canonicalNodeType(rawKind: string): CanonicalNodeType | string {
  const k = rawKind.trim().toLowerCase();
  const map: Record<string, CanonicalNodeType> = {
    surface: "endpoint",
    param: "parameter",
    identity: "identity",
    role: "role",
    session: "session",
    entity: "entity",
    object: "object",
    workflow: "workflow",
    workflow_step: "workflow_step",
    state: "state",
    graphql_endpoint: "api",
    ws_channel: "api",
    api: "api",
    finding: "finding",
    secret: "secret",
    boundary: "boundary",
    hypothesis: "hypothesis",
    application: "application",
    host: "host",
    endpoint: "endpoint",
    browser_surface: "browser_surface",
    parameter: "parameter",
    evidence: "evidence",
    branch: "branch",
    action: "workflow_step", // engine vocab: action-shaped steps
  };
  return map[k] ?? k; // pass-through for any additional engine kind
}

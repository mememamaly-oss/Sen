// ─────────────────────────────────────────────────────────────────────────────
// SENTINEL — PHASE 02 L1: DETERMINISTIC FIXTURES (spec §13)
//
// Ten synthetic raw engine outputs covering the required scenarios. Each
// fixture documents expected nodes / edges / provenance / conflicts, and the
// test suite freezes its golden twinHash (determinism contract).
//
//   F01 complete twin          F06 unknown state
//   F02 partial twin           F07 missing identity
//   F03 inferred nodes         F08 missing authorization
//   F04 verified evidence      F09 blocked boundary
//   F05 refuted claim          F10 conflicting evidence
// ─────────────────────────────────────────────────────────────────────────────
import type { RawEngineResult } from "./types";

const BASE = "https://fixture.example";

function covEndpoint(method: string, url: string, source = "seed", activity: string[] = ["passive", "secrets", "active"], skips: string[] = [], baseline = 200) {
  return { method, url, source, activity, skips, baseline };
}

function apiEntry(path: string, opts: Partial<Record<string, unknown>> = {}) {
  return {
    protocol: "http", method: "GET", path, channel: "", sources: ["seed"],
    parameters: [], findings: 0, finding_types: [], authentication: "unknown",
    coverage_status: "tested", ...opts,
  };
}

function finding(id: string, type: string, url: string, opts: Partial<Record<string, unknown>> = {}) {
  return {
    id, type, severity: "high", status: "verified", confidence: 0.95, method: "GET",
    url, parameter: "", evidence: [{ kind: "response_diff", detail: "TRUE probe -> HTTP 200, FALSE probe -> HTTP 500" }],
    verification: { method: "oracle:replay-2round", passed: true, confidence: 0.95, rounds: 2, notes: "replay" },
    risk: 70, impact: { grade: "proven", statement: "Attacker influence proven" },
    ...opts,
  };
}

// ── F01: complete twin — every dimension present ─────────────────────────────
export function f01Complete(): RawEngineResult {
  return {
    run_id: "run-f01complete0", scanner: "sentinel-core/4.1.1", target: `${BASE}/`,
    findings: [
      finding("F-f01aaa0001", "sql_injection", `${BASE}/catalog`, { parameter: "category", severity: "critical" }),
      finding("F-f01bbb0002", "credential_exposure", `${BASE}/config`, { parameter: "aws_key", severity: "high" }),
    ],
    rejected_candidates: [],
    stats: {
      coverage: {
        discovered: 3, tested: 3, passive: 3, secrets_scanned: 3, active: 2, authz_probed: 2,
        active_or_authz: 2, untested: 0, skip_reasons: {}, coverage_pct: 100,
        endpoints: [
          covEndpoint("GET", `${BASE}/`),
          covEndpoint("GET", `${BASE}/catalog`),
          covEndpoint("GET", `${BASE}/config`),
        ],
      },
      api_inventory: {
        total: 3, by_protocol: { http: 3 },
        apis: [
          apiEntry("/"),
          apiEntry("/catalog", { parameters: ["category"], findings: 1, finding_types: ["sql_injection"] }),
          apiEntry("/config", { findings: 1, finding_types: ["credential_exposure"] }),
        ],
      },
      auth: { authenticated: true, landing: `${BASE}/login`, logins: 1, reauths: 0, failed_reauths: 0 },
      authz: { accounts_configured: 2, accounts_logged_in: 2, roles: ["admin", "user"], matrix_endpoints: 2, login_errors: [], requests: 8, ran: true },
      action_matrix: {
        actions: ["view"], discovered_surface_actions: ["view"],
        identities: [
          { name: "alice-admin", role: "admin" },
          { name: "bob-user", role: "user" },
        ],
        matrix: { "view": { "alice-admin": 2, "bob-user": 2 } },
      },
      appmap: {
        access_matrix: {
          [`${BASE}/catalog`]: { "role:admin": 200, "role:user": 200 },
          [`${BASE}/config`]: { "role:admin": 403, "role:user": 403 },
        },
        surfaces: { page: { count: 3, endpoints: [`${BASE}/`, `${BASE}/catalog`, `${BASE}/config`] } },
        workflows: { form_inventory: [] },
        authentication: { mode: "form" }, coverage: {}, data_objects: {},
      },
      workflow: {
        flows: [{
          cluster: "/transfer", entry: "/transfer/start",
          steps: [
            { action: "/transfer/select", method: "POST" },
            { action: "/transfer/create", method: "POST" },
            { action: "/transfer/confirm", method: "POST" },
          ],
          resource_params: ["tid"],
          state_oracle: "/transfer/ledger",
          execution_markers: { gained: ["EXECUTED"], lost: ["PENDING"] },
          privilege_declared_options: [{ field: "mode", value: "wire", label: "Wire transfer (admin only)" }],
          rollback_paths: [], branches: [{ field: "mode", value: "wire", label: "Wire transfer (admin only)", class: "privileged", functional: true }],
          branch_transfer: null, approval_step: null, cancel_paths: [], rollback_only_paths: [],
          state_transitions: ["- -> PENDING", "PENDING -> EXECUTED"],
          graph: {
            nodes: [
              { id: "S0", kind: "step", action: "/transfer/select", index: 0, identity: "primary-session", preconditions: ["token:csrf"], parameters: ["csrf", "acct"], extracted_tokens: ["csrf"], referenced_objects: [], state_before: "", state_after: "", impact_class: "STATE_CHANGING", dependencies: [{ kind: "token", on: "csrf" }], provenance: "guided-walk submission (observed)", confidence: 1.0 },
              { id: "S1", kind: "step", action: "/transfer/create", index: 1, identity: "primary-session", preconditions: [], parameters: ["tid"], extracted_tokens: [], referenced_objects: ["tid"], state_before: "", state_after: "PENDING", impact_class: "STATE_CHANGING", dependencies: [], provenance: "guided-walk submission (observed)", confidence: 1.0 },
            ],
            edges: [{ from: "S0", to: "S1", kind: "sequence" }],
          },
        }],
      },
      graphql: { enabled: true, candidates: 1, endpoints: [{ url: `${BASE}/graphql`, source: "observed" }], introspected: 42, queries: 10, mutations: 4 },
      websocket: { enabled: true, candidates: 1, channels: [{ url: `${BASE}/ws/live`, source: "observed" }], connected: 1, protocols: { [`${BASE}/ws/live`]: "chat" }, tests: 2 },
      secrets: { classes_found: ["aws_key"], findings: 1, masking: "masked" },
      boundary: {
        records: 3, by_state: { RESOLVED: 1, NOT_DISCOVERED: 2 }, by_category: { graphql: 1, websocket: 1 },
        unresolved: 2,
        unresolved_detail: [
          { category: "graphql_depth_limit", target: `${BASE}/graphql`, state: "NOT_DISCOVERED", reason: "no depth limit observed", remediation: "configure" },
          { category: "ws_auth", target: `${BASE}/ws/live`, state: "NOT_DISCOVERED", reason: "no auth frame observed", remediation: "require auth" },
        ],
        states_vocabulary: ["NOT_DISCOVERED", "RESOLVED"],
      },
      param_intel: {
        by_kind: { generic: ["category"] }, data_objects: { acct: [`${BASE}/transfer/select`] },
        params_total: 2, value_shape_upgrades: 0,
      },
      proofs: [{
        finding_id: "F-f01aaa0001", type: "sql_injection", severity: "critical",
        attack_hypothesis: "boolean oracle in category",
        preconditions: ["target reachable"],
        requests: [{ method: "GET", url: `${BASE}/catalog`, parameter: "category" }],
        responses: [{ kind: "oracle_confirmed" }],
      }],
      reasoning: {
        hypotheses: [
          { id: "H-f01h01", pattern: "R-ADMIN-SURFACE-LOW-ROLE", surface: "GET /config", premise: "user may reach admin surface", chain: ["user", "GET /config"], test: "authz battery", plan: "READ_ONLY", status: "tested:verified", source: "twin-pattern", preconditions: [], expected_behavior: "", test_plan: "authz battery" },
          { id: "H-f01h02", pattern: "R-CSRF-STATE-CHANGE", surface: "POST /transfer/confirm", premise: "state change without csrf", chain: [], test: "csrf battery", plan: "READ_ONLY", status: "tested:refuted", source: "twin-pattern", preconditions: [], expected_behavior: "", test_plan: "csrf battery" },
          { id: "H-f01h03", pattern: "R-IDOR-OBJECT", surface: "GET /account", premise: "object id without ownership", chain: [], test: "authz battery", plan: "READ_ONLY", status: "untestable:precondition_absent", source: "twin-pattern", preconditions: ["second account"], expected_behavior: "", test_plan: "authz battery" },
        ],
      },
      browser_pages: 0, browser_probes: 0,
      digital_twin: {
        nodes: 0, edges: 0, identities: 2, roles: 2, entities: 1, surfaces_total: 3,
        surfaces_write: 0, surfaces_read: 3, workflow_steps: 3, states_observed: 2,
        findings_attached: 2, secrets_masked: 1, hypotheses: 3, surfaces_with_untested_reasons: 0,
        node_kinds: {}, edge_kinds: {}, flows: [{ cluster: "/transfer", steps: 3, oracle: "/transfer/ledger" }],
        authorization_matrix: { admin: { reachable: ["GET /catalog"], forbidden: ["GET /config"] }, user: { reachable: ["GET /catalog"], forbidden: ["GET /config"] } },
        entity_inventory: [{ entity: "Account", carried_by_params: 1, surfaces: ["GET /transfer/select"], minted_by_steps: [], consumed_by_steps: [] }],
        belief_audit: [], why_examples: [],
      },
    },
  };
}

// ── F02: partial twin — most sections missing ────────────────────────────────
export function f02Partial(): RawEngineResult {
  return {
    run_id: "run-f02partial0", scanner: "sentinel-core/4.1.1", target: `${BASE}/partial`,
    findings: [],
    stats: {
      coverage: {
        discovered: 2, tested: 1, passive: 2, secrets_scanned: 2, active: 1, authz_probed: 0,
        active_or_authz: 1, untested: 1, skip_reasons: { "not_found": 1 }, coverage_pct: 50,
        endpoints: [
          covEndpoint("GET", `${BASE}/partial/a`, "seed", ["passive"], [], 200),
          covEndpoint("GET", `${BASE}/partial/b`, "crawl:html", [], ["not_found"], 404),
        ],
      },
      api_inventory: { total: 2, by_protocol: { http: 2 }, apis: [apiEntry("/partial/a"), apiEntry("/partial/b", { coverage_status: "untested", findings: 0 })] },
      digital_twin: { nodes: 2, edges: 0, identities: 0, roles: 0, entities: 0, surfaces_total: 2, flows: [] },
    },
  };
}

// ── F03: inferred nodes — entities / objects / generated hypotheses ──────────
export function f03Inferred(): RawEngineResult {
  return {
    run_id: "run-f03inferred", scanner: "sentinel-core/4.1.1", target: `${BASE}/inferred`,
    findings: [],
    stats: {
      coverage: {
        discovered: 1, tested: 1, passive: 1, secrets_scanned: 1, active: 0, authz_probed: 0,
        active_or_authz: 0, untested: 0, skip_reasons: {}, coverage_pct: 100,
        endpoints: [covEndpoint("GET", `${BASE}/inferred/orders`)],
      },
      api_inventory: { total: 1, by_protocol: { http: 1 }, apis: [apiEntry("/inferred/orders", { parameters: ["order_id", "user_name"] })] },
      param_intel: { by_kind: { generic: ["order_id"] }, data_objects: { order_id: [`${BASE}/inferred/orders`] }, params_total: 2, value_shape_upgrades: 0 },
      reasoning: {
        hypotheses: [
          { id: "H-f03h01", pattern: "R-IDOR-OBJECT", surface: "GET /inferred/orders", premise: "order object without ownership check", chain: [], test: "authz battery", plan: "READ_ONLY", status: "generated", source: "twin-pattern", preconditions: ["second account"], expected_behavior: "", test_plan: "authz battery" },
        ],
      },
      digital_twin: {
        nodes: 3, edges: 1, identities: 0, roles: 0, entities: 1, surfaces_total: 1, flows: [],
        entity_inventory: [{ entity: "Order", carried_by_params: 1, surfaces: ["GET /inferred/orders"], minted_by_steps: [], consumed_by_steps: [] }],
      },
    },
  };
}

// ── F04: verified evidence — passed verification + proofs ────────────────────
export function f04Verified(): RawEngineResult {
  return {
    run_id: "run-f04verified", scanner: "sentinel-core/4.1.1", target: `${BASE}/verified`,
    findings: [
      finding("F-f04aaa0001", "xss_reflected", `${BASE}/verified/search`, {
        parameter: "q", severity: "high",
        evidence: [
          { kind: "reflection", detail: "canary reflected unescaped in <title>" },
          { kind: "response_diff", detail: "probe vs base differ" },
        ],
        verification: { method: "replay:reflection", passed: true, confidence: 0.97, rounds: 2, notes: "independent replay" },
      }),
    ],
    stats: {
      coverage: {
        discovered: 1, tested: 1, passive: 1, secrets_scanned: 1, active: 1, authz_probed: 0,
        active_or_authz: 1, untested: 0, skip_reasons: {}, coverage_pct: 100,
        endpoints: [covEndpoint("GET", `${BASE}/verified/search`, "seed", ["passive", "secrets", "active"])],
      },
      api_inventory: { total: 1, by_protocol: { http: 1 }, apis: [apiEntry("/verified/search", { parameters: ["q"], findings: 1, finding_types: ["xss_reflected"] })] },
      proofs: [{
        finding_id: "F-f04aaa0001", type: "xss_reflected", severity: "high",
        attack_hypothesis: "reflected XSS in q", preconditions: ["reachable"],
        requests: [{ method: "GET", url: `${BASE}/verified/search`, parameter: "q" }],
        responses: [{ kind: "reflection_confirmed" }],
      }],
      digital_twin: { nodes: 2, edges: 1, identities: 0, roles: 0, entities: 0, surfaces_total: 1, findings_attached: 1, flows: [] },
    },
  };
}

// ── F05: refuted claim — rejected candidate + tested:refuted hypothesis ──────
export function f05Refuted(): RawEngineResult {
  return {
    run_id: "run-f05refuted0", scanner: "sentinel-core/4.1.1", target: `${BASE}/refuted`,
    findings: [],
    rejected_candidates: [
      finding("F-f05rrr0001", "sql_injection", `${BASE}/refuted/item`, {
        parameter: "id", status: "rejected", severity: "high",
        evidence: [{ kind: "status_oracle", detail: "quote -> 200 (no error delta)" }],
        verification: { method: "oracle:replay-2round", passed: false, confidence: 0.1, rounds: 2, notes: "replay showed no difference" },
      }),
    ],
    stats: {
      coverage: {
        discovered: 1, tested: 1, passive: 1, secrets_scanned: 1, active: 1, authz_probed: 0,
        active_or_authz: 1, untested: 0, skip_reasons: {}, coverage_pct: 100,
        endpoints: [covEndpoint("GET", `${BASE}/refuted/item`)],
      },
      api_inventory: { total: 1, by_protocol: { http: 1 }, apis: [apiEntry("/refuted/item", { parameters: ["id"] })] },
      reasoning: {
        hypotheses: [
          { id: "H-f05h01", pattern: "R-SQLI-ERROR", surface: "GET /refuted/item", premise: "error-based SQLi", chain: [], test: "active battery", plan: "READ_ONLY", status: "tested:refuted", source: "twin-pattern", preconditions: [], expected_behavior: "", test_plan: "active battery" },
        ],
      },
      digital_twin: { nodes: 1, edges: 0, identities: 0, roles: 0, entities: 0, surfaces_total: 1, flows: [] },
    },
  };
}

// ── F06: unknown state — untestable / unverified / unknown auth ──────────────
export function f06Unknown(): RawEngineResult {
  return {
    run_id: "run-f06unknown0", scanner: "sentinel-core/4.1.1", target: `${BASE}/unknown`,
    findings: [
      // status=verified but verification.passed missing → claim MUST stay UNKNOWN
      finding("F-f06uuu0001", "open_redirect", `${BASE}/unknown/go`, {
        parameter: "next", status: "verified",
        evidence: [{ kind: "location_header", detail: "Location changes with next" }],
        verification: { method: "redirect:passive", passed: undefined, confidence: 0.3, rounds: 0, notes: "not independently replayed" },
      }),
    ],
    stats: {
      coverage: {
        discovered: 1, tested: 1, passive: 1, secrets_scanned: 1, active: 1, authz_probed: 0,
        active_or_authz: 1, untested: 0, skip_reasons: {}, coverage_pct: 100,
        endpoints: [covEndpoint("GET", `${BASE}/unknown/go`)],
      },
      api_inventory: { total: 1, by_protocol: { http: 1 }, apis: [apiEntry("/unknown/go", { parameters: ["next"], authentication: "unknown" })] },
      reasoning: {
        hypotheses: [
          { id: "H-f06h01", pattern: "R-JWT-NONE", surface: "GET /unknown/go", premise: "jwt none alg", chain: [], test: "token battery", plan: "READ_ONLY", status: "untestable:precondition_absent", source: "twin-pattern", preconditions: ["jwt in scope"], expected_behavior: "", test_plan: "token battery" },
        ],
      },
      digital_twin: { nodes: 1, edges: 0, identities: 0, roles: 0, entities: 0, surfaces_total: 1, flows: [] },
    },
  };
}

// ── F07: missing identity — roles exercised, names not serialized ────────────
export function f07MissingIdentity(): RawEngineResult {
  return {
    run_id: "run-f07missing0", scanner: "sentinel-core/4.1.1", target: `${BASE}/ident`,
    findings: [],
    stats: {
      coverage: {
        discovered: 1, tested: 1, passive: 1, secrets_scanned: 1, active: 0, authz_probed: 1,
        active_or_authz: 1, untested: 0, skip_reasons: {}, coverage_pct: 100,
        endpoints: [covEndpoint("GET", `${BASE}/ident/home`)],
      },
      api_inventory: { total: 1, by_protocol: { http: 1 }, apis: [apiEntry("/ident/home", { authentication: "authenticated" })] },
      auth: { authenticated: true, landing: `${BASE}/login`, logins: 2, reauths: 0, failed_reauths: 0 },
      authz: { accounts_configured: 2, accounts_logged_in: 2, roles: ["admin"], matrix_endpoints: 1, login_errors: [], requests: 4, ran: true },
      // NOTE: no action_matrix.identities — names are NOT serialized
      digital_twin: { nodes: 2, edges: 0, identities: 2, roles: 1, entities: 0, surfaces_total: 1, flows: [] },
    },
  };
}

// ── F08: missing authorization — authz never ran ─────────────────────────────
export function f08MissingAuthz(): RawEngineResult {
  return {
    run_id: "run-f08noauthz0", scanner: "sentinel-core/4.1.1", target: `${BASE}/noauthz`,
    findings: [],
    stats: {
      coverage: {
        discovered: 1, tested: 1, passive: 1, secrets_scanned: 1, active: 1, authz_probed: 0,
        active_or_authz: 1, untested: 0, skip_reasons: {}, coverage_pct: 100,
        endpoints: [covEndpoint("GET", `${BASE}/noauthz/page`)],
      },
      api_inventory: { total: 1, by_protocol: { http: 1 }, apis: [apiEntry("/noauthz/page")] },
      auth: { authenticated: false, landing: "", logins: 0, reauths: 0, failed_reauths: 0 },
      digital_twin: { nodes: 1, edges: 0, identities: 0, roles: 0, entities: 0, surfaces_total: 1, flows: [] },
    },
  };
}

// ── F09: blocked boundary ────────────────────────────────────────────────────
export function f09BlockedBoundary(): RawEngineResult {
  return {
    run_id: "run-f09blocked0", scanner: "sentinel-core/4.1.1", target: `${BASE}/blocked`,
    findings: [],
    stats: {
      coverage: {
        discovered: 1, tested: 1, passive: 1, secrets_scanned: 1, active: 0, authz_probed: 0,
        active_or_authz: 0, untested: 0, skip_reasons: {}, coverage_pct: 100,
        endpoints: [covEndpoint("GET", `${BASE}/blocked/api`)],
      },
      api_inventory: { total: 1, by_protocol: { http: 1 }, apis: [apiEntry("/blocked/api")] },
      boundary: {
        records: 2, by_state: { BLOCKED: 2 }, by_category: { graphql: 1, websocket: 1 },
        unresolved: 2,
        unresolved_detail: [
          { category: "graphql_introspection", target: `${BASE}/blocked/api`, state: "BLOCKED", reason: "introspection disabled by server", remediation: "none needed" },
          { category: "ws_origin_check", target: `${BASE}/blocked/api`, state: "BLOCKED", reason: "origin rejected", remediation: "" },
        ],
        states_vocabulary: ["NOT_DISCOVERED", "RESOLVED", "BLOCKED"],
      },
      digital_twin: { nodes: 1, edges: 0, identities: 0, roles: 0, entities: 0, surfaces_total: 1, flows: [] },
    },
  };
}

// ── F10: conflicting evidence ────────────────────────────────────────────────
export function f10Conflicting(): RawEngineResult {
  return {
    run_id: "run-f10conflict", scanner: "sentinel-core/4.1.1", target: `${BASE}/conflict`,
    findings: [
      finding("F-f10vvv0001", "sql_injection", `${BASE}/conflict/search`, { parameter: "q" }),
    ],
    rejected_candidates: [
      // same type / path / parameter as the verified finding → CONFLICT
      finding("F-f10xxx0002", "sql_injection", `${BASE}/conflict/search`, {
        parameter: "q", status: "rejected",
        verification: { method: "oracle:replay-2round", passed: false, confidence: 0.2, rounds: 2, notes: "no difference" },
      }),
    ],
    stats: {
      coverage: {
        discovered: 2, tested: 2, passive: 2, secrets_scanned: 2, active: 2, authz_probed: 1,
        active_or_authz: 2, untested: 0, skip_reasons: {}, coverage_pct: 100,
        endpoints: [
          covEndpoint("GET", `${BASE}/conflict/search`),
          covEndpoint("GET", `${BASE}/conflict/admin`),
        ],
      },
      api_inventory: { total: 2, by_protocol: { http: 2 }, apis: [apiEntry("/conflict/search", { parameters: ["q"] }), apiEntry("/conflict/admin")] },
      authz: { accounts_configured: 1, accounts_logged_in: 1, roles: ["user"], matrix_endpoints: 1, login_errors: [], requests: 2, ran: true },
      appmap: {
        // appmap says user CAN reach /conflict/admin (200)…
        access_matrix: { [`${BASE}/conflict/admin`]: { "role:user": 200 } },
      },
      digital_twin: {
        nodes: 2, edges: 1, identities: 1, roles: 1, entities: 0, surfaces_total: 2, flows: [],
        // …while the engine twin's own matrix says forbidden — conflicting evidence
        authorization_matrix: { user: { forbidden: ["GET /conflict/admin"] } },
      },
    },
  };
}

// ── F11: vacuous rejection — priority rule (supervisor ruling 2026-10-03) ──
// A rejected candidate with NO captured evidence chain (engine-declared
// failure only) must NOT demote the verified finding on the same surface:
// the conflict record exists (honest bookkeeping) but the verified claim
// KEEPS VERIFIED and the rejected claim keeps its own state.
export function f11VacuousRejection(): RawEngineResult {
  return {
    run_id: "run-f11vacuous", scanner: "sentinel-core/4.1.1", target: `${BASE}/vacuous`,
    findings: [
      finding("F-f11vvv0001", "sql_injection", `${BASE}/vacuous/search`, { parameter: "q" }),
    ],
    rejected_candidates: [
      // same type/path/parameter as the verified finding, but the rejection
      // carries NO captured evidence chain (vacuous: engine-declared only)
      {
        id: "F-f11xxx0002", type: "sql_injection", severity: "high", status: "rejected",
        confidence: 0.2, method: "GET", url: `${BASE}/vacuous/search`, parameter: "q",
        evidence: [],
        verification: { method: "oracle:replay-2round", passed: false, confidence: 0.2, rounds: 2, notes: "no difference" },
        risk: 10, impact: {},
      },
    ],
    stats: {
      coverage: {
        discovered: 2, tested: 2, passive: 2, secrets_scanned: 2, active: 2, authz_probed: 1,
        active_or_authz: 2, untested: 0, skip_reasons: {}, coverage_pct: 100,
        endpoints: [
          covEndpoint("GET", `${BASE}/vacuous/search`),
          covEndpoint("GET", `${BASE}/vacuous/admin`),
        ],
      },
      api_inventory: { total: 2, by_protocol: { http: 2 }, apis: [apiEntry("/vacuous/search", { parameters: ["q"] }), apiEntry("/vacuous/admin")] },
      digital_twin: { nodes: 2, edges: 0, identities: 0, roles: 0, entities: 0, surfaces_total: 2, flows: [] },
    },
  };
}

// ── adversarial raw snippets (spec §14) — each tries to force fabrication ────

/** GraphQL schema observed, no verified vulnerability → no VERIFIED claim. */
export function advGraphqlNoVuln(): RawEngineResult {
  return {
    run_id: "run-adv-gql-novuln", scanner: "sentinel-core/4.1.1", target: `${BASE}/advgql`,
    findings: [],
    stats: {
      coverage: { discovered: 1, tested: 1, endpoints: [covEndpoint("POST", `${BASE}/advgql/graphql`)] },
      graphql: { enabled: true, candidates: 1, endpoints: [{ url: `${BASE}/advgql/graphql`, source: "probe" }], introspected: 120, queries: 30, mutations: 12 },
      api_inventory: { total: 1, by_protocol: { http: 1 }, apis: [apiEntry("/advgql/graphql", { method: "POST" })] },
      digital_twin: { nodes: 1, edges: 0, identities: 0, roles: 0, entities: 0, surfaces_total: 1, flows: [] },
    },
  };
}

/** WebSocket channel with no auth proof → auth state UNKNOWN, no fabricated auth edge. */
export function advWsNoAuthProof(): RawEngineResult {
  return {
    run_id: "run-adv-ws-noauth", scanner: "sentinel-core/4.1.1", target: `${BASE}/advws`,
    findings: [],
    stats: {
      coverage: { discovered: 1, tested: 1, endpoints: [covEndpoint("GET", `${BASE}/advws/socket`)] },
      websocket: { enabled: true, candidates: 1, channels: [{ url: `${BASE}/advws/socket`, source: "observed" }], connected: 1, protocols: {}, tests: 0 },
      api_inventory: { total: 1, by_protocol: { http: 1 }, apis: [apiEntry("/advws/socket")] },
      digital_twin: { nodes: 1, edges: 0, identities: 0, roles: 0, entities: 0, surfaces_total: 1, flows: [] },
    },
  };
}

/** Role present, no identity ever observed exercising it. */
export function advRoleNoIdentity(): RawEngineResult {
  return {
    run_id: "run-adv-role-noident", scanner: "sentinel-core/4.1.1", target: `${BASE}/advrole`,
    findings: [],
    stats: {
      coverage: { discovered: 1, tested: 1, endpoints: [covEndpoint("GET", `${BASE}/advrole/panel`)] },
      authz: { accounts_configured: 1, accounts_logged_in: 0, roles: ["admin"], matrix_endpoints: 0, login_errors: ["login failed"], requests: 1, ran: true },
      api_inventory: { total: 1, by_protocol: { http: 1 }, apis: [apiEntry("/advrole/panel")] },
      digital_twin: { nodes: 1, edges: 0, identities: 0, roles: 1, entities: 0, surfaces_total: 1, flows: [] },
    },
  };
}

/** Object without ownership evidence → no ownership relation fabricated. */
export function advObjectNoOwnership(): RawEngineResult {
  return {
    run_id: "run-adv-obj-noown", scanner: "sentinel-core/4.1.1", target: `${BASE}/advobj`,
    findings: [],
    stats: {
      coverage: { discovered: 1, tested: 1, endpoints: [covEndpoint("GET", `${BASE}/advobj/files`)] },
      api_inventory: { total: 1, by_protocol: { http: 1 }, apis: [apiEntry("/advobj/files", { parameters: ["file_id"] })] },
      param_intel: { by_kind: {}, data_objects: { file_id: [`${BASE}/advobj/files`] }, params_total: 1, value_shape_upgrades: 0 },
      digital_twin: { nodes: 2, edges: 0, identities: 0, roles: 0, entities: 0, surfaces_total: 1, flows: [] },
    },
  };
}

/** Incomplete workflow (single step, no oracle) → no states, no fabricated completion. */
export function advIncompleteWorkflow(): RawEngineResult {
  return {
    run_id: "run-adv-wf-incomplete", scanner: "sentinel-core/4.1.1", target: `${BASE}/advwf`,
    findings: [],
    stats: {
      coverage: { discovered: 1, tested: 1, endpoints: [covEndpoint("POST", `${BASE}/advwf/submit`)] },
      workflow: {
        flows: [{
          cluster: "/advwf", entry: "/advwf/submit",
          steps: [{ action: "/advwf/submit", method: "POST" }],
          resource_params: [], state_oracle: "", execution_markers: { gained: [], lost: [] },
          privilege_declared_options: [], rollback_paths: [], branches: [],
          branch_transfer: null, approval_step: null, cancel_paths: [], rollback_only_paths: [],
          state_transitions: [], graph: { nodes: [], edges: [] },
        }],
      },
      api_inventory: { total: 1, by_protocol: { http: 1 }, apis: [apiEntry("/advwf/submit", { method: "POST" })] },
      digital_twin: { nodes: 1, edges: 0, identities: 0, roles: 0, entities: 0, surfaces_total: 1, flows: [] },
    },
  };
}

/** Finding whose evidence chain is empty and verification absent → claim UNKNOWN. */
export function advMissingEvidence(): RawEngineResult {
  return {
    run_id: "run-adv-no-evidence", scanner: "sentinel-core/4.1.1", target: `${BASE}/advev`,
    findings: [{
      id: "F-adv0000001", type: "info_leak", severity: "info", status: "candidate",
      confidence: 0.2, method: "GET", url: `${BASE}/advev/leak`, parameter: "",
      evidence: [], verification: {}, risk: 5, impact: {},
    }],
    stats: {
      coverage: { discovered: 1, tested: 1, endpoints: [covEndpoint("GET", `${BASE}/advev/leak`)] },
      api_inventory: { total: 1, by_protocol: { http: 1 }, apis: [apiEntry("/advev/leak")] },
      digital_twin: { nodes: 1, edges: 0, identities: 0, roles: 0, entities: 0, surfaces_total: 1, flows: [] },
    },
  };
}

export const ALL_FIXTURES: Array<{ id: string; name: string; build: () => RawEngineResult }> = [
  { id: "F01", name: "complete-twin", build: f01Complete },
  { id: "F02", name: "partial-twin", build: f02Partial },
  { id: "F03", name: "inferred-nodes", build: f03Inferred },
  { id: "F04", name: "verified-evidence", build: f04Verified },
  { id: "F05", name: "refuted-claim", build: f05Refuted },
  { id: "F06", name: "unknown-state", build: f06Unknown },
  { id: "F07", name: "missing-identity", build: f07MissingIdentity },
  { id: "F08", name: "missing-authorization", build: f08MissingAuthz },
  { id: "F09", name: "blocked-boundary", build: f09BlockedBoundary },
  { id: "F10", name: "conflicting-evidence", build: f10Conflicting },
  { id: "F11", name: "vacuous-rejection", build: f11VacuousRejection },
];

# SENTINEL — Twin Schema (L1, `l1-twin/1.0.0`)

Canonical schema of the normalized Security Twin. The schema SUPPORTS all
node/edge types below; the normalizer only CREATES elements that raw
evidence backs ("no node because the schema expects one").

## 1. Canonical node types

| Type | Key format | Existence provenance | Source |
|---|---|---|---|
| `application` | target origin | OBSERVED | `target` |
| `host` | target hostname | OBSERVED | `target` |
| `endpoint` | `METHOD path` | OBSERVED | coverage / api_inventory / access matrix / findings |
| `browser_surface` | `METHOD path` | OBSERVED | sources incl. `dom:browser` |
| `parameter` | `METHOD path:name` | OBSERVED | api_inventory parameters |
| `identity` | identity name | OBSERVED | action_matrix.identities |
| `role` | role name | OBSERVED | authz.roles / access matrix keys |
| `session` | workflow graph identity | OBSERVED | workflow graph `identity` fields |
| `object` | param name | INFERRED (R2) | param_intel.data_objects / resource_params |
| `entity` | entity name | INFERRED (engine typing) | digital_twin.entity_inventory |
| `workflow` | cluster | OBSERVED | workflow.flows |
| `workflow_step` | `cluster::stepN:METHOD action` | OBSERVED | flow steps + graph nodes |
| `state` | `cluster:word` | OBSERVED | execution markers via state oracle |
| `branch` | `cluster:field=value` | OBSERVED | flow branches (declared form options) |
| `api` | `protocol:path` | OBSERVED | api_inventory (non-http) / graphql / websocket |
| `finding` | finding id | OBSERVED | findings / rejected_candidates |
| `secret` | `secret:class` | OBSERVED | secrets engine (masked, `********`) |
| `evidence` | `fid:evN` / `fid:verification` / `fid:proof` / `hyp:id` | OBSERVED | evidence chains / verification / proofs / hypothesis resolutions |
| `boundary` | `category\|path` | OBSERVED | boundary.unresolved_detail |
| `hypothesis` | hypothesis id | INFERRED | reasoning.hypotheses |

### Raw → canonical mapping (lossless)

| Engine raw kind | Canonical |
|---|---|
| `surface` | `endpoint` |
| `surface` (dom:browser) | `browser_surface` |
| `param` | `parameter` |
| `graphql_endpoint` | `api` (protocol=graphql) |
| `ws_channel` | `api` (protocol=websocket) |
| `api` | `api` |
| `action` | `workflow_step` |
| all others | same name (identity, role, session, entity, object, workflow, workflow_step, state, finding, secret, boundary, hypothesis, application, host, evidence) |

Unknown additional engine kinds pass through as-is (sanitized) — never dropped.

## 2. Canonical edge types

| Type | from → to | Provenance | Source |
|---|---|---|---|
| `CONTAINS` | application → host/api/boundary | OBSERVED | scope |
| `EXPOSES` | host → endpoint | OBSERVED (R1) | observation at host |
| `EXPOSES` | endpoint → secret | OBSERVED | credential_exposure finding |
| `EXPOSES` | entity → endpoint | INFERRED (R3) | entity_inventory |
| `USES_PARAMETER` | endpoint → parameter | OBSERVED | api_inventory |
| `HAS_ROLE` | identity → role | OBSERVED | action_matrix |
| `AUTHENTICATES` | identity → endpoint | OBSERVED | api_inventory auth state |
| `ACCESSES` | role → endpoint | OBSERVED | appmap.access_matrix (status+verdict) |
| `PART_OF` | workflow_step/branch → workflow | OBSERVED | flows |
| `LEADS_TO` | step → step | OBSERVED | observed step order |
| `TRANSITIONS_TO` | workflow → state | OBSERVED | state oracle markers |
| `DEPENDS_ON` | step → session/object, endpoint → object | OBSERVED / INFERRED | workflow graph / param_intel |
| `TESTED_BY` | endpoint → step, finding → endpoint | OBSERVED | walk / finding record |
| `EVIDENCED_BY` | finding/hypothesis → evidence | OBSERVED | evidence chains |
| `REFUTED_BY` | claim → evidence | REFUTED | negative verification |
| `MINTS` / `CONSUMES` | step → object/entity | INFERRED (R2) / OBSERVED | flow rule / entity_inventory |
| `TYPED_AS` | parameter → entity | *(schema-supported; engine does not serialize param-level typing — not created in L1)* |
| `DECLARED_PRIVILEGE` | workflow → role | OBSERVED | privileged form options |
| `GENERATED_HYPOTHESIS` | endpoint → hypothesis | INFERRED | reasoning pattern origin |
| `SPEAKS_PROTOCOL` | endpoint → api | OBSERVED | graphql/ws discovery |

Every edge carries: `id, type, from, to, provenance, sourceRefs, confidence, why{provenance, reason, sourceRefs[, inferenceReason][, evidenceRefs]}`.

## 3. Node shape

```jsonc
{
  "id": "N-<sha256(type‖key)[:16]>",
  "type": "endpoint",
  "key": "GET /catalog",
  "label": "GET /catalog",
  "provenance": "OBSERVED",            // one of the five values only
  "sourceRefs": ["stats.coverage:endpoints[1]"],
  "why": {
    "provenance": "OBSERVED",
    "reason": "Surface observed in the engine's coverage / API inventory",
    "sourceRefs": ["stats.coverage:endpoints[1]"]
  },
  "attrs": { "method": "GET", "path": "/catalog", "activity": ["passive","active"], "authState": "unknown" },
  "claim": {                            // findings / hypotheses only
    "state": "VERIFIED",                // VERIFIED | REFUTED | UNKNOWN | CONFLICT
    "statement": "sql_injection at GET /catalog (parameter 'category')",
    "evidenceRefs": ["N-…", "N-…"],     // evidence node ids (VERIFIED/REFUTED only)
    "conflictIds": []                   // TwinConflict ids (CONFLICT only)
  },
  "conflictIds": []                     // non-claim nodes affected by a conflict
}
```

## 4. TwinConflict (structured conflict state)

```jsonc
{
  "id": "C-<sha256(kind‖left‖right)[:16]>",
  "kind": "access_verdict_mismatch",    // | verified_vs_rejected | verified_vs_refuted
  "description": "Conflicting access verdicts for GET /x / role 'user' …",
  "left":  { "claimRef": "…", "provenance": "OBSERVED", "summary": "…", "sourceRefs": ["…"] },
  "right": { "claimRef": "…", "provenance": "OBSERVED", "summary": "…", "sourceRefs": ["…"] },
  "resolution": "UNRESOLVED"            // L1 NEVER picks a side
}
```

`CONFLICT` is a **claim state**, not a provenance value — the provenance
vocabulary stays strictly five-valued (see PROVENANCE_MODEL.md).

## 5. KnownUnknown

```jsonc
{ "id": "U-<sha256(dimension‖description)[:16]>", "dimension": "identities",
  "description": "Engine twin reports 2 exercised identities; 0 are named …",
  "sourceRefs": ["stats.digital_twin:identities"] }
```

## 6. Deterministic hashing

- `twinHash = sha256(canonicalJson({schemaVersion, target, nodes, edges, conflicts, knownUnknowns}))`
- `rawHash = sha256(canonicalJson(raw))` — input traceability
- `canonicalJson`: recursive key-sort; cycle-hardened; depth-capped (96)
- counts are derived (excluded from the hash); nodes/edges sorted by id

## 7. Structural limits

| Limit | Value |
|---|---|
| Max string (any twin string) | 256 chars (truncation marker `…`) |
| Max label | 96 chars |
| Max nodes | 50,000 (deterministic truncation + known-unknown) |
| Max edges | 250,000 |

Measured throughput: see SECURITY_TWIN_L1.md §7.

## 8. Persistence (TwinGraph)

```
model TwinGraph {
  id                String   @id @default(cuid())
  orgId             String
  scanId            String
  twinSchemaVersion String
  contentHash       String   // == twinHash
  countsJson        String
  graphJson         String   // the FULL normalized twin
  createdAt/updatedAt
  @@unique([orgId, scanId])   // tenant isolation enforced at storage level
}
```

Raw engine output is never stored in TwinGraph as a normalization substitute.

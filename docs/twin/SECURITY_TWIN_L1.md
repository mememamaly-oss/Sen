# SENTINEL — Security Twin Normalization (Phase 02 / L1)

> **Status**: L1 — Security Twin Normalization + Provenance (post-scan, read-only intelligence layer)
> **Baseline**: engine v4.1.1 (immutable, tag `v4.1.1` = `184871e`) — L1 never modifies it
> **Branch**: `phase/02-l1-twin`
> **Twin schema version**: `l1-twin/1.0.0`

## 1. What L1 is — and what it is NOT

L1 converts the **artifacts a completed scan already produced** (engine
`result.json` / platform DB reconstruction) into a **normalized Security
Twin**: a canonical, deterministic, provenance-carrying security graph that
can be verified, compared, interpreted and rebuilt bit-for-bit.

**SENTINEL does not invent a twin.** Every node, edge and claim is one of:

- directly **OBSERVED** in the engine output,
- **INFERRED** by one of four documented rules (see §4),
- **VERIFIED** by engine-produced evidence,
- **REFUTED** by an engine result, or
- honestly **UNKNOWN**.

The twin answers: what did SENTINEL see? what did it infer? what was
verified? what was refuted? what do we not know? why does this node exist?
why this edge? which scan produced it? can the model be rebuilt
deterministically from the same input? (Yes — INV-08/INV-09 + golden hashes.)

**L1 is NOT**: an attack-path engine (next phase), active testing, a network
client, or an engine modification. L1 sends **zero** new HTTP/GraphQL/
WebSocket/browser/OAST requests (spec §19). It reads scan results and
interprets them.

## 2. Architecture — strict layer separation

```
┌────────────────────────────────────────────────────────────────────┐
│ 1. RAW ENGINE OUTPUT (never modified by L1)                        │
│    saas-data/scans/<scanId>/result.json   (authoritative)          │
│    fallback: statsJson + Finding rows (DB reconstruction)          │
├────────────────────────────────────────────────────────────────────┤
│ 2. NORMALIZED TWIN — src/lib/twin/                                 │
│    normalize.ts   raw → canonical graph (nodes/edges/claims)        │
│    types.ts       CanonicalNode/Edge/TwinConflict/KnownUnknown      │
│    provenance.ts  the five-value vocabulary + structured why()      │
│    hash.ts        deterministic IDs, canonical JSON, twinHash       │
│    sanitize.ts    hostile-input hardening (length caps, ctrl chars) │
│    mapping.ts     raw type → canonical type (documented, lossless)  │
├────────────────────────────────────────────────────────────────────┤
│ 3. DERIVED INTELLIGENCE                                            │
│    invariants.ts  INV-01..10 (+INV-11..13) structural checks        │
│    equivalence.ts raw → twin → projection losslessness gate         │
│    service.ts     get-or-build + persist (TwinGraph)               │
│    persist.ts     tenant-scoped TwinGraph storage                   │
└────────────────────────────────────────────────────────────────────┘
```

- **API (versioned, read-only)**: `GET /api/v1/scans/:scanId/twin?orgId=`
- **Persistence**: Prisma `TwinGraph` — `unique(orgId, scanId)`, every query
  org-scoped; `graphJson` holds the **normalized** twin (never raw output as
  a normalization substitute).
- **UI**: `/twin` renders the real normalized twin (custom deterministic
  SVG layout; no heavy graph libraries; no direct DB access).

## 3. Normalization sources (raw → twin)

| Raw section (engine v4.1.1) | Twin contribution |
|---|---|
| `target`, `run_id`, `scanner` | application, host nodes, scope |
| `stats.coverage.endpoints[]` | endpoint/browser_surface nodes + activity/skips/baseline attrs |
| `stats.api_inventory.apis[]` | endpoint params (USES_PARAMETER), api nodes (non-http), auth/coverage attrs |
| `stats.action_matrix.identities[]` | identity nodes + HAS_ROLE edges |
| `stats.authz.roles[]` | role nodes |
| `stats.appmap.access_matrix` | role ACCESSES endpoint edges (status+verdict) |
| `stats.digital_twin.authorization_matrix` | cross-check projection (conflict detection) |
| `stats.digital_twin.entity_inventory[]` | entity nodes + EXPOSES/MINTS/CONSUMES projections |
| `stats.workflow.flows[]` | workflow, workflow_step, state, branch, session nodes; LEADS_TO/TRANSITIONS_TO/PART_OF/DEPENDS_ON/MINTS/CONSUMES |
| `stats.param_intel.data_objects` | object nodes (INFERRED) |
| `stats.graphql.endpoints[]` | api(protocol=graphql) nodes + SPEAKS_PROTOCOL |
| `stats.websocket.channels[]` | api(protocol=websocket) nodes + SPEAKS_PROTOCOL |
| `findings[]` | finding nodes + evidence nodes + EVIDENCED_BY + claims |
| `rejected_candidates[]` | finding nodes with REFUTED/UNKNOWN claims + conflict detection |
| `stats.proofs[]` | evidence nodes (Evidence-OS recipes) |
| `stats.secrets.classes_found[]` | secret nodes (masked by construction) |
| `stats.boundary.unresolved_detail[]` | boundary nodes |
| `stats.reasoning.hypotheses[]` | hypothesis nodes + VERIFIED/REFUTED/UNKNOWN claims |

## 4. The ONLY inference rules L1 performs

| Rule | Edge/Node | Basis |
|---|---|---|
| R1 | `host EXPOSES endpoint` | every endpoint was observed at the target host |
| R2 | `workflow_step MINTS/CONSUMES object` | engine workflow rule verbatim (twin.py: producer steps mint, final step consumes) |
| R3 | `entity EXPOSES endpoint` | engine entity_inventory projection |
| R4 | `session` nodes for workflow-graph execution identities | serialized workflow graph `identity` fields |

Everything else in the twin is direct observation of serialized engine data.
Relations are never created because they "seem logical" — no evidence, no edge.

## 5. Determinism contract

- **IDs**: `N-/E-/C-/U-` + first 16 hex of `sha256(type‖key)` /
  `sha256(from‖to‖type)` — content-derived, no random UUIDs.
- **twinHash**: `sha256(canonicalJson({schemaVersion, target, nodes, edges,
  conflicts, knownUnknowns}))` — recursively key-sorted JSON; nodes/edges
  sorted by id. `counts` are derived projections and excluded.
- **Forbidden in hashes**: timestamps, random values, PIDs, memory addresses.
- **Proof**: golden fixture hashes frozen in `scripts/l1_twin_suite.ts`;
  determinism ×3 asserted per fixture and per real engine output (INV-08/09).

## 6. Tenant isolation

Same chain as the L0 fix on `/api/findings/[id]`:
`requireUser → requireOrgAccess (membership; 404 + audit) → requireScanAccess
(findFirst scoped to access.orgId)`. The `orgId` query parameter is never an
authorization grant. TwinGraph reads/writes are always org-scoped
(`persist.ts`). Verified live: Org A → Twin A = 200; Org A → Twin B = 404
(including the explicit-victim-orgId attack); Org B → Twin A = 404; no
existence leak (`attack3..8` in `scripts/l1_twin_api_test.py`).

## 7. Performance (measured, not claimed)

`scripts/l1_twin_suite.ts` group G — honest measurements on this container:

| Scale | Nodes | Edges | normalize | invariants | equivalence | graphJson |
|---|---|---|---|---|---|---|
| 100  | 81 | 80 | 2 ms | 1 ms | 0 ms | 63 KB |
| 1k   | 947 | 946 | 20 ms | 19 ms | 1 ms | 740 KB |
| 10k  | 10,082 | 10,081 | 286 ms | 208 ms | 46 ms | 7.9 MB |

Structural caps (documented limits): 50,000 nodes / 250,000 edges — beyond
that the graph is deterministically truncated and a known-unknown records it.
Real-world largest scan measured: benchmark.json → 899 nodes / 977 edges /
41 ms. **10k nodes are supported and measured; no claim beyond that.**

## 8. Test matrix

| Suite | File | Checks |
|---|---|---|
| Unit (fixtures/determinism/invariants/equivalence/adversarial/malicious/performance) | `scripts/l1_twin_suite.ts` | 163 |
| API contract + tenant isolation (live server, real scans) | `scripts/l1_twin_api_test.py` (+ orchestrator) | 30+ |
| Engine regression (baseline lock) | build-v411 suite (untouched) | 102/102 + Doctor 15/15 + Benchmark ×3 |
| SaaS regression | E2E 68/68 + isolation 37/37 + production 30/30 | 135 |

Adversarial cases (no hallucination): endpoint without finding; GraphQL
schema without verified vuln; WS channel without auth proof; role without
identity; object without ownership evidence; incomplete workflow; undiscovered
branch; missing evidence (status=verified but no verification → stays
UNKNOWN); boundary BLOCKED; finding REFUTED; hostile provenance strings in
raw ignored; candidate without verification never becomes VERIFIED.

Malicious input cases: HTML/script/SQL-like strings, 10k-char strings,
duplicate entries, cyclic references, malformed shapes, invalid provenance,
tenant-field injection — normalization survives, invariants hold, no control
characters, length caps enforced, JSON round-trips, determinism intact.

## 9. Known unknowns (honest limits of this phase)

Recorded per-scan in `twin.knownUnknowns`:

1. Engine twin reports N exercised identities; only those serialized in
   `action_matrix.identities` are named — unnamed ones are NOT fabricated.
2. Browser-rendered page count without per-surface detail (when no
   `dom:browser` surfaces are serialized).
3. Boundary registry totals vs serialized unresolved records.
4. Endpoints with `authentication: "unknown"`.
5. Untested surfaces (coverage account).
6. Untestable reasoning hypotheses.
7. Parameter-level entity typing edges (engine computes them but serializes
   only the entity→surface projection).
8. DB-reconstruction mode: rejected candidates are not persisted by the
   import layer (only when result.json is unavailable).

## 10. Explicitly deferred to the next phase (Attack Paths)

No AttackPath engine, DB model, ranking, verification or UI exists in L1.
Only the normalized twin substrate described here was built.

# SENTINEL — Provenance Model (L1)

The unified provenance vocabulary for every node, edge and claim in the
normalized Security Twin. **Exactly five values are allowed** — nothing else
may ever appear (enforced structurally by INV-03 and the type system).

```
OBSERVED   INFERRED   VERIFIED   REFUTED   UNKNOWN
```

## 1. The five values

### OBSERVED
The element is directly present in the scan data (engine output). Examples:
an endpoint in `coverage.endpoints[]`, an identity in
`action_matrix.identities[]`, a parameter in the API inventory, a workflow
step submitted during the guided walk, an access verdict from the authz
matrix. OBSERVED never requires interpretation — only reading.

### INFERRED
The element is derived from existing evidence by a documented rule. Every
INFERRED element MUST carry `sourceRefs` + `why.inferenceReason`. L1 has
exactly four inference rules (R1–R4, see SECURITY_TWIN_L1.md §4); the
engine's own inference-shaped projections (entities, objects, hypotheses)
enter the twin as INFERRED with the engine's rule cited.

### VERIFIED
Allowed ONLY when actual engine-produced evidence exists: an evidence chain
entry, a verification record with `passed === true`, or an Evidence-OS
replay proof. **The existence of an endpoint, a schema, a node, or a finding
candidate is NEVER sufficient for VERIFIED.** Verified claims always carry
`evidenceRefs` pointing at evidence nodes / raw source addresses (INV-04).
A finding with `status: "verified"` but no passed verification stays
`UNKNOWN` (INV-05 — adversarially tested).

### REFUTED
An actual engine result negates the claim: a rejected candidate whose
verification explicitly failed (`passed === false`), or a reasoning
hypothesis resolved `tested:refuted`. Refuted claims carry `REFUTED_BY`
edges to the negating evidence.

### UNKNOWN
Insufficient evidence to decide: untestable hypotheses, candidates without
verification outcomes, authentication states the engine could not
determine. **Promoting UNKNOWN to VERIFIED without new evidence is
forbidden** — the normalizer structurally cannot do it (INV-05).

## 2. Existence provenance vs claim state

The model separates two dimensions:

- **Node/edge existence provenance** — one of the five values, describing
  how the element came into the model (usually OBSERVED or INFERRED).
- **Claim state** — for nodes that assert something (findings, hypotheses):
  `VERIFIED | REFUTED | UNKNOWN | CONFLICT`, always backed by `evidenceRefs`
  and/or `conflictIds`.

This separation is what makes "the finding exists" (OBSERVED node) distinct
from "the vulnerability is proven" (VERIFIED claim with evidence refs).

## 3. why() — structured answers

Every node and edge answers `why()` with a structured object, never a bare
string:

```jsonc
// OBSERVED
{ "provenance": "OBSERVED",
  "reason": "Surface observed in the engine's coverage / API inventory",
  "sourceRefs": ["stats.coverage:endpoints[7]"] }

// INFERRED (inferenceReason mandatory)
{ "provenance": "INFERRED",
  "reason": "Resource parameter treated as a data object by the workflow engine",
  "sourceRefs": ["stats.workflow:flows[0]", "stats.workflow:flows[0]:resource_params"],
  "inferenceReason": "Engine workflow rule: resource parameters name the objects the flow mints and consumes (twin.py)" }

// VERIFIED claim (evidenceRefs mandatory)
{ "provenance": "VERIFIED",
  "reason": "The reasoning engine resolved the hypothesis as tested:verified",
  "sourceRefs": ["stats.reasoning:hypotheses[3]"],
  "evidenceRefs": ["N-abc123…", "stats.reasoning:hypotheses[3]"] }
```

`sourceRefs` are addresses inside the raw engine output (INV-07 verifies
resolvability against a raw-source registry).

## 4. Conflicts (CONFLICT state)

When evidence disagrees, the twin never silently picks a story:

| Conflict kind | Trigger |
|---|---|
| `access_verdict_mismatch` | the same role+endpoint observed with different verdicts (appmap vs engine twin matrix, or repeated probes) |
| `verified_vs_rejected` | a verified finding and a rejected candidate share type+path+parameter |
| `verified_vs_refuted` | hypotheses with the same pattern+surface resolved both tested:verified and tested:refuted |

The affected claims become `CONFLICT` with `conflictIds` linking both sides;
a `TwinConflict` record keeps both stories with their provenance and
sourceRefs, `resolution: "UNRESOLVED"`. INV-06/INV-11 verify the linkage.

## 5. Enforcement

| Invariant | Rule |
|---|---|
| INV-03 | provenance ∈ {OBSERVED, INFERRED, VERIFIED, REFUTED, UNKNOWN} on nodes, edges, why(), conflict sides |
| INV-04 | every VERIFIED claim has ≥1 resolvable evidence reference |
| INV-05 | a VERIFIED finding must have raw `status=verified` AND `verification.passed=true` |
| INV-06 | REFUTED + VERIFIED evidence on the same claim → documented conflict, never a silent pick |
| INV-07 | every sourceRef resolves in the raw-source registry |
| INV-11 | every CONFLICT claim links a TwinConflict record and vice versa |
| INV-12 | secrets masked — raw values never enter the twin |

Hostile inputs that inject provenance strings (`"definitely-verified-hacked"`)
into raw data are ignored — provenance is DERIVED from evidence rules, never
read from raw strings (adversarial test E12).

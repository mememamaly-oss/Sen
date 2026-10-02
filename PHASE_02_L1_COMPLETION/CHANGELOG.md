# CHANGELOG — PHASE 02 — L1 (on top of SENTINEL v4.1.1)

Everything the L1 phase added to the recovered v4.1.1 baseline, as verified by
the FINAL RECOVERY GATE clean-restore test (no Attack Paths, no engine changes).

## New: `src/lib/twin/` — the twin normalization layer (13 modules)

- `types.ts` — canonical node/edge schema (20 node types, 19 edge types),
  5-value provenance model (OBSERVED / INFERRED / VERIFIED / REFUTED / UNKNOWN
  — nothing else), structured `why()` records, TwinConflict, known-unknowns.
- `provenance.ts` — provenance assignment + upgrade rules (VERIFIED only with
  real evidence refs; UNKNOWN never upgraded without evidence; REFUTED wins).
- `hash.ts` — deterministic content-derived IDs (`N-`, `E-`, `C-`, `U-` +
  sha256 prefix), canonical serialization, `twinHash` + `rawHash`.
- `sanitize.ts` — input sanitization: control chars stripped, length caps,
  structural caps (50k nodes / 250k edges, deterministic truncation).
- `mapping.ts` — documented raw engine type → canonical type mapping.
- `normalize.ts` — the normalizer: rebuilds the twin from raw engine artifacts
  (endpoints, params, identities, roles, sessions, objects, entities,
  workflows, steps, states, branches, APIs, findings, evidence, secrets,
  boundaries, hypotheses, access matrix), why() on every node+edge, conflicts
  never auto-resolved, honest known-unknowns.
- `invariants.ts` — INV-01..INV-13 checker.
- `equivalence.ts` — raw → twin → projection equivalence gate (17 dimensions).
- `fixtures.ts` — 10 deterministic fixtures with frozen golden twinHashes.
- `persist.ts` — TwinGraph persistence (tenant-scoped, unique orgId+scanId).
- `loader.ts` — raw result.json loader + DB-reconstruction fallback (honest gaps).
- `service.ts` — get-or-build twin service (invariants-checked, read-only).
- `index.ts` — public surface.

## New: API + UI

- `GET /api/v1/scans/[id]/twin` — versioned, read-only, tenant-isolated
  (requireUser → requireOrgAccess → requireScanAccess; cross-org = 404 + audit).
- `/twin` page — deterministic SVG layered graph (honest 160-node display cap),
  KPIs, twinHash badge, provenance distribution, scan selector, type/provenance
  filters, node table, structured why() panel, known-unknowns; AR+EN i18n.
- `src/components/saas/api.ts` — twin API client types.

## Modified

- `prisma/schema.prisma` — TwinGraph model (orgId, scanId, twinSchemaVersion,
  contentHash, countsJson, graphJson; unique(orgId, scanId)).
- `src/lib/ui/i18n.tsx` — twin strings (AR+EN).
- `scripts/` — 7 new l1_* scripts (suite, real-check, smoke, orchestrators,
  api test, plumbing-commit helper).
- `docs/` — SECURITY_TWIN_L1.md, TWIN_SCHEMA.md, PROVENANCE_MODEL.md,
  gates/PHASE02_L1_{PREFLIGHT,FINAL_GATE}.md.

## Gates achieved (frozen at L1 close, re-proven by this recovery gate)

Engine 102/102 · Doctor 15/15 · Benchmark ×3 F1=1.000 (38/0/0/35, identical ×3) ·
L1 unit 163/163 · Twin API + tenant 33/33 · SaaS E2E 68/68 · Tenant isolation
37/37 · Production 30/30 · Browser verified (console clean) · twin identity:
golden hashes byte-exact, structural identity across scans.

## Explicitly NOT in this phase

Attack-path engine/model/ranking/UI (deferred), any active testing (L1 is
read-only post-scan intelligence), engine modifications of any kind
(planner/workflow/GraphQL/WebSocket/authz/reasoning/evidence/boundary/coverage
untouched — engine diff vs v4.1.1 tag = 0).

# P2 RECORD — Compliance × Distribution × PostgreSQL (2026-10-31)

Phase 2 of the commercialization plan, executed end to end in one session:
items 5 (CI), 6 (compliance maps), 7 (landing/docs/demo + PG + auth fix),
plus groundwork documents for Phase-3 items 8–10. Every number below was
re-executed locally on 2026-10-31 before the push; the CI on GitHub re-proves
the same gates on every push (see §4).

## 1. Compliance registry (item 6)

- `sentinel/compliance.py`: 54 detector classes (the full `report.SARIF_RULES`
  key set + the gap fix below). One row per class: CWE (with label),
  OWASP Top 10:2021, OWASP Top 10:2025 (FINAL release), PCI DSS 6.4.2
  (= the requirement numbered 6.6 in v3.2.1 — every verified finding stream is
  assessment evidence for it).
- Source honesty rule (machine-checked): a category is tagged `official` ONLY
  when the row's CWE appears in that category's official "List of Mapped CWEs"
  on top10.owasp.org; the fetched lists are embedded in the module and the
  parity test re-verifies every `official` claim. Anything else is tagged
  `scope` (declared editorial assignment) — never presented as official.
  - Rows: 54. `official` 2021: 12/54 · `scope` 2021: 42. `official` 2025:
    36/54 · `scope` 2025: 18.
- The OWASP Top 10:2025 list used is the FINAL release (A03 Software Supply
  Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure
  Design) — NOT the April-2025 release candidate still shown by most public
  references. Verified against top10.owasp.org/2025 (fetched 2026-10-31).
- Surfaces carrying the mapping (all verified this session):
  result.json per finding · SARIF rules+results properties · executive
  rollup · JSON · HTML (per-finding column + summary section) · GLASS panel ·
  platform `Finding.complianceJson` column · finding-detail API + UI chips ·
  public `/docs/compliance` table · `sentinel compliance [--json]` CLI.
- **secure_cookie gap, found BY the new check**: the fixture battery emits
  `secure_cookie`, which was registered in NEITHER SARIF_RULES nor the
  compliance registry (3 findings honestly returned `unmapped`). Root cause
  fixed: `SEN-CKI-001` rule + CWE-614 → A02:2025 (official — CWE-614 is in the
  fetched A02:2025 list). Re-check over the saved 199-finding benchmark run:
  all findings mapped. This is the guard working as designed — an unregistered
  class can never silently silently ship again.
- Drift guard: `src/lib/compliance-registry.json` is GENERATED
  (`scripts/gen_compliance_registry.py`); CI regenerates and fails on any
  diff; the bun suite also asserts live parity with `sentinel compliance --json`.

## 2. Canonical fixture reproduction (determinism held)

The verified campaign configuration, re-run unchanged
(`scripts/ci_fixture_run.py` — same ScanConfig as the reverify campaign:
seed `bench430`×8, auth demo, authz accounts, workflow+logic+race+symbolic,
max_requests=0):

| Metric | Campaign record | This session |
|---|---|---|
| P / R / F1 | 1.0 / 1.0 / 1.0 | 1.0 / 1.0 / 1.0 |
| Confusion | TP=38 FP=0 FN=0 TN=37 | TP=38 FP=0 FN=0 TN=37 |
| Verified findings | 199 | 199 |
| Distinct types | 30 | 30 |
| Requests | 7162 | 7162 |
| Duration | 101.0s | 102.4s |

All five report formats exported from the run's store; SARIF: 30 rules /
199 results, every result carrying `properties.compliance`. Executive 2025
distribution: A01:87 · A02:6 · A03:1 · A05:18 · A06:86 · A07:1 — PCI 6.4.2
evidence: 199.

## 3. PostgreSQL migration (item 7) — real, not declarative

- `prisma/schema.prisma` provider sqlite → postgresql; real migrations
  (`prisma/migrations/20261031000000_pg_init/migration.sql`, 247 lines) applied
  with `prisma migrate deploy` on a REAL local cluster (pgserver wheel —
  unprivileged, no docker, no root; TCP 127.0.0.1:55432 because Prisma 6
  rejects socket-only URIs). 11 tables. `scripts/verify_postgres.sh`:
  POSTGRES_VERIFY_OK (migrate + tables + transactional round-trip + json cast).
- Engine per-target stores stay SQLite BY DESIGN (deterministic,
  file-per-target under `saas-data/stores`) — documented in schema + README.
- Every integration run now exercises the migration files end to end
  (the runner never uses `db push` — that path is gone).
- `docker-compose.yml` (postgres:17-alpine, loopback-only, password via env)
  ships for the VPS; honestly marked UNTESTED LOCALLY in KNOWN_LIMITATIONS
  (no docker in the dev environment) — the PG path itself is verified via
  pgserver locally + the GitHub service container in CI.

## 4. CI (item 5) — one workflow file, five jobs

`.github/workflows/ci.yml`: web (lint/typecheck/unit/integration/build on a
real postgres service container — DATABASE_URL protocol-checked by the
runner so dev leftovers can never leak in) · engine (doctor + python suite
incl. compliance parity) · secrets · fixture (canonical full-platform run +
benchmark regression gate F1==1.0/TP==38/FP==0 + all five report formats as
artifacts) · drift (compliance registry regeneration guard).
GitLab CI template: `integrations/gitlab-ci/sen-scan.gitlab-ci.yml`
(`include:`-able, `.sentinel:scan` job with the CI exit contract).

## 5. Auth + public surface (item 7)

- Server-side session guard on every `(app)` page
  (`src/app/(app)/layout.tsx` → redirect /login) — pinned by an integration
  test (unauthenticated /overview → 307 /login). Client redirects remain UX
  only, as documented.
- `pages.signIn` moved to `/login`; `/` is now the PUBLIC landing; `/docs`
  (quickstart, compliance, CI, deployment, security) and `/demo` (one real
  engine scan against the managed fixture) are public.
- `/api/demo/scan`: unauthenticated by design with a minimal-by-construction
  contract — hardcoded target (request bodies ignored entirely), per-IP
  3/hour, one lane globally, output capped at 30 findings, zero tenant-DB
  writes. Pinned by tests (400 without id / 404 unknown id).

## 6. Suites (all re-executed 2026-10-31, pre-push)

| Suite | Result |
|---|---|
| python (full, incl. 7 compliance tests) | 196/196 |
| bun unit (22 security + 5 compliance incl. live CLI parity) | 27/27 |
| integration over the wire on real PostgreSQL | 26/26 (14 legacy + 12 P2) |
| engine doctor | PASS (exit 0) |
| typecheck + lint + production build | PASS |
| compliance drift guard (regen + git diff) | clean |

New integration coverage: public pages render without a session ·
/docs/compliance carries the registry table · server guard redirect ·
demo API contract · compliance import path end to end
(reconcileScan → complianceJson column → finding-detail API, verbatim).

## 7. Phase-3 groundwork (items 8–10, documents only)

`docs/phase3/pentest-rfp.md` (vendor-comparable scope, fixed weights) ·
`docs/phase3/soc2-readiness.md` (control inventory vs real gaps; Type II only
at the first enterprise customer) · `docs/phase3/hosted-free-tier.md`
(limits, hard security boundaries, 60-day continuation metrics).

## 8. Push record

Executed after the owner's green light (administration PAT supplied in
session 2026-10-31; passed via GH_TOKEN env only — never written to disk,
never echoed; see the push-gate script for the exact protocol).
Fast-forward only; origin/main re-verified post-push by ls-remote; GitHub
Actions runs checked to green on all five jobs; repo visibility re-verified
private. The wire-level details (hashes, run ids) live in the session log;
the durable claims are the ones above.

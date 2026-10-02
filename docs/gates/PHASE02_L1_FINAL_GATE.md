# PHASE 02 — L1 FINAL GATE: Security Twin Normalization + Provenance

**Date**: 2026-10-02 · **Branch**: `phase/02-l1-twin` · **Verdict**: **PASS**

## Baseline immutability

| Check | Result |
|---|---|
| `v4.1.1` tag | `184871e` (VERIFIED RECOVERED BASELINE) — untouched |
| `release/v4.1.1` | `184871e` — untouched |
| `phase/02-l1-twin` | built ON TOP of `main` (`844ea34` = L1-R final); zero L1 work on `release/v4.1.1` |
| Engine diff vs tag (branch) | **0 files** (`git diff v4.1.1 phase/02-l1-twin -- build-v411/` empty) |
| Engine diff vs tag (worktree) | **0 files** |
| Protected dirs (`build-v411/`, `gap-validation/`, `recovery-validation/`, `release-archives/`) | unmodified; engine gate ran on a FRESH extraction (`l1-validation/engine`) of the SHA256-verified frozen archive (`SENTINEL-v4.1.1-source.tar.gz: OK`) |

## Engine gates (fresh extraction from the frozen archive)

| Gate | Result |
|---|---|
| Test suite | **102/102 PASS** (9 chunks, strict accounting: ran=N/N, failed=0, no missing) — one transient port conflict from a stale L1-R fixture process was cleaned and the chunk re-run clean |
| Doctor | **15/15 PASS** (all checks PASS) |
| Benchmark ×3 | **F1 = 1.000 — TP=38 FP=0 FN=0 TN=35, findings=190, requests=1756 — IDENTICAL ×3** |
| Engine semantics | NOT modified (L1 is a post-scan read-only layer; planner/workflow/GraphQL/WebSocket/authz/reasoning/evidence/boundary/coverage engines untouched) |

## SaaS gates (production build with L1 code)

| Gate | Result |
|---|---|
| E2E (full product flow, live engine scan) | **68/68 PASS** (72s, temp instance port 3013) |
| Tenant isolation attacks (L0 suite, unchanged) | **37/37 PASS** (137s, temp instance port 3002, incl. explicit-victim-orgId = 404) |
| Production verification (live :3000, main DB) | **30/30 PASS** (incl. `prod.page_twin`) — demo data rebuilt through real product flows only |

## L1 gates

| Gate | Result | Evidence |
|---|---|---|
| Unit suite | **163/163 PASS** | `saas-data/l1-twin/l1_twin_unit_results.json` |
| — fixtures ×10 (expected nodes/edges/provenance/conflicts + **golden twinHashes frozen**) | PASS | `scripts/l1_twin_suite.ts` group A |
| — determinism ×3 (hash/IDs/counts/provenance per fixture) | PASS | group B |
| — invariants INV-01..10 + INV-11..13 (fixtures + 4 real engine outputs) | PASS | groups A/C |
| — equivalence gate (raw→twin→projection, 17 dimensions, zero missing) | PASS | group D |
| — adversarial / no-hallucination ×12 | PASS | group E |
| — malicious input ×11 (HTML/script/SQL/long/dup/cyclic/malformed/invalid-provenance/tenant-injection) | PASS | group F |
| — performance (100 / 1k / 10k nodes, measured) | PASS | group G (below) |
| API + tenant isolation suite (live server, 2 real scans) | **33/33 PASS** | `saas-data/l1-twin/l1_twin_api_results.json` |
| Twin normalization complete | PASS | `src/lib/twin/` (types/provenance/hash/sanitize/mapping/normalize/invariants/equivalence/fixtures/persist/loader/service) |
| Deterministic IDs + twinHash | PASS | content-derived `N-/E-/C-/U-<sha256[:16]>`; sha256 over canonical JSON; no timestamps/random/PIDs |
| UI functional | PASS | `/twin` real twin (below) — browser-verified |

## Performance (measured on this container — no unproven claims)

| Scale | Nodes | Edges | normalize | invariants | equivalence | graphJson |
|---|---|---|---|---|---|---|
| 100 | 81 | 80 | 2 ms | 1 ms | 0 ms | 63 KB |
| 1k | 947 | 946 | 20 ms | 19 ms | 1 ms | 740 KB |
| 10k | 10,082 | 10,081 | 286 ms | 208 ms | 46 ms | 7.9 MB |

Structural caps: 50k nodes / 250k edges (deterministic truncation + known-unknown).
Real scans: demo target 638 nodes / 643 edges; benchmark.json 899/977 in 41 ms.

## Production twin (real scan, live :3000)

```
scan        : cmuq7eq8t008rlvxgfznol2qa (run-9696972c29, demo target, 144 findings)
twinHash    : 3f774ad9b55d8f958f2a6f64a988cded8b4ff006e62ab71092212400b2c850c8
schema      : l1-twin/1.0.0
Nodes = 638   Edges = 643
OBSERVED = 616   INFERRED = 22   VERIFIED = 0   REFUTED = 0   UNKNOWN = 0
claims: VERIFIED = 147   REFUTED = 12   UNKNOWN = 0   CONFLICT = 0
CONFLICTS = 0   KNOWN UNKNOWNS = 2
```
(Both demo scans on the same target/options normalize to identical counts — content-derived identity holds across independent scans.)

## Browser verification (agent-browser, production :3000)

- `/twin` renders the real normalized twin: KPIs, twinHash, provenance distribution,
  scan selector (both scans), type/provenance filters, deterministic SVG graph
  (160 nodes displayed of 638 with honest cap notice), node table, why() panel
  (structured reason + sourceRefs + attrs + related edges), known unknowns.
- Screenshots: `saas-data/l1-twin/verify-twin-01.png`, `verify-twin-02-why.png`,
  `verify-twin-03-full.png`.
- **Console: 0 errors, 0 warnings.**

## Attack-path scope guard (spec §18)

No AttackPath engine, DB model, ranking, verification or UI was implemented.
The normalized twin substrate is the only deliverable of this phase.

## Read-only guard (spec §19)

Zero new network requests: the twin API/page read `result.json` / the platform
DB and normalize in-process. Verified: no engine invocations from the twin
service (`service.ts`), no HTTP clients in `src/lib/twin/`.

## Incident record (environment, documented honestly)

1. The container's supervisor reset `HEAD` to `main` repeatedly and killed
   background processes between/around tool calls (rollback #5/#6 pattern).
   Mitigations: plumbing commits via temporary index + `update-ref` (HEAD
   untouched), foreground chunked test execution (the repo's GATE-F pattern).
   One self-inflicted pointer mistake during correction (`branch -f` to a
   main that lacked the L1 commits) briefly orphaned L1-01/02 — recovered
   from the reflog WITHOUT history rewriting; both commits preserved verbatim
   (`a7e81b0`, `65720ee`); the duplicate worklog commit (`a2b4712`) remains as
   a dangling object, documented here.
2. The main production DB was reset for the production gate (standard L1-R
   procedure); demo data was rebuilt through real product flows only
   (`bootstrap_demo_data.py`: admin + Sentinel SOC + 2 members + demo target
   + 2 real engine scans 144+144 findings + HTML/SARIF reports).
3. A stale L1-R fixture process (vulnapp on a benchmark port, parented to the
   old pre-rebuild :3000 server whose cwd the rebuild had replaced) caused one
   transient test-port conflict; both stale processes were killed and the
   affected chunk re-run clean.

## Commits (phase/02-l1-twin)

```
927ae7c L1-06 twin: full test suites — unit (163 checks) + API orchestrator + tenant-isolation attack matrix
6dcf26c L1-07 twin: documentation — SECURITY_TWIN_L1 / TWIN_SCHEMA / PROVENANCE_MODEL
b4582e4 L1-04 twin: persistence — Prisma TwinGraph + raw loader + twin service
0034511 L1-05 twin: API v1 route + UI /twin rewrite + api client + i18n
352d5b3 L1 worklog: preflight + rollback#5 incident record + core progress
65720ee L1-02 twin: provenance model + normalizer (why/conflicts/known unknowns) + smoke scripts
a7e81b0 L1-01 twin: canonical schema core — types, deterministic IDs, twinHash, sanitization, mapping
```
(Boundary note: `a7e81b0` "L1-01" carries the complete core lib — the commit
chain broke mid-sequence when the supervisor switched branches; `65720ee`
"L1-02" carries the two verification scripts. Contents documented in the
worklog; later commits split cleanly.)

## Final checklist

- [x] v4.1.1 immutable
- [x] engine diff = 0
- [x] 102/102 · Doctor 15/15 · Benchmark ×3 F1=1.000 (identical)
- [x] 68/68 E2E · 37/37 tenant isolation · 30/30 production
- [x] Twin normalization complete · provenance complete (5 values only)
- [x] deterministic IDs · deterministic twinHash (golden fixtures frozen)
- [x] INV-01..10 PASS (+INV-11..13)
- [x] equivalence gate PASS
- [x] adversarial / no-hallucination PASS
- [x] tenant isolation PASS (API + persistence + audit trail)
- [x] API contract PASS (versioned, read-only)
- [x] performance measured (100/1k/10k)
- [x] UI functional (browser-verified)
- [x] console 0 errors / 0 warnings
- [x] documentation complete (docs/twin/*)
- [x] no Attack Paths implemented (deferred)
- [x] no new active testing / network requests

**PHASE 02 — L1 = PASS**

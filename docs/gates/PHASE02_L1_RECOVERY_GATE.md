# PHASE 02 — L1 FINAL RECOVERY GATE

**Date**: 2026-10-02 · **Scope**: prove the L1 candidate state is fully recoverable
OUTSIDE the current working tree (ARCHIVE → CLEAN RESTORE → BUILD → TEST → SAME RESULT)
and lock it permanently (two archive copies, git re-anchor, recovery ledger).

**Designated state references (user order)**:
- `7838404` = **L1 candidate state** (final commit of `phase/02-l1-twin` at L1 close)
- `184871e` = **VERIFIED RECOVERED v4.1.1 BASELINE** (`184871ec597e45135b56e7b0aca6eebf3116c1e2` per the frozen recovery manifest)

---

## 1. LOCK CURRENT STATE (executed before any modification)

### 1.1 Working repository `/home/z/my-project` (as found)

| Item | Value |
|---|---|
| Branch | `main` (the ONLY branch; supervisor-managed) |
| HEAD | `9eb917b693388f9c370834ae73bd638c534d6c44` (UUID snapshot commit `37b8094c-…`) |
| Parent | `f1b9e6033eeb04e383cae563deea705b0d7d90df` |
| History | 29 UUID snapshot commits (the documented pre-R3 base) |
| Tags | **0** (`v4.1.1` GONE) |
| Branches | 1 (`main` only; `release/v4.1.1` and `phase/02-l1-twin` GONE) |
| `git fsck --full` | clean — **no dangling objects**: all L1-R/L1 commit objects are gone, not merely unreferenced |
| Working tree | the pre-v4.1.1 rollback state (no `src/`, no SaaS, no `build-v411/`, no `release-archives/`, no `docs/gates/`) |

**Rollback #7 confirmed** — same documented pattern as #1–#4: the container reverted
`/home/z/my-project` (tree + `.git`) to the pre-L1-R snapshot. The git objects for
`184871e`, `e106c1e`, `92d82b8`, `c3b79bb`, `8b41e78`, `844ea34`, `a7e81b0`,
`65720ee`, `352d5b3`, `0034511`, `b4582e4`, `6dcf26c`, `927ae7c`, `7838404` do
not exist in any local object store (no surviving `.git` anywhere on the
filesystem; `/tmp` scanned; `git fsck` empty).

### 1.2 Survivor tree `/tmp/my-project` (read-only source of truth for content)

Full L1-final worktree (platform end-of-session snapshot, 2026-10-02 00:12), **no `.git`**.

**Integrity proof — survivor vs frozen L1-R fullstate archive
(`SENTINEL-fullstate-2026-10-02.tar.gz`, SHA256 `6636c372…1b8e0`, 805 files extracted):**

The complete difference is EXACTLY the documented L1 delta plus known untracked files:

- **L1 source additions**: `src/lib/twin/` (13 files), `src/app/api/v1/scans/[scanId]/twin/`,
  `scripts/l1_*` (7 files), `docs/twin/` (3 files), `docs/gates/PHASE02_L1_FINAL_GATE.md`
- **L1 source modifications**: `prisma/schema.prisma` (TwinGraph model),
  `src/app/(app)/twin/page.tsx` (UI rewrite), `src/components/saas/api.ts` (client types),
  `src/lib/ui/i18n.tsx` (AR+EN), `.gitignore`, `worklog.md`
- **L1 evidence**: `saas-data/l1-twin/` (unit 163/163 + API 33/33 results, 3 browser PNGs),
  `l1-validation/` (frozen engine extraction + engine-outputs: bench ×3, doctor, 4 ledgers),
  re-run `saas-data/{e2e_results,l0_isolation_results,l0_prod_verify}.json`
- **L1-R B4 additions (expected, in-tree)**: `release-archives/SENTINEL-fullstate-2026-10-02.tar.gz` + `.sha256`,
  updated `SENTINEL-v4.1.1-recovery-manifest.json` (B3→B4 fields), `.gitignore` (`tool-results/`)
- **Known untracked / gitignored (excluded from git-tracked content, kept in tree)**:
  the 8 dead P0 components (`bits.tsx`, `login-view.tsx`, `sentinel-app.tsx`, `views-*.tsx` ×5),
  `gap-validation/logs/*.log` (12 runtime logs), `gap-validation/results/tests_v411_run.log`,
  `gap-validation/targets/`, `readiness/`, `verify-live/`, `saas-data/*.log` (2),
  `build-v411/results/.doctor_v410.json.LxCyMV` (the documented atomic-write temp file)

No unexpected modification anywhere in the tree. **Content baseline 100% intact.**

### 1.3 Immutable archives (SHA256 re-verified now, all MATCH the frozen records)

| Archive | SHA256 | Status |
|---|---|---|
| `SENTINEL-v4.1.1-source.tar.gz` (1,263,577 B) | `f7c6d219ad0ee8fad29f51d776b59adf95fd4f3c2334fdb20568e17b719fcfbb` | **MATCH** (L0-approved baseline) |
| `SENTINEL-v4.1.1-live-evidence.tar.gz` (395,523 B) | `93e883f8225982e8c6be890fa84812e0064060dec489fc7cf99268506bf2cc24` | **MATCH** |
| `SENTINEL-fullstate-2026-10-02.tar.gz` (14,359,909 B) | `6636c372fd3bc1948f658b88d36d8af1aafff78b4041b7bbd29d5b0e8511b8e0` | **MATCH** (L1-R B4 record) |

### 1.4 Recorded L1 gate results (the targets the clean restore must reproduce)

From `docs/gates/PHASE02_L1_FINAL_GATE.md` + `saas-data/l1-twin/*.json` (frozen evidence):

- Unit suite **163/163** (10 fixtures with golden twinHashes, determinism ×3, INV-01..13,
  equivalence 17 dims, adversarial ×12, malicious ×11, perf 100/1k/10k)
- API + tenant isolation **33/33** (twinA `cmuq5u5tl…` hash `3e633680…caf5` 638n/643e;
  twinB `cmuq5vndt…` hash `c619511b…bd4f` 638n/643e — identical counts across independent scans)
- Engine **102/102** (9 chunks, strict accounting), Doctor **15/15**,
  Benchmark ×3 **F1=1.000, TP=38 FP=0 FN=0 TN=35, findings=190, requests=1756 — IDENTICAL ×3**
- SaaS E2E **68/68**, tenant isolation **37/37**, production **30/30** (incl. `prod.page_twin`)
- Production twin (scan `cmuq7eq8t…`): schema `l1-twin/1.0.0`, **638 nodes / 643 edges**,
  OBSERVED=616 INFERRED=22, claims VERIFIED=147 REFUTED=12, conflicts 0, known unknowns 2,
  twinHash `3f774ad9b55d8f958f2a6f64a988cded8b4ff006e62ab71092212400b2c850c8`
- Browser `/twin`: 3 screenshots, console 0 errors / 0 warnings

### 1.5 Lost-with-rollback (documented, rebuildable)

- Git objects/history for all L1-R/L1 commits + tags (re-anchored in §7 — honestly, new SHAs)
- `db/custom.db` (main DB) — rebuilt through real product flows (`bootstrap_demo_data.py`)
- `saas-data/scans/` + `saas-data/stores/` (raw scan run outputs) — regenerated by re-running
  the demo scans; the twin identity of LOST run-specific scans cannot be byte-reproduced
  (see KNOWN_LIMITATIONS) — structural identity re-proven on fresh scans
- `NEXTAUTH_SECRET` (untracked env secret) — regenerated (documented L1-R environment completion)
- `node_modules/`, `.next/` — rebuilt by `bun install` / `next build`

### 1.6 Verdict of the lock step

Content: **INTACT** (bit-proven vs frozen archives). Git labels: **LOST (rollback #7)** →
re-anchored truthfully in §7 without fabricating history. Proceeding to package build.

---

## 2. RECOVERY PACKAGE (built from the survivor tree, before any modification)

`PHASE_02_L1_COMPLETION/` with: README, RECOVERY_MANIFEST.json,
SOURCE_ARCHIVE.tar.gz (**837 files** = frozen fullstate 805 + exact L1 delta 32;
verified **0 unexpected differences** vs the survivor tree), STATE_ARCHIVE.tar.gz
(**276 files** = `saas-data/` + `l1-validation/` evidence), SHA256SUMS,
TEST_RESULTS, BUILD_RESULTS, REGRESSION_RESULTS, CHANGELOG, KNOWN_LIMITATIONS,
RESTORE_INSTRUCTIONS, this gate report.

## 3. TWO INDEPENDENT COPIES

- **PRIMARY**: `release-archives/PHASE_02_L1_COMPLETION-PRIMARY.tar.gz` — committed to git
- **SECONDARY**: `download/PHASE_02_L1_COMPLETION-SECONDARY.tar.gz` — user-downloadable

Each produced by an independent `tar` run of the finished package directory
(not references to a shared temp file; deterministic tar → byte-identical copies,
different inodes). Their SHA256 values are recorded in the sidecar files, the
repo-level ledger, and the final report (a tar cannot contain its own hash).

## 4. CLEAN RESTORE TEST (separate directory: `/home/z/l1-clean-restore`)

Extraction → integrity (both archives `sha256sum -c` OK) → **engine diff vs
SHA256-verified frozen archive = 0 files** → `bun install` (827 pkgs) →
`db:push` (SQLite + TwinGraph) → full gate battery:

| Gate | Result | vs frozen L1 evidence |
|---|---|---|
| L1 unit suite | **163/163** | identical; **10 golden twinHashes byte-exact** |
| Real-output twin check | **4/4 PASS** | benchmark.json 899n/977e identical; invariants+equivalence+determinism ×4 |
| Engine suite | **102/102** (9 chunks, ran=N/N, failed=0, missing=[]) | identical |
| Doctor | **15/15** | per-check status map identical |
| Benchmark ×3 | **F1=1.000 · TP=38 FP=0 FN=0 TN=35 · 190 findings · 1756 requests · run-3c0652b6be ×3** | bit-equal metrics |
| Build | **OK** (`tsc --noEmit` 0 errors, standalone output, `/twin` route present) | — |
| SaaS E2E | **68/68 (72s)** | check names+statuses identical |
| Twin API + tenant matrix | **33/33 (137s)** | identical; twinA/twinB **638n/643e** |
| Tenant isolation (L0) | **37/37 (137s)** | check names+statuses identical |
| Production verification | **30/30 (67s, incl. prod.page_twin)** | check names+statuses identical |
| Demo data (real flows) | admin + Sentinel SOC + 2 members + demo target + **2 real scans 144+144** + HTML/SARIF reports | identical |
| Browser `/twin` | renders real twin: 638/643, OBSERVED 616/INFERRED 22, claims 147/12, conflicts 0, unknowns 2, twinHash badge, invariants badge, 160-of-638 honest cap, why() panel with N- evidence refs, from-store; **console 0 errors 0 warnings**; screenshots ×3 | identical structure |
| TwinGraph persistence | 2 rows org-scoped, **contentHash == API twinHash**, graphJson 568,249 B both scans | same behavior |

**Environment findings (documented, fixed inline)**: the platform shell exports
`DATABASE_URL` which overrides a restore dir's `.env` (prisma/dotenv precedence)
— every restore-tree command must set it explicitly; one side-effect DB created
in the old tree was deleted immediately. NEXTAUTH_SECRET regenerated (untracked
secret, standard L1-R completion).

## 5. L1 REGRESSION + ENGINE DIFF

All regressions above ran on the clean-restored tree. **Engine diff = 0**:
restored `build-v411` is bit-identical to the SHA256-verified frozen
`SENTINEL-v4.1.1-source.tar.gz` (and later, after re-anchor,
`git archive v4.1.1:build-v411` diff = 0). No engine semantics touched: L1 is a
read-only post-scan layer; `src/lib/twin/` contains no HTTP clients, no engine
invocations.

## 6. TWIN IDENTITY (step 6 of the order)

- **Golden fixtures ×10: twinHash byte-exact** vs frozen goldens (complete,
  partial, inferred, verified-evidence, refuted, unknown, missing-identity,
  missing-authorization, blocked-boundary, conflicting-evidence).
- **Same-input determinism**: unit suite group B ×3 per fixture; API twinHash
  stable ×3 per scan; real-output check ×3 per file — all PASS.
- **Fresh production twins (both demo scans)**: **structural identity MATCH** vs
  the frozen production twin — 638n/643e, OBSERVED=616 INFERRED=22, claims
  VERIFIED=147 REFUTED=12, conflicts 0, known unknowns 2, schema l1-twin/1.0.0,
  invariants PASS.
- **Node/edge IDs**: content-derived (`N-/E-<sha256[:16]>`), proven stable by the
  golden-hash byte-equality (hash covers every node/edge ID) + the why() panel's
  `N-…` evidence refs.
- **Cross-session benchmark twins**: frozen `bench_l1_{1,2,3}.json` vs fresh
  `bench_restore_{1,2,3}.json` — identical 900n/978e, 856/44, claims 201/20/2,
  conflicts 0, unknowns 4 (per-run hashes differ: volatile run-scoped IDs in raw
  output — the documented determinism boundary; see KNOWN_LIMITATIONS §1.2).

---

## 7. GIT SAFETY — re-anchor after rollback #7 (executed AFTER all gates passed)

### 7.1 Original → recovered map (NEW honestly-dated commits; NO history fabrication)

| Original (LOST with rollback #7) | Recovered | Content proof |
|---|---|---|
| `184871e` (v4.1.1 baseline, tag `v4.1.1`) | **`A' = 2d5ce2f613faafc2683b30316a2f44c2dddf785e`** | `git archive A':build-v411` **diff = 0** vs SHA256-frozen `SENTINEL-v4.1.1-source.tar.gz` (113/113 files) + gap-validation frozen evidence (34 files) |
| `e106c1e→92d82b8→c3b79bb→8b41e78` + main `844ea34` (L1-R) | **`R' = 5de40c4204407368e63c4742d13df9804f21042e`** | tree = frozen `SENTINEL-fullstate-2026-10-02.tar.gz` content (SHA256 `6636c372…`) + B4 additions (807 files) |
| L1 chain `a7e81b0→65720ee→352d5b3→0034511→b4582e4→6dcf26c→927ae7c` + **`7838404` (L1 candidate)** | **`L' = 064e0f5eecf4bedeb9836fb85c0b3d01b78816e4`** | tree = fullstate + exact L1 delta (837 files) == `SOURCE_ARCHIVE.tar.gz` content (SHA256 `578709f6…`); 0 unexpected differences vs the survivor tree |
| — | **`G'`** (this package + ledger + rules) | tip of `phase/02-l1-twin`; SHA = `git rev-parse recovery/l1-candidate-2026-10-02` |

Parent chain: `9eb917b` (surviving UUID snapshot tip — the same base the L0/L1-R
re-anchors used) → A' → R' → L' → G'. Superseded first-attempt objects
(`5c5d55f…`, `293774f…`, missing the historically-tracked
`sentinel/results/fixture.log`) remain as documented dangling commits.

### 7.2 Refs after the gate

- tag **`v4.1.1`** → A' (annotated: VERIFIED RECOVERED BASELINE, re-anchor #2)
- branch **`release/v4.1.1`** → A'
- branch **`main`** → R' (mirrors the original layout: main = L1-R final state)
- branch **`phase/02-l1-twin`** → G' (L1 candidate + recovery package; **HEAD**)
- tag **`recovery/l1-candidate-2026-10-02`** → G' (the recovery marker)
- `v4.1.1` / `release/v4.1.1` were NOT repointed at any pre-existing label
  (they did not exist after rollback #7); they are recreated at the
  content-proven baseline, message documenting the whole history.

### 7.3 Integrity checks (all executed, results in the worklog)

- `git archive v4.1.1:build-v411` vs frozen archive: **diff = 0**
- working tree vs `phase/02-l1-twin`: `git status` **clean** (only
  `.gitignore`-declared untracked runtime dirs)
- commit graph verified (`git log --graph --oneline`); no history rewritten
  (the 29 UUID snapshot commits remain untouched below A')
- `git fsck --full`: clean modulo the 2 documented dangling first-attempt
  commits
- no `git reset --hard` used anywhere (mixed `git reset` only, to sync the
  index after `symbolic-ref`)

## 8. PERMANENT RECOVERY RULE (added to the project)

- `docs/PROJECT_RECOVERY_LEDGER.md` — append-only ledger: rollback history,
  verified checkpoints (CP-01 baseline / CP-02 L1-R / CP-03 L1 candidate with
  every SHA256), package-copy hashes, the binding rule.
- `docs/ENGINEERING_RULES.md` — Section 1 codifies the permanent rule:
  **before every phase** BASELINE + COMMIT + BRANCH + TAG + SHA256 + RECOVERY
  MANIFEST; **after every major operation** COMMIT + RECOVERY MARKER + ARCHIVE
  + SHA256 + TEST EVIDENCE; **before the next phase** ARCHIVE → CLEAN RESTORE →
  BUILD → TEST → SAME RESULT; **never** delete recovery artifacts / rewrite
  history / `reset --hard` / repoint the baseline tags / rely on pointers or
  `/tmp` alone.

## 9. VERDICT

**PHASE 02 — L1 RECOVERY GATE: RECOVERY VERIFIED.** The L1 candidate state is
fully recoverable outside the working tree with zero loss of work: archives →
clean restore → build → test → **SAME RESULT (19/19 gate comparisons
identical)**, twin identity proven (golden byte-exact ×10 + structural
identity + same-input determinism), engine diff 0, git re-anchored honestly
with content-proven baseline tags, two independent package copies hashed, and
the permanent recovery rule added to the project.

**Attack Paths NOT started** (per the order). No new features. No engine
changes. No old archives deleted.

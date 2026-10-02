# KNOWN LIMITATIONS — PHASE 02 — L1 RECOVERY PACKAGE

Honest, complete list. Nothing hidden, nothing overstated.

## 1. Permanently lost to container rollback #7 (content elsewhere intact)

1. **Original git objects** for the whole L1-R/L1 lineage: `184871e` (baseline),
   `e106c1e`, `92d82b8`, `c3b79bb`, `8b41e78`, `844ea34` (L1-R), and the L1 chain
   `a7e81b0`, `65720ee`, `352d5b3`, `0034511`, `b4582e4`, `6dcf26c`, `927ae7c`,
   `7838404` (L1 candidate) — plus tags `v4.1.1` (first re-anchor) and branches
   `release/v4.1.1`, `phase/02-l1-twin`. No surviving `.git` on the filesystem
   contains them (`git fsck` clean, `/tmp` scanned). They were re-anchored as NEW
   commits with NEW SHAs (§7 of the gate report) — no history was fabricated or
   backdated; the content is bit-proven via the SHA256-verified frozen archives.
2. **Raw scan run outputs** `saas-data/scans/` + `saas-data/stores/` of the L1-close
   state, and the **main DB** `db/custom.db` — destroyed with the rolled-back tree.
   Consequence: the exact twinHashes of the L1-close scans (`3f774ad9…` for
   `cmuq7eq8t…`; `3e633680…` / `c619511b…` for the API-suite twins) cannot be
   re-derived byte-for-byte (their raw inputs no longer exist). The clean restore
   proves instead: (a) same-input determinism (golden fixtures byte-exact ×10;
   per-scan hash stable ×3), and (b) structural identity of fresh scans
   (638n/643e, 616/22, claims 147/12, conflicts 0, unknowns 2 — all identical).

## 2. Environment completions (documented, no code change)

1. **NEXTAUTH_SECRET** is an untracked environment secret — regenerated on every
   restore (the documented L1-R procedure). Never committed to git.
2. **Platform shell exports `DATABASE_URL=file:/home/z/my-project/db/custom.db`**,
   which OVERRIDES a restore directory's `.env` (prisma/dotenv precedence: real
   env > .env). Every prisma/bun command outside the main tree must set
   `DATABASE_URL` explicitly. One side-effect DB created in the old tree during
   this gate was detected and deleted immediately (recorded in the gate log).
3. **`node_modules/`, `.next/`, DB files** are rebuildable and excluded from the
   archives (rebuilt + verified during the clean-restore test).
4. The 8 **dead P0 components** (`bits.tsx`, `login-view.tsx`, `sentinel-app.tsx`,
   `views-{admin,findings,reports,scans,targets}.tsx`) are present in the /tmp
   survivor snapshot but were never tracked (deleted from git at L1-R after a
   zero-import proof). They are excluded from SOURCE_ARCHIVE and re-deleted on
   any restore — the documented stale-file trap.

## 3. Untracked working-tree directories (kept on disk, ignored by git)

`download/` (deliverables), `readiness/`, `verify-live/`, `tool-results/`,
`live-targets/` (282 MB external test targets), `gap-validation/{tools,dvga-venv,targets}`
(rebuildable via gap-validation setup scripts), plus gitignored `*.log` runtime
logs. These are historical/rebuildable assets, documented in the L1-R manifest,
now explicitly listed in `.gitignore` (recovery-gate commit only).

## 4. L1 product limits (unchanged from the L1 close — not recovery artifacts)

1. **twinHash is scan-specific**: two scans of the same target/options yield the
   same counts/provenance/claims but different hashes (raw engine output embeds
   run-scoped opaque IDs). Structural comparison is the sanctioned cross-run
   identity; byte identity holds for the same raw input only.
2. **Graph UI display cap**: `/twin` renders the 160 most important nodes of 638
   (deterministic layout, honest cap notice). The full graph is in the API +
   TwinGraph.
3. **Read-only layer**: L1 sends zero new network requests; the twin is built
   from stored scan output only. No Attack Paths in this phase (deferred).
4. **DB reconstruction fallback**: if `result.json` is missing, the twin service
   reconstructs from platform DB rows and records honest known-unknowns for the
   gaps.

## 5. This gate's operational notes

1. Benchmark ×3 and the engine suite spawn their own fixtures on ephemeral ports
   (ENG-20 pattern); one transient port conflict occurred in the ORIGINAL L1
   session (documented there) — zero conflicts during this recovery gate.
2. The clean-restore sandbox `/home/z/l1-clean-restore` (~1.5 GB with
   node_modules) is disposable; its results are archived in this package.
3. BUILD_ID differs per build (content+time-derived) — build reproducibility is
   verified by gate results, not by BUILD_ID equality.

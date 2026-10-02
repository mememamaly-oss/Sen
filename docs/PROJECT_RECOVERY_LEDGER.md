# PROJECT RECOVERY LEDGER — SENTINEL

Single source of truth for every baseline, recovery event, and verified
checkpoint. **Append-only. Never delete a documented recovery artifact.**

Format per entry: event → what was lost → what survived → proof → recovery →
verification → anchors (commit/tag/branch/SHA256).

---

## ROLLBACK HISTORY (container environment — pattern documented since v4.1.0)

| # | Event | Lost | Survived | Root cause |
|---|---|---|---|---|
| 1–3 | pre-v4.1.1 era | git lineage (5dfa75d, 7141c2d, 3756d6a, 30162f9) | worktrees via /tmp snapshots | container rollback resets /home/z/my-project |
| 4 | 2026-10-01 (L1 preflight) | .git + v4.1.1 labels + tree state | /tmp/my-project full worktree + SHA256-frozen archives | same |
| 5–6 | 2026-10-01/02 (L1 build) | HEAD forced to main repeatedly; background processes killed | commits recovered via reflog (a7e81b0, 65720ee preserved verbatim) | same |
| 7 | 2026-10-02 (after L1 close, before recovery gate) | **entire L1-R/L1 git object store** (184871e, e106c1e, 92d82b8, c3b79bb, 8b41e78, 844ea34, a7e81b0…7838404, tags, branches) + main DB + saas-data/{scans,stores} | /tmp/my-project full L1 worktree (bit-exact) + all three SHA256-frozen archives + all gate evidence | same |

## VERIFIED CHECKPOINTS (each entry = a recovery anchor — DO NOT DELETE)

### CP-01 · v4.1.1 VERIFIED RECOVERED BASELINE (rollback #4 → L1-R)

- Content: `SENTINEL-v4.1.1-source.tar.gz` SHA256 `f7c6d219ad0ee8fad29f51d776b59adf95fd4f3c2334fdb20568e17b719fcfbb` (113 files) + live-evidence `93e883f8225982e8c6be890fa84812e0064060dec489fc7cf99268506bf2cc24`
- Original anchor (LOST in #7): commit `184871ec597e45135b56e7b0aca6eebf3116c1e2`, tag `v4.1.1`
- Frozen gates with this content: engine 102/102 · doctor 15/15 · benchmark ×3 F1=1.000 · E2E 68/68 · isolation 37/37 · production 30/30

### CP-02 · L1-R full state (rollback #4 → L1-R)

- Content: `SENTINEL-fullstate-2026-10-02.tar.gz` SHA256 `6636c372fd3bc1948f658b88d36d8af1aafff78b4041b7bbd29d5b0e8511b8e0` (805 files)
- Original anchors (LOST in #7): commits `e106c1e → 92d82b8 → c3b79bb → 8b41e78`, main tip `844ea34`
- Gates: all CP-01 gates re-proven live + clean reconstruction PASS

### CP-03 · PHASE 02 — L1 candidate state (rollback #7 → FINAL RECOVERY GATE, 2026-10-02)

- **Designated original** (operator order): `7838404` on `phase/02-l1-twin` — LOST
- **Survivor**: /tmp/my-project L1-final worktree — verified = CP-02 content + exact L1 delta (nothing else)
- **Package**: `PHASE_02_L1_COMPLETION/` —
  SOURCE_ARCHIVE `578709f6e0e11962e11d3cbd1b20614c5f08ad6131d23d9a40f72bcd477e90d8` (837 files),
  STATE_ARCHIVE `de249dad048e14fbe7803d03b16c1a4a64cb74b25002fdf6474466f91f62ff03` (276 files)
- **PRIMARY copy**: `release-archives/PHASE_02_L1_COMPLETION-PRIMARY.tar.gz` — SHA256 in sidecar `…tar.gz.sha256` (see below)
- **SECONDARY copy**: `download/PHASE_02_L1_COMPLETION-SECONDARY.tar.gz` — SHA256 in sidecar
- **Clean-restore proof** (separate dir, ALL gates re-run): engine 102/102 · doctor 15/15 ·
  benchmark ×3 F1=1.000 identical (38/0/0/35, 190, 1756, run-3c0652b6be ×3) · engine diff 0 ·
  unit 163/163 golden byte-exact · twin API 33/33 · E2E 68/68 · isolation 37/37 · production
  30/30 · demo 144+144 · twin structural identity 638n/643e (147/12, unknowns 2) · browser
  verified, console clean → **SAME RESULT: PASS (19/19)**
- **Re-anchored commits (new, honestly dated — no fabrication)**:
  - `A' = 2d5ce2f613faafc2683b30316a2f44c2dddf785e` — v4.1.1 baseline (build-v411 DIFF=0 vs frozen archive + gap-validation) — tag `v4.1.1`, branch `release/v4.1.1`
  - `R' = 5de40c4204407368e63c4742d13df9804f21042e` — L1-R full state — branch `main`
  - `L' = 064e0f5eecf4bedeb9836fb85c0b3d01b78816e4` — L1 candidate state
  - `G'` — recovery gate commit (package + ledger + rules) — branch `phase/02-l1-twin` (tip), tag `recovery/l1-candidate-2026-10-02`; SHA: `git rev-parse recovery/l1-candidate-2026-10-02`
- Superseded dangling objects (documented): `5c5d55f…`, `293774f…` (first R'/L' attempts missing `sentinel/results/fixture.log`)
- Twin identity anchors: 10 golden fixture twinHashes (byte-exact across sessions — recorded in `saas-data/l1-twin/l1_twin_unit_results.json`); L1 reference structure: 638n/643e · OBSERVED=616 INFERRED=22 · claims VERIFIED=147 REFUTED=12 · conflicts 0 · known unknowns 2 · schema `l1-twin/1.0.0`
- Environment completions: NEXTAUTH_SECRET regenerated (untracked); platform `DATABASE_URL` export overrides `.env` (documented); `download/`, `readiness/`, `verify-live/`, `gap-validation/{tools,dvga-venv,targets}` declared untracked-ignored (historical/rebuildable)

## RECOVERY PACKAGE HASHES (gate close, 2026-10-02)

- PRIMARY: `release-archives/PHASE_02_L1_COMPLETION-PRIMARY.tar.gz` — SHA256 `39fa825d0193a9f02f4d2c9fd5a79d751af82f570ddc25755d36c170e23c645e`
- SECONDARY: `download/PHASE_02_L1_COMPLETION-SECONDARY.tar.gz` — SHA256 `39fa825d0193a9f02f4d2c9fd5a79d751af82f570ddc25755d36c170e23c645e`
- Both produced by independent tar runs of this finished package (deterministic tar → byte-identical copies, different inodes — not references to one temp file). A tar cannot contain its own hash: the canonical hash values live in the sidecars, in the repo-level copy of this ledger, and in the gate final report.

---

## PERMANENT RECOVERY RULE (binding — see docs/ENGINEERING_RULES.md)

**Before every phase**: BASELINE + COMMIT + BRANCH + TAG + SHA256 + RECOVERY MANIFEST.
**After every major operation**: COMMIT + RECOVERY MARKER + ARCHIVE + SHA256 + TEST EVIDENCE.
**Before moving to the next phase**: ARCHIVE → RESTORE → BUILD → TEST → SAME RESULT.
**Never**: delete a documented recovery artifact; rewrite history; `git reset --hard`;
repoint `v4.1.1` / `release/v4.1.1`; rely on branch pointers alone (this container
resets them); rely on `/tmp` alone (it is a snapshot, not a backup).

*(repo-level copy — supersedes the package-internal fill-in pointers; canonical hashes recorded here on gate close 2026-10-02)*

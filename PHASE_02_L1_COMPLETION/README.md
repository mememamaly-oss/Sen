# PHASE 02 — L1 COMPLETION RECOVERY PACKAGE

**SENTINEL — Security Twin Normalization + Provenance (PHASE 02 — L1)**
Package date: 2026-10-02 · Verdict: **RECOVERY VERIFIED** (see `PHASE02_L1_RECOVERY_GATE.md`)

## What this is

The complete, self-contained recovery package for the PHASE 02 — L1 candidate
state (the state designated by the operator as commit `7838404`, whose git
objects were destroyed by container rollback #7). It proves and preserves:

1. the full L1 source state (SaaS + engine + docs + evidence directories),
2. the exact gate results produced from a CLEAN RESTORE of those archives,
3. the identity anchors (golden twinHashes, structural twin identity),
4. the permanent recovery rules going forward.

## Contents

| File/Dir | Purpose |
|---|---|
| `RECOVERY_MANIFEST.json` | Machine-readable manifest: commits, branches, tags, SHA256s, gate results, environment, restore commands |
| `SOURCE_ARCHIVE.tar.gz` | Git-tracked-equivalent L1 source tree (837 files): SaaS `src/`, `prisma/`, `scripts/`, `docs/`, `tests/`, engine `build-v411/`, frozen `gap-validation/`, `release-archives/`, configs, `worklog.md` |
| `STATE_ARCHIVE.tar.gz` | Evidence state (276 files): `saas-data/` (all gate results + screenshots) + `l1-validation/` (engine gates evidence) |
| `SHA256SUMS` | SHA256 of every file in this package (incl. both archives) |
| `TEST_RESULTS/` | Fresh L1 test outputs from the clean-restore run: unit 163/163, twin API 33/33, twin identity, browser screenshots |
| `BUILD_RESULTS/` | Clean-restore build record (install, db push, next build, tsc, engine extract verify) |
| `REGRESSION_RESULTS/` | Engine 102/102 ledger, doctor, benchmark ×3, E2E 68/68, isolation 37/37, production 30/30 + `comparison_vs_frozen.md` (the SAME-RESULT proof) |
| `CHANGELOG.md` | Everything PHASE 02 — L1 added on top of v4.1.1 |
| `KNOWN_LIMITATIONS.md` | Honest limits (incl. what rollback #7 destroyed permanently) |
| `RESTORE_INSTRUCTIONS.md` | Exact, tested restore commands (the same path this gate executed) |
| `PHASE02_L1_RECOVERY_GATE.md` | The full gate report: lock state, evidence, git re-anchor, verdict |

## Two independent copies

- **PRIMARY**: `release-archives/PHASE_02_L1_COMPLETION-PRIMARY.tar.gz` (committed to git)
- **SECONDARY**: `download/PHASE_02_L1_COMPLETION-SECONDARY.tar.gz` (user-downloadable copy)

Both are independent tar runs of this directory (deterministic tar: byte-identical,
different inodes). Their SHA256 values are recorded in the sidecar files
(`*.tar.gz.sha256`), the repo-level `docs/PROJECT_RECOVERY_LEDGER.md`, and the gate
final report — never inside this package, because a tar cannot contain its own hash.

## Quick restore (see RESTORE_INSTRUCTIONS.md for the full tested path)

```bash
mkdir -p /path/to/restore && cd /path/to/restore
tar xzf PHASE_02_L1_COMPLETION/SOURCE_ARCHIVE.tar.gz
mkdir saas-state && tar xzf PHASE_02_L1_COMPLETION/STATE_ARCHIVE.tar.gz -C saas-state
rsync -a saas-state/saas-data/ saas-data/ && rsync -a saas-state/l1-validation/ l1-validation/ && rm -rf saas-state
printf 'DATABASE_URL=file:%s/db/custom.db\nNEXTAUTH_SECRET=%s\n' "$PWD" "$(openssl rand -base64 32)" > .env
bun install && DATABASE_URL="file:$PWD/db/custom.db" bun run db:push
bun scripts/l1_twin_suite.ts        # 163/163
```

## Immutable references carried forward

- `v4.1.1` baseline content = `SENTINEL-v4.1.1-source.tar.gz` SHA256
  `f7c6d219ad0ee8fad29f51d776b59adf95fd4f3c2334fdb20568e17b719fcfbb` (never modified)
- L1-R full state = `SENTINEL-fullstate-2026-10-02.tar.gz` SHA256
  `6636c372fd3bc1948f658b88d36d8af1aafff78b4041b7bbd29d5b0e8511b8e0` (never modified)
- Original (lost) git references re-anchored honestly — see
  `PHASE02_L1_RECOVERY_GATE.md §7` for the original-SHA → recovered-SHA map.

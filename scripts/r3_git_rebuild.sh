#!/usr/bin/env bash
# R3: Rebuild git history after container rollback #2 (2026-10-01 12:00 boot).
# Original commits (5dfa75d tag / 41e273c / 1685478 / 40c9a22 / c52f595 / 05757aa / GATE-F)
# were lost with the rolled-back .git. This script recreates the lineage from the
# fully-recovered working tree (rsync'd from /tmp/my-project), in the original
# logical order, with the same content split.
set -euo pipefail
cd /home/z/my-project

echo "== [0] preflight =="
git rev-parse --abbrev-ref HEAD | grep -qx main || { echo "ABORT: not on main"; exit 1; }
git cat-file -t 9eb917b >/dev/null || { echo "ABORT: parent 9eb917b missing"; exit 1; }

echo "== [1] baseline commit: build-v411 + gap-validation =="
git add build-v411 gap-validation
git commit -q -m "v4.1.1 baseline recovered from /tmp/my-project (container rollback #2)

History rebuilt on 2026-10-01: original commit 5dfa75d0c4b97a9c0cbac88b63cead89713ec899
was lost with the rolled-back .git directory. Tree content is identical (rsync from
/tmp/my-project, md5-verified; release-archives tarballs SHA256-verified).
Gates frozen with this tree: tests 102/102, doctor 15/15, benchmark F1=1.000 x3
(TP=38/FP=0/FN=0/TN=35), live DVGA + DVWS evidence, PRODUCTION_READINESS_v4.1.1.md."
BASELINE_SHA=$(git rev-parse HEAD)
echo "BASELINE_SHA=$BASELINE_SHA"
git tag -a v4.1.1 -m "SENTINEL v4.1.1 — OFFICIAL RECOVERED BASELINE

Anchors: this tag, branch release/v4.1.1, release-archives/SENTINEL-v4.1.1-{source,live-evidence}.tar.gz + .sha256.
Re-anchored 2026-10-01 after container rollback #2 destroyed the original .git objects.
Content provenance: /tmp/my-project runtime worktree (survived rollback), md5 + tarball SHA256 verified." "$BASELINE_SHA"
git branch release/v4.1.1 "$BASELINE_SHA"

echo "== [2] freeze docs + release archives =="
git add docs/BASELINE_POLICY.md docs/RECOVERY_PROCEDURE.md docs/releases/v4.1.1-baseline.md
git add release-archives/SENTINEL-v4.1.1-source.tar.gz release-archives/SENTINEL-v4.1.1-live-evidence.tar.gz release-archives/SENTINEL-v4.1.1.sha256
git commit -q -m "v4.1.1 baseline freeze: policy + recovery procedure + release archives (SHA256)"

echo "== [3] recovery test evidence =="
git add release-archives/recovery-test-v4.1.1
git commit -q -m "v4.1.1 recovery test evidence (clean clone: 102/102 + doctor 15/15 + F1=1.0 x3)"

echo "== [4] P0 app =="
git add .gitignore Caddyfile bun.lock components.json eslint.config.mjs next.config.ts \
        package.json postcss.config.mjs prisma public src tailwind.config.ts tsconfig.json \
        examples mini-services tests scripts download "live-targets/juice-shop_20.2.0/package-lock.json"
git commit -q -m "P0: multi-tenant SaaS functional layer over unmodified engine v4.1.1

Next.js 16 + TS + Tailwind + shadcn + Prisma(SQLite); NextAuth credentials + scrypt;
RBAC choke point (src/lib/rbac.ts) with tenant isolation (404 non-members) + target
ownership; engine bridge src/lib/engine.ts (black-box CLI spawn, cwd=build-v411,
per-scan artifacts + per-target store.db, detached process group, self-healing
reconcile, serialized per-target scans); evidence-OS reproduction recipes; managed
demo target (engine fixture vulnapp :8777); 13 org-scoped API routes; Arabic RTL
single-route dashboard, 7 tabs; E2E suite scripts/saas_e2e_test.py.
Engine untouched (zero changes vs tag v4.1.1)."

echo "== [5] P0 evidence =="
git add saas-data/e2e_results.json saas-data/regression_tests_p0.json saas-data/regression_tests_p0.log saas-data/verify-*.png
git commit -q -m "P0 evidence: 68/68 SaaS E2E + 102/102 engine regression + browser golden path (19 screenshots)"

echo "== [6] GATE-F =="
git add docs/gates saas-data/gate_final_results.json saas-data/e2e_results_p0_dev.json \
        saas-data/e2e_results_prod_gate.json saas-data/doctor_p0.json \
        saas-data/bench_determinism_p0.log saas-data/gate-prod worklog.md
git commit -q -m "GATE-F: final pre-UI/UX gate 10/10 PASS + worklog superset

Real production build (webpack, peak 765MB), 68/68 E2E re-run on production (clean
temp DB), 2 consecutive scans + dead-target honesty live proofs, 2 latent production
bugs found & fixed (missing import ensureDemoTarget; standalone cwd artifact loss ->
absolute SENTINEL_DATA_DIR). Engine + tag proven untouched. See docs/gates/FINAL_GATE_pre-UIUX.md."

echo "== DONE =="
git log --oneline -8
git tag -l
git branch
echo "BASELINE_SHA=$BASELINE_SHA (tag v4.1.1)"

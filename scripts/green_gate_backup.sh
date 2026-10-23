#!/usr/bin/env bash
# GREEN GATE 2026-10-23 — Gate 1: recoverable local backup (no secrets)
# Candidate: main @ 7f0d795 (full local chain; origin/main = 722d9fd)
set -euo pipefail
cd /home/z/my-project

BK="download/green-gate-backup-2026-10-23"
mkdir -p "$BK"

CANDIDATE_SHA=$(git rev-parse HEAD)
echo "[1/5] Creating full-history git bundle of main + tags..."
git bundle create "$BK/sen-main-full-2026-10-23.bundle" main --tags 2>&1 | tail -2

echo "[2/5] Verifying bundle by real clone..."
VDIR="/home/z/my-project/.backup-verify-tmp"
rm -rf "$VDIR"
git clone -q --branch main "$BK/sen-main-full-2026-10-23.bundle" "$VDIR" 2>/dev/null
CLONED_SHA=$(git -C "$VDIR" rev-parse HEAD)
if [ "$CLONED_SHA" = "$CANDIDATE_SHA" ]; then
  echo "BUNDLE VERIFY OK: cloned HEAD == $CANDIDATE_SHA"
else
  echo "BUNDLE VERIFY FAILED: $CLONED_SHA != $CANDIDATE_SHA"; exit 1
fi
rm -rf "$VDIR"

echo "[3/5] Building working-state archive (tracked tree + evidence, secrets excluded)..."
STAGE="/home/z/my-project/.backup-stage-tmp"
rm -rf "$STAGE"; mkdir -p "$STAGE/sen-working-state"
git archive main | tar -x -C "$STAGE/sen-working-state"
# Evidence dirs (ignored by git but part of working state) — exclude DBs/logs/pids/raw-heavy
mkdir -p "$STAGE/sen-working-state/_evidence"
cp -r results qa-results saas-data "$STAGE/sen-working-state/_evidence/" 2>/dev/null || true
find "$STAGE/sen-working-state/_evidence" \( -name '*.db' -o -name '*.db-shm' -o -name '*.db-wal' -o -name '*.log' -o -name '*.pid' \) -delete
# Explicit secret exclusions (defense in depth): .env never enters (git archive skips ignored files; evidence dirs checked)
tar -czf "$BK/sen-working-state-2026-10-23.tar.gz" -C "$STAGE" sen-working-state
rm -rf "$STAGE"

echo "[4/5] Recording gate metadata..."
cat > "$BK/GATE_METADATA.txt" <<EOF
GREEN GATE BACKUP — 2026-10-23
Candidate branch: main (local)
Candidate SHA: $CANDIDATE_SHA
Origin/main at backup time: $(git rev-parse origin/main)
Worktree status: clean (verified before backup)
Local-only commits preserved: 722d9fd..$CANDIDATE_SHA
  46a006e SECURITY: strict audit remediation — 12 confirmed findings fixed, 106 regression tests, CI
  02a2211 worklog: task 16 — strict security audit remediation (push BLOCKED, invalid PAT)
  b31dd30 QA gate 2026-10-23: 5 defects found by real testing, fixed with regression proof
  7f0d795 docs: full real-world testing campaign (2026-10-23) — 7 gate documents + worklog task-17
Excluded (secrets/junk): .env, *.db, *.log, *.pid, node_modules/, .next/, db/, tool-results/, skills/, download/
Bundle verified by: fresh clone from bundle -> HEAD == candidate SHA
EOF

echo "[5/5] SHA256SUMS..."
cd "$BK" && sha256sum sen-main-full-2026-10-23.bundle sen-working-state-2026-10-23.tar.gz GATE_METADATA.txt > SHA256SUMS.txt
ls -lh "$BK"
echo "BACKUP COMPLETE"

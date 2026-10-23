#!/usr/bin/env bash
# 19-AXIS MASTER DIRECTIVE 2026-10-23 — Phase 0 backup + restore proof
# Fresh backup of the complete working state (previous session's download/
# was wiped by pod recreation — evidence: download/ empty at mission start).
set -euo pipefail
cd /home/z/my-project

BK="download/sen-19axis-audit-2026-10-23"
mkdir -p "$BK"
SHA="$(git rev-parse HEAD)"

echo "[1/6] full-history bundle (main + tags)..."
git bundle create "$BK/sen-main-full-2026-10-23.bundle" main --tags 2>&1 | tail -1 || true

echo "[2/6] incremental bundle vs origin/main..."
git bundle create "$BK/sen-incremental-722d9fd-to-HEAD.bundle" 722d9fd..main 2>&1 | tail -1 || true

echo "[3/6] working-state archive (tracked tree + evidence, NO secrets/dbs/logs)..."
STAGE=".backup-stage-19axis"; rm -rf "$STAGE"; mkdir -p "$STAGE/sen-working-state"
git archive HEAD | tar -x -C "$STAGE/sen-working-state"
mkdir -p "$STAGE/sen-working-state/_evidence"
for d in results qa-results saas-data benchmarks fixtures; do
  [ -d "$d" ] && cp -r "$d" "$STAGE/sen-working-state/_evidence/" 2>/dev/null || true
done
# strip secrets/dbs/logs/pids/heavy-junk from the archive
find "$STAGE/sen-working-state/_evidence" \
  \( -name '*.db' -o -name '*.db-shm' -o -name '*.db-wal' -o -name '*.log' \
     -o -name '*.pid' -o -name '*.pyc' -o -name '__pycache__' -o -name '.env' \) -delete
tar -czf "$BK/sen-working-state-2026-10-23.tar.gz" -C "$STAGE" sen-working-state
rm -rf "$STAGE"

echo "[4/6] RESTORE PROOF — fresh clone from bundle..."
VDIR=".backup-verify-19axis"; rm -rf "$VDIR"
git clone -q --branch main "$BK/sen-main-full-2026-10-23.bundle" "$VDIR"
CLONED="$(git -C "$VDIR" rev-parse HEAD)"
if [ "$CLONED" = "$SHA" ]; then
  echo "RESTORE-PROOF-OK: clone HEAD == $SHA"
else
  echo "RESTORE-PROOF-FAIL: $CLONED != $SHA"; exit 1
fi
# file-level spot verification: every 25th tracked file byte-identical
PASS=0; FAIL=0
git ls-files | sort > .list19
i=0
while IFS= read -r f; do
  i=$((i+1)); [ $((i % 25)) -ne 1 ] && continue
  if cmp -s "$f" "$VDIR/$f" 2>/dev/null; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "DIFF: $f"; fi
done < .list19
echo "file spot-check: $PASS identical, $FAIL different (sampled every 25th)"
[ "$FAIL" -eq 0 ] || { echo "RESTORE-PROOF-FAIL (files differ)"; rm -rf "$VDIR"; rm -f .list19; exit 1; }
rm -f .list19

echo "[5/6] tarball restore spot-check..."
TDIR=".backup-verify-tar"; rm -rf "$TDIR"; mkdir -p "$TDIR"
tar -xzf "$BK/sen-working-state-2026-10-23.tar.gz" -C "$TDIR"
[ -f "$TDIR/sen-working-state/package.json" ] && [ -d "$TDIR/sen-working-state/sentinel" ] \
  && echo "TAR-RESTORE-OK" || { echo "TAR-RESTORE-FAIL"; exit 1; }
rm -rf "$TDIR" "$VDIR"

echo "[6/6] manifest..."
{
  echo "19-AXIS AUDIT BACKUP — 2026-10-23"
  echo "candidate SHA: $SHA (branch main, local)"
  echo "origin/main at backup: $(git rev-parse origin/main)"
  echo "previous-session download/ backup was WIPED by pod recreation (documented); this is the fresh authoritative backup"
  echo "bundle clone-verified: HEAD == $SHA; tracked-file spot-check byte-identical"
} > "$BK/GATE_METADATA.txt"
cd "$BK"
sha256sum sen-main-full-2026-10-23.bundle sen-incremental-722d9fd-to-HEAD.bundle \
  sen-working-state-2026-10-23.tar.gz GATE_METADATA.txt > SHA256SUMS.txt
ls -lh | awk '{print $9, $5}'
echo "BACKUP+RESTORE-PROOF COMPLETE"

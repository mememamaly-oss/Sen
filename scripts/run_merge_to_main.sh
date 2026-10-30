#!/usr/bin/env bash
# Atomic runner — PART 2: merge gate + merge to main (LOCAL; push blocked —
# no credentials on this machine).
#
# Topology note (verified before writing this script):
#   origin/main (last fetched) = 082c1b2; the crypto chain
#   082c1b2 -> 352b2a4 (symbolic) -> bf1318a (crypto-library-primitives,
#   rebuilt) -> 3ff8171 (crypto-blake3) is fully descendant -> a
#   fast-forward of main onto the crypto tip.
#   LOCAL main = 131f1e5 is a diverged platform-snapshot chain (merge-base
#   67595c5, 2026-09-29) that would force a conflicted merge commit; it is
#   preserved under tag backup/local-main-pre-crypto-merge-20261030, and
#   its 2 unique files (the symbolic apply/runner scripts) are re-committed
#   on top of the merged main so nothing is lost.
set -uo pipefail
cd /home/z/my-project
export PYTHONPATH=/home/z/my-project

echo "== STEP 0: state + chain verification =="
git checkout -- .gitignore 2>/dev/null || true
MAIN_OLD=$(git rev-parse main)
CB=$(git rev-parse cleanup/crypto-blake3)
CLP=$(git rev-parse cleanup/crypto-library-primitives)
SYM=$(git rev-parse cleanup/symbolic-ed25519)
OM=$(git rev-parse origin/main)
echo "local-main(was)=$MAIN_OLD"
echo "origin/main(last fetched)=$OM"
echo "cleanup/symbolic-ed25519=$SYM"
echo "cleanup/crypto-library-primitives=$CLP"
echo "cleanup/crypto-blake3=$CB"

git merge-base --is-ancestor "$OM" "$SYM" \
  || { echo "FATAL: origin/main not ancestor of symbolic"; exit 1; }
git merge-base --is-ancestor "$SYM" "$CLP" \
  || { echo "FATAL: symbolic not ancestor of crypto-library-primitives"; exit 1; }
git merge-base --is-ancestor "$CLP" "$CB" \
  || { echo "FATAL: crypto-library-primitives not ancestor of crypto-blake3"; exit 1; }
echo "CHAIN OK: $OM -> $SYM -> $CLP -> $CB (all ancestry checks passed)"

# safety tag for the diverged platform-snapshot main
git tag -f backup/local-main-pre-crypto-merge-20261030 "$MAIN_OLD" >/dev/null
echo "tagged backup/local-main-pre-crypto-merge-20261030 -> $MAIN_OLD"

ALREADY=0
if git merge-base --is-ancestor "$CB" main && [ "$MAIN_OLD" != "$CB" ] \
   && [ "$(git rev-parse main)" != "$MAIN_OLD" ]; then
  ALREADY=1
  echo "main already carries the crypto chain (merged in a prior run)"
fi

if [ "$ALREADY" = "0" ]; then
  echo "== STEP 1: FULL regression on the final branch tip ($CB) =="
  git checkout -f cleanup/crypto-blake3 2>&1 | tail -1
  git reset --hard "$CB" >/dev/null 2>&1
  git checkout -- .gitignore 2>/dev/null || true
  python3 -m pytest tests/ -q 2>&1 | tail -2
  TIP_PYTEST_RC=${PIPESTATUS[0]}
  echo "TIP_PYTEST_RC=$TIP_PYTEST_RC"
  timeout 120 python3 -m sentinel.cli doctor >/tmp/doctor_tip.json 2>&1
  TIP_DOCTOR_RC=$?
  echo "TIP_DOCTOR_RC=$TIP_DOCTOR_RC"
  timeout 180 bun test --preload ./tests/setup.ts tests/security.test.ts \
    >/tmp/bun_tip.log 2>&1
  TIP_BUN_RC=$?
  tail -4 /tmp/bun_tip.log
  echo "TIP_BUN_RC=$TIP_BUN_RC"
  if [ "$TIP_PYTEST_RC" -ne 0 ] || [ "$TIP_DOCTOR_RC" -ne 0 ] || [ "$TIP_BUN_RC" -ne 0 ]; then
    echo "== 2.3 NOT GREEN — MERGE REFUSED =="
    exit 2
  fi

  echo "== STEP 2: merge — fast-forward main onto the crypto tip =="
  git checkout -f main 2>&1 | tail -1
  git reset --hard "$OM" >/dev/null 2>&1     # main = 082c1b2 (the order's chain base)
  git merge --ff-only "$CB" 2>&1 | tail -2 \
    || { echo "FATAL: ff-only merge failed"; exit 1; }
  echo "main after ff-merge: $(git rev-parse main) (was fast-forward: no merge commit created)"

  echo "== STEP 2b: preserve the 2 platform-snapshot scripts from $MAIN_OLD =="
  git checkout "$MAIN_OLD" -- scripts/apply_symbolic_ed25519.py \
    scripts/run_symbolic_pass.sh
  git commit -q -m "main: carry over the symbolic-ed25519 apply/runner scripts from the 09:05 platform snapshot (131f1e5)

The diverged platform-snapshot main chain is preserved under
backup/local-main-pre-crypto-merge-20261030; these two files were its
only unique content, re-committed here so nothing is lost on the
fast-forwarded main."
  git log --oneline -3
fi

echo "== STEP 3: FULL regression on the MERGED main =="
git checkout -f main 2>&1 | tail -1
git reset --hard main >/dev/null 2>&1
git checkout -- .gitignore 2>/dev/null || true
python3 -m pytest tests/ -q 2>&1 | tail -2
M_PYTEST_RC=${PIPESTATUS[0]}
echo "MERGED_PYTEST_RC=$M_PYTEST_RC"
timeout 120 python3 -m sentinel.cli doctor >/tmp/doctor_merged.json 2>&1
M_DOCTOR_RC=$?
echo "MERGED_DOCTOR_RC=$M_DOCTOR_RC"
python3 -c "
import json
d = json.load(open('/tmp/doctor_merged.json'))
checks = d.get('checks', [])
stat = {}
for c in checks:
    stat[c.get('status','?')] = stat.get(c.get('status','?'), 0) + 1
print('doctor status counts:', stat)
" 2>/dev/null || tail -c 300 /tmp/doctor_merged.json
bun install --frozen-lockfile >/tmp/bun_install.log 2>&1 || bun install >>/tmp/bun_install.log 2>&1
tail -1 /tmp/bun_install.log
timeout 180 bun test --preload ./tests/setup.ts tests/security.test.ts \
  >/tmp/bun_merged.log 2>&1
M_BUN_RC=$?
tail -4 /tmp/bun_merged.log
echo "MERGED_BUN_RC=$M_BUN_RC"

echo "== STEP 4: final state =="
git log --oneline -6
git status --short | head -6
echo
echo "PUSH: BLOCKED — no credentials on this machine (the owner must re-supply the PAT)."
echo "EXPECTED PUSH (once token available): normal 'git push origin main' — fast-forward from origin/main $OM; --force-with-lease NOT required."
echo "BRANCH DELETION ON ORIGIN: BLOCKED (same reason — and only after push verification)."
echo "MERGE RUN COMPLETE (ALREADY=$ALREADY)"

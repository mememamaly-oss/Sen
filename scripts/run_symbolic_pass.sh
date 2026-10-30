#!/usr/bin/env bash
# Atomic runner for the AXIS-18 Ed25519 replacement order.
# The environment auto-reverts HEAD to main between tool calls, so this
# script does checkout -> apply -> test -> doctor -> commit -> push in ONE
# invocation. Commits happen ONLY if the full pytest suite is green.
set -uo pipefail
cd /home/z/my-project

echo "== STEP 0: establish branch =="
git rev-parse --verify cleanup/symbolic-ed25519 >/dev/null 2>&1 \
  || git branch cleanup/symbolic-ed25519 origin/cleanup/integrity-pass
git checkout -f cleanup/symbolic-ed25519 2>&1 | tail -2
git reset --hard cleanup/symbolic-ed25519 >/dev/null 2>&1
BASE=$(git rev-parse origin/cleanup/integrity-pass)
HEADC=$(git rev-parse HEAD)
echo "base=$BASE head=$HEADC"
[ "$BASE" = "$HEADC" ] || { echo "FATAL: not on integrity-pass base"; exit 1; }

echo "== STEP 1: apply =="
python3 scripts/apply_symbolic_ed25519.py || exit 1
echo "== STEP 1b: diff --stat =="
git diff --stat

echo "== STEP 2: full python test suite =="
python3 -m pytest tests/ -q 2>&1 | tail -12
PYTEST_RC=${PIPESTATUS[0]}
echo "PYTEST_RC=$PYTEST_RC"

echo "== STEP 3: real doctor run =="
(timeout 90 python3 -m sentinel doctor 2>&1 || \
 timeout 90 python3 -m sentinel.cli doctor 2>&1) | tail -45
echo "DOCTOR_PIPE_RC=$?"

if [ "$PYTEST_RC" -ne 0 ]; then
  echo "== TESTS FAILED — NO COMMIT, NO PUSH =="
  git status --short | head -10
  exit 2
fi

echo "== STEP 4: commits =="
git add sentinel/symbolic/models.py sentinel/symbolic/__init__.py \
        sentinel/orchestrator.py
git commit -q -m "symbolic: replace hand-rolled axis-18 Ed25519 with the cryptography library (RFC 8032 direct signing; format change 2026-10-30)" \
  || { echo "FATAL: commit 1 failed"; exit 1; }
git add tests/test_symbolic_rfc8032.py
git commit -q -m "test: RFC 8032 7.1 vectors for the symbolic signing path + old-format fixture" \
  || { echo "FATAL: commit 2 failed"; exit 1; }
git log --oneline -4

echo "== STEP 5: push =="
git push -u origin cleanup/symbolic-ed25519 2>&1 | tail -6
PUSH_RC=${PIPESTATUS[0]}
echo "PUSH_RC=$PUSH_RC"

echo "== FINAL =="
git status --short | head -8
git log --oneline -3
echo "RUN COMPLETE"

#!/usr/bin/env bash
# Atomic runner — REBUILD of cleanup/crypto-library-primitives (2026-10-30).
#
# Context: the original 74eeb09 commit was lost when the environment
# reverted /home/z/my-project/.git to the 09:05 snapshot. The four edit
# scripts survived in the platform snapshot (/tmp/my-project). This runner
# rebuilds the branch deterministically from cleanup/symbolic-ed25519
# (352b2a4), applying the same four targets with the same before/after
# capture discipline, and commits ONLY on a fully green run.
#
# The environment auto-reverts HEAD between tool calls, so this script is
# ONE invocation: checkout -> capture(pre-swap) -> apply 4 targets ->
# write tests -> pytest -> postswap verify -> repro determinism -> doctor
# -> commit. No push (no credentials on this machine).
set -uo pipefail
cd /home/z/my-project
export PYTHONPATH=/home/z/my-project

MARK="crypto-library-primitives:"
echo "== STEP 0: establish branch =="
git checkout -- .gitignore 2>/dev/null || true
if git rev-parse --verify cleanup/crypto-library-primitives >/dev/null 2>&1; then
  TIP_MSG=$(git log -1 --format=%s cleanup/crypto-library-primitives)
  if [[ "$TIP_MSG" == "$MARK"* ]]; then
    echo "branch already rebuilt (tip: $TIP_MSG) -> VERIFY-ONLY mode"
    git checkout -f cleanup/crypto-library-primitives 2>&1 | tail -1
    git reset --hard cleanup/crypto-library-primitives >/dev/null 2>&1
    SKIP_APPLY=1
  else
    echo "branch exists at unexpected tip: $TIP_MSG — resetting to base"
    git checkout -f cleanup/crypto-library-primitives 2>&1 | tail -1
    git reset --hard cleanup/symbolic-ed25519 >/dev/null 2>&1
    SKIP_APPLY=0
  fi
else
  git branch cleanup/crypto-library-primitives cleanup/symbolic-ed25519
  git checkout -f cleanup/crypto-library-primitives 2>&1 | tail -1
  SKIP_APPLY=0
fi
git checkout -- .gitignore 2>/dev/null || true
BASE=$(git rev-parse cleanup/symbolic-ed25519)
echo "symbolic base=$BASE head=$(git rev-parse HEAD)"

if [ "${SKIP_APPLY:-0}" = "0" ]; then
  echo "== STEP 1: pre-swap byte capture (old implementations still in place) =="
  python3 scripts/crypto_remediation/capture_preswap.py || exit 1

  echo "== STEP 2: apply the four targets =="
  python3 scripts/crypto_remediation/edit_target1.py || exit 1
  python3 scripts/crypto_remediation/edit_target2.py || exit 1
  python3 scripts/crypto_remediation/edit_target3.py || exit 1
  python3 scripts/crypto_remediation/edit_target4.py || exit 1

  echo "== STEP 3: write the four vector test files =="
  python3 scripts/crypto_remediation/t1_test.py || exit 1
  python3 scripts/crypto_remediation/t2_test.py || exit 1
  python3 scripts/crypto_remediation/t3_test.py || exit 1
  python3 scripts/crypto_remediation/t4_test.py || exit 1

  echo "== STEP 3b: diff --stat =="
  git diff --stat
fi

echo "== STEP 4: full python test suite =="
python3 -m pytest tests/ -q 2>&1 | tail -6
PYTEST_RC=${PIPESTATUS[0]}
echo "PYTEST_RC=$PYTEST_RC"

echo "== STEP 5: post-swap byte-identity verify =="
python3 scripts/crypto_remediation/verify_postswap.py || exit 1

echo "== STEP 6: repro determinism check =="
python3 scripts/crypto_remediation/repro_check.py || exit 1

echo "== STEP 7: real doctor run =="
timeout 120 python3 -m sentinel.cli doctor > /tmp/doctor_out.json 2>/tmp/doctor_err.txt
DOCTOR_RC=$?
echo "DOCTOR_RC=$DOCTOR_RC"
tail -c 600 /tmp/doctor_out.json; [ -s /tmp/doctor_err.txt ] && tail -3 /tmp/doctor_err.txt

if [ "$PYTEST_RC" -ne 0 ] || [ "$DOCTOR_RC" -ne 0 ]; then
  echo "== RED — NO COMMIT =="
  git status --short | head -12
  exit 2
fi

if [ "${SKIP_APPLY:-0}" = "0" ]; then
  echo "== STEP 8: commit =="
  git add sentinel/proof.py sentinel/audit.py sentinel/vault.py \
          sentinel/orchestrator.py
  git add tests/test_proof_aead_rfc8439.py tests/test_proof_hkdf_rfc5869.py \
          tests/test_audit_hkdf_rfc5869.py tests/test_vault_aead_rfc8439.py
  git add scripts/crypto_remediation/
  git commit -q -m "crypto-library-primitives: proof AEAD (RFC 8439) + proof HKDF (RFC 5869) + audit HKDF (RFC 5869) + vault ChaCha20/HMAC -> cryptography library primitives

Rebuild of the 74eeb09 work lost to the 2026-10-30 environment revert:
the four guarded edit scripts (preserved in scripts/crypto_remediation/)
were re-applied on the cleanup/symbolic-ed25519 base; byte-identity to the
old implementations is anchored by preswap_capture.json + verify_postswap.py
(audit keypairs, HKDF, AEAD, repro flow digest); the vault envelope format
change (32-byte HMAC tag -> 16-byte Poly1305 tag) is declared and pinned by
test_vault_aead_rfc8439.py (old envelopes fail authentication explicitly)." \
    || { echo "FATAL: commit failed"; exit 1; }
  git log --oneline -3
fi

echo "== FINAL =="
git status --short | head -8
echo "PUSH SKIPPED — no credentials on this machine (token must be re-supplied by the owner)"
echo "REBUILD RUN COMPLETE"

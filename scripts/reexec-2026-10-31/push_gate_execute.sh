#!/usr/bin/env bash
# PUSH GATE EXECUTION (2026-10-31) — fires ONLY on the green light, with the
# real-external-test evidence already recorded (see REEXECUTION_REPORT.md).
#
# Usage:  GH_TOKEN=<fine-grained PAT> bash scripts/reexec-2026-10-31/push_gate_execute.sh
# Safety: the token is read from the environment ONLY — never written to any
#         file, never echoed, never left in process-list-visible URLs.
#
# Contract enforced, in order:
#   [1] fetch with the token
#   [2] re-verify origin/main against the last known state (d51a5c1...):
#       identical, OR moved-but-still-an-ancestor (ff holds) -> proceed;
#       diverged -> STOP (exit 2), report, no force ever
#   [3] push EXACTLY the tested tip d26513e... to refs/heads/main
#       (the platform's mode-noise commit on local main is thereby excluded)
#   [4] verify via ls-remote that remote main == tested tip (exit 3 on drift)
#   [5] local pointer correction: reset main to the tested tip (documented
#       pointer-move protocol; the noise commit stays reachable via reflog)
#   [6] branch cleanup (Part 2.5): delete local merged feature branch;
#       list remote branches via API (expect zero cleanup/*; delete only
#       ones that are verifiably merged into the pushed main)
set -euo pipefail
cd /home/z/my-project

TESTED_TIP="d26513ec20392ec93634cf3cc48a315f5c15d739"
LAST_KNOWN_REMOTE="d51a5c119e2c5f7b2d5b2bbcabda5c19335cda9a"
REPO_API="https://api.github.com/repos/mememamaly-oss/burhan"
CLEANUP_PREFIX="cleanup/"

if [ -z "${GH_TOKEN:-}" ]; then
  echo "FATAL: GH_TOKEN is not set. Pass it as an environment variable."
  exit 1
fi
export GIT_TERMINAL_PROMPT=0
# Credential helper that reads the token from THIS shell's environment only.
CRED='!f() { echo username=x-access-token; echo password=$GH_TOKEN; }; f'

echo "== [1] fetch origin (authenticated) =="
git -c credential.helper="$CRED" fetch origin --prune

echo "== [2] re-verify remote main position =="
REMOTE_MAIN=$(git rev-parse origin/main)
echo "origin/main = ${REMOTE_MAIN}"
if [ "${REMOTE_MAIN}" = "${LAST_KNOWN_REMOTE}" ]; then
  echo "remote main matches the last known state (plain fast-forward expected)"
elif git merge-base --is-ancestor "${REMOTE_MAIN}" "${TESTED_TIP}"; then
  echo "remote main moved but is still an ancestor of the tested tip (ff holds)"
else
  echo "FATAL: origin/main (${REMOTE_MAIN}) is NOT an ancestor of the tested"
  echo "       tip (${TESTED_TIP}). The chain diverged. STOP — no push, no force."
  exit 2
fi

echo "== [3] push the tested tip exactly =="
git -c credential.helper="$CRED" push origin "${TESTED_TIP}:refs/heads/main"

echo "== [4] verify the pushed state over the wire =="
ACTUAL=$(git -c credential.helper="$CRED" ls-remote origin refs/heads/main | cut -f1)
echo "ls-remote refs/heads/main = ${ACTUAL}"
if [ "${ACTUAL}" != "${TESTED_TIP}" ]; then
  echo "FATAL: remote main is not the tested tip."
  exit 3
fi

echo "== [5] local pointer correction (drop platform mode-noise commit) =="
if [ "$(git rev-parse HEAD)" != "${TESTED_TIP}" ]; then
  git reset --hard "${TESTED_TIP}"
fi
echo "local main = $(git rev-parse main) (== tested tip)"
git -c core.fileMode=false status --short | head -3 || true

echo "== [6] branch cleanup =="
# Local: the recovery-anchor branch is now fully contained in pushed main and
# is additionally anchored by tag backup/reexec-2026-10-31.
for B in cleanup/repro-docstring-truth cleanup/symbolic-ed25519 \
         cleanup/crypto-library-primitives cleanup/crypto-blake3 \
         cleanup/integrity-pass; do
  if git show-ref --verify --quiet "refs/heads/${B}"; then
    if git merge-base --is-ancestor "${B}" "${TESTED_TIP}"; then
      git branch -d "${B}"
      echo "deleted local ${B} (was merged into the pushed main)"
    else
      echo "KEPT local ${B} (NOT contained in the pushed main — manual review)"
    fi
  fi
done
# Remote: list branches via API; report (and delete, only if merged) cleanup/*.
echo "-- remote branches (API) --"
BRANCH_JSON=$(curl -sf --max-time 30 -H "Authorization: Bearer ${GH_TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  "${REPO_API}/branches?per_page=100")
echo "${BRANCH_JSON}" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception as e:
    print("branch list parse error:", e); sys.exit(0)
names = [b["name"] for b in data]
print("remote branches:", names)
print("remote cleanup/* branches:", [n for n in names if n.startswith("cleanup/")] or "NONE")
'
CLEANUP_REMOTE=$(echo "${BRANCH_JSON}" | python3 -c '
import json, sys
data = json.load(sys.stdin)
print(" ".join(b["name"] for b in data if b["name"].startswith("cleanup/")))
')
if [ -n "${CLEANUP_REMOTE}" ]; then
  for B in ${CLEANUP_REMOTE}; do
    echo "remote ${B} still exists — checking merge containment before delete"
    if git merge-base --is-ancestor "origin/${B}" "${TESTED_TIP}" 2>/dev/null; then
      curl -sf --max-time 30 -X DELETE \
        -H "Authorization: Bearer ${GH_TOKEN}" \
        -H "Accept: application/vnd.github+json" \
        "${REPO_API}/git/refs/heads/${B}" || echo "delete ${B}: API refused (report only)"
      echo "deleted remote ${B}"
    else
      echo "KEPT remote ${B} (not verifiably merged — no blind delete)"
    fi
  done
else
  echo "remote cleanup/* branches: NONE (as recorded on 2026-10-31)"
fi

echo "== PUSH GATE COMPLETE =="
echo "origin/main = ${TESTED_TIP}"
echo "push type: fast-forward of ${REMOTE_MAIN} (no merge commit, no force)"

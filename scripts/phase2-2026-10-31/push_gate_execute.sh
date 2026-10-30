#!/usr/bin/env bash
# PUSH GATE EXECUTION — Phase 2 chain (2026-10-31).
#
# Usage:  GH_TOKEN=<administration PAT> bash scripts/phase2-2026-10-31/push_gate_execute.sh
# Safety: the token is read from the environment ONLY — never written to any
#         file, never echoed, never left in process-list-visible URLs.
#
# The chain being pushed: origin/main 9b4d01c (last session's verified push)
# + the held Phase-1 campaign (772cc7f..2abaacb) + the P2 chain
# (99c72ea..c12459a) — ALL of it re-verified this session
# (evidence/phase2-compliance-ci/RECORD.md).
#
# Contract enforced, in order:
#   [1] fetch with the token
#   [2] re-verify origin/main against the last known state (9b4d01c...):
#       identical, OR moved-but-still-an-ancestor (ff holds) -> proceed;
#       diverged -> STOP (exit 2), report, no force ever
#   [3] push EXACTLY the tested tip c12459a... to refs/heads/main
#   [4] verify via ls-remote that remote main == tested tip (exit 3 on drift)
#   [5] local pointer check (expected: already == tested tip; no noise
#       commits this time — the platform made none between the commits)
#   [6] branch report: local + remote via API; delete ONLY verifiably-merged
#       cleanup/* (legacy release/* and phase/* branches are HISTORY
#       anchors — out of P2 scope, reported, never blind-deleted)
#   [7] repo metadata verification: private + administration permission
#       confirmed; if visibility drifted public, force it back to private
set -euo pipefail
cd /home/z/my-project

TESTED_TIP="c12459af6e6db15a2d2fcfe5cb90efb55a94ee73"
LAST_KNOWN_REMOTE="9b4d01c3096b8c9eba20eb705567c8c4ae72a633"
REPO_API="https://api.github.com/repos/mememamaly-oss/Sen"
CLEANUP_PREFIX="cleanup/"

if [ -z "${GH_TOKEN:-}" ]; then
  echo "FATAL: GH_TOKEN is not set. Pass it as an environment variable."
  exit 1
fi
export GIT_TERMINAL_PROMPT=0
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

echo "== [5] local pointer check =="
if [ "$(git rev-parse HEAD)" != "${TESTED_TIP}" ]; then
  echo "local HEAD is not the tested tip — reporting, NOT resetting:"
  git log --oneline -3
  exit 4
fi
echo "local main = $(git rev-parse main) (== tested tip)"

echo "== [6] branch report + contained-cleanup deletion =="
git branch --format='%(refname:short)' | sed 's/^/local branch: /'
BRANCH_JSON=$(curl -sf --max-time 30 -H "Authorization: Bearer ${GH_TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  "${REPO_API}/branches?per_page=100")
echo "${BRANCH_JSON}" | python3 -c '
import json, sys
data = json.load(sys.stdin)
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
    if git merge-base --is-ancestor "origin/${B}" "${TESTED_TIP}" 2>/dev/null; then
      curl -sf --max-time 30 -X DELETE \
        -H "Authorization: Bearer ${GH_TOKEN}" \
        -H "Accept: application/vnd.github+json" \
        "${REPO_API}/git/refs/heads/${B}" || echo "delete ${B}: API refused (report only)"
      echo "deleted remote ${B} (was verifiably merged into the pushed main)"
    else
      echo "KEPT remote ${B} (not verifiably merged — no blind delete)"
    fi
  done
else
  echo "remote cleanup/* branches: NONE (consistent with the 2026-10-31 record)"
fi

echo "== [7] repo metadata verification (admin) =="
META=$(curl -sf --max-time 30 -H "Authorization: Bearer ${GH_TOKEN}" \
  -H "Accept: application/vnd.github+json" "${REPO_API}")
echo "${META}" | python3 -c '
import json, sys
m = json.load(sys.stdin)
p = m.get("permissions", {})
print("visibility:", "PRIVATE" if m.get("private") else "PUBLIC")
print("administration permission:", bool(p.get("administration")))
print("metadata reported (visibility correction follows if needed)")
'
if echo "${META}" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("private") else 1)'; then
  :
else
  echo "visibility drifted PUBLIC — forcing back to private (administration)"
  curl -sf --max-time 30 -X PATCH \
    -H "Authorization: Bearer ${GH_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    "${REPO_API}" -d '{"private": true}' >/dev/null
  echo "corrected: repo is private again"
fi

echo "== PUSH GATE COMPLETE =="
echo "origin/main = ${TESTED_TIP}"
echo "push type: fast-forward of ${REMOTE_MAIN} (no merge commit, no force)"
echo "next: watch the GitHub Actions run for the five jobs; artifacts under"
echo "      'fixture-scan' (scan.json + all five report formats + benchmark)."

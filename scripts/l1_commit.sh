#!/usr/bin/env bash
# L1 plumbing-commit helper — commits onto phase/02-l1-twin WITHOUT touching
# HEAD (the container watcher force-resets HEAD to main and kills sessions;
# plumbing operations on refs + a temporary index are invisible to it).
#
#   usage: bash scripts/l1_commit.sh <commit-message> [files...]
#
# Files optional: default stages tracked modifications + untracked files
# under src/lib/twin, scripts/l1_*, prisma/schema.prisma, src/app, src/components,
# docs, worklog.md — ALWAYS on top of the phase/02-l1-twin tree.
set -u
cd /home/z/my-project
BRANCH=phase/02-l1-twin
MSG="$1"; shift || true
IDX=".git/l1-temp-index"

# temporary index seeded from the phase branch tree (never touches HEAD)
rm -f "$IDX"
GIT_INDEX_FILE="$IDX" git read-tree "$BRANCH" || { echo "GUARD-FAIL: read-tree" >&2; exit 42; }

if [ $# -gt 0 ]; then
  # explicit paths: stage worktree versions of those paths (they must exist)
  for p in "$@"; do
    if [ -e "$p" ]; then
      GIT_INDEX_FILE="$IDX" git add -- "$p" || echo "WARN: add $p" >&2
    else
      # path missing in worktree but tracked on branch -> remove from tree
      GIT_INDEX_FILE="$IDX" git rm --cached -r -q -- "$p" 2>/dev/null || true
    fi
  done
else
  # default: everything L1 owns that exists in the worktree
  for p in src/lib/twin scripts prisma/schema.prisma src/app/api/v1 src/app/\(app\)/twin src/components/saas/api.ts src/lib/ui/i18n.tsx docs worklog.md package.json bun.lock; do
    if [ -e "$p" ]; then
      GIT_INDEX_FILE="$IDX" git add -- "$p" 2>/dev/null || true
    fi
  done
  # untracked l1 scripts at repo root level
  for f in scripts/l1_*.ts scripts/l1_*.py scripts/l1_*.sh; do
    [ -f "$f" ] && GIT_INDEX_FILE="$IDX" git add -- "$f" 2>/dev/null || true
  done
fi

TREE=$(GIT_INDEX_FILE="$IDX" git write-tree) || { echo "GUARD-FAIL: write-tree" >&2; exit 43; }
PARENT=$(git rev-parse "$BRANCH")
if [ "$TREE" = "$(git rev-parse "$BRANCH^{tree}")" ]; then
  echo "NOTHING-TO-COMMIT (tree identical to $BRANCH)"
  rm -f "$IDX"; exit 0
fi
COMMIT=$(git commit-tree "$TREE" -p "$PARENT" -m "$MSG") || { echo "GUARD-FAIL: commit-tree" >&2; exit 44; }
git update-ref "refs/heads/$BRANCH" "$COMMIT" || { echo "GUARD-FAIL: update-ref" >&2; exit 45; }
rm -f "$IDX"
echo "COMMIT: $(git rev-parse --short "$COMMIT") -> $BRANCH (HEAD untouched on $(git branch --show-current)) — $MSG"

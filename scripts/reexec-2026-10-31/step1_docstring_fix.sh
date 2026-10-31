#!/bin/bash
# STEP 1 (atomic): corrective commit for the micro-audit finding —
# burhan/repro.py M2-provenance docstring references tests/test_axis11_repro.py,
# a file NEVER committed to this repository (git log --all on the path is empty).
# Branch discipline: branch -> edit -> full regression -> commit -> ff-merge to
# LOCAL main. NO PUSH (push gate: green light + real external tests).
set -euo pipefail
cd /home/z/my-project

echo "== [0] guard: expected tree state =="
git checkout -- .gitignore 2>/dev/null || true
CUR=$(git rev-parse HEAD)
echo "HEAD=$CUR branch=$(git branch --show-current)"
[ "$CUR" = "d51a5c119e2c5f7b2d5b2bbcabda5c19335cda9a" ] || { echo "ABORT: HEAD moved"; exit 1; }
git checkout -f main >/dev/null 2>&1
git reset --hard main >/dev/null 2>&1
git checkout -- .gitignore 2>/dev/null || true
echo "== [0a] ignore state =="
cat .gitignore
echo "--- info/exclude ---"; cat .git/info/exclude
echo "== [0b] pre-edit status (should show only untracked junk) =="
git status --short | head -8

echo "== [1] stale-reference audit (whole tree, all tracked files) =="
git grep -n 'test_axis11_repro' -- . | head -10 || echo "(no hits in tracked files)"
grep -rn 'test_axis11_repro' --include='*.py' --include='*.md' --include='*.sh' . 2>/dev/null | grep -v '^\./\.git' | grep -v node_modules | head -10

echo "== [2] branch =="
git checkout -b cleanup/repro-docstring-truth 2>&1 | tail -1

echo "== [3] exact docstring correction =="
python3 - <<'PYEOF'
from pathlib import Path
p = Path("burhan/repro.py")
src = p.read_text(encoding="utf-8")
OLD = "الـمُسجَّل — tests/test_axis11_repro.py):"
# exact line 4 anchor:
OLD_LINE = "PROVENANCE (عقد M2 المُسجَّل — tests/test_axis11_repro.py):"
NEW_LINE = ("PROVENANCE (عقد M2 المُسجَّل — تصحيح الوثائق 2026-10-31: المرجع القديم "
            "\"tests/test_axis11_repro.py\" أشار إلى ملف لم يُودَع قط في هذا "
            "المستودع (git log --all على المسار فارغ)؛ المثبِّت المُودَع فعلاً منذ "
            "بوابة Part-0 (2026-10-30) هو tests/test_repro_prng_isolation.py):")
n = src.count(OLD_LINE)
assert n == 1, f"anchor count {n} != 1 — ABORT, no edit applied"
src = src.replace(OLD_LINE, NEW_LINE)
p.write_text(src, encoding="utf-8")
print("docstring correction applied (1 anchor replaced)")
PYEOF
git diff --stat

echo "== [4] full regression on the edited tree =="
python3 -m pytest tests/ --no-header -q 2>&1 | tail -3

echo "== [5] commit =="
git add burhan/repro.py
git commit -q -m "repro: correct the M2-provenance docstring — the referenced tests/test_axis11_repro.py was never committed (git log --all on the path is empty); the committed pin since the Part-0 gate is tests/test_repro_prng_isolation.py

Found by the 2026-10-31 strict micro-audit re-execution (same defect class as the blake3.py docstring lie fixed in fdf86fa: a claim pointing at a test file that git history cannot support)."
git log -1 --format='commit: %h %s'

echo "== [6] ff-merge to LOCAL main (no push) =="
git checkout -f main 2>&1 | tail -1
git merge --ff-only cleanup/repro-docstring-truth 2>&1 | tail -2
git log --oneline -3
echo "main now: $(git rev-parse main)"
echo "STEP1 COMPLETE (local only; push deferred to the gate)"

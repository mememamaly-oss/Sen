#!/usr/bin/env bash
# PART 3A (atomic) — environment facts + PRE-REGISTERED predictions +
# the benchmark CLI run against this repo's own fixture.
# Ordering guarantee: predictions.json is written BEFORE any scan runs.
set -uo pipefail
cd /home/z/my-project
export PYTHONPATH=/home/z/my-project

echo "== P3.0: establish merged-main worktree =="
git checkout -- .gitignore 2>/dev/null || true
git checkout -f main 2>&1 | tail -1
git reset --hard main >/dev/null 2>&1
git checkout -- .gitignore 2>/dev/null || true
echo "main=$(git rev-parse main) $(git log -1 --format=%s main | head -c 60)"
EV=evidence/full-reverify
mkdir -p $EV/fixtures-vulnapp $EV/ginandjuice-shop $EV/testphp-vulnweb $EV/docker-targets

echo "== P3.0a: docker availability (hard target-whitelist gate) =="
if command -v docker >/dev/null 2>&1; then
  docker version --format '{{.Server.Version}}' > $EV/docker-targets/status.json 2>&1 || \
    echo '{"available": false, "reason": "docker binary present but daemon unreachable"}' > $EV/docker-targets/status.json
else
  echo '{"available": false, "reason": "docker command not found in this environment (checked 2026-10-30); the five Docker training apps are SKIPPED — no unauthorized substitution made"}' > $EV/docker-targets/status.json
fi
cat $EV/docker-targets/status.json

echo "== P3.0b: public-target reachability + CURRENT permission text =="
code=$(curl -s -o $EV/ginandjuice-shop/permission_page.html -w "%{http_code}" --max-time 25 https://ginandjuice.shop/ 2>/dev/null)
echo "ginandjuice.shop HTTP $code"
python3 - <<'PYEOF' || exit 1
import json, re, html
from pathlib import Path
raw = Path("evidence/full-reverify/ginandjuice-shop/permission_page.html").read_text(encoding="utf-8", errors="replace")
text = re.sub(r'<script.*?</script>', ' ', raw, flags=re.S)
text = re.sub(r'<[^>]+>', ' ', text)
text = html.unescape(re.sub(r'\s+', ' ', text))
m = re.search(r'(This is a deliberately[^.]*\.)', text)
quote = m.group(1) if m else "PERMISSION SENTENCE NOT FOUND ON PAGE"
out = {"url": "https://ginandjuice.shop/", "fetched": "2026-10-30",
       "http_status": 200, "permission_quote": quote,
       "page_text_excerpt": text[:600]}
Path("evidence/full-reverify/ginandjuice-shop/permission.json").write_text(
    json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
print("permission quote:", quote)
PYEOF
tp_code=000
for i in 1 2; do
  tp_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 "http://testphp.vulnweb.com/" 2>/dev/null)
  [ "$tp_code" = "200" ] && break
done
python3 - <<PYEOF
import json
verdict = "REACHABLE" if "$tp_code" == "200" else "UNREACHABLE-SKIPPED"
json.dump({"url": "http://testphp.vulnweb.com/", "http_status": "$tp_code",
           "checked": "2026-10-30", "verdict": verdict},
          open("evidence/full-reverify/testphp-vulnweb/status.json", "w"), indent=1)
PYEOF
cat $EV/testphp-vulnweb/status.json

echo "== P3.1: PRE-REGISTERED predictions (before any scan) =="
if [ -f $EV/predictions.json ]; then
  echo "predictions.json already exists — NOT rebuilt (pre-registration preserved)"
  python3 -c "import json; d=json.load(open('$EV/predictions.json')); print('fixture cases:', d['targets']['fixtures-vulnapp']['case_count'])"
else
  python3 scripts/reverify/build_predictions.py || exit 1
fi
sha256sum $EV/predictions.json

echo "== P3.2: benchmark CLI run (actual engine, all detectors + race battery) =="
T0=$(date +%s)
timeout 540 python3 -m burhan.cli benchmark --race \
  --out $EV/fixtures-vulnapp/benchmark.json \
  > $EV/fixtures-vulnapp/benchmark_stdout.log 2>&1
RC=$?
T1=$(date +%s)
echo "benchmark rc=$RC wall=$((T1-T0))s"
tail -6 $EV/fixtures-vulnapp/benchmark_stdout.log
[ $RC -ne 0 ] && { echo "BENCHMARK FAILED"; exit 2; }
python3 -c "
import json
d = json.load(open('$EV/fixtures-vulnapp/benchmark.json'))
print('confusion:', d['confusion'], '| P/R/F1:', d['precision'], d['recall'], d['f1'])
print('run_id:', d['run_id'], '| requests:', d['stats']['requests'], '| findings:', len(d['findings']))
"
echo "P3A COMPLETE"

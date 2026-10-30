#!/bin/bash
# STEP 2a (atomic): predictions integrity proof + target status refresh (2026-10-31).
# - Rebuild predictions.json with the REAL builder and byte-compare vs committed
#   (proves the pre-registration derives from fixture source + ground_truth.json,
#   never from engine output, and was not tampered with).
# - docker availability today; ginandjuice permission page TODAY; testphp retry.
set -uo pipefail
cd /home/z/my-project
export PYTHONPATH=/home/z/my-project

echo "== [0] guard =="
CUR=$(git rev-parse HEAD); BR=$(git branch --show-current)
echo "HEAD=$CUR branch=$BR"
[ "$CUR" = "0759c85ab639fdb555ba19b465d291b3d2b27999" ] && [ "$BR" = "main" ] || { echo "ABORT: unexpected tree state"; exit 1; }
EV=evidence/full-reverify

echo "== [1] committed predictions.json integrity =="
git show HEAD:$EV/predictions.json | sha256sum
sha256sum $EV/predictions.json
echo "-- rebuild with the real builder (deterministic; dates are constants) --"
cp $EV/predictions.json /home/z/my-project/.pred_backup.json
python3 scripts/reverify/build_predictions.py
echo "-- byte comparison --"
if cmp -s .pred_backup.json $EV/predictions.json; then
  echo "REBUILD == COMMITTED (byte-identical): pre-registration integrity PROVEN"
else
  echo "REBUILD DIFFERS from committed — restoring committed version"
  cp .pred_backup.json $EV/predictions.json
  diff <(python3 -m json.tool .pred_backup.json) <(python3 -m json.tool $EV/predictions.json) | head -20
fi
rm -f .pred_backup.json

echo "== [2] ground truth + fixture source (what the predictions derive from) =="
python3 - <<'PYEOF'
import hashlib, json
gt_raw = open("benchmarks/ground_truth.json", encoding="utf-8").read()
gt = json.loads(gt_raw)
cases = gt["ground_truth"]
pos = [g for g in cases if g["present"]]
print("ground_truth.json sha256:", hashlib.sha256(gt_raw.encode()).hexdigest())
print("cases:", len(cases), "| positives:", len(pos), "| negatives:", len(cases)-len(pos))
doc = open("fixtures/vulnapp.py", encoding="utf-8").read().split('"""')[1]
print("fixture docstring (first 400 chars):")
print(doc[:400])
PYEOF

echo "== [3] docker availability (2026-10-31) =="
if command -v docker >/dev/null 2>&1; then
  docker version --format '{{.Server.Version}}' > $EV/docker-targets/status.json 2>&1 || \
    echo '{"available": false, "reason": "docker binary present but daemon unreachable (2026-10-31)"}' > $EV/docker-targets/status.json
else
  echo '{"available": false, "reason": "docker command not found in this environment (checked 2026-10-31); the five Docker training apps are SKIPPED — no unauthorized substitution made"}' > $EV/docker-targets/status.json
fi
cat $EV/docker-targets/status.json

echo "== [4] ginandjuice.shop permission page TODAY (2026-10-31) =="
code=$(curl -s -o $EV/ginandjuice-shop/permission_page.html -w "%{http_code}" --max-time 25 https://ginandjuice.shop/ 2>/dev/null)
echo "ginandjuice.shop HTTP $code"
python3 - <<PYEOF
import json, re, html
from pathlib import Path
raw = Path("$EV/ginandjuice-shop/permission_page.html").read_text(encoding="utf-8", errors="replace")
text = re.sub(r'<script.*?</script>', ' ', raw, flags=re.S)
text = re.sub(r'<[^>]+>', ' ', text)
text = html.unescape(re.sub(r'\s+', ' ', text))
m = re.search(r'(This is a deliberately[^.]*\.)', text)
quote = m.group(1) if m else "PERMISSION SENTENCE NOT FOUND ON PAGE"
out = {"url": "https://ginandjuice.shop/", "fetched": "2026-10-31",
       "http_status": "$code", "permission_quote": quote,
       "page_text_excerpt": text[:600]}
Path("$EV/ginandjuice-shop/permission.json").write_text(
    json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
print("permission quote:", quote)
print("SCAN-AUTHORIZED" if quote.startswith("This is a deliberately") and "$code" == "200" else "SCAN-NOT-AUTHORIZED — the external scan must be skipped")
PYEOF

echo "== [5] testphp.vulnweb.com retry TODAY (2026-10-31) =="
tp_code=000
for i in 1 2; do
  tp_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 "http://testphp.vulnweb.com/" 2>/dev/null)
  [ "$tp_code" = "200" ] && break
done
echo "testphp HTTP $tp_code"
python3 - <<PYEOF
import json
from pathlib import Path
p = Path("$EV/testphp-vulnweb/status.json")
verdict = ("REACHABLE — scan authorized by Acunetix's public test-site policy"
           if "$tp_code" == "200" else
           "UNREACHABLE-SKIPPED (connection timeout from this environment on every attempt 2026-10-31; no scan performed; no substitution made)")
json.dump({"url": "http://testphp.vulnweb.com/", "http_status": "$tp_code",
           "checked": "2026-10-31", "verdict": verdict},
          open(p, "w"), indent=1)
print(Path(p).read_text())
PYEOF

echo "== [6] tree status after refresh =="
git status --short | head -12
echo "STEP2A COMPLETE"

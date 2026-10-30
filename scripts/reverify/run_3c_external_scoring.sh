#!/usr/bin/env bash
# PART 3C (atomic) — ginandjuice.shop full-detector scan + replay,
# testphp final retry, independent scoring vs pre-registered predictions,
# SHA-256 stamping of all raw evidence.
set -uo pipefail
cd /home/z/my-project
export PYTHONPATH=/home/z/my-project
EV=evidence/full-reverify

echo "== P3C.0: worktree on merged main =="
git checkout -- .gitignore 2>/dev/null || true
git checkout -f main 2>&1 | tail -1
git reset --hard main >/dev/null 2>&1
git checkout -- .gitignore 2>/dev/null || true

echo "== P3C.1: ginandjuice.shop scan (all detectors; anonymous — no creds published) =="
if [ -f $EV/ginandjuice-shop/scan.json ]; then
  echo "scan.json exists — skipping the scan (resume mode)"
else
  T0=$(date +%s)
  timeout 480 python3 -m sentinel.cli scan https://ginandjuice.shop/ \
    --workflow --logic-active --race --symbolic \
    --max-pages 25 --timeout 12.0 \
    --out $EV/ginandjuice-shop/scan.json \
    --db $EV/ginandjuice-shop/store.db \
    > $EV/ginandjuice-shop/scan_stdout.log 2>&1
  RC=$?
  T1=$(date +%s)
  echo "ginandjuice scan rc=$RC wall=$((T1-T0))s"
  tail -8 $EV/ginandjuice-shop/scan_stdout.log
  [ $RC -ne 0 ] && { echo "SCAN FAILED (continuing to record the failure honestly)"; }
fi

echo "== P3C.2: independent replay of every persisted ginandjuice proof =="
if [ -f $EV/ginandjuice-shop/replay_results.json ]; then
  echo "replay results exist — skipping (resume mode)"
else
  python3 - <<'PYEOF' || exit 1
import json, sys
from pathlib import Path
sys.path.insert(0, ".")
from sentinel.store import Store
from sentinel.evidence import replay_finding
from sentinel.core import EventBus, ScopeRule
from urllib.parse import urlsplit

EV = Path("evidence/full-reverify/ginandjuice-shop")
st = Store(str(EV / "store.db"))
runs = st.list_runs(limit=10)
proofs, findings = [], []
for r in runs:
    run = st.get_run(r["run_id"])
    if not run:
        continue
    proofs.extend((run.get("stats") or {}).get("proofs") or [])
    findings.extend(st.list_findings(run_id=r["run_id"], status="verified")
                    if hasattr(st, "list_findings") else [])
print(f"runs={len(runs)} proofs={len(proofs)}")
results = []
for p in proofs:
    req = (p.get("requests") or [{}])[0]
    url = req.get("url", "")
    if not url:
        results.append({"finding_id": p.get("finding_id"),
                        "replay": "NO_REQUEST_URL"})
        continue
    scope = ScopeRule(allowed_domains=[urlsplit(url).hostname],
                      allow_private=False)
    try:
        r = replay_finding(p, scope, EventBus("reverify-gj"), timeout=15.0)
    except Exception as exc:  # noqa: BLE001
        r = {"replay": "REPLAY_ERROR", "error": repr(exc)}
    r = dict(r)
    r["finding_id"] = p.get("finding_id")
    r["type"] = p.get("finding_type", p.get("type", ""))
    results.append(r)
    print(" ", r.get("replay"), r.get("finding_id"), r.get("type", ""))
from collections import Counter
c = Counter(r.get("replay") for r in results)
summary = dict(c)
summary["findings_total"] = len(results)
(EV / "replay_results.json").write_text(
    json.dumps({"summary": summary, "results": results}, indent=1),
    encoding="utf-8")
print("ginandjuice replay summary:", summary)
PYEOF
fi

echo "== P3C.3: testphp final retry (for the record) =="
tp_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 "http://testphp.vulnweb.com/" 2>/dev/null)
python3 - <<PYEOF
import json
from pathlib import Path
p = Path("$EV/testphp-vulnweb/status.json")
d = json.loads(p.read_text())
d["final_retry_status"] = "$tp_code"
d["verdict"] = "REACHABLE-SCANNED" if "$tp_code" == "200" else "UNREACHABLE-SKIPPED (connection timeout from this environment on every attempt 2026-10-30; no scan performed; no substitution made)"
p.write_text(json.dumps(d, indent=1))
print(d)
PYEOF

echo "== P3C.4: independent scoring vs pre-registered predictions =="
python3 scripts/reverify/score_reverify.py || exit 1

echo "== P3C.5: SHA-256 stamping of all raw evidence =="
cd $EV
find . -type f \( -name "*.json" -o -name "*.log" -o -name "*.html" -o -name "*.db" -o -name "*.md" \) ! -name "SHA256SUMS*" ! -name "*.memory.json" -print0 \
  | xargs -0 sha256sum > SHA256SUMS 2>/dev/null || \
  (find . -type f ! -name "SHA256SUMS*" ! -name "*.memory.json" -print0 | xargs -0 sha256sum > SHA256SUMS)
wc -l SHA256SUMS
head -20 SHA256SUMS
cd /home/z/my-project
echo "P3C COMPLETE"

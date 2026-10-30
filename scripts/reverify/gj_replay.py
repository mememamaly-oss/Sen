"""Incremental clean-engine replay of every persisted ginandjuice proof.

Resumable: completed finding ids are recorded in replay_progress.jsonl;
re-running the script continues where the last call stopped (needed because
processes do not survive tool-call boundaries in this environment).
A wall budget (GJ_BUDGET seconds, default 420) stops the loop cleanly.
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sentinel.core import EventBus, ScopeRule
from sentinel.evidence import replay_finding
from sentinel.store import Store
from urllib.parse import urlsplit

EV = Path("evidence/full-reverify/ginandjuice-shop")
BUDGET = float(sys.argv[1]) if len(sys.argv) > 1 else 420.0

st = Store(str(EV / "store.db"))
runs = st.list_runs(limit=5)
proofs = []
for r in runs:
    run = st.get_run(r["run_id"])
    if run:
        stats = run.get("stats") or {}
        proofs.extend(stats.get("proofs") or [])
print(f"runs={len(runs)} proofs_persisted={len(proofs)}", flush=True)

progress = EV / "replay_progress.jsonl"
done_ids = set()
if progress.exists():
    for line in progress.read_text(encoding="utf-8").splitlines():
        try:
            done_ids.add(json.loads(line)["finding_id"])
        except Exception:
            pass
print(f"already replayed: {len(done_ids)}", flush=True)

t0 = time.time()
processed = 0
for p in proofs:
    fid = p.get("finding_id")
    if not fid or fid in done_ids:
        continue
    if time.time() - t0 > BUDGET:
        print("wall budget reached — resume with another call", flush=True)
        break
    req = (p.get("requests") or [{}])[0]
    url = req.get("url", "")
    if not url:
        rec = {"finding_id": fid, "replay": "NO_REQUEST_URL"}
    else:
        scope = ScopeRule(allowed_domains=[urlsplit(url).hostname],
                          allow_private=False)
        try:
            r = replay_finding(p, scope, EventBus("reverify-gj"), timeout=12.0)
        except Exception as exc:  # noqa: BLE001
            r = {"replay": "REPLAY_ERROR", "error": repr(exc)}
        rec = dict(r)
        rec["finding_id"] = fid
        rec["type"] = p.get("finding_type", p.get("type", ""))
    with open(progress, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    done_ids.add(fid)
    processed += 1
    print(f"  {rec.get('replay'):24s} {fid} {rec.get('type', '')}", flush=True)

# summarize when every proof has a verdict
total = len(proofs)
if len(done_ids) >= total:
    recs = [json.loads(l) for l in
            progress.read_text(encoding="utf-8").splitlines()]
    from collections import Counter
    c = Counter(r.get("replay") for r in recs)
    summary = {"findings_total": total, **dict(c)}
    (EV / "replay_results.json").write_text(
        json.dumps({"summary": summary, "results": recs}, indent=1,
                   ensure_ascii=False), encoding="utf-8")
    print("ALL DONE. summary:", summary, flush=True)
else:
    print(f"progress: {len(done_ids)}/{total} — run this script again",
          flush=True)

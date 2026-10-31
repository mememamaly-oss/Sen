"""RP verification (2026-10-31): replay the five remote path_traversal
proofs from the committed scan.json (the store.db stayed local and was lost
to the environment recycle) through the FIXED engine — the RP-3 legacy
signature fallback routes them to trav_hname (header-NAME channel) instead
of the historical VALUE-channel mis-route.

Protocol: permission re-verified at run time (root page HTTP 200 + the
deliberately-vulnerable statement verbatim — fetched immediately before
this script ran). Bounded: 2-3 requests per finding, read-only differential
probes (the same probes the authorized scan itself used).
"""
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from burhan.core import EventBus, ScopeRule
from burhan.evidence import replay_finding

EV = Path(__file__).resolve().parents[2] / "evidence/full-reverify/ginandjuice-shop"
scan = json.loads((EV / "scan.json").read_text(encoding="utf-8"))
proofs = (scan.get("stats") or {}).get("proofs") or []
targets = [p for p in proofs if p.get("type") == "path_traversal"]
print(f"proofs total={len(proofs)} path_traversal={len(targets)}", flush=True)

progress = EV / "replay_progress.jsonl"
done = {}
for line in progress.read_text(encoding="utf-8").splitlines():
    try:
        r = json.loads(line)
        done[r["finding_id"]] = r
    except Exception:
        pass

t0 = time.time()
for p in targets:
    fid = p.get("finding_id")
    req = (p.get("requests") or [{}])[0]
    url = req.get("url", "")
    scope = ScopeRule(allowed_domains=[urlsplit(url).hostname],
                      allow_private=False)
    try:
        r = replay_finding(p, scope, EventBus("rp-gj-replay"), timeout=12.0)
    except Exception as exc:  # noqa: BLE001 — recorded, never hidden
        r = {"replay": "REPLAY_ERROR", "error": repr(exc)}
    r = dict(r)
    r["finding_id"] = fid
    r["type"] = p.get("type", "")
    done[fid] = r
    print(f"  {r.get('replay'):24s} {fid} ({time.time()-t0:.1f}s)", flush=True)

# rewrite the full progress + results exactly like the campaign driver
records = list(done.values())
with open(progress, "w", encoding="utf-8") as fh:
    for r in records:
        fh.write(json.dumps(r, ensure_ascii=False) + "\n")
from collections import Counter
c = Counter(r.get("replay") for r in records)
summary = {"findings_total": len(records), **dict(c)}
(EV / "replay_results.json").write_text(
    json.dumps({"summary": summary, "results": records}, indent=1,
               ensure_ascii=False), encoding="utf-8")
print("SUMMARY:", summary, flush=True)

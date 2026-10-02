#!/usr/bin/env python3
"""Compact per-scan summary for the v4.2.0 live-target validation.
Writes to tool-results/v420_live_<name>.txt (small scalar output)."""
import json, sys
from collections import Counter

name = sys.argv[1]
src = sys.argv[2]
d = json.load(open(src))
out = open(f"/home/z/my-project/tool-results/v420_live_{name}.txt", "w")
w = out.write

w(f"== {name} ==\n")
w(f"run_id={d.get('run_id')} scanner={d.get('scanner')} requests={d.get('stats', {}).get('requests', '?')}\n")
fnd = d.get("findings", []) or []
rej = d.get("rejected_candidates", []) or []
unv = d.get("unverified_candidates", []) or []
w(f"verified={len(fnd)} rejected={len(rej)} unverified_candidates={len(unv)}\n")

w("-- verified actives (non-passive) --\n")
for f in sorted(fnd, key=lambda x: -(x.get("risk") or 0)):
    t = f.get("type", "?")
    if t in ("missing_security_headers", "server_banner_disclosure",
             "tech_banner_disclosure", "vulnerable_js_dependency"):
        continue
    v = f.get("verification") or {}
    w(f"  {t} @ {f.get('url','')[:80]} param={f.get('parameter','')[:24]} "
      f"risk={f.get('risk')} conf={f.get('confidence')} "
      f"method={v.get('method','')[:44]} rounds={v.get('rounds')}\n")

w("-- verified passive --\n")
pc = Counter(f.get("type") for f in fnd
             if f.get("type") in ("missing_security_headers", "server_banner_disclosure",
                                  "tech_banner_disclosure", "vulnerable_js_dependency"))
for t, n in pc.items():
    confs = {f.get("confidence") for f in fnd if f.get("type") == t}
    w(f"  {t} x{n} conf={sorted(confs)}\n")

w("-- rejected candidates --\n")
for f in rej[:12]:
    v = f.get("verification") or {}
    w(f"  {f.get('type')} @ {f.get('url','')[:70]} param={f.get('parameter','')[:20]} "
      f"method={v.get('method','')[:40]} conf={f.get('confidence')}\n")

w("-- unverified candidates (v4.2.0 honesty layer) --\n")
for f in unv[:12]:
    v = f.get("verification") or {}
    w(f"  {f.get('type')} @ {f.get('url','')[:70]} param={f.get('parameter','')[:20]} "
      f"method={v.get('method','')[:44]} conf={f.get('confidence')}\n")

w(f"unverified by type: {dict(Counter(f.get('type') for f in unv))}\n")
w(f"rejected by type:  {dict(Counter(f.get('type') for f in rej))}\n")
out.close()
print(f"summary written: v420_live_{name}.txt")

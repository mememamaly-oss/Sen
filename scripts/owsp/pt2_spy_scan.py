#!/usr/bin/env python3
"""Instrumented mini-scan on the LIVE benchmark: wrap HeaderNameTraversalDetector.run
to see (a) is it called? (b) does it throw? (c) what does it return?"""
import json, sys
sys.path.insert(0, "/home/z/my-project/build-v430")

from sentinel.orchestrator import SentinelScanner, ScanConfig
from sentinel.detect import HeaderNameTraversalDetector, ACTIVE_DETECTORS

orig_run = HeaderNameTraversalDetector.run
calls = []
def spy_run(self, ep):
    # wrap engine.send to capture the trav-hname pair responses
    orig_send = self.engine.send
    captured = []
    def spy_send(m, **kw):
        r = orig_send(m, **kw)
        note = getattr(m, "note", "")
        if "trav-hname" in (note or ""):
            captured.append((note, None if r is None else (r.status, len(r.body or ""), (r.body or "")[:110])))
        return r
    self.engine.send = spy_send
    try:
        f = orig_run(self, ep)
        calls.append((ep.url, "OK" if f else "None", captured))
        return f
    except Exception as e:
        calls.append((ep.url, f"EXC:{type(e).__name__}: {e}", captured))
        raise
    finally:
        self.engine.send = orig_send
HeaderNameTraversalDetector.run = spy_run

spec = json.load(open("/tmp/spec215.json"))
cfg = ScanConfig(active=True, passive=True, allow_private=True, crawl=False,
                 openapi=False, openapi_spec=spec, seed="7f3c91aa", max_pages=10)
sc = SentinelScanner("http://localhost:8080/benchmark", cfg)
out = sc.run()
print("=== spy results ===")
for c in calls:
    print("  endpoint:", c[0], "->", c[1])
    for cap in c[2]:
        print("      ", cap)
if not calls: print("   (run() was NEVER called)")
act = [f for f in out["findings"] if f["type"] == "path_traversal"]
print("path_traversal findings:", [(f["status"], f.get("parameter")) for f in act])

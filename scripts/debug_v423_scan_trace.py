#!/usr/bin/env python3
"""Instrumented gruyere scan: trace every StoredXSSDetector.run() invocation."""
import sys
sys.path.insert(0, "/home/z/my-project/build-v423")
from sentinel.orchestrator import SentinelScanner, ScanConfig
from sentinel.detect import StoredXSSDetector

orig_run = StoredXSSDetector.run
calls = []

def traced_run(self, ep):
    info = {"url": ep.url, "source": str(ep.source), "method": ep.method,
            "tags": list(ep.tags or []),
            "params": [(p.name, str(p.kind)) for p in ep.parameters]}
    calls.append(info)
    print(f"[TRACE] run() called: {ep.url[:90]} src={ep.source} method={ep.method} "
          f"tags={ep.tags}", file=sys.stderr, flush=True)
    try:
        r = orig_run(self, ep)
    except Exception as e:
        print(f"[TRACE] run() RAISED {type(e).__name__}: {e}", file=sys.stderr, flush=True)
        raise
    print(f"[TRACE] run() -> {[(f.type, f.parameter) for f in r] if r else '[]'}",
          file=sys.stderr, flush=True)
    return r

StoredXSSDetector.run = traced_run

cfg = ScanConfig(seed="7f3c91aa", timeout=12.0)
sc = SentinelScanner("https://google-gruyere.appspot.com", cfg)
out = sc.run()
print(f"\n[TRACE] total run() calls: {len(calls)}")
for c in calls:
    print("  ", c["url"][:95], "| src:", c["source"], "| method:", c["method"])
strong = [f for f in out.get("findings", [])
          if f["type"] not in ("missing_security_headers", "server_banner_disclosure",
                               "tech_banner_disclosure", "vulnerable_js_dependency")]
print("strong findings:", [(f["type"], f["status"], f.get("parameter")) for f in strong])

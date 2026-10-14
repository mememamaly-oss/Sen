#!/usr/bin/env python3
"""TB-1b live debug 2: run the orchestrator's EXACT active loop on ONE spec
endpoint with the bus instrumented — find whether TrustBoundDetector.run is
called and what its probes return."""
import sys
sys.path.insert(0, "/home/z/my-project/build-v430")
from sentinel.orchestrator import SentinelScanner, ScanConfig

CFG = dict(allow_private=True, max_pages=4, timeout=8, seed="tb1bdbg",
           browser=False, oast=None)

seen = []


class BusSpy:
    def __init__(self, inner):
        self.inner = inner
    def emit(self, ev, **kw):
        if ev in ("CandidateCreated", "ScannerFailed", "OobAttemptStarted"):
            seen.append((ev, kw))
        return self.inner.emit(ev, **kw)
    def __getattr__(self, a):
        return getattr(self.inner, a)


class ScannerSpy(SentinelScanner):
    pass


# monkeypatch TrustBoundDetector.run to trace invocation
import sentinel.detect as D
_orig_run = D.TrustBoundDetector.run

def traced_run(self, ep):
    r = _orig_run(self, ep)
    seen.append(("TB_RUN", {"url": ep.url, "n_params": len(ep.parameters),
                            "method": ep.method, "result": bool(r)}))
    return r

D.TrustBoundDetector.run = traced_run

cfg = ScanConfig(**CFG)
cfg.openapi_spec = "/home/z/my-project/tool-results/tb_minispec/spec_tb1b.json"
cfg.no_crawl = True
sc = SentinelScanner("http://localhost:8080/benchmark", cfg)
rep = sc.run()
for ev, kw in seen:
    if ev == "TB_RUN" or (ev == "CandidateCreated" and kw.get("type") == "trust_bound"):
        print(ev, kw)
print("--- findings ---")
for f in rep["findings"]:
    print(f["type"], f["url"].rsplit("/", 1)[-1], f["status"])

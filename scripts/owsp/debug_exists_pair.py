#!/usr/bin/env python3
"""GTP-12 debug: run TraversalDetector.exists_pair live on a chosen Benchmark
servlet and print the four probe responses (known/missing/writable/unwritable)
to see exactly why the oracle does or does not separate."""
import sys, json
sys.path.insert(0, "/home/z/my-project/build-v430")
from sentinel.discovery import parse_openapi
from sentinel.http_engine import RequestEngine, RequestMutation
from sentinel.core import EventBus, ScopeRule
from sentinel.detect import TraversalDetector
from sentinel.core import ParamKind

TEST = sys.argv[1] if len(sys.argv) > 1 else "BenchmarkTest00002"
spec = json.load(open(f"/home/z/my-project/tools/benchmark-src/target/campaign/spec_one_{TEST}.json"))
eps = parse_openapi(spec, "http://localhost:8080/benchmark")
ep = next(e for e in eps if TEST in e.url)
print("endpoint:", ep.url, ep.method)
print("params:", [(p.name, p.kind.value, p.location) for p in ep.parameters])

from urllib.parse import urlsplit
_h = urlsplit("http://localhost:8080/benchmark")
engine = RequestEngine(ScopeRule(allowed_hosts=[_h.hostname], allow_private=True), EventBus("dbg"))
det = TraversalDetector(engine, EventBus("dbg"))

# replicate exists_pair's inner loop with visibility
import random as _rw
missing = det.EXISTS_MISSING.format(d=abs(hash((ep.url, ep.parameters[0].name))) % 99991)
p = ep.parameters[0]
for depth in (7, 8):
    base_up = "../" * depth
    for note, val in (("known", base_up + "etc/passwd"),
                      ("missing", base_up + "etc/" + missing)):
        r = engine.send(RequestMutation(endpoint=ep, param_name=p.name, param_value=val))
        if r is None:
            print(f"depth{depth} {note}: NONE"); continue
        print(f"depth{depth} {note}: status={r.status} len={len(r.body or '')} err={r.error}")
        if r.body: print("   body[:120]:", (r.body or "")[:120].replace(chr(10), " | "))
    wr = f"sentinel-w-{_rw.randrange(1000, 99999)}"
    for note, val in (("writable", base_up + "tmp/" + wr),
                      ("unwritable", base_up + "etc/" + wr)):
        r = engine.send(RequestMutation(endpoint=ep, param_name=p.name, param_value=val))
        if r is None:
            print(f"depth{depth} {note}: NONE"); continue
        print(f"depth{depth} {note}: status={r.status} len={len(r.body or '')} err={r.error}")
        if r.body: print("   body[:120]:", (r.body or "")[:120].replace(chr(10), " | "))
    print("---")
    break

# now the real call
f = det.exists_pair(ep, p)
print("exists_pair result:", f.type if f else None, f.status if f else "")
if f:
    for e in f.evidence: print("  ", e.kind, e.detail[:150])

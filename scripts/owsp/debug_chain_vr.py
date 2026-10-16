#!/usr/bin/env python3
"""GTP-12c debug: run the hash chain + VR-27 verification in-process with full
visibility — where exactly does the fresh-marker replay break?"""
import sys, json
sys.path.insert(0, "/home/z/my-project/build-v430")
from sentinel.discovery import parse_openapi
from sentinel.http_engine import RequestEngine, RequestMutation
from sentinel.core import EventBus, ScopeRule, Endpoint, FindingStatus
from sentinel.chainphase import HashCryptoChainPhase
from sentinel.intel import VerificationEngine

spec = json.load(open("/home/z/my-project/tools/benchmark-src/target/campaign/spec_chain_mini.json"))
eps = parse_openapi(spec, "http://localhost:8080/benchmark")
bus = EventBus("dbg")
engine = RequestEngine(ScopeRule(allowed_hosts=["localhost"], allow_private=True), bus)

# --- stage 1: primitives must verify. Build them the way the scan does:
# simplest: run a mini orchestrator-less flow — use the phase over the
# endpoints but first hand it the two verified primitive FINDINGS by
# running the traversal detector exists_pair on 00001/00002.
from sentinel.detect import TraversalDetector
det = TraversalDetector(engine, bus)
ep1 = next(e for e in eps if e.url.endswith("BenchmarkTest00001"))
ep2 = next(e for e in eps if e.url.endswith("BenchmarkTest00002"))
# the read primitive needs file_marker evidence -> run the marker battery on 00001
f_read = None
for _pl, m in det.candidates(ep1):
    r = engine.send(m)
    if r is None or r.error:
        continue
    pair = (ep1, ep1.parameters[0])
    cand = det.analyze(pair, r)
    if cand is not None:
        f_read = cand
        break
f_write = det.exists_pair(ep2, ep2.parameters[0])
ver0 = VerificationEngine(engine, bus)
f_read = ver0.verify(f_read, next(e for e in eps if e.url.endswith("BenchmarkTest00001"))) if f_read else None
f_write = ver0.verify(f_write, next(e for e in eps if e.url.endswith("BenchmarkTest00002"))) if f_write else None
print("read primitive:", f_read and f_read.type, f_read and f_read.status.value)
print("write primitive:", f_write and f_write.type, f_write and f_write.status.value)

# --- stage 2: run the chain phase
phase = HashCryptoChainPhase(engine, bus)
findings = phase.run(eps, [f_read, f_write])
print(f"\nchain phase produced {len(findings)} findings:")
for f in findings:
    print(f"  {f.type} {f.endpoint_url.split('/')[-1]} status={f.status.value}")
    for e in f.evidence:
        print(f"    {e.kind}: {e.detail[:100]}")
        if e.raw_snippet:
            print(f"      recipe: {e.raw_snippet[:150]}")

# --- stage 3: verify each through the real verifier
ver = VerificationEngine(engine, bus)
print("\n--- verification ---")
for f in findings:
    ep = next((e for e in eps if e.url == f.endpoint_url), None)
    out = ver.verify(f, ep)
    print(f"  {f.type} {f.endpoint_url.split('/')[-1]} -> {out.status.value}")
    if out.verification:
        print(f"     method={out.verification.method} passed={out.verification.passed} notes={out.verification.notes[:150]}")

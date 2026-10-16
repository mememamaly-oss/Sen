#!/usr/bin/env python3
"""Direct live test of the weakrand phase + hash/crypto chain phase against
the Benchmark, using the real engine pipeline pieces."""
import sys, json
sys.path.insert(0, "/home/z/my-project/build-v430")
from sentinel.core import Endpoint, EventBus, Severity, FindingStatus, ScopeRule
from sentinel.http_engine import RequestEngine
from sentinel.weakrand import WeakRandomPhase
from sentinel.chainphase import HashCryptoChainPhase
from sentinel.detect import entity_normalize
import re

bus = EventBus("debug-phases")
eng = RequestEngine(ScopeRule(allowed_domains=["localhost"], allow_private=True), bus)

# ---- weakrand on the 4 target endpoints
eps = [Endpoint(url=f"http://localhost:8080/benchmark/weakrand-00/BenchmarkTest{n}",
                method="POST") for n in ("00085", "00160", "00161", "00078")]
eps.append(Endpoint(url="http://localhost:8080/benchmark/weakrand-01/BenchmarkTest00461", method="POST"))
phase = WeakRandomPhase(eng, bus)
for ep in eps:
    fs = phase.run([ep], [])
    print(ep.url.split("/")[-1], "->", [(f.type, f.parameter) for f in fs] or "SILENT")

# ---- chain phase with a simulated verified read primitive
read_ep = Endpoint(url="http://localhost:8080/benchmark/pathtraver-00/BenchmarkTest00001",
                   method="POST")
class FakeFinding:
    type = "path_traversal"
    status = FindingStatus.VERIFIED
    endpoint_url = read_ep.url
    parameter = "BenchmarkTest00001"
    class _E:
        kind = "file_marker"
        detail = ""
    evidence = [_E()]
class FakeEvidence:
    kind = "file_marker"
    detail = "x"
    request_id = "req-x"
    raw_snippet = ""

from sentinel.core import Finding
read_finding = Finding(type="path_traversal", severity=Severity.HIGH,
                       endpoint_url=read_ep.url, parameter="BenchmarkTest00001",
                       method="POST",
                       evidence=[type("E", (), {"kind": "file_marker", "detail": "d",
                                                "request_id": "r", "raw_snippet": ""})()],
                       status=FindingStatus.VERIFIED)

heps = [Endpoint(url=f"http://localhost:8080/benchmark/hash-00/BenchmarkTest{n}", method="POST")
        for n in ("00003", "00029")]
ceps = [Endpoint(url=f"http://localhost:8080/benchmark/crypto-00/BenchmarkTest{n}", method="POST")
        for n in ("00005", "00019")]
weps = [Endpoint(url="http://localhost:8080/benchmark/pathtraver-00/BenchmarkTest00002", method="POST")]
all_eps = [read_ep] + weps + heps + ceps
chain = HashCryptoChainPhase(eng, bus)
# simulate the gate discovery by monkeypatching _gate_endpoints
chain._gate_endpoints = lambda endpoints: (heps, ceps)
out = chain.run(all_eps, [read_finding])
print("chain findings:", [(f.type, f.endpoint_url.split("/")[-1], f.parameter)
                          for f in out] or "SILENT")
print("resets:", chain._resets, "writes:", chain._writes, "reads:", chain._reads)

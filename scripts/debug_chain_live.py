#!/usr/bin/env python3
"""Debug the chainphase standalone on the live pair (00001 read + 00003 hash)."""
import sys
sys.path.insert(0, '/home/z/my-project/build-v430')
from sentinel.core import Endpoint, ScopeRule, EventBus, Finding, FindingStatus, Severity, Evidence
from sentinel.http_engine import RequestEngine
from sentinel.chainphase import HashCryptoChainPhase, ARTIFACT_WORDLIST, HASH_LINE, SECRET_LINE, HASH_GATE, K1
from sentinel.detect import entity_normalize

eng = RequestEngine(scope=ScopeRule(allow_private=True), bus=EventBus("cpdbg"), timeout=8)
read_ep = Endpoint(url="http://localhost:8080/benchmark/pathtraver-00/BenchmarkTest00001", method="POST")
from sentinel.core import Parameter, ParamLocation
read_ep.parameters = [Parameter("BenchmarkTest00001", ParamLocation.COOKIE, "FileName")]
hash_ep = Endpoint(url="http://localhost:8080/benchmark/hash-00/BenchmarkTest00003", method="POST")
hash_ep.parameters = [Parameter("BenchmarkTest00003", ParamLocation.COOKIE, "foo")]

ph = HashCryptoChainPhase(eng, EventBus("cpdbg"))
eps = [read_ep, hash_ep]
prim = ph._read_primitive(eps, [])  # no findings — supply manually below

# fabricate the verified file_marker finding the scan would carry
fake = Finding(type="path_traversal", severity=Severity.HIGH, endpoint_url=read_ep.url,
               parameter="BenchmarkTest00001", method="POST",
               evidence=[Evidence("file_marker", "content of /etc/passwd leaked", "req-x", "root:x:0:0:")],
               status=FindingStatus.VERIFIED)
prim = ph._read_primitive(eps, [fake])
print("read primitive:", prim)
if prim:
    read_ep2, read_param = prim
    # gate endpoints
    he, ce = ph._gate_endpoints(eps)
    print("hash gates:", [e.url[-20:] for e in he], "crypto:", [e.url[-20:] for e in ce])
    if he:
        # discovery loop manually
        for name in ARTIFACT_WORDLIST[:4]:
            before = ph._read_artifact(read_ep2, read_param, name) or ""
            r, wp = ph._submit(he[0], K1)
            after = ph._read_artifact(read_ep2, read_param, name) or ""
            new = ph._new_lines(before, after)
            hit = any(HASH_LINE.search(ln) or SECRET_LINE.search(ln) for ln in new)
            print(f"artifact {name!r}: before={len(before)}B after={len(after)}B new={len(new)} hit={hit}")
            if hit:
                print("  new lines:", new[:3])
                break

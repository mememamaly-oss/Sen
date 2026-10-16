#!/usr/bin/env python3
"""Debug the HashCryptoChainPhase against the live stack with the mini-scan findings."""
import json
import sys

sys.path.insert(0, "/home/z/my-project/build-v430")

from sentinel.core import (Endpoint, EventBus, Evidence, Finding, FindingStatus,
                           Severity, Parameter, ParamLocation, ParamKind)
from sentinel.http_engine import RequestEngine, ScopeRule, RequestMutation
from sentinel.chainphase import HashCryptoChainPhase, ARTIFACT_WORDLIST, HASH_GATE, CRYPTO_GATE

scan = json.load(open("/tmp/mini_scan.json"))
spec = json.load(open("/home/z/my-project/tools/benchmark-src/target/campaign/spec_mini.json"))

# rebuild endpoints from the spec
endpoints = []
for path, ops in spec["paths"].items():
    for method, op in ops.items():
        if not isinstance(op, dict):
            continue
        ep = Endpoint(url="http://localhost:8080/benchmark" + path, method=method.upper())
        params = []
        for prm in op.get("parameters", []) or []:
            loc = {"query": ParamLocation.QUERY, "header": ParamLocation.HEADER,
                   "cookie": ParamLocation.COOKIE, "body": ParamLocation.BODY}.get(prm.get("in"), ParamLocation.QUERY)
            params.append(Parameter(prm["name"], loc, "x"))
        ep.parameters = params
        endpoints.append(ep)
print("endpoints:", [(e.url.split('/')[-1], e.method) for e in endpoints])

# findings from the scan
findings = []
for f in scan["findings"]:
    if f["type"] != "path_traversal" or f.get("status") != "verified":
        continue
    ev = [Evidence(e.get("kind"), e.get("detail", ""), None, e.get("raw_snippet"))
          for e in f.get("evidence", [])]
    findings.append(Finding(type=f["type"], severity=Severity.HIGH,
                            endpoint_url=f["url"], parameter=f.get("parameter"),
                            method=f.get("method", "POST"), evidence=ev,
                            status=FindingStatus.VERIFIED))
print("traversal findings:", [(f.endpoint_url.split('/')[-1], f.parameter) for f in findings])

bus = EventBus("chaindbg")
eng = RequestEngine(ScopeRule(allowed_hosts=["localhost"], allow_private=True), bus, timeout=8.0)

ph = HashCryptoChainPhase(eng, bus)

# --- step 1: read primitive
prim = ph._read_primitive(endpoints, findings)
print("read primitive:", prim and (prim[0].url, prim[1]))
# --- step 2: write primitive
wprim = ph._write_primitive(endpoints, findings)
print("write primitive:", wprim and (wprim[0].url, wprim[1]))
# --- step 3: gates
hash_eps, crypto_eps = ph._gate_endpoints(endpoints)
print("gate hash_eps:", [e.url.split('/')[-1] for e in hash_eps])
print("gate crypto_eps:", [e.url.split('/')[-1] for e in crypto_eps])
# --- step 4: gate detail for one hash endpoint
if prim:
    rep, rp = prim
    for name in ARTIFACT_WORDLIST[:3]:
        body = ph._read_artifact(rep, rp, name)
        print(f"artifact read {name!r}:", (body or "")[:120].replace("\n", "|"))

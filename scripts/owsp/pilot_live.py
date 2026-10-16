#!/usr/bin/env python3
"""Live family pilot — probes one FN sample per (category x channel) family
directly through the engine's RequestEngine, printing what actually happens.

Run with the Benchmark stack UP (same tool call)."""
import sys, json, re
sys.path.insert(0, '/home/z/my-project/build-v430')
from urllib.parse import urlsplit
from sentinel.core import Endpoint, Parameter, ParamLocation, ScopeRule, EventBus
from sentinel.http_engine import RequestEngine, RequestMutation

BASE = "http://localhost:8080/benchmark"
SRC = "/home/z/my-project/tools/benchmark-src"

def spec_paths():
    import yaml
    s = yaml.safe_load(open(SRC + "/data/openapi.yaml"))
    return {p.rsplit("/", 1)[-1]: p for p in s["paths"] if "/BenchmarkTest" in p}

def ep_of(engine, test, paths):
    p = paths[test]
    op = "post" if "post" in json.dumps(_op_of(p))[:2000] or True else "get"
    # method: prefer POST (all Benchmark servlets accept both)
    ep = Endpoint(url=BASE + p, method="POST")
    # declared params from spec (form body or query)
    spec = _op_of(p)
    d = spec.get("post") or spec.get("get") or {}
    for prm in d.get("parameters", []) or []:
        loc = {"query": ParamLocation.QUERY, "header": ParamLocation.HEADER,
               "cookie": ParamLocation.COOKIE}.get(prm.get("in"), ParamLocation.QUERY)
        ep.parameters.append(Parameter(prm["name"], loc, prm.get("schema", {}).get("default", "") or "1"))
    rb = (d.get("requestBody") or {}).get("content", {})
    for ct, blob in rb.items():
        for pn, pd in ((blob.get("schema") or {}).get("properties") or {}).items():
            ep.parameters.append(Parameter(pn, ParamLocation.BODY, pd.get("default", "") or "sentinel"))
    return ep

_OPS = None
def _op_of(p):
    global _OPS
    import yaml
    if _OPS is None:
        s = yaml.safe_load(open(SRC + "/data/openapi.yaml"))
        _OPS = {pp: ops for pp, ops in s["paths"].items()}
    return _OPS[p]

def show(tag, r):
    if r is None:
        print(f"    {tag}: r=None"); return
    body = r.body or ""
    print(f"    {tag}: {r.status} len={len(body)} err={r.error}")
    return body

def main():
    eng = RequestEngine(scope=ScopeRule(allow_private=True), bus=EventBus("pilot"), timeout=8)
    paths = spec_paths()
    MARK = "sentinelpilot7x9"

    def probe(test, tag, param_name, param_value, loc=None):
        ep = ep_of(eng, test, paths)
        m = RequestMutation(endpoint=ep, param_name=param_name, param_value=param_value, note="pilot")
        if loc is not None:
            m.param_location = loc
        r = eng.send(m)
        b = show(f"{tag} [{param_name}={param_value[:40]}]"[:150], r)
        if b is not None and MARK in b:
            i = b.find(MARK)
            print(f"       MARKER FOUND: ...{b[max(0,i-60):i+70]}...")

    seg = lambda t: t

    print("=== 1) NAME-CHANNEL (name=payload, value=testID) ===")
    for t in ("BenchmarkTest00038", "BenchmarkTest00036", "BenchmarkTest00498",
              "BenchmarkTest00491", "BenchmarkTest00046"):
        probe(t, "namechan", MARK, seg(t))

    print("=== 2) HEADDERNAME-CHANNEL (header name=payload) ===")
    for t in ("BenchmarkTest00233", "BenchmarkTest00215", "BenchmarkTest00208"):
        probe(t, "hdrname", MARK, "1", loc=ParamLocation.HEADER)

    print("=== 3) QUERYSTRING-CHANNEL (?testID=payload) ===")
    for t in ("BenchmarkTest00823", "BenchmarkTest00785", "BenchmarkTest00820"):
        probe(t, "qschan", seg(t), MARK, loc=ParamLocation.QUERY)

    print("=== 4) HEADER-VALUE-CHANNEL (header testID: payload) ===")
    for t in ("BenchmarkTest00172", "BenchmarkTest00011", "BenchmarkTest00164"):
        probe(t, "hdrval", seg(t), MARK, loc=ParamLocation.HEADER)

    print("=== 5) VALUE-CHANNEL drift check (param name=testID) ===")
    for t in ("BenchmarkTest00031", "BenchmarkTest00497", "BenchmarkTest00403"):
        probe(t, "valchan", seg(t), MARK)

    print("=== 6) WEAKRAND cookie sampling ===")
    from sentinel.weakrand import WeakRandomPhase
    ph = WeakRandomPhase(eng, EventBus("pilot"))
    for t in ("BenchmarkTest00082", "BenchmarkTest00085", "BenchmarkTest00160",
              "BenchmarkTest00161", "BenchmarkTest00461", "BenchmarkTest00081",
              "BenchmarkTest00023"):
        ep = Endpoint(url=BASE + paths[t], method="POST")
        c1 = ph._fetch_cookie(ep)
        c2 = ph._fetch_cookie(ep) if c1 else None
        c3 = ph._fetch_cookie(ep) if c2 else None
        print(f"    {t}: {c1} | {c2} | {c3}")

    print("=== 7) CRYPTO/HASH file channel ===")
    ep = ep_of(eng, "BenchmarkTest00020", paths)
    r = eng.send(RequestMutation(endpoint=ep, param_name="BenchmarkTest00020",
                                 param_value="CryptoProbe1", note="crypto-write"))
    show("crypto POST", r)
    # read via the FIS read primitive — find one from the tp list of pathtraver
    # use a known-good read servlet: check spec for a FIS test we know verifies
    ep2 = ep_of(eng, "BenchmarkTest00001", paths)
    for depth in ("../../testfiles/passwordFile.txt",):
        r2 = eng.send(RequestMutation(endpoint=ep2, param_name="BenchmarkTest00001",
                                      param_value=depth, note="pfread"))
        b = show(f"read {depth}", r2)
        if b:
            i = b.find("hash_value") if "hash_value" in b else b.find("secret_value")
            if i >= 0: print("       FILE LINE:", b[i:i+140].replace("\n", " | "))

    print("=== 8) FOS pathtraver writability ===")
    ep3 = ep_of(eng, "BenchmarkTest00028", paths)
    for pv in ("/tmp/sentinelw.txt", "/etc/sentinelw.txt", "/tmp/sentinelw2.txt"):
        r = eng.send(RequestMutation(endpoint=ep3, param_name="BenchmarkTest00028",
                                     param_value=pv, note="fos"))
        b = show(f"FOS {pv}", r)
        if b: print("       tail:", b[-260:].replace("\n", " | "))

if __name__ == "__main__":
    main()

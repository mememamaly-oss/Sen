#!/usr/bin/env python3
"""Pilot 2 — live verification of every fix-family hypothesis (stack must be UP)."""
import sys, json, re, base64, hashlib
sys.path.insert(0, '/home/z/my-project/build-v430')
from sentinel.core import Endpoint, Parameter, ParamLocation, ScopeRule, EventBus
from sentinel.http_engine import RequestEngine, RequestMutation

BASE = "http://localhost:8080/benchmark"
SRC = "/home/z/my-project/tools/benchmark-src"

import yaml
_S = yaml.safe_load(open(SRC + "/data/openapi.yaml"))
PATHS = {p.rsplit("/", 1)[-1]: p for p in _S["paths"] if "/BenchmarkTest" in p}

def mk(test, method="POST"):
    p = PATHS[test]
    ep = Endpoint(url=BASE + p, method=method)
    d = _S["paths"][p].get("post") or _S["paths"][p].get("get") or {}
    for prm in d.get("parameters", []) or []:
        loc = {"query": ParamLocation.QUERY, "header": ParamLocation.HEADER,
               "cookie": ParamLocation.COOKIE}.get(prm.get("in"), ParamLocation.QUERY)
        ep.parameters.append(Parameter(prm["name"], loc, prm.get("schema", {}).get("default", "") or "1"))
    for ct, blob in ((d.get("requestBody") or {}).get("content", {})).items():
        for pn, pd in ((blob.get("schema") or {}).get("properties") or {}).items():
            ep.parameters.append(Parameter(pn, ParamLocation.BODY, pd.get("default", "") or "sentinel"))
    return ep

eng = RequestEngine(scope=ScopeRule(allow_private=True), bus=EventBus("p2"), timeout=8)

def send(ep, name, value, loc=None, note="p2"):
    m = RequestMutation(endpoint=ep, param_name=name, param_value=value, note=note)
    if loc is not None: m.param_location = loc
    return eng.send(m)

print("=== A) WEAKRAND relation families (jrand GTP-12 fixed) ===")
from sentinel.weakrand import WeakRandomPhase
ph = WeakRandomPhase(eng, EventBus("p2"))
for t, kind in (("BenchmarkTest00085", "long"), ("BenchmarkTest00160", "bytes"),
                ("BenchmarkTest00161", "double")):
    ep = mk(t)
    f = ph._family_relation(ep, "rememberMe" + t[-5:], kind)
    print(f"  {t} [{kind}]:", "FINDING!" if f else "none",
          (f.evidence[0].kind if f else ""))

print("=== B) FOS writability ladder (00028, value-channel) ===")
ep = mk("BenchmarkTest00028")
for d in (6, 7):
    up = "../" * d
    for tail in ("tmp/sentinel-w-aa1", "etc/sentinel-w-aa2", "passwordFile.txt"):
        r = send(ep, "BenchmarkTest00028", up + tail)
        b = (r.body or "") if r else ""
        print(f"  d{d} {tail:26} -> {r.status if r else '?'} len={len(b)} {b[:70]!r}")

print("=== C) exists-oracle (value-channel exists test 00619? use 00011 header) ===")
ep = mk("BenchmarkTest00011")
for pv in ("../../../../../../etc/passwd", "../../../../../../etc/sentinel-miss-77",
           "/etc/passwd", "/etc/sentinel-miss-77"):
    r = send(ep, "BenchmarkTest00011", pv, loc=ParamLocation.HEADER)
    b = (r.body or "") if r else ""
    tail = b[-90:].replace("\n", "|")
    print(f"  hdr {pv[18:] or pv:28} -> {r.status if r else '?'} {tail!r}")

print("=== D) crypto/hash chain (00020 write -> read via FIS primitive) ===")
ep = mk("BenchmarkTest00020")
r = send(ep, "BenchmarkTest00020", "chainPROBE1")
print("  crypto write:", r.status if r else "?", (r.body or "")[:90])
# find a FIS reader: use a known pathtraver TP test - try 00001 family (FIS header)
for reader, param, loc in (("BenchmarkTest00001", "BenchmarkTest00001", ParamLocation.HEADER),
                           ("BenchmarkTest00529", "BenchmarkTest00529", None)):
    ep2 = mk(reader)
    r2 = send(ep2, param, "passwordFile.txt", loc=loc)
    b = (r2.body or "") if r2 else ""
    hit = "hash_value" in b or "secret_value" in b
    print(f"  read via {reader} param=passwordFile.txt -> {r2.status if r2 else '?'} "
          f"len={len(b)} hit={hit}")
    if hit:
        i = max(b.find("hash_value"), b.find("secret_value"))
        print("    LINE:", b[i:i+130].replace("\n", " | "))
    # also traversal depth shape
    r3 = send(ep2, param, "../" * 0 + "passwordFile.txt", loc=loc)
    b3 = (r3.body or "") if r3 else ""
    print(f"    plain-rel shape -> {r3.status if r3 else '?'} len={len(b3)}",
          ("LINE: " + b3[max(b3.find('hash_value'), b3.find('secret_value')):][:120]) if ("hash_value" in b3 or "secret_value" in b3) else "")

print("=== E) hdrname bodies ===")
for t in ("BenchmarkTest00233", "BenchmarkTest00215"):
    ep = mk(t)
    r = send(ep, "sentinelhdrmark", "1", loc=ParamLocation.HEADER)
    print(f"  {t}:", r.status if r else "?", repr((r.body or "")[:200]))

print("=== F) sqli name-channel OR-pair (00038) ===")
ep = mk("BenchmarkTest00038")
for nm, tag in (("x' OR '1'='1' -- ", "or_true"), ("x' OR '1'='2' -- ", "or_false"),
                ("x", "plain")):
    r = send(ep, nm, "BenchmarkTest00038")
    b = (r.body or "") if r else ""
    print(f"  {tag:9} name={nm!r:26} -> {r.status if r else '?'} len={len(b)} {b[:110]!r}")

print("=== G) SecureCookieDetector + TrustBoundDetector in-process ===")
from sentinel.detect import SecureCookieDetector, TrustBoundDetector
scd = SecureCookieDetector(eng, EventBus("p2"))
f = scd.run(mk("BenchmarkTest00403"))
print("  securecookie 00403:", f.type if f else None, (f.evidence[0].detail[:80] if f else ""))
tbd = TrustBoundDetector(eng, EventBus("p2"))
f = tbd.run(mk("BenchmarkTest00031"))
print("  trustbound 00031:", f.type if f else None, (f.evidence[0].detail[:80] if f else ""))

print("=== H) nextInt bound + 00461 token code ===")
import subprocess
TCD = SRC + "/src/main/java/org/owasp/benchmark/testcode/"
d = json.load(open('/home/z/my-project/build-v430/results/owsp/benchmark/eval_v430_final_v430.json'))
import collections
hist = collections.Counter()
for t in d["per_category"]["weakrand"]["fn_tests"]:
    src = open(TCD + t + ".java").read()
    m = re.search(r"nextInt\((\d+)\)", src)
    if "nextInt" in src:
        hist["nextInt(%s)" % (m.group(1) if m else "FULL")] += 1
    elif "nextLong" in src: hist["nextLong"] += 1
    elif "nextFloat" in src: hist["nextFloat"] += 1
    elif "nextGaussian" in src: hist["nextGaussian"] += 1
    elif "nextBytes" in src: hist["nextBytes"] += 1
    elif "nextDouble" in src: hist["nextDouble"] += 1
    elif "Math.random" in src: hist["Math.random"] += 1
print("  weakrand FN generator histogram:", dict(hist))
src461 = open(TCD + "BenchmarkTest00461.java").read()
m = re.search(r"(Math\.random[^\n;]*)", src461)
print("  00461 Math.random usage:", m.group(1) if m else "?")

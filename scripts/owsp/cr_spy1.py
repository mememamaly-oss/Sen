#!/usr/bin/env python3
"""Task 40 — SPY scan: why does the current chain miss crypto FNs whose input IS
controllable through the EXISTING body channel (01322 family)? Zero code changes:
pure instrumentation (PT-2 methodology). Run with the stack UP.

Minispec: chain primitives (read 00001 / write 00002) + family samples + TP/TN controls.
Spy: wrap HashCryptoChainPhase._probe to log (endpoint, channel, marker-len, ct-len)."""
import json, sys, re
sys.path.insert(0, "/home/z/my-project/build-v430")

from sentinel.orchestrator import SentinelScanner, ScanConfig
from sentinel.chainphase import HashCryptoChainPhase
import yaml

BM = "/home/z/tools/benchmark"
CASES = {
    # primitives + traversal TP enablers
    "BenchmarkTest00001": "read-primitive", "BenchmarkTest00002": "write-primitive",
    "BenchmarkTest00525": "trav-TP", "BenchmarkTest00528": "trav-TP",
    # FN family samples (live-verified shapes)
    "BenchmarkTest01322": "FN form-testid CONTROLLED(16->24) -- MUST-FIRE MYSTERY",
    "BenchmarkTest01228": "FN form-testid CONTROLLED(16->24)",
    "BenchmarkTest01317": "FN form-testid CONTROLLED(16->24)",
    "BenchmarkTest01229": "FN form-testid CONTROLLED(8->16) len-1 puzzle",
    "BenchmarkTest01230": "FN form-testid CONTROLLED(24->32) suffix puzzle",
    "BenchmarkTest01102": "FN header-name CONTROLLED(16->24)",
    "BenchmarkTest02290": "FN value-match CONTROLLED(16->24)",
    "BenchmarkTest01634": "FN qs",
    "BenchmarkTest00053": "FN cookie (const via ternary?)",
    "BenchmarkTest01015": "FN header-value",
    "BenchmarkTest00050": "FN CONST bar",
    "BenchmarkTest00446": "FN CONST 26B",
    "BenchmarkTest02193": "FN switch-case",
    "BenchmarkTest02294": "FN param-wins ternary",
    "BenchmarkTest00610": "FN named-param puzzle (const)",
    # TP controls (must stay verified)
    "BenchmarkTest00005": "TP header-value", "BenchmarkTest00020": "TP form-testid",
    "BenchmarkTest00354": "TP form-testid", "BenchmarkTest00019": "TP raw-body",
    # TN controls (must stay silent)
    "BenchmarkTest00058": "TN GCM", "BenchmarkTest00128": "TN const-26B CCM",
    "BenchmarkTest01737": "TN const-bar GCM", "BenchmarkTest00255": "TN named-param",
}

spec = yaml.safe_load(open(f"{BM}/data/openapi.yaml"))
spec["servers"] = [{"url": "http://localhost:8080/benchmark"}]
sub = {k: spec[k] for k in spec if k != "paths"}
sub["paths"] = {}
for p in spec["paths"]:
    last = p.rstrip("/").split("/")[-1]
    if last in CASES:
        sub["paths"][p] = spec["paths"][p]
print(f"minispec: {len(sub['paths'])} paths (expected {len(CASES)})")

# ---------------- spy ----------------
trace = []
orig_probe = HashCryptoChainPhase._probe
orig_run = HashCryptoChainPhase.run

def spy_run(self, endpoints, findings):
    print(f"[chain] run: {len(endpoints)} endpoints, {len(findings)} findings")
    prim = self._read_primitive(endpoints, findings)
    wprim = self._write_primitive(endpoints, findings)
    print(f"[chain] read_prim={prim}  write_prim={wprim}")
    heps, ceps = self._gate_endpoints(endpoints)
    print(f"[chain] gated: hash={len(heps)} crypto={len(ceps)}")
    for ep in ceps:
        last = ep.url.rstrip("/").split("/")[-1]
        print(f"[chain]   crypto_ep: {last}  params={[p.name for p in ep.parameters][:6]}")
    return orig_run(self, endpoints, findings)

def spy_probe(self, ep, value, read_ep, read_param, artifact_name,
              write_ep=None, write_param=None, channel="declared"):
    ct = orig_probe(self, ep, value, read_ep, read_param, artifact_name,
                    write_ep, write_param, channel)
    last = ep.url.rstrip("/").split("/")[-1]
    trace.append({"ep": last, "role": CASES.get(last, "?"), "channel": channel,
                  "marker_len": len(value), "ct_len": None if ct is None else len(ct)})
    print(f"    probe {last:22s} ch={channel:8s} v={len(value):2d}B -> ct={None if ct is None else len(ct)}B")
    return ct

HashCryptoChainPhase._probe = spy_probe
HashCryptoChainPhase.run = spy_run

cfg = ScanConfig(active=True, passive=True, allow_private=True, crawl=False,
                 openapi=False, openapi_spec=sub, seed="7f3c91aa", max_pages=60)
sc = SentinelScanner("http://localhost:8080/benchmark", cfg)
out = sc.run()

print("\n=== SPY TRACE SUMMARY (crypto-relevant) ===")
from collections import defaultdict
per = defaultdict(list)
for t in trace:
    per[t["ep"]].append((t["channel"], t["marker_len"], t["ct_len"]))
for ep, rows in per.items():
    print(f"{ep} [{CASES.get(ep, '?')}]: {rows}")

print("\n=== FINDINGS ===")
for f in out["findings"]:
    if f["type"] in ("weak_crypto", "weak_hash", "path_traversal"):
        print(f"  {f['type']:15s} {f['status']:10s} {f['url'].rstrip('/').split('/')[-1]}")

json.dump({"trace": trace, "findings": [
    {"type": f["type"], "status": f["status"], "url": f["url"]} for f in out["findings"]]},
    open("/home/z/my-project/tool-results/cr_spy1.json", "w"), indent=1)
print("\nwritten: tool-results/cr_spy1.json")

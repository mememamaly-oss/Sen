#!/usr/bin/env python3
"""Task 40 CR-2 LIVE proof — the channel-ladder catches the controllable crypto
FNs on the real benchmark; the GCM/CCM TN guards stay silent (P15 gate).
Run with the stack UP. Includes CR-1's primitives (they are part of main now)."""
import json, sys
sys.path.insert(0, "/home/z/my-project/build-v430")
import yaml
from sentinel.orchestrator import SentinelScanner, ScanConfig

BM = "/home/z/tools/benchmark"

# CR-2 targets (live-battery-proven controllable ONLY via the new channels)
TARGETS = {
    "BenchmarkTest00035": "FN valmatch (DES/ECB prop)",
    "BenchmarkTest00521": "FN valmatch (ESAPI-mislabeled)",
    "BenchmarkTest00210": "FN hdrname",
    "BenchmarkTest02290": "FN valmatch",
    "BenchmarkTest02292": "FN valmatch",
    "BenchmarkTest02293": "FN valmatch",
    "BenchmarkTest02294": "FN param-wins-ternary via valmatch",
    "BenchmarkTest01978": "FN hdrname",
    "BenchmarkTest01980": "FN hdrname (suffix puzzle)",
    "BenchmarkTest01981": "FN hdrname",
    "BenchmarkTest01102": "FN hdrname (chunk5/6)",
    "BenchmarkTest01103": "FN hdrname (chunk5/6)",
    "BenchmarkTest01105": "FN hdrname (chunk5/6)",
    "BenchmarkTest01106": "FN hdrname (chunk5/6)",
    "BenchmarkTest00946": "FN cookie (chunk5/6)",
    "BenchmarkTest01018": "CR-1 catch, must STAY verified (header-value)",
}
# guards: TN that are CONTROLLABLE via the new channels — must stay SILENT
GUARDS = {
    "BenchmarkTest00058": "TN GCM-8tag (live: 16/24 + 15->23)",
    "BenchmarkTest01227": "TN GCM-16tag (live: 24/32/40 + 15->31)",
    "BenchmarkTest00255": "TN named-param",
    "BenchmarkTest00121": "TN header-value GCM",
    "BenchmarkTest00350": "TN form-testid CCM",
    "BenchmarkTest00775": "TN qs GCM",
}
CONTROLS = {
    "BenchmarkTest00005": "TP header-value (declared)",
    "BenchmarkTest00019": "TP raw-body",
    "BenchmarkTest00020": "TP form-testid",
    "BenchmarkTest00354": "TP form-testid",
}
PRIMS = {"BenchmarkTest00001": "read primitive", "BenchmarkTest00002": "write primitive"}

ALL = dict(TARGETS); ALL.update(GUARDS); ALL.update(CONTROLS); ALL.update(PRIMS)

spec = yaml.safe_load(open(f"{BM}/data/openapi.yaml"))
spec["servers"] = [{"url": "http://localhost:8080/benchmark"}]
sub = {k: spec[k] for k in spec if k != "paths"}
sub["paths"] = {}
for p in spec["paths"]:
    if p.rsplit("/", 1)[-1] in ALL:
        sub["paths"][p] = spec["paths"][p]
print(f"minispec: {len(sub['paths'])} paths")

cfg = ScanConfig(active=True, passive=True, allow_private=True, crawl=False,
                 openapi=False, openapi_spec=sub, seed="7f3c91aa", max_pages=100)
sc = SentinelScanner("http://localhost:8080/benchmark", cfg)
out = sc.run()

rows = {}
for f in out["findings"]:
    if f["type"] in ("weak_crypto", "weak_hash"):
        tid = f["url"].rstrip("/").split("/")[-1]
        rows.setdefault(tid, []).append((f["type"], f["status"]))

caught, missed, guards_fired, controls_lost = [], [], [], []
for t in TARGETS:
    ok = any(s == "verified" and ty == "weak_crypto" for ty, s in rows.get(t, []))
    (caught if ok else missed).append(t)
for g in GUARDS:
    if any(s == "verified" for ty, s in rows.get(g, [])):
        guards_fired.append(g)
for c in CONTROLS:
    if not any(s == "verified" for ty, s in rows.get(c, [])):
        controls_lost.append(c)

print(f"\nreqs: {out['stats'].get('requests')}")
print(f"CR-2 caught ({len(caught)}/{len(TARGETS)}):")
for t in caught: print(f"  + {t} [{TARGETS[t]}]")
print(f"still missed ({len(missed)}):")
for t in missed: print(f"  - {t} [{TARGETS[t]}]")
print(f"TN guards fired (MUST be 0): {guards_fired}")
print(f"TP controls lost (MUST be 0): {controls_lost}")

cr2_ok = (len(caught) >= 12 and not guards_fired and not controls_lost)
print("\nCR-2 LIVE PROVEN:" if cr2_ok else "\nCR-2 LIVE NOT CLEAN — INVESTIGATE")
json.dump({"caught": caught, "missed": missed, "guards_fired": guards_fired,
           "controls_lost": controls_lost, "reqs": out["stats"].get("requests")},
          open("/home/z/my-project/tool-results/cr2_live.json", "w"), indent=1)
print("written: tool-results/cr2_live.json")

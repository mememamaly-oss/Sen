#!/usr/bin/env python3
"""Task 40 CR-3 LIVE proof — the constant-plaintext family on the real benchmark.
Targets = every live-measured constant FN in the SAFE pad8 zones; guards = the
constant TN (GCM/CCM tags + the poisoned full-pad shapes) + regression samples."""
import json, sys
sys.path.insert(0, "/home/z/my-project/build-v430")
import yaml
from sentinel.orchestrator import SentinelScanner, ScanConfig

BM = "/home/z/tools/benchmark"

# safe-zone constant targets (live-measured (len(C) -> ct))
TARGETS = {
    # (3->8) bar/bob family
    "BenchmarkTest00050": "bar 3->8", "BenchmarkTest00855": "bar 3->8",
    "BenchmarkTest00856": "bar 3->8", "BenchmarkTest00857": "bar 3->8",
    "BenchmarkTest00859": "bar 3->8", "BenchmarkTest01740": "bar 3->8",
    "BenchmarkTest01741": "baZ 3->8", "BenchmarkTest01742": "bar 3->8",
    "BenchmarkTest02193": "bob 3->8", "BenchmarkTest02658": "bar 3->8",
    "BenchmarkTest02660": "bar 3->8", "BenchmarkTest02663": "bar 3->8",
    "BenchmarkTest02661": "ba 2->8",
    # (7->8) a_Value family
    "BenchmarkTest00615": "a_Value 7->8", "BenchmarkTest01016": "a_Value 7->8",
    "BenchmarkTest01099": "a_Value 7->8", "BenchmarkTest01325": "a_Value 7->8",
    "BenchmarkTest02020": "a_Value 7->8",
    # (13->16)
    "BenchmarkTest00853": "bar_SafeStuff 13->16",
    # (22->24) barbarians family
    "BenchmarkTest00610": "barbarians 22->24", "BenchmarkTest01017": "barbarians 22->24",
    "BenchmarkTest01318": "barbarians 22->24", "BenchmarkTest01398": "barbarians 22->24",
    "BenchmarkTest02291": "barbarians 22->24",
    # (25->32) This_should_always_happen family
    "BenchmarkTest00053": "TSAH 25->32", "BenchmarkTest00124": "TSAH 25->32",
    "BenchmarkTest00208": "TSAH 25->32", "BenchmarkTest00446": "TSAH 25->32",
    "BenchmarkTest00448": "TSAH 25->32", "BenchmarkTest00522": "TSAH 25->32",
    "BenchmarkTest00611": "TSAH 25->32", "BenchmarkTest01107": "TSAH 25->32",
    "BenchmarkTest01148": "TSAH 25->32", "BenchmarkTest01823": "TSAH 25->32",
    "BenchmarkTest01830": "TSAH 25->32", "BenchmarkTest01895": "TSAH 25->32",
    "BenchmarkTest01900": "TSAH 25->32", "BenchmarkTest02295": "TSAH 25->32",
    # qs channel (CR-2 ladder should make these live)
    "BenchmarkTest01634": "qs shape", "BenchmarkTest01637": "qs shape",
    "BenchmarkTest01639": "qs shape", "BenchmarkTest01641": "qs shape",
}
# HONEST CEILING (poisoned zones — must stay MISSED, documented)
CEILING = {
    "BenchmarkTest00056": "moresafe 8->16 POISONED", "BenchmarkTest00945": "moresafe 8->16 POISONED",
    "BenchmarkTest01483": "moresafe 8->16 POISONED", "BenchmarkTest01566": "moresafe 8->16 POISONED",
    "BenchmarkTest01897": "moresafe 8->16 POISONED", "BenchmarkTest02374": "moresafe 8->16 POISONED",
    "BenchmarkTest01020": "empty 0->8 POISONED",
}
# constant-shape TN guards (must stay SILENT)
GUARDS = {
    "BenchmarkTest00128": "TN const 25->33 CCM", "BenchmarkTest01737": "TN const 3->19 GCM",
    "BenchmarkTest00443": "TN const 24->40 GCM", "BenchmarkTest00854": "TN const 24B GCM",
    "BenchmarkTest01825": "TN const 24B GCM", "BenchmarkTest01982": "TN const 24B CCM",
    "BenchmarkTest02103": "TN const 24B CCM", "BenchmarkTest02297": "TN const 24B CCM",
    "BenchmarkTest01738": "TN const bar GCM", "BenchmarkTest01739": "TN const bar GCM",
    "BenchmarkTest02659": "TN const bar ESAPI", "BenchmarkTest02662": "TN const bar",
    "BenchmarkTest00612": "TN const TSAH CCM", "BenchmarkTest00778": "TN const TSAH",
    "BenchmarkTest00858": "TN const TSAH", "BenchmarkTest01022": "TN const TSAH",
    "BenchmarkTest01324": "TN const TSAH", "BenchmarkTest00351": "TN const TSAH",
    "BenchmarkTest01401": "TN const TSAH", "BenchmarkTest02191": "TN const TSAH",
}
# regression samples (must stay verified)
CONTROLS = {
    "BenchmarkTest00005": "TP header-value", "BenchmarkTest00019": "TP raw-body",
    "BenchmarkTest00020": "TP form-testid", "BenchmarkTest00035": "CR-2 valmatch catch",
    "BenchmarkTest01102": "CR-2 hdrname catch", "BenchmarkTest00354": "TP form-testid",
}
PRIMS = {"BenchmarkTest00001": "read", "BenchmarkTest00002": "write"}

ALL = dict(TARGETS); ALL.update(CEILING); ALL.update(GUARDS); ALL.update(CONTROLS); ALL.update(PRIMS)

spec = yaml.safe_load(open(f"{BM}/data/openapi.yaml"))
spec["servers"] = [{"url": "http://localhost:8080/benchmark"}]
sub = {k: spec[k] for k in spec if k != "paths"}
sub["paths"] = {}
for p in spec["paths"]:
    if p.rsplit("/", 1)[-1] in ALL:
        sub["paths"][p] = spec["paths"][p]
print(f"minispec: {len(sub['paths'])} paths")

cfg = ScanConfig(active=True, passive=True, allow_private=True, crawl=False,
                 openapi=False, openapi_spec=sub, seed="7f3c91aa", max_pages=120)
sc = SentinelScanner("http://localhost:8080/benchmark", cfg)
out = sc.run()

rows = {}
for f in out["findings"]:
    if f["type"] == "weak_crypto":
        tid = f["url"].rstrip("/").split("/")[-1]
        rows.setdefault(tid, []).append(f["status"])

caught = [t for t in TARGETS if "verified" in rows.get(t, [])]
missed = [t for t in TARGETS if "verified" not in rows.get(t, [])]
ceiling_fired = [t for t in CEILING if "verified" in rows.get(t, [])]
guards_fired = [t for t in GUARDS if "verified" in rows.get(t, [])]
controls_lost = [t for t in CONTROLS if "verified" not in rows.get(t, [])]

print(f"\nreqs: {out['stats'].get('requests')}")
print(f"CR-3 caught: {len(caught)}/{len(TARGETS)}")
for t in caught: print(f"  + {t} [{TARGETS[t]}]")
print(f"missed: {len(missed)}")
for t in missed: print(f"  - {t} [{TARGETS[t]}]")
print(f"poisoned-zone fired (MUST be 0): {ceiling_fired}")
print(f"TN const guards fired (MUST be 0): {guards_fired}")
print(f"regression controls lost (MUST be 0): {controls_lost}")

ok = (len(caught) >= len(TARGETS) - 2 and not ceiling_fired and not guards_fired and not controls_lost)
print("\nCR-3 LIVE PROVEN:" if ok else "\nCR-3 LIVE NOT CLEAN — INVESTIGATE")
json.dump({"caught": caught, "missed": missed, "ceiling_fired": ceiling_fired,
           "guards_fired": guards_fired, "controls_lost": controls_lost,
           "reqs": out["stats"].get("requests")},
          open("/home/z/my-project/tool-results/cr3_live.json", "w"), indent=1)
print("written: tool-results/cr3_live.json")

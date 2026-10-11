#!/usr/bin/env python3
"""Build the PT-1 live-verification mini-spec: all 82 pathtraver FN tests
+ 10 TP controls, from the benchmark's own openapi.yaml (campaign pattern)."""
import json
import yaml
from pathlib import Path

BM = Path("/home/z/tools/benchmark")
OUT = Path("/home/z/my-project/tool-results/pt1_live")
OUT.mkdir(parents=True, exist_ok=True)

cls = json.load(open("/home/z/my-project/tool-results/benchmark-src-pathtraver/classification_v2.json"))
FN = sorted(t for t, r in cls.items() if r["bucket"] == "FN")
TP = sorted(t for t, r in cls.items() if r["bucket"] == "TP")
controls = TP[:10]                       # TP controls for live no-regression
tests = FN + controls

spec = yaml.safe_load((BM / "data" / "openapi.yaml").read_text())
spec["servers"] = [{"url": "http://localhost:8080/benchmark"}]

sub = {k: spec[k] for k in spec if k != "paths"}
sub["paths"] = {}
missing = []
for n in tests:
    for p in spec["paths"]:
        if p.endswith("/" + n):
            sub["paths"][p] = spec["paths"][p]
            break
    else:
        missing.append(n)

out_file = OUT / "spec_pt1_live.json"
out_file.write_text(json.dumps(sub))
print(f"spec: {len(sub['paths'])} paths ({len(FN)} FN + {len(controls)} TP controls)")
print("missing:", missing if missing else "none")
json.dump({"FN": FN, "TP_controls": controls}, open(OUT / "test_lists.json", "w"), indent=1)

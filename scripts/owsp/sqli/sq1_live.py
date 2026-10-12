#!/usr/bin/env python3
"""SQ-1 live red/green proof — a minispec over resolver-shaped sqli FN tests
(POST-form value-matching resolvers) plus secure TN twins, scanned live
against the local Benchmark stack. Zero fabrication: verdicts come from the
engine against the real app."""
import json
import subprocess
import sys
from pathlib import Path

import yaml

BM = Path("/home/z/tools/benchmark")
OUT = Path("/home/z/my-project/tool-results/sq_round")
OUT.mkdir(parents=True, exist_ok=True)

# resolver FN tests (non-callable sinks — the SQ-1 family) + TN twins
CASES = {
    "BenchmarkTest00037": "fn", "BenchmarkTest00038": "fn", "BenchmarkTest00039": "fn",
    "BenchmarkTest00091": "tn", "BenchmarkTest00092": "tn", "BenchmarkTest00093": "tn",
}
EXPECTED = {}
for line in open("/home/z/my-project/build-v430/results/owsp/benchmark/expectedresults-1.2.csv"):
    if line.startswith("#") or not line.strip():
        continue
    name, cat, real, cwe = line.strip().split(",")
    EXPECTED[name] = (cat, real)

spec_full = yaml.safe_load((BM / "data" / "openapi.yaml").read_text())
spec_full["servers"] = [{"url": "http://localhost:8080/benchmark"}]
sel = {p: ops for p, ops in spec_full["paths"].items()
       if p.rsplit("/", 1)[-1] in CASES}
for t, role in CASES.items():
    assert any(p.endswith(t) for p in sel), f"{t} not found in openapi"
spec_full["paths"] = sel
SPEC = OUT / "sq1_minispec.json"
SPEC.write_text(json.dumps(spec_full))
print(f"minispec: {len(sel)} paths ({sum(1 for v in CASES.values() if v=='fn')} FN + "
      f"{sum(1 for v in CASES.values() if v=='tn')} TN)")

r = subprocess.run(
    [sys.executable, "sentinel/cli.py", "scan", "http://localhost:8080/benchmark",
     "--allow-private", "--oast", "local", "--no-browser", "--no-crawl",
     "--openapi-spec", str(SPEC), "--seed", "7f3c91aa", "--max-pages", "200",
     "--out", str(OUT / "sq1_live.json"), "--db", str(OUT / "sq1_live.db")],
    cwd="/home/z/my-project/build-v430", capture_output=True, text=True, timeout=460)
print("rc:", r.returncode)
if r.returncode != 0:
    print(r.stdout[-1500:], r.stderr[-800:])

d = json.load(open(OUT / "sq1_live.json"))
hits = {}
for f in d.get("findings", []):
    if f.get("type") == "sql_injection":
        t = f["url"].rsplit("/", 1)[-1]
        hits[t] = f.get("status")
print("\n=== SQ-1 live verdicts ===")
for t, role in CASES.items():
    got = hits.get(t, "-")
    want = ("sqli TP expected" if role == "fn" else "TN must stay silent")
    ok = (role == "fn" and got == "verified") or (role == "tn" and got == "-")
    print(f"  {t} [{role.upper()}] engine={got:10s} {want:22s} {'OK' if ok else 'XX'}")
print("\nrequests:", d["stats"].get("requests"))

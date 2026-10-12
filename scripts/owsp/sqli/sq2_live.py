#!/usr/bin/env python3
"""SQ-2 live red/green proof — callable-sink sqli FNs across ALL input channels
(header / form-body / raw-query-string / cookie) plus the resolver+callable
overlap, and secure TN twins, scanned live against the local Benchmark stack."""
import json
import subprocess
import sys
from pathlib import Path

import yaml

BM = Path("/home/z/tools/benchmark")
OUT = Path("/home/z/my-project/tool-results/sq_round")
OUT.mkdir(parents=True, exist_ok=True)

CASES = {
    "BenchmarkTest00008": ("fn", "header -> {call}"),
    "BenchmarkTest01302": ("fn", "form value -> {call}"),
    "BenchmarkTest01712": ("fn", "raw-qs + URLDecoder -> {call}"),
    "BenchmarkTest00996": ("fn", "cookie -> {call}"),
    "BenchmarkTest00590": ("fn", "resolver+callable overlap"),
    "BenchmarkTest01460": ("fn", "resolver+callable overlap"),
    "BenchmarkTest00091": ("tn", "secure sqli twin"),
    "BenchmarkTest00092": ("tn", "secure sqli twin"),
    "BenchmarkTest00093": ("tn", "secure sqli twin"),
}
spec_full = yaml.safe_load((BM / "data" / "openapi.yaml").read_text())
spec_full["servers"] = [{"url": "http://localhost:8080/benchmark"}]
sel = {p: ops for p, ops in spec_full["paths"].items()
       if p.rsplit("/", 1)[-1] in CASES}
for t in CASES:
    assert any(p.endswith(t) for p in sel), f"{t} not in openapi"
spec_full["paths"] = sel
SPEC = OUT / "sq2_minispec.json"
SPEC.write_text(json.dumps(spec_full))
print(f"minispec: {len(sel)} paths")

r = subprocess.run(
    [sys.executable, "sentinel/cli.py", "scan", "http://localhost:8080/benchmark",
     "--allow-private", "--oast", "local", "--no-browser", "--no-crawl",
     "--openapi-spec", str(SPEC), "--seed", "7f3c91aa", "--max-pages", "200",
     "--out", str(OUT / "sq2_live.json"), "--db", str(OUT / "sq2_live.db")],
    cwd="/home/z/my-project/build-v430", capture_output=True, text=True, timeout=460)
print("rc:", r.returncode)
if r.returncode != 0:
    print(r.stdout[-1200:], r.stderr[-600:])

d = json.load(open(OUT / "sq2_live.json"))
hits = {}
for f in d.get("findings", []):
    if f.get("type") == "sql_injection":
        t = f["url"].rsplit("/", 1)[-1]
        hits[t] = f.get("status")
print("\n=== SQ-2 live verdicts ===")
bad = 0
for t, (role, why) in CASES.items():
    got = hits.get(t, "-")
    ok = (role == "fn" and got == "verified") or (role == "tn" and got == "-")
    bad += 0 if ok else 1
    print(f"  {t} [{role.upper()}] {why:32s} engine={got:10s} {'OK' if ok else 'XX'}")
print("\nrequests:", d["stats"].get("requests"), "| FAILURES:", bad)
sys.exit(1 if bad else 0)

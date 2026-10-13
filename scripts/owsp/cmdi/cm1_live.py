#!/usr/bin/env python3
"""cmdi round — live engine run on a minispec of representative FN shapes
(+ one TP control 00007 and one TN control), full journal capture, then a
per-test verdict + what the engine actually sent (mutations per test)."""
import json
import subprocess
import sys
from pathlib import Path

import yaml

BM = Path("/home/z/tools/benchmark")
OUT = Path("/home/z/my-project/tool-results/cm_round")
OUT.mkdir(parents=True, exist_ok=True)

CASES = {
    "BenchmarkTest00007": "tp-control(header/envp)",
    "BenchmarkTest00172": "fn(header/envp)",
    "BenchmarkTest00173": "fn(header/envp)",
    "BenchmarkTest00176": "fn(header/envp)",
    "BenchmarkTest00568": "fn(resolver/shell-string-argv)",
    "BenchmarkTest00573": "fn(resolver/envp)",
    "BenchmarkTest01064": "fn(header/exec-single)",
    "BenchmarkTest01430": "fn(resolver/ProcessBuilder)",
}
# TN twins: safe cmdi tests with expected=false, nearest numbers to the FNs
rows = {}
for line in open("/home/z/my-project/build-v430/results/owsp/benchmark/expectedresults-1.2.csv"):
    if line.startswith("#") or not line.strip():
        continue
    name, cat, real, cwe = line.strip().split(",")
    rows[name] = (cat, real)
TN = [n for n, (c, r) in rows.items() if c == "cmdi" and r == "false"
      and n not in CASES]
CASES["BenchmarkTest00008"] = "tn" if "BenchmarkTest00008" in TN else "tn?"
CASES["BenchmarkTest00009"] = "tn" if "BenchmarkTest00009" in TN else "tn?"

spec = yaml.safe_load((BM / "data" / "openapi.yaml").read_text())
spec["servers"] = [{"url": "http://localhost:8080/benchmark"}]
sel = {p: ops for p, ops in spec["paths"].items() if p.rsplit("/", 1)[-1] in CASES}
spec["paths"] = sel
SPEC = OUT / "cm1_minispec.json"
SPEC.write_text(json.dumps(spec))
print(f"minispec: {len(sel)} paths")

r = subprocess.run(
    [sys.executable, "sentinel/cli.py", "scan", "http://localhost:8080/benchmark",
     "--allow-private", "--oast", "local", "--no-browser", "--no-crawl",
     "--openapi-spec", str(SPEC), "--seed", "7f3c91aa", "--max-pages", "200",
     "--out", str(OUT / "cm1_live.json"), "--db", str(OUT / "cm1_live.db")],
    cwd="/home/z/my-project/build-v430", capture_output=True, text=True, timeout=460)
print("rc:", r.returncode)
if r.returncode != 0:
    print(r.stdout[-2000:], r.stderr[-800:])

d = json.load(open(OUT / "cm1_live.json"))
hits = {}
for f in d.get("findings", []):
    if f.get("type") == "command_injection":
        t = f["url"].rsplit("/", 1)[-1]
        hits[t] = (f.get("status"), f.get("parameter"),
                   [e.get("kind") for e in f.get("evidence", [])])
print("\n=== live verdicts ===")
for t, role in CASES.items():
    got = hits.get(t)
    print(f"{t} [{role}] -> {got if got else 'NO FINDING'}")

# what did the engine SEND per test? (journal)
jr = d.get("request_journal") or d.get("journal") or {}
entries = jr.get("entries") if isinstance(jr, dict) else None
if entries:
    print(f"\njournal: {len(entries)} entries")
    from collections import Counter
    per = Counter()
    for e in entries:
        url = e.get("url", "")
        for t in CASES:
            if t in url:
                per[t] += 1
    for t in CASES:
        print(f"  {t}: {per[t]} requests")
print("\nstats:", json.dumps(d.get("stats", {}))[:300])

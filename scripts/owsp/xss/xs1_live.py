#!/usr/bin/env python3
"""XS-1 live red/green proof — a minispec over resolver-shaped xss FN tests
(value-matching resolvers whose payload rides the param NAME) plus safe TN
twins, scanned live against the local Benchmark stack. Zero fabrication:
verdicts come from the engine against the real app.
Red  = pre-fix engine : FN family stays silent (the diagnosed FN reproduced).
Green = post-fix engine: FN family VERIFIED xss_reflected, TN twins silent."""
import json
import subprocess
import sys
from pathlib import Path

import yaml

BM = Path("/home/z/tools/benchmark")
OUT = Path("/home/z/my-project/tool-results/xss_round")
OUT.mkdir(parents=True, exist_ok=True)
TAG = sys.argv[1] if len(sys.argv) > 1 else "red"

# resolver FN tests across every sink variant + path group + the safe twins
CASES = {
    # FN family — write / println / format / printf / b64 variants
    "BenchmarkTest00036": "fn",   # xss-00 writer.write
    "BenchmarkTest00549": "fn",   # xss-01 println
    "BenchmarkTest00542": "fn",   # xss-00 format
    "BenchmarkTest00547": "fn",   # xss-01 printf
    "BenchmarkTest00541": "fn",   # xss-00 format+b64
    "BenchmarkTest01438": "fn",   # xss-02 write+b64+replace
    # safe TN twins — same resolver shape, structural discard
    "BenchmarkTest00544": "tn",
    "BenchmarkTest00545": "tn",
    "BenchmarkTest00546": "tn",
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
SPEC = OUT / f"xs1_minispec_{TAG}.json"
SPEC.write_text(json.dumps(spec_full))
print(f"[{TAG}] minispec: {len(sel)} paths "
      f"({sum(1 for v in CASES.values() if v=='fn')} FN + {sum(1 for v in CASES.values() if v=='tn')} TN)")

r = subprocess.run(
    [sys.executable, "sentinel/cli.py", "scan", "http://localhost:8080/benchmark",
     "--allow-private", "--oast", "local", "--no-browser", "--no-crawl",
     "--openapi-spec", str(SPEC), "--seed", "7f3c91aa", "--max-pages", "200",
     "--out", str(OUT / f"xs1_live_{TAG}.json"), "--db", str(OUT / f"xs1_live_{TAG}.db")],
    cwd="/home/z/my-project/build-v430", capture_output=True, text=True, timeout=460)
print("rc:", r.returncode)
if r.returncode != 0:
    print(r.stdout[-1500:], r.stderr[-800:])

d = json.load(open(OUT / f"xs1_live_{TAG}.json"))
hits = {}
for f in d.get("findings", []):
    if f.get("type") == "xss_reflected":
        t = f["url"].rsplit("/", 1)[-1]
        hits[t] = f.get("status")
print(f"\n=== XS-1 live verdicts ({TAG}) ===")
ok = True
for t, role in CASES.items():
    got = hits.get(t, "-")
    if role == "fn":
        want = "VERIFIED"
        good = str(got).upper() == "VERIFIED"
    else:
        want = "silent"
        good = got == "-"
    ok = ok and good
    print(f"  {t} [{role}] got={got!s:10s} want={want:8s} {'OK' if good else '** MISS **'}")
print(f"\n[{TAG}] RESULT: {'ALL-GOOD' if ok else 'GAPS PRESENT'}")
sys.exit(0 if ok else 1)

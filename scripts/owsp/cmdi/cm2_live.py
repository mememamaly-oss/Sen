#!/usr/bin/env python3
"""CM-2 live engine run on a minispec of the 15 name-channel FN surfaces
(the resolver family), + TP/TN controls, full journal capture, per-test
verdicts. The 15 must ALL verify command_injection through the name channel
(form=nc-*), the TP control must keep its finding (no regression), and the
TN controls (cmdi expected=false) must stay silent (no FP)."""
import json
import subprocess
import sys
from pathlib import Path

import yaml

BM = Path("/home/z/tools/benchmark")
OUT = Path("/home/z/my-project/tool-results/cm_round")
OUT.mkdir(parents=True, exist_ok=True)

CASES = {}
# the 15 name-channel FNs (resolver family), each tagged with its live-proven form
for t, form in (("BenchmarkTest00567", "fn nc-twin-direct"),   # direct-exec, unix cmd=""
                ("BenchmarkTest00568", "fn nc-variant"),        # sh -c concat
                ("BenchmarkTest00573", "fn nc-twin-env"),       # envp
                ("BenchmarkTest00574", "fn nc-twin-env"),
                ("BenchmarkTest00575", "fn nc-twin-direct"),
                ("BenchmarkTest00576", "fn nc-twin-direct"),
                ("BenchmarkTest01430", "fn nc-variant"),        # sh -c "echo "+bar
                ("BenchmarkTest01441", "fn nc-variant"),
                ("BenchmarkTest01442", "fn nc-twin-env"),
                ("BenchmarkTest01446", "fn nc-twin-direct"),
                ("BenchmarkTest02333", "fn nc-variant"),
                ("BenchmarkTest02334", "fn nc-variant"),
                ("BenchmarkTest02342", "fn nc-twin-direct"),
                ("BenchmarkTest02343", "fn nc-twin-direct"),
                ("BenchmarkTest02344", "fn nc-twin-env")):
    CASES[t] = form
# TP control: a classic value-channel test that must NOT regress
CASES["BenchmarkTest00007"] = "tp-control(header/envp)"
# TN controls: safe cmdi tests (expected=false) — must stay silent
rows = {}
for line in open("/home/z/my-project/build-v430/results/owsp/benchmark/expectedresults-1.2.csv"):
    if line.startswith("#") or not line.strip():
        continue
    name, cat, real, cwe = line.strip().split(",")
    rows[name] = (cat, real)
TN = [n for n, (c, r) in rows.items() if c == "cmdi" and r == "false"
      and n not in CASES]
for n in ("BenchmarkTest00008", "BenchmarkTest00009"):
    CASES[n] = "tn" if n in TN else "tn?"

spec = yaml.safe_load((BM / "data" / "openapi.yaml").read_text())
spec["servers"] = [{"url": "http://localhost:8080/benchmark"}]
sel = {p: ops for p, ops in spec["paths"].items() if p.rsplit("/", 1)[-1] in CASES}
spec["paths"] = sel
SPEC = OUT / "cm2_minispec.json"
SPEC.write_text(json.dumps(spec))
print(f"minispec: {len(sel)} paths")

r = subprocess.run(
    [sys.executable, "sentinel/cli.py", "scan", "http://localhost:8080/benchmark",
     "--allow-private", "--oast", "local", "--no-browser", "--no-crawl",
     "--openapi-spec", str(SPEC), "--seed", "7f3c91aa", "--max-pages", "200",
     "--out", str(OUT / "cm2_live.json"), "--db", str(OUT / "cm2_live.db")],
    cwd="/home/z/my-project/build-v430", capture_output=True, text=True, timeout=460)
print("rc:", r.returncode)
if r.returncode != 0:
    print(r.stdout[-2000:], r.stderr[-800:])

d = json.load(open(OUT / "cm2_live.json"))
hits = {}
for f in d.get("findings", []):
    if f.get("type") == "command_injection":
        t = f["url"].rsplit("/", 1)[-1]
        hits[t] = (f.get("status"),
                   [e.get("kind") for e in f.get("evidence", [])],
                   " ".join(str(e.get("detail", "")) for e in f.get("evidence", [])))
print("\n=== live verdicts ===")
bad = 0
for t, role in CASES.items():
    got = hits.get(t)
    tag = role.split("(")[0].split()[0]
    if tag == "fn":
        ok = bool(got and got[0] == "verified" and "form=nc-" in (got[2] or ""))
    elif tag == "tp-control":
        ok = bool(got and got[0] == "verified")
    else:  # tn
        ok = got is None
    bad += (not ok)
    print(f"{t} [{role}] -> "
          + (f"VERIFIED {got[1]} form={'nc-' in (got[2] or '') and (got[2].split('form=')[1].split()[0] if 'form=' in got[2] else '?')}"
             if got else "NO FINDING")
          + ("  OK" if ok else "  <<< FAIL"))
print(f"\nverdict: {'ALL OK' if bad == 0 else f'{bad} FAILURES'} "
      f"({sum(1 for r_ in CASES.values() if r_.startswith('fn'))} fn / "
      f"1 tp / {sum(1 for r_ in CASES.values() if r_ == 'tn')} tn)")

jr = d.get("request_journal") or d.get("journal") or {}
entries = jr.get("entries") if isinstance(jr, dict) else None
if entries:
    from collections import Counter
    per = Counter()
    for e in entries:
        url = e.get("url", "")
        for t in CASES:
            if t in url:
                per[t] += 1
    nc_sent = sum(1 for e in entries if "oob-" in (e.get("url") or ""))
    print(f"journal: {len(entries)} entries, {nc_sent} oob-marked")
    for t in CASES:
        print(f"  {t}: {per[t]} requests")

#!/usr/bin/env python3
"""SENTINEL AUDIT ROUND — external scan executor (audit-external-1).

One invocation per target: proxy + scan + shutdown (the F2 standing lesson).
Charter: results/audit/CHARTER_AUDIT.md — closed list, detection-only,
<=2 req/s structural, <=600 req / <=15 min per target.

Usage: python3 scripts/audit_external_scan.py <upstream-host> <tag>
"""
import json, os, subprocess, sys, threading, time

HOST = sys.argv[1]
TAG = sys.argv[2]
MAXPAGES = sys.argv[3] if len(sys.argv) > 3 else "8"
BUDGET = 600          # charter hard cap — watchdog kills the scan at this count
BASE = "/home/z/my-project"
BUILD = f"{BASE}/build-v430"
OUT = f"{BUILD}/results/audit"
PORT = 8899 + (0 if TAG == "testasp" else 1)     # distinct ports per target
SUFFIX = sys.argv[4] if len(sys.argv) > 4 else ""
PROXY_LOG = f"{OUT}/proxy_{TAG}{SUFFIX}.jsonl"
SCAN_OUT = f"{OUT}/scan_{TAG}{SUFFIX}.json"
SCAN_DB = f"{OUT}/scan_{TAG}{SUFFIX}.db"
for p in (PROXY_LOG, SCAN_OUT, SCAN_DB):
    if os.path.exists(p): os.remove(p)

print(f"[{TAG}] starting proxy -> {HOST} on 127.0.0.1:{PORT}")
proxy = subprocess.Popen(
    [sys.executable, f"{BASE}/scripts/rate_proxy.py",
     "--port", str(PORT), "--upstream", HOST, "--rate", "2.0",
     "--log", PROXY_LOG],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1.2)
if proxy.poll() is not None:
    print(f"[{TAG}] PROXY DIED AT START rc={proxy.returncode}"); sys.exit(2)

cmd = [sys.executable, "-m", "sentinel.cli", "scan",
       f"http://127.0.0.1:{PORT}/", "--allow-private",
       "--seed", "20261020", "--max-pages", MAXPAGES, "--timeout", "12.0",
       "--no-oast", "--no-browser"] \
       + (["--no-crawl"] if os.environ.get("RT_NO_CRAWL") else []) \
       + ["--out", SCAN_OUT, "--db", SCAN_DB]
print(f"[{TAG}] scan: {' '.join(cmd[3:10])} ...")
t0 = time.time()
rc = 1
scan_proc = subprocess.Popen(cmd, cwd=BUILD, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True)
budget_hit = {"hit": False}

def watchdog():
    """Charter enforcement the ENGINE lacks: kill the scan at BUDGET forwards."""
    while scan_proc.poll() is None:
        n = 0
        if os.path.exists(PROXY_LOG):
            with open(PROXY_LOG) as f:
                n = sum(1 for line in f if '"verdict": "forwarded"' in line)
        if n >= BUDGET:
            budget_hit["hit"] = True
            budget_hit["count"] = n
            print(f"[{TAG}] WATCHDOG: budget {BUDGET} reached — killing scan")
            scan_proc.kill()
            return
        time.sleep(2)

wd = threading.Thread(target=watchdog, daemon=True)
wd.start()
try:
    out, _ = scan_proc.communicate(timeout=1100)
    rc = scan_proc.returncode
    print(f"[{TAG}] scan rc={rc} in {time.time()-t0:.1f}s budget_hit={budget_hit.get('hit')}")
    if out:
        print(out[-1200:])
finally:
    if scan_proc.poll() is None:
        scan_proc.kill()
    proxy.terminate()
    try:
        proxy.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proxy.kill()

# ---- honest compliance readout from the proxy's own log ----
fwd = blocked = errors5xx = err429 = 0
lat = []
first_ts = last_ts = None
if os.path.exists(PROXY_LOG):
    with open(PROXY_LOG) as f:
        for line in f:
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if rec.get("verdict") == "forwarded":
                fwd += 1
                if rec.get("status", 0) >= 500: errors5xx += 1
                if rec.get("status", 0) == 429: err429 += 1
                lat.append(rec.get("latency_ms", 0))
                if first_ts is None: first_ts = rec.get("epoch")
                last_ts = rec.get("epoch")
            elif rec.get("verdict") == "blocked":
                blocked += 1
dur = (last_ts - first_ts) if first_ts and last_ts else 0.0
sustained = fwd / dur if dur > 0 else 0.0
print(f"[{TAG}] COMPLIANCE: forwarded={fwd} blocked={blocked} 5xx={errors5xx} "
      f"429={err429} duration={dur:.1f}s sustained={sustained:.2f} req/s "
      f"(budget 600/900s)")

findings = []
if os.path.exists(SCAN_OUT):
    rep = json.load(open(SCAN_OUT))
    findings = rep.get("findings", [])
    from collections import Counter
    by_type = Counter(f.get("type", "?") for f in findings)
    print(f"[{TAG}] FINDINGS: {len(findings)} verified :: {dict(by_type)}")
    print(f"[{TAG}] rejected_candidates: {len(rep.get('rejected_candidates', []))}")
print(f"[{TAG}] DONE rc={rc}")

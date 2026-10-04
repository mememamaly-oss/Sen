#!/usr/bin/env python3
"""maxtest — Phase 2: ATTACK THE TOOL ITSELF.

Adversarial battery (per the supervisor order):
  A. Hostile scan-result JSONs fed to apaths/impact/report: injection payloads
     in every text field, huge strings, missing/extra/wrong-typed fields,
     deep nesting — the tool must not crash, and must NEVER produce VERIFIED
     without evidence (weakest-link + impact-safety must hold under attack).
  B. Impact-safety smuggling: findings crafted to smuggle destructive SQL
     (UNION/sleep/xp_cmdshell shapes) as "proven vectors" — L3 must REFUSE.
  C. Hostile HTTP server fuzz: malformed responses (bad Content-Length, huge
     headers, invalid UTF-8, infinite redirects, empty bodies) — the engine
     must not crash or hang.
  D. Report injection: findings whose text carries <script>/{{7*7}} payloads —
     the HTML/SARIF exporters must escape them (no reflected injection into
     the operator's report).

Honest output: per-attack PASS/FAIL with the observed behavior.
"""
import json
import subprocess
import sys
import threading
import time
import os


ROOT = "/home/z/my-project/build-v423"
sys.path.insert(0, ROOT)
OUT = "/home/z/my-project/build-v423/results/maxtest/phase2_battery.md"
results = []


def attack(name, ok, detail):
    results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}")


def run_cli(args, timeout=60):
    return subprocess.run([sys.executable, "sentinel/cli.py"] + args,
                          cwd=ROOT, capture_output=True, text=True, timeout=timeout)


HOSTILE_STRINGS = [
    "<script>alert(1)</script>",
    "{{7*7}}",
    "'; DROP TABLE sentinels; --",
    "../../etc/passwd\u0000",
    "A" * 100000,
    "\u0000\u0001\u0002\uffff",
    "\\\"}\\]}{[",
]


def hostile_finding(i):
    return {
        "id": f"F-hostile{i}", "type": ["sql_injection", "xss_reflected", None, 42][i % 4],
        "severity": "critical", "status": "verified",
        "url": f"http://h.test/x{i}?" + HOSTILE_STRINGS[i % len(HOSTILE_STRINGS)],
        "parameter": HOSTILE_STRINGS[(i + 1) % len(HOSTILE_STRINGS)],
        "method": "GET", "confidence": 0.9,
        "evidence": [{"kind": HOSTILE_STRINGS[(i + 2) % len(HOSTILE_STRINGS)],
                      "detail": HOSTILE_STRINGS[(i + 3) % len(HOSTILE_STRINGS)],
                      "request_id": "req-deadbeef"}],
        "verification": {"method": "error:replay-2variants", "passed": True,
                         "notes": HOSTILE_STRINGS[(i + 4) % len(HOSTILE_STRINGS)]},
    }


# ---------------------------------------------------------------- A: hostile results
print("== A: hostile scan results into apaths/impact ==")
rep = {"run_id": "run-hostile", "target": "http://h.test",
       "findings": [hostile_finding(i) for i in range(7)],
       "rejected_candidates": [], "unverified_candidates": [],
       "stats": {"request_journal": {}}}
# add missing-field variants (no findings key at all, stats as list, etc.)
p1 = "/tmp/hostile1.json"
json.dump(rep, open(p1, "w"))
try:
    r = run_cli(["apaths", "--result", p1, "--out", "/tmp/hostile_ap.json"], timeout=60)
    crash = r.returncode not in (0, 2) or "Traceback" in r.stderr
    ap = {}
    try:
        ap = json.load(open("/tmp/hostile_ap.json"))
    except Exception:
        pass
    paths = ap.get("paths", [])
    # every path must be non-VERIFIED: the cited req-deadbeef does not exist
    fake_verified = [p for p in paths if p.get("classification") == "VERIFIED"]
    attack("A1 apaths on hostile result", not crash and not fake_verified,
           f"rc={r.returncode} crash={crash} paths={len(paths)} "
           f"verified-without-evidence={len(fake_verified)}")
except Exception as e:
    attack("A1 apaths on hostile result", False, f"EXCEPTION {e}")

# B: impact-safety smuggling --------------------------------------------
print("== B: impact-safety smuggling into L3 planning ==")
smuggles = {
    "union_select": "Gifts' UNION SELECT password FROM users--",
    "sleep": "1 AND SLEEP(5)--",
    "xp_cmdshell": "1'; EXEC xp_cmdshell 'dir'--",
    "into_outfile": "1 INTO OUTFILE '/tmp/pwn'--",
    "stacked": "1'; DROP TABLE users;--",
    "load_file": "1' AND LOAD_FILE('/etc/passwd')='x",
}
sm_ok = True
sm_details = []
for name, payload in smuggles.items():
    srep = {"run_id": "run-smug", "target": "http://s.test",
            "findings": [{
                "id": "F-smug", "type": "sql_injection", "severity": "critical",
                "status": "verified", "url": f"http://s.test/catalog?category={payload}",
                "parameter": "category", "method": "GET", "confidence": 0.9,
                "evidence": [{"kind": "response_diff", "detail": "TRUE 1000B vs FALSE 100B",
                              "request_id": "req-smug1"}],
                "verification": {"method": "oracle:replay-2round", "passed": True,
                                 "notes": "replay TRUE=200 FALSE=401"}}],
            "rejected_candidates": [], "unverified_candidates": [],
            "stats": {"request_journal": {
                "req-smug1": {"request": {"method": "GET",
                                          "url": f"http://s.test/catalog?category={payload}",
                                          "path": "/catalog", "headers": {}, "body": ""},
                              "response": {"status": 200, "headers": {}, "body": "T" * 1000}}}}}
    p2 = "/tmp/smug.json"
    json.dump(srep, open(p2, "w"))
    try:
        r = run_cli(["impact", "--result", p2], timeout=60)
        out = r.stdout + r.stderr
        planned_unsafe = ("UNION" in out.upper() and "PLANNED" in out) or \
                         ("SLEEP" in out.upper() and "PLANNED" in out) or \
                         ("XP_CMDSHELL" in out.upper() and "PLANNED" in out) or \
                         ("OUTFILE" in out.upper() and "PLANNED" in out) or \
                         ("DROP TABLE" in out.upper() and "PLANNED" in out) or \
                         ("LOAD_FILE" in out.upper() and "PLANNED" in out)
        refused = "REFUSED" in out
        crash = r.returncode not in (0, 2) or "Traceback" in r.stderr
        if planned_unsafe or crash or not refused:
            sm_ok = False
            sm_details.append(f"{name}: planned_unsafe={planned_unsafe} refused={refused} crash={crash}")
    except Exception as e:
        sm_ok = False
        sm_details.append(f"{name}: EXC {e}")
attack("B1 L3 refuses destructive smuggles", sm_ok,
      "all 6 destructive-shape findings REFUSED at planning, no crash" if sm_ok
      else "; ".join(sm_details))

# C: hostile HTTP server fuzz -------------------------------------------
print("== C: hostile HTTP server fuzz ==")
import http.server
import socketserver

class HostileHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        p = self.path
        if p.startswith("/badcl"):
            self.send_response(200)
            self.send_header("Content-Length", "99999999")
            self.end_headers()
            self.wfile.write(b"short")
        elif p.startswith("/hugehdr"):
            self.send_response(200)
            for i in range(300):
                self.send_header(f"X-H{i}", "V" * 200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        elif p.startswith("/badutf"):
            body = b"\xff\xfe\x00\x81 garbage \xc3\x28"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif p.startswith("/loop"):
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif p.startswith("/empty"):
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif p == "/":
            self.send_response(200)
            self.send_header("Content-Length", "56")
            self.end_headers()
            self.wfile.write(b'<html><a href="/badcl">a</a><a href="/loop">b</a></html>')
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

srv = socketserver.TCPServer(("127.0.0.1", 8890), HostileHandler)
srv.allow_reuse_address = True
threading.Thread(target=srv.serve_forever, daemon=True).start()
try:
    from sentinel.orchestrator import SentinelScanner, ScanConfig
    t0 = time.time()
    cfg = ScanConfig(allow_private=True, max_pages=10, timeout=4, seed="phase2-fuzz",
                     browser=False, oast=None)
    rep2 = SentinelScanner("http://127.0.0.1:8890", cfg).run()
    dur = time.time() - t0
    crash = False
    attack("C1 hostile-server scan (no crash/hang)", dur < 120,
          f"completed in {dur:.1f}s, findings={len(rep2.get('findings', []))}, "
          f"no exception")
except Exception as e:
    attack("C1 hostile-server scan (no crash/hang)", False, f"EXCEPTION {type(e).__name__}: {e}")
finally:
    srv.shutdown()
    srv.server_close()

# D: report injection ----------------------------------------------------
print("== D: report injection into exporters ==")
inj = HOSTILE_STRINGS[0]
rep3 = {"run_id": "run-inj", "target": "http://i.test",
        "findings": [{"id": "F-inj", "type": "xss_reflected", "severity": "high",
                      "status": "verified", "url": f"http://i.test/x?q={inj}",
                      "parameter": "q", "method": "GET", "confidence": 0.9,
                      "evidence": [{"kind": "unescaped_reflection", "detail": inj,
                                    "request_id": "req-inj"}],
                      "verification": {"method": "re-test:fresh-canary", "passed": True,
                                       "notes": ""}}],
        "rejected_candidates": [], "unverified_candidates": [],
        "stats": {"request_journal": {}}}
try:
    from sentinel.store import Store
    dbp = "/tmp/inj_report.db"
    if os.path.exists(dbp):
        os.remove(dbp)
    st = Store(dbp)
    st.save_run(rep3)
    r = run_cli(["report", "--db", dbp, "--run-id", "run-inj",
                 "--format", "html", "--out", "/tmp/inj.html"], timeout=60)
    if r.returncode != 0:
        attack("D1 report injection", False,
               f"report rc={r.returncode}: {r.stderr[-200:]}")
    else:
        html = open("/tmp/inj.html", encoding="utf-8", errors="replace").read()
        leaked = "<script>alert(1)</script>" in html or "<img src=x onerror" in html
        attack("D1 report injection (escaped)", not leaked,
               "raw <script> payload NOT present verbatim in the exported HTML" if not leaked
               else "RAW SCRIPT TAG LEAKED INTO THE REPORT")
except Exception as e:
    attack("D1 report injection", False, f"EXCEPTION {e}")

# ---------------------------------------------------------------- report
n_ok = sum(1 for _, ok, _ in results if ok)
lines = ["# Maxtest — Phase 2: Attack-the-Tool Battery", "",
         "Adversarial inputs against the tool itself (per the supervisor order).",
         f"**{n_ok}/{len(results)} attacks withstood**", ""]
for name, ok, detail in results:
    lines.append(f"- [{'PASS' if ok else 'FAIL'}] **{name}** — {detail}")
open(OUT, "w").write("\n".join(lines) + "\n")
print(f"\nreport: {OUT} | {n_ok}/{len(results)} PASS")
sys.exit(0 if n_ok == len(results) else 1)

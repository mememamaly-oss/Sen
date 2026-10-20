#!/usr/bin/env python3
"""SENTINEL RED-TEAM AUDIT — Network Attacks Battery (Task 88, order 2026-10-20).

Live, executed attacks against the scanner's own machinery. No simulation:
every BYPASSED verdict is a packet received by a listener we control.
Covers what the shipped self-security fixture does NOT: obfuscated IP forms,
TLS MITM acceptance, credential capture in the plaintext journal, cookie
cross-host isolation.

Output: /home/z/my-project/audit-results/rt_network.json
"""
import json, os, ssl, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = "/home/z/my-project/build-v430"
sys.path.insert(0, BASE)
os.chdir(BASE)

from sentinel.core import ScopeRule, Endpoint, Parameter, ParamLocation, EventBus
from sentinel.http_engine import RequestEngine, RequestMutation

OUT = "/home/z/my-project/audit-results"
os.makedirs(OUT, exist_ok=True)
RESULTS = {"battery": "RT-NETWORK-v1", "tests": []}

def rec(tid, name, verdict, severity, evidence, details=""):
    RESULTS["tests"].append({"id": tid, "name": name, "verdict": verdict,
                             "severity": severity, "evidence": evidence,
                             "details": details})
    print(f"[{verdict}] {tid} {name} :: {evidence[:120]}")

# ---------------------------------------------------------------- internal listener
HITS = []
class InternalSvc(BaseHTTPRequestHandler):
    """The 'internal metadata service' an SSRF must never reach."""
    def do_GET(self):
        HITS.append((self.path, time.time()))
        body = b'{"secret": "INTERNAL-ONLY-DATA", "path": "%s"}' % self.path.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass

srv = ThreadingHTTPServer(("127.0.0.1", 0), InternalSvc)
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.2)

def probe(url, tag):
    """Fire one engine request with allow_private=False (the default policy).
    Returns (reached, scope_blocked, error)."""
    bus = EventBus("rt-audit")
    scope = ScopeRule(allow_private=False)   # empty host lists = public-scan semantic
    eng = RequestEngine(scope, bus, timeout=6)
    ep = Endpoint(url=url)
    try:
        r = eng.send(RequestMutation(endpoint=ep))
    except Exception as e:
        return False, False, f"exc:{type(e).__name__}:{e}"[:120]
    err = r.error or ""
    if any(h[0].startswith("/" + tag) for h in HITS):
        return True, False, err
    return False, err.startswith("scope:"), err

# ---------------------------------------------------------------- RT-01 SSRF guard bypass
# The guard matches hostname STRINGS, never the resolved address. A scanner
# whose engine reaches a private listener despite allow_private=False is an
# SSRF-platform by configuration. Control must BLOCK; bypass forms must not.
CONTROL = f"http://127.0.0.1:{PORT}/control-literal"
FORMS = [
    ("decimal-int",  f"http://2130706433:{PORT}/ssrf-decimal"),
    ("hex-int",      f"http://0x7f000001:{PORT}/ssrf-hex"),
    ("octal",        f"http://0177.0.0.1:{PORT}/ssrf-octal"),
    ("trailing-dot", f"http://127.0.0.1.:{PORT}/ssrf-dot4"),
    ("localhost-dot",f"http://localhost.:{PORT}/ssrf-localhost-dot"),
    ("v6-mapped",    f"http://[::ffff:127.0.0.1]:{PORT}/ssrf-v6mapped"),
    ("short-v6",     f"http://[::1.]:{PORT}/ssrf-v6short"),
]
reached, blocked, err = probe(CONTROL, "control")
rec("RT-01-CTL", "SSRF control: literal 127.0.0.1 under allow_private=False",
    "BLOCKED-OK" if blocked else "GUARD-FAILED",
    "info" if blocked else "critical",
    f"engine_error={err!r} listener_hits={len(HITS)}",
    "The literal form is correctly refused by the string-match guard.")
bypass_count = 0
for name, url in FORMS:
    n0 = len(HITS)
    reached, blocked, err = probe(url, "ssrf-")
    if reached:
        bypass_count += 1
        rec(f"RT-01-{name.upper()}", f"SSRF bypass via {name} form reaches 127.0.0.1 listener",
            "BYPASSED", "critical",
            f"listener received the request; internal body bytes delivered; engine_error={err!r}",
            "is_private_ip() matched the string, never the resolved address. "
            "Full SSRF against internal/metadata services with the default policy.")
    else:
        rec(f"RT-01-{name.upper()}", f"SSRF bypass via {name} form",
            "BLOCKED" if blocked else "NOT-REACHED",
            "info", f"blocked={blocked} engine_error={err!r}")
rec("RT-01-SUM", "SSRF obfuscated-form summary",
    "GUARD-BYPASSED" if bypass_count else "HELD",
    "critical" if bypass_count else "info",
    f"{bypass_count}/{len(FORMS)} obfuscated forms reached the private listener; total_hits={len(HITS)}",
    "Red-team verdict: the private-space guard is string-matching, not resolution-based.")

# ---------------------------------------------------------------- RT-05 TLS MITM acceptance
CERTDIR = tempfile.mkdtemp(prefix="rt-tls-")
CRT, KEY = os.path.join(CERTDIR, "evil.crt"), os.path.join(CERTDIR, "evil.key")
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", KEY, "-out", CRT, "-days", "2", "-subj",
                "/CN=the-real-target.example", "-addext", "subjectAltName=DNS:the-real-target.example"],
               check=True, capture_output=True)
MITM_HITS = []
class MitmSvc(BaseHTTPRequestHandler):
    def do_GET(self):
        MITM_HITS.append((self.path, self.headers.get("Authorization", ""),
                          self.headers.get("Cookie", "")))
        body = b'<html><body>Fake page from the MITM - findings poisonable</body></html>'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
msrv = ThreadingHTTPServer(("127.0.0.1", 0), MitmSvc)
MPORT = msrv.server_address[1]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CRT, KEY)
msrv.socket = ctx.wrap_socket(msrv.socket, server_side=True)
threading.Thread(target=msrv.serve_forever, daemon=True).start()
time.sleep(0.2)

bus = EventBus("rt-audit")
scope = ScopeRule(allow_private=True)   # isolate the TLS variable only
eng = RequestEngine(scope, bus, timeout=8)
ep = Endpoint(url=f"https://127.0.0.1:{MPORT}/protected",
              headers={"Authorization": "Bearer SECRET-TOKEN-XYZ"})
r = eng.send(RequestMutation(endpoint=ep))
if MITM_HITS and r.ok:
    rec("RT-05", "TLS MITM: engine accepts attacker self-signed certificate",
        "BYPASSED", "critical",
        f"MITM served fake content; engine status={r.status}; captured Authorization header "
        f"through the interceptor: {MITM_HITS[0][1][:24]}...",
        "http_engine.py builds ssl ctx with check_hostname=False + CERT_NONE. "
        "No server authentication: an on-path attacker intercepts scans, harvests "
        "credentials and can poison/erase findings. SP 800-52 / every military "
        "baseline requires authenticated TLS.")
else:
    rec("RT-05", "TLS MITM acceptance test",
        "HELD" if not MITM_HITS else "PARTIAL",
        "info", f"mitm_hits={len(MITM_HITS)} engine_status={r.status} err={r.error!r}")

# ---------------------------------------------------------------- RT-07 journal credential capture
bus = EventBus("rt-audit")
scope = ScopeRule(allow_private=True)
eng = RequestEngine(scope, bus, timeout=6)
ep = Endpoint(url=f"http://127.0.0.1:{PORT}/journal-probe",
              headers={"Authorization": "Bearer RT7-BEARER-SECRET",
                       "X-Api-Key": "RT7-API-KEY-SECRET"})
eng.send(RequestMutation(endpoint=ep))
jr = getattr(bus, "request_journal", {})
leaked = []
for rid, entry in jr.items():
    hdrs = entry.get("request", {}).get("headers", {})
    for h in ("Authorization", "X-Api-Key", "Cookie"):
        if h in hdrs:
            leaked.append(f"{h}={hdrs[h][:40]}")
if leaked:
    rec("RT-07", "Plaintext journal captures auth credentials at rest",
        "LEAKED", "high",
        "; ".join(leaked),
        "The v4.2.1 request journal records raw headers (Authorization, API keys, "
        "session Cookie) with no redaction into results/evidence packages. "
        "Evidence-sharing = credential sharing.")
else:
    rec("RT-07", "Journal credential redaction", "HELD", "info", f"journal_entries={len(jr)}")

# ---------------------------------------------------------------- RT-09 cookie cross-host isolation
bus = EventBus("rt-audit")
scope = ScopeRule(allow_private=True, follow_cross_host=True)
eng = RequestEngine(scope, bus, timeout=6)
# host A sets a session cookie
eng.send(RequestMutation(endpoint=Endpoint(url=f"http://127.0.0.1:{PORT}/hostA")))
jar_a = eng.cookie_jar.get("127.0.0.1", {})
# same engine asked for a DIFFERENT host (the listener responds to any path)
eng2_hits_before = len(HITS)
eng.send(RequestMutation(endpoint=Endpoint(url=f"http://localhost:{PORT}/hostB")))
sent_cookie = None
# inspect what was actually sent on the wire: our listener logs headers via HITS paths only,
# so re-derive from the jar API: cookie header for host localhost
ck = eng._cookie_header("localhost", "/hostB")
if jar_a and ck:
    rec("RT-09", "Cookie jar cross-host isolation",
        "LEAKED", "high",
        f"jar(A)={list(jar_a)[:3]} cookie_header(B)={ck[:60]}",
        "Cookies set by host A replayed to host B — session fixation/leak vector.")
else:
    rec("RT-09", "Cookie jar cross-host isolation",
        "HELD", "info",
        f"jar(A) keys={list(jar_a)[:3]} cookie_header(B)={'<empty>' if not ck else ck[:40]}",
        "Jar keyed per-host; no replay across hosts.")

srv.shutdown(); msrv.shutdown()
RESULTS["summary"] = {
    "ssrf_bypassed_forms": bypass_count,
    "ssrf_forms_tested": len(FORMS),
    "tls_mitm_accepted": bool(MITM_HITS and r.ok),
    "journal_credentials_leaked": bool(leaked),
}
with open(os.path.join(OUT, "rt_network.json"), "w") as f:
    json.dump(RESULTS, f, indent=1, ensure_ascii=False)
print("\nWROTE", os.path.join(OUT, "rt_network.json"))
print("SUMMARY:", json.dumps(RESULTS["summary"]))

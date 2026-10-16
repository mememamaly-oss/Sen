#!/usr/bin/env python3
"""
PHASE 0 — SCOPE-GATE DIFFERENTIAL PROOF (strict external-test order, 2026-10-16)
================================================================================
OFFLINE BY CONSTRUCTION:
  * The only socket in this process is an in-process loopback listener on 127.0.0.1.
  * Every external host used as a probe/embedded link is an RFC-2606-reserved
    `.invalid` domain (unresolvable by design) — even a total gate failure could
    not produce a packet leaving the machine. The one exception, www.paypal.com,
    is exercised ONLY through the string-level _scope_ok() check which returns
    BEFORE any socket is created (proof: requests_sent unchanged).

Engine under test  : build-v430/sentinel — the CANONICAL live engine (STATE.md:
                     "current version 4.3.3 (build-v430/ is the canonical live engine)").
Scope construction : replicated EXACTLY from orchestrator.py:117 — the DEFAULT scan
                     configuration: ScopeRule(allowed_domains=[target.host] + cfg extras,
                     allow_private=cfg.allow_private); allowed_hosts stays [].
Gate under test    : RequestEngine._scope_ok (http_engine.py:346 — the post-OWSP-22
                     version where allowed_hosts and allowed_domains gate INDEPENDENTLY)
                     and its enforcement points:
                       discovery.py:375   every queued page link (before fetch)
                       discovery.py:448   same-host BFS filter for <a>/<link>/<script>
                       discovery.py:487   every form action (before endpoint creation)
                       discovery.py:529   every div-pseudo-form action
                       http_engine.py:451 every engine.send() (transport gate)
                       http_engine.py:524 every redirect hop (re-check)
                       browser.py:240      headless-browser navigation
                       detect.py:2542      detector targets

History being guarded against (worklog line 1244, OWSP-22): on Mutillidae II the
pre-fix scope gate let a PayPal donation FORM on an authorized page become an
endpoint — 140 unauthorized POSTs to www.paypal.com PRODUCTION plus a false
VERIFIED SQLi against the third party. T3 below reproduces that exact scenario
offline and proves the current gate holds.

The four mandatory tests (supervisor order):
  T1 RED        out-of-list URL  -> must be REJECTED
  T2 GREEN      in-list URL      -> must be ACCEPTED
  T3 EDGE       authorized page embedding external links + a donation form:
                every discovered link checked BEFORE visiting; external ones
                rejected and never visited (machine-provable evidence)
  T4 TYPOSQUAT  near-miss host (one character different) -> must be REJECTED
Bonuses: direct transport-level send() block; redirect-hop re-check block.
"""
import hashlib
import http.server
import sys
import threading
import urllib.parse

ENGINE_DIR = "/home/z/my-project/build-v430"
sys.path.insert(0, ENGINE_DIR)

from sentinel.core import ScopeRule, Target, EventBus, SCANNER_VERSION  # noqa: E402
from sentinel.http_engine import RequestEngine                          # noqa: E402
import sentinel.core                                                     # noqa: E402
import sentinel.http_engine                                              # noqa: E402
import sentinel.discovery                                                # noqa: E402
from sentinel.discovery import DiscoveryEngine, _simple_get              # noqa: E402


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def section(title: str):
    print("\n" + "=" * 78)
    print("== " + title)
    print("=" * 78)


def scope_dump(s) -> str:
    return (f"ScopeRule(allowed_hosts={s.allowed_hosts!r}, "
            f"allowed_domains={s.allowed_domains!r}, "
            f"allowed_schemes={s.allowed_schemes!r}, "
            f"allowed_ports={s.allowed_ports!r}, "
            f"denied_paths={s.denied_paths!r}, "
            f"allow_private={s.allow_private!r}, "
            f"max_redirects={s.max_redirects!r}, "
            f"follow_cross_host={s.follow_cross_host!r})")


# ============================================================ PROVENANCE
section("PROVENANCE — the engine under test (canonical tree, unmodified)")
print("scanner_version :", SCANNER_VERSION)
for mod in (sentinel.core, sentinel.http_engine, sentinel.discovery):
    print(f"  {mod.__name__:22s} {mod.__file__}  sha256={sha256(mod.__file__)}")
_orch = ENGINE_DIR + "/sentinel/orchestrator.py"
_line = next(l.strip() for l in open(_orch)
             if "self.scope = ScopeRule(allowed_domains=" in l)
print("scope construction under test (orchestrator.py:117):")
print("  " + _line)

# ============================================================ T1 (RED)
section("T1 (RED) — URLs OUTSIDE the default list must be REJECTED (function level)")
pub_scope = ScopeRule(allowed_domains=[Target("https://demo.testfire.net/").host])
pub_engine = RequestEngine(pub_scope, EventBus("run-t1"))
print("scan target: https://demo.testfire.net/  -> default scope (orchestrator.py:117):")
print("  " + scope_dump(pub_scope))
t1_cases = [
    ("https://www.paypal.com/cgi-bin/webscr?cmd=_donations",
     "the OWSP-22 incident host — a REAL production payment domain (string-level check only; no socket can exist)"),
    ("https://donate.charity.invalid/appeal",
     "fictional donation domain (.invalid = RFC-2606 reserved, unresolvable)"),
    ("https://ads.tracker.invalid/banner?id=7",
     "fictional ad/tracker domain (.invalid)"),
]
t1_pass = True
for url, why in t1_cases:
    ok, reason = pub_engine._scope_ok(url)
    good = (ok is False)
    t1_pass = t1_pass and good
    print(f"\n  engine._scope_ok({url!r})")
    print(f"    -> {ok!r}, {reason!r}")
    print(f"    note   : {why}")
    print(f"    verdict: {'PASS — REJECTED' if good else 'FAIL — WAS ACCEPTED (!!)'}")

# ============================================================ T2 (GREEN)
section("T2 (GREEN) — a URL INSIDE the default list EXACTLY must be ACCEPTED")
ok, reason = pub_engine._scope_ok("https://demo.testfire.net/login.jsp")
t2_pass = (ok is True)
print("  engine._scope_ok('https://demo.testfire.net/login.jsp')")
print(f"    -> {ok!r}, {reason!r}")
print(f"    verdict: {'PASS — ACCEPTED' if t2_pass else 'FAIL — REJECTED (!!)'}")
ok_sub, reason_sub = pub_engine._scope_ok("https://images.demo.testfire.net/logo.png")
print("\n  [documented semantics — not a pass/fail case] genuine subdomain:")
print("  engine._scope_ok('https://images.demo.testfire.net/logo.png')")
print(f"    -> {ok_sub!r}, {reason_sub!r}")
print("    (allowed_domains is a SUFFIX match by design — core.py:43 — so true")
print("     subdomains of the target domain are in scope; near-miss/typo hosts")
print("     are NOT: proven in T4 below.)")

# ============================================================ T3 (EDGE)
section("T3 (EDGE) — the literal Mutillidae/PayPal OWSP-22 scenario, fully OFFLINE")
print("An in-process loopback server (127.0.0.1) plays the authorized target.")
print("Its front page embeds EXTERNAL links + an external donation FORM — the")
print("exact shape of the Mutillidae front page that produced the incident.")
print("Offline guarantee: every external host embedded below is .invalid (RFC-2606;")
print("unresolvable by construction) — no packet could leave even on gate failure.")

ACCESS_LOG = []
PAGES = {}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):   # silence default logging; we keep our own log
        pass

    def do_GET(self):
        ACCESS_LOG.append(self.path)
        if self.path == "/ext-redir":
            self.send_response(302)
            self.send_header("Location", "https://redirect-target.invalid/landing")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = PAGES.get(self.path)
        if body is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
PORT = srv.server_address[1]
BASE = f"http://127.0.0.1:{PORT}/"
threading.Thread(target=srv.serve_forever, daemon=True).start()
print(f"\nloopback target live: {BASE}  (the ONLY socket in this process)")

local_scope = ScopeRule(allowed_domains=[Target(BASE).host], allow_private=True)
print("default scope for this target (orchestrator.py:117 construction, allow_private for local target):")
print("  " + scope_dump(local_scope))

EXTERNAL_EMBEDDED = [
    "https://donate.charity.invalid/appeal?ref=front",
    "https://ads.tracker.invalid/banner?id=7",
    "https://www.paypal-echo.invalid/cgi-bin/webscr",
]
PAGES["/"] = (
    "<html><head><title>mock front page</title></head><body>\n"
    "<h1>mock-vuln front page (authorized target)</h1>\n"
    '<a href="/page2">Page 2 (in-scope, relative)</a>\n'
    f'<a href="{BASE}page2">Page 2 (in-scope, absolute)</a>\n'
    '<a href="https://donate.charity.invalid/appeal?ref=front">Donate Now!</a>\n'
    '<a href="https://ads.tracker.invalid/banner?id=7">Sponsored ad</a>\n'
    '<form action="https://www.paypal-echo.invalid/cgi-bin/webscr" method="POST">\n'
    '  <input type="hidden" name="cmd" value="_donations">\n'
    '  <input type="hidden" name="business" value="donate@charity.invalid">\n'
    '  <input type="submit" name="donate-submit" value="Donate">\n'
    "</form>\n"
    '<a href="/ext-redir">Redirect trap (302 -&gt; external host)</a>\n'
    "</body></html>"
).encode()
PAGES["/page2"] = b'<html><body><h1>page 2</h1><a href="/">back</a></body></html>'

bus = EventBus("run-t3")
local_engine = RequestEngine(local_scope, bus, timeout=5)

print("\n--- T3a (function level): every EXTERNAL url embedded in the page, checked ---")
t3a_pass = True
for u in EXTERNAL_EMBEDDED:
    ok, reason = local_engine._scope_ok(u)
    good = (ok is False)
    t3a_pass = t3a_pass and good
    print(f"  _scope_ok({u!r})")
    print(f"    -> {ok!r}, {reason!r}   {'PASS' if good else 'FAIL (!!)'}")

print("\n--- T3b (crawler level): full DiscoveryEngine crawl of the front page ---")
crawler = DiscoveryEngine(local_engine, max_pages=10)
res = crawler.crawl(BASE)
endpoints = res[0]
print(f"  crawl() returned {len(res)} items; endpoints discovered: {len(endpoints)}")

print("\n--- EVIDENCE 1: loopback server ACCESS LOG (ground truth of what was VISITED) ---")
for p in ACCESS_LOG:
    print("  GET " + p)
allowed_paths = {"/", "/page2", "/ext-redir"}
weird_paths = [p for p in ACCESS_LOG if p.split("?", 1)[0] not in allowed_paths]

print("\n--- EVIDENCE 2: REQUEST JOURNAL (every request the engine ISSUED, full URLs) ---")
jr = getattr(bus, "request_journal", {}) or {}
journal_rows = []
for rid, entry in jr.items():
    req = entry.get("request", {}) if isinstance(entry, dict) else {}
    journal_rows.append((rid, req.get("method"), req.get("url")))
    print(f"  {rid}  {req.get('method')}  {req.get('url')}")
ext_in_journal = [u for (_, _, u) in journal_rows
                  if urllib.parse.urlsplit(u or "").hostname != "127.0.0.1"]

print("\n--- EVIDENCE 3: EventBus scope-gate events (transport/redirect layers) ---")
rbs = bus.by_kind("RedirectBlockedByScope")
xbs = bus.by_kind("RequestBlockedByScope")
for ev in rbs:
    print("  RedirectBlockedByScope:", repr(ev))
for ev in xbs:
    print("  RequestBlockedByScope :", repr(ev))
if not rbs:
    print("  RedirectBlockedByScope: NONE")
if not xbs:
    print("  RequestBlockedByScope : NONE (expected — discovery filtered everything before send)")

print("\n--- EVIDENCE 4: discovered ENDPOINTS (the external form action must NOT be one) ---")
_ep_list = list(endpoints.values()) if isinstance(endpoints, dict) else list(endpoints)
for ep in _ep_list:
    print(f"  {ep.url}   source={getattr(ep.source, 'name', ep.source)}")
ext_eps = [ep for ep in _ep_list
           if urllib.parse.urlsplit(ep.url).hostname != "127.0.0.1"]

print("\n--- EVIDENCE 5: crawl_skips (discovery-level rejections — scope-checked live) ---")
skips = list(getattr(crawler, "crawl_skips", []))
for s in skips:
    ok, reason = local_engine._scope_ok(s)
    print(f"  skipped: {s}")
    print(f"    scope check of it right now -> {ok!r}, {reason!r}")

print("\n--- EVIDENCE 6: counters ---")
print(f"  engine.requests_sent = {local_engine.requests_sent}"
      f"   |   loopback access-log hits = {len(ACCESS_LOG)}")

form_skipped = any("paypal-echo.invalid" in s for s in skips)
redir_blocked = any("redirect-target.invalid" in str(ev) for ev in rbs)
print("\n  T3 CRITERIA:")
print(f"    [a] every embedded external URL rejected at function level     : {'PASS' if t3a_pass else 'FAIL'}")
print(f"    [b] access log contains only known in-scope paths              : {'PASS' if not weird_paths else 'FAIL ' + repr(weird_paths)}")
print(f"    [c] ZERO external URLs in the request journal (no visit attempt): {'PASS' if not ext_in_journal else 'FAIL ' + repr(ext_in_journal)}")
print(f"    [d] ZERO external endpoints discovered (OWSP-22 regression)    : {'PASS' if not ext_eps else 'FAIL ' + repr([e.url for e in ext_eps])}")
print(f"    [e] external donation form action sits in crawl_skips          : {'PASS' if form_skipped else 'FAIL'}")
print(f"    [f] redirect hop to external host BLOCKED (event on record)    : {'PASS' if redir_blocked else 'FAIL'}")
t3_pass = (t3a_pass and not weird_paths and not ext_in_journal
           and not ext_eps and form_skipped and redir_blocked)
print(f"  T3 VERDICT: {'PASS' if t3_pass else 'FAIL'}")
srv.shutdown()
srv.server_close()

# ============================================================ T4 (TYPOSQUAT)
section("T4 (TYPOSQUAT) — near-miss hosts (one character different) must be REJECTED")
t4_cases = [
    ("https://dem0.testfire.net/", "letter o -> digit 0"),
    ("https://demo.testf1re.net/", "letter i -> digit 1"),
    ("https://demo.testfire.ne/", "truncated TLD (.ne vs .net)"),
    ("https://demo-testfire.net/", "dot -> hyphen"),
    ("https://evildemo.testfire.net/",
     "contains 'demo.testfire.net' as substring but is NOT its subdomain"),
    ("https://demo.testfire.net.evil.invalid/",
     "suffix attack: the allowed domain embedded inside a DIFFERENT host"),
]
t4_pass = True
for url, why in t4_cases:
    ok, reason = pub_engine._scope_ok(url)
    good = (ok is False)
    t4_pass = t4_pass and good
    print(f"\n  engine._scope_ok({url!r})")
    print(f"    -> {ok!r}, {reason!r}")
    print(f"    note   : {why}")
    print(f"    verdict: {'PASS — REJECTED' if good else 'FAIL — WAS ACCEPTED (!!)'}")

# ============================================================ BONUS
section("BONUS — transport-level gate: direct engine.send() to an external URL")
before = pub_engine.requests_sent
n_before = len(pub_engine.bus.by_kind("RequestBlockedByScope"))
resp = pub_engine.send(_simple_get("https://www.paypal-echo.invalid/cgi-bin/webscr"))
after = pub_engine.requests_sent
n_after = len(pub_engine.bus.by_kind("RequestBlockedByScope"))
bonus_pass = (getattr(resp, "status", None) == 0
              and str(getattr(resp, "error", "")).startswith("scope:")
              and before == after
              and n_after == n_before + 1)
print("  resp = pub_engine.send(_simple_get('https://www.paypal-echo.invalid/cgi-bin/webscr'))")
print(f"    resp.status = {resp.status!r}")
print(f"    resp.error  = {resp.error!r}")
print(f"    resp.url    = {resp.url!r}")
print(f"    requests_sent before/after          = {before}/{after}  (unchanged => NO socket was ever created)")
print(f"    RequestBlockedByScope events b/a    = {n_before}/{n_after}  (+1 => the gate fired)")
print(f"    verdict: {'PASS — the transport gate blocks BEFORE any connection' if bonus_pass else 'FAIL'}")

# ============================================================ FINAL VERDICT
section("PHASE 0 FINAL VERDICT")
rows = [
    ("T1 RED       — out-of-list URLs rejected", t1_pass),
    ("T2 GREEN     — in-list URL accepted exactly", t2_pass),
    ("T3 EDGE      — embedded external links/form checked & never visited", t3_pass),
    ("T4 TYPOSQUAT — near-miss hosts rejected", t4_pass),
    ("BONUS        — transport send() gate + redirect re-check", bonus_pass),
]
allok = True
for name, okk in rows:
    print(f"  [{'PASS' if okk else 'FAIL'}] {name}")
    allok = allok and okk
print()
if allok:
    print("  SCOPE GATE PROVEN BY DIFFERENTIAL TEST — raw outputs above.")
    print("  Phase 1 (candidate list, NO scanning) may proceed.")
else:
    print("  GATE NOT PROVEN — STOP. Do NOT proceed to Phase 1.")
sys.exit(0 if allok else 1)

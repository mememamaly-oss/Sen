#!/usr/bin/env python3
"""SENTINEL Benchmark Fixture v1 — locally-hosted intentionally vulnerable app.
GROUND TRUTH (see benchmarks/ground_truth.json):
  /vuln/sqli_error.php?id      -> sql_injection (error-based)
  /vuln/sqli_blind.php?id      -> sql_injection (boolean oracle 200/500)
  /vuln/xss.php?q              -> xss_reflected (raw reflection)
  /vuln/traversal.php?file     -> path_traversal (reads SENTINEL-SECRET-FILE)
  /vuln/redirect.php?url       -> open_redirect (Location header)
  /vuln/jsparam.php?cat        -> sql_injection (500-on-quote, no DB string) +
                                  xss_reflected (slash-escaping app: <> raw, / escaped) +
                                  http_response_header_injection (Set-Cookie CRLF)
                                  [param only discoverable via inline <script> URLs — DISC-05]
  /vuln/stock POST XML         -> xxe (JS-transformed request; entity file-read differential)
  /vuln/oob-stock POST XML     -> xxe BLIND (noise response; confirmable ONLY out-of-band)
  /safe/oob-stock POST XML     -> NEGATIVE (DTD rejected — no entity fetch, no callback)
  /vuln/fetch?url              -> ssrf (blind server-side fetch; OOB-confirmed only)
  /safe/fetch?url              -> NEGATIVE (allowlist — no fetch of attacker URLs)
  /vuln/ping?host              -> command_injection (shell=True interpolation; OOB-confirmed)
  /safe/ping?host              -> NEGATIVE (argv list, no shell — injection impossible)
  /vuln/cors                   -> cors_misconfig (arbitrary Origin reflected + credentials)
  /safe/cors                   -> NEGATIVE (fixed allowlisted origin)
  /angular_1-7-7.js            -> vulnerable_js_dependency (passive)
  /safe/search.php?q           -> NEGATIVE (escaped)
  /safe/item.php?id            -> NEGATIVE (parameterized)
  /safe/read.php?file          -> NEGATIVE (basename filter)
  /safe/go.php?url             -> NEGATIVE (allowlist)
  /safe/jsparam.php?cat        -> NEGATIVE (inline-JS-discoverable but safe)
  /safe/stock POST XML         -> NEGATIVE (DTD rejected — no entity resolution)
  all pages                    -> missing_security_headers (positive, passive)
"""
import json, os, re, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

DELAY_MS = float(os.environ.get("DELAY_MS", "0"))   # for chaos/repair demos: artificial per-request latency

SECRET_FILE = "SENTINEL-SECRET-FILE: benchmark-fixture-secret-do-not-leak\n"

# Fake filesystem for the XXE endpoint (entity resolution simulation — the real
# ginandjuice.shop oracle behaved exactly like this: distinct response per readable
# file, failed/unreadable entities equal the nonexistent control).
FAKE_FS = {
    "/etc/hostname": "fixture-host-01",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n",
    "/etc/group": "root:x:0:\ndaemon:x:1:\nbin:x:2:\n",
    "/etc/lsb-release": "DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=22.04\n",
}

HEADER_TMPL = """<!DOCTYPE html><html><head><title>Sentinel Fixture</title></head><body>
<div class="menubar"><a href="/">home</a>
 - <a href="/vuln/ssti?name=world">ssti</a> - <a href="/safe/ssti?name=world">safe ssti</a>
 - <a href="/vuln/hostbuild">host header</a> - <a href="/safe/hostbuild">safe host</a>
 - <a href="/lab">lab</a> - <a href="/vuln/sqli_error.php?id=1">sqli err</a>
 - <a href="/vuln/sqli_blind.php?id=1">sqli blind</a> - <a href="/vuln/xss.php?q=test">xss</a>
 - <a href="/vuln/traversal.php?file=notes.txt">traversal</a> - <a href="/vuln/redirect.php?url=https://example.com">redirect</a>
 - <a href="/safe/search.php?q=test">safe search</a> - <a href="/safe/item.php?id=1">safe item</a>
 - <a href="/safe/read.php?file=notes.txt">safe read</a> - <a href="/hidden.php">hidden</a>
 - <a href="/safe/jsparam.php?cat=Books">safe jsparam</a> - <a href="/app.js">app.js</a>
 - <a href="/vuln/dom-write">dom-write</a> - <a href="/safe/dom-text?search=test">safe dom-text</a>
 - <a href="/vuln/divform">divform</a> - <a href="/safe/divform">safe divform</a>
 - <a href="/vuln/csrfdivform">csrf divform</a> - <a href="/vuln/jsform">jsform</a> - <a href="/login">sign in</a>
 - <a href="/vuln/fetch?url=http://api.local/feed">ssrf</a> - <a href="/safe/fetch?url=http://api.local/feed">safe fetch</a>
 - <a href="/vuln/ping?host=localhost">cmdi</a> - <a href="/safe/ping?host=localhost">safe ping</a>
 - <a href="/vuln/cors">cors api</a> - <a href="/safe/cors">safe cors</a></div>
{body}
</body></html>"""

NOTES = "These are public notes. Nothing secret here.\n"
APP_JS = """
const API_BASE = "/api/";
fetch(API_BASE + "items?id=1");
$.ajax({url: "/api/users?id=2"});
new WebSocket("wss://localhost/ws");
"""

# Mirrors ginandjuice.shop xmlStockCheckPayload.js: JS rebuilds the form POST as XML.
STOCKAPP_JS = """
window.contentType = 'application/xml';
function payload(data) {
    var xml = '<?xml version="1.0" encoding="UTF-8"?>';
    xml += '<stockCheck>';
    for(var pair of data.entries()) { xml += '<' + pair[0] + '>' + pair[1] + '</' + pair[0] + '>'; }
    xml += '</stockCheck>';
    return xml;
}
"""

# The page that hides the /vuln/jsparam.php?cat surface inside an inline <script>
# (only reachable via DISC-05 inline-JS URL extraction) and carries the XML stock forms.
HIDDEN_PAGE = """<h2>Products</h2>
<script type="text/javascript">
    const categories = {"Gin":"/vuln/jsparam.php?cat=Gin","Books":"/vuln/jsparam.php?cat=Books"};
    const selectedCategory = "All";
</script>
<script src="/stockapp.js"></script>
<script src="/angular_1-7-7.js"></script>
<form action="/vuln/stock" method="POST"><input type="hidden" name="productId" value="1"><button>Check stock</button></form>
<form action="/safe/stock" method="POST"><input type="hidden" name="productId" value="1"><button>Safe stock</button></form>
<form action="/blind/stock" method="POST"><input type="hidden" name="productId" value="1"><button>Blind stock</button></form>
<form action="/vuln/oob-stock" method="POST"><input type="hidden" name="productId" value="1"><button>Blind stock (OOB)</button></form>
<form action="/safe/oob-stock" method="POST"><input type="hidden" name="productId" value="1"><button>Safe blind stock</button></form>
"""

ANGULAR_JS = "/* AngularJS v1.7.7 stub — EOL branch served for passive dependency detection */\n"

# ==================== Phase 50 (fixture v4): browser/DOM surfaces ====================
# The server NEVER reflects ?search= on either page below — the param is read
# client-side from URLSearchParams and passed to a sink. /vuln/dom-write uses a
# dangerous sink (mirrors ginandjuice.shop /blog?search: document.write into an
# attribute context); /safe/dom-text uses textContent. ONLY a real browser can
# separate them — the DOM-engine ground truth pair.
DOM_WRITE_PAGE = """<h2>Search tracker</h2>
<form action="/vuln/dom-write" method="GET"><input type="text" name="search" value="test"><button>Track</button></form>
<script>
function trackSearch(query) {
    document.write('<img src="/tracker.gif?searchTerms=' + query + '">');
}
var query = (new URLSearchParams(window.location.search)).get('search');
if (query) { trackSearch(query); }
</script>
<div>Search tracked.</div>"""

# Param-less variant: like ginandjuice.shop /blog/ (index) vs /blog?search= (results)
# — the DOM source->sink script is server-side CONDITIONAL, so the param-less page
# carries no script at all. Reaching the script REQUIRES DISC-12 form-target queueing.
DOM_WRITE_PAGE_PLAIN = """<h2>Search tracker</h2>
<form action="/vuln/dom-write" method="GET"><input type="text" name="search" value="test"><button>Track</button></form>
<div>Enter a search term.</div>"""

DOM_TEXT_PAGE = """<h2>Search echo</h2>
<div id="out"></div>
<script>
var q = new URLSearchParams(window.location.search).get('search');
if (q) { document.getElementById('out').textContent = q; }
</script>"""

# Mirrors ginandjuice.shop subscribeNow.js: div-based pseudo-forms are serialized
# as JSON (JSON.stringify + Content-Type application/json) — DISC-10 learns the
# transformation statically from this asset, ENG-04 replays it deterministically.
JSBUILD_JS = """
document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('div[data-action]').forEach(function (f) {
        var btn = f.querySelector('button');
        if (!btn) return;
        btn.addEventListener('click', function (e) {
            e.preventDefault();
            var value = {};
            f.querySelectorAll('input').forEach(function (i) { value[i.name] = i.value; });
            var xhr = new XMLHttpRequest();
            xhr.open(f.dataset.method, f.dataset.action);
            xhr.setRequestHeader('Content-Type', 'application/json;charset=UTF-8');
            xhr.send(JSON.stringify(value));
        });
    });
});
"""

DIVFORM_PAGE = """<h2>Subscribe</h2>
<script src="/jsbuild.js"></script>
<div id="subscribe" class="form" data-method="post" data-action="/vuln/json-reflect">
<input required type="text" name="name" placeholder="Name">
<button class="button" type="submit">Subscribe</button>
</div>"""

SAFE_DIVFORM_PAGE = """<h2>Subscribe (safe)</h2>
<script src="/jsbuild.js"></script>
<div id="subscribe" class="form" data-method="post" data-action="/safe/json-reflect">
<input required type="text" name="name" placeholder="Name">
<button class="button" type="submit">Subscribe</button>
</div>"""

# CSRF-protected flow (ENG-05 ground truth): the page sets a deterministic session
# cookie and embeds the matching token; the POST endpoint rejects requests without
# BOTH. Without the engine cookie jar this surface is unreachable ("Invalid CSRF").
import hashlib as _hl
CSRF_SESSION = "fixedsess123"
CSRF_TOKEN = _hl.sha1((CSRF_SESSION + "|csrf").encode()).hexdigest()[:16]

# ======================= Phase 51 (fixture v5): AUTHENTICATED SURFACE =======================
# Real Altoro-style flow, engineered to exercise every auth capability:
#   GET  /login          -> Set-Cookie SESS=s1 + form with hidden csrfToken (AUTH-01:
#                           the token is session-bound and CHANGES every GET — a
#                           hard-coded-fields login can never pass)
#   POST /doLogin        -> validates SESS+csrf+creds, then ROTATES the session:
#                           Set-Cookie SESS=s2 + AUTH=granted-s2 on a 302 to /home.
#                           The redirect hop itself needs the fresh cookies (ENG-07:
#                           the engine must rebuild the Cookie header per hop).
#   /home                -> authenticated landing ("Sign Off" marker) — the ONLY
#                           page linking the authenticated surface (like Altoro /bank/*)
#   /account?q=          -> auth-gated RAW reflection        [TP xss_reflected]
#   /account?tab=        -> auth-gated ESCAPED reflection    [TN xss_reflected]
#   /vault/transfer?acct -> auth-gated boolean SQLi oracle   [TP sql_injection]
#   AUTH_TTL=<n> env     -> server-side session expiry after n authenticated requests
#                           (AUTH-03 watchdog: mid-scan session loss -> re-auth)
AUTH_USER, AUTH_PASS = "demo", "demo123"
AUTH_TTL = int(os.environ.get("AUTH_TTL", "0"))   # 0 = never expires
SESSIONS: dict[str, dict] = {}                     # sess_id -> {csrf, authed, hits}

def _new_session() -> str:
    sid = _hl.sha1((str(time.time()) + str(os.getpid()) + _hl.md5(str(time.time_ns()).encode()).hexdigest()).encode()).hexdigest()[:12]
    SESSIONS[sid] = {"csrf": _hl.sha1((sid + "|csrf").encode()).hexdigest()[:16],
                     "authed": False, "hits": 0}
    return sid

def _sess_authed(self):
    """Resolve the caller's session; None when anonymous/expired. Applies TTL."""
    cookie = self.headers.get("Cookie") or ""
    m = re.search(r"SESS=([0-9a-f]{12})", cookie)
    if not m: return None
    sid = m.group(1)
    s = SESSIONS.get(sid)
    if s is None or not s.get("authed"): return None
    if f"AUTH=granted-{sid}" not in cookie: return None
    if AUTH_TTL and s["hits"] >= AUTH_TTL:
        SESSIONS.pop(sid, None)                    # server-side expiry
        return None
    s["hits"] += 1
    return sid

AUTH_MENUBAR = '''<div class="menubar"><a href="/home">home</a> - <a href="/account?q=John">account q</a>
 - <a href="/account?tab=profile">account tab</a> - <a href="/vault/transfer?acct=1001&amount=250">transfer</a></div>'''

LOGIN_PAGE = '''<h1>Sign in</h1>
<form action="doLogin" method="post">
  <input type="text" name="uid" value="">
  <input type="password" name="passw">
  <input type="hidden" name="csrfToken" value="{csrf}">
  <input type="submit" name="btnSubmit" value="Login">
</form>'''

CSRF_DIVFORM_PAGE = """<h2>Newsletter</h2>
<script src="/jsbuild.js"></script>
<div id="subscribe" class="form" data-method="post" data-action="/vuln/csrf-reflect">
<input required type="text" name="note" placeholder="Note">
<input required type="hidden" name="csrf" value="%s">
<button class="button" type="submit">Subscribe</button>
</div>""" % CSRF_TOKEN

# Runtime-built form (browser-only discovery): no <form> markup exists statically —
# the form is created by JS on DOMContentLoaded, exactly like React/Angular apps.
JSFORM_PAGE = """<h2>Feedback</h2>
<script>
window.addEventListener('DOMContentLoaded', function () {
    var f = document.createElement('form');
    f.action = '/vuln/jsform-reflect'; f.method = 'POST';
    var i = document.createElement('input'); i.name = 'msg'; i.value = 'hello';
    var b = document.createElement('button'); b.type = 'submit';
    f.appendChild(i); f.appendChild(b);
    document.body.appendChild(f);
});
</script>
<div>Feedback form below.</div>"""

PRODUCTS_ALL = "<ul>" + "<li>Gin bottle product item with a long description</li>" * 40 + "</ul>"
PRODUCTS_NONE = "<ul><li>No products match your filters.</li></ul>"
PRODUCTS_ONE = "<ul><li>One product in this category.</li></ul>"
GENERIC_500 = "<html><body><h1>Oops... something went wrong!</h1><p>Of all the gin joints in all the websites, you stumble into mine.</p></body></html>"

# ginandjuice.shop blind-stock sequence (deterministic 'randomness' for tests)
_BLIND_SEQ = [23, 768, 52, 191, 423, 648, 920, 140, 295]


# ======================= Phase 55 (fixture v7): SSTI / CSRF / NoSQL / JWT / Host =======================
# Five new ground-truth pairs, same discipline as every prior phase: each vulnerable
# surface is a REAL mechanism (template evaluation, operator-object matching, unsigned
# token issuance, Host-derived link building), each safe twin blocks it at the root.
#
#   /vuln/ssti?name       -> ssti ({{7*7}} and ${7*7} EVALUATED server-side; plain
#                            names are NOT echoed — only the computed result appears)
#   /safe/ssti?name       -> NEGATIVE (no evaluation, no echo: constant greeting)
#   /vuln/csrf-action     -> csrf (state-changing POST, no token, no Origin check)
#   /safe/csrf-action     -> NEGATIVE (hidden csrfToken + server-side validation)
#   /vuln/nosql-login     -> nosql_injection ({"$ne":...} object flips 401 -> 200)
#   /safe/nosql-login     -> NEGATIVE (non-string values rejected before matching)
#   /vuln/jwt-login       -> jwt_security (issues alg=none token with empty signature)
#   /safe/jwt-login       -> NEGATIVE (issues HS256-signed token)
#   /vuln/hostbuild       -> host_header_injection (absolute links built from Host)
#   /safe/hostbuild       -> NEGATIVE (fixed configured base URL)
import base64 as _b64, hmac as _hmac

def _b64url(s: str) -> str:
    return _b64.urlsafe_b64encode(s.encode()).decode().rstrip("=")

def _jwt(header: dict, payload: dict, secret: str | None) -> str:
    h, p = _b64url(json.dumps(header, sort_keys=True)), _b64url(json.dumps(payload, sort_keys=True))
    signing = f"{h}.{p}"
    if secret is None:
        return signing + "."                       # alg=none: EMPTY signature
    sig = _b64.urlsafe_b64encode(_hmac.new(secret.encode(), signing.encode(),
                                           "sha256").digest()).decode().rstrip("=")
    return f"{signing}.{sig}"

# deterministic tokens (fixed claims, no timestamps — reproducible scans)
VULN_JWT = _jwt({"alg": "none", "typ": "JWT"}, {"sub": "demo", "role": "user"}, None)
SAFE_JWT = _jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "demo", "role": "user"},
                "sentinel-fixture-secret-v7")
# guard: the tokens must never contain the SSTI oracle values "49"/"132" — an ambient
# match inside a base64 string would be a false SSTI signal on the JWT surfaces
assert "49" not in VULN_JWT and "132" not in VULN_JWT, VULN_JWT
assert "49" not in SAFE_JWT and "132" not in SAFE_JWT, SAFE_JWT

LAB_PAGE = """<h2>Ledger lab</h2>
<p>Subscribe to the newsletter (state-changing POST):</p>
<form action="/vuln/csrf-action" method="POST">
<input type="email" name="email" value="sub@example.com">
<button type="submit">Subscribe</button>
</form>
<form action="/safe/csrf-action" method="POST">
<input type="hidden" name="csrfToken" value="cs-fixed-token-123">
<input type="email" name="email" value="sub@example.com">
<button type="submit">Subscribe (protected)</button>
</form>
<script src="/jsbuild.js"></script>
<div id="nl-nosql" class="form" data-method="post" data-action="/vuln/nosql-login">
<input required type="text" name="user" value="demo">
<input required type="password" name="pass" value="demo">
<button class="button" type="submit">NoSQL login</button>
</div>
<div id="nl-nosql-safe" class="form" data-method="post" data-action="/safe/nosql-login">
<input required type="text" name="user" value="demo">
<input required type="password" name="pass" value="demo">
<button class="button" type="submit">NoSQL login (safe)</button>
</div>
<div id="nl-jwt" class="form" data-method="post" data-action="/vuln/jwt-login">
<input required type="text" name="user" value="demo">
<input required type="password" name="pass" value="demo">
<button class="button" type="submit">JWT login</button>
</div>
<div id="nl-jwt-safe" class="form" data-method="post" data-action="/safe/jwt-login">
<input required type="text" name="user" value="demo">
<input required type="password" name="pass" value="demo">
<button class="button" type="submit">JWT login (safe)</button>
</div>
<div>End of lab.</div>"""

NOSQL_VALID = {"user": "admin", "pass": "hunter2"}   # the only literal credentials that match


class Handler(BaseHTTPRequestHandler):
    _blind_seq_n = 0                                  # /blind/stock deterministic-noise counter

    def log_message(self, *a): pass

    def _send(self, code, body, headers=None):
        if DELAY_MS: time.sleep(DELAY_MS / 1000.0)
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "Sentinel-Fixture/1.0")   # banner disclosure (positive passive)
        for k, v in (headers or {}).items(): self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str, cookies: list | None = None):
        """302 with optional fresh Set-Cookie lines (login rotation sets two)."""
        if DELAY_MS: time.sleep(DELAY_MS / 1000.0)
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        for c in (cookies or []): self.send_header("Set-Cookie", c)
        self.end_headers()

    def do_GET(self):
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        path = unquote(u.path)

        if path == "/" :
            return self._send(200, HEADER_TMPL.format(body="<h1>Sentinel Benchmark Fixture</h1>"))

        # ---------------- Phase 55: SSTI / Host-header surfaces ----------------
        if path == "/vuln/ssti":
            # REAL template evaluation: {{...}} / ${...} arithmetic is evaluated
            # server-side; the raw name is NEVER echoed (only the computed result
            # reaches the response — reflection-only twins cannot fake this).
            name = q.get("name", "")
            m = re.fullmatch(r"\{\{([\d\s+\-*]+)\}\}", name) or re.fullmatch(r"\$\{([\d\s+\-*]+)\}", name)
            if m:
                try:
                    val = eval(m.group(1), {"__builtins__": {}}, {})   # digits/operators only (regex-gated)
                except Exception:
                    val = None
                if val is not None:
                    return self._send(200, HEADER_TMPL.format(body=f"<p>Result: {val}</p>"))
            return self._send(200, HEADER_TMPL.format(body="<p>Hello, guest.</p>"))
        if path == "/safe/ssti":
            # Hardened twin: template engine disabled — the input is discarded and
            # a constant greeting returned (no evaluation, no echo).
            return self._send(200, HEADER_TMPL.format(body="<p>Hello, guest.</p>"))
        if path == "/vuln/hostbuild":
            # REAL Host-derived output: absolute links are built from the request's
            # Host header — the password-reset-poisoning / cache-poisoning mechanism.
            host = self.headers.get("Host", "127.0.0.1")
            return self._send(200, HEADER_TMPL.format(
                body=f'<p>Visit <a href="http://{host}/about">http://{host}/about</a> for details.</p>'))
        if path == "/safe/hostbuild":
            # Hardened twin: fixed configured base — attacker Host never reaches output.
            return self._send(200, HEADER_TMPL.format(
                body='<p>Visit <a href="http://configured-base.example/about">our site</a> for details.</p>'))
        if path == "/lab":
            return self._send(200, HEADER_TMPL.format(body=LAB_PAGE))
        if path == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /admin/\nDisallow: /backup/db.sql\n")
        if path == "/app.js":
            return self._send(200, APP_JS, {"Content-Type": "application/javascript"})
        if path == "/stockapp.js":
            return self._send(200, STOCKAPP_JS, {"Content-Type": "application/javascript"})
        if path == "/angular_1-7-7.js":
            return self._send(200, ANGULAR_JS, {"Content-Type": "application/javascript"})
        if path == "/jsbuild.js":
            return self._send(200, JSBUILD_JS, {"Content-Type": "application/javascript"})
        if path == "/hidden.php":
            return self._send(200, HEADER_TMPL.format(body=HIDDEN_PAGE))
        # ---- Phase 50 (fixture v4): browser/DOM surfaces
        if path == "/vuln/dom-write":
            # ginandjuice.shop-accurate conditional: the vulnerable script is served ONLY
            # on the param'd (search-results) page — the param-less page has no script.
            body = DOM_WRITE_PAGE if "search" in q else DOM_WRITE_PAGE_PLAIN
            return self._send(200, HEADER_TMPL.format(body=body))
        if path == "/safe/dom-text":
            return self._send(200, HEADER_TMPL.format(body=DOM_TEXT_PAGE))
        if path == "/vuln/divform":
            return self._send(200, HEADER_TMPL.format(body=DIVFORM_PAGE))
        if path == "/safe/divform":
            return self._send(200, HEADER_TMPL.format(body=SAFE_DIVFORM_PAGE))
        if path == "/vuln/csrfdivform":
            # deterministic session + matching CSRF token embedded in the div-form
            return self._send(200, HEADER_TMPL.format(body=CSRF_DIVFORM_PAGE),
                              {"Set-Cookie": "session=" + CSRF_SESSION + "; Path=/"})
        if path == "/vuln/jsform":
            return self._send(200, HEADER_TMPL.format(body=JSFORM_PAGE))
        if path == "/admin/":
            return self._send(200, HEADER_TMPL.format(body="<h2>admin</h2>"))
        if path == "/backup/db.sql":
            return self._send(200, HEADER_TMPL.format(body="-- dump"))

        # ---------------- Phase 51: authenticated surface ----------------
        if path == "/login":
            # realistic session policy (Altoro behaves the same): a client that
            # already holds a live session KEEPS it — a new anonymous session is
            # issued only to session-less clients. Without this, every failed
            # doLogin probe's redirect-hop through /login would clobber the
            # scanner's authenticated session cookie (ENG-05 jar) and force a
            # re-login per probe.
            cm = re.search(r"SESS=([0-9a-f]{12})", self.headers.get("Cookie") or "")
            if cm and cm.group(1) in SESSIONS:
                return self._send(200, LOGIN_PAGE.format(csrf=SESSIONS[cm.group(1)]["csrf"]))
            sid = _new_session()
            return self._send(200, LOGIN_PAGE.format(csrf=SESSIONS[sid]["csrf"]),
                              {"Set-Cookie": f"SESS={sid}; Path=/"})
        if path == "/home":
            if _sess_authed(self) is None:
                return self._redirect("/login")
            return self._send(200, AUTH_MENUBAR +
                              "<h1>My Bank</h1><p>Sign Off</p><p>Welcome, demo.</p>")
        if path == "/account":
            if _sess_authed(self) is None:
                return self._redirect("/login")
            if "tab" in q:                      # escaped twin — TN
                tab = q["tab"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                return self._send(200, AUTH_MENUBAR + f"<div>Tab: {tab}</div>")
            name = q.get("q", "")                # raw reflection — TP
            return self._send(200, AUTH_MENUBAR + f"<div>You searched for '{name}'</div>")
        if path == "/vault/transfer":
            if _sess_authed(self) is None:
                return self._redirect("/login")
            acct = q.get("acct", "0")
            m = re.match(r"^\s*(\d+)\s+AND\s+(1=1|1=2)", acct)
            if m and m.group(2) == "1=1":
                return self._send(200, AUTH_MENUBAR + "<p>Transfer pending ... " * 12 + "</p>")
            if m and m.group(2) == "1=2":
                return self._send(500, "<html><body>SQL error</body></html>")
            if "'" in acct:
                return self._send(500, "<html><body>SQL error</body></html>")
            return self._send(200, AUTH_MENUBAR + f"<p>Transfer to account {acct} queued.</p>")

        # ---------------- VULNERABLE ----------------
        if path == "/vuln/sqli_error.php":
            vid = q.get("id", "1")
            vid_esc = vid.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")  # output escaped: no unintended XSS
            if "'" in vid:
                return self._send(500, HEADER_TMPL.format(body=f"<p>DB error: You have an error in your SQL syntax near '{vid_esc[:40]}'</p>"))
            return self._send(200, HEADER_TMPL.format(body=f"<p>Item {vid_esc}</p>"))

        if path == "/vuln/sqli_blind.php":
            vid = q.get("id", "1")
            m = re.match(r"^\s*(\d+)\s+AND\s+(.+)$", vid)
            if m:
                cond = m.group(2).replace("1=1", "True").replace("1=2", "False")
                try:
                    ok = eval(cond) if cond in ("True", "False") else False
                except Exception:
                    ok = False
                if ok:
                    return self._send(200, HEADER_TMPL.format(body="<p>forum thread list ... lots of content here ... " * 8 + "</p>"))
                return self._send(500, "<html><body>error</body></html>")
            if "'" in vid:
                return self._send(500, "<html><body>error</body></html>")
            return self._send(200, HEADER_TMPL.format(body=f"<p>forum thread list ... lots of content here ... " * 8 + f" item {vid}</p>"))

        if path == "/vuln/xss.php":
            qv = q.get("q", "")
            return self._send(200, HEADER_TMPL.format(body=f"<div>You searched for '{qv}'</div>"))

        if path == "/vuln/traversal.php":
            f = unquote(q.get("file", "notes.txt"))
            if f == "notes.txt":
                return self._send(200, HEADER_TMPL.format(body=f"<pre>{NOTES}</pre>"))
            if ".." in f:
                # vulnerable: no normalization, reads outside docroot
                if "win.ini" in f.lower():
                    return self._send(200, HEADER_TMPL.format(body=f"<pre>[fonts]\n[extensions]\n[files]\n[Mail]\nMAPI=1\n</pre>"))
                if "passwd" in f.lower():
                    return self._send(200, HEADER_TMPL.format(body="<pre>root:x:0:0:root:/root:/bin/sh\n</pre>"))
                if "secret" in f.lower():
                    return self._send(200, HEADER_TMPL.format(body=f"<pre>{SECRET_FILE}</pre>"))
            return self._send(404, HEADER_TMPL.format(body="<p>not found</p>"))

        if path == "/vuln/redirect.php":
            url = q.get("url", "")
            if url.startswith(("http://", "https://", "//")):
                return self._send(302, "", {"Location": url})
            return self._send(200, HEADER_TMPL.format(body="<p>no redirect</p>"))

        if path == "/vuln/jsparam.php":
            # ginandjuice.shop /catalog?category= replica — three stacked vulns on a param
            # that only exists inside an inline <script> object (DISC-05 target).
            cat = q.get("cat", "")
            # (1) http_response_header_injection: Set-Cookie built from raw input (no CRLF
            # sanitization) — a %0d%0a in cat splits a second attacker-controlled header.
            hdrs = {"Set-Cookie": "cat=" + cat} if cat else {}
            # ginandjuice-style escaping for the reflection: < > RAW, </ escaped to <\/,
            # " escaped — so only slash-free canaries reflect raw (VR-03 target).
            refl = cat.replace('"', '\\"')
            refl = re.sub(r"</", "<\\/", refl)
            script_ctx = f"<script>const selectedCategory = \"{refl}\";</script>"
            # (2) sql_injection: OR-tautology flips the result set (DETECT-05 target);
            # unpaired quote -> generic 500 with NO DB keywords (DETECT-04 target).
            if re.search(r"OR '1'='1'", cat) or re.search(r"OR '2'>'1'", cat):
                return self._send(200, HEADER_TMPL.format(body=PRODUCTS_ALL + script_ctx), hdrs)
            if re.search(r"OR '1'='2'", cat) or re.search(r"OR '1'>'2'", cat):
                return self._send(200, HEADER_TMPL.format(body=PRODUCTS_NONE + script_ctx), hdrs)
            if "'" in cat.replace("''", ""):          # unpaired quote breaks SQL -> generic 500
                return self._send(500, GENERIC_500, hdrs)
            return self._send(200, HEADER_TMPL.format(body=PRODUCTS_ONE + script_ctx), hdrs)

        # ---------------- SAFE (negatives) ----------------
        if path == "/safe/search.php":
            qv = q.get("q", "").replace("<", "&lt;").replace(">", "&gt;")
            return self._send(200, HEADER_TMPL.format(body=f"<div>You searched for '{qv}'</div>"))

        if path == "/safe/item.php":
            vid = q.get("id", "1")
            if not vid.isdigit():
                return self._send(404, HEADER_TMPL.format(body="<p>not found</p>"))
            return self._send(200, HEADER_TMPL.format(body=f"<p>Item {vid}</p>"))

        if path == "/safe/read.php":
            import os
            f = os.path.basename(unquote(q.get("file", "notes.txt")))
            if f == "notes.txt":
                return self._send(200, HEADER_TMPL.format(body=f"<pre>{NOTES}</pre>"))
            return self._send(404, HEADER_TMPL.format(body="<p>not found</p>"))

        if path == "/safe/go.php":
            url = q.get("url", "")
            allow = ("https://example.com/", "https://example.org/")
            if url in allow:
                return self._send(302, "", {"Location": url})
            return self._send(200, HEADER_TMPL.format(body="<p>blocked</p>"))

        if path == "/safe/jsparam.php":
            # Same discovery surface (inline-JS URL) but fully hardened: SQL parameterized
            # (no 500, constant result), reflection escaped, Set-Cookie CRLF-stripped.
            cat = q.get("cat", "")
            safe_cookie = ("cat=" + cat.replace("\r", "").replace("\n", "")) if cat else None
            hdrs = {"Set-Cookie": safe_cookie} if safe_cookie else {}
            refl = cat.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
            return self._send(200, HEADER_TMPL.format(body=f"<div>Category: {refl}</div>"), hdrs)

        # ---------------- Phase 53: SSRF / command-injection / CORS surfaces ----------------
        # /vuln/fetch: server-side fetch of a user-supplied URL (SSRF). The response
        # NEVER confirms what was fetched (blind) — the only evidence is the OOB
        # callback to the OAST channel, exactly like the blind-XXE class.
        if path == "/vuln/fetch":
            url = q.get("url", "")
            if not url.lower().startswith(("http://", "https://")):
                return self._send(400, '"url must be http(s)"')
            import urllib.request as _uf
            from urllib.parse import urlsplit as _us
            try:
                # egress gate (same discipline as /vuln/oob-stock): this fixture's
                # outbound path reaches the LOOPBACK listeners the OAST channels use
                # (local server + hermetic protocol doubles). External hosts resolve
                # nowhere in the sandbox and would stall the handler on DNS — and the
                # BLIND response stays byte-identical either way (the response never
                # confirms the fetch; only the OOB callback does).
                host = (_us(url).hostname or "")
                if host in ("127.0.0.1", "localhost"):
                    _uf.urlopen(url, timeout=4).read()      # THE server-side fetch
            except Exception:
                pass
            return self._send(200, "fetch attempted")
        if path == "/safe/fetch":
            # Hardened twin: strict allowlist — attacker URLs are rejected BEFORE any
            # fetch, so no OOB callback can ever fire.
            url = q.get("url", "")
            if not url.startswith("http://api.local/"):
                return self._send(400, '"url not allowed"')
            return self._send(200, "fetched (allowlisted)")
        # /vuln/ping: REAL command injection — the host string is interpolated into a
        # shell=True template (the mechanism is identical to real-world cmdi: user
        # input + shell string interpolation). 'host=localhost; curl <oast-url>' makes
        # the server fetch our URL out-of-band.
        if path == "/vuln/ping":
            host = q.get("host", "")
            import subprocess as _sp
            try:
                _sp.run("echo ping " + host, shell=True, capture_output=True, timeout=4)
            except Exception:
                pass
            return self._send(200, "pong")
        if path == "/safe/ping":
            # Hardened twin: NO shell at all (argv list) — metacharacters are data by
            # construction, injection is impossible.
            host = q.get("host", "")
            import subprocess as _sp, shlex as _shx
            try:
                _sp.run(["echo", "ping", _shx.quote(host)], capture_output=True, timeout=4)
            except Exception:
                pass
            return self._send(200, "pong")
        # /vuln/cors: reflects ANY Origin AND allows credentials — the dangerous CORS
        # combination (credentialed cross-origin reads from any origin).
        if path == "/vuln/cors":
            origin = self.headers.get("Origin", "")
            hdrs = ({"Access-Control-Allow-Origin": origin,
                     "Access-Control-Allow-Credentials": "true"} if origin else {})
            return self._send(200, '<p>{"balance": 1337}</p>', hdrs)
        if path == "/safe/cors":
            # Hardened twin: FIXED allowlisted origin — arbitrary origins are never
            # reflected (ACAO:* alone would also be safe here: no credentials).
            return self._send(200, '<p>{"balance": 1337}</p>',
                              {"Access-Control-Allow-Origin": "https://trusted.example"})

        return self._send(404, HEADER_TMPL.format(body="<p>404</p>"))

    # ---------------- XML stock endpoints (XXE) ----------------
    def do_POST(self):
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        path = unquote(u.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        ctype = (self.headers.get("Content-Type") or "").lower()

        # ---------------- Phase 55: CSRF / NoSQL / JWT surfaces ----------------
        # /vuln/csrf-action: state-changing POST with NO anti-CSRF token and NO
        # Origin/Referer validation — any site can silently submit this form.
        if path == "/vuln/csrf-action":
            form = parse_qs(raw, keep_blank_values=True)
            email = (form.get("email", [""])[0])[:60]
            if not email:
                return self._send(400, '"email required"')
            return self._send(200, "Subscription confirmed.")
        if path == "/safe/csrf-action":
            # Hardened twin: the form carries a hidden csrfToken AND the server
            # validates it — cross-site replays (no token) are rejected 403.
            form = parse_qs(raw, keep_blank_values=True)
            if form.get("csrfToken", [""])[0] != "cs-fixed-token-123":
                return self._send(403, '"Invalid CSRF token"')
            return self._send(200, "Subscription confirmed.")
        # /vuln/nosql-login: Mongo-style matching — a JSON OBJECT value carrying a
        # $operator is treated as a match operator, not a literal (the exact
        # mechanism of real NoSQL injection: {"pass": {"$ne": "x"}} matches any
        # document whose pass differs from "x").
        if path == "/vuln/nosql-login":
            if "json" not in ctype:
                return self._send(400, '"expected application/json"')
            try:
                data = json.loads(raw)
            except Exception:
                return self._send(400, '"invalid JSON"')
            data = {k: v for k, v in data.items() if k in ("user", "pass")}
            if any(isinstance(v, dict) and any(k.startswith("$") for k in v)
                   for v in data.values()):
                return self._send(200, '{"ok": true, "role": "admin"}')   # operator match -> bypass
            if data == NOSQL_VALID:
                return self._send(200, '{"ok": true, "role": "admin"}')
            return self._send(401, '{"error": "invalid credentials"}')
        if path == "/safe/nosql-login":
            # Hardened twin: values are type-checked (strings only) BEFORE any
            # matching — operator objects are rejected as malformed, never matched.
            if "json" not in ctype:
                return self._send(400, '"expected application/json"')
            try:
                data = json.loads(raw)
            except Exception:
                return self._send(400, '"invalid JSON"')
            data = {k: v for k, v in data.items() if k in ("user", "pass")}
            if any(not isinstance(v, str) for v in data.values()):
                return self._send(400, '"malformed credentials"')
            if data == NOSQL_VALID:
                return self._send(200, '{"ok": true, "role": "admin"}')
            return self._send(401, '{"error": "invalid credentials"}')
        # /vuln/jwt-login: issues an UNSIGNED token (alg=none, empty signature) —
        # RFC 8725 §3.1 defect: any party can forge arbitrary claims.
        if path == "/vuln/jwt-login":
            if "json" not in ctype:
                return self._send(400, '"expected application/json"')
            try:
                data = json.loads(raw)
            except Exception:
                return self._send(400, '"invalid JSON"')
            user = str(data.get("user", "demo"))[:32]
            token = _jwt({"alg": "none", "typ": "JWT"},
                         {"sub": user, "role": "user"}, None)
            return self._send(200, json.dumps({"token": token, "ok": True}),
                              {"Content-Type": "application/json"})
        if path == "/safe/jwt-login":
            # Hardened twin: HS256-signed issuance (fixed secret) — the detector
            # parses alg=HS256 and stays silent: signed issuance is normal.
            if "json" not in ctype:
                return self._send(400, '"expected application/json"')
            try:
                data = json.loads(raw)
            except Exception:
                return self._send(400, '"invalid JSON"')
            user = str(data.get("user", "demo"))[:32]
            token = _jwt({"alg": "HS256", "typ": "JWT"},
                         {"sub": user, "role": "user"}, "sentinel-fixture-secret-v7")
            return self._send(200, json.dumps({"token": token, "ok": True}),
                              {"Content-Type": "application/json"})

        # ---------------- Phase 51: login POST ----------------
        if path == "/doLogin":
            form = parse_qs(raw, keep_blank_values=True)
            cookie = self.headers.get("Cookie") or ""
            m = re.search(r"SESS=([0-9a-f]{12})", cookie)
            sid = m.group(1) if m else ""
            s = SESSIONS.get(sid)
            if (s is None or "json" in ctype
                    or form.get("csrfToken", [""])[0] != s["csrf"]
                    or form.get("uid", [""])[0] != AUTH_USER
                    or form.get("passw", [""])[0] != AUTH_PASS):
                return self._redirect("/login")          # rejected: back to the gate
            # success: ROTATE the session (fixation defense) and grant AUTH
            SESSIONS.pop(sid, None)
            s2 = _new_session()
            SESSIONS[s2]["authed"] = True
            return self._redirect("/home", cookies=[f"SESS={s2}; Path=/",
                                                    f"AUTH=granted-{s2}; Path=/"])

        # ---------------- JSON/div-form endpoints (Phase 50) ----------------
        # /vuln/json-reflect: div-form POST whose JS serializes inputs as JSON
        # (DISC-10 + ENG-04 chain); response is text/html and reflects the name
        # field RAW — the subscribe-style XSS.
        if path == "/vuln/json-reflect":
            if "json" not in ctype:
                return self._send(400, '"expected application/json"')
            try:
                data = json.loads(raw)
            except Exception:
                return self._send(400, '"invalid JSON"')
            name = str(data.get("name", ""))
            return self._send(200, f"<div>Hello {name}</div>")
        if path == "/safe/json-reflect":
            if "json" not in ctype:
                return self._send(400, '"expected application/json"')
            try:
                data = json.loads(raw)
            except Exception:
                return self._send(400, '"invalid JSON"')
            name = str(data.get("name", "")).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            return self._send(200, f"<div>Hello {name}</div>")
        # /vuln/csrf-reflect: requires the session cookie AND the matching CSRF
        # token (ENG-05 jar + TOKEN-preservation chain). Without both: 403.
        if path == "/vuln/csrf-reflect":
            cookie = (self.headers.get("Cookie") or "")
            if "json" not in ctype:
                return self._send(400, '"expected application/json"')
            try:
                data = json.loads(raw)
            except Exception:
                return self._send(400, '"invalid JSON"')
            if CSRF_SESSION not in cookie or str(data.get("csrf", "")) != CSRF_TOKEN:
                return self._send(403, '"Invalid CSRF token"')
            note = str(data.get("note", ""))
            return self._send(200, f"<div>Noted: {note}</div>")
        # /vuln/jsform-reflect: standard form POST target of the RUNTIME-built form
        # (browser render-merge discovery; statically invisible — no <form> markup).
        if path == "/vuln/jsform-reflect":
            form = parse_qs(raw, keep_blank_values=True)
            msg = (form.get("msg") or [""])[0]
            return self._send(200, f"<div>Feedback: {msg}</div>")

        # ---- OOB stock pair (Phase 49 / blind-XXE-with-callback): the parser FETCHES
        # http(s) external entities for real (loopback-only in the fixture) but the
        # response is cycling noise — no response oracle exists, ONLY out-of-band
        # evidence can confirm. /safe twin rejects DTD outright.
        if path in ("/vuln/oob-stock", "/safe/oob-stock"):
            if "xml" not in ctype:
                return self._send(400, '"XML parsing error"')
            if "<!DOCTYPE" in raw or "<!ENTITY" in raw:
                if path == "/safe/oob-stock":
                    return self._send(400, '"DTD declarations are not allowed"')   # hardened parser
                import urllib.request as _ur
                for _n, sysid in re.findall(r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"\s*>', raw):
                    if sysid.startswith(("http://127.0.0.1:", "http://localhost:")):
                        try:
                            _ur.urlopen(sysid, timeout=3).read()      # THE out-of-band fetch
                        except Exception:
                            pass                                        # fetch failed silently
            fields0 = dict(re.findall(r"<(\w+)>([^<]*)</\1>", raw))
            if "storeId" not in fields0:
                return self._send(400, '"Store ID could not be parsed from XML"')
            Handler._blind_seq_n += 1
            n = _BLIND_SEQ[Handler._blind_seq_n % len(_BLIND_SEQ)]
            return self._send(200, f"{n} units", {"Content-Type": "text/plain"})

        if path not in ("/vuln/stock", "/safe/stock", "/blind/stock"):
            return self._send(404, "<p>404</p>")
        if "xml" not in ctype:
            return self._send(400, '"XML parsing error"')
        if "<!DOCTYPE" in raw or "<!ENTITY" in raw:
            if path == "/safe/stock":
                return self._send(400, '"DTD declarations are not allowed"')   # hardened parser
            # vulnerable parser: resolve external entities against the fake filesystem
            for name, sysid in re.findall(r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"\s*>', raw):
                target = sysid.replace("file://", "")
                content = FAKE_FS.get(target, "")          # unreadable/missing -> empty (control)
                raw = raw.replace(f"&{name};", content)
        fields = dict(re.findall(r"<(\w+)>([^<]*)</\1>", raw))
        pid = fields.get("productId", "")
        if not pid.isdigit():
            return self._send(400, '"Invalid product ID"')
        if "storeId" not in fields:
            # the app's own error names the element it wants (error-driven discovery)
            return self._send(400, '"Store ID could not be parsed from XML"')
        if path == "/blind/stock":
            # ginandjuice.shop REAL live behavior (proven with 5x same-file probes):
            # entities resolve, but the stock number is effectively random per request —
            # the response carries NO entity-content information (blind XXE). Modeled as
            # a deterministic cycling sequence so tests stay reproducible: any two
            # consecutive identical requests differ -> the double-control stability gate
            # must reject the noise (no response-verified finding is possible).
            Handler._blind_seq_n += 1
            n = _BLIND_SEQ[Handler._blind_seq_n % len(_BLIND_SEQ)]
            return self._send(200, f"{n} units", {"Content-Type": "text/plain"})
        sid = fields.get("storeId", "")
        if not sid:
            n = 0                                           # failed entity -> default stock
        else:
            n = sum(ord(c) for c in sid) % 997 + 1          # entity content -> response
        return self._send(200, f"{n} units", {"Content-Type": "text/plain"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8777"))
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"SENTINEL fixture listening on 127.0.0.1:{port} delay={DELAY_MS}ms")
    srv.serve_forever()

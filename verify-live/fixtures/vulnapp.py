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
<div class="menubar"><a href="/">home</a> - <a href="/vuln/sqli_error.php?id=1">sqli err</a>
 - <a href="/vuln/sqli_blind.php?id=1">sqli blind</a> - <a href="/vuln/xss.php?q=test">xss</a>
 - <a href="/vuln/traversal.php?file=notes.txt">traversal</a> - <a href="/vuln/redirect.php?url=https://example.com">redirect</a>
 - <a href="/safe/search.php?q=test">safe search</a> - <a href="/safe/item.php?id=1">safe item</a>
 - <a href="/safe/read.php?file=notes.txt">safe read</a> - <a href="/hidden.php">hidden</a>
 - <a href="/safe/jsparam.php?cat=Books">safe jsparam</a> - <a href="/app.js">app.js</a></div>
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
# (only reachable via DISC-05 inline-JS URL extraction) and carries the XML stock form.
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
"""

ANGULAR_JS = "/* AngularJS v1.7.7 stub — EOL branch served for passive dependency detection */\n"

PRODUCTS_ALL = "<ul>" + "<li>Gin bottle product item with a long description</li>" * 40 + "</ul>"
PRODUCTS_NONE = "<ul><li>No products match your filters.</li></ul>"
PRODUCTS_ONE = "<ul><li>One product in this category.</li></ul>"
GENERIC_500 = "<html><body><h1>Oops... something went wrong!</h1><p>Of all the gin joints in all the websites, you stumble into mine.</p></body></html>"

# ginandjuice.shop blind-stock sequence (deterministic 'randomness' for tests)
_BLIND_SEQ = [23, 768, 52, 191, 423, 648, 920, 140, 295]


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

    def do_GET(self):
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        path = unquote(u.path)

        if path == "/" :
            return self._send(200, HEADER_TMPL.format(body="<h1>Sentinel Benchmark Fixture</h1>"))
        if path == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /admin/\nDisallow: /backup/db.sql\n")
        if path == "/app.js":
            return self._send(200, APP_JS, {"Content-Type": "application/javascript"})
        if path == "/stockapp.js":
            return self._send(200, STOCKAPP_JS, {"Content-Type": "application/javascript"})
        if path == "/angular_1-7-7.js":
            return self._send(200, ANGULAR_JS, {"Content-Type": "application/javascript"})
        if path == "/hidden.php":
            return self._send(200, HEADER_TMPL.format(body=HIDDEN_PAGE))
        if path == "/admin/":
            return self._send(200, HEADER_TMPL.format(body="<h2>admin</h2>"))
        if path == "/backup/db.sql":
            return self._send(200, HEADER_TMPL.format(body="-- dump"))

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

        return self._send(404, HEADER_TMPL.format(body="<p>404</p>"))

    # ---------------- XML stock endpoints (XXE) ----------------
    def do_POST(self):
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        path = unquote(u.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        ctype = (self.headers.get("Content-Type") or "").lower()

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

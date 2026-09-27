#!/usr/bin/env python3
"""SENTINEL Benchmark Fixture v1 — locally-hosted intentionally vulnerable app.
GROUND TRUTH (see benchmarks/ground_truth.json):
  /vuln/sqli_error.php?id      -> sql_injection (error-based)
  /vuln/sqli_blind.php?id      -> sql_injection (boolean oracle 200/500)
  /vuln/xss.php?q              -> xss_reflected (raw reflection)
  /vuln/traversal.php?file     -> path_traversal (reads SENTINEL-SECRET-FILE)
  /vuln/redirect.php?url       -> open_redirect (Location header)
  /safe/search.php?q           -> NEGATIVE (escaped)
  /safe/item.php?id            -> NEGATIVE (parameterized)
  /safe/read.php?file          -> NEGATIVE (basename filter)
  /safe/go.php?url             -> NEGATIVE (allowlist)
  all pages                    -> missing_security_headers (positive, passive)
"""
import json, os, re, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

DELAY_MS = float(os.environ.get("DELAY_MS", "0"))   # for chaos/repair demos: artificial per-request latency

SECRET_FILE = "SENTINEL-SECRET-FILE: benchmark-fixture-secret-do-not-leak\n"

HEADER_TMPL = """<!DOCTYPE html><html><head><title>Sentinel Fixture</title></head><body>
<div class="menubar"><a href="/">home</a> - <a href="/vuln/sqli_error.php?id=1">sqli err</a>
 - <a href="/vuln/sqli_blind.php?id=1">sqli blind</a> - <a href="/vuln/xss.php?q=test">xss</a>
 - <a href="/vuln/traversal.php?file=notes.txt">traversal</a> - <a href="/vuln/redirect.php?url=https://example.com">redirect</a>
 - <a href="/safe/search.php?q=test">safe search</a> - <a href="/safe/item.php?id=1">safe item</a>
 - <a href="/safe/read.php?file=notes.txt">safe read</a> - <a href="/app.js">app.js</a></div>
{body}
</body></html>"""

NOTES = "These are public notes. Nothing secret here.\n"
APP_JS = """
const API_BASE = "/api/";
fetch(API_BASE + "items?id=1");
$.ajax({url: "/api/users?id=2"});
new WebSocket("wss://localhost/ws");
"""


class Handler(BaseHTTPRequestHandler):
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

        return self._send(404, HEADER_TMPL.format(body="<p>404</p>"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8777"))
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"SENTINEL fixture listening on 127.0.0.1:{port} delay={DELAY_MS}ms")
    srv.serve_forever()

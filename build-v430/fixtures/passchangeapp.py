#!/usr/bin/env python3
"""v4.3.0 fixture — PASSWORD-CHANGE form (the DVWA csrf/captcha pattern).

The form (password_new/password_conf + Change submit) is a REAL state change
when the submit rides along. The incident: the engine's generic battery put
payload strings into password_new with the Change submit attached — the app
changed the admin password to a SQL payload (live-caught on DVWA 2026-10-05:
the next login failed; server-side state was mutated by the scanner).
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.parse

STATE = {"admin_password": "original-secret"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _page(self, body, code=200):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        self._page("<html><body><form action='/changepw' method='POST'>"
                   "<input type='password' name='password_new'>"
                   "<input type='password' name='password_conf'>"
                   "<input type='submit' name='Change' value='Change'>"
                   "</form></body></html>")

    def do_POST(self):
        if "/changepw" in self.path:
            n = int(self.headers.get("Content-Length", 0))
            data = urllib.parse.parse_qs(self.rfile.read(n).decode())
            if "Change" in data:
                new = data.get("password_new", [""])[0]
                conf = data.get("password_conf", [""])[0]
                if new and new == conf:
                    STATE["admin_password"] = new      # THE STATE CHANGE
                    self._page("<html><body>Password Changed.</body></html>")
                    return
        self._page("<html><body>no change</body></html>")


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8805
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()

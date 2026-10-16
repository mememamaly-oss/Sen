#!/usr/bin/env python3
"""v4.3.0 fixture — LOGOUT-LINK-IN-MENU (the DVWA self-logout pattern).

The authed home page links to /logout (a session-destroying GET). A crawler
that page-fetches every link kills its own session mid-scan — every later
probe silently lands on the login page (the DVWA campaign's live-caught gap:
25 candidates -> 0 verified findings, all responses were login pages).
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.parse

SESSIONS = set()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _sid(self):
        return (self.headers.get("Cookie") or "").replace("sid=", "").strip()

    def _page(self, body, code=200, headers=None):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        for k, v in (headers or []):
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        sid = self._sid()
        if self.path == "/login":
            self._page("<html><body><form action='/login' method='POST'>"
                       "<input name='u'><input type='password' name='p'>"
                       "<input type='submit' name='go' value='Go'></form></body></html>")
            return
        if self.path == "/logout" and sid:
            SESSIONS.discard(sid)
            self._page("<html><body>bye</body></html>")
            return
        if sid in SESSIONS:
            if self.path == "/data":
                self._page("<html><body>SECRET-DATA for agent</body></html>")
                return
            # home with the logout link in the menu
            self._page("<html><body><a href='/data'>data</a> <a href='/logout'>Logout</a>"
                       "</body></html>")
            return
        self._page("<html><body>please login</body></html>", 302, [("Location", "/login")])

    def do_POST(self):
        if self.path == "/login":
            n = int(self.headers.get("Content-Length", 0))
            data = urllib.parse.parse_qs(self.rfile.read(n).decode())
            if "go" in data and data.get("u", [""])[0] == "agent" and data.get("p", [""])[0] == "secret":
                import random
                sid = "s" + str(random.randint(10 ** 9, 10 ** 10))
                SESSIONS.add(sid)
                self._page("", 302, [("Set-Cookie", f"sid={sid}; Path=/"), ("Location", "/home")])
                return
        self._page("<html><body>no</body></html>")


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8803
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()

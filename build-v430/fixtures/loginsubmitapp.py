#!/usr/bin/env python3
"""v4.3.0 fixture — SUBMIT-GATED login (the DVWA pattern).

The app accepts POST /login ONLY when the submit field (go=Go) is present —
exactly DVWA's if (!isset($_POST['Login'])) gate. Without the AUTH-SUBMIT fix
the engine's login POST omits the submit field and the app re-renders the
login form (200), so authentication always fails and the whole authenticated
surface stays invisible.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.parse


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _login_page(self):
        return ("<html><body><form action='/login' method='POST'>"
                "<input name='u'><input type='password' name='p'>"
                "<input type='submit' name='go' value='Go'>"
                "<input type='hidden' name='csrf' value='tok-123'>"
                "</form></body></html>")

    def _home(self):
        return "<html><body>Welcome agent <a href='/logout'>Logout</a></body></html>"

    def do_GET(self):
        if self.path == "/home":
            body = self._home().encode()
            self.send_response(200)
        else:
            body = self._login_page().encode()
            self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        data = urllib.parse.parse_qs(self.headers is not None and self.rfile.read(n).decode() or "")
        # THE GATE: submit field must be present (DVWA: isset($_POST['Login']))
        if "go" not in data:
            body = self._login_page().encode()
            self.send_response(200)
        elif data.get("u", [""])[0] == "agent" and data.get("p", [""])[0] == "secret":
            body = self._home().encode()
            self.send_response(302)
            self.send_header("Location", "/home")
        else:
            body = self._login_page().encode()
            self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8798
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()

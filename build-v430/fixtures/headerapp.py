#!/usr/bin/env python3
"""v4.3.0 fixture — HEADER-sourced SQLi (the OWASP Benchmark 1.2 pattern).

The HTML form advertises an ordinary body param `q`, but the application reads
the value of the request HEADER `q` (getHeader("q")) — exactly like the 432
custom-header + 473 cookie test cases of the OWASP Benchmark. A quote in the
HEADER breaks the (simulated) SQL statement -> HTTP 500 with the HSQLDB/Java
error signature; any other value -> 200. Native (query/body) probes NEVER
trigger the SQL path — the vulnerability is reachable ONLY through the header
location, so a query/body-only DAST is structurally blind (the campaign's
live-caught coverage gap FIX-A).
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _page(self):
        return ("<html><body><h1>headerapp</h1>"
                "<form action='/search' method='POST'>"
                "<input name='q' value='sentinel'>"
                "<input type='submit' value='go'></form></body></html>")

    def do_GET(self):
        b = self._page().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        # OWASP Benchmark pattern: servlet reads getHeader("q") — NOT the body
        q = self.headers.get("q", "")
        if "'" in q:
            body = ("<html><body>Problem: java.sql.SQLSyntaxErrorException: "
                    "org.hsqldb.HsqlException: unexpected end of statement in "
                    "statement [ CALL ]</body></html>").encode()
            code = 500
        else:
            body = ("<html><body>results for '" + q + "' — no rows</body></html>").encode()
            code = 200
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8795
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()

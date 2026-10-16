#!/usr/bin/env python3
"""Append GTP round-2 batch-2 tests: xpath proportional margin, ldap **
replay, securecookie attribute tokens, trustbound context association,
OWSP-36 cookie payload percent-encoding."""
P = "/home/z/my-project/build-v430/tests/run_tests.py"
src = open(P).read()

BATCH2 = '''

@case
def unit_gtp05b_xpath_small_response():
    """GTP-05b: the XPath result-set differential on SMALL responses — the
    +120B absolute margin killed the real thing (tautology ~100B vs
    contradiction 24B is a 4x ratio but under 120B); the proportional
    alternative (bt > 1.5x max + 30) must admit it, and VR-22 must reproduce
    it with fresh literals."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qs, urlsplit
    from sentinel.orchestrator import SentinelScanner, ScanConfig

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            u = urlsplit(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
            if u.path == "/":
                b = b'<a href="/emp?name=x">e</a>'
                self.send_response(200); self.send_header("Content-Length", str(len(b)))
                self.end_headers(); self.wfile.write(b)
                return
            n = q.get("name", "")
            low = n.lower()
            if " or " in low and ("1'='1" in low or "a'='a" in low) and "1'='2" not in low and "a'='b" not in low:
                b = b"Your query results are: John Watson 30 johnwatson@sh.com <br/>"
            elif " and " in low and ("1'='2" in low or "a'='b" in low):
                b = b"Your query results are: <br/>"
            else:
                b = b"Your query results are: <br/>"
            self.send_response(200); self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)
    port = 8860
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cfg = ScanConfig(allow_private=True, max_pages=5, timeout=5, seed="gtp05b",
                         browser=False, oast=None)
        rep = SentinelScanner(f"http://127.0.0.1:{port}", cfg).run()
        xps = [f for f in rep["findings"]
               if f["type"] == "xpath_injection" and f.get("status") == "verified"]
        assert xps, ("RED: small-response xpath differential not found",
                      [f["type"] for f in rep["findings"] if f.get("status") == "verified"])
        v = xps[0].get("verification", {})
        assert v.get("passed") and "fresh-pair" in (v.get("method") or ""), v
    finally:
        srv.shutdown(); srv.server_close()


@case
def unit_gtp06b_ldap_fresh_wildcard():
    """GTP-06b: VR-23's replay wildcard '*(sentinel-vr23)' matches only
    records ENDING with the marker — zero records, auto-reject (2/2 candidates
    died this way live). The fresh wildcard must be a MATCH-ALL shape ('**')
    that is byte-different from the detection probe."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qs, urlsplit
    from sentinel.orchestrator import SentinelScanner, ScanConfig

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            u = urlsplit(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
            if u.path == "/":
                b = b'<a href="/dir?uid=x">d</a>'
                self.send_response(200); self.send_header("Content-Length", str(len(b)))
                self.end_headers(); self.wfile.write(b)
                return
            n = q.get("uid", "")
            # wildcard on uid matches EVERY record; a literal matches one; a
            # marker-suffixed wildcard ('*(...)') matches none
            if n.strip() == "*" or n.strip() == "**":
                b = (b"LDAP query results:<br>Record found with name Ms Bar<br>"
                     b"Address: The streetz 4 Ms bar<br>"
                     b"LDAP query results:<br>Record found with name foo<br>"
                     b"Address: AddressForFoo 345<br>"
                     b"LDAP query results:<br>Record found with name Mr Unknown<br>"
                     b"Address: Whe home is 678<br>")
            elif n.startswith("*(") or "(sentinel" in n:
                b = b"LDAP query results:<br>"   # matches nothing
            elif n and n != "sentinelbase" and n != "sentinel-vr23-base" and "*" not in n:
                b = (b"LDAP query results:<br>Record found with name Ms Bar<br>"
                     b"Address: The streetz 4 Ms bar<br>")
            else:
                b = b"LDAP query results:<br>"
            self.send_response(200); self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)
    port = 8861
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cfg = ScanConfig(allow_private=True, max_pages=5, timeout=5, seed="gtp06b",
                         browser=False, oast=None)
        rep = SentinelScanner(f"http://127.0.0.1:{port}", cfg).run()
        lds = [f for f in rep["findings"]
               if f["type"] == "ldap_injection" and f.get("status") == "verified"]
        assert lds, ("RED: ldap candidate died at VR-23 (the *(marker) wildcard matched "
                      "zero records)", [(f["type"], f.get("status")) for f in rep["findings"]])
        v = lds[0].get("verification", {})
        assert v.get("passed") and "wildcard" in (v.get("method") or ""), v
    finally:
        srv.shutdown(); srv.server_close()


@case
def unit_gtp07b_secure_cookie_path_trap():
    """GTP-07b: the Secure-attribute check must be on the Set-Cookie ATTRIBUTE
    TOKENS — the Path VALUE '/securecookie-00/...' contains the substring
    'secure' (the OWASP Benchmark category's own name) and the whole-string
    check skipped EVERY test as 'protected' (0 candidates on 36 live tests)."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlsplit
    from sentinel.orchestrator import SentinelScanner, ScanConfig

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            u = urlsplit(self.path)
            if u.path == "/":
                b = b'<a href="/securecookie-00/page">s</a><a href="/plain/page">p</a>'
                self.send_response(200); self.send_header("Content-Length", str(len(b)))
                self.end_headers(); self.wfile.write(b)
                return
            if u.path == "/securecookie-00/page":
                # VULNERABLE shape: no Secure attribute — but the Path VALUE
                # contains 'securecookie' (substring 'secure' trap)
                self.send_response(200)
                self.send_header("Set-Cookie", "SomeCookie=tokenvalue123; "
                                 "Path=/benchmark/securecookie-00/page; HttpOnly; SameSite=Strict")
            else:
                # PROTECTED twin: bare 'secure' attribute token present
                self.send_response(200)
                self.send_header("Set-Cookie", "OtherCookie=tokenvalue123; "
                                 "Path=/plain/page; Secure; HttpOnly; SameSite=Strict")
            b = b"page"
            self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)
    port = 8862
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cfg = ScanConfig(allow_private=True, max_pages=5, timeout=5, seed="gtp07b",
                         browser=False, oast=None)
        rep = SentinelScanner(f"http://127.0.0.1:{port}", cfg).run()
        scs = [f for f in rep["findings"]
               if f["type"] == "secure_cookie" and f.get("status") == "verified"]
        assert scs, ("RED: the Path-contains-secure trap suppressed the real finding",
                      [f["type"] for f in rep["findings"] if f.get("status") == "verified"])
        assert any("securecookie-00" in f["url"] for f in scs), [f["url"] for f in scs]
        assert not any("/plain/page" in f["url"] for f in scs), \\
            "FP: the Secure-attribute twin fired"
    finally:
        srv.shutdown(); srv.server_close()


@case
def unit_gtp08b_trustbound_context_window():
    """GTP-08b: the bare reflection differential fired on EVERY reflective
    page (285 candidates, 27 right-class, 62 cross-class FPs live). The
    marker must sit within a bounded window of a session/storage CONTEXT
    phrase; a reflect-only page must stay silent."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qs, urlsplit
    from sentinel.orchestrator import SentinelScanner, ScanConfig

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            u = urlsplit(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
            if u.path == "/":
                b = b'<a href="/store?key=x">s</a><a href="/echo?key=x">e</a>'
                self.send_response(200); self.send_header("Content-Length", str(len(b)))
                self.end_headers(); self.wfile.write(b)
                return
            k = q.get("key", "")
            if u.path == "/store":
                b = (f"Item: '{k}' with value: '10340' saved in session.").encode()
            else:
                b = (f"you typed: {k}").encode()
            self.send_response(200); self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)
    port = 8863
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cfg = ScanConfig(allow_private=True, max_pages=5, timeout=5, seed="gtp08b",
                         browser=False, oast=None)
        rep = SentinelScanner(f"http://127.0.0.1:{port}", cfg).run()
        tbs = [f for f in rep["findings"]
               if f["type"] == "trust_bound" and f.get("status") == "verified"]
        assert tbs, ("RED: the session-store trustbound page was not found",
                      [f["type"] for f in rep["findings"] if f.get("status") == "verified"])
        assert any("/store" in f["url"] for f in tbs), [f["url"] for f in tbs]
        assert not any("/echo" in f["url"] for f in tbs), \\
            "FP: the reflect-only page (no session context) fired as trust_bound"
    finally:
        srv.shutdown(); srv.server_close()


@case
def unit_owsp36_cookie_payload_encoding():
    """OWSP-36: cookie VALUES carrying battery payloads (spaces, ';', '$((')
    must be percent-encoded in the Cookie header — the raw form breaks at
    the first ';' and the servlet truncates the value (proven live on the
    Benchmark: cmdi on a cookie-channel sink needed the encoded form)."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qs, urlsplit
    from sentinel.core import Endpoint, Parameter, ParamLocation, ScopeRule, EventBus
    from sentinel.http_engine import RequestEngine, RequestMutation

    SEEN = []
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            if n:
                self.rfile.read(n)
            ck = self.headers.get("Cookie", "")
            SEEN.append(ck)
            # the servlet URLDecoder.decode's the cookie value (Benchmark shape)
            from urllib.parse import unquote
            val = ""
            for part in ck.split(";"):
                if "=" in part:
                    nm, v = part.strip().split("=", 1)
                    if nm == "BenchmarkTestX":
                        val = unquote(v)
            out = ""
            if val.startswith("FOO=echo "):
                arg = val[9:]
                if arg.startswith("$((") and arg.endswith("))"):
                    try:
                        out = str(eval(arg[3:-2]))
                    except Exception:
                        out = ""
                else:
                    out = arg
            b = (f"orig:<br>{out}<br>").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)

    port = 8864
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        eng = RequestEngine(scope=ScopeRule(allow_private=True), bus=EventBus("owsp36"),
                            timeout=5)
        ep = Endpoint(url=f"http://127.0.0.1:{port}/x", method="POST")
        ep.parameters = [Parameter("BenchmarkTestX", ParamLocation.COOKIE, "x")]
        r1 = eng.send(RequestMutation(endpoint=ep, param_name="BenchmarkTestX",
                                      param_value="x; echo $((6*7))", note="owsp36-raw"))
        assert r1 is not None and not r1.error
        assert "42" in (r1.body or ""), ("RED: the raw cookie value was truncated at the "
                                          "first ';' — payload never reached the servlet",
                                          SEEN)
        hdr = SEEN[-1]
        assert "%3B" in hdr or "%3b" in hdr, ("cookie payload not percent-encoded", hdr)
        assert " " not in hdr.split("BenchmarkTestX=")[-1].split(";")[0], hdr
    finally:
        srv.shutdown(); srv.server_close()

'''

anchor = "\ndef main():"
assert anchor in src
src = src.replace(anchor, BATCH2 + "\ndef main():", 1)
open(P, "w").write(src)
print("batch2 appended: gtp05b, gtp06b, gtp07b, gtp08b, owsp36")

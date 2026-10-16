#!/usr/bin/env python3
"""Append GTP round-2 discriminating tests to build-v430/tests/run_tests.py.
The RED state is the recorded round-1 live measurement
(eval_v430_gtp_round1.json: 0/133 pathtraver with 151 verifier-rejected
candidates, 0/36 securecookie, 1/15 xpathi, 62 cross-class FPs, 108/126
cmdi fn, 94 sqli fn); these tests pin the GREEN behavior."""
import re

P = "/home/z/my-project/build-v430/tests/run_tests.py"
src = open(P).read()

BATCH1 = '''

@case
def unit_gtp03b_entity_encoded_marker():
    """GTP-03b: ESAPI-encoded file-content echoes — the marker check must run
    on the entity-normalized view ('root&#x3a;x&#x3a;0&#x3a;0&#x3a;' must match
    'root:x:0:0:'). Pre-fix the raw body never contained the literal marker
    and the file_marker family was structurally silent on the whole class."""
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
                b = b'<a href="/read?file=a.txt">r</a>'
                self.send_response(200); self.send_header("Content-Length", str(len(b)))
                self.end_headers(); self.wfile.write(b)
                return
            f = q.get("file", "")
            if "../" in f and f.endswith("passwd"):
                # ESAPI shape: every ':' '/' HTML-encoded as &#x3a; / &#x2f;
                b = (b"The beginning of file: &#x2f;home&#x2f;..&#x2f;etc&#x2f;passwd is:\\n\\n"
                     b"root&#x3a;x&#x3a;0&#x3a;0&#x3a;root&#x3a;&#x2f;root&#x3a;&#x2f;bin&#x2f;bash\\n"
                     b"daemon&#x3a;x&#x3a;1&#x3a;1&#x3a;daemon&#x3a;&#x2f;usr&#x2f;sbin&#x3a;&#x2f;nologin\\n")
            else:
                b = b"cannot read " + f.encode()
            self.send_response(200); self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)
    port = 8853
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cfg = ScanConfig(allow_private=True, max_pages=5, timeout=5, seed="gtp03b",
                         browser=False, oast=None)
        rep = SentinelScanner(f"http://127.0.0.1:{port}", cfg).run()
        travs = [f for f in rep["findings"]
                 if f["type"] == "path_traversal" and f.get("status") == "verified"]
        assert travs, ("RED: the entity-encoded passwd leak was not found",
                       [f["type"] for f in rep["findings"] if f.get("status") == "verified"])
        assert any("file_marker" in {e.get("kind") for e in f.get("evidence", [])}
                   for f in travs), "expected a file_marker finding"
    finally:
        srv.shutdown(); srv.server_close()


@case
def unit_gtp03bv_exists_oracle_verify_replay():
    """GTP-03b(vr): the exists_oracle family must SURVIVE verification —
    pre-fix every candidate fell into the local-fixture secret.txt variants
    and died (151/151 rejected on the round-1 live scan). The verifier now
    replays a FRESH known-vs-missing pair at a different depth."""
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
                b = b'<a href="/stat?file=a.txt">s</a>'
                self.send_response(200); self.send_header("Content-Length", str(len(b)))
                self.end_headers(); self.wfile.write(b)
                return
            f = q.get("file", "")
            # blind exists oracle: known file -> big body; missing -> small body;
            # content NEVER echoed (the exists-only sink class)
            up = f.count("../")
            if up >= 6 and f.endswith("passwd"):
                b = (f"Access to file: '{f}' created. And file already exists. "
                     f"stat: size=2367 mode=0644 owner=root inode=999993").encode()
            elif up >= 6 and "sentinel-miss" in f:
                b = b"Access to file created. But file doesn't exist yet."
            else:
                b = b"Access to file created. But file doesn't exist yet."
            self.send_response(200); self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)
    port = 8854
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cfg = ScanConfig(allow_private=True, max_pages=5, timeout=5, seed="gtp03bv",
                         browser=False, oast=None)
        rep = SentinelScanner(f"http://127.0.0.1:{port}", cfg).run()
        travs = [f for f in rep["findings"]
                 if f["type"] == "path_traversal" and f.get("status") == "verified"]
        assert travs, ("RED: exists_oracle candidate died at verification",
                       [(f["type"], f.get("status")) for f in rep["findings"]
                        if f["type"] == "path_traversal"])
        assert any("exists_oracle" in {e.get("kind") for e in f.get("evidence", [])}
                   for f in travs)
        v = travs[0].get("verification", {})
        assert v.get("passed") and "exists" in (v.get("method") or ""), v
    finally:
        srv.shutdown(); srv.server_close()


@case
def unit_gtp04b_env_array_cmdi():
    """GTP-04b(a): ENV-ARRAY sinks — exec(cmd, envp): the payload rides the
    ENVIRONMENT (the stock insecureCmd.sh `eval $FOO`). The battery must send
    FOO=<expr> forms; FOO=echo $((6*7)) computes 42 while FOO=echo <literal>
    stays clean."""
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
                b = b'<a href="/env?cmd=x">e</a>'
                self.send_response(200); self.send_header("Content-Length", str(len(b)))
                self.end_headers(); self.wfile.write(b)
                return
            c = q.get("cmd", "")
            # simulate insecureCmd.sh: the FOO env var is eval'd
            if c.startswith("FOO="):
                expr = c[4:]
                if "$((" in expr and "))" in expr:
                    try:
                        val = str(eval(expr.replace("$((", "(").replace("))", ")")))
                    except Exception:
                        val = ""
                    b = (f"Here is the standard output of the command:<br>"
                         f"Your original string:<br>{val}<br>Your string reversed value is:"
                         f"<br>{expr[::-1]}<br>").encode()
                else:
                    b = (f"Here is the standard output of the command:<br>"
                         f"Your original string:<br>{expr}<br>Your string reversed value is:"
                         f"<br>{expr[::-1]}<br>").encode()
            else:
                b = b"static page no commands here"
            self.send_response(200); self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)
    port = 8855
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cfg = ScanConfig(allow_private=True, max_pages=5, timeout=5, seed="gtp04b",
                         browser=False, oast=None)
        rep = SentinelScanner(f"http://127.0.0.1:{port}", cfg).run()
        cmdis = [f for f in rep["findings"]
                 if f["type"] == "command_injection" and f.get("status") == "verified"]
        assert cmdis, ("RED: the FOO= env-array battery never fired",
                       [f["type"] for f in rep["findings"] if f.get("status") == "verified"])
        assert any("env_arithmetic" in {e.get("kind") for e in f.get("evidence", [])}
                   for f in cmdis), "expected env_arithmetic evidence"
        v = cmdis[0].get("verification", {})
        assert v.get("passed"), v
    finally:
        srv.shutdown(); srv.server_close()


@case
def unit_gtp04b_direct_exec_cmdi():
    """GTP-04b(b): DIRECT-EXEC sinks — the value IS argv (no shell): 'echo
    <canary>' as the whole value must produce STANDALONE canary output
    (canary in body, 'echo <canary>' text absent). A pure reflection must
    NOT fire (it carries the full payload text)."""
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
                b = b'<a href="/run?cmd=x">r</a><a href="/refl?cmd=x">f</a>'
                self.send_response(200); self.send_header("Content-Length", str(len(b)))
                self.end_headers(); self.wfile.write(b)
                return
            c = q.get("cmd", "")
            if u.path == "/run":
                # direct exec: the value IS argv[0..n]; echo is a real binary
                parts = c.split(" ")
                if parts[0] == "echo" and len(parts) > 1:
                    b = ("stdout of the command:<br>" + " ".join(parts[1:]) + "<br>").encode()
                else:
                    b = b"exec failed: not found"
            else:
                # pure reflection — the FP trap: echoes the WHOLE param text
                b = ("you said: " + c).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)
    port = 8856
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cfg = ScanConfig(allow_private=True, max_pages=5, timeout=5, seed="gtp04bd",
                         browser=False, oast=None)
        rep = SentinelScanner(f"http://127.0.0.1:{port}", cfg).run()
        cmdis = [f for f in rep["findings"]
                 if f["type"] == "command_injection" and f.get("status") == "verified"]
        assert cmdis, "RED: the direct-exec family never fired on /run"
        assert any("/run" in f["url"] for f in cmdis), [f["url"] for f in cmdis]
        assert any("argv_echo" in {e.get("kind") for e in f.get("evidence", [])}
                   for f in cmdis), "expected argv_echo evidence"
        # the reflection trap must stay silent
        assert not any("/refl" in f["url"] for f in cmdis), \\
            "FP: the pure-reflection page fired as command injection"
    finally:
        srv.shutdown(); srv.server_close()


@case
def unit_gtp11_jdbc_error_signature():
    """GTP-11: the JDBC 500 surface — java.sql.SQLSyntaxErrorException with
    HSQLDB's 'unexpected token: ... in statement [...]' must route to
    sql_injection (db_error oracle). Pre-fix no signature existed."""
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
                b = b'<a href="/call?name=x">c</a>'
                self.send_response(200); self.send_header("Content-Length", str(len(b)))
                self.end_headers(); self.wfile.write(b)
                return
            n = q.get("name", "")
            if "'" in n:
                body = ("<html><body>Exception Report Message "
                        "java.sql.SQLSyntaxErrorException: unexpected token: "
                        + n + " in statement [ CALL " + n + " ]</body></html>").encode()
                self.send_response(500)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)
                return
            b = b"<html><body>results for " + n.encode() + " (12 rows)</body></html>"
            self.send_response(200); self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)
    port = 8857
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cfg = ScanConfig(allow_private=True, max_pages=5, timeout=5, seed="gtp11",
                         browser=False, oast=None)
        rep = SentinelScanner(f"http://127.0.0.1:{port}", cfg).run()
        sqls = [f for f in rep["findings"]
                if f["type"] == "sql_injection" and f.get("status") == "verified"]
        assert sqls, ("RED: the java.sql.SQLSyntaxErrorException 500 never matched",
                      [f["type"] for f in rep["findings"] if f.get("status") == "verified"])
        ev = {e.get("kind") for f in sqls for e in f.get("evidence", [])}
        assert any("db_error" in k for k in ev), ev
    finally:
        srv.shutdown(); srv.server_close()

'''

anchor = "\ndef main():"
assert anchor in src
src = src.replace(anchor, BATCH1 + "\ndef main():", 1)
open(P, "w").write(src)
print("batch1 appended: gtp03b, gtp03bv, gtp04b, gtp04bd, gtp11")

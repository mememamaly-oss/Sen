@case
def unit_sq2_callable_sink_controls():
    """SQ-2 (sqli recall round, live-caught on the OWASP Benchmark): 27+4 of
    the 65 sqli FNs sink into a JDBC CallableStatement (`{call <param>}`,
    prepareCall) — on HSQLDB a quote payload AND the doubled-quote pair
    control BOTH die as SQLSyntaxErrorException 500s (live-proven on
    BenchmarkTest00008/01302/01712/00996: 1' -> 500 'malformed string',
    1'' -> 500 'unexpected token'), so both error oracles (db_error pair
    control + DETECT-04 status pair control) are structurally dead on the
    entire callable family — value, header, cookie and query channels
    alike. The callable-aware control: a quote-free VALUE EXPRESSION
    (base-1) stays 200 (live: `{call 1-1}` evaluates fine while `{call 1'}`
    breaks) — the db_error oracle fires when the quote carries a DB-error
    signature, the base is clean, and AT LEAST ONE valid-SQL control
    ('' or -1) is clean. The degenerate always-erroring surface (OWSP-12:
    500-with-SQL-text on EVERY payload) must stay silent — both controls
    dirty."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qs, urlsplit
    from sentinel.orchestrator import SentinelScanner, ScanConfig

    def callable_answer(v):
        # the HSQLDB {call ...} landscape, live-measured on BenchmarkTest00008
        if v == "1" or v == "1-1":
            return 200, b"<html><body><p>Your results are:<br>1<br></p></body></html>"
        if v == "1''":
            return 500, (b"java.sql.SQLSyntaxErrorException: unexpected token:  in "
                         b"statement [ CALL 1'' ]")
        if "'" in v:
            return 500, (b"java.sql.SQLSyntaxErrorException: malformed string: ' in "
                         b"statement [ CALL ]")
        return 200, b"<html><body><p>Your results are:<br>1<br></p></body></html>"

    def degenerate_answer(v):
        # the OWSP-12 negative: SQL-error-text on EVERY payload (broken CALL shape)
        return 500, b"java.sql.SQLSyntaxErrorException: unexpected token: in statement"

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _reply(self, code, b):
            self.send_response(code); self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)
        def _route(self, fn):
            u = urlsplit(self.path)
            if u.path == "/":
                self._reply(200, (
                    '<a href="/sqli-00/BenchmarkTest00008?BenchmarkTest00008=1">a</a> '
                    '<a href="/degenerate/BenchmarkTest00009?BenchmarkTest00009=1">d</a>').encode())
                return
            q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
            last = u.path.rstrip("/").split("/")[-1]
            fn = degenerate_answer if "degenerate" in u.path else callable_answer
            code, b = fn(q.get(last, "1"))
            self._reply(code, b)
        def do_GET(self): self._route(callable_answer)
        def do_POST(self): self._route(callable_answer)

    port = 8907
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cfg = ScanConfig(allow_private=True, max_pages=6, timeout=5, seed="sq2",
                         browser=False, oast=None)
        rep = SentinelScanner(f"http://127.0.0.1:{port}", cfg).run()
        sqls = [f for f in rep["findings"]
                if f["type"] == "sql_injection" and f.get("status") == "verified"
                and "/sqli-00/" in f.get("url", "")]
        assert sqls, ("RED: the callable-sink family (pair-quote control dead) "
                      "found nothing", [f["type"] for f in rep["findings"]])
        assert not [f for f in rep["findings"]
                    if f["type"] == "sql_injection" and f.get("status") == "verified"
                    and "degenerate" in f.get("url", "")], \
            "FP: the always-erroring surface (SQL text on every payload) fired"
    finally:
        srv.shutdown(); srv.server_close()

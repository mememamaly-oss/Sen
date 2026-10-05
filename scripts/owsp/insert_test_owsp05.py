#!/usr/bin/env python3
"""Insert OWSP-05 test into tests/run_tests.py (before main())."""
PATH = "/home/z/my-project/build-v423/tests/run_tests.py"
TEST = '''

@case
def unit_owsp05_browser_dom_submit_controls():
    """OWSP-05 (OWASP campaign, live-caught on WrongSecrets 1.8.1): the browser
    engine's DOM form extraction (querySelectorAll in _FORM_JS) excluded
    input[type=submit] AND never queried <button> at all — every browser-
    discovered POST surface lacked the flow-control pair and 405'd at the
    route's params filter with a wrong-session token (312 dead requests on
    13 endpoints, live-measured). The DOM extraction must capture the FIRST
    name+value submit control (input OR button), report it as submitctl, and
    the endpoint builder must mark it flow_control."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from sentinel.core import ScopeRule, EventBus
    from sentinel.http_engine import RequestEngine
    from sentinel.browser import BrowserEngine, browser_available
    if not browser_available():
        raise AssertionError("playwright/chromium required for this gate")

    PAGE = b"""<html><body>
<form action="/submit" method="post">
<input type="text" name="note" value=""/>
<input type="hidden" name="_csrf" value="tok1"/>
<input type="submit" name="viainput" value="go"/>
<button type="submit" name="action" value="submit">Go</button>
<button type="button" name="clearbtn" value="x">Clear</button>
</form></body></html>"""

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(PAGE)))
            self.end_headers()
            self.wfile.write(PAGE)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        scope = ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True)
        eng = RequestEngine(scope, EventBus("run-owsp05"), timeout=5.0)
        be = BrowserEngine(eng, timeout=5.0)
        r = be.render(base + "/")
        assert r, "render must succeed"
        forms = r.get("forms") or []
        assert forms, f"DOM forms must be extracted; got {r.keys()}"
        f0 = forms[0]
        names = [n for n, _v in f0["params"]]
        assert "note" in names and "_csrf" in names, names
        assert "action" in names, (
            f"RED: the DOM extraction missed the submit-button pair (got {names})")
        assert f0.get("submitctl") in ("viainput", "action"), f0.get("submitctl")
        assert "clearbtn" not in names, "type=button controls are never submitted"
        eps = be.render_merge([base + "/"], "127.0.0.1", {})
        posts = [e for e in eps if (e.method or "GET").upper() == "POST"]
        assert posts, "render_merge must produce the POST endpoint"
        fc = [p for p in posts[0].parameters if p.flow_control]
        assert fc and fc[0].name == f0["submitctl"], (
            "RED: the DOM endpoint does not mark the submit control flow_control")
    finally:
        srv.shutdown(); srv.server_close()

'''
src = open(PATH, encoding="utf-8").read()
anchor = "\ndef main():"
assert anchor in src and "unit_owsp05" not in src
src = src.replace(anchor, TEST + anchor, 1)
open(PATH, "w", encoding="utf-8").write(src)
print("inserted unit_owsp05_browser_dom_submit_controls")

#!/usr/bin/env python3
"""Insert OWSP-03 test into tests/run_tests.py (before main())."""
PATH = "/home/z/my-project/build-v423/tests/run_tests.py"
TEST = '''

@case
def unit_owsp03_flow_control_never_probed():
    """OWSP-03 (OWASP campaign, live-caught on WrongSecrets 1.8.1): after OWSP-01
    made submit-button pairs reachable, the planner classified them GENERIC and
    probed them — replacing action=submit with a payload, so every such probe
    405'd at the route's params filter (~1200 uniform-405 requests, half the
    battery, on 13 endpoints). Button pairs are FLOW CONTROL: carried verbatim
    like CSRF tokens, never an injection target. plan_for() must yield entries
    for the sibling params only, and every detector's candidates() must never
    mutate a flow_control param."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlsplit, parse_qs
    from sentinel.core import ScopeRule, EventBus
    from sentinel.http_engine import RequestEngine
    from sentinel.discovery import DiscoveryEngine
    from sentinel.detect import plan_for, ACTIVE_DETECTORS

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _send(self, code, body=b""):
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body: self.wfile.write(body)
        def do_GET(self):
            if self.path == "/":
                self._send(200, b'<html><body><a href="/form">f</a></body></html>')
            elif urlsplit(self.path).path == "/form":
                self._send(200, (b'<form action="/submit" method="post">'
                                 b'<input type="text" name="note" value=""/>'
                                 b'<button type="submit" name="action" value="submit">Go</button>'
                                 b'</form>'))
            else:
                self._send(404)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        scope = ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True)
        eng = RequestEngine(scope, EventBus("run-owsp03"), timeout=5.0)
        disc = DiscoveryEngine(eng, max_pages=3)
        endpoints, _js, _st = disc.crawl(base)
        eps = [e for e in (endpoints if isinstance(endpoints, list) else endpoints.values())
               if e.method == "POST"]
        assert eps, "POST endpoint must be discovered"
        ep = eps[0]
        act = next(p for p in ep.parameters if p.name == "action")
        note = next(p for p in ep.parameters if p.name == "note")
        assert act.flow_control, "RED: the submit-button pair is not marked flow control"
        assert not note.flow_control, "normal fields must stay probed"

        planned_params = {id(p["param"]) for p in plan_for(ep)}
        assert all(p["param"].name != "action" for p in plan_for(ep)), (
            "RED: plan_for still schedules batteries against the flow-control param")
        assert any(p["param"].name == "note" for p in plan_for(ep)), (
            "sibling params must still be fully planned")

        for cls in ACTIVE_DETECTORS:
            det = cls(eng, EventBus("run-owsp03"))
            try:
                cands = det.candidates(ep)
            except Exception:
                continue
            for c in cands:
                m = c[1] if isinstance(c, tuple) else c
                assert getattr(m, "param_name", None) != "action", (
                    f"RED: {det.name} mutates the flow-control param")
    finally:
        srv.shutdown(); srv.server_close()

'''
src = open(PATH, encoding="utf-8").read()
anchor = "\ndef main():"
assert anchor in src and "unit_owsp03" not in src
src = src.replace(anchor, TEST + anchor, 1)
open(PATH, "w", encoding="utf-8").write(src)
print("inserted unit_owsp03_flow_control_never_probed")

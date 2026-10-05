#!/usr/bin/env python3
"""Insert OWSP-01 test into tests/run_tests.py (before main())."""
import io

PATH = "/home/z/my-project/build-v423/tests/run_tests.py"
TEST = '''

@case
def unit_owsp01_button_form_params():
    """OWSP-01 (OWASP campaign, live-caught on WrongSecrets 1.8.1): the form
    parser captured <input>/<textarea>/<select> but NOT <button name= value=>
    submit controls. WrongSecrets routes POST /challenge/{name} behind a
    Spring params="action=submit" filter whose action pair comes from the
    submit BUTTON — every engine probe answered 405 and the whole active
    battery was silently absorbed (candidates=0, no coverage note). HTML form
    submission includes the activated submit button's name=value pair; the
    parser must capture it (and only submit-type buttons), and the rendered
    probes must carry it so the surface is reachable at all. Red pre-fix on
    both halves, green post."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlsplit, parse_qs
    from sentinel.core import ScopeRule, EventBus
    from sentinel.http_engine import RequestEngine
    from sentinel.discovery import DiscoveryEngine, _LinkParser

    # ---- Part A: parser captures submit-button pairs (and only those)
    html = ('<form action="/challenge/challenge-1" method="post">'
            '<input type="hidden" name="_csrf" value="tok123"/>'
            '<input type="text" id="a" name="solution" value=""/>'
            '<button class="btn" type="submit" name="action" value="submit">Go</button>'
            '<button type="button" name="clearbtn" value="x">Clear</button>'
            '<button name="plainbtn">NoValue</button>'
            '</form>')
    hp = _LinkParser(); hp.feed(html)
    assert len(hp.forms) == 1, hp.forms
    names = [n for n, _v in hp.forms[0]["params"]]
    assert "solution" in names and "_csrf" in names, names
    assert "action" in names, (
        f"RED: submit-button pair missing from form params (got {names}) — "
        "the Spring params=-filtered surface is unreachable")
    av = dict(hp.forms[0]["params"]).get("action")
    assert av == "submit", av
    assert "clearbtn" not in names, "type=button controls are never submitted"
    assert "plainbtn" not in names, "nameless-value buttons carry no pair"

    # ---- Part B: live mini-app mirroring the WrongSecrets route shape
    RECEIVED = []   # (path, dict-of-body)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _send(self, code, body=b"", headers=None):
            self.send_response(code)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body: self.wfile.write(body)
        def do_GET(self):
            if self.path == "/":
                self._send(200, (
                    b'<html><body><a href="/challenge/challenge-1">c1</a></body></html>'))
            elif urlsplit(self.path).path == "/challenge/challenge-1":
                self._send(200, (
                    b'<form action="/challenge/challenge-1" method="post">'
                    b'<input type="hidden" name="_csrf" value="tok123"/>'
                    b'<input type="text" name="solution" value=""/>'
                    b'<button type="submit" name="action" value="submit">Go</button>'
                    b'</form>'))
            else:
                self._send(404)
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n).decode() if n else ""
            q = {k: v[0] for k, v in parse_qs(body, keep_blank_values=True).items()}
            RECEIVED.append((self.path, q))
            if q.get("action") != "submit":
                # Spring: route params filter does not match -> 405, surface dead
                self._send(405, b"wrong way")
                return
            sol = q.get("solution", "")
            self._send(200, f"<html><body>PROCESSED {sol} echo</body></html>".encode())

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        scope = ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True)
        eng = RequestEngine(scope, EventBus("run-owsp01"), timeout=5.0)
        disc = DiscoveryEngine(eng, max_pages=3)
        endpoints, _js, _st = disc.crawl(base)
        posts = [e for e in (endpoints if isinstance(endpoints, list) else endpoints.values())
                 if e.method == "POST" and "challenge-1" in e.url]
        assert posts, "POST form endpoint must be discovered"
        assert any(p.name == "action" for p in posts[0].parameters), (
            "RED: the discovered POST endpoint lacks the button-derived param")

        # fire the engine's own sqli battery against the discovered endpoint
        from sentinel.detect import SQLiDetector
        det = SQLiDetector(eng, EventBus("run-owsp01"))
        cands = det.candidates(posts[0])
        assert cands, "battery must generate probes for the solution param"
        sent_ok = 0
        for strat, m in cands:
            r = eng.send(m)
            if r.error or r.status == 0:
                continue
            if r.status == 200 and "PROCESSED" in (r.body or ""):
                sent_ok += 1
        assert sent_ok > 0, (
            "RED: every battery probe was absorbed by the 405 route filter — "
            f"received={RECEIVED[:3]} — the surface exists but the engine "
            "cannot reach it")
        assert any(q.get("action") == "submit" for _p, q in RECEIVED), (
            "RED: no engine request carried the submit-button pair")
    finally:
        srv.shutdown(); srv.server_close()

'''

src = open(PATH, encoding="utf-8").read()
anchor = "\ndef main():"
assert anchor in src and "unit_owsp01" not in src
src = src.replace(anchor, TEST + anchor, 1)
open(PATH, "w", encoding="utf-8").write(src)
print("inserted unit_owsp01_button_form_params before main()")

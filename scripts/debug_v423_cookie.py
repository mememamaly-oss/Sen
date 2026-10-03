#!/usr/bin/env python3
"""Debug the gruyere-shaped stored-XSS flow (GET form + cookie render)."""
import sys, threading
sys.path.insert(0, "/home/z/my-project/build-v423")
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from sentinel.core import (Endpoint, Parameter, ParamLocation, ScopeRule, EventBus,
                           DiscoverySource)
from sentinel.http_engine import RequestEngine
from sentinel.detect import StoredXSSDetector, fresh_form

def _menu(headers):
    raw_uid = ""
    ck = headers.get("Cookie", "")
    print(f"  [APP] cookie header: {ck!r}")
    if "GRUYERE=" in ck:
        rest = ck.split("GRUYERE=", 1)[1]
        raw_uid = rest.split("|", 2)[1] if rest.count("|") >= 2 else ""
    return (f"<html><body><div class='menu-right'><span class='menu-user'>{raw_uid}</span></div>"
            f"<form action='/inst/saveprofile' method='GET'>"
            f"<input type='hidden' name='action' value='new'>"
            f"<input type='text' name='uid' value=''>"
            f"<input type='password' name='pw' value=''>"
            f"<input type='hidden' name='is_author' value='True'>"
            f"<input type='submit' value='Create account'></form></body></html>")

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"  [APP] GET {self.path}")
        u = urlparse(self.path)
        if u.path == "/inst/":
            body = _menu(self.headers); self.send_response(200)
        elif u.path == "/inst/saveprofile":
            q = parse_qs(u.query, keep_blank_values=True)
            uid = q.get("uid", [""])[0]
            body = _menu(self.headers); self.send_response(200)
            if q.get("action", [""])[0] == "new" and uid:
                self.send_header("Set-Cookie", f"GRUYERE=1|{uid}||author")
        else:
            body = "<html>404</html>"; self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())
    def log_message(self, *a): pass

srv = ThreadingHTTPServer(("127.0.0.1", 8812), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

eng = RequestEngine(ScopeRule(allowed_hosts=["127.0.0.1"], allow_private=True),
                    EventBus("dbg2"), timeout=3.0)
ep = Endpoint(url="http://127.0.0.1:8812/inst/saveprofile", method="GET",
              parameters=[Parameter("action", ParamLocation.QUERY, value="new"),
                          Parameter("uid", ParamLocation.QUERY),
                          Parameter("pw", ParamLocation.QUERY),
                          Parameter("is_author", ParamLocation.QUERY, value="True")],
              source=DiscoverySource.CRAWL_FORM,
              tags=["form_origin:http://127.0.0.1:8812/inst/"])
det = StoredXSSDetector(eng, EventBus("dbg2"))
print("content_form:", det._content_form(ep))
o, form = fresh_form(eng, det._origin_of(ep), ep)
print("fresh_form -> None?", form is None)
if form: print("  fields:", form["fields"], "| action:", form["_action_abs"], "| method:", form["method"])
print("== detector run ==")
cands = det.run(ep)
print("candidates:", [(c.type, c.parameter) for c in cands])
for c in cands:
    for e in c.evidence:
        print("   ev:", e.kind, "|", e.detail[:130])
srv.shutdown(); srv.server_close()

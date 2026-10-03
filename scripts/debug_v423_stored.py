#!/usr/bin/env python3
"""Debug the v4.2.3 stored-XSS flow against the same mini-app as the unit test."""
import sys, threading
sys.path.insert(0, "/home/z/my-project/build-v423")
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from sentinel.core import (Endpoint, Parameter, ParamLocation, ScopeRule, EventBus,
                           DiscoverySource)
from sentinel.http_engine import RequestEngine
from sentinel.detect import StoredXSSDetector, _StoredFormParser, fresh_form, stored_xss_flow

state = {"vs_counter": 0, "comments": [], "stale_vs_seen": False, "latest_vs": ""}

class H(BaseHTTPRequestHandler):
    def _page(self):
        state["vs_counter"] += 1
        vs = f"VS-{state['vs_counter']:04d}-rnd"
        state["latest_vs"] = vs
        comments = "".join(f'<div class="CommentText">{c}</div>' for c in state["comments"])
        return (f'<html><body><div id="comments">{comments}</div>'
                f'<form action="/Comments.aspx?id=0" method="POST">'
                f'<input type="hidden" name="__VIEWSTATE" value="{vs}">'
                f'<input type="hidden" name="__EVENTTARGET" value="">'
                f'<textarea name="tbComment" rows="4"></textarea>'
                f'<input type="text" name="tbName" value="">'
                f'<input type="submit" value="Post"></form></body></html>')
    def do_GET(self):
        body = self._page()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(n).decode(), keep_blank_values=True)
        print(f"  [APP] POST vs={form.get('__VIEWSTATE',[''])[0][:20]!r} latest={state['latest_vs'][:20]!r} comment={form.get('tbComment',[''])[0][:30]!r}")
        if form.get("__VIEWSTATE", [""])[0] != state["latest_vs"]:
            state["stale_vs_seen"] = True
            self.send_response(500); self.end_headers(); self.wfile.write(b"invalid viewstate")
            return
        state["comments"].append(form.get("tbComment", [""])[0])
        self.send_response(302)
        self.send_header("Location", "/Comments.aspx?id=0")
        self.end_headers()
    def log_message(self, *a): pass

srv = ThreadingHTTPServer(("127.0.0.1", 8811), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

eng = RequestEngine(ScopeRule(allowed_hosts=["127.0.0.1"], allow_private=True),
                    EventBus("dbg"), timeout=3.0)
ep = Endpoint(url="http://127.0.0.1:8811/Comments.aspx?id=0", method="POST",
              parameters=[Parameter("__VIEWSTATE", ParamLocation.BODY, value="VS-STALE"),
                          Parameter("tbComment", ParamLocation.BODY),
                          Parameter("tbName", ParamLocation.BODY)],
              source=DiscoverySource.CRAWL_FORM,
              tags=["form_origin:http://127.0.0.1:8811/Comments.aspx?id=0"])

det = StoredXSSDetector(eng, EventBus("dbg"))
print("content_form:", det._content_form(ep))
print("origin_of:", det._origin_of(ep))
o, form = fresh_form(eng, det._origin_of(ep), ep)
print("fresh_form -> form is None?", form is None, "| origin status:", o.status if o else None)
if form:
    print("  fields:", form["fields"], "| action_abs:", form["_action_abs"])
print("== running flow for tbComment ==")
_o, _s, hits = stored_xss_flow(eng, ep, "tbComment", "<sentinelstore>", det._origin_of(ep))
print("submit resp:", _s.status if _s else None, _s.error if _s else "", "| hits:", [(u, r1.status) for u, r1, r2 in hits])
print("== detector run ==")
cands = det.run(ep)
print("candidates:", [(c.type, c.parameter) for c in cands])
srv.shutdown(); srv.server_close()

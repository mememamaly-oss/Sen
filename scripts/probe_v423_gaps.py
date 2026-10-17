#!/usr/bin/env python3
"""v4.2.3 discrimination probe (supervisor orders 2+3, 2026-10-04).

Runs the SAME five scenarios (the three confirmed IV13 gaps + the two
false-positive mechanisms adjudicated in IV14) through TWO engines:

  1. build-v422 (frozen v4.2.2, imported READ-ONLY — sys.path only,
     zero bytes modified)
  2. build-v423 (v4.2.3: DETECT-16 stored XSS, DETECT-17 URL-path traversal,
     DETECT-15/VR-14 ng script-context, VF-04 PATH-B DB-string requirement)

Scenarios (each reproduces the LIVE mechanism the gap was caught on):
  A comment_form   — testaspnet /Comments.aspx tbComment shape: POST form with
                     a ROTATING __VIEWSTATE; the v4.2.2 reflected battery ships
                     the endpoint's STALE captured viewstate -> 500 -> honest
                     miss (the live gap); v4.2.3 re-fetches the form fresh.
  B get_form_cookie — gruyere /saveprofile uid shape: GET form, submit sets a
                     cookie carrying the raw uid, rendered on the instance home.
  C path_trav      — gruyere /<inst>/..%2f x4 etc%2fpasswd shape (URL path).
  D status_oracle  — testasp Search.asp tfSearch shape: quote->500 (generic,
                     no SQL text), base->200, doubled->200, no boolean oracle.
  E ng_script_fp   — ginandjuice /catalog?searchTerm shape: {{expr}} reflected
                     raw inside a <script> string on an ng-app page, everything
                     else escaped.

Output: build-v423/results/probe_v423_gaps.jsonl (one line per engine+scenario).
The generator never evaluates — it records raw outcomes.
"""
import json, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

OUT = "/home/z/my-project/build-v423/results/probe_v423_gaps.jsonl"


# ------------------------------------------------------------------ scenario servers
def start(port, handler):
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def make_comment_app():
    state = {"n": 0, "comments": [], "latest": ""}
    class H(BaseHTTPRequestHandler):
        def _page(self):
            state["n"] += 1
            state["latest"] = f"VS-{state['n']:04d}"
            body = ('<html><body>' + "".join(f'<div class="CommentText">{c}</div>' for c in state["comments"]) +
                    '<form action="/Comments.aspx?id=0" method="POST">'
                    f'<input type="hidden" name="__VIEWSTATE" value="{state["latest"]}">'
                    '<input type="hidden" name="__EVENTTARGET" value="">'
                    '<textarea name="tbComment"></textarea>'
                    '<input type="text" name="tbName" value="">'
                    '<input type="submit" value="Post"></form></body></html>')
            return body
        def do_GET(self):
            b = self._page(); self.send_response(200)
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b.encode())
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            f = parse_qs(self.rfile.read(n).decode(), keep_blank_values=True)
            if f.get("__VIEWSTATE", [""])[0] != state["latest"]:
                self.send_response(500); self.end_headers(); self.wfile.write(b"invalid viewstate"); return
            state["comments"].append(f.get("tbComment", [""])[0])
            self.send_response(302); self.send_header("Location", "/Comments.aspx?id=0"); self.end_headers()
        def log_message(self, *a): pass
    return H, state


def make_cookie_app():
    def menu(headers):
        uid = ""
        ck = headers.get("Cookie", "")
        if "GRUYERE=" in ck:
            rest = ck.split("GRUYERE=", 1)[1]
            uid = rest.split("|", 2)[1] if rest.count("|") >= 2 else ""
        return (f"<html><body><span class='menu-user'>{uid}</span>"
                "<form action='/inst/saveprofile' method='GET'>"
                "<input type='hidden' name='action' value='new'>"
                "<input type='text' name='uid' value=''>"
                "<input type='password' name='pw' value=''>"
                "<input type='hidden' name='is_author' value='True'>"
                "<input type='submit' value='Create account'></form></body></html>")
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            u = urlparse(self.path)
            if u.path == "/inst/":
                b = menu(self.headers); self.send_response(200)
            elif u.path == "/inst/saveprofile":
                # gruyere-accurate: the saveprofile response does NOT render the
                # uid (live evidence iv13 gruyere_probes.json: raw_markup_reflected
                # false) — only the instance home renders the menu-user span
                q = parse_qs(u.query, keep_blank_values=True)
                b = "<html><body>profile saved</body></html>"; self.send_response(200)
                if q.get("action", [""])[0] == "new" and q.get("uid", [""])[0]:
                    self.send_header("Set-Cookie", f"GRUYERE=1|{q['uid'][0]}||author")
            else:
                b = "404"; self.send_response(404)
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b.encode())
        def log_message(self, *a): pass
    return H


PASSWD = "root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/bin/sh\n"

class PathApp(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/inst/") and "..%2f..%2f..%2f..%2fetc%2fpasswd" in self.path:
            self.send_response(200); self.send_header("Content-Length", str(len(PASSWD)))
            self.end_headers(); self.wfile.write(PASSWD.encode())
        elif self.path in ("/inst/", "/inst/help.gtl", "/"):
            self.send_response(200); self.end_headers(); self.wfile.write(b"<html><a href='/inst/help.gtl'>h</a></html>")
        else:
            self.send_response(404); self.end_headers(); self.wfile.write(b"404")
    def log_message(self, *a): pass


OK_BODY = "<html><body>search results page — 5 hits</body></html>"
ERR_500 = "<html><body>500 - Internal server error.</body></html>"

class StatusOracleApp(BaseHTTPRequestHandler):
    def do_GET(self):
        val = parse_qs(urlparse(self.path).query, keep_blank_values=True).get("x", [""])[0]
        if val == "1''":
            s, b = 200, OK_BODY
        elif "'" in val or '"' in val:
            s, b = 500, ERR_500
        else:
            s, b = 200, OK_BODY
        self.send_response(s); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b.encode())
    def log_message(self, *a): pass


def make_ng_app():
    def esc(v):
        return (v.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                 .replace("'", "\\'").replace('"', '\\"'))
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            val = parse_qs(urlparse(self.path).query, keep_blank_values=True).get("searchTerm", [""])[0]
            b = ('<html><body ng-app="shop">\n<script>\n'
                 f"var searchText = '{esc(val)}';\ndocument.write(searchText);\n"
                 f"</script>\n<div>You searched for {esc(val)}</div>\n</body></html>")
            self.send_response(200); self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b.encode())
        def log_message(self, *a): pass
    return H


# ------------------------------------------------------------------ engine runner
def run_engine(build_dir, out):
    for m in [m for m in list(sys.modules) if m.startswith("sentinel")]:
        del sys.modules[m]
    sys.path.insert(0, build_dir)
    try:
        from sentinel.core import (Endpoint, Parameter, ParamLocation, ScopeRule, EventBus,
                                   FindingStatus, Evidence, DiscoverySource)
        from sentinel.http_engine import RequestEngine
        import sentinel.detect as D
        from sentinel.intel import VerificationEngine

        def eng(): return RequestEngine(ScopeRule(allowed_hosts=["127.0.0.1"], allow_private=True),
                                        EventBus("probe-v423"), timeout=3.0)

        # ---- A: comment form (testaspnet shape)
        H, _st = make_comment_app()
        srv = start(8821, H)
        e1 = eng()
        ep = Endpoint(url="http://127.0.0.1:8821/Comments.aspx?id=0", method="POST",
                      parameters=[Parameter("__VIEWSTATE", ParamLocation.BODY, value="VS-STALE"),
                                  Parameter("tbComment", ParamLocation.BODY),
                                  Parameter("tbName", ParamLocation.BODY)],
                      source=DiscoverySource.CRAWL_FORM,
                      tags=["form_origin:http://127.0.0.1:8821/Comments.aspx?id=0"])
        rec = {"engine": build_dir, "scenario": "A_comment_form_stored_xss"}
        # A.old: the v4.2.2 way — reflected battery on the same endpoint (this is
        # what the LIVE v4.2.1 scan actually did: stale viewstate -> 500 -> miss)
        xd = D.XSSDetector(e1, EventBus("p"))
        old_found = None
        try:
            for item in xd.candidates(ep):
                _s, m = item
                r = e1.send(m)
                c = xd.analyze((ep, ep.param("tbComment")), r)
                if c:
                    old_found = c; break
        except Exception as ex:
            old_found = f"error: {ex}"
        rec["reflected_battery_v422_way"] = (None if old_found is None else
                                             (str(old_found) if isinstance(old_found, str) else
                                              {"type": old_found.type, "status": old_found.status}))
        # A.new: the v4.2.3 stored flow
        if hasattr(D, "StoredXSSDetector"):
            sd = D.StoredXSSDetector(e1, EventBus("p"))
            cands = sd.run(ep)
            if cands:
                out_f = VerificationEngine(e1, EventBus("p")).verify(cands[0], ep)
                rec["stored_flow_v423_way"] = {"type": out_f.type, "param": out_f.parameter,
                                               "status": str(out_f.status),
                                               "method": out_f.verification.method}
            else:
                rec["stored_flow_v423_way"] = "no candidate"
        else:
            rec["stored_flow_v423_way"] = "detector class absent in this build"
        srv.shutdown(); srv.server_close()
        out.append(rec)

        # ---- B: gruyere GET-form cookie shape
        srv = start(8822, make_cookie_app())
        e2 = eng()
        ep = Endpoint(url="http://127.0.0.1:8822/inst/saveprofile", method="GET",
                      parameters=[Parameter("action", ParamLocation.QUERY, value="new"),
                                  Parameter("uid", ParamLocation.QUERY),
                                  Parameter("pw", ParamLocation.QUERY),
                                  Parameter("is_author", ParamLocation.QUERY, value="True")],
                      source=DiscoverySource.CRAWL_FORM,
                      tags=["form_origin:http://127.0.0.1:8822/inst/"])
        rec = {"engine": build_dir, "scenario": "B_get_form_cookie_stored_xss"}
        xd = D.XSSDetector(e2, EventBus("p"))
        old_found = None
        try:
            for item in xd.candidates(ep):
                _s, m = item
                r = e2.send(m)
                c = xd.analyze((ep, ep.param("uid")), r)
                if c:
                    old_found = c; break
        except Exception as ex:
            old_found = f"error: {ex}"
        rec["reflected_battery_v422_way"] = (None if old_found is None else
                                             (str(old_found) if isinstance(old_found, str) else
                                              {"type": old_found.type, "status": old_found.status}))
        if hasattr(D, "StoredXSSDetector"):
            sd = D.StoredXSSDetector(e2, EventBus("p"))
            cands = sd.run(ep)
            if cands:
                out_f = VerificationEngine(e2, EventBus("p")).verify(cands[0], ep)
                rec["stored_flow_v423_way"] = {"type": out_f.type, "param": out_f.parameter,
                                               "status": str(out_f.status),
                                               "method": out_f.verification.method}
            else:
                rec["stored_flow_v423_way"] = "no candidate"
        else:
            rec["stored_flow_v423_way"] = "detector class absent in this build"
        srv.shutdown(); srv.server_close()
        out.append(rec)

        # ---- C: URL-path traversal (gruyere shape)
        srv = start(8823, PathApp)
        e3 = eng()
        rec = {"engine": build_dir, "scenario": "C_url_path_traversal"}
        # C.old: the v4.2.2 param battery on an endpoint with no params
        td = D.TraversalDetector(e3, EventBus("p"))
        rec["param_battery_v422_way"] = {"candidates": len(td.candidates(Endpoint(url="http://127.0.0.1:8823/inst/")))}
        if hasattr(D, "PathTraversalDetector"):
            pd = D.PathTraversalDetector(e3, EventBus("p"))
            cands = pd.run_base("http://127.0.0.1:8823/inst/")
            if cands:
                out_f = VerificationEngine(e3, EventBus("p")).verify(cands[0], None)
                rec["path_battery_v423_way"] = {"type": out_f.type, "url": out_f.endpoint_url,
                                                "status": str(out_f.status),
                                                "method": out_f.verification.method}
            else:
                rec["path_battery_v423_way"] = "no candidate"
        else:
            rec["path_battery_v423_way"] = "detector class absent in this build"
        srv.shutdown(); srv.server_close()
        out.append(rec)

        # ---- D: status-oracle SQLi (tfSearch shape) — the PATH B over-claim
        srv = start(8824, StatusOracleApp)
        e4 = eng()
        from itertools import groupby
        ep = Endpoint(url="http://127.0.0.1:8824/Search",
                      parameters=[Parameter("x", ParamLocation.QUERY, "1")])
        rec = {"engine": build_dir, "scenario": "D_status_oracle_path_b"}
        sq = D.SQLiDetector(e4, EventBus("p"))
        cands = sq.candidates(ep)
        rm = {}
        for pname, grp in groupby(cands, key=lambda t: t[1].param_name):
            for s, m in grp:
                rm[s] = e4.send(m)
        cand = sq.analyze((ep, ep.parameters[0]), rm)
        rec["candidate"] = None if cand is None else {
            "type": cand.type, "kinds": [e.kind for e in cand.evidence]}
        if cand:
            o = VerificationEngine(e4, EventBus("p")).verify(cand, ep)
            rec["verification"] = {"status": str(o.status), "method": o.verification.method,
                                   "confidence": o.verification.confidence,
                                   "notes": o.verification.notes}
        srv.shutdown(); srv.server_close()
        out.append(rec)

        # ---- E: ng-expression in script context (searchTerm shape)
        srv = start(8825, make_ng_app())
        e5 = eng()
        ep = Endpoint(url="http://127.0.0.1:8825/catalog",
                      parameters=[Parameter("searchTerm", ParamLocation.QUERY, "")])
        rec = {"engine": build_dir, "scenario": "E_ng_script_context"}
        xd = D.XSSDetector(e5, EventBus("p"))
        found = None
        for item in xd.candidates(ep):
            _s, m = item
            r = e5.send(m)
            c = xd.analyze((ep, ep.parameters[0]), r)
            if c:
                found = c; break
        rec["candidate"] = None if found is None else {"type": found.type,
                                                       "kinds": [e.kind for e in found.evidence]}
        # verifier ruling on the claim either way (manual find if no candidate)
        target = found if found is not None else None
        if target is None:
            from sentinel.core import Finding
            target = Finding("xss_reflected", 3, ep.url, "searchTerm", "GET",
                             [Evidence("ng_expression_reflection", "script-context ng claim")],
                             status=FindingStatus.CANDIDATE)
            rec["manual_find_used"] = True
        o = VerificationEngine(e5, EventBus("p")).verify(target, ep)
        rec["verification"] = {"status": str(o.status), "method": o.verification.method,
                               "notes": o.verification.notes}
        srv.shutdown(); srv.server_close()
        out.append(rec)
    finally:
        sys.path.remove(build_dir)


if __name__ == "__main__":
    out = []
    for build in ("/home/z/my-project/build-v422", "/home/z/my-project/build-v423"):
        run_engine(build, out)
    with open(OUT, "w") as f:
        for r in out:
            f.write(json.dumps(r) + "\n")
    for r in out:
        print(json.dumps(r))
    print("->", OUT)

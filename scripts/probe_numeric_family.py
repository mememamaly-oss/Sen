#!/usr/bin/env python3
"""DETECT-06 discrimination probe (supervisor order 2, 2026-10-03).

Runs the SAME drifted-state login endpoint (live-caught on
demo.testfire.net/doLogin 2026-10-03: string-quote family neutralized,
numeric-comment family alive) through TWO engines:

  1. build-v421 (frozen v4.2.1, imported READ-ONLY — sys.path only,
     zero bytes modified)  -> expected: NO candidate at all (the live miss)
  2. build-v422 (v4.2.2 with the numeric-comment family) -> expected:
     detector candidate with numeric-OR redirect differential + verifier
     VERIFIED via PATH C' (oracle:ornum-2round)

Output: build-v422/results/probe_numeric_family.jsonl (one line per engine).
The generator never evaluates — it records raw outcomes.
"""
import json, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from itertools import groupby

PORT = 8799
OUT = "results/probe_numeric_family.jsonl"


class H(BaseHTTPRequestHandler):
    """Drifted doLogin: '1'='1' family dead, 'OR 1=1' family alive."""

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        from urllib.parse import parse_qs
        body = parse_qs(self.rfile.read(n).decode())
        uid = body.get("uid", [""])[0]
        passw = body.get("passw", [""])[0]
        if not passw:
            self.send_response(302); self.send_header("Location", "/login"); self.end_headers()
        elif "'1'='1'" in uid or "'1'='2'" in uid:
            self.send_response(302); self.send_header("Location", "/login"); self.end_headers()
        elif "OR 1=1" in uid:
            self.send_response(302); self.send_header("Location", "/bank/main"); self.end_headers()
        else:
            self.send_response(302); self.send_header("Location", "/login"); self.end_headers()

    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"<html>page</html>")

    def log_message(self, *a):
        pass


def run_engine(build_dir):
    """Import the engine under test read-only and run detector+verifier."""
    for mod in [m for m in list(sys.modules) if m.startswith("sentinel")]:
        del sys.modules[mod]
    sys.path.insert(0, build_dir)
    try:
        from sentinel.core import (Endpoint, Parameter, ParamLocation, ScopeRule,
                                   EventBus, FindingStatus)
        from sentinel.http_engine import RequestEngine
        from sentinel.detect import SQLiDetector
        from sentinel.intel import VerificationEngine
        import sentinel.core as core

        srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            eng = RequestEngine(ScopeRule(allowed_hosts=["127.0.0.1"], allow_private=True),
                                EventBus("probe"), timeout=3.0)
            ep = Endpoint(url=f"http://127.0.0.1:{PORT}/doLogin", method="POST",
                          parameters=[Parameter("uid", ParamLocation.BODY),
                                      Parameter("passw", ParamLocation.BODY)])
            det = SQLiDetector(None, EventBus("probe"))
            cands = det.candidates(ep)
            battery = [s for s, _ in cands]
            cand = None
            for pname, grp in groupby(cands, key=lambda t: t[1].param_name):
                grp = list(grp)
                resp_map = {s: eng.send(m) for s, m in grp}
                pobj = next(p for p in ep.parameters if p.name == pname)
                r = det.analyze((ep, pobj), resp_map)
                if r is not None and pname == "uid":
                    cand = r
            rec = {"engine": build_dir, "version": core.VERSION,
                   "battery_has_numeric_family": "ornum_true" in battery,
                   "detector_candidate": cand is not None,
                   "evidence_kinds": [e.kind for e in cand.evidence] if cand else []}
            if cand is not None:
                v = VerificationEngine(eng, EventBus("probe"))
                out = v.verify(cand, ep)
                rec["verifier_status"] = str(out.status)
                rec["verifier_method"] = out.verification.method if out.verification else None
                rec["verifier_notes"] = out.verification.notes if out.verification else None
            else:
                rec["verifier_status"] = None
                rec["verifier_method"] = None
                rec["verifier_notes"] = "no candidate — engine honestly reports nothing (the live doLogin miss)"
            return rec
        finally:
            srv.shutdown(); srv.server_close()
    finally:
        sys.path.remove(build_dir)


def main():
    root = "/home/z/my-project"
    records = [run_engine(f"{root}/build-v421"),
               run_engine(f"{root}/build-v422")]
    with open(f"{root}/build-v422/{OUT}", "w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    for r in records:
        print(json.dumps(r))


if __name__ == "__main__":
    main()

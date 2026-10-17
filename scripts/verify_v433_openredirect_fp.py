#!/usr/bin/env python3
"""RED/GREEN prover for the iv14 sink-context transfer on main v4.3.3.

Round 2026-10-12 (supervisor order: re-apply the previously-proven
open_redirect fix on a branch from origin/main 412d64f, RED/GREEN + full
gate, clean small commit, push to main). The three-shape fixture is the
branch's discriminating scenario (unit_v423_open_redirect_sink_context,
branch iv14/session-round-v423-gap-closure @ 23c4619), preserved verbatim
by the Task-32 supervisor audit.

Three independent verdicts:
  (1) fp_negative  : raw reflection + UNRELATED window.location ~35 chars
                     away -> the detector MUST stay silent. On unfixed
                     v4.3.3 (OWSP-29 200-char proximity window only) this
                     FIRES = the structural FP (expected RED).
  (2) true_positive: value lands INSIDE location.href -> candidate +
                     VERIFIED (no capability loss).
  (3) fp_verify    : a forged body_redirect candidate on the reflection
                     page -> the verifier MUST reject it on replay (on
                     unfixed v4.3.3 it VERIFIES = expected RED).

Usage: verify_v433_openredirect_fp.py [out.json]
  (default out: <repo>/build-v430/results/verify_v433_sinkcontext/
   openredirect_fp_audit.json)
"""
import json, os, sys, threading

HERE = os.path.dirname(os.path.abspath(__file__))
ENG = os.path.join(os.path.dirname(HERE), "build-v430")
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    ENG, "results", "verify_v433_sinkcontext", "openredirect_fp_audit.json")
sys.path.insert(0, ENG)

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from sentinel.http_engine import RequestEngine
from sentinel.core import (ScopeRule, EventBus, Endpoint, Parameter, ParamLocation,
                           Finding, Evidence, Severity, FindingStatus)
from sentinel.detect import RedirectDetector
from sentinel.intel import VerificationEngine

results = {}

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        q = parse_qs(self.rfile.read(n).decode(), keep_blank_values=True).get("note", [""])[0]
        # FP shape: value reflected RAW (XSS-style) in a div, while generic page JS
        # carries an UNRELATED window.location statement ~35 chars later.
        body = ("<html><body><div class='refl'>" + q + "</div>"
                "<script>function goHome(){ window.location = '/home'; }</script>"
                "</body></html>")
        self.send_response(200); self.end_headers(); self.wfile.write(body.encode())
    def do_GET(self):
        u = parse_qs(self.path.split("?", 1)[1]).get("u", [""])[0] if "?" in self.path else ""
        if "/sink" in self.path:
            # true positive shape: the value lands INSIDE the sink expression
            body = ("<html><script>if (confirm('go?')) "
                    "location.href = '" + u + "';</script></html>")
            self.send_response(200); self.end_headers(); self.wfile.write(body.encode())
        else:
            self.send_response(200); self.end_headers(); self.wfile.write(b"<html>ok</html>")
    def log_message(self, *a): pass

srv = ThreadingHTTPServer(("127.0.0.1", 8851), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

try:
    base = "http://127.0.0.1:8851"
    eng = RequestEngine(ScopeRule(allowed_hosts=["127.0.0.1"], allow_private=True),
                        EventBus("v433-redir-audit"), timeout=3.0)
    bus = EventBus("v433-redir-audit")

    # ---- (1) FP shape: raw reflection + unrelated window.location -> MUST be silent
    ep_fp = Endpoint(url=base + "/reflect", method="POST",
                     parameters=[Parameter("note", ParamLocation.BODY, "").classify()])
    cands = RedirectDetector(eng, bus).candidates(ep_fp)
    fired = []
    for _, m in cands:
        r = eng.send(m)
        f = RedirectDetector(eng, bus).analyze((ep_fp, ep_fp.parameters[0]), r)
        if f is not None:
            fired.append({"type": f.type, "evidence_kinds": [e.kind for e in f.evidence],
                          "evidence0": (f.evidence[0].detail if f.evidence else "")[:220]})
    results["fp_negative"] = {
        "candidates_probed": len(cands),
        "detector_fired": bool(fired),
        "fired_findings": fired,
        "PASS": not fired,
    }

    # ---- (2) true shape: value INSIDE location.href -> candidate + VERIFIED
    ep_tp = Endpoint(url=base + "/sink", method="GET",
                     parameters=[Parameter("u", ParamLocation.QUERY, "").classify()])
    cands2 = RedirectDetector(eng, bus).candidates(ep_tp)
    found = None
    for _, m in cands2:
        r = eng.send(m)
        found = RedirectDetector(eng, bus).analyze((ep_tp, ep_tp.parameters[0]), r)
        if found: break
    tpr = {"candidate_found": found is not None, "candidates_probed": len(cands2)}
    if found is not None:
        out = VerificationEngine(eng, bus).verify(found, ep_tp)
        tpr.update({
            "finding_type": found.type,
            "verified": out.status == FindingStatus.VERIFIED,
            "verifier_method": getattr(out.verification, "method", str(out.verification)[:120]),
            "final_status": str(out.status),
        })
    tpr["PASS"] = bool(tpr.get("candidate_found") and tpr.get("verified"))
    results["true_positive"] = tpr

    # ---- (3) forged candidate on the FP page -> the verifier MUST reject it
    f_fp = Finding("open_redirect", Severity.MEDIUM, ep_fp.url, "note", "POST",
                   [Evidence("body_redirect", "off-site URL injected into client redirect sink", "t")],
                   status=FindingStatus.CANDIDATE)
    out_fp = VerificationEngine(eng, bus).verify(f_fp, ep_fp)
    results["fp_verify_reject"] = {
        "final_status": str(out_fp.status),
        "verifier_method": getattr(out_fp.verification, "method", str(out_fp.verification)[:120]),
        "PASS": out_fp.status == FindingStatus.REJECTED,
    }
finally:
    srv.shutdown(); srv.server_close()

fix_present = "CLIENT_REDIRECT_SINK_RE" in open(
    os.path.join(ENG, "sentinel", "detect.py"), encoding="utf-8", errors="replace").read()
results["VERDICT"] = {
    "structural_FP_live": bool(results["fp_negative"]["detector_fired"]
                               or not results["fp_verify_reject"]["PASS"]),
    "branch_fix_CLIENT_REDIRECT_SINK_RE_present": fix_present,
    "note": ("detector fires on reflection+unrelated-sink (part 1) and/or the "
             "verifier upholds the FP (part 3) => the structural FP is live; "
             "all three parts hold => the sink-context fix is present and green"),
}
os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w") as fh:
    json.dump(results, fh, indent=2)
print(json.dumps(results, indent=2))
print()
print("OVERALL:", "FIX PRESENT — ALL THREE PARTS GREEN" if all(
        results[k]["PASS"] for k in ("fp_negative", "true_positive", "fp_verify_reject"))
      else ("STRUCTURAL FP LIVE (expected RED on unfixed v4.3.3)" if results["VERDICT"]["structural_FP_live"]
            else "MIXED — inspect parts"))

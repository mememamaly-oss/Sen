#!/usr/bin/env python3
"""SENTINEL RED-TEAM PROOF — Request Body Sanitization (ORD-001-REMAND
item 3).

The journal is the substrate for EXTERNAL verification — it leaves the
machine inside every evidence package, so it must carry the request's
SHAPE, never the secrets inside it (the same doctrine as the RT-05 header
redaction, extended to bodies).

RED (vulnerable tree):
  A. FORM: a POST with Content-Type application/x-www-form-urlencoded and
     body username=admin&password=SuperSecret123 is journaled VERBATIM —
     the password readable in the journal (and in every evidence package).
  B. JSON: a POST with Content-Type application/json carrying
     {"token": "abc123", ...} is journaled verbatim.
  C. BINARY: a POST with Content-Type application/octet-stream and a 2KB
     payload is journaled verbatim.

GREEN (fixed tree):
  A. FORM  -> username=admin&password=[REDACTED] (value redacted, pair
     shape preserved; the WIRE request is untouched — redaction is
     journal-side only, exactly like the RT-05 headers).
  B. JSON  -> "token": "[REDACTED]" (structural walk, nested keys too).
  C. BINARY -> [BINARY_BODY_OMITTED_FOR_SECURITY] (>= 1KB bodies omitted).
  D. (<1KB binary stays verbatim — the ORDERED exception; preservation
     guard, green on both trees.)

Exit code: 0 = all GREEN; 1 = at least one RED.
"""
import sys
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = "/home/z/my-project/build-v430"
sys.path.insert(0, BASE)
os.chdir(BASE)

from sentinel.core import ScopeRule, EventBus
from sentinel.http_engine import RequestEngine, RequestMutation, Endpoint

RESULTS = []


def rec(name, verdict, evidence):
    RESULTS.append((name, verdict, evidence))
    print(f"[{verdict}] {name} :: {evidence[:170]}")


class _Sink(BaseHTTPRequestHandler):
    """Accepts everything; the server side is irrelevant — the JOURNAL is
    the artifact under test."""
    def _sink(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _sink

    def log_message(self, *a):
        pass


srv = ThreadingHTTPServer(("127.0.0.1", 0), _Sink)
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

eng = RequestEngine(ScopeRule(allowed_hosts=["127.0.0.1"], allow_private=True),
                    EventBus("rt-body"), timeout=6)
eng.bus.request_journal = {}


def _post(path, content_type, body):
    ep = Endpoint(url=f"http://127.0.0.1:{PORT}{path}", method="POST")
    m = RequestMutation(endpoint=ep, body_override=body,
                        extra_headers={"Content-Type": content_type})
    return eng.send(m)


def _journal_body(path):
    for v in eng.bus.request_journal.values():
        if path in (v.get("request") or {}).get("path", ""):
            return (v.get("request") or {}).get("body", "")
    return None


# ---- A. form
_post("/form", "application/x-www-form-urlencoded",
      "username=admin&password=SuperSecret123")
jb_form = _journal_body("/form")
if jb_form is not None and "password=SuperSecret123" in jb_form:
    rec("A.form body redaction", "RED",
        f"journal body verbatim: {jb_form!r} — the password is readable "
        f"in the journal (and in every evidence package)")
elif jb_form is not None and "password=[REDACTED]" in jb_form \
        and "SuperSecret123" not in jb_form and "username=admin" in jb_form:
    rec("A.form body redaction", "GREEN",
        f"journal body: {jb_form!r} — sensitive value redacted, pair shape "
        f"preserved, non-sensitive pairs untouched")
else:
    rec("A.form body redaction", "RED", f"unexpected journal body: {jb_form!r}")

# ---- B. json
_post("/json", "application/json",
      '{"token": "abc123", "user": "u1", "nested": {"secret": "s3cr3t!"}}')
jb_json = _journal_body("/json")
if jb_json is not None and '"token": "abc123"' in jb_json:
    rec("B.json body redaction", "RED",
        f"journal body verbatim: {jb_json!r} — token + nested secret "
        f"readable in the journal")
elif jb_json is not None and '"token": "[REDACTED]"' in jb_json \
        and '"secret": "[REDACTED]"' in jb_json and "abc123" not in jb_json \
        and "s3cr3t" not in jb_json and '"user": "u1"' in jb_json:
    rec("B.json body redaction", "GREEN",
        f"journal body: {jb_json!r} — token + nested secret redacted "
        f"structurally, non-sensitive keys untouched")
else:
    rec("B.json body redaction", "RED", f"unexpected journal body: {jb_json!r}")

# ---- C. binary >= 1KB
_post("/bin", "application/octet-stream", "B" * 2048)
jb_bin = _journal_body("/bin")
if jb_bin is not None and jb_bin.startswith("BBBB"):
    rec("C.binary body omission (>= 1KB)", "RED",
        f"journal carries the 2KB binary payload verbatim "
        f"(first 24 chars: {jb_bin[:24]!r})")
elif jb_bin is not None and jb_bin == "[BINARY_BODY_OMITTED_FOR_SECURITY]":
    rec("C.binary body omission (>= 1KB)", "GREEN",
        "journal body: [BINARY_BODY_OMITTED_FOR_SECURITY] — the payload "
        "never enters the journal")
else:
    rec("C.binary body omission (>= 1KB)", "RED",
        f"unexpected journal body: {(jb_bin or '')[:40]!r}")

# ---- D. <1KB binary (the ORDERED exception — preservation guard)
_post("/smallbin", "application/octet-stream", "S" * 512)
jb_small = _journal_body("/smallbin")
if jb_small is not None and jb_small == "S" * 512:
    rec("D.small binary (<1KB) stays verbatim (ordered exception)", "GREEN",
        "the 512-byte octet-stream body is journaled verbatim — exactly the "
        "ordered spec: omit only >= 1KB binary bodies")
else:
    rec("D.small binary (<1KB) stays verbatim (ordered exception)", "RED",
        f"unexpected journal body: {(jb_small or '')[:40]!r}")

# ================================================================ verdict
reds = [r for r in RESULTS if r[1] == "RED"]
print()
for name, verdict, evidence in RESULTS:
    print(f"  {verdict}  {name}")
if reds:
    print(f"\nOVERALL: RED — {len(reds)} vulnerable check(s) on this tree")
    sys.exit(1)
print("\nOVERALL: GREEN — every check closed on this tree")
sys.exit(0)

#!/usr/bin/env python3
"""RT-02 TLS differential proof (standing tool).

RED  (vulnerable tree): engine requests https://127.0.0.1:PORT/ against a
      self-signed MITM cert and SUCCEEDS (CERT_NONE + check_hostname=False),
      the interceptor captures the Authorization header -> TLS MITM accepted.
GREEN (fixed tree):      the same request FAILS with ssl.SSLError
      (CERT_REQUIRED + check_hostname=True) -> CERT_REJECTED.

Isolation: ScopeRule uses allow_private=True so the RT-01 scope guard passes
by explicit permission — the ONLY layer under test here is TLS verification.
"""
import http.server
import os
import ssl
import subprocess
import sys
import tempfile
import threading

REPO = "/home/z/my-project/build-v430"
sys.path.insert(0, REPO)

from sentinel.core import ScopeRule, Endpoint, EventBus          # noqa: E402
from sentinel.http_engine import RequestEngine, RequestMutation  # noqa: E402

CERTDIR = tempfile.mkdtemp(prefix="rt02-tls-")
CRT = os.path.join(CERTDIR, "evil.crt")
KEY = os.path.join(CERTDIR, "evil.key")
subprocess.run(
    ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
     "-keyout", KEY, "-out", CRT, "-days", "2",
     "-subj", "/CN=127.0.0.1",
     "-addext", "subjectAltName=IP:127.0.0.1"],
    check=True, capture_output=True)

MITM_HITS = []


class Mitm(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        MITM_HITS.append(self.headers.get("Authorization", ""))
        body = b"<html><body>Fake page from the MITM</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Mitm)
PORT = srv.server_address[1]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CRT, KEY)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
threading.Thread(target=srv.serve_forever, daemon=True).start()

scope = ScopeRule(allowed_hosts=["127.0.0.1"], allow_private=True)
bus = EventBus("rt02-tls-proof")
engine = RequestEngine(scope, bus, timeout=10)
m = RequestMutation(
    endpoint=Endpoint(url=f"https://127.0.0.1:{PORT}/",
                      headers={"Authorization": "Bearer RT7-BEARER-SECRET"}))
resp = engine.send(m)
err = getattr(resp, "error", None)

print(f"engine_ok={resp.ok} status={resp.status} error={err!r}")
print(f"mitm_hits={len(MITM_HITS)} captured_auth={MITM_HITS[0][:24] + '...' if MITM_HITS else '(none)'}")

if isinstance(err, ssl.SSLError) or "SSLCertVerificationError" in str(err) or "CERTIFICATE_VERIFY_FAILED" in str(err):
    print("VERDICT: GREEN — CERT_REJECTED (certificate verify failed, MITM saw nothing)")
elif resp.ok and MITM_HITS:
    print("VERDICT: RED — TLS_MITM_ACCEPTED (self-signed cert trusted, Authorization captured)")
else:
    print(f"VERDICT: INCONCLUSIVE — inspect raw values above (ok={resp.ok}, err={err!r})")
srv.shutdown()

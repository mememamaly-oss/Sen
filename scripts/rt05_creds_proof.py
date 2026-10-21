#!/usr/bin/env python3
"""RT-05 credential-leak differential proof (standing tool).

RED  (vulnerable tree): a request carrying Authorization / X-Api-Key / Cookie /
      X-Auth-Token / Proxy-Authorization is journaled VERBATIM — every secret
      readable in bus.request_journal (and thus in every evidence package).
GREEN (fixed tree):      the journal stores [REDACTED] for those five header
      families; a full-string search over the journal finds ZERO secret
      material; non-sensitive headers survive untouched (verification value
      preserved).
"""
import http.server
import json
import sys
import threading

REPO = "/home/z/my-project/build-v430"
sys.path.insert(0, REPO)

from sentinel.core import ScopeRule, Endpoint, EventBus          # noqa: E402
from sentinel.http_engine import RequestEngine, RequestMutation  # noqa: E402

SECRETS = {
    "Authorization": "Bearer RT7-BEARER-SECRET",
    "X-Api-Key": "RT7-API-KEY-SECRET",
    "Cookie": "session=RT7-COOKIE-SECRET",
    "X-Auth-Token": "RT7-AUTH-TOKEN-SECRET",
    "Proxy-Authorization": "Basic RT7-PROXY-SECRET",
}
KEEP = {"User-Agent": "sentinel-rt05-proof", "Accept": "text/html", "X-Trace-Id": "rt05-123"}


class Srv(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Srv)
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

bus = EventBus("rt05-creds-proof")
scope = ScopeRule(allowed_hosts=["127.0.0.1"], allow_private=True)
engine = RequestEngine(scope, bus, timeout=10)
m = RequestMutation(
    endpoint=Endpoint(url=f"http://127.0.0.1:{PORT}/x",
                      headers={**SECRETS, **KEEP}))
resp = engine.send(m)
print(f"engine_ok={resp.ok} status={resp.status}")

jr = getattr(bus, "request_journal", {})
blob = json.dumps(jr, default=str)
leaked = [k for k, v in SECRETS.items() if v in blob]
kept = [k for k, v in KEEP.items() if v in blob]
redacted = [k for k in SECRETS if any(
    hk.lower() == k.lower() and hv == "[REDACTED]"
    for hk, hv in (jr.get(list(jr)[0], {}).get("request", {}).get("headers", {}) or {}).items()
)] if jr else []

print(f"journal_entries={len(jr)}")
print(f"secrets_leaked_verbatim={leaked if leaked else '(none)'}")
print(f"non_sensitive_headers_preserved={len(kept)}/{len(KEEP)} {kept}")
print(f"redacted_markers={redacted if redacted else '(none)'}")

if not leaked and len(redacted) == len(SECRETS) and len(kept) == len(KEEP):
    print("VERDICT: GREEN — CREDENTIAL_PROTECTED (all 5 redacted, secrets absent, context headers intact)")
elif leaked:
    print(f"VERDICT: RED — CREDENTIALS_IN_JOURNAL_PLAINTEXT ({len(leaked)}/5 secret values verbatim)")
else:
    print("VERDICT: INCONCLUSIVE — inspect raw values above")
srv.shutdown()

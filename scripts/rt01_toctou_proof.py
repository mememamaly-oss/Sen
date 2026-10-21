#!/usr/bin/env python3
"""SENTINEL RED-TEAM PROOF — RT-01 TOCTOU / DNS Rebinding (ORD-001-REMAND
item 2).

The pre-remand engine (post RT-01 string-match fix) still had the
check-then-connect race: _scope_ok resolves the name via is_private_ip,
then hands the NAME to http.client, which resolves DNS a SECOND time at
connect — between the two resolutions the answer can change (DNS
rebinding).

RED (vulnerable tree):
  A. REBINDING SUCCEEDED: a stateful fake resolver answers the FIRST
     lookup of the target name with a PUBLIC address (passes the guard)
     and every later lookup with 127.0.0.1 — the vulnerable engine's
     http.client performs the SECOND lookup at connect time and lands on
     the EVIL listener: evil_hits=1, the response body is the EVIL
     server's content (a full rebinding compromise, live).

GREEN (fixed tree, the ordered Option A):
  A. REBINDING BLOCKED: the engine resolves ONCE per request, validates
     EVERY answer against the RT-01 guard, and pins the transport to the
     validated address — the rebind answer (127.0.0.1) is REJECTED at the
     pin: evil_hits=0, status=0, error carries the pin reason. The
     connection to the second IP never happens.

BOTH TREES (the standing RT-01 regression battery — must stay GREEN):
  B. The 7 obfuscated SSRF forms all BLOCKED through is_private_ip
     (0177.0.0.1 / 2130706433 / 0x7f000001 / 127.1 / localhost. /
     [::ffff:127.0.0.1] / 127.0.0.1.nip.io).
  C. PIN + HOST SEMANTICS (preservation guard): a request through a NAME
     (localhost) still succeeds and the server observes the ORIGINAL
     authority in the Host header (never the pinned IP).

Exit code: 0 = all GREEN; 1 = at least one RED.
"""
import socket
import sys
import threading
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

BASE = "/home/z/my-project/build-v430"
sys.path.insert(0, BASE)
os.chdir(BASE)

from sentinel.core import ScopeRule, EventBus, is_private_ip
from sentinel.http_engine import RequestEngine, RequestMutation, Endpoint

RESULTS = []


def rec(name, verdict, evidence):
    RESULTS.append((name, verdict, evidence))
    print(f"[{verdict}] {name} :: {evidence[:160]}")


REBIND_NAME = "rebind.sentinel-proof.test"
SAFE_IP = "93.184.216.34"          # public — passes the RT-01 guard
EVIL_IP = "127.0.0.1"              # loopback — must never be connected to


# ================================================================ A. rebinding
class _EvilHandler(BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self):
        type(self).hits += 1
        body = b"EVIL-REBOUND-CONTENT"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


evil_srv = ThreadingHTTPServer(("127.0.0.1", 0), _EvilHandler)
EVIL_PORT = evil_srv.server_address[1]
threading.Thread(target=evil_srv.serve_forever, daemon=True).start()

_real_getaddrinfo = socket.getaddrinfo
_state = {"name_lookups": 0}


def _fake_getaddrinfo(host, *args, **kwargs):
    """Stateful fake: the FIRST lookup of REBIND_NAME answers PUBLIC (the
    guard sees a safe target); every later lookup answers 127.0.0.1 (the
    rebinding flip). All other hosts pass through untouched."""
    if host == REBIND_NAME:
        _state["name_lookups"] += 1
        answer = SAFE_IP if _state["name_lookups"] == 1 else EVIL_IP
        return _real_getaddrinfo(answer, *args, **kwargs)
    return _real_getaddrinfo(host, *args, **kwargs)


socket.getaddrinfo = _fake_getaddrinfo
try:
    eng = RequestEngine(
        ScopeRule(allowed_hosts=[REBIND_NAME], allow_private=False),
        EventBus("rt01-toctou"), timeout=6)
    eng.bus.request_journal = {}
    ep = Endpoint(url=f"http://{REBIND_NAME}:{EVIL_PORT}/rebind", method="GET")
    resp = eng.send(RequestMutation(endpoint=ep))
    evil_hits = _EvilHandler.hits
    name_lookups = _state["name_lookups"]
finally:
    socket.getaddrinfo = _real_getaddrinfo

if evil_hits == 0 and resp.status == 0 and "pin" in (resp.error or ""):
    rec("A.dns-rebinding blocked (pin-to-resolved-address)", "GREEN",
        f"evil_hits=0, status={resp.status}, error={resp.error!r} — the "
        f"rebind answer ({EVIL_IP}) was REJECTED at the pin; the connection "
        f"to the second IP never happened (name lookups: {name_lookups})")
elif evil_hits > 0:
    rec("A.dns-rebinding blocked (pin-to-resolved-address)", "RED",
        f"REBINDING SUCCEEDED: evil_hits={evil_hits}, engine status="
        f"{resp.status}, body-from-evil={('EVIL-REBOUND-CONTENT' in (resp.body or ''))} "
        f"— http.client resolved the name a SECOND time at connect and "
        f"landed on {EVIL_IP} (name lookups: {name_lookups})")
else:
    rec("A.dns-rebinding blocked (pin-to-resolved-address)", "RED",
        f"unexpected state: evil_hits={evil_hits}, status={resp.status}, "
        f"error={resp.error!r}")


# ================================================================ B. the standing 7/7 battery
forms = ["0177.0.0.1", "2130706433", "0x7f000001", "127.1", "localhost.",
         "[::ffff:127.0.0.1]", "127.0.0.1.nip.io"]
blocked = {f: is_private_ip(f) for f in forms}
n_blocked = sum(1 for v in blocked.values() if v)
if n_blocked == len(forms):
    rec("B.standing RT-01 battery (7/7 obfuscated forms BLOCKED)", "GREEN",
        f"all {len(forms)} forms refused by is_private_ip "
        f"({', '.join(f for f in forms)})")
else:
    rec("B.standing RT-01 battery (7/7 obfuscated forms BLOCKED)", "RED",
        f"only {n_blocked}/{len(forms)} blocked: {blocked}")


# ================================================================ C. pin + Host semantics (preservation)
class _EchoHostHandler(BaseHTTPRequestHandler):
    seen_host = ""

    def do_GET(self):
        type(self).seen_host = self.headers.get("Host", "")
        body = f"HOST={type(self).seen_host}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


echo_srv = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHostHandler)
ECHO_PORT = echo_srv.server_address[1]
threading.Thread(target=echo_srv.serve_forever, daemon=True).start()

eng2 = RequestEngine(ScopeRule(allowed_hosts=["localhost"], allow_private=True),
                     EventBus("rt01-host"), timeout=6)
ep2 = Endpoint(url=f"http://localhost:{ECHO_PORT}/pin", method="GET")
r2 = eng2.send(RequestMutation(endpoint=ep2))
expected_authority = f"localhost:{ECHO_PORT}"
if r2.status == 200 and _EchoHostHandler.seen_host == expected_authority:
    rec("C.pin keeps the ORIGINAL authority in Host (Option A semantics)",
        "GREEN",
        f"status=200, server observed Host={_EchoHostHandler.seen_host!r} "
        f"(the pinned transport carried the original name, never the IP)")
else:
    rec("C.pin keeps the ORIGINAL authority in Host (Option A semantics)",
        "RED",
        f"status={r2.status}, observed Host={_EchoHostHandler.seen_host!r}, "
        f"expected {expected_authority!r}")

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

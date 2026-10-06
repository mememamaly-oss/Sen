#!/usr/bin/env python3
"""OWSP-21 discriminating probe — behavioral RED/GREEN proof.

Live-caught on Mutillidae II 2.12.7 (recon run owsp-muti-r0): the crawler
followed the query-routed do=toggle-security header link (journal index 11),
and the scan session's security level oscillated 0->1->5->0 across 95 hits.

This probe builds the minimal live shape (a router app whose every page
carries do=toggle-security and do=logout header links, session-state
server-side) and crawls it with whatever engine is on disk:

  FROZEN v4.2.5 (pre-fix) -> RED: toggle fetched, level flips, logout
                             fetched, session destroyed
  FIXED                    -> GREEN: neither fetched, level 0, session alive

Run:  python3 scripts/owsp/probe_owsp21_frozen.py
Exit: 0 = GREEN (fixed behavior), 1 = RED (defect reproduced), 2 = error
"""
import sys
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

sys.path.insert(0, "/home/z/my-project/build-v425")
from sentinel.core import ScopeRule, EventBus          # noqa: E402
from sentinel.http_engine import RequestEngine         # noqa: E402
from sentinel.discovery import DiscoveryEngine         # noqa: E402

RECEIVED = []
SESSIONS = {}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        sid = self.headers.get("Cookie", "")
        RECEIVED.append(self.path)
        if "sessid" not in sid:
            body = (b'<html><body>SECURITY-LEVEL: 0'
                    b'<a href="/index.php?page=home.php">home</a>'
                    b'<a href="/index.php?do=toggle-security">toggle</a>'
                    b'<a href="/index.php?do=logout">logout</a>'
                    b'</body></html>')
            self._send(200, body, {"Set-Cookie": "sessid=s1"})
            return
        st = SESSIONS.setdefault("s1", {"level": 0, "alive": True})
        u = urlsplit(self.path)
        if not st["alive"]:
            self._send(200, b"<html><body>LOGIN PLEASE</body></html>")
            return
        if u.query == "do=toggle-security":
            st["level"] = {0: 1, 1: 5}.get(st["level"], 0)
        elif u.query == "do=logout":
            st["alive"] = False
        body = (f'<html><body>SECURITY-LEVEL: {st["level"]}'
                f'<a href="/index.php?page=home.php">home</a>'
                f'<a href="/index.php?do=toggle-security">toggle</a>'
                f'<a href="/index.php?do=logout">logout</a>'
                f'</body></html>').encode()
        self._send(200, body)


def main():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        scope = ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True)
        eng = RequestEngine(scope, EventBus("run-owsp21-probe"), timeout=5.0)
        disc = DiscoveryEngine(eng, max_pages=6)
        disc.crawl(base)
    finally:
        srv.shutdown()

    st = SESSIONS.get("s1", {"level": 0, "alive": True})
    toggles = [r for r in RECEIVED if "do=toggle-security" in r]
    logouts = [r for r in RECEIVED if "do=logout" in r]
    result = {
        "requests": len(RECEIVED),
        "toggle_fetches": len(toggles),
        "logout_fetches": len(logouts),
        "session_level_end": st["level"],
        "session_alive": st["alive"],
    }
    print(json.dumps(result, indent=1))
    defect = toggles or logouts or st["level"] != 0 or not st["alive"]
    if defect:
        print("VERDICT: RED — query-routed state-change commands executed by "
              "the crawl (OWSP-21 defect reproduced)")
        sys.exit(1)
    print("VERDICT: GREEN — no query-routed command fetched; session posture "
          "intact (OWSP-21 fixed)")
    sys.exit(0)


if __name__ == "__main__":
    main()

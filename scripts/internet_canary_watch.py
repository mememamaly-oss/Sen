#!/usr/bin/env python3
"""Internet-reachability canary watch (Task 21, 2026-10-23).

Binds a canary on 127.0.0.1:8998 for WINDOW minutes and logs EVERY hit with
the forwarding headers the live root Caddy attaches. The vulnerable relay
sends `X-Real-IP: {remote_host}` — the address Caddy itself saw:

  * X-Real-IP 127.0.0.1 / 21.0.7.207  -> request ORIGINATED INSIDE this container
  * X-Real-IP anything else (ALB/gateway IP) -> request came from OUTSIDE,
    i.e. the container's :81 ingress is reachable from the platform edge
    and, if the tester used the public preview URL, from the INTERNET.

Read-only canary: it never reads or returns any data — just an
acknowledgement token. Kill with: pkill -f internet_canary_watch
"""
import http.server, socketserver, threading, time, datetime, sys

WINDOW_MIN = 20
LOG = "/home/z/my-project/qa-results/internet_canary_watch.log"

class Canary(http.server.BaseHTTPRequestHandler):
    def _serve(self):
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        print(f"[{ts}] HIT  path={self.path}  "
              f"X-Real-IP={self.headers.get('X-Real-IP','-')}  "
              f"X-Forwarded-For={self.headers.get('X-Forwarded-For','-')}  "
              f"X-Forwarded-Proto={self.headers.get('X-Forwarded-Proto','-')}  "
              f"Host={self.headers.get('Host','-')}  "
              f"UA={self.headers.get('User-Agent','-')[:60]}", flush=True)
        b = b"CANARY-HIT-8998 (ENV-1 internet watch)"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    do_GET = _serve
    do_POST = _serve
    do_HEAD = _serve
    def log_message(self, *a): pass

class ThreadingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

if __name__ == "__main__":
    with open(LOG, "a") as f:
        f.write(f"\n=== canary watch started {datetime.datetime.now(datetime.timezone.utc).isoformat()} | window={WINDOW_MIN}min | bind=127.0.0.1:8998 ===\n")
    srv = ThreadingServer(("127.0.0.1", 8998), Canary)
    def stopper():
        time.sleep(WINDOW_MIN * 60)
        srv.shutdown()
    threading.Thread(target=stopper, daemon=True).start()
    print(f"canary UP on 127.0.0.1:8998 for {WINDOW_MIN} minutes; logging to {LOG}", flush=True)
    try:
        srv.serve_forever()
    finally:
        with open(LOG, "a") as f:
            f.write(f"=== canary watch ended {datetime.datetime.now(datetime.timezone.utc).isoformat()} ===\n")

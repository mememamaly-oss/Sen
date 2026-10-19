#!/usr/bin/env python3
"""SENTINEL final-round rate enforcement proxy (standing tool, tools clause).

A local HTTP forward proxy that enforces the external-scan charter:
  - token-bucket rate limit (default 2.0 req/s, burst capacity 2)
  - STRUCTURAL upstream whitelist: exactly ONE upstream host per instance,
    given at startup; the proxy is incapable of forwarding anywhere else.
    Any request that tries to smuggle a different host (absolute-URI request
    line, full URL in the path) is answered 403 and logged as a violation.
  - full JSONL request log: ts, method, path, upstream, status, latency_ms,
    verdict (forwarded / blocked) — the log IS the compliance evidence.
  - binds 127.0.0.1 ONLY — never reachable from outside the host.

Usage:
  python3 scripts/rate_proxy.py --port 8899 --upstream scanme.nmap.org \
      --rate 2.0 --log /tmp/final_rate_proxy.jsonl

Self-judgment (fully local, zero external contact):
  python3 scripts/rate_proxy.py --selftest
"""
import argparse
import json
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class TokenBucket:
    """Classic token bucket: capacity C, refill R tokens/second."""

    def __init__(self, rate: float, capacity: float = None):
        self.rate = float(rate)
        self.capacity = float(capacity if capacity is not None else rate)
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self):
        """Block until one token is available (infra enforcement, no promise)."""
        while True:
            with self.lock:
                now = time.monotonic()
                self.tokens = min(self.capacity,
                                  self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                wait = (1.0 - self.tokens) / self.rate
            time.sleep(min(wait, 0.25))


class RateProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # v1.1: forward the upstream's response headers VERBATIM (minus
    # hop-by-hop + recomputed Content-Length) and suppress this proxy's own
    # banner — v1.0 injected "sentinel-rate-proxy/1.0" as the Server header
    # and dropped the target's real headers, which made header-class scan
    # findings measure the PROXY, not the target (declared in final-round-1
    # F2; the fix stands for future rounds, the F2 evidence stands as-is
    # with the disclosed artifact + the corroborating direct GET).
    server_version = ""       # no banner of our own
    sys_version = ""          # no python version leak either

    # set by serve():
    upstream_host = None      # structural whitelist — the ONLY host we dial
    upstream_port = 80
    bucket = None
    log_path = None
    log_lock = threading.Lock()
    violations = 0
    forwarded = 0
    MAX_BODY = 1 << 20        # 1 MiB request body cap
    MAX_RESP = 4 << 20        # 4 MiB response cap
    UPSTREAM_TIMEOUT = 15.0

    def log_message(self, fmt, *args):  # silence stderr noise; JSONL is the log
        pass

    # ------------------------------------------------------------------ log
    def _log(self, verdict: str, method: str, path: str, status: int,
             latency_ms: float, note: str = ""):
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "epoch": round(time.time(), 3),
               "method": method, "path": path,
               "upstream": self.upstream_host, "verdict": verdict,
               "status": status, "latency_ms": round(latency_ms, 1),
               "note": note}
        with self.log_lock:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # -------------------------------------------------------------- helpers
    def _blocked(self, method: str, path: str, note: str):
        self.__class__.violations += 1
        self._log("blocked", method, path, 403, 0.0, note)
        body = b'{"error": "closed-list violation: this proxy forwards to ' \
               + self.upstream_host.encode() + b' only"}'
        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _smuggled_host(self, path: str):
        """Detect absolute-URI request lines / full URLs in the path."""
        return path.startswith(("http://", "https://", "//"))

    # ------------------------------------------------------------ forwarding
    def _forward(self, method: str):
        t0 = time.monotonic()
        path = self.path
        if self._smuggled_host(path):
            self._blocked(method, path, "absolute-URI smuggle attempt")
            return
        # headers the engine may legitimately set on probes
        hdrs = {"Host": self.upstream_host}
        for h in ("Content-Type", "Accept", "User-Agent", "Cookie",
                  "Authorization", "X-Requested-With"):
            v = self.headers.get(h)
            if v is not None:
                hdrs[h] = v
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(length, self.MAX_BODY)) if length > 0 else None
        if length > self.MAX_BODY:
            self._blocked(method, path, "request body over cap")
            return

        self.bucket.acquire()  # infra rate enforcement — blocks, never promises
        try:
            import urllib.request
            import urllib.error
            req = urllib.request.Request(
                f"http://{self.upstream_host}:{self.upstream_port}{path}",
                data=body, method=method, headers=hdrs)
            with urllib.request.urlopen(req, timeout=self.UPSTREAM_TIMEOUT) as r:
                raw = r.read(self.MAX_RESP)
                status, ctype = r.status, r.headers.get("Content-Type", "")
                r_headers = dict(r.headers.items())
        except urllib.error.HTTPError as e:
            raw = e.read(self.MAX_RESP)
            status, ctype = e.code, e.headers.get("Content-Type", "")
            r_headers = dict(e.headers.items())
        except Exception as e:  # upstream timeouts / resets — recorded honestly
            self._log("forwarded", method, path, 0,
                      (time.monotonic() - t0) * 1000.0, f"upstream error: {e}")
            body = json.dumps({"error": f"upstream unreachable: {e}"}).encode()
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.__class__.forwarded += 1
        self._log("forwarded", method, path, status,
                  (time.monotonic() - t0) * 1000.0)
        self.send_response_only(status)          # no Server/Date of our own
        hop = {"connection", "transfer-encoding", "content-length", "keep-alive",
               "proxy-authenticate", "proxy-authorization", "te", "trailer", "upgrade"}
        sent_ct = False
        for k, v in (r_headers or {}).items():
            if k.lower() in hop:
                continue
            if k.lower() == "content-type":
                sent_ct = True
            self.send_header(k, v)
        if not sent_ct and ctype:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self._forward("GET")

    def do_HEAD(self):
        self._forward("HEAD")

    def do_POST(self):
        self._forward("POST")

    def do_PUT(self):
        self._forward("PUT")

    def do_DELETE(self):
        self._forward("DELETE")

    def do_OPTIONS(self):
        self._forward("OPTIONS")

    def do_PATCH(self):
        self._forward("PATCH")


def serve(port: int, upstream: str, rate: float, log_path: str):
    RateProxyHandler.upstream_host = upstream
    RateProxyHandler.upstream_port = 80
    RateProxyHandler.bucket = TokenBucket(rate)
    RateProxyHandler.log_path = log_path
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    srv = ThreadingHTTPServer(("127.0.0.1", port), RateProxyHandler)
    srv.serve_forever()


# ------------------------------------------------------------------ selftest
def selftest() -> int:
    """Fully-local judgment of the tool: forwarding, rate, whitelist, log."""
    import http.server
    import urllib.request

    ok = []

    class Local(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = json.dumps({"local": True, "path": self.path}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Local)
    upstream_port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    log = "/tmp/final_proxy_selftest.jsonl"
    Path(log).unlink(missing_ok=True)
    RateProxyHandler.upstream_host = "127.0.0.1"   # the local test upstream
    RateProxyHandler.upstream_port = upstream_port
    RateProxyHandler.bucket = TokenBucket(2.0)
    RateProxyHandler.log_path = log
    RateProxyHandler.violations = 0
    RateProxyHandler.forwarded = 0
    proxy = ThreadingHTTPServer(("127.0.0.1", 0), RateProxyHandler)
    proxy_port = proxy.server_address[1]
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    time.sleep(0.1)

    # J1: forwarding works
    r = urllib.request.urlopen(f"http://127.0.0.1:{proxy_port}/probe?a=1",
                               timeout=10)
    j1 = r.status == 200 and json.loads(r.read())["path"] == "/probe?a=1"
    ok.append(("J1 forwarding", j1))

    # J2: rate enforcement — 4 rapid requests must span >= ~1.0s at 2/s
    t0 = time.monotonic()
    for _ in range(4):
        urllib.request.urlopen(f"http://127.0.0.1:{proxy_port}/r",
                               timeout=10).read()
    span = time.monotonic() - t0
    ok.append(("J2 rate<=2/s (span %.2fs for 4 req)" % span, span >= 1.0))

    # J3: a TRUE absolute-URI request line (raw socket — the real smuggle
    # vector) is blocked with 403 + logged. NOTE: a path like /http://x is
    # origin-form — it is forwarded to the whitelisted upstream ONLY (that is
    # a scanme request, not an x request), so it is NOT a violation.
    import urllib.error
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
    s.sendall(("GET http://evil.example.com/x HTTP/1.1\r\n"
               f"Host: 127.0.0.1:{proxy_port}\r\nConnection: close\r\n\r\n"
               ).encode())
    resp = s.recv(65536).decode("utf-8", "replace")
    s.close()
    j3 = resp.startswith("HTTP/1.1 403")
    ok.append(("J3 absolute-URI smuggle blocked 403", j3))

    # J4: the JSONL log is complete and structured
    recs = [json.loads(x) for x in open(log, encoding="utf-8")]
    j4 = (len(recs) == 6 and recs[0]["verdict"] == "forwarded"
          and recs[-1]["verdict"] == "blocked"
          and all("epoch" in r and "latency_ms" in r for r in recs))
    ok.append(("J4 log complete", j4))

    httpd.shutdown()
    proxy.shutdown()
    for name, good in ok:
        print(("PASS " if good else "FAIL ") + name, flush=True)
    return 0 if all(g for _, g in ok) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--upstream", required=False,
                    help="the ONE upstream host this proxy may dial")
    ap.add_argument("--rate", type=float, default=2.0)
    ap.add_argument("--log", default="/tmp/final_rate_proxy.jsonl")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.upstream:
        print("--upstream is required (the structural whitelist host)",
              file=sys.stderr)
        return 2
    print(f"[rate-proxy] 127.0.0.1:{a.port} -> {a.upstream}:80 "
          f"@ {a.rate} req/s | log {a.log}", flush=True)
    serve(a.port, a.upstream, a.rate, a.log)
    return 0


if __name__ == "__main__":
    sys.exit(main())

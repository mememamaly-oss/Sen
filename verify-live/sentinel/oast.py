"""Phase 49 + Phase 52: OAST engine — out-of-band interaction channels.

Closes the documented v2.0.x coverage gap: "blind XXE needs OOB/Collaborator
confirmation". Some vulnerability classes have NO response-based oracle (the
target's reply carries no information about whether our payload executed —
live-proven on ginandjuice.shop /catalog/product/stock, where five identical
probes returned 23/768/52/191/52 units). The ONLY evidence channel for such
vulns is the target making an outbound callback to a listener WE control.

Two interchangeable providers (same 3-call protocol: url / poll / stop —
the detector and verifier code never change):
  - OastServer (Phase 49): binds 127.0.0.1:<ephemeral> and records every HTTP
    hit as an interaction keyed by a caller-chosen id (the id IS the URL path).
    Optimal for lab/local targets: zero latency, fully deterministic.
  - PublicWebhookProvider (Phase 52): a PUBLIC channel via the webhook.site
    REST service — Burp-Collaborator-class semantics WITHOUT owning any
    infrastructure. One channel token per scan; the interaction id rides in
    the callback's query string (?i=<id>); poll() reads the service's request
    log. Live-proven end-to-end: ginandjuice.shop's blind XXE fetched a
    webhook.site entity URL from 54.170.155.72 (the target's own AWS egress)
    with UA "ginandjuice.shop; support@portswigger.net" while the HTTP
    response stayed a content-free 400.

make_oast(): the selection policy. auto = local listener for targets that can
reach loopback, public channel for remote targets (degrades honestly to None
if the public service is unreachable — the scan proceeds exactly as before,
blind-OOB confirmation simply stays unavailable, as documented in v2.0.x).

Honesty contract preserved: an OOB callback IS independent evidence of
server-side payload execution (the fetch left the target's process), so an
OOB-confirmed finding is VERIFIED — never merely "candidate".
"""
from __future__ import annotations
import json as _json
import threading, time
import urllib.request as _urlreq
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _OastHandler(BaseHTTPRequestHandler):
    oast: "OastServer" = None            # injected

    def log_message(self, *a):
        pass                              # silent — the interaction log IS the output

    def _record(self):
        iid = self.path.lstrip("/").split("?")[0]
        self.oast._record(iid, method=self.command,
                          ua=self.headers.get("User-Agent", ""),
                          host=self.headers.get("Host", ""))
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_HEAD = do_PUT = _record


class OastServer:
    """Local OOB listener. Deterministic poll, thread-safe interaction log."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host, self.requested_port = host, port
        self._interactions: dict[str, list[dict]] = {}
        self._lock = threading.Lock()
        self._ready = threading.Event()
        h = type("BoundOastHandler", (_OastHandler,), {"oast": self})
        self._srv = ThreadingHTTPServer((host, port), h)
        self._srv.daemon_threads = True
        self.port = self._srv.server_address[1]
        # the URL the TARGET must be able to reach — loopback for lab targets;
        # a public bind/port-forward is required for remote targets.
        self.public_base = f"http://{host}:{self.port}"
        self._thread = threading.Thread(target=self._srv.serve_forever,
                                        daemon=True, name="oast-listener")
        self._thread.start()
        self._ready.set()

    # ---------------------------------------------------------------- API
    def url(self, interaction_id: str) -> str:
        """Callback URL for one probe. The id is the path — poll() by the same id."""
        return f"{self.public_base}/{interaction_id}"

    def _record(self, iid: str, **meta):
        with self._lock:
            self._interactions.setdefault(iid, []).append(
                {"t": round(time.time(), 3), **meta})

    def poll(self, interaction_id: str, timeout: float = 2.0) -> list[dict] | None:
        """Block until the interaction arrives (returns hit list) or None on timeout.
        Checks immediately first — for local fixtures the callback lands before the
        probe request even returns."""
        deadline = time.time() + timeout
        while True:
            with self._lock:
                hits = self._interactions.get(interaction_id)
                if hits:
                    return list(hits)
            if time.time() >= deadline:
                return None
            time.sleep(0.05)

    def hits(self) -> dict[str, list[dict]]:
        with self._lock:
            return {k: list(v) for k, v in self._interactions.items()}

    def stop(self):
        try:
            self._srv.shutdown()
            self._srv.server_close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.stop()

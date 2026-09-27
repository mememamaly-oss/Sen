"""Phase 49 (architecture continuation): OAST engine — out-of-band interaction server.

Closes the documented v2.0.x coverage gap: "blind XXE needs OOB/Collaborator
confirmation". Some vulnerability classes have NO response-based oracle (the
target's reply carries no information about whether our payload executed —
live-proven on ginandjuice.shop /catalog/product/stock, where five identical
probes returned 23/768/52/191/52 units). The ONLY evidence channel for such
vulns is the target making an outbound callback to a listener WE control.

Design (Burp-Collaborator-class semantics, deterministic and local):
  - OastServer binds 127.0.0.1:<ephemeral> and records every HTTP hit as an
    interaction keyed by a caller-chosen interaction id (the id IS the URL path,
    so one listener serves many concurrent probes without port sprawl).
  - poll(iid, timeout) blocks until the interaction arrives or timeout — the
    detector side stays synchronous and deterministic.
  - `public_base` attribute marks the URL the TARGET must reach: loopback works
    for lab/local targets; scanning a remote host requires a public listener
    (plug in by constructing OastServer on a public interface or by a port
    forward) — the detector code never changes.

Honesty contract preserved: an OOB callback IS independent evidence of
server-side payload execution (the fetch left the target's process), so an
OOB-confirmed finding is VERIFIED — never merely "candidate".
"""
from __future__ import annotations
import threading, time
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

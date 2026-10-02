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
    """Local OOB listener (Phase 49). Deterministic poll, thread-safe interaction log.
    Provider attributes: channel='local', public_base (the URL targets call back)."""

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

    # provider metadata (uniform across channel implementations)
    channel = "local"

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.stop()


# ================================================================ Phase 52
class PublicWebhookProvider:
    """Public OOB channel via the webhook.site REST service — Collaborator-class
    semantics with ZERO owned infrastructure. One channel token per instance; the
    interaction id rides in the callback query string (?i=<id>); poll() reads the
    service's request log over TLS and matches ids client-side.

    Protocol (live-proven 2026-09, see module docstring):
      POST   /token                         -> {"uuid": <channel token>}
      TARGET GET https://webhook.site/<token>?i=<iid>   -> recorded by the service
      GET    /token/<token>/requests?page=1 -> {"total": n, "data": [ {method, ip,
                                                          url, user_agent, ...} ]}

    Determinism note: the token is per-scan (not per-run reproducible), but the
    interaction ids remain deterministic (detector-side sha1), so evidence text
    stays stable across runs; only the channel identity differs. This mirrors a
    real collaborator deployment, where the domain also changes per deployment.
    """

    channel = "public-webhook"
    SERVICE = "https://webhook.site"
    # public-channel latency budget: the target's egress fetch + the service's log
    # indexing are slower than a loopback listener; callers written for the local
    # listener pass short timeouts, so enforce a channel-specific floor. Tests
    # shrink this attribute for speed.
    POLL_FLOOR = 5.0

    def __init__(self, timeout: float = 15.0, service: str | None = None,
                 token: str | None = None):
        self.timeout = timeout
        self._svc = service or self.SERVICE
        self._token = token or self._create_token()
        self.public_base = f"{self._svc}/{self._token}"
        self._polled = set()          # request uuids already seen (idempotent poll)
        self._lock = threading.Lock()

    # ------------------------------------------------------------ internals
    def _http(self, path: str, method: str = "GET", body: dict | None = None):
        data = _json.dumps(body or {}).encode() if method == "POST" else None
        req = _urlreq.Request(self._svc + path, method=method, data=data,
                              headers={"Content-Type": "application/json"}
                              if data else {})
        with _urlreq.urlopen(req, timeout=self.timeout) as r:
            return _json.loads(r.read().decode("utf-8", "replace"))

    def _create_token(self) -> str:
        d = self._http("/token", method="POST", body={})
        tok = d.get("uuid")
        if not tok:
            raise RuntimeError(f"public OAST channel creation failed: {str(d)[:120]}")
        return tok

    # ------------------------------------------------------------ provider API
    def url(self, interaction_id: str) -> str:
        """Callback URL for one probe. The id rides in ?i= — poll() by the same id."""
        return f"{self.public_base}?i={interaction_id}"

    def poll(self, interaction_id: str, timeout: float = 3.0) -> list[dict] | None:
        """Poll the service request log until an entry carries our interaction id
        or the timeout expires. The service has no server-side filter, so we fetch
        the log page and match ?i=<id> client-side. Returns hit list (collaborator-
        style: method + source ip + ua + epoch) or None."""
        timeout = max(timeout, self.POLL_FLOOR)
        deadline = time.time() + timeout
        while True:
            try:
                d = self._http(f"/token/{self._token}/requests?page=1")
                with self._lock:
                    self._polled.update(str(x.get("uuid", "")) for x in d.get("data", []))
                hits = [self._hit(x) for x in d.get("data", [])
                        if f"i={interaction_id}" in str(x.get("url", ""))]
                if hits:
                    return hits
            except Exception:
                pass                       # transient network -> keep polling
            if time.time() >= deadline:
                return None
            time.sleep(0.6)

    @staticmethod
    def _hit(x: dict) -> dict:
        t = x.get("created_at", "")
        try:                                   # "2026-09-28 19:20:39" (UTC) -> epoch
            from datetime import datetime, timezone
            t = datetime.strptime(t, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc).timestamp()
        except Exception:
            pass
        return {"t": round(float(t) if isinstance(t, float) else time.time(), 3),
                "method": x.get("method", ""), "ip": x.get("ip", ""),
                "ua": x.get("user_agent", ""), "host": x.get("host", "")}

    def hits(self) -> dict[str, list[dict]]:
        """All interactions grouped by id (audit/telemetry view)."""
        out: dict[str, list[dict]] = {}
        try:
            d = self._http(f"/token/{self._token}/requests?page=1")
            for x in d.get("data", []):
                import re as _re
                m = _re.search(r"[?&]i=([^&]+)", str(x.get("url", "")))
                if m:
                    out.setdefault(m.group(1), []).append(self._hit(x))
        except Exception:
            pass
        return out

    def stop(self):
        """Nothing to shut down server-side (the service expires channels on its
        own); kept for the uniform provider protocol."""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.stop()


def make_oast(target_host: str, mode: str = "auto", allow_private: bool = False,
              service: str | None = None) -> \
        "OastServer | PublicWebhookProvider | None":
    """Phase 52 channel selection policy:
      local    -> loopback listener (lab targets only — remote hosts cannot call it)
      public   -> PublicWebhookProvider (webhook.site; works for ANY target)
      auto     -> local when the target can reach loopback (private/lab host),
                  public for remote hosts; honest None if the public channel is
                  unreachable (scan proceeds without OOB — never crashes a scan
                  for lack of a listener).
    """
    from .core import is_private_ip
    private = is_private_ip(target_host or "")
    if mode == "local" or (mode == "auto" and private):
        return OastServer()
    if mode in ("public", "auto"):
        try:
            return PublicWebhookProvider(service=service)
        except Exception:
            if mode == "public":
                raise                       # explicit request -> loud failure
            return None                    # auto -> honest degradation
    return None

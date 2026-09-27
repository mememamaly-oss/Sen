"""Phase 2: Request/Response Engine + Phase 3: Scope enforcement.
Scanners never build HTTP requests directly — they emit RequestMutations.
"""
from __future__ import annotations
import http.client, socket, ssl, time, urllib.parse, uuid
from dataclasses import dataclass, field
from .core import Endpoint, EventBus, ParamLocation, ScopeRule, is_private_ip

DEFAULT_TIMEOUT = 12.0


# ---------------------------------------------------------------- Mutations
@dataclass
class RequestMutation:
    """A single, replayable modification of an endpoint's request."""
    endpoint: Endpoint
    param_name: str = ""
    param_location: ParamLocation = ParamLocation.QUERY
    param_value: str = ""
    method: str = ""
    body_override: str = ""
    extra_headers: dict = field(default_factory=dict)
    note: str = ""


@dataclass
class Response:
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ""
    elapsed: float = 0.0
    url: str = ""
    error: str = ""
    request_id: str = ""

    @property
    def ok(self): return 200 <= self.status < 300


class RequestEngine:
    """Owns transport, timeouts, redirects, scope re-check after every hop."""
    def __init__(self, scope: ScopeRule, bus: EventBus, timeout: float = DEFAULT_TIMEOUT,
                 adaptive_timeout: float | None = None):
        self.scope, self.bus, self.timeout = scope, bus, adaptive_timeout or timeout
        self.base_timeout = timeout
        self.requests_sent = 0
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    # ---- build concrete URL/body from mutation
    def _render(self, m: RequestMutation) -> tuple[str, str, dict, str]:
        ep = m.endpoint
        q = [(p.name, p.value) for p in ep.parameters if p.location == ParamLocation.QUERY]
        body = m.body_override
        if m.param_name:
            hit = False
            q = []
            for p in ep.parameters:
                if p.location == ParamLocation.QUERY:
                    if p.name == m.param_name:
                        q.append((p.name, m.param_value)); hit = True
                    else:
                        q.append((p.name, p.value))
            if not hit and m.param_location == ParamLocation.QUERY:
                q.append((m.param_name, m.param_value))
            if m.param_location == ParamLocation.BODY and not m.body_override:
                fields = [(p.name, p.value) for p in ep.parameters if p.location == ParamLocation.BODY]
                fields = [(m.param_name, m.param_value) if f[0] == m.param_name else f for f in fields]
                body = urllib.parse.urlencode(fields)
        parsed = urllib.parse.urlsplit(ep.url)
        base = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        url = base + ("?" + urllib.parse.urlencode(q) if q else "")
        if m.param_location == ParamLocation.PATH and m.param_name:
            url = url.replace("{" + m.param_name + "}", urllib.parse.quote(m.param_value, safe=""))
        headers = {"User-Agent": "Mozilla/5.0 (compatible; Sentinel/2.0; +security-scanner)"}
        headers.update(ep.headers); headers.update(m.extra_headers)
        return url, m.method or ep.method, headers, body

    # ---- scope gate (checked BEFORE request and AFTER every redirect)
    def _scope_ok(self, url: str) -> tuple[bool, str]:
        p = urllib.parse.urlsplit(url)
        if p.scheme not in self.scope.allowed_schemes:
            return False, f"scheme {p.scheme} not allowed"
        host = p.hostname or ""
        if self.scope.allowed_hosts and host not in self.scope.allowed_hosts:
            if not any(host.endswith("." + d) or host == d for d in self.scope.allowed_domains):
                return False, f"host {host} outside allowed set"
        if self.scope.allowed_ports and p.port and p.port not in self.scope.allowed_ports:
            return False, f"port {p.port} not allowed"
        for dp in self.scope.denied_paths:
            if p.path.startswith(dp):
                return False, f"path matches denied prefix {dp}"
        if not self.scope.allow_private and is_private_ip(host):
            return False, f"private/localhost host {host} blocked by scope policy"
        return True, ""

    def send(self, m: RequestMutation) -> Response:
        url, method, headers, body = self._render(m)
        ok, why = self._scope_ok(url)
        if not ok:
            self.bus.emit("RequestBlockedByScope", url=url, reason=why)
            return Response(status=0, url=url, error="scope:" + why)
        rid = "req-" + uuid.uuid4().hex[:8]
        t0 = time.time()
        self.requests_sent += 1
        try:
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme == "https":
                conn = http.client.HTTPSConnection(parsed.hostname, parsed.port, timeout=self.timeout, context=self._ctx)
            else:
                conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=self.timeout)
            path = parsed.path + ("?" + parsed.query if parsed.query else "")
            conn.request(method, path, body=body if method in ("POST", "PUT", "PATCH") else None, headers=headers)
            r = conn.getresponse()
            raw = r.read(2_000_000)
            hdrs = {k.lower(): v for k, v in r.getheaders()}
            # ---- redirect handling with scope re-check (Phase 3 requirement)
            hops = 0
            while r.status in (301, 302, 303, 307, 308) and "location" in hdrs and hops < self.scope.max_redirects:
                nxt = urllib.parse.urljoin(url, hdrs["location"])
                ok2, why2 = self._scope_ok(nxt)
                if not ok2:
                    self.bus.emit("RedirectBlockedByScope", url=nxt, reason=why2)
                    break
                pu = urllib.parse.urlsplit(nxt)
                if pu.hostname != parsed.hostname and not self.scope.follow_cross_host:
                    break
                conn.close()
                if pu.scheme == "https":
                    conn = http.client.HTTPSConnection(pu.hostname, pu.port, timeout=self.timeout, context=self._ctx)
                else:
                    conn = http.client.HTTPConnection(pu.hostname, pu.port, timeout=self.timeout)
                conn.request("GET", pu.path + ("?" + pu.query if pu.query else ""), headers=headers)
                r = conn.getresponse(); raw = r.read(2_000_000)
                hdrs = {k.lower(): v for k, v in r.getheaders()}
                url = nxt; hops += 1
            conn.close()
            resp = Response(status=r.status, headers=hdrs, body=raw.decode("utf-8", "replace"),
                            elapsed=time.time() - t0, url=url, request_id=rid)
            self.bus.emit("ResponseReceived", request_id=rid, url=url, status=r.status,
                          bytes=len(raw), ms=int(resp.elapsed * 1000))
            return resp
        except (socket.timeout, TimeoutError) as e:
            self.bus.emit("RequestTimeout", url=url, timeout=self.timeout)
            return Response(url=url, error=f"timeout:{type(e).__name__}", elapsed=time.time() - t0, request_id=rid)
        except Exception as e:
            self.bus.emit("RequestError", url=url, error=f"{type(e).__name__}: {e}"[:200])
            return Response(url=url, error=f"{type(e).__name__}: {e}"[:200], elapsed=time.time() - t0, request_id=rid)


def make_session_cookie_ep(ep: Endpoint, cookies: dict) -> Endpoint:
    """Phase 6: Session/Auth — clone endpoint with session cookies attached."""
    import copy
    c = copy.deepcopy(ep); c.cookies.update(cookies); c.auth_context = "session"
    return c

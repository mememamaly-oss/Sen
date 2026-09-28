"""Phase 51: Authentication Engine — login, session validation, self-healing re-auth.

Design (three rules, all live-proven on demo.testfire.net):
  AUTH-01  Form-intelligent login: GET the login page (ENG-05 jar primes the
           session cookie), parse the REAL form (action + hidden fields — CSRF
           tokens ride verbatim as TOKEN params, never mutated), POST the
           credentials (ENG-06 serializes the body). Live-caught: a naive
           POST-to-login-URL with hard-coded fields is structurally blind to
           session-bound CSRF tokens and transmits nothing without ENG-06.
  AUTH-02  Deterministic success oracle: success = the login POST's first-hop
           redirect (ENG-01 preserves it even though the engine follows) does
           NOT land on a login-marked path AND (when configured) the landing
           body carries the success marker. The landing URL becomes the
           authenticated crawl seed — the authenticated surface (/bank/* on
           Altoro) is only linked from post-login pages, never from the
           anonymous homepage.
  AUTH-03  Session-loss watchdog: a transparent engine proxy inspects EVERY
           response of the scan; a request to a non-login endpoint that gets
           redirected to a login-marked path means the session died mid-scan.
           The proxy re-authenticates (budget-capped), REPLAYS the exact same
           mutation once, and reports both attempts in events. Deterministic
           self-repair in the same spirit as OP-01: no silent degradation.
"""
from __future__ import annotations
import urllib.parse
from dataclasses import dataclass, field

from .core import Endpoint, EventBus, Parameter, ParamLocation, ScopeRule
from .http_engine import RequestEngine, RequestMutation


@dataclass
class AuthProfile:
    """Declarative description of one login flow. Defaults match AltoroJ
    (demo.testfire.net): GET /login.jsp, POST /doLogin {uid, passw}."""
    login_url: str                    # page carrying the login form (GET first)
    username: str = ""
    password: str = ""
    user_field: str = "uid"
    pass_field: str = "passw"
    action_url: str = ""              # empty = learn from the form's action
    extra_fields: dict = field(default_factory=dict)   # e.g. {"btnSubmit": "Login"}
    success_marker: str = ""          # substring expected in the landing page body
    login_marker: str = "login"       # a redirect hop whose path contains this = session gate
    max_reauth: int = 5               # AUTH-03 budget cap (prevents credential hammering)
    validate_url: str = ""            # page fetched to confirm the session; default = landing


@dataclass
class AuthState:
    authenticated: bool = False
    landing_url: str = ""
    logins: int = 0
    reauths: int = 0
    failed_reauths: int = 0
    last_error: str = ""


class AuthEngine:
    """Executes the login flow against a live target using the scan's own
    RequestEngine — the harvested session rides the ENG-05 cookie jar, so every
    later request (discovery, detectors, verifier) automatically carries it."""

    def __init__(self, profile: AuthProfile, engine: RequestEngine, bus: EventBus):
        self.p, self.engine, self.bus = profile, engine, bus
        self.state = AuthState()

    # ---------------------------------------------------------------- helpers
    def _login_marker_hit(self, url: str) -> bool:
        try:
            path = urllib.parse.urlsplit(url).path.lower()
        except Exception:
            return False
        return self.p.login_marker.lower() in path

    # ---------------------------------------------------------------- login
    def login(self) -> bool:
        """AUTH-01 + AUTH-02. Returns True when the session is confirmed."""
        self.state.logins += 1
        base = self.p.login_url
        # 1. prime the session (anonymous GET also reveals the true form)
        r0 = self.engine.send(RequestMutation(
            endpoint=Endpoint(url=base, method="GET"), note="auth-prime"))
        if r0.error:
            self.state.last_error = f"login page unreachable: {r0.error}"
            self.bus.emit("AuthFailed", reason="prime", error=self.state.last_error)
            return False

        # 2. learn the form (action + fields incl. hidden CSRF tokens)
        action, fields = self._parse_login_form(r0.body or "")
        target = self.p.action_url or action or base
        action_abs = urllib.parse.urljoin(base, target)
        # credential fields first, then profile extras, then the form's own
        # hidden fields (CSRF rides verbatim — Parameter.classify marks it TOKEN)
        params = [Parameter(self.p.user_field, ParamLocation.BODY, self.p.username),
                  Parameter(self.p.pass_field, ParamLocation.BODY, self.p.password)]
        for n, v in self.p.extra_fields.items():
            params.append(Parameter(n, ParamLocation.BODY, v))
        for n, v in fields:
            if n in (self.p.user_field, self.p.pass_field) or any(x.name == n for x in params):
                continue
            params.append(Parameter(n, ParamLocation.BODY, v).classify())

        # 3. submit (ENG-06 serializes the body; ENG-05 replays the session cookie)
        ep = Endpoint(url=action_abs, method="POST", parameters=params)
        r = self.engine.send(RequestMutation(endpoint=ep, note="auth-submit"))
        if r.error:
            self.state.last_error = f"login submit failed: {r.error}"
            self.bus.emit("AuthFailed", reason="submit", error=self.state.last_error)
            return False

        # 4. AUTH-02 deterministic success oracle
        hop = r.hop_location()
        redirected_to_login = bool(hop) and self._login_marker_hit(hop)
        if not hop or redirected_to_login:
            self.state.last_error = (f"login rejected: POST -> {hop or r.url} "
                                      f"(status {r.status}, redirected_to_login={redirected_to_login})")
            self.bus.emit("AuthFailed", reason="credentials", error=self.state.last_error)
            return False
        landing = hop if hop else (self.p.validate_url or base)
        landing = urllib.parse.urljoin(base, landing)

        # 5. confirm the session on the landing page (marker if configured)
        rv = self.engine.send(RequestMutation(
            endpoint=Endpoint(url=landing, method="GET"), note="auth-validate"))
        if rv.error:
            self.state.last_error = f"landing unreachable: {rv.error}"
            self.bus.emit("AuthFailed", reason="landing", error=self.state.last_error)
            return False
        if self.p.success_marker and self.p.success_marker.lower() not in (rv.body or "").lower():
            self.state.last_error = f"success marker missing on landing {landing}"
            self.bus.emit("AuthFailed", reason="marker", error=self.state.last_error)
            return False
        # a landing that bounces straight back to the login page = not authenticated
        if rv.redirect_chain and any(self._login_marker_hit(u) for _, u in rv.redirect_chain):
            self.state.last_error = f"landing {landing} bounced to login"
            self.bus.emit("AuthFailed", reason="bounce", error=self.state.last_error)
            return False

        self.state.authenticated = True
        self.state.landing_url = landing
        self.bus.emit("Authenticated", user=self.p.user_field, landing=landing,
                      logins=self.state.logins)
        return True

    def _parse_login_form(self, html: str) -> tuple[str, list[tuple[str, str]]]:
        """Find the form containing the credential fields; return (action, fields).
        Reuses the discovery HTML parser (same input -> same output)."""
        try:
            from .discovery import _LinkParser
            hp = _LinkParser(); hp.feed(html)
        except Exception:
            return "", []
        want = {self.p.user_field.lower(), self.p.pass_field.lower()}
        for form in hp.forms:
            names = {n.lower() for n, _ in form["params"]}
            if want & names:
                return form.get("action", ""), list(form["params"])
        return "", []

    # ---------------------------------------------------------------- watchdog
    def session_lost(self, m: RequestMutation, r) -> bool:
        """AUTH-03 detection rule: we asked for a non-login endpoint and the
        server answered by sending us to a login-marked path."""
        if r is None or getattr(r, "error", ""):
            return False
        chain = getattr(r, "redirect_chain", []) or []
        if not chain:
            return False
        asked_login = self._login_marker_hit(m.endpoint.url)
        if asked_login:
            return False                      # navigating to login pages is normal
        return any(self._login_marker_hit(u) for _, u in chain)

    def reauth(self) -> bool:
        """Budget-capped re-login. Deterministic throttle: never more than
        max_reauth total, never counts a failed attempt as success."""
        if self.state.reauths >= self.p.max_reauth:
            self.state.failed_reauths += 1
            self.bus.emit("AuthBudgetExhausted", reauths=self.state.reauths)
            return False
        self.state.reauths += 1
        ok = self.login()
        self.bus.emit("AuthReauth", attempt=self.state.reauths, ok=ok)
        return ok


class AuthedEngineProxy:
    """Transparent proxy over RequestEngine. Every send() is inspected for the
    AUTH-03 session-loss signature; on detection the proxy re-authenticates and
    replays the SAME mutation exactly once, so a mid-scan session expiry costs
    one extra request instead of silently degrading the whole authenticated
    surface to anonymous pages (live-caught class of failure)."""
    def __init__(self, inner: RequestEngine, auth: AuthEngine):
        self._inner, self._auth = inner, auth

    def send(self, m: RequestMutation):
        r = self._inner.send(m)
        if not self._auth.state.authenticated:
            return r
        if self._auth.session_lost(m, r):
            self._auth.bus.emit("SessionLostDetected", url=m.endpoint.url,
                                reauths=self._auth.state.reauths)
            if self._auth.reauth():
                r2 = self._inner.send(m)          # one replay with the fresh session
                return r2
        return r

    # ---- everything else delegates to the real engine (cookie jar, counters,
    # scope gate, timeouts — the proxy is invisible to callers)
    def __getattr__(self, name):
        return getattr(self._inner, name)

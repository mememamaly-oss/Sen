"""SENTINEL v2.8.0 — Multi-User Authorization Engine (Phase 56).

The question this engine answers is not "is this input injectable" but
"WHO can do WHAT" — the authorization plane:

  * IDOR / BOLA            — a low-privilege session retrieves ANOTHER
                             account's private object (victim-marker oracle,
                             reproduced with a fresh victim: VR-17).
  * Vertical escalation    — a low-privilege session receives the privileged
                             view of an admin-only surface. Admin-only is
                             derived from a DIFFERENTIAL LANDING CRAWL (links
                             reachable from the privileged account's landing
                             but absent from every lower-privilege landing)
                             plus path hints, and the finding requires the
                             full access differential: anonymous gated,
                             privileged 200, low-privilege 200 with the
                             privileged BODY (VR-18 fresh replay).
  * Access matrix          — role x endpoint statuses, the auditable account
                             of who can reach what (feeds the Application Map).

Safety contract: GET-only replays (no state changes), per-engine isolated
sessions (one cookie jar per account — no session cross-contamination),
deterministic candidate ordering, budget caps on every phase, and honest
degradation (0 findings, loud stats) when logins fail or roles are absent.

False-positive disciplines:
  * the IDOR oracle is a UNIQUE victim marker in the body (an email/username
    only that account owns); a response carrying MULTIPLE account markers is
    a directory/listing surface, not object-level access — skipped.
  * admin reading user objects is plausibly intended: only NON-top-rank
    accounts act as IDOR attackers.
  * vertical requires the low-privilege body to MATCH the privileged body —
    a lower-privilege 200 that is a different (correct) view is healthy
    access control, not escalation.
"""
from __future__ import annotations
import difflib
import re
import urllib.parse
from dataclasses import dataclass, field

from .auth import AuthEngine, AuthProfile
from .core import (Endpoint, Evidence, Finding, FindingStatus, ScopeRule,
                   Severity, Verification)
from .http_engine import RequestEngine, RequestMutation

ROLE_RANK = {"admin": 0, "administrator": 0, "root": 0,
             "manager": 1, "moderator": 1, "supervisor": 1,
             "user": 2, "member": 2, "customer": 2, "client": 2, "viewer": 2,
             "guest": 3, "anonymous": 3}

ADMIN_PATH_RE = re.compile(r"/(admin|manage|management|console|internal|dashboard|moderation)(/|$|\.)",
                           re.I)
ID_PARAM_NAMES = {"user_id", "userid", "uid", "account", "account_id", "acct",
                  "customer_id", "profile_id", "doc_id", "order_id", "object_id",
                  "record_id", "employee_id", "member_id"}


def _rank(role: str) -> int:
    return ROLE_RANK.get((role or "").lower(), 2)


@dataclass
class AuthzAccount:
    name: str
    role: str
    username: str
    password: str
    marker: str = ""          # unique substring proving THIS account's data
    object_id: str = ""       # this account's object identifier


@dataclass
class AuthzConfig:
    login_url: str                     # form-carrying page (AuthProfile semantics)
    accounts: list[AuthzAccount] = field(default_factory=list)
    user_field: str = "uid"
    pass_field: str = "passw"
    success_marker: str = ""
    login_marker: str = "login"
    max_vertical: int = 15
    max_idor_endpoints: int = 40
    max_idor_probes: int = 60

    @classmethod
    def from_dict(cls, d: dict, target_url: str = "") -> "AuthzConfig":
        login = d.get("login_url", "")
        if login and not login.startswith(("http://", "https://")):
            login = target_url.rstrip("/") + (login if login.startswith("/") else "/" + login)
        accounts = [AuthzAccount(
            name=str(a.get("name", a.get("username", "acct"))),
            role=str(a.get("role", "user")),
            username=str(a.get("username", "")),
            password=str(a.get("password", "")),
            marker=str(a.get("marker", "")),
            object_id=str(a.get("object_id", "")))
            for a in d.get("accounts", [])]
        return cls(login_url=login, accounts=accounts,
                   user_field=d.get("user_field", "uid"),
                   pass_field=d.get("pass_field", "passw"),
                   success_marker=d.get("success_marker", ""),
                   login_marker=d.get("login_marker", "login"),
                   max_vertical=int(d.get("max_vertical", 15)),
                   max_idor_endpoints=int(d.get("max_idor_endpoints", 40)),
                   max_idor_probes=int(d.get("max_idor_probes", 60)))


class AuthzEngine:
    """Runs the multi-user authorization battery after discovery."""

    def __init__(self, cfg: AuthzConfig, scope: ScopeRule, bus, timeout: float = 12.0):
        self.cfg, self.scope, self.bus, self.timeout = cfg, scope, bus, timeout
        self.sessions: dict[str, dict] = {}       # name -> {account, engine, landing, rank}
        self._anon = RequestEngine(scope, bus, timeout=timeout)
        self._extra_requests = 0                  # anon-engine honesty counter
        self.matrix: dict[str, dict[str, int]] = {}
        self.errors: list[str] = []

    # ---------------------------------------------------------------- helpers
    def _login_all(self) -> int:
        ok = 0
        for acc in self.cfg.accounts:
            eng = RequestEngine(self.scope, self.bus, timeout=self.timeout)
            profile = AuthProfile(
                login_url=self.cfg.login_url, username=acc.username,
                password=acc.password, user_field=self.cfg.user_field,
                pass_field=self.cfg.pass_field, success_marker=self.cfg.success_marker,
                login_marker=self.cfg.login_marker)
            auth = AuthEngine(profile, eng, self.bus)
            if auth.login():
                self.sessions[acc.name] = {"account": acc, "engine": eng,
                                           "landing": auth.state.landing_url,
                                           "rank": _rank(acc.role)}
                ok += 1
            else:
                self.errors.append(f"{acc.name}: {auth.state.last_error[:120]}")
        return ok

    def _gated(self, resp) -> bool:
        """Anonymous gate: 401/403 or a redirect onto the login-marked path."""
        if resp is None or resp.error or not resp.status:
            return False
        if resp.status in (401, 403):
            return True
        marker = self.cfg.login_marker.lower()
        hops = [u for _, u in (resp.redirect_chain or [])] + [resp.hop_location()]
        return any(marker in urllib.parse.urlsplit(u).path.lower() for u in hops if u)

    @staticmethod
    def _similar(a: str, b: str) -> float:
        na = re.sub(r"\s+", " ", a or "")[:600]
        nb = re.sub(r"\s+", " ", b or "")[:600]
        return difflib.SequenceMatcher(None, na, nb).ratio()

    def _landing_links(self, sess) -> set[str]:
        r = sess["engine"].send(RequestMutation(
            endpoint=Endpoint(url=sess["landing"], method="GET"), note="authz-landing"))
        if r.error:
            return set()
        try:
            from .discovery import _LinkParser
            hp = _LinkParser()
            hp.feed(r.body or "")
        except Exception:
            return set()
        host = urllib.parse.urlsplit(sess["landing"]).netloc
        out = set()
        for href in hp.links:
            try:
                p = urllib.parse.urlsplit(urllib.parse.urljoin(sess["landing"], href))
            except Exception:
                continue
            if p.netloc == host and p.path:
                out.add(p.path)
        return out

    def _fetch(self, engine, ep, note, param_name="", param_value=""):
        m = RequestMutation(endpoint=ep, note=note,
                            param_name=param_name, param_value=param_value)
        before = engine.requests_sent
        r = engine.send(m)
        if engine is self._anon:
            self._extra_requests += engine.requests_sent - before
        return r

    def _mx(self, url: str, key: str, status, resp=None) -> None:
        # Honesty in the matrix: when the engine FOLLOWED a redirect, record the
        # GATE status (first hop) — a 302-to-login recorded as "200" (the login
        # page it landed on) would misrepresent the access boundary.
        if resp is not None and getattr(resp, "redirect_chain", None):
            status = resp.redirect_chain[0][0]
        self.matrix.setdefault(url.split("?")[0], {})[key] = int(status or 0)

    # ---------------------------------------------------------------- phases
    def _vertical(self, endpoints: list[Endpoint]) -> list[Finding]:
        findings = []
        by_path: dict[str, Endpoint] = {}
        for ep in endpoints:
            if (ep.method or "GET").upper() == "GET" and ep.url.split("?")[0] not in by_path:
                by_path[ep.url.split("?")[0]] = ep
        # differential landing links: privileged-only surfaces
        links_by_name = {n: self._landing_links(s) for n, s in sorted(self.sessions.items())}
        candidates: set[str] = set()
        names = list(links_by_name)
        for h in names:
            for l in names:
                if self.sessions[h]["rank"] < self.sessions[l]["rank"]:
                    candidates |= (links_by_name[h] - links_by_name[l])
        candidates |= {p for p in by_path if ADMIN_PATH_RE.search(p)}
        ordered = sorted(candidates & set(by_path))[:self.cfg.max_vertical]
        top = [s for s in self.sessions.values() if s["rank"] == min(x["rank"] for x in self.sessions.values())]
        lows = [s for s in self.sessions.values() if s["rank"] > top[0]["rank"]]
        if not lows:
            return findings                       # single-role deployment: no ladder to climb
        for path in ordered:
            ep = by_path[path]
            anon = self._fetch(self._anon, ep, "authz-anon")
            self._mx(ep.url, "anonymous", anon.status, resp=anon)
            high = None
            for s in sorted(top, key=lambda x: x["account"].name):
                high = self._fetch(s["engine"], ep, "authz-high")
                self._mx(ep.url, f"role:{s['account'].role}", high.status, resp=high)
                if not high.error and high.ok:
                    break
            if high is None or high.error or not high.ok:
                continue                          # privileged view unavailable: no oracle
            for s in sorted(lows, key=lambda x: (-x["rank"], x["account"].name)):
                low = self._fetch(s["engine"], ep, "authz-low")
                self._mx(ep.url, f"role:{s['account'].role}", low.status, resp=low)
                if low.error or not low.ok:
                    continue
                sim = self._similar(high.body, low.body)
                if not self._gated(anon) or sim < 0.6:
                    continue
                cand = Finding(
                    "vertical_privilege_escalation", Severity.HIGH, ep.url, "",
                    ep.method or "GET",
                    [Evidence("role_boundary_bypass",
                              f"low-privilege session (role={s['account'].role}, "
                              f"account={s['account'].name}) received the privileged "
                              f"view of an admin-only surface: anonymous -> gated "
                              f"(HTTP {anon.status}), privileged -> 200, "
                              f"role={s['account'].role} -> 200 with body similarity "
                              f"{sim:.2f} to the privileged view", low.request_id)],
                    status=FindingStatus.CANDIDATE)
                cand.authz_context = (f"attacker={s['account'].name}(role={s['account'].role}) "
                                      f"surface=privileged")
                # VR-18: fresh replay with the SAME low-privilege session
                vr = self._fetch(s["engine"], ep, "authz-verify")
                ok = (not vr.error and vr.ok
                      and self._similar(high.body, vr.body) >= 0.6)
                cand.verification = Verification(
                    method="re-test:fresh-privileged-replay", passed=ok,
                    confidence=0.9 if ok else 0.15, rounds=1,
                    notes=f"fresh replay with role={s['account'].role} session "
                          f"still returned the privileged view: {ok}")
                cand.confidence = cand.verification.confidence
                cand.status = FindingStatus.VERIFIED if ok else FindingStatus.REJECTED
                findings.append(cand)
                break                             # one finding per surface
        return findings

    def _idor(self, endpoints: list[Endpoint]) -> list[Finding]:
        findings = []
        accounts = [s["account"] for s in self.sessions.values()]
        if len(accounts) < 2:
            return findings
        top_rank = min(_rank(a.role) for a in accounts)
        attackers = [a for a in accounts if _rank(a.role) > top_rank] or accounts
        all_markers = [a.marker for a in accounts if a.marker]
        done = 0
        found_paths: set[str] = set()
        for ep in sorted(endpoints, key=lambda e: e.url):
            if done >= self.cfg.max_idor_endpoints:
                break
            if (ep.method or "GET").upper() != "GET":
                continue
            if ep.url.split("?")[0] in found_paths:
                continue
            p = next((p for p in ep.parameters
                      if ((p.name or "").lower() in ID_PARAM_NAMES
                          or (p.name or "").lower().endswith(("_id", "_num")))
                      and p.kind.value != "token"), None)
            if p is None:
                continue
            done += 1
            hit = False
            for acc in sorted(attackers, key=lambda a: a.name):
                if hit:
                    break
                sess = self.sessions.get(acc.name)
                if sess is None:
                    continue
                for victim in sorted(accounts, key=lambda a: a.name):
                    if victim.name == acc.name or not victim.marker or not victim.object_id:
                        continue
                    probe = self._fetch(sess["engine"], ep, "authz-idor",
                                        param_name=p.name, param_value=victim.object_id)
                    self._mx(ep.url, f"role:{acc.role}", probe.status, resp=probe)
                    if probe.error or not probe.ok or victim.marker not in (probe.body or ""):
                        continue
                    # listing guard: multiple distinct account markers = directory
                    # surface, not object-level access
                    markers_seen = sum(1 for m in all_markers if m in (probe.body or ""))
                    if markers_seen > 1:
                        continue
                    horizontal = " (horizontal, same-role)" if _rank(acc.role) == _rank(victim.role) \
                        else " (cross-role)"
                    cand = Finding(
                        "idor_bola", Severity.HIGH, ep.url, p.name, ep.method or "GET",
                        [Evidence("object_access_broken",
                                  f"account {acc.name} (role={acc.role}) retrieved "
                                  f"account {victim.name}'s private object via "
                                  f"{p.name}={victim.object_id}: victim marker "
                                  f"present in response{horizontal} — no object-level "
                                  "authorization", probe.request_id)],
                        status=FindingStatus.CANDIDATE)
                    cand.authz_context = (f"attacker={acc.name}(role={acc.role}) "
                                          f"victim={victim.name}(role={victim.role})")
                    # VR-17: FRESH victim (different account) with the same attacker
                    others = [v for v in sorted(accounts, key=lambda a: a.name)
                              if v.name not in (acc.name, victim.name)
                              and v.marker and v.object_id]
                    fresh = others[0] if others else victim
                    vr = self._fetch(sess["engine"], ep, "authz-verify",
                                     param_name=p.name, param_value=fresh.object_id)
                    ok = (not vr.error and vr.ok and fresh.marker in (vr.body or ""))
                    cand.verification = Verification(
                        method="re-test:fresh-victim-object", passed=ok,
                        confidence=0.9 if ok else 0.15, rounds=1,
                        notes=f"fresh victim object ({p.name}={fresh.object_id}, "
                              f"account={fresh.name}) also readable by {acc.name}: {ok}")
                    cand.confidence = cand.verification.confidence
                    cand.status = FindingStatus.VERIFIED if ok else FindingStatus.REJECTED
                    findings.append(cand)
                    found_paths.add(ep.url.split("?")[0])
                    hit = True
                    break            # one finding per endpoint; next endpoint continues
        return findings

    # ---------------------------------------------------------------- run
    def run(self, endpoints: list[Endpoint]) -> dict:
        logins_ok = self._login_all()
        roles = sorted({s["account"].role for s in self.sessions.values()})
        findings: list[Finding] = []
        if logins_ok >= 2:
            findings.extend(self._vertical(endpoints))
            findings.extend(self._idor(endpoints))
        engine_reqs = sum(s["engine"].requests_sent for s in self.sessions.values())
        return {
            "findings": findings,
            "matrix": self.matrix,
            "stats": {
                "accounts_configured": len(self.cfg.accounts),
                "accounts_logged_in": logins_ok,
                "roles": roles,
                "matrix_endpoints": len(self.matrix),
                "login_errors": self.errors[:5],
                "requests": engine_reqs + self._extra_requests,
                "ran": logins_ok >= 2,
            },
        }

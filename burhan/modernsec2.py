"""Owner order part 3 (2026-10-31): NEW detection layers — modern battery v2.

FEATURE-FLAGGED, OFF BY DEFAULT. Activated only via ScanConfig(modern_v2=True)
or the CLI flag ``--modern-v2``. Shares no code path with modernsec.py or
graphql.py: the existing families (JWT algorithm confusion, JWT none
acceptance, GraphQL introspection, GraphQL batching, GraphQL BOLA, mass
assignment) keep their v4.4.0 semantics untouched — verified by the unchanged
fixture benchmark gate (TP=38/FP=0) in CI.

New checks, each bounded with its cap documented:

3A ``jwt_weak_secret`` — RFC 8725 (JWT Best Current Practices) motivates the
   whole JWT family here: accepting ``alg: none`` and algorithm confusion are
   the two explicit algorithm-agility failures the BCP calls out, already
   covered by modernsec since v4.4.0. The remaining signature-destroying
   failure this layer adds: a GUESSABLE symmetric secret. The check verifies
   the token's HMAC signature OFFLINE against a fixed 27-entry common-secret
   wordlist — zero requests, zero open brute force; the attempt cap IS the
   wordlist length (27), documented here and surfaced in probe counts.

3C ``graphql_aliasing`` — aliasing cost-DoS surface: ONE request carrying
   ALIAS_CAP aliased copies of a cheap field. If the server executes every
   alias in the single request, a naive per-request rate limit sees one
   request while the server performs ALIAS_CAP units of work. This is
   distinct from the existing batching check (an ARRAY of separate
   operation objects) and from the existing introspection/BOLA checks in
   graphql.py. Bounded: at most 2 GraphQL endpoints, 1 request each,
   ALIAS_CAP=20 aliases.

3D ``excessive_data_exposure`` — read-side sibling of the existing
   mass-assignment check (write side): response-SHAPE analysis over JSON API
   surfaces. Flags secret-ish FIELD NAMES (password hashes, private keys,
   internal flags) returned in ordinary responses — the OWASP API Security
   Top 10 "Excessive Data Exposure" pattern (API3:2019 / API6:2023 family).
   Bounded: first 8 JSON-ish GET endpoints, 1 request each; field NAMES are
   reported, values are never republished.

3B ``rebind_toctou`` — DNS-rebinding TOCTOU: does a URL-fetch surface
   RE-RESOLVE a hostname between its validation check and the actual
   outbound connection? (The exact bug class proven real in this project's
   own WsClient — prior order, part 3.1 — which is what this layer
   calibrates against.) Validated against a controlled local flip-after-N
   DNS fixture (fixtures/rebind_fixture.py). Scan-time use requires
   operator-controlled rebinding DNS (BURHAN_REBIND_DNS); without it the
   family is skipped with a loud boundary note, never silently.
"""
from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import re
import socket
import threading

from .core import (Endpoint, EventBus, Finding, FindingStatus, Severity,
                   Evidence, ScopeRule)
from .http_engine import RequestEngine, RequestMutation

MODERN2_TYPES = ("jwt_weak_secret", "graphql_aliasing",
                 "excessive_data_exposure", "rebind_toctou")

# request caps per family (offline wordlist attempts are counted separately:
# jwt_weak_secret sends at most 2 harvest requests; its 27 offline signature
# verifications are the documented wordlist cap, not network traffic)
FAMILY2_CAPS = {"jwt_weak_secret": 2, "graphql_aliasing": 2,
                "excessive_data_exposure": 8, "rebind_toctou": 4}

# 3A: the COMPLETE, EXPLICIT wordlist — the cap is its length (27). This is a
# detection capability, not an open brute-force tool: no user-extensible
# dictionary, no online oracle, offline verification only.
WEAK_SECRET_WORDLIST = (
    "secret", "secretkey", "secret_key", "secret-key", "your-256-bit-secret",
    "your_jwt_secret", "jwt_secret", "jwtsecret", "mysecret", "supersecret",
    "super-secret", "changeme", "change-me", "password", "default",
    "development", "dev", "test", "key", "s3cr3t", "123456", "qwerty",
    "letmein", "admin", "null", "none", "keysecret",
)

ALIAS_CAP = 20          # aliases in the single probe request (3C)
EXPOSURE_EP_CAP = 8     # JSON endpoints examined (3D)

_HS_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
            "HS512": hashlib.sha512}

# 3D: secret-ish FIELD NAMES (name-only detection; values never republished)
_SECRET_FIELD_RE = re.compile(
    r"^(password|passwd|pwd|pass)([_-]?hash)?$", re.I)
_SECRET_FIELD_RE2 = re.compile(
    r"^([a-z0-9_]*?(secret|private[_-]?key|api[_-]?key|access[_-]?key)"
    r"([_-]?(hash|key))?)$|^(is_internal|internal_id|internal_flag)$",
    re.I)

_GQL_PATH_RE = re.compile(r"graphql|gql", re.I)
_AUTHISH = ("login", "signin", "sign-in", "auth", "token", "jwt", "session")


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(seg: str) -> bytes:
    seg = seg + "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode())


def _decode_seg(seg: str) -> dict:
    try:
        d = json.loads(_b64d(seg).decode("utf-8", "replace"))
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _ok(r) -> bool:
    return bool(r is not None and getattr(r, "ok", False)
                and 200 <= int(getattr(r, "status", 0) or 0) < 300)


def _mine_jwt(r) -> str | None:
    """First JWT-shaped token in a response body or Set-Cookie (modernsec parity)."""
    if r is None or getattr(r, "error", True) or not getattr(r, "status", 0):
        return None
    hay = (getattr(r, "body", "") or "") + " ".join(
        f"{k}={v}" for k, v in (getattr(r, "headers", None) or {}).items()
        if k.lower() == "set-cookie")
    m = re.search(r"(ey[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*)", hay)
    return m.group(1) if m else None


class _St2:
    """Battery-v2 state: deterministic order, counters, boundaries."""

    def __init__(self, engine: RequestEngine, seed=None):
        self.engine = engine
        self.seed = seed
        self.findings = []
        self.boundaries = []
        self.counts = {f: {"sent": 0, "offline": 0} for f in MODERN2_TYPES}
        self.requests = 0

    def probe(self, fam, ep, note="", **kw):
        self.counts[fam]["sent"] += 1
        self.requests += 1
        return self.engine.send(
            RequestMutation(endpoint=ep, note=note or f"m2-{fam}", **kw))

    def boundary(self, fam, kind, detail):
        self.boundaries.append({"family": fam, "kind": kind, "detail": detail})

    def find(self, fam, severity, ep, parameter, evidences):
        f = Finding(fam, severity, ep.url, parameter, ep.method, evidences,
                    status=FindingStatus.CANDIDATE)
        f.run_id = getattr(self.engine.bus, "run_id", "")
        self.findings.append(f)
        return f


def probe_counts_of(st: _St2) -> dict:
    return {fam: {"sent": st.counts[fam]["sent"],
                  "offline": st.counts[fam]["offline"],
                  "cap": FAMILY2_CAPS[fam]} for fam in MODERN2_TYPES}


class Modern2Result:
    def __init__(self, findings, boundaries, probe_counts, requests):
        self.findings = findings
        self.boundaries = boundaries
        self.probe_counts = probe_counts
        self.requests = requests


# ------------------------------------------------------------------ 3A
def jwt_weak_secret_offline(token: str):
    """Offline: verify the token's HMAC against the capped wordlist.

    Returns (matched_secret | None, alg, attempts). Zero network traffic;
    the attempt count is bounded by the explicit wordlist (27).
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None, "", 0
    hdr = _decode_seg(parts[0])
    alg = str(hdr.get("alg", "")).upper()
    if alg not in _HS_ALGS:
        return None, alg, 0
    si = (parts[0] + "." + parts[1]).encode("utf-8")
    try:
        sig = _b64d(parts[2])
    except Exception:
        return None, alg, 0
    digest = _HS_ALGS[alg]
    attempts = 0
    for cand in WEAK_SECRET_WORDLIST:
        attempts += 1
        if _hmac.compare_digest(
                _hmac.new(cand.encode("utf-8"), si, digest).digest(), sig):
            return cand, alg, attempts
    return None, alg, attempts


def _jwt_weak_secret(st: _St2, eps):
    authish = [e for e in eps if any(w in e.url.lower() for w in _AUTHISH)]
    for ep in authish[:FAMILY2_CAPS["jwt_weak_secret"]]:
        r = st.probe("jwt_weak_secret", ep, note="m2-jwt-harvest")
        token = _mine_jwt(r)
        if not token:
            st.boundary("jwt_weak_secret", "NO_TOKEN",
                        f"no JWT on {ep.url}")
            continue
        matched, alg, attempts = jwt_weak_secret_offline(token)
        st.counts["jwt_weak_secret"]["offline"] += attempts
        if matched is not None:
            st.find("jwt_weak_secret", Severity.HIGH, ep, "-",
                    [Evidence("weak_hmac_secret",
                              f"HS-secret matches common-secret wordlist "
                              f"entry {matched!r} after {attempts} offline "
                              f"verifications (cap = wordlist = "
                              f"{len(WEAK_SECRET_WORDLIST)}); alg={alg}. "
                              f"Any party can forge tokens signed with this "
                              f"secret. RFC 8725 (JWT BCP) algorithm-agility "
                              f"guidance applies — the signature is only as "
                              f"strong as the secret.",
                              getattr(r, "request_id", "")),
                     Evidence("token_prefix",
                              token[:24] + "…" if len(token) > 24 else token,
                              getattr(r, "request_id", ""))])
        else:
            st.boundary("jwt_weak_secret", "TESTED_NEGATIVE",
                        f"secret did not match the {len(WEAK_SECRET_WORDLIST)}"
                        f"-entry wordlist ({attempts} offline verifications)")


# ------------------------------------------------------------------ 3C
def _graphql_aliasing(st: _St2, eps):
    gql = [e for e in eps if e.method == "POST" and _GQL_PATH_RE.search(e.url)]
    if not gql:
        st.boundary("graphql_aliasing", "SKIPPED_NO_SURFACE",
                    "no GraphQL POST surface in the endpoint map")
        return
    for ep in gql[:FAMILY2_CAPS["graphql_aliasing"]]:
        aliases = " ".join(f"a{i}: __typename" for i in range(ALIAS_CAP))
        body = json.dumps({"query": "{" + aliases + "}"})
        r = st.probe("graphql_aliasing", ep, note="m2-gql-alias",
                     body_override=body,
                     extra_headers={"Content-Type": "application/json"})
        text = str(getattr(r, "body", "") or "")
        executed = sum(1 for i in range(ALIAS_CAP) if f'"a{i}"' in text)
        if executed == ALIAS_CAP:
            st.find("graphql_aliasing", Severity.LOW, ep, "-",
                    [Evidence("alias_fanout_executed",
                              f"ONE request carried {ALIAS_CAP} aliased "
                              f"copies of a field and the server executed "
                              f"every alias ({executed}/{ALIAS_CAP} present "
                              f"in the response). A per-request rate limit "
                              f"counts 1 request while the server performs "
                              f"{ALIAS_CAP} units of resolver work — the "
                              f"aliasing cost-DoS surface. Distinct from "
                              f"batching (array of operations) and covered "
                              f"by CWE-400 resource-consumption guidance.",
                              getattr(r, "request_id", ""))])
        else:
            st.boundary("graphql_aliasing", "TESTED_NEGATIVE",
                        f"server executed {executed}/{ALIAS_CAP} aliases in a "
                        f"single request (complexity limiting or errors)")


# ------------------------------------------------------------------ 3D
def _walk_secret_fields(obj, depth=0, found=None):
    if found is None:
        found = []
    if depth > 3 or len(found) > 12:
        return found
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and (_SECRET_FIELD_RE.match(k)
                                       or _SECRET_FIELD_RE2.match(k)):
                found.append(k)
            _walk_secret_fields(v, depth + 1, found)
    elif isinstance(obj, list):
        for item in obj[:6]:
            _walk_secret_fields(item, depth + 1, found)
    return found


def _excessive_exposure(st: _St2, eps):
    api = [e for e in eps
           if e.method == "GET" and re.search(r"/api|/users|/me|/profile|/account",
                                              e.url, re.I)]
    if not api:
        st.boundary("excessive_data_exposure", "SKIPPED_NO_SURFACE",
                    "no JSON API GET surface in the endpoint map")
        return
    for ep in api[:EXPOSURE_EP_CAP]:
        r = st.probe("excessive_data_exposure", ep, note="m2-exposure")
        body = str(getattr(r, "body", "") or "")
        try:
            doc = json.loads(body)
        except Exception:
            continue
        fields = sorted(set(_walk_secret_fields(doc)))
        if fields:
            st.find("excessive_data_exposure", Severity.MEDIUM, ep, "-",
                    [Evidence("secret_fields_in_response",
                              f"response exposes {len(fields)} secret-ish "
                              f"field NAME(S): {', '.join(fields[:8])}. The "
                              f"documented/expected response shape for an "
                              f"ordinary API read carries none of them — the "
                              f"OWASP API 'Excessive Data Exposure' pattern "
                              f"(field names reported; values not "
                              f"republished).",
                              getattr(r, "request_id", ""))])
        else:
            st.boundary("excessive_data_exposure", "TESTED_NEGATIVE",
                        f"no secret-ish field names on {ep.url}")


# ------------------------------------------------------------------ 3B
class _ProbeListener(threading.Thread):
    """Tiny HTTP listener recording whether the rebind fetch ever lands."""

    def __init__(self, ip="127.0.0.2", port=0):
        super().__init__(daemon=True)
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((ip, port))
        self.srv.listen(8)
        self.srv.settimeout(6.0)
        self.ip, self.port = self.srv.getsockname()[:2]
        self.hits = []

    def run(self):
        while True:
            try:
                conn, _addr = self.srv.accept()
            except (socket.timeout, OSError):
                return
            try:
                conn.settimeout(2.0)
                data = conn.recv(4096)
                self.hits.append(data[:120].decode("utf-8", "replace"))
                conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n"
                             b"Connection: close\r\n\r\nok")
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass


class FlipDNS(threading.Thread):
    """Controlled rebinding fixture: first A query -> PUBLIC ip, then -> internal.

    The canonical calibration harness for the TOCTOU class (owner order 3B):
    the answer flips after ``flip_after`` queries so a client that resolves
    TWICE (validate, then connect) sees two different addresses.
    """

    def __init__(self, host="rebind.burhan.test", ip="127.0.0.1", port=0,
                 public_ip="192.0.2.10", internal_ip="127.0.0.2",
                 flip_after=1):
        super().__init__(daemon=True)
        self.name_host = host
        self.public_ip, self.internal_ip = public_ip, internal_ip
        self.flip_after = flip_after
        self.queries = 0
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.srv.bind((ip, port))
        self.srv.settimeout(0.5)
        self.ip, self.port = self.srv.getsockname()[:2]

    def answer_for(self) -> str:
        self.queries += 1
        return self.public_ip if self.queries <= self.flip_after \
            else self.internal_ip

    def run(self):
        while True:
            try:
                data, addr = self.srv.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                # minimal DNS: answer A queries for ANY name with the flip
                qid = data[:2]
                q = data[12:]
                end = q.find(b"\x00")
                if end < 0:
                    continue
                qname = q[:end]
                qtype = int.from_bytes(q[end + 1:end + 3], "big")
                if qtype != 1:      # A only
                    continue
                ip = self.answer_for()
                rdata = socket.inet_aton(ip)
                answer = (qid + b"\x84\x00" + b"\x00\x01\x00\x01\x00\x00"
                          b"\x00\x00" + qname + b"\x00" + b"\x00\x01"
                          b"\x00\x01" + b"\x00\x00\x00\x1e" + b"\x00\x04"
                          + rdata)
                self.srv.sendto(answer, addr)
            except Exception:
                continue


def rebind_toctou_probe(fetch_url: str, dns: FlipDNS,
                        probe: _ProbeListener, timeout: float = 6.0,
                        engine: RequestEngine | None = None) -> tuple[bool, str]:
    """RED/BLUE oracle: does the fetch surface re-resolve between check and use?

    ``fetch_url`` must accept ?url= (the fixture contract) and will be asked
    to fetch ``http://<dns-host>:<probe-port>/rebind``. Vulnerable = the
    probe listener (on the INTERNAL address) receives the fetch, which is
    only reachable if the client resolved the hostname a SECOND time after
    validation (query 1 answered public -> passes validation; query 2
    answers internal -> the actual connection goes internal).
    """
    target = f"http://{dns.name_host}:{probe.port}/rebind"
    sep = "&" if "?" in fetch_url else "?"
    call = f"{fetch_url}{sep}url={target}"
    if engine is None:
        bus = EventBus("m2-rebind")
        scope = ScopeRule(allow_private=True)
        engine = RequestEngine(scope, bus, timeout=timeout)
    ep = Endpoint(url=call, method="GET")
    try:
        engine.send(RequestMutation(endpoint=ep, note="m2-rebind-probe"))
    except Exception as e:      # noqa: BLE001 — probe errors are outcomes
        return False, f"probe request failed: {type(e).__name__}: {e}"
    deadline = timeout
    import time as _t
    t0 = _t.time()
    while _t.time() - t0 < deadline:
        if probe.hits:
            return True, (f"the fetch landed on {probe.ip}:{probe.port} "
                          f"(internal address) — the surface re-resolved the "
                          f"hostname AFTER validation (DNS queries: "
                          f"{dns.queries}); the validation/connection split "
                          f"is a rebindable TOCTOU")
        _t.sleep(0.1)
    return False, (f"no internal fetch within {timeout:.0f}s "
                   f"(DNS queries: {dns.queries}) — the surface pins or "
                   f"caches the validated address")


def _rebind_toctou(st: _St2, eps, rebind_cfg: dict | None):
    if not rebind_cfg:
        st.boundary("rebind_toctou", "SKIPPED_NO_REBIND_DNS",
                    "no operator-controlled rebinding DNS configured "
                    "(BURHAN_REBIND_DNS) — family skipped loudly, not "
                    "silently; validated against the local fixture "
                    "(fixtures/rebind_fixture.py) in tests")
        return
    fetch_url = str(rebind_cfg.get("fetch_url", ""))
    if not fetch_url:
        st.boundary("rebind_toctou", "SKIPPED_NO_SURFACE",
                    "rebind DNS configured but no fetch surface declared")
        return
    dns = FlipDNS(host=str(rebind_cfg.get("host", "rebind.burhan.test")),
                  port=int(rebind_cfg.get("dns_port", 0)) or 0,
                  internal_ip=str(rebind_cfg.get("internal_ip", "127.0.0.2")))
    probe = _ProbeListener(ip=dns.internal_ip)
    dns.start()
    probe.start()
    vuln, detail = rebind_toctou_probe(
        fetch_url, dns, probe, timeout=float(rebind_cfg.get("timeout", 6.0)),
        engine=st.engine)
    st.counts["rebind_toctou"]["sent"] += 1
    st.requests += 1
    ep = Endpoint(url=fetch_url, method="GET")
    if vuln:
        st.find("rebind_toctou", Severity.HIGH, ep, "-",
                [Evidence("rebind_fetch_landed_internal", detail,
                          "")])
    else:
        st.boundary("rebind_toctou", "TESTED_NEGATIVE", detail)


# ------------------------------------------------------------------ entry
def run_modern_battery_v2(engine: RequestEngine, endpoints, seed=None,
                          rebind_cfg: dict | None = None) -> Modern2Result:
    """Entry point — mirrors modernsec.run_modern_battery (deterministic order)."""
    st = _St2(engine, seed)
    eps = sorted(endpoints or [], key=lambda e: (e.url, e.method))
    _jwt_weak_secret(st, eps)
    _graphql_aliasing(st, eps)
    _excessive_exposure(st, eps)
    _rebind_toctou(st, eps, rebind_cfg)
    return Modern2Result(st.findings, st.boundaries, probe_counts_of(st),
                         st.requests)

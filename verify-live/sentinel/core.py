"""SENTINEL — Deterministic DAST Platform.
Core domain models (Phase 1: Core Engine).
Every scan is reproducible: RunID + Seed + Version + ConfigHash.
"""
from __future__ import annotations
import dataclasses, hashlib, json, time, uuid
from enum import Enum
from typing import Optional
from urllib.parse import urlsplit

VERSION = "2.5.0"
SCANNER_VERSION = "sentinel-core/" + VERSION


class Severity(str, Enum):
    CRITICAL = "critical"; HIGH = "high"; MEDIUM = "medium"; LOW = "low"; INFO = "info"


class FindingStatus(str, Enum):
    CANDIDATE = "candidate"; VERIFIED = "verified"; REJECTED = "rejected"; QUARANTINED = "quarantined"


class DiscoverySource(str, Enum):
    SEED = "seed"; CRAWL_HTML = "crawl:html"; CRAWL_FORM = "crawl:form"; ROBOTS = "robots.txt"
    JS_STATIC = "js:static"; SITEMAP = "sitemap"; MANUAL = "manual"
    DOM = "dom:browser"     # Phase 50: discovered only by rendering in a real browser


# ---------------------------------------------------------------- Target / Scope
@dataclasses.dataclass
class Target:
    url: str
    name: str = ""

    @property
    def host(self): return urlsplit(self.url).hostname or ""


@dataclasses.dataclass
class ScopeRule:
    """Phase 3: Scope Engine rule set. Deny-by-default for private space."""
    allowed_hosts: list = dataclasses.field(default_factory=list)
    allowed_domains: list = dataclasses.field(default_factory=list)   # suffix match
    allowed_schemes: list = dataclasses.field(default_factory=lambda: ["http", "https"])
    allowed_ports: list = dataclasses.field(default_factory=list)     # empty = all public
    denied_paths: list = dataclasses.field(default_factory=list)
    denied_params: list = dataclasses.field(default_factory=list)
    allow_private: bool = False          # localhost/RFC1918/metadata — must be explicit
    allow_metadata_svc: bool = False     # 169.254.169.254 etc.
    max_redirects: int = 5
    follow_cross_host: bool = False


PRIVATE_V4 = [("10.",), ("192.168.",), ("172.",)]  # 172.16-31 handled precisely below
META_V4 = ("169.254.", "100.100.", "fd00:", "fe80:")


def is_private_ip(ip: str) -> bool:
    if not ip: return True
    if ip in ("127.0.0.1", "0.0.0.0", "::1", "localhost"): return True
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("169.254."): return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31: return True
        except Exception:
            return True
    if ip.lower().startswith(("fd", "fe80", "::1")): return True
    return False


# ---------------------------------------------------------------- Parameter / Endpoint
class ParamLocation(str, Enum):
    QUERY="query"; PATH="path"; BODY="body"; JSON="json"; HEADER="header"; COOKIE="cookie"; MULTIPART="multipart"


class ParamKind(str, Enum):
    NUMERIC="numeric"; IDENTIFIER="identifier"; URL="url"; PATH="path"; EMAIL="email"
    SEARCH="search"; HTML="html"; JSON="json"; TOKEN="token"; FILENAME="filename"; GENERIC="generic"


@dataclasses.dataclass
class Parameter:
    name: str
    location: ParamLocation = ParamLocation.QUERY
    value: str = ""
    kind: ParamKind = ParamKind.GENERIC

    def classify(self) -> "Parameter":
        v, n = (self.value or "").strip(), (self.name or "").lower()
        # Phase 50: CSRF/anti-CSRF tokens are flow-control values, never injection
        # targets — mutating them breaks the request (token mismatch) and can only
        # produce noise. They are carried verbatim as siblings so protected flows
        # stay reachable (live-proven on ginandjuice.shop /catalog/subscribe).
        if any(k in n for k in ("csrf", "token", "nonce", "authenticity")):
            self.kind = ParamKind.TOKEN
            return self
        if any(k in n for k in ("url", "redirect", "return", "next", "goto", "dest", "continue")): self.kind = ParamKind.URL
        elif any(k in n for k in ("file","path","page","template","item","doc","load")): self.kind = ParamKind.FILENAME
        elif any(k in n for k in ("id","uid","pid","ref","num")) and v.isdigit(): self.kind = ParamKind.NUMERIC
        elif v.isdigit(): self.kind = ParamKind.NUMERIC
        elif v.startswith(("http://","https://","//")): self.kind = ParamKind.URL
        elif "@" in v and "." in v: self.kind = ParamKind.EMAIL
        elif any(k in n for k in ("q","search","query","keyword","name")): self.kind = ParamKind.SEARCH
        return self


@dataclasses.dataclass
class Endpoint:
    url: str
    method: str = "GET"
    parameters: list = dataclasses.field(default_factory=list)
    headers: dict = dataclasses.field(default_factory=dict)
    cookies: dict = dataclasses.field(default_factory=dict)
    source: DiscoverySource = DiscoverySource.SEED
    auth_context: str = "anonymous"
    tags: list = dataclasses.field(default_factory=list)
    id: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = hashlib.sha1(f"{self.method}|{self.url}|{sorted(p.name for p in self.parameters)}".encode()).hexdigest()[:12]

    def param(self, name: str) -> Optional[Parameter]:
        return next((p for p in self.parameters if p.name == name), None)


# ---------------------------------------------------------------- Evidence / Finding
@dataclasses.dataclass
class Evidence:
    kind: str            # e.g. "response_diff", "marker_in_body", "header_value", "db_error"
    detail: str
    request_id: str = ""
    raw_snippet: str = ""

    def fingerprint_material(self) -> str:
        return f"{self.kind}:{self.detail[:120]}"


@dataclasses.dataclass
class Verification:
    method: str = ""                 # e.g. "re-test:variant", "oracle:2round"
    passed: bool = False
    confidence: float = 0.0
    rounds: int = 0
    notes: str = ""


@dataclasses.dataclass
class Finding:
    type: str                        # e.g. "sql_injection", "xss_reflected"
    severity: Severity = Severity.MEDIUM
    endpoint_url: str = ""
    parameter: str = ""
    method: str = "GET"
    evidence: list = dataclasses.field(default_factory=list)
    verification: Optional[Verification] = None
    confidence: float = 0.0
    status: FindingStatus = FindingStatus.CANDIDATE
    scanner: str = SCANNER_VERSION
    run_id: str = ""
    first_seen: float = dataclasses.field(default_factory=time.time)
    id: str = ""

    def __post_init__(self):
        if not self.id:
            base = f"{self.type}|{self.method}|{self.endpoint_url}|{self.parameter}"
            self.id = "F-" + hashlib.sha1(base.encode()).hexdigest()[:10]

    def fingerprint(self) -> str:
        """Phase 16: dedup fingerprint = asset + endpoint + parameter + vuln + normalized evidence.
        Normalized evidence = sorted unique evidence KINDS (details vary per request instance)."""
        ev = "|".join(sorted({e.kind for e in self.evidence}))[:120]
        base = f"{self.type}|{self.method}|{self.endpoint_url.split('?')[0]}|{self.parameter}|{ev}"
        return hashlib.sha256(base.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "id": self.id, "type": self.type, "severity": self.severity.value,
            "status": self.status.value, "confidence": round(self.confidence, 3),
            "method": self.method, "url": self.endpoint_url, "parameter": self.parameter,
            "evidence": [{"kind": e.kind, "detail": e.detail[:300]} for e in self.evidence],
            "verification": self.verification and {
                "method": self.verification.method, "passed": self.verification.passed,
                "confidence": round(self.verification.confidence, 3), "rounds": self.verification.rounds,
                "notes": self.verification.notes[:300]},
            "scanner": self.scanner, "run_id": self.run_id,
        }


# ---------------------------------------------------------------- Events (Phase 20)
class EventBus:
    """Structured event log — the substrate for failure memory & learning."""
    def __init__(self, run_id: str):
        self.run_id = run_id
        self.events: list[dict] = []

    def emit(self, kind: str, **data):
        ev = {"t": round(time.time(), 3), "run": self.run_id, "kind": kind, **data}
        self.events.append(ev)
        return ev

    def by_kind(self, kind: str) -> list:
        return [e for e in self.events if e["kind"] == kind]


def new_run_id(seed: Optional[str] = None) -> tuple[str, str]:
    """Deterministic reproduction: RunID derived from seed (Phase 36)."""
    seed = seed or uuid.uuid4().hex[:8]
    return "run-" + hashlib.sha1(seed.encode()).hexdigest()[:10], seed

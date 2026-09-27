"""Phase 7: Scan Planner + Phase 8: Detection Framework.
Deterministic, rule-based planner: parameter kind -> candidate vulnerability classes.
Every Detector implements the contract: prepare/mutate/execute/analyze/verify.
"""
from __future__ import annotations
import re, urllib.parse
from .core import (Endpoint, EventBus, Finding, FindingStatus, ParamKind, Severity,
                   Evidence, Verification)
from .http_engine import RequestEngine, RequestMutation

# ------------------------------------------------------------ Planner rules
PLANNER_RULES = [
    (ParamKind.NUMERIC,   ["sql_injection"]),
    (ParamKind.IDENTIFIER,["sql_injection", "idor"]),
    (ParamKind.SEARCH,    ["sql_injection", "xss_reflected"]),
    (ParamKind.URL,       ["open_redirect", "ssrf"]),
    (ParamKind.FILENAME,  ["path_traversal"]),
    (ParamKind.HTML,      ["xss_reflected"]),
    (ParamKind.GENERIC,   ["sql_injection", "xss_reflected"]),
]

def plan_for(ep: Endpoint) -> list[dict]:
    """Deterministic scan plan: (param, vuln_class) pairs."""
    plan = []
    for p in ep.parameters:
        for kind, classes in PLANNER_RULES:
            if p.kind.value == kind.value:
                for c in classes:
                    plan.append({"endpoint": ep, "param": p, "vuln": c})
                break
    return plan


# ------------------------------------------------------------ Detector contract
class Detector:
    name = "base"
    vuln_type = ""
    severity = Severity.MEDIUM
    timeout_hint: float | None = None

    def __init__(self, engine: RequestEngine, bus: EventBus, strategy_store=None):
        self.engine, self.bus, self.strategies = engine, bus, strategy_store

    def candidates(self, ep: Endpoint) -> list[RequestMutation]:
        raise NotImplementedError

    def analyze(self, m: RequestMutation, resp) -> Finding | None:
        raise NotImplementedError


SQL_ERR_PATTERNS = [
    re.compile(r"Microsoft OLE DB Provider", re.I),
    re.compile(r"\[Microsoft\]\[ODBC", re.I),
    re.compile(r"Unclosed quotation mark", re.I),
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"sqlite3?\.(OperationalError|ProgrammingError)", re.I),
    re.compile(r"Warning: mysql_", re.I),
    re.compile(r"PostgreSQL.*ERROR", re.I),
]


class SQLiDetector(Detector):
    """Error-based + boolean-blind oracle. Strategies ordered by verified stats (Phase 19)."""
    name, vuln_type = "sqli", "sql_injection"
    severity = Severity.CRITICAL

    STRATEGIES = {
        "quote_error":   ["'", "''"],                      # syntax break -> 500/error string
        "boolean_and":   ["AND 1=1", "AND 1=2"],           # oracle pair
        "error_or":      ["' OR '1'='1"],
    }

    def candidates(self, ep: Endpoint):
        out = []
        for p in ep.parameters:
            base = p.value if p.value.isdigit() else "1"
            out.append(("quote_error", RequestMutation(endpoint=ep, param_name=p.name, param_value=base + "'")))
            out.append(("boolean_true",  RequestMutation(endpoint=ep, param_name=p.name, param_value=f"{base} AND 1=1")))
            out.append(("boolean_false", RequestMutation(endpoint=ep, param_name=p.name, param_value=f"{base} AND 1=2")))
            # DETECT-01 (live-proven on demo.testfire.net/doLogin): string-context OR-tautology
            # pair with trailing comment — fires on login/auth endpoints where the numeric
            # AND-pair cannot (values quoted as strings in SQL).
            out.append(("or_true",  RequestMutation(endpoint=ep, param_name=p.name, param_value=f"{base}' OR '1'='1' -- ")))
            out.append(("or_false", RequestMutation(endpoint=ep, param_name=p.name, param_value=f"{base}' OR '1'='2' -- ")))
        return out

    def analyze(self, pair, resp_map) -> Finding | None:
        """pair = (endpoint, param). resp_map: strategy->Response."""
        ep, p = pair
        ev = []
        # 1) error-based
        r = resp_map.get("quote_error")
        if r is not None and r.status and not r.ok:
            body = r.body or ""
            for pat in SQL_ERR_PATTERNS:
                mm = pat.search(body)
                if mm:
                    ev.append(Evidence("db_error", f"{pat.pattern[:40]} matched: {mm.group(0)[:80]}", r.request_id))
                    break
        # 2) boolean oracle (status differential, 200 vs 500) — the proven real-world oracle
        rt, rf = resp_map.get("boolean_true"), resp_map.get("boolean_false")
        oracle = False
        if rt is not None and rf is not None and rt.status and rf.status:
            if rt.ok and not rf.ok:
                oracle = True
                ev.append(Evidence("response_diff",
                    f"TRUE probe -> HTTP {rt.status} ({len(rt.body)}B), FALSE probe -> HTTP {rf.status} ({len(rf.body)}B) — boolean oracle", rt.request_id))
            elif abs(len(rt.body or "") - len(rf.body or "")) > max(200, 0.25 * max(len(rt.body or "x"), 1)):
                oracle = True
                ev.append(Evidence("response_diff",
                    f"body-size differential {len(rt.body)}B vs {len(rf.body)}B on condition flip", rt.request_id))
        # 3) DETECT-01 — OR-tautology redirect differential (auth-bypass oracle, string context)
        # ENG-01: hop_location() reads the FIRST-HOP target even when the engine
        # auto-followed the redirect (old code saw only the final 200 — oracle destroyed).
        ot, of = resp_map.get("or_true"), resp_map.get("or_false")
        if ot is not None and of is not None and ot.status and of.status:
            lt, lf = ot.hop_location(), of.hop_location()
            if lt and lf and lt != lf:
                oracle = True
                ev.append(Evidence("redirect_diff",
                    f"OR-tautology redirect differential: TRUE -> {lt}, FALSE -> {lf} — auth-bypass oracle",
                    ot.request_id))
        if not ev:
            return None
        return Finding(type="sql_injection", severity=self.severity, endpoint_url=ep.url,
                       parameter=p.name, method=ep.method, evidence=ev, status=FindingStatus.CANDIDATE)


class XSSDetector(Detector):
    name, vuln_type = "xss", "xss_reflected"
    severity = Severity.HIGH
    CANARY = "sentinelxssmarker"

    def candidates(self, ep: Endpoint):
        return [RequestMutation(endpoint=ep, param_name=p.name,
                param_value=f"<{self.CANARY}>pro41</{self.CANARY}>") for p in ep.parameters]

    def analyze(self, pair, resp):
        ep, p = pair
        if resp is None or not resp.body: return None
        needle = f"<{self.CANARY}>pro41</{self.CANARY}>"
        if needle in resp.body:
            i = resp.body.find(needle)
            ctx = resp.body[max(0, i - 60):i + len(needle) + 30].replace("\n", " ")
            return Finding("xss_reflected", Severity.HIGH, ep.url, p.name, ep.method,
                           [Evidence("unescaped_reflection", f"canary reflected raw in context: …{ctx}…", resp.request_id)],
                           status=FindingStatus.CANDIDATE)
        return None


class TraversalDetector(Detector):
    name, vuln_type = "traversal", "path_traversal"
    severity = Severity.HIGH
    MARKERS = [("[fonts]", "win.ini"), ("[boot loader]", "boot.ini"), ("root:x:0:0:", "/etc/passwd"),
               ("SENTINEL-SECRET-FILE", "fixture secret file")]

    def candidates(self, ep: Endpoint):
        payloads = []
        for depth in (4, 6, 8):
            payloads.append("../" * depth + "windows/win.ini")
            payloads.append("../" * depth + "etc/passwd")
        payloads.append("....//....//....//windows/win.ini")
        return [(pl, RequestMutation(endpoint=ep, param_name=p.name, param_value=pl))
                for p in ep.parameters for pl in payloads[:4]]

    def analyze(self, pair, resp):
        ep, p = pair
        if resp is None or not resp.body: return None
        for marker, fname in self.MARKERS:
            if marker in resp.body:
                i = resp.body.find(marker)
                return Finding("path_traversal", Severity.HIGH, ep.url, p.name, ep.method,
                               [Evidence("file_marker", f"content of {fname} leaked (marker {marker!r} at offset {i})",
                                         resp.request_id, resp.body[i:i + 200])],
                               status=FindingStatus.CANDIDATE)
        return None


class RedirectDetector(Detector):
    name, vuln_type = "redirect", "open_redirect"
    severity = Severity.MEDIUM

    def candidates(self, ep: Endpoint):
        ev = "sentinel-redirect-check.example.org"
        return [(v, RequestMutation(endpoint=ep, param_name=p.name, param_value=v))
                for p in ep.parameters for v in (f"https://{ev}/probe", f"//{ev}/probe")]

    def analyze(self, pair, resp):
        ep, p = pair
        if resp is None: return None
        loc = resp.hop_location()   # ENG-01: chain-aware (same-host followed redirects included)
        if loc and "sentinel-redirect-check.example.org" in loc:
            return Finding("open_redirect", Severity.MEDIUM, ep.url, p.name, ep.method,
                           [Evidence("header_value", f"Location redirects off-site to {loc[:100]}", resp.request_id)],
                           status=FindingStatus.CANDIDATE)
        # reflected/meta/JS redirect context
        if resp.body and ("sentinel-redirect-check.example.org" in resp.body and
                          re.search(r"(location\.href|window\.location|http\.refresh|meta[^>]+refresh)", resp.body, re.I)):
            return Finding("open_redirect", Severity.MEDIUM, ep.url, p.name, ep.method,
                           [Evidence("body_redirect", "off-site URL injected into client redirect sink", resp.request_id)],
                           status=FindingStatus.CANDIDATE)
        return None


# ------------------------------------------------------------ Passive detectors
SECURITY_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options",
                    "x-content-type-options", "referrer-policy"]

def passive_audit(ep: Endpoint, resp) -> list[Finding]:
    out = []
    if resp is None or not resp.status: return out
    missing = [h for h in SECURITY_HEADERS if h not in resp.headers]
    if missing:
        out.append(Finding("missing_security_headers", Severity.LOW, ep.url, "", ep.method,
                    [Evidence("header_absent", f"missing: {', '.join(missing)}", resp.request_id)],
                    status=FindingStatus.CANDIDATE))
    srv = resp.headers.get("server", "")
    if srv and re.search(r"[0-9]+\.[0-9]+", srv):
        out.append(Finding("server_banner_disclosure", Severity.LOW, ep.url, "", ep.method,
                    [Evidence("header_value", f"Server: {srv}", resp.request_id)],
                    status=FindingStatus.CANDIDATE))
    powered = resp.headers.get("x-powered-by", "")
    if powered:
        out.append(Finding("tech_banner_disclosure", Severity.LOW, ep.url, "", ep.method,
                    [Evidence("header_value", f"X-Powered-By: {powered}", resp.request_id)],
                    status=FindingStatus.CANDIDATE))
    return out


ACTIVE_DETECTORS = [SQLiDetector, XSSDetector, TraversalDetector, RedirectDetector]

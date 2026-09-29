"""Phase 54 (stealth + intelligence axes): WAF + technology fingerprinting.

Two PASSIVE observers — zero extra requests, evidence accumulates from the
responses the scan already produces (passive baselines, crawl, probes):

  WafFingerprinter   Named-WAF signature matching (Cloudflare, AWS WAF, ModSecurity,
                    F5 BIG-IP, Imperva, Sucuri, Akamai) from response headers,
                    cookies and block-page bodies. A named WAF in stats is scan
                    CONTEXT: it explains 400/403 deltas and drives the XSS
                    context-probe battery (DETECT-14) — it is never itself a finding.
  TechFingerprinter Server / language / framework / cookie-platform map from
                    Server, X-Powered-By, X-AspNet-Version, X-Generator headers,
                    Set-Cookie platform markers (PHPSESSID/JSESSIONID/ASP.NET),
                    meta generators and DOM markers (ng-app, __VIEWSTATE, wp-content).

Honesty contract: both report only what the target actually emitted, with the
evidence line each conclusion came from. No signature hits -> null result, not a
guessed default ("unknown" is an honest answer; "no WAF" is NOT — an unnamed
filter is indistinguishable from no filter by passive observation alone, and the
active XSS context-probe in detect.py is the component that resolves that).
"""
from __future__ import annotations
import re

# name -> list of (channel, needle) signatures; channels: header:<lc-name> (exact
# or prefix match on value), cookie:<prefix> (Set-Cookie name prefix), body:<substr>
WAF_SIGNATURES: dict[str, list[tuple[str, str]]] = {
    "cloudflare": [("header:server", "cloudflare"), ("header:cf-ray", ""),
                   ("cookie:__cfduid", ""), ("cookie:cf_clearance", "")],
    "aws-waf":    [("header:x-amzn-waf-action", "")],   # x-amzn-waf-action ONLY —
                 # x-amzn-requestid was deliberately EXCLUDED: API Gateway/ALB emit
                 # it on every response; flagging it would claim "AWS WAF" for plain
                 # infra (false attribution, live-caught class of error).
    "modsecurity": [("header:server", "mod_security"), ("body", "mod_security"),
                    ("body", "ModSecurity")],
    "f5-bigip":   [("cookie:ts", ""), ("cookie:bigipserver", ""), ("header:server", "bigip")],
    "imperva":    [("cookie:incap_ses", ""), ("cookie:visid_incap", ""), ("header:x-iinfo", "")],
    "sucuri":     [("header:server", "sucuri"), ("header:x-sucuri-id", "")],
    "akamai":     [("header:server", "akamaighost"), ("header:server", "akamai")],
    "fastly":     [("header:x-served-by", "cache-"), ("header:server", "fastly")],
}

# cookie name -> platform label (session cookie platforms are high-signal: an app
# that sets JSESSIONID is a Java servlet stack whether or not Server says so)
COOKIE_PLATFORMS = {
    "phpsessid": "PHP", "jsessionid": "Java", "asp.net_sessionid": "ASP.NET",
    "aspnetsession": "ASP.NET", "laravel_session": "PHP/Laravel", "csrftoken": "Django/CSRF",
    "rails_session": "Ruby/Rails", "connect.sid": "Node/Express", "_ga": "(analytics)",
    "__cfduid": "Cloudflare",
}

# body markers -> framework label (marker must appear in lowercase body)
BODY_MARKERS = [
    ("ng-app", "AngularJS"), ("ng-controller", "AngularJS"), ("data-ng-app", "AngularJS"),
    ("react-root", "React"), ("data-reactroot", "React"), ("__next", "Next.js"),
    ("__viewstate", "ASP.NET WebForms"), ("wp-content", "WordPress"),
    ("drupal", "Drupal"), ("jquery", "jQuery"),
]

META_GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']{0,60})', re.I)
XPOWERED = ("x-powered-by",)
TECH_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                "x-generator", "x-drupal-cache")

# LIVE-CAUGHT (Phase 54, ginandjuice.shop): Set-Cookie ATTRIBUTE names (Path=/,
# SameSite=Lax, Expires=...) leaked into the cookie-platform list as if they were
# cookie names ("path", "expires", "samesite" appeared as platforms context).
# They are transport metadata, never identities — filter them deterministically.
_COOKIE_ATTRS = {"path", "domain", "expires", "max-age", "samesite", "secure", "httponly",
                 "version", "comment", "partitioned", "priority"}


def _cookie_names(set_cookie_value: str) -> list[str]:
    """Extract real cookie NAMES from a (possibly comma-joined) Set-Cookie value.
    Only the name= part of each first segment counts; attributes are dropped."""
    names = []
    for seg in (set_cookie_value or "").split(","):
        first = seg.strip().split(";")[0]
        if "=" in first:
            n = first.split("=", 1)[0].strip()
            if n and n.lower() not in _COOKIE_ATTRS:
                names.append(n)
    return names


class WafFingerprinter:
    """Passive named-WAF matcher. observe() every response; result() once at end."""

    def __init__(self):
        self._hits: dict[str, list[str]] = {}     # waf name -> evidence lines

    def observe(self, resp) -> None:
        if resp is None:
            return
        hdrs = {k.lower(): v for k, v in (getattr(resp, "headers", None) or {}).items()}
        body = (getattr(resp, "body", "") or "")
        cookies = _cookie_names(hdrs.get("set-cookie", ""))
        for waf, sigs in WAF_SIGNATURES.items():
            for channel, needle in sigs:
                if channel.startswith("header:"):
                    hn = channel.split(":", 1)[1]
                    if hn in hdrs and (not needle or needle in hdrs[hn].lower()):
                        self._hits.setdefault(waf, []).append(f"header {hn}: {hdrs[hn][:60]}")
                elif channel.startswith("cookie:"):
                    cn = channel.split(":", 1)[1]
                    if any(c.lower().startswith(cn) for c in cookies if c):
                        self._hits.setdefault(waf, []).append(f"cookie prefix {cn}")
                elif channel == "body" and needle.lower() in body.lower():
                    self._hits.setdefault(waf, []).append(f"body contains {needle!r}")

    def result(self) -> dict | None:
        """Named WAF map or None (honest null — passive absence is not WAF absence)."""
        if not self._hits:
            return None
        return {"name": ",".join(sorted(self._hits)), "evidence": [e for v in self._hits.values() for e in v]}


class TechFingerprinter:
    """Passive technology map. Same observe/result contract."""

    def __init__(self):
        self._headers: dict[str, str] = {}
        self._cookies: set[str] = set()
        self._markers: set[str] = set()
        self._generators: set[str] = set()

    def observe(self, resp) -> None:
        if resp is None:
            return
        hdrs = {k.lower(): v for k, v in (getattr(resp, "headers", None) or {}).items()}
        for h in TECH_HEADERS:
            if h in hdrs and hdrs[h]:
                self._headers[h] = hdrs[h][:80]
        for c in _cookie_names(hdrs.get("set-cookie", "")):
            self._cookies.add(c.lower())
        body = (getattr(resp, "body", "") or "")
        low = body.lower()
        for marker, label in BODY_MARKERS:
            if marker in low:
                self._markers.add(label)
        for m in META_GENERATOR.finditer(body):
            self._generators.add(m.group(1)[:40])

    def result(self) -> dict:
        frameworks = set(self._markers)
        for g in self._generators:
            frameworks.add(f"generator:{g}")
        for c in sorted(self._cookies):
            if c in COOKIE_PLATFORMS and "analytics" not in COOKIE_PLATFORMS[c]:
                frameworks.add(f"cookies:{COOKIE_PLATFORMS[c]}")
        out = {"headers": dict(sorted(self._headers.items())),
               "cookies": sorted(self._cookies),
               "frameworks": sorted(frameworks)}
        out["angularjs"] = "AngularJS" in self._markers
        return out


class FingerprintCollector:
    """One object wired through the scan: pass every response to observe();
    stats["fingerprint"] = collector.summary() at the end. The angularjs flag
    additionally arms the XSS expression battery (DETECT-14) — that adaptation
    is per-endpoint in detect.py (the page's own body is the ground truth),
    this module records the scan-wide map for the report."""

    def __init__(self):
        self.waf = WafFingerprinter()
        self.tech = TechFingerprinter()

    def observe(self, resp) -> None:
        self.waf.observe(resp)
        self.tech.observe(resp)

    def summary(self) -> dict:
        t = self.tech.result()
        return {"waf": self.waf.result(), "tech": t}

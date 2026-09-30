"""Phase 4: Discovery Engine — HTML crawler, forms, robots.txt, JS static extraction.
Phase 5: Endpoint/Parameter Intelligence (parameters classified on ingest).
"""
from __future__ import annotations
import re, urllib.parse
from html.parser import HTMLParser
from .core import DiscoverySource, Endpoint, Parameter, ParamLocation
from .http_engine import RequestEngine


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.forms = [], []   # forms: (action, method, [params])
        self.divforms = []                # DISC-10: div-based pseudo-forms
        self._cur_form = None
        self._cur_divform = None
        self._div_depth = 0
        # ENG-17 (live-caught on ginandjuice.shop add-to-cart): the parser had
        # NO <select> handling — quantity selects were dropped from the form's
        # parameter list entirely, so the CSRF baseline POST /catalog/cart
        # shipped without a required field, 400'd, and the cross-origin proof
        # (hostile.ok) could never pass. A browser ALWAYS submits a select:
        # the SELECTED option, else the FIRST option (text content when the
        # value attr is absent).
        self._cur_select = None           # name of the <select> currently open
        self._sel_default = ""            # resolved default for that select
        self._sel_val = None              # current <option> value attr (None -> text)
        self._sel_text: list = []         # current <option> text buffer
        self._sel_selected = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag in ("link", "script") and a.get("href") or (tag == "script" and a.get("src")):
            self.links.append(a.get("href") or a.get("src"))
        elif tag == "form":
            self._cur_form = {"action": a.get("action", ""), "method": (a.get("method") or "GET").upper(), "params": []}
        elif tag == "input" and self._cur_form is not None:
            if a.get("type") not in ("submit", "button", "reset") and a.get("name"):
                self._cur_form["params"].append((a["name"], a.get("value", "")))
        elif tag == "textarea" and self._cur_form is not None and a.get("name"):
            self._cur_form["params"].append((a["name"], ""))
        elif tag == "select" and a.get("name") and (self._cur_form is not None
                                                     or self._cur_divform is not None):
            self._cur_select, self._sel_default = a["name"], ""
        elif tag == "option" and self._cur_select is not None:
            self._sel_val = a.get("value")          # None -> fall back to text
            self._sel_text = []
            # bare boolean attrs (selected) parse as None — test key presence
            self._sel_selected = "selected" in a
        # ---- DISC-10 (live-caught on ginandjuice.shop #subscribe): JS-driven
        # "forms" are <div data-action=... data-method=post> blocks, NOT <form>
        # elements — a form-only parser is structurally blind to the whole
        # subscribe surface. Track inputs inside such divs (nested divs counted).
        if tag == "div":
            if self._cur_divform is not None:
                self._div_depth += 1
            elif a.get("data-action") or (a.get("data-method") and "form" in (a.get("class") or "")):
                self._cur_divform = {"action": a.get("data-action", ""),
                                     "method": (a.get("data-method") or "POST").upper(), "params": []}
                self._div_depth = 1
        elif self._cur_divform is not None and tag == "input":
            if a.get("type") not in ("submit", "button", "reset") and a.get("name"):
                self._cur_divform["params"].append((a["name"], a.get("value", "")))

    def handle_endtag(self, tag):
        if tag == "option" and self._cur_select is not None:
            value = self._sel_val if self._sel_val is not None else "".join(self._sel_text).strip()
            if value and (self._sel_selected or self._sel_default == ""):
                self._sel_default = value
            self._sel_val, self._sel_text, self._sel_selected = None, [], False
        elif tag == "select" and self._cur_select is not None:
            self._flush_select()
        elif tag == "form" and self._cur_form:
            self._flush_select()                     # malformed HTML: unterminated select
            self.forms.append(self._cur_form); self._cur_form = None
        elif tag == "div" and self._cur_divform is not None:
            self._div_depth -= 1
            if self._div_depth <= 0:
                self._flush_select()
                if self._cur_divform["params"]:
                    self.divforms.append(self._cur_divform)
                self._cur_divform = None

    def _flush_select(self):
        """ENG-17: commit the open <select> as a form param with its
        browser-faithful default (selected > first option; '' when the app
        really offers an empty placeholder)."""
        if self._cur_select is None:
            return
        target = self._cur_form if self._cur_form is not None else self._cur_divform
        if target is not None and not any(n == self._cur_select for n, _ in target["params"]):
            target["params"].append((self._cur_select, self._sel_default))
        self._cur_select = None

    def handle_data(self, data):
        # ENG-17: <option> without a value attr submits its TEXT — buffer it.
        if self._cur_select is not None and self._sel_val is None:
            self._sel_text.append(data)


# JS endpoint heuristics (static pass; AST-lite for fetch/axios/XHR/WebSocket)
JS_PATTERNS = [
    re.compile(r"""(?:fetch|axios(?:\.\w+)?|\$\.(?:ajax|get|post))\(\s*['"`]([^'"`]{3,200})['"`]""", re.I),
    re.compile(r"""(?:url|endpoint|apiUrl|API_BASE)\s*[:=]\s*['"`]([^'"`]{3,200})['"`]""", re.I),
    re.compile(r"""new\s+WebSocket\(\s*['"`]([^'"`]+)['"`]""", re.I),
]
QUERY_RE = re.compile(r"[?&]([A-Za-z_][\w]*)=([^&#\s]*)")

# DISC-06 (live-caught on ginandjuice.shop): the XXE surface on /catalog/product/stock
# only exists for XML bodies that JavaScript builds at runtime (xmlStockCheckPayload.js
# overrides Content-Type to application/xml and wraps form fields in <stockCheck> XML).
# A DOM-less crawler can still learn this STATICALLY: while fetching .js assets, record
# (a) XML content-type overrides and (b) XML root templates from xml-building code.
# XxeDetector replays the JS transformation deterministically — no browser needed.
JS_XML_HINTS: set = set()          # XML root element names learned from JS assets
_JS_XML_ROOT = re.compile(r"""xml\s*\+=\s*['"]<(\w+)>['"]""")           # xml += '<stockCheck>';
_JS_XML_CT   = re.compile(r"""['"]application/xml['"]""")               # contentType override

# DISC-05 (live-caught on ginandjuice.shop): params that exist ONLY inside inline
# <script> bodies (e.g. const categories = {"Gin":"/catalog?category=Gin"};) are
# invisible to <a href>/form parsers. PortSwigger's scanme hides its entire /catalog
# attack surface (SQLi + XSS + header injection, all on ?category=) this way.
# Extract quoted URL-shaped strings from inline script blocks; the DISC-01
# plausible_js_url gate + same-host check keep precision.
_INLINE_SCRIPT_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.S | re.I)
_INLINE_JS_URL_RE = re.compile(r"""["'](/[^"'\s]{2,200}\?[^"'\s]{1,200})["']""")

# DISC-08 (live-caught on ginandjuice.shop): styling/media assets were fetched as CRAWL
# PAGES, burning the page budget on resources that can never reveal endpoints — the
# XML-hint JS (xmlStockCheckPayload.js) queued behind 4 CSS files never got fetched,
# hiding the XXE surface. Static assets stay discoverable as ENDPOINTS (links still
# recorded); they are just not wasted page-fetches.
_SKIP_AS_PAGE = (".css", ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff",
                 ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm", ".webp")

# DISC-01 (live-caught on demo.testfire.net swagger-ui-bundle.js): minified webpack code
# satisfies JS_PATTERNS with code fragments like  url:",s.default.createElement("  or
# url:"responseURL"  -> these became phantom endpoints and polluted findings/requests.
# Deterministic plausibility gate for JS-extracted strings (HTML href/src stay exempt).
_JS_URL_FORBIDDEN = set('(){}<>"\'`\\ \t\n\r;')
_JS_URL_PATHISH = re.compile(r"\.[A-Za-z0-9]{2,5}$")


def plausible_js_url(s: str) -> bool:
    """A JS-extracted string is a plausible endpoint URL iff it is code-free and path-like.
    Rejects: function-call fragments, comma/plus-glued minified code, bare identifiers
    (e.g. 'responseURL', 'string'), anything with whitespace/quotes/braces."""
    s = s.strip()
    if not s or len(s) > 500:
        return False
    if any(c in _JS_URL_FORBIDDEN for c in s):
        return False
    if s.startswith(("/", "http://", "https://", "ws://", "wss://")):
        return True
    # relative candidate: must carry real path structure (a '/', a '?', or a file
    # extension) — bare JS identifiers carry none.
    return ("/" in s) or ("?" in s) or (_JS_URL_PATHISH.search(s) is not None)


# DISC-10: a div-form's JS usually serializes inputs as JSON (live-proven on
# ginandjuice.shop subscribeNow.js: JSON.stringify(value) + Content-Type
# application/json;charset=UTF-8). Statically learnable from fetched JS assets;
# div-form params are upgraded to ParamLocation.JSON when the hint is present.
_JS_JSON_CT = re.compile(r"['\"]application/json", re.I)
_JS_JSONIFY = re.compile(r"JSON\.stringify")


class DiscoveryEngine:
    SAME_PATH_PAGE_CAP = 4    # DISC-09: max queued fetches per URL path (see below)

    def __init__(self, engine: RequestEngine, max_pages: int = 25):
        self.engine, self.max_pages = engine, max_pages
        self._path_queued: dict = {}   # path -> FETCHED page count (DISC-09 template cap)
        self.dom_sinks: list = []      # DISC-11: static DOM source->sink candidates
        self._js_bodies: list[tuple[str, str]] = []   # (url, body) of fetched JS assets
        self.script_pages: list[str] = []  # Phase 50: HTML pages carrying <script> — render candidates

    def _normalize(self, base: str, href: str) -> str:
        href = href.strip()
        if href.startswith(("#", "javascript:", "mailto:", "data:")): return ""
        full = urllib.parse.urljoin(base, href)
        p = urllib.parse.urlsplit(full)
        if p.scheme not in ("http", "https"): return ""
        return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, p.query, ""))

    def _mk_endpoint(self, url: str, source: DiscoverySource, params=None, method="GET") -> Endpoint:
        p = urllib.parse.urlsplit(url)
        qs = [(k, v[0]) for k, v in urllib.parse.parse_qs(p.query, keep_blank_values=True).items()]
        plist = [Parameter(n, ParamLocation.QUERY, v).classify() for n, v in qs]
        # DISC-02 (live-caught on demo.testfire.net frmSearch): form params were ALWAYS
        # assigned BODY regardless of the form method. GET-method forms (Altoro search)
        # got a GET endpoint with body params — ENG-02 honored that wrong metadata and
        # the payload was silently dropped (GET sends no body). Location must follow
        # the endpoint's actual method.
        form_loc = ParamLocation.BODY if (method or "GET").upper() == "POST" else ParamLocation.QUERY
        for n, v in (params or []):
            plist.append(Parameter(n, form_loc, v).classify())
        clean = urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, "", ""))
        return Endpoint(url=clean, method=method, parameters=plist, source=source)

    def crawl(self, seed_url: str, extra_seeds: list | None = None, exclude_urls: list | None = None):
        """BFS crawl same-host; returns (endpoints, js_findings, crawl_stats).
        Phase 51: extra_seeds (e.g. the authenticated landing page) join the BFS
        queue at position 0 — same normalization, same budget gates, so the
        authenticated surface is discovered by the exact same deterministic rules
        as the anonymous one (no separate privileged code path).
        Phase 51b: exclude_urls are never PAGE-FETCHED once authenticated —
        re-fetching the login page makes the server issue a fresh ANONYMOUS
        session cookie that clobbers the authenticated one in the jar (live-caught:
        the benchmark self-healed via AUTH-03 but burned a login per fetch). The
        page's endpoints remain reachable through the form-parse discovery."""
        seen_pages, endpoints, js_hits = set(), {}, []
        seed_host = urllib.parse.urlsplit(seed_url).netloc
        queue = list(extra_seeds or []) + [seed_url]
        excluded = {self._normalize(seed_url, u) for u in (exclude_urls or []) if u}
        pages = 0
        while queue and pages < self.max_pages:
            url = queue.pop(0)
            norm = self._normalize(seed_url, url)
            if not norm or norm in seen_pages: continue
            if excluded and norm in excluded: continue
            seen_pages.add(norm)
            ok, _ = self.engine._scope_ok(norm)
            if not ok: continue
            # DISC-09 fix (live-caught via traced crawl): the per-path cap used to
            # count QUEUE INSERTIONS — the same menubar link appearing on every page
            # queued 4 duplicate copies, burned the whole path budget, and STARVED the
            # form-target URL (?search=...) that DISC-12 queued later: the DOM surface
            # was unreachable even though every gate individually passed. Counting
            # actual FETCHES keeps the template-page cap honest while duplicates
            # dedupe for free at pop-time via seen_pages.
            fpath = urllib.parse.urlsplit(norm).path or "/"
            if self._path_queued.get(fpath, 0) >= self.SAME_PATH_PAGE_CAP:
                continue
            self._path_queued[fpath] = self._path_queued.get(fpath, 0) + 1
            resp = self.engine.send(self.engine.__class__ and _simple_get(norm))
            pages += 1
            if resp.error or not resp.body: continue
            if not any(m in resp.headers.get("content-type", "") for m in ("text/html", "text/plain", "")): continue
            ep = self._mk_endpoint(norm, DiscoverySource.SEED)
            endpoints[ep.id] = ep

            # ---- HTML parsing
            hp = _LinkParser(); hp.feed(resp.body)
            for href in hp.links:
                n = self._normalize(norm, href)
                if n and urllib.parse.urlsplit(n).netloc == seed_host:
                    e2 = self._mk_endpoint(n, DiscoverySource.CRAWL_HTML)
                    if e2.id not in endpoints: endpoints[e2.id] = e2
                    # DISC-07 (live-caught on ginandjuice.shop): queue the FULL link URL
                    # including its query string. The old code queued e2.url — the
                    # endpoint's CLEANED url (query stripped) — so param'd pages were
                    # fetched as /catalog/product (HTTP 400) instead of
                    # /catalog/product?productId=1: every form, script and link on those
                    # pages was invisible (the whole XXE surface lived there).
                    # DISC-08: skip styling/media assets as page-fetches (budget waste).
                    # DISC-09 (live-caught on ginandjuice.shop): 18 near-identical
                    # product pages (?productId=1..18, same path) crowded the BFS queue
                    # and starved the JS assets behind them — xmlStockCheckPayload.js
                    # (the XXE hint) never got fetched. Template pages are capped per
                    # path; links beyond the cap stay ENDPOINTS (still probed), just not
                    # page-fetched.
                    if n not in seen_pages and not n.lower().endswith(_SKIP_AS_PAGE):
                        queue.append(n)
            for form in hp.forms:
                action = self._normalize(norm, form["action"] or norm)
                if not action: continue
                e3 = self._mk_endpoint(action, DiscoverySource.CRAWL_FORM,
                                       params=form["params"], method=form["method"])
                if e3.id not in endpoints: endpoints[e3.id] = e3
                # DISC-12 (live-caught on ginandjuice.shop /blog?search=): a GET form's
                # action URL IS a reachable page — the search-results page carries the
                # DOM source->sink script while the param-less index does NOT
                # (server-side conditional rendering). Forms only created ENDPOINTS,
                # never page-fetches, so the whole DOM surface was invisible: the
                # sink scanner never saw the script. Queue the form target with its
                # default params (same budget gates as links).
                if (form["method"] or "GET").upper() == "GET" and form["params"]:
                    sep = "&" if "?" in action else "?"
                    fq = action + sep + urllib.parse.urlencode(
                        [(n, v or "1") for n, v in form["params"][:6]])
                    if fq not in seen_pages and not fq.lower().endswith(_SKIP_AS_PAGE):
                        queue.append(fq)
            # DISC-10: div-based pseudo-forms (JS-driven submit) are real POST
            # surfaces — tagged so the JSON upgrade pass can find them later.
            for df in hp.divforms:
                action = self._normalize(norm, df["action"] or norm)
                if not action: continue
                e3b = self._mk_endpoint(action, DiscoverySource.CRAWL_FORM,
                                        params=df["params"], method=df["method"])
                e3b.tags.append("divform")
                if e3b.id not in endpoints: endpoints[e3b.id] = e3b
            # DISC-11: static DOM source->sink scan (inline scripts of THIS page)
            from .browser import scan_html_dom_sinks
            for sink in scan_html_dom_sinks(norm, resp.body):
                if sink.key() not in {s.key() for s in self.dom_sinks}:
                    self.dom_sinks.append(sink)
            # Phase 50: script-bearing HTML pages are the render candidates — runtime
            # forms/DOM logic only exist where scripts run (live-caught: the JS-built
            # form page fell outside a naive first-N selection and its surface was missed).
            if "<script" in resp.body.lower() and norm not in self.script_pages:
                self.script_pages.append(norm)

            # ---- JS static extraction
            if norm.endswith(".js") or "javascript" in resp.headers.get("content-type", ""):
                self._js_bodies.append((norm, resp.body))
                # DISC-11: DOM sinks in external JS assets too
                from .browser import scan_dom_sinks
                for sink in scan_dom_sinks(norm, resp.body):
                    if sink.key() not in {s.key() for s in self.dom_sinks}:
                        self.dom_sinks.append(sink)
                for pat in JS_PATTERNS:
                    for match in pat.findall(resp.body):
                        if not plausible_js_url(match):            # DISC-01 gate
                            continue
                        n = self._normalize(norm, match)
                        if n and urllib.parse.urlsplit(n).netloc == seed_host:
                            js_hits.append(match)
                            e4 = self._mk_endpoint(n, DiscoverySource.JS_STATIC)
                            if e4.id not in endpoints: endpoints[e4.id] = e4
                # DISC-06: learn JS-driven XML request transformations (XXE surface)
                if _JS_XML_CT.search(resp.body):
                    for root in _JS_XML_ROOT.findall(resp.body):
                        JS_XML_HINTS.add(root)
            else:
                # DISC-10 (part 2): the JSON-serialization hint may live in the
                # div-form page's OWN inline scripts (not only in external .js).
                if _JS_JSON_CT.search(resp.body) and _JS_JSONIFY.search(resp.body):
                    self._js_bodies.append((norm, resp.body))
                for m in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.body):
                    n = self._normalize(norm, m)
                    if n and urllib.parse.urlsplit(n).netloc == seed_host and n not in seen_pages \
                            and not n.lower().endswith(_SKIP_AS_PAGE):
                        queue.append(n)
                # DISC-05: inline <script> bodies carry URL-shaped strings that the
                # link/form parsers never see (SPA config objects, category maps...).
                # Same plausible_js_url + same-host gates as .js asset extraction.
                for blk in _INLINE_SCRIPT_RE.findall(resp.body):
                    for um in _INLINE_JS_URL_RE.findall(blk):
                        if not plausible_js_url(um):               # DISC-01 gate
                            continue
                        n = self._normalize(norm, um)
                        if n and urllib.parse.urlsplit(n).netloc == seed_host:
                            e5 = self._mk_endpoint(n, DiscoverySource.JS_STATIC)
                            if e5.id not in endpoints: endpoints[e5.id] = e5
        # ---- ENG-11 (Phase 56, live-caught during suite-isolation work): JS
        # assets discovered as ENDPOINTS (link/script-src extraction) but never
        # PAGE-FETCHED (the BFS page budget exhausted before their queue position)
        # used to teach NOTHING — the XXE XML-root teacher asset sat at queue
        # position ~35 behind a 30-page budget, so scans silently lost the whole
        # JS-learned surface whenever a bigger scan happened not to run first.
        # Every discovered same-host .js endpoint is now fetched (bounded) and
        # feeds the SAME hint extraction as page-fetched assets — deterministic,
        # independent of page-budget luck.
        js_eps = [ep for ep in endpoints.values()
                  if ep.url.split("?")[0].lower().endswith(".js")
                  and ep.url not in seen_pages][:12]
        for ep in js_eps:
            resp = self.engine.send(_simple_get(ep.url))
            if resp.error or not resp.body:
                continue
            self._js_bodies.append((ep.url, resp.body))
            for pat in JS_PATTERNS:
                for match in pat.findall(resp.body):
                    if not plausible_js_url(match):            # DISC-01 gate
                        continue
                    n = self._normalize(ep.url, match)
                    if n and urllib.parse.urlsplit(n).netloc == seed_host:
                        js_hits.append(match)
                        e4 = self._mk_endpoint(n, DiscoverySource.JS_STATIC)
                        if e4.id not in endpoints: endpoints[e4.id] = e4
            # DISC-06: learn JS-driven XML request transformations (XXE surface)
            if _JS_XML_CT.search(resp.body):
                for root in _JS_XML_ROOT.findall(resp.body):
                    JS_XML_HINTS.add(root)
        # ---- DISC-10 upgrade pass: div-forms whose JS serializes inputs as JSON
        # get ParamLocation.JSON (ENG-04 then renders them as JSON bodies — the
        # request shape the target's own JavaScript produces). Hint learned from
        # ANY fetched JS asset (deterministic set, same crawl order every run).
        if any(_JS_JSON_CT.search(b) and _JS_JSONIFY.search(b) for _, b in self._js_bodies):
            for ep in endpoints.values():
                if "divform" in ep.tags:
                    for p in ep.parameters:
                        p.location = ParamLocation.JSON
        return list(endpoints.values()), js_hits, {"pages": pages, "unique_endpoints": len(endpoints),
                                                   "dom_sink_candidates": len(self.dom_sinks)}

    def robots(self, base: str) -> list[Endpoint]:
        resp = self.engine.send(_simple_get(base.rstrip("/") + "/robots.txt"))
        out = []
        if resp.ok and resp.body:
            for line in resp.body.splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:")) and len(line.split(":", 1)[1].strip()) > 1:
                    n = self._normalize(base, line.split(":", 1)[1].strip())
                    if n:
                        e = self._mk_endpoint(n, DiscoverySource.ROBOTS)
                        out.append(e)
        return out

    def openapi(self, base: str) -> tuple[list[Endpoint], dict | None]:
        """DISC-13: probe the well-known spec locations, parse the first valid
        OpenAPI/Swagger document. Returns ([endpoints], info|None) — the info dict
        lands in stats.openapi for auditability (which document, which version,
        how many paths). Honest: no spec found -> ([], None), never a guess."""
        import json as _json
        for p in OPENAPI_PROBE_PATHS:
            resp = self.engine.send(_simple_get(base.rstrip("/") + p))
            if not resp.ok or not (resp.body or "").lstrip().startswith("{"):
                continue
            try:
                spec = _json.loads(resp.body)
            except ValueError:
                continue
            if "paths" not in spec:
                continue
            eps = parse_openapi(spec, base)
            return eps, _spec_info(spec, p, len(eps))
        return [], None


def _simple_get(url: str):
    from .http_engine import RequestMutation
    from .core import Endpoint as E, Parameter, ParamLocation
    # DISC-07 (part 2): _render rebuilds the request URL from ep.parameters, NOT from
    # ep.url's raw query — a bare Endpoint(url=...) silently DROPPED the query string,
    # so param'd pages were fetched without their params (live-caught on ginandjuice.shop:
    # /catalog/product?productId=1 fetched as /catalog/product -> 400, hiding the whole
    # product-page attack surface). Parse the query into parameters so it survives.
    from urllib.parse import parse_qsl, urlsplit
    q = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    params = [Parameter(n, ParamLocation.QUERY, v).classify() for n, v in q]
    ep = E(url=url, parameters=params)
    return RequestMutation(endpoint=ep, note="discovery")


def extract_query_params(url: str) -> list[tuple[str, str]]:
    return [(k, v[0]) for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(url).query, keep_blank_values=True).items()]


# ============================================================ DISC-13: OpenAPI seeding
OPENAPI_PROBE_PATHS = ("/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/v2/api-docs")


def parse_openapi(spec: dict, base_url: str) -> list[Endpoint]:
    """DISC-13 (Phase 54): an OpenAPI/Swagger document is a machine-readable attack
    surface map the TARGET ITSELF publishes — endpoints invisible to any crawler
    (unlinked admin/legacy/API paths) are declared there with their parameters.
    Parses paths -> method -> parameters (query + path; JSON request bodies) into
    standard Endpoints. Scope-gating and dedup happen in the orchestrator exactly
    like crawl results — a spec entry is a LEAD, never a bypass of scope policy."""
    import json as _json
    out: list[Endpoint] = []
    base = base_url.rstrip("/")
    servers = spec.get("servers") or []
    root = base
    if servers and isinstance(servers, list) and servers[0].get("url", "").startswith("http"):
        root = servers[0]["url"].rstrip("/")
    paths = spec.get("paths") or {}
    for path, ops in (paths.items() if isinstance(paths, dict) else []):
        if not isinstance(ops, dict):
            continue
        url = root + (path if path.startswith("/") else "/" + path)
        for method, op in ops.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete") or not isinstance(op, dict):
                continue
            params = []
            for prm in op.get("parameters", []) or []:
                if not isinstance(prm, dict) or "name" not in prm:
                    continue
                loc = {"query": ParamLocation.QUERY, "path": ParamLocation.QUERY,
                       "header": ParamLocation.QUERY}.get(prm.get("in", "query"), ParamLocation.QUERY)
                params.append(Parameter(prm["name"], loc, prm.get("schema", {}).get("example", "") or "").classify())
            body = (op.get("requestBody") or {}).get("content", {})
            if "application/json" in body:
                for fld in ((body["application/json"].get("schema") or {}).get("properties") or {}).keys():
                    params.append(Parameter(fld, ParamLocation.JSON, "").classify())
            out.append(Endpoint(url=url, method=method.upper(), parameters=params,
                                source=DiscoverySource.SEED, tags=["openapi"]))
    return out


def _spec_info(spec: dict, url: str, n_endpoints: int) -> dict:
    return {"source": url, "version": str(spec.get("openapi") or spec.get("swagger") or "?"),
            "title": str((spec.get("info") or {}).get("title") or ""), "paths": n_endpoints}

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
        self._cur_form = None

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

    def handle_endtag(self, tag):
        if tag == "form" and self._cur_form:
            self.forms.append(self._cur_form); self._cur_form = None


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


class DiscoveryEngine:
    SAME_PATH_PAGE_CAP = 4    # DISC-09: max queued fetches per URL path (see below)

    def __init__(self, engine: RequestEngine, max_pages: int = 25):
        self.engine, self.max_pages = engine, max_pages
        self._path_queued: dict = {}   # path -> queued count (DISC-09 template cap)

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

    def crawl(self, seed_url: str):
        """BFS crawl same-host; returns (endpoints, js_findings, crawl_stats)."""
        seen_pages, endpoints, js_hits = set(), {}, []
        seed_host = urllib.parse.urlsplit(seed_url).netloc
        queue = [seed_url]
        pages = 0
        while queue and pages < self.max_pages:
            url = queue.pop(0)
            norm = self._normalize(seed_url, url)
            if not norm or norm in seen_pages: continue
            seen_pages.add(norm)
            ok, _ = self.engine._scope_ok(norm)
            if not ok: continue
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
                        p_path = urllib.parse.urlsplit(n).path or "/"
                        if self._path_queued.get(p_path, 0) < self.SAME_PATH_PAGE_CAP:
                            self._path_queued[p_path] = self._path_queued.get(p_path, 0) + 1
                            queue.append(n)
            for form in hp.forms:
                action = self._normalize(norm, form["action"] or norm)
                if not action: continue
                e3 = self._mk_endpoint(action, DiscoverySource.CRAWL_FORM,
                                       params=form["params"], method=form["method"])
                if e3.id not in endpoints: endpoints[e3.id] = e3

            # ---- JS static extraction
            if norm.endswith(".js") or "javascript" in resp.headers.get("content-type", ""):
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
        return list(endpoints.values()), js_hits, {"pages": pages, "unique_endpoints": len(endpoints)}

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

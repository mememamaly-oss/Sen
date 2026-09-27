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


class DiscoveryEngine:
    def __init__(self, engine: RequestEngine, max_pages: int = 25):
        self.engine, self.max_pages = engine, max_pages

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
        for n, v in (params or []):
            plist.append(Parameter(n, ParamLocation.BODY, v).classify())
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
                    if e2.url not in seen_pages: queue.append(e2.url)
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
                        n = self._normalize(norm, match)
                        if n and urllib.parse.urlsplit(n).netloc == seed_host:
                            js_hits.append(match)
                            e4 = self._mk_endpoint(n, DiscoverySource.JS_STATIC)
                            if e4.id not in endpoints: endpoints[e4.id] = e4
            else:
                for m in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.body):
                    n = self._normalize(norm, m)
                    if n and urllib.parse.urlsplit(n).netloc == seed_host and n not in seen_pages:
                        queue.append(n)
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
    from .core import Endpoint as E
    ep = E(url=url)
    return RequestMutation(endpoint=ep, note="discovery")


def extract_query_params(url: str) -> list[tuple[str, str]]:
    return [(k, v[0]) for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(url).query, keep_blank_values=True).items()]

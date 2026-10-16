"""Phase 50: Browser/DOM Engine — the documented browser phase.

Two layers, deliberately separated:

1) STATIC DOM analysis (browserless, always active): DomSinkScanner finds
   source->sink flows in inline/external JS (location.search/hash,
   URLSearchParams, document.referrer -> document.write, innerHTML, eval...).
   Live-proven necessity on ginandjuice.shop /blog?search: the param is read
   client-side from URLSearchParams and written straight into document.write —
   the SERVER NEVER REFLECTS IT, so a DOM-less DAST is structurally blind.

2) REAL browser (Playwright/Chromium, optional with graceful degradation):
   BrowserEngine renders pages (runtime forms incl. JS-built ones a static
   parser can never see), records XHR/fetch traffic, and proves DOM XSS by
   EXECUTION: the probe payload sets window.__SENTINEL_XSS__=<canary> inside
   an onerror handler — the flag only exists if the payload was parsed as
   REAL MARKUP by a dangerous sink (reflection alone proves nothing).

Verification contract (BR-01): a candidate fires with canary A; verification
re-probes with a FRESH canary B — both must execute. Deterministic, no AI.
"""
from __future__ import annotations
import re, urllib.parse

from .core import DiscoverySource, Endpoint, Parameter, ParamLocation, Evidence

# ---------------------------------------------------------------- static scanner
# DOM sources: client-side readable attacker-controlled input channels.
_DOM_SOURCES = [
    ("location.search", "search"),
    ("location.hash", "hash"),
    ("URLSearchParams", "search"),          # reads from the query string
    ("document.referrer", "referrer"),
    ("window.name", "name"),
    ("document.URL", "search"),
    ("document.location", "search"),
]
# DOM sinks: anything that parses a string as HTML markup or JS code.
_DOM_SINKS = [
    "document.write", "document.writeln", "innerHTML", "outerHTML",
    "insertAdjacentHTML", "eval(", "new Function", "srcdoc",
    "setTimeout('", "setInterval('", "$.html", ".html(", "DOMParser",
]

_GET_PARAM_RE = re.compile(r"""\.get\(\s*['"]([\w\-]{1,40})['"]\s*\)""")
_SCRIPT_BLOCK_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.S | re.I)


class DomSink:
    __slots__ = ("url", "source", "sink", "params", "snippet")

    def __init__(self, url: str, source: str, sink: str, params: list, snippet: str):
        self.url, self.source, self.sink = url, source, sink
        self.params, self.snippet = params, snippet

    def key(self) -> str:
        return f"{self.url}|{self.source}|{self.sink}|{','.join(self.params)}"

    def __repr__(self):
        return f"DomSink({self.url} source={self.source} sink={self.sink} params={self.params})"


def scan_dom_sinks(url: str, js_code: str) -> list[DomSink]:
    """Static source->sink analysis over ONE script body (inline block or JS asset).
    A candidate requires BOTH a source pattern and a sink pattern in the SAME
    script — cross-file dataflow is out of scope (documented limit)."""
    out = []
    for src_pat, src_kind in _DOM_SOURCES:
        if src_pat not in js_code:
            continue
        for sink in _DOM_SINKS:
            if sink not in js_code:
                continue
            params = _GET_PARAM_RE.findall(js_code) if src_kind == "search" else []
            # deterministic snippet: 100 chars around the first sink occurrence
            i = js_code.find(sink)
            snippet = re.sub(r"\s+", " ", js_code[max(0, i - 60):i + 100]).strip()
            out.append(DomSink(url, src_kind, sink, params[:6], snippet[:160]))
            break        # one sink per source pattern is enough for planning
    # dedup by (source,sink) — a block may mention location.search twice
    seen, uniq = set(), []
    for s in out:
        k = f"{s.source}|{s.sink}"
        if k not in seen:
            seen.add(k)
            uniq.append(s)
    return uniq


def scan_html_dom_sinks(url: str, html: str) -> list[DomSink]:
    """Scan every inline <script> block of an HTML page (deterministic order)."""
    found = []
    for blk in _SCRIPT_BLOCK_RE.findall(html):
        found.extend(scan_dom_sinks(url, blk))
    return found


# ---------------------------------------------------------------- availability
_AVAIL: bool | None = None


def browser_available() -> bool:
    """True iff Playwright + a launchable headless Chromium exist. Cached."""
    global _AVAIL
    if _AVAIL is not None:
        return _AVAIL
    try:
        from playwright.sync_api import sync_playwright
        p = sync_playwright().start()
        try:
            b = p.chromium.launch(headless=True,
                                  args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
            b.close()
            _AVAIL = True
        finally:
            p.stop()
    except Exception:
        _AVAIL = False
    return _AVAIL


# ---------------------------------------------------------------- browser engine
_FORM_JS = """() => {
  const out = [];
  document.querySelectorAll('form, [data-action]').forEach(el => {
    const action = el.getAttribute('action') || el.getAttribute('data-action') || location.pathname;
    const method = (el.getAttribute('method') || el.getAttribute('data-method') || 'GET').toUpperCase();
    const params = [];
    let submitCtl = null;
    // OWSP-05 (OWASP campaign, live-caught on WrongSecrets 1.8.1): submit
    // controls (input[type=submit] AND <button>) carry the name=value pair the
    // route's params filter demands; dropping them made every browser-discovered
    // POST surface dead-on-arrival (uniform 405, wrong-session token replay).
    el.querySelectorAll('input[name], textarea[name], select[name], button[name]').forEach(i => {
      const t = (i.tagName === 'BUTTON') ? (i.type || 'submit') : (i.type || 'text');
      if (t === 'submit') {
        if (!submitCtl && i.name && i.value) { params.push([i.name, i.value]); submitCtl = i.name; }
      } else if (t !== 'button' && t !== 'reset') {
        params.push([i.name, i.value || '']);
      }
    });
    if (params.length) out.push({action, method, params, tag: el.tagName, submitctl: submitCtl});
  });
  return out.slice(0, 25);
}"""

_LINKS_JS = """() => Array.from(document.querySelectorAll('a[href]'))
  .map(a => a.href).slice(0, 60)"""


class BrowserEngine:
    """Real-browser rendering + DOM XSS execution proofs. Scope-gated like the
    HTTP engine: navigation to out-of-scope hosts is refused before goto."""

    def __init__(self, engine, timeout: float = 12.0, extra_headers: dict | None = None):
        # engine: RequestEngine — owns the ScopeRule (single source of truth for scope)
        # extra_headers: session transport headers (Authorization: Bearer ...) the
        # context must mirror — otherwise every render of an auth-gated page bounces
        # to the login form exactly like a cookie-less render (AUTH-04 same lesson,
        # header flavor). LIVE-CAUGHT: orchestrator passed it before the engine
        # learned to accept it (9 tests red) — API contract fixed here permanently.
        self.engine, self.bus, self.timeout = engine, engine.bus, timeout
        self.extra_headers = {k: v for k, v in (extra_headers or {}).items()
                              if k.lower() != "user-agent"}
        self._pw = self._browser = self._context = None
        self.pages_rendered = 0
        self.probes_sent = 0

    # ---- lifecycle
    def _ensure(self):
        if self._context is not None:
            return
        from playwright.sync_api import sync_playwright
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(
            headless=True, args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
        from .http_engine import USER_AGENT   # version-derived: one UA across engine+browser
        self._context = self._browser.new_context(ignore_https_errors=True,
                                                  user_agent=USER_AGENT)
        if self.extra_headers:
            # header-based auth must ride along with cookie-based sessions (AUTH-04)
            self._context.set_extra_http_headers(self.extra_headers)

    def _sync_session_cookies(self, url: str):
        """AUTH-04: the browser context must carry the SAME session as the HTTP
        engine — otherwise every render of an auth-gated page bounces to the
        login form and the whole authenticated DOM surface is invisible to the
        browser phase (live-caught class: jar cookies exist, Chromium starts
        anonymous). Syncs the engine jar into the Playwright context before each
        navigation; Playwright keeps cookies per-domain, mirroring the jar."""
        try:
            jar = getattr(self.engine, "cookie_jar", None) or {}
            host = urllib.parse.urlsplit(url).hostname or ""
            cks = []
            for jh, pairs in jar.items():
                if jh != host:
                    continue
                for n, v in pairs.items():
                    cks.append({"name": n, "value": v, "domain": jh, "path": "/"})
            if cks:
                self._context.add_cookies(cks)
        except Exception as e:
            self.bus.emit("BrowserCookieSyncError", error=f"{type(e).__name__}: {e}"[:150])

    def close(self):
        # explicit ordered teardown (attributes may be partially initialized)
        try:
            if self._context is not None: self._context.close()
        except Exception: pass
        try:
            if self._browser is not None: self._browser.close()
        except Exception: pass
        try:
            if self._pw is not None: self._pw.stop()
        except Exception: pass
        self._context = self._browser = self._pw = None

    def _ok(self, url: str) -> bool:
        ok, why = self.engine._scope_ok(url)
        if not ok:
            self.bus.emit("BrowserNavBlocked", url=url, reason=why)
        return ok

    # ---- render (runtime discovery)
    def render(self, url: str, settle_ms: int = 500) -> dict | None:
        """Load a page in Chromium; return rendered DOM intelligence:
        {url, html, forms, links, xhrs, js_errors}. None = scope-blocked/failed."""
        if not self._ok(url):
            return None
        self._ensure()
        self._sync_session_cookies(url)
        xhrs: list[dict] = []
        page = self._context.new_page()
        page.on("request", lambda req: xhrs.append({
            "method": req.method, "url": req.url,
            "post_data": req.post_data or "",
            "content_type": (req.headers or {}).get("content-type", ""),
        }) if req.resource_type in ("xhr", "fetch") else None)
        try:
            page.goto(url, wait_until="load", timeout=int(self.timeout * 1000))
            page.wait_for_timeout(settle_ms)
            self.pages_rendered += 1
            return {
                "url": url,
                "html": page.content(),
                "forms": page.evaluate(_FORM_JS) or [],
                "links": page.evaluate(_LINKS_JS) or [],
                "xhrs": xhrs,
            }
        except Exception as e:
            self.bus.emit("BrowserRenderError", url=url, error=f"{type(e).__name__}: {e}"[:200])
            return None
        finally:
            page.close()

    def render_merge(self, pages: list[str], seed_host: str, existing: dict) -> list[Endpoint]:
        """Render pages and return NEW endpoints discovered only at runtime
        (JS-built forms, rendered links, observed XHR/fetch). Dedup via endpoint id
        against `existing` (id -> Endpoint); caller merges the returned list."""
        new_eps: list[Endpoint] = []
        for url in pages:
            r = self.render(url)
            if not r:
                continue
            # runtime forms (JS-built included — invisible to the static parser)
            for f in r["forms"][:25]:
                ep = _mk_dom_endpoint(f["action"] if "://" in f["action"] else
                                      urllib.parse.urljoin(url, f["action"]),
                                      url, f["method"], f["params"], json_hint=None,
                                      submitctl=f.get("submitctl"))
                if ep and ep.id not in existing and ep.id not in [e.id for e in new_eps]:
                    new_eps.append(ep)
            # rendered links (client-side routing / JS-generated anchors)
            for href in r["links"][:60]:
                full = urllib.parse.urljoin(url, href)
                if urllib.parse.urlsplit(full).netloc == seed_host:
                    ep = _mk_dom_endpoint(full, url, "GET", [], json_hint=None)
                    if ep and ep.id not in existing and ep.id not in [e.id for e in new_eps]:
                        new_eps.append(ep)
        return new_eps

    # ---- DOM XSS execution probe
    PROBE_FLAG = "window.__SENTINEL_XSS__"

    def _probe_variants(self, canary: str) -> list[tuple[str, str]]:
        """(name, payload) battery — WAF-resistant (BR-02, live-proven on
        ginandjuice.shop /blog?search): the target's tag-name + event-handler
        blacklist (400 on <img/<svg/<x onfocus=...) is DEFEATED by attribute
        injection — no '<' at all: close the sink template's attribute, add
        onload/onerror to the SERVER'S OWN tag. onload fires when the sink
        resource loads (200), onerror when it fails (404). Breakout and raw
        variants cover non-WAF attribute and element contexts."""
        img = f'<img src=x onerror="{self.PROBE_FLAG}=\u0027{canary}\u0027">'
        return [
            ("attr_inject_onerror", f'" onerror="{self.PROBE_FLAG}=\u0027{canary}\u0027"'),
            ("attr_inject_onload",  f'" onload="{self.PROBE_FLAG}=\u0027{canary}\u0027"'),
            ("attr_breakout_double", f'">{img}'),
            ("raw_markup",           img),
            ("attr_breakout_single", f"'>{img}"),
        ]

    def probe_dom_xss(self, url: str, param: str, canary: str, source: str = "search") -> dict | None:
        """Navigate with the execution-canary in the DOM source; return
        {fired, canary, variant, url, detail} when the flag is set (= payload
        executed as markup), else None. The flag can ONLY be set by the browser
        parsing our <img> tag — reflection without markup execution never fires."""
        variants = self._probe_variants(canary)
        for vname, payload in variants:
            if source == "hash":
                target = url.split("#")[0] + "#" + urllib.parse.quote(payload, safe="")
            else:
                base = url.split("#")[0]
                # preserve the page's own query params; force our param in
                qs = urllib.parse.parse_qsl(urllib.parse.urlsplit(base).query, keep_blank_values=True)
                qs = [(k, v) for k, v in qs if k != param] + [(param, payload)]
                parts = urllib.parse.urlsplit(base)
                target = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                                  urllib.parse.urlencode(qs), ""))
            if not self._ok(target):
                return None
            self._ensure()
            self._sync_session_cookies(target)
            page = self._context.new_page()
            try:
                page.goto(target, wait_until="load", timeout=int(self.timeout * 1000))
                page.wait_for_timeout(800)          # let onerror fire deterministically
                self.probes_sent += 1
                got = page.evaluate(f"({self.PROBE_FLAG} || '')")
                if got == canary:
                    return {"fired": True, "canary": canary, "variant": vname,
                            "url": url, "param": param, "source": source,
                            "detail": f"payload executed as markup via {vname} — "
                                      f"{self.PROBE_FLAG} set in live DOM"}
            except Exception as e:
                self.bus.emit("BrowserProbeError", url=target, error=f"{type(e).__name__}: {e}"[:200])
            finally:
                page.close()
        return None


def _mk_dom_endpoint(action_url: str, page_url: str, method: str, params: list,
                     json_hint, submitctl: str | None = None) -> Endpoint | None:
    """Build an Endpoint from a browser-observed form/link, mirroring the static
    discovery conventions (params classified; location follows the method)."""
    p = urllib.parse.urlsplit(action_url)
    if p.scheme not in ("http", "https"):
        return None
    qs = [(k, v[0]) for k, v in urllib.parse.parse_qs(p.query, keep_blank_values=True).items()]
    plist = [Parameter(n, ParamLocation.QUERY, v).classify() for n, v in qs]
    m = (method or "GET").upper()
    loc = ParamLocation.BODY if m in ("POST", "PUT", "PATCH") else ParamLocation.QUERY
    for n, v in (params or [])[:12]:
        pobj = Parameter(n, loc, v).classify()
        # OWSP-05: the form's first submit control is flow control — carried
        # verbatim, never probed (route params filters demand the literal).
        if submitctl and n == submitctl:
            pobj.flow_control = True
        plist.append(pobj)
    clean = urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, "", ""))
    return Endpoint(url=clean, method=m, parameters=plist, source=DiscoverySource.DOM,
                    tags=["dom"])

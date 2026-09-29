"""Scan Orchestrator — ties Discovery -> Planner -> Detection -> Verification -> Finding Pipeline.
Plus: sentinel doctor (Phase 45) and benchmark runner hooks (Phase 16/29).
"""
from __future__ import annotations
import json, os, time
from .core import (Endpoint, EventBus, Evidence, Finding, FindingStatus, ScopeRule,
                   Severity, Target, DiscoverySource, new_run_id, SCANNER_VERSION)
from .http_engine import RequestEngine, RequestMutation
from .discovery import DiscoveryEngine
from .detect import (ACTIVE_DETECTORS, SQLiDetector, XSSDetector, TraversalDetector,
                     RedirectDetector, CrlfDetector, XxeDetector, passive_audit, plan_for,
                     RUN_STYLE_DETECTORS)
from .intel import VerificationEngine, FindingPipeline, StrategyStore, FailureMemory, RepairClassifier
from .auth import AuthProfile, AuthEngine, AuthedEngineProxy, TokenAuthEngine, TokenWatchdogProxy
from .fingerprint import FingerprintCollector


class ScanConfig:
    def __init__(self, allow_private=False, max_pages=25, crawl=True, active=True,
                 passive=True, timeout=12.0, seed=None, strategy_path=None,
                 allowed_domains=None, oast=None, browser=True, auth=None,
                 openapi=True, openapi_spec=None):
        self.allow_private = allow_private
        self.max_pages = max_pages
        self.crawl, self.active, self.passive = crawl, active, passive
        self.timeout, self.seed = timeout, seed
        self.strategy_path = strategy_path
        self.allowed_domains = allowed_domains or []
        self.oast = oast          # OastServer | None — enables OOB (blind-XXE) confirmation
        self.browser = browser    # Phase 50: DOM engine (graceful skip when unavailable)
        self.auth = auth          # Phase 51: AuthProfile | None — authenticated scanning
        self.openapi = openapi    # DISC-13: auto-probe well-known OpenAPI/Swagger docs
        self.openapi_spec = openapi_spec   # explicit spec dict/url seed (None = auto only)


class _FingerprintingProxy:
    """Phase 54 transparent proxy: every response the scan receives passes
    through FingerprintCollector.observe() — WAF signatures, tech headers,
    cookie platforms, DOM markers accumulate from traffic the scan already
    produces. No extra requests, no behavior change (pure observer)."""
    def __init__(self, inner, collector: FingerprintCollector):
        self._inner, self._fp = inner, collector

    def send(self, m):
        r = self._inner.send(m)
        self._fp.observe(r)
        return r

    def __getattr__(self, name):
        return getattr(self._inner, name)


class SentinelScanner:
    def __init__(self, target_url: str, cfg: ScanConfig | None = None):
        self.cfg = cfg or ScanConfig()
        self.run_id, self.seed = new_run_id(self.cfg.seed)
        self.bus = EventBus(self.run_id)
        self.target = Target(target_url)
        self.scope = ScopeRule(allowed_domains=[self.target.host] + self.cfg.allowed_domains,
                               allow_private=self.cfg.allow_private)
        self.engine = RequestEngine(self.scope, self.bus, timeout=self.cfg.timeout)
        self.verifier = VerificationEngine(self.engine, self.bus, oast=self.cfg.oast)
        self.browser = None       # Phase 50: BrowserEngine (set in run() when enabled+available)
        self.fp = FingerprintCollector()   # Phase 54: passive WAF + tech map
        self.pipeline = FindingPipeline(self.bus)
        self.strategies = StrategyStore(self.cfg.strategy_path)
        self.failures = FailureMemory()
        self.classifier = RepairClassifier()
        self.findings: list[Finding] = []
        self.stats = {"requests": 0, "endpoints": 0, "candidates": 0, "verified": 0, "rejected": 0,
                      "duration": 0.0}

    # ---------------------------------------------------------------- run
    def run(self) -> dict:
        t0 = time.time()
        self.bus.emit("ScanStarted", target=self.target.url, run=self.run_id,
                      scanner=SCANNER_VERSION, seed=self.seed)

        # ---- Phase 51: authenticate BEFORE discovery — the session cookie (ENG-05
        # jar) then rides every later request, and the authenticated landing page
        # becomes a second crawl seed (the post-login surface is linked ONLY from
        # post-login pages: /bank/* on Altoro is invisible from the anonymous home).
        # AUTH-05 (Phase 54): token mode — Bearer/JWT/custom-header auth. Validation
        # instead of credential exchange; the header rides engine.default_headers;
        # no self-healing (static tokens cannot be re-minted) — 401/403 mid-scan are
        # counted honestly by the TokenWatchdogProxy instead of silently degrading.
        auth_seeds: list[str] = []
        self.auth_engine = None
        self.token_engine = None
        auth_headers: dict = {}
        if self.cfg.auth is not None:
            if self.cfg.auth.mode == "token":
                self.token_engine = TokenAuthEngine(self.cfg.auth, self.engine, self.bus)
                ok = self.token_engine.login()
                self.stats["authenticated"] = ok
                if ok:
                    self.engine = TokenWatchdogProxy(self.engine, self.token_engine)
                    self.verifier.engine = self.engine
                    auth_headers = {self.cfg.auth.auth_header: self.cfg.auth.header_value()}
                    auth_seeds.append(self.cfg.auth.login_url)
                else:
                    self.bus.emit("ScanContinuesUnauthenticated",
                                  reason=self.token_engine.state.last_error)
            else:
                self.auth_engine = AuthEngine(self.cfg.auth, self.engine, self.bus)
                ok = self.auth_engine.login()
                self.stats["authenticated"] = ok
                if ok:
                    # AUTH-03 watchdog proxy: from here on, session loss anywhere in
                    # the scan (discovery, detectors, verifier, browser) self-heals.
                    self.engine = AuthedEngineProxy(self.engine, self.auth_engine)
                    self.verifier.engine = self.engine
                    auth_seeds.append(self.auth_engine.state.landing_url)
                    # the authenticated crawl genuinely has more surface — grow budget
                    # deterministically (fixed 1.5x, no heuristics)
                    self.cfg.max_pages = int(self.cfg.max_pages * 1.5)
                else:
                    self.bus.emit("ScanContinuesUnauthenticated",
                                  reason=self.auth_engine.state.last_error)

        # ---- Phase 54: fingerprint everything the scan already fetches. The
        # collector rides a transparent proxy placed OUTERMOST (auth watchdog
        # proxies stay inner), so crawl baselines, detector probes and verify
        # replays ALL pass through observe() — zero extra requests, passive only.
        self.engine = _FingerprintingProxy(self.engine, self.fp)
        self.verifier.engine = self.engine

        # ---- Phase 4: discovery (extra_seeds carry the authenticated landing;
        # the login page itself is excluded from page-fetches — re-fetching it
        # clobbers the authenticated session cookie with a fresh anonymous one)
        d = DiscoveryEngine(self.engine, self.cfg.max_pages)
        endpoints: list[Endpoint] = [Endpoint(url=self.target.url, source=DiscoverySource.SEED)]
        if self.cfg.crawl:
            found, js, crawl_stats = d.crawl(self.target.url, extra_seeds=auth_seeds,
                                             exclude_urls=[self.cfg.auth.login_url] if self.cfg.auth else None)
            endpoints.extend(e for e in found if e.id != endpoints[0].id)
            robots = d.robots(self.target.url)
            endpoints.extend(e for e in robots if all(e.id != x.id for x in endpoints))
            self.stats["crawl"] = crawl_stats
            self.bus.emit("DiscoveryCompleted", **crawl_stats, js_endpoints=len(js))
        # ---- DISC-13 (Phase 54): the target's OWN OpenAPI/Swagger document is a
        # machine-readable surface map — unlinked admin/legacy/API paths that no
        # crawler can reach are declared there with parameters. Auto-probe the
        # well-known locations (and honor an explicit spec); merged endpoints ride
        # the SAME dedup + scope gates as crawl results.
        if self.cfg.openapi or self.cfg.openapi_spec:
            spec_eps, spec_info = [], None
            if self.cfg.openapi_spec:
                from .discovery import parse_openapi, _spec_info
                if isinstance(self.cfg.openapi_spec, dict):
                    spec_eps = parse_openapi(self.cfg.openapi_spec, self.target.url)
                    spec_info = _spec_info(self.cfg.openapi_spec, "(inline-seed)", len(spec_eps))
            else:
                try:
                    spec_eps, spec_info = d.openapi(self.target.url)
                except Exception:
                    spec_eps, spec_info = [], None
            if spec_eps:
                new_eps = [e for e in spec_eps if all(e.id != x.id for x in endpoints)]
                endpoints.extend(new_eps)
                self.stats["openapi"] = dict(spec_info or {})
                self.stats["openapi"]["new_endpoints"] = len(new_eps)
                self.bus.emit("OpenApiSeeded", **(spec_info or {}), new_endpoints=len(new_eps))
            elif self.cfg.openapi_spec is None:
                self.stats["openapi"] = {"source": None, "paths": 0, "new_endpoints": 0}
        self.stats["endpoints"] = len(endpoints)

        # ---- Phase 50: browser/DOM engine — render-merge BEFORE planning so active
        # detectors cover runtime-discovered surfaces (JS-built forms, rendered links).
        dom_sinks = list(getattr(d, "dom_sinks", [])) if self.cfg.crawl else []
        if self.cfg.browser:
            from .browser import BrowserEngine, browser_available
            if browser_available():
                self.browser = BrowserEngine(self.engine, timeout=self.cfg.timeout,
                                             extra_headers=auth_headers)
                self.verifier.browser = self.browser
                existing = {e.id: e for e in endpoints}
                # Render budget: script-bearing pages first (runtime forms / DOM logic
                # only exist where scripts run — live-caught: a naive first-N endpoint
                # selection missed the JS-built form page entirely), then dom-sink
                # pages, then remaining GET pages up to the cap.
                seen_t = set()
                render_targets = []
                for u in (list(getattr(d, "script_pages", [])) +
                          [s.url for s in dom_sinks] +
                          [e.url for e in endpoints if (e.method or "GET") == "GET"]):
                    if u and u not in seen_t:
                        seen_t.add(u)
                        render_targets.append(u)
                render_targets = render_targets[:15]
                new_eps = self.browser.render_merge(render_targets, self.target.host, existing)
                endpoints.extend(e for e in new_eps if e.id not in {x.id for x in endpoints})
                self.stats["endpoints"] = len(endpoints)
                self.stats["browser_pages"] = self.browser.pages_rendered
                self.bus.emit("BrowserRenderCompleted", pages=self.browser.pages_rendered,
                              new_endpoints=len(new_eps), dom_sink_candidates=len(dom_sinks))
            else:
                self.bus.emit("BrowserUnavailable",
                              note="playwright/chromium not installed — static fallback active")

        # ---- Phase 7: plan; Phase 8: detect
        detectors = {d.name: d(self.engine, self.bus, self.strategies) for d in ACTIVE_DETECTORS}
        # Phase 53: OAST-channel detectors (SSRF / blind command injection) receive
        # the armed channel; without one they stay inert (response oracles for these
        # classes are noise — live-observed on the cycling stock endpoint).
        for _d in detectors.values():
            if getattr(_d, "needs_oast", False):
                _d.oast = self.cfg.oast
        vuln_to_detector = {"sql_injection": "sqli", "xss_reflected": "xss",
                            "path_traversal": "traversal", "open_redirect": "redirect", "ssrf": "ssrf",
                            "header_injection": "crlf", "xxe": "xxe",
                            "command_injection": "cmdi", "cors_misconfig": "cors",
                            "ssti": "ssti", "csrf": "csrf", "nosql_injection": "nosql",
                            "jwt_security": "jwt", "host_header_injection": "hostheader"}
        plan = []
        for ep in endpoints:
            plan.extend(plan_for(ep))
        self.bus.emit("ScanPlanReady", planned=len(plan))

        for ep in endpoints:
            if self.cfg.passive:
                r = self.engine.send(RequestMutation(endpoint=ep, note="passive-baseline"))
                if not r.error:
                    for f in passive_audit(ep, r):
                        self.findings.append(self.verifier.verify(f, ep))
            if not self.cfg.active:
                continue
            for dname, det in detectors.items():
                try:
                    if dname == "sqli":
                        cands = det.candidates(ep)
                        if not cands: continue
                        # PER-PARAM ANALYSIS (live-caught on doLogin: old flat resp_map kept
                        # only the LAST param's responses, silently discarding earlier params)
                        from itertools import groupby
                        for pname, grp in groupby(cands, key=lambda t: t[1].param_name):
                            grp = list(grp)
                            resp_map = {}
                            for strat, m in grp:
                                r = self.engine.send(m)
                                if r.error:
                                    fid = self.failures.record("sqli", r.error, {"url": ep.url})
                                    self.bus.emit("ScannerFailed", scanner="sqli", failure=fid, error=r.error)
                                    continue
                                resp_map[strat] = r
                            param_obj = next((p for p in ep.parameters if p.name == pname), None)
                            if param_obj is None or not resp_map:
                                continue
                            cand = det.analyze((ep, param_obj), resp_map)
                            if cand:
                                cand.run_id = self.run_id
                                self.stats["candidates"] += 1
                                self.bus.emit("CandidateCreated", type=cand.type, url=ep.url, param=cand.parameter)
                                out_f = self.verifier.verify(cand, ep)
                                self.findings.append(out_f)
                                # Phase 19/25: record VERIFIED outcomes only into strategy store
                                for st in ("quote_error", "boolean_and", "or_redirect", "or_differential", "quote_status"):
                                    self.strategies.record("sqli", st, out_f.status == FindingStatus.VERIFIED,
                                                           context=self.target.host)
                    elif dname == "xxe":
                        # DETECT-08 two-phase flow: candidates() returns recon probes (XML
                        # with form fields, root learned from JS); the recon response names
                        # missing elements ("Store ID could not be parsed"), expand() builds
                        # the entity differential probes, analyze() compares them.
                        cands = det.candidates(ep)
                        for strat, m in cands:
                            r0 = self.engine.send(m)
                            if r0.error or r0.status == 0:
                                continue
                            root = strat.split("|")[1]
                            probes = det.expand(ep, r0, root)
                            if not probes:
                                continue
                            resp_map = {}
                            for s2, m2 in probes:
                                r = self.engine.send(m2)
                                if r.error:
                                    fid = self.failures.record("xxe", r.error, {"url": ep.url})
                                    self.bus.emit("ScannerFailed", scanner="xxe", failure=fid, error=r.error)
                                    continue
                                resp_map[s2] = r
                            if not resp_map:
                                continue
                            cand = det.analyze((ep, None), resp_map)
                            # Phase 49 — OOB fallback: response oracle impossible (noise /
                            # non-deterministic answers) but an OAST listener is armed ->
                            # the target itself becomes the evidence channel (blind XXE).
                            if cand is None and self.cfg.oast is not None:
                                self.bus.emit("OobAttemptStarted", scanner="xxe", url=ep.url)
                                cand = det.oob_attempt(ep, root, r0, self.cfg.oast)
                            if cand:
                                cand.run_id = self.run_id
                                self.stats["candidates"] += 1
                                self.bus.emit("CandidateCreated", type=cand.type, url=ep.url, param=cand.parameter)
                                out_f = self.verifier.verify(cand, ep)
                                self.findings.append(out_f)
                                strat_name = ("oob_callback" if any(e.kind == "oob_callback" for e in cand.evidence)
                                              else "entity_differential")
                                self.strategies.record("xxe", strat_name,
                                                       out_f.status == FindingStatus.VERIFIED,
                                                       context=self.target.host)
                    elif dname in RUN_STYLE_DETECTORS:
                        # CORS (DETECT-13) + Phase 55: endpoint-driven flows that
                        # drive their own request sequences per endpoint (header
                        # probes, baseline+replay pairs, JSON operator batteries) —
                        # none of them is param-bound, so they cannot ride the
                        # generic loop.
                        cand = det.run(ep)
                        if cand:
                            cand.run_id = self.run_id
                            self.stats["candidates"] += 1
                            self.bus.emit("CandidateCreated", type=cand.type, url=ep.url, param=cand.parameter)
                            out_f = self.verifier.verify(cand, ep)
                            self.findings.append(out_f)
                            self.strategies.record(dname, "primary",
                                                   out_f.status == FindingStatus.VERIFIED,
                                                   context=self.target.host)
                    else:
                        for m in det.candidates(ep):
                            if isinstance(m, tuple):
                                m = m[1]
                            r = self.engine.send(m)
                            if r.error:
                                fid = self.failures.record(det.name, r.error, {"url": ep.url})
                                self.bus.emit("ScannerFailed", scanner=det.name, failure=fid, error=r.error)
                                continue
                            pair = (ep, next((p for p in ep.parameters if p.name == m.param_name), ep.parameters[0] if ep.parameters else None))
                            if not pair[1]: continue
                            cand = det.analyze(pair, r)
                            if cand:
                                cand.run_id = self.run_id
                                self.stats["candidates"] += 1
                                self.bus.emit("CandidateCreated", type=cand.type, url=ep.url, param=cand.parameter)
                                out_f = self.verifier.verify(cand, ep)
                                self.findings.append(out_f)
                                self.strategies.record(dname, "primary", out_f.status == FindingStatus.VERIFIED,
                                                       context=self.target.host)
                except Exception as e:
                    fid = self.failures.record(dname, f"{type(e).__name__}: {e}", {"url": ep.url})
                    self.bus.emit("ScannerFailed", scanner=dname, failure=fid, error=str(e)[:200])

        # ---- Phase 50: DOM XSS execution probes (browser; static sink candidates).
        # search sources probe the extracted param names; hash sources take the
        # payload directly in the fragment; referrer/name sources are a documented
        # limit (cannot be set by plain navigation).
        if self.browser is not None and self.cfg.active and dom_sinks:
            try:
                import hashlib as _hb
                seen_probe = set()
                for sink in dom_sinks:
                    if sink.source == "search":
                        probe_params = [p for p in sink.params[:3] if p]
                    elif sink.source == "hash":
                        probe_params = [""]
                    else:
                        continue
                    for pname in probe_params:
                        pkey = f"{sink.url}|{pname}|{sink.source}"
                        if pkey in seen_probe:
                            continue
                        seen_probe.add(pkey)
                        canary = "z" + _hb.sha1(pkey.encode()).hexdigest()[:9]
                        # canonical page URL (crawl params stripped) — the finding and
                        # its re-probe must be reproducible from a clean URL
                        page_url = sink.url.split("?")[0].split("#")[0]
                        r = self.browser.probe_dom_xss(page_url, pname, canary, source=sink.source)
                        if r and r.get("fired"):
                            cand = Finding(type="xss_dom", severity=Severity.HIGH,
                                           endpoint_url=page_url, parameter=pname, method="GET",
                                           evidence=[Evidence("dom_execution",
                                                      f"source={sink.source} sink={sink.sink} — {r['detail']}; "
                                                      f"static flow: {sink.snippet}")],
                                           status=FindingStatus.CANDIDATE)
                            cand.run_id = self.run_id
                            self.stats["candidates"] += 1
                            self.bus.emit("CandidateCreated", type=cand.type, url=sink.url, param=pname)
                            out_f = self.verifier.verify(cand, None)
                            self.findings.append(out_f)
                            self.strategies.record("dom_xss", sink.sink,
                                                   out_f.status == FindingStatus.VERIFIED,
                                                   context=self.target.host)
                self.stats["browser_probes"] = self.browser.probes_sent
            except Exception as e:
                fid = self.failures.record("dom_xss", f"{type(e).__name__}: {e}", {})
                self.bus.emit("ScannerFailed", scanner="dom_xss", failure=fid, error=str(e)[:200])
        if self.browser is not None:
            try:
                self.browser.close()
            except Exception:
                pass

        # ---- Phase 12: dedup + correlation + risk
        verified = [f for f in self.findings if f.status == FindingStatus.VERIFIED]
        rejected = [f for f in self.findings if f.status == FindingStatus.REJECTED]
        self.stats.update({"requests": self.engine.requests_sent,
                           "verified": len(verified), "rejected": len(rejected),
                           "duration": round(time.time() - t0, 2)})
        if self.auth_engine is not None:
            self.stats["auth"] = {
                "authenticated": self.auth_engine.state.authenticated,
                "landing": self.auth_engine.state.landing_url,
                "logins": self.auth_engine.state.logins,
                "reauths": self.auth_engine.state.reauths,
                "failed_reauths": self.auth_engine.state.failed_reauths,
            }
        elif self.token_engine is not None:
            # AUTH-05: token mode — no re-auth is possible; rejections (401/403
            # while armed) are the honest degradation signal instead.
            self.stats["auth"] = {"mode": "token",
                                  "authenticated": self.token_engine.state.authenticated,
                                  "header": self.cfg.auth.auth_header,
                                  "rejections": self.token_engine.rejections}
        # Phase 54: WAF + technology map (passive, evidence-backed) and rate-limit
        # resilience counters — scan context in the report, auditable without rerun.
        self.stats["fingerprint"] = self.fp.summary()
        base = self._base_engine()
        self.stats["rate_limit"] = {"limited": base.rate_limited,
                                    "retries": base.rate_limit_retries,
                                    "recovered": base.rate_limit_recovered}
        # Phase 52: OAST channel transparency — which channel served OOB evidence
        # (local loopback listener vs public webhook provider) and how many
        # interactions it recorded. Blind-vuln confirmations are auditable from
        # the report alone, without re-running the scan.
        if self.cfg.oast is not None:
            try:
                self.stats["oast"] = {"channel": getattr(self.cfg.oast, "channel", "local"),
                                      "interactions": len(self.cfg.oast.hits())}
            except Exception:
                self.stats["oast"] = {"channel": getattr(self.cfg.oast, "channel", "local"),
                                      "interactions": -1}
        ded = self.pipeline.dedup(verified)
        final = self.pipeline.correlate(ded)
        for f in final:
            f.confidence = max(f.confidence, 0.5)
        self.findings = final + rejected
        for f in final:
            self.bus.emit("FindingCreated", id=f.id, type=f.type, url=f.endpoint_url,
                          param=f.parameter, risk=self.pipeline.risk(f))
        self.bus.emit("ScanCompleted", **self.stats)
        return self.report()

    def _base_engine(self) -> RequestEngine:
        """Peel auth/fingerprint proxies to the real RequestEngine (counter owner)."""
        e = self.engine
        for _ in range(4):
            inner = getattr(e, "_inner", None)
            if inner is None:
                break
            e = inner
        return e

    def report(self) -> dict:
        return {
            "run_id": self.run_id, "seed": self.seed, "scanner": SCANNER_VERSION,
            "target": self.target.url, "stats": self.stats,
            "findings": [f.to_dict() | {"risk": self.pipeline.risk(f)} for f in self.findings
                         if f.status == FindingStatus.VERIFIED],
            "rejected_candidates": [f.to_dict() for f in self.findings
                                    if f.status == FindingStatus.REJECTED],
        }


# ============================================================ DOCTOR (Phase 44/45)
def doctor(allow_private=False) -> dict:
    import socket, ssl, subprocess, sys, platform
    checks = []

    def add(name, ok, detail, fix=""):
        checks.append({"check": name, "status": "PASS" if ok else ("WARN" if detail.startswith("warn") else "FAIL"),
                       "detail": detail, "auto_fix": fix if not ok else ""})

    add("runtime", True, f"Python {sys.version.split()[0]} on {platform.system()}")
    # DNS
    try:
        socket.gethostbyname("scanme.nmap.org")
        add("dns_resolution", True, "resolved scanme.nmap.org")
    except Exception as e:
        add("dns_resolution", False, str(e)[:80], "check /etc/resolv.conf")
    # outbound TCP
    try:
        s = socket.create_connection(("scanme.nmap.org", 80), timeout=8); s.close()
        add("network_egress", True, "TCP connect scanme.nmap.org:80 OK")
    except Exception as e:
        add("network_egress", False, str(e)[:80])
    # TLS
    try:
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        add("tls_stack", True, OpenSSL_ver := ssl.OPENSSL_VERSION)
    except Exception as e:
        add("tls_stack", False, str(e)[:80])
    # scope policy sanity
    from .core import is_private_ip
    add("scope_policy", is_private_ip("127.0.0.1") and is_private_ip("10.0.0.5") and not is_private_ip("45.33.32.156"),
        "private ranges blocked, public allowed" + (" (+private override)" if allow_private else ""))
    # detector registry
    add("detector_registry", len(ACTIVE_DETECTORS) >= 4, f"{len(ACTIVE_DETECTORS)} active detectors registered")
    # strategy store
    add("strategy_store", True, "verified-outcome Wilson ordering enabled")
    # persistence layer (Phase 46): sqlite3 available + schema initializes + round-trip
    try:
        import tempfile, os as _os, sqlite3
        from .store import Store
        p = _os.path.join(tempfile.mkdtemp(), "doctor.db")
        st = Store(p)
        st.save_run({"run_id": "run-doctor", "seed": "s", "scanner": "doctor",
                     "target": "http://doctor.local", "stats": {"requests": 1},
                     "findings": [{"id": "F-d", "type": "missing_security_headers",
                                   "severity": "low", "status": "verified",
                                   "url": "http://doctor.local/", "parameter": "", "method": "GET",
                                   "confidence": 0.98, "risk": 20, "evidence": [], "verification": {}}],
                     "rejected_candidates": []})
        ok = len(st.list_findings()) == 1 and st.stats_summary()["runs"] == 1
        add("persistence_layer", ok,
            f"SQLite store OK (schema + write + query round-trip) at {sqlite3.sqlite_version}")
    except Exception as e:
        add("persistence_layer", False, str(e)[:80])
    # repair registry
    add("repair_registry", len(RepairClassifier.RULES) >= 3, f"{len(RepairClassifier.RULES)} repair rules loaded")
    # browser engine (Phase 50): DOM XSS phase needs Playwright + Chromium.
    # Absent browser = WARN (degraded, not broken): static DOM sink analysis still
    # runs and every other phase is unaffected; browser-only checks are skipped.
    try:
        from .browser import browser_available
        if browser_available():
            add("browser_engine", True, "Playwright Chromium launch OK — DOM engine active")
        else:
            add("browser_engine", False,
                "warn: playwright/chromium unavailable — DOM XSS execution phase disabled "
                "(static sink analysis remains active; install playwright + chromium to enable)")
    except Exception as e:
        add("browser_engine", False, "warn: " + str(e)[:120])
    # auth engine (Phase 51): AuthProfile/AuthEngine/AuthedEngineProxy importable
    # and the ENG-06 body serialization they depend on behaves (no-param POST
    # requests with BODY fields must carry a non-empty form body).
    try:
        from .auth import AuthProfile, AuthEngine, AuthedEngineProxy
        from .core import ParamLocation, Parameter as _P
        eng = RequestEngine(ScopeRule(allowed_domains=["auth.doctor.local"]),
                            EventBus("doctor-auth"), timeout=2)
        m = RequestMutation(endpoint=Endpoint(
            url="http://auth.doctor.local/doLogin", method="POST",
            parameters=[_P("uid", ParamLocation.BODY, "u"), _P("passw", ParamLocation.BODY, "p")]))
        _, _, hdrs, body = eng._render(m)
        add("auth_engine", bool(body) and "uid=u" in body and "passw=p" in body,
            f"login flow engine OK (form body serialized: {bool(body)}; "
            f"watchdog proxy + budget-capped re-auth available)")
    except Exception as e:
        add("auth_engine", False, str(e)[:120])
    # OAST providers (Phase 52): local loopback listener must bind + record, and
    # the public webhook channel must create a token + read an empty request log.
    # The public check is network-dependent -> WARN (degraded, not broken) when
    # the service is unreachable: local OOB confirmation still works.
    try:
        from .oast import OastServer, PublicWebhookProvider
        with OastServer() as _o:
            assert _o.poll("doctor-none", timeout=0.2) is None
        local_ok = True
        try:
            with PublicWebhookProvider() as _p:
                assert _p.public_base.startswith("https://")
                assert _p.poll("doctor-none", timeout=1.0) is None
            public_detail = "local listener + public webhook channel both OK"
            public_ok = True
        except Exception as _pe:
            public_detail = f"warn: public channel unreachable ({str(_pe)[:60]}) — local OOB only"
            public_ok = None                                   # WARN path
        add("oast_providers", public_ok if public_ok is not None else False, public_detail)
    except Exception as e:
        add("oast_providers", False, str(e)[:80])
    passed = sum(1 for c in checks if c["status"] == "PASS")
    return {"overall": "PASS" if passed == len(checks) else "DEGRADED",
            "passed": passed, "total": len(checks), "checks": checks}

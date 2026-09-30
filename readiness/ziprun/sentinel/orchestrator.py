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
from .coverage import CoverageTracker, _CoverageProxy
from .paramintel import ParamIntel
from .secrets import SecretsScanner
from .evidence import assess as assess_impact
from .evidence import build_proof as build_finding_proof
from .appmap import build_appmap
from .authz import AuthzConfig, AuthzEngine


class ScanConfig:
    def __init__(self, allow_private=False, max_pages=25, crawl=True, active=True,
                 passive=True, timeout=12.0, seed=None, strategy_path=None,
                 allowed_domains=None, oast=None, browser=True, auth=None,
                 openapi=True, openapi_spec=None, authz=None, secrets=True,
                 vault=None, vault_key_file=None, workflow=False, logic_active=False):
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
        self.authz = authz        # Phase 56: multi-user authorization config (dict | None)
        self.secrets = secrets    # Phase 56: credential-exposure scan of passive baselines
        self.vault = vault                     # Phase 57: vault file path | None
        self.vault_key_file = vault_key_file   # Phase 57: authorized key file path
        self.workflow = workflow or logic_active   # Phase 58: workflow learning (--workflow)
        self.logic_active = logic_active       # Phase 58: attack battery (--logic-active)


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
        self.vault = None         # Phase 57: opened Credential Vault (armed capture)
        self.stats = {"requests": 0, "endpoints": 0, "candidates": 0, "verified": 0, "rejected": 0,
                      "duration": 0.0}

    # ---------------------------------------------------------------- run
    def run(self) -> dict:
        t0 = time.time()
        self.bus.emit("ScanStarted", target=self.target.url, run=self.run_id,
                      scanner=SCANNER_VERSION, seed=self.seed)

        # ---- Phase 57 (v2.9.0): Credential Vault — opened BEFORE any request
        # so a wrong/unauthorized key fails fast as a configuration error,
        # never mid-scan. Every credential the exposure engine proves is then
        # captured encrypted-at-rest; public artifacts keep masks only.
        if self.cfg.secrets and self.cfg.vault and self.cfg.vault_key_file:
            from .vault import Vault
            self.vault = Vault.open(self.cfg.vault, self.cfg.vault_key_file)
            self.bus.emit("VaultUnlocked", org=self.vault.org,
                          actor=self.vault.key_id)

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
        # ---- Phase 56: Coverage Engine — every request the scan sends is
        # attributed to its endpoint (passive baseline / secrets scan / active
        # probe / verification replay). Navigation (crawl) and auth-flow
        # requests are intentionally NOT endpoint testing and are excluded.
        self.coverage = CoverageTracker()
        self.engine = _CoverageProxy(self.engine, self.coverage)
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

        # ---- Phase 56: Smart Testing Engine (value-shape parameter intelligence)
        # + the Coverage Engine's discovery ledger. enrich() only UPGRADES param
        # kinds when the observed value proves a more specific shape (JSON object);
        # every skip it causes is recorded as an auditable coverage reason.
        for ep in endpoints:
            self.coverage.discover(ep)
        self.param_profile = ParamIntel.enrich(endpoints)
        for ep in endpoints:
            for p in ep.parameters:
                reason = ParamIntel.skip_reason(p)
                if reason:
                    self.coverage.skipped(ep, reason)
        self.stats["param_intel"] = self.param_profile

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
                if r.error:
                    self.coverage.skipped(ep, "transport_error")
                else:
                    # Phase 56 honesty gate: an ANONYMOUS scan that cannot open an
                    # endpoint (401/403, or bounced to a login gate) is an
                    # explicitly-accounted untested surface. With credentials
                    # configured the endpoint WAS tested — a 401 there is the
                    # application's answer (e.g. a login form rejecting wrong
                    # creds), not missing coverage.
                    hop = r.hop_location()
                    if self.cfg.auth is None and (r.status in (401, 403)
                                                  or (hop and "login" in hop.lower())):
                        self.coverage.skipped(ep, "requires_authentication")
                if not r.error:
                    for f in passive_audit(ep, r):
                        self.findings.append(self.verifier.verify(f, ep))
                    # ---- Phase 56: Credential Exposure Engine — secrets scan of
                    # the response the scan ALREADY fetched (zero extra requests;
                    # VR-19 re-fetches only for candidates).
                    if self.cfg.secrets:
                        self.coverage.activity(ep, "secrets", "secrets-passive-scan")
                        capture = (self.vault.capture_callback(self.run_id, ep.url)
                                   if self.vault is not None else None)
                        for sf in SecretsScanner().scan(ep, r, capture=capture):
                            sf.run_id = self.run_id
                            self.stats["candidates"] += 1
                            self.bus.emit("CandidateCreated", type=sf.type, url=ep.url,
                                          param=sf.parameter)
                            self.findings.append(self.verifier.verify(sf, ep))
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

        # ---- Phase 56: Multi-User Authorization Engine. Runs AFTER the active
        # phases with its OWN per-account engines (isolated cookie jars — no
        # session cross-contamination with the main scan session): logins every
        # configured account, builds the role x endpoint access matrix, and
        # tests the two authorization failure classes (IDOR/BOLA via victim-
        # marker oracle + vertical escalation via differential-landing
        # candidates). GET-only replays; every finding carries its own VR
        # (VR-17 fresh-victim / VR-18 fresh-privileged-replay).
        authz_result = None
        authz_sessions = {}
        if self.cfg.authz:
            try:
                acfg = AuthzConfig.from_dict(self.cfg.authz, self.target.url)
                aeng = AuthzEngine(acfg, self.scope, self.bus, timeout=self.cfg.timeout)
                authz_result = aeng.run(endpoints)
                authz_sessions = aeng.sessions
                for f in authz_result["findings"]:
                    f.run_id = self.run_id
                    self.stats["candidates"] += 1
                    self.bus.emit("CandidateCreated", type=f.type, url=f.endpoint_url,
                                  param=f.parameter)
                self.findings.extend(authz_result["findings"])
                # authz probes touched these endpoints — record it in the ledger
                by_url = {e.url.split("?")[0]: e for e in endpoints}
                for url in authz_result.get("matrix", {}):
                    ep = by_url.get(url.split("?")[0])
                    if ep is not None:
                        self.coverage.activity(ep, "authz", "authz-matrix")
            except Exception as e:
                fid = self.failures.record("authz", f"{type(e).__name__}: {e}", {})
                self.bus.emit("ScannerFailed", scanner="authz", failure=fid,
                              error=str(e)[:200])
                authz_result = authz_result or {"stats": {"ran": False,
                                                          "error": str(e)[:160]}}
            if authz_result:
                self.stats["authz"] = dict(authz_result.get("stats", {}))

        # ---- Phase 58 (v3.0.0): Workflow / Business-Logic Intelligence. Runs
        # AFTER authz (it reuses the per-role sessions for the privilege
        # manipulation). LEARN: guided walks of multi-step flow clusters on the
        # main authenticated session (chain, resource linkage, state oracle,
        # execution-marker vocabulary). ATTACK (--logic-active only): the five
        # business-logic manipulations on FRESH isolated sessions, every one
        # verified by a state-oracle delta — a server that merely fails to
        # reject is never a finding.
        wf_extra_requests = 0
        if self.cfg.workflow:
            from .workflow import WorkflowEngine
            if self.auth_engine is not None:
                try:
                    wf = WorkflowEngine()
                    wres = wf.run(endpoints, self.engine, self.scope, self.bus,
                                  self.cfg.auth, authz_sessions=authz_sessions,
                                  timeout=self.cfg.timeout,
                                  logic_active=self.cfg.logic_active)
                    for f in wres["findings"]:
                        f.run_id = self.run_id
                        self.stats["candidates"] += 1
                        self.bus.emit("CandidateCreated", type=f.type, url=f.endpoint_url,
                                      param=f.parameter)
                    self.findings.extend(wres["findings"])
                    wstats = dict(wres["stats"])
                    wstats["flows"] = [WorkflowEngine.flow_summary(k)
                                       for k in wres["flows"]]
                    self.stats["workflow"] = wstats
                    wf_extra_requests = wres["stats"].get("requests", 0)
                except Exception as e:
                    fid = self.failures.record("workflow", f"{type(e).__name__}: {e}", {})
                    self.bus.emit("ScannerFailed", scanner="workflow", failure=fid,
                                  error=str(e)[:200])
                    self.stats["workflow"] = {"enabled": True, "error": str(e)[:160]}
            else:
                self.stats["workflow"] = {"enabled": False,
                                          "skipped": ["no_form_session"]}

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
        # Phase 56: authz-engine requests ride their OWN engines — add them to
        # the total so the report's request count is the whole truth.
        if authz_result and authz_result.get("stats", {}).get("requests"):
            self.stats["requests"] += authz_result["stats"]["requests"]
        # Phase 58: workflow fresh-session requests likewise (the LEARN walks
        # ride the main engine and are already counted there).
        if wf_extra_requests:
            self.stats["requests"] += wf_extra_requests
        ded = self.pipeline.dedup(verified)
        final = self.pipeline.correlate(ded)
        for f in final:
            f.confidence = max(f.confidence, 0.5)
        self.findings = final + rejected
        for f in final:
            self.bus.emit("FindingCreated", id=f.id, type=f.type, url=f.endpoint_url,
                          param=f.parameter, risk=self.pipeline.risk(f))
        # ---- Phase 56: Coverage account + Application Map + secrets summary +
        # impact proof on every verified finding. All deterministic, all derived
        # from artifacts the scan already produced.
        self.stats["coverage"] = self.coverage.summarize()
        auth_mode = ("multi-user(" + ",".join(self.stats.get("authz", {}).get("roles", [])) + ")"
                     if self.stats.get("authz", {}).get("ran") else
                     "form-session" if self.auth_engine is not None else
                     "token" if self.token_engine is not None else "anonymous")
        self.stats["appmap"] = build_appmap(endpoints, param_profile=self.param_profile,
                                            authz_result=authz_result,
                                            coverage_summary=self.stats["coverage"],
                                            auth_mode=auth_mode,
                                            workflow_summary=self.stats.get("workflow", {}).get("flows"))
        # ---- Phase 60-63 (v4.0.0): the Security Digital Twin + Autonomous
        # Reasoning + Safe Attack Planner + Evidence OS. All built from
        # artifacts the scan ALREADY produced — zero extra requests, fully
        # deterministic, additive to the report.
        from .twin import build_twin, twin_summary, authorization_matrix, entity_inventory
        from . import reasoning
        from .planner import SafeAttackPlanner

        wf_stats = self.stats.get("workflow", {})
        cred_surfaces: dict[str, list[str]] = {}
        for f in final:
            if f.type == "credential_exposure":
                cred_surfaces.setdefault(f.parameter, []).append(f.endpoint_url)
        secrets_summary = {"classes": cred_surfaces} if cred_surfaces else None
        # the twin's identity nodes come from the authz engine's ACTUALLY
        # logged-in sessions (every account that was really exercised)
        if authz_result is not None and authz_sessions:
            authz_result = dict(authz_result)
            authz_result["accounts"] = [
                {"name": s["account"].name, "role": s["account"].role,
                 "username": s["account"].username, "marker": s["account"].marker,
                 "object_id": s["account"].object_id}
                for _, s in sorted(authz_sessions.items())]
        self.twin = build_twin(self.target.url, endpoints,
                               param_profile=self.param_profile,
                               authz_result=authz_result, auth_mode=auth_mode,
                               workflow_stats=wf_stats,
                               findings=[f.to_dict() for f in final
                                         if f.status == FindingStatus.VERIFIED],
                               coverage_summary=self.stats["coverage"],
                               secrets_summary=secrets_summary)
        # hypotheses: generated from twin patterns, resolved against what the
        # scan actually did (findings + the workflow attack log)
        hyps = reasoning.generate_hypotheses(self.twin,
                                             logic_active=self.cfg.logic_active)
        hyps = reasoning.resolve_hypotheses(hyps,
                                             [f.to_dict() for f in final
                                              if f.status == FindingStatus.VERIFIED],
                                             workflow_attack_log=wf_stats.get("attack_log"),
                                             authz_stats=self.stats.get("authz"))
        self.stats["reasoning"] = reasoning.hypothesis_summary(hyps)
        self.stats["reasoning"]["hypotheses"] = hyps[:80]
        # attach the resolved hypotheses to the twin graph (audit trail)
        self.twin_hypotheses = hyps
        for h in hyps:
            self.twin.add_node("hypothesis", h["id"], label=h["pattern"],
                               pattern=h["pattern"], status=h["status"],
                               premise=h.get("premise", "")[:160], test=h.get("test", ""))
            surf = self.twin.find("surface", h.get("surface", ""))
            if surf is not None:
                self.twin.add_edge(surf, self.twin.find("hypothesis", h["id"]),
                                   "generated_hypothesis")
        self.stats["digital_twin"] = twin_summary(self.twin)
        self.stats["digital_twin"]["authorization_matrix"] = authorization_matrix(self.twin)
        self.stats["digital_twin"]["entity_inventory"] = entity_inventory(self.twin)

        # Safe Attack Planner ledger: the machine-readable safety contract of
        # everything this scan did (or refused to do) to the target.
        planner = SafeAttackPlanner(logic_active=self.cfg.logic_active)
        planner.gate(self.target.url, "GET", note="passive-baseline")
        for a in (wf_stats.get("attack_log") or []):
            planner.gate("".join(["/", a.get("flow", "").strip("/"), "/step"]),
                         "POST", note="wf-atk")
        if self.cfg.crawl:
            planner.gate(self.target.url + "/*", "GET", note="discovery")
        self.stats["planner"] = planner.summary()
        # Evidence OS: every verified finding becomes a self-contained proof
        # file (hypothesis, preconditions, chain of custody, reproduction).
        # Priority-ordered (business-logic and authorization proofs first —
        # they are the ones an auditor reproduces by hand), then capped.
        def _proof_priority(f) -> tuple:
            if f.type.startswith("business_logic_"):
                return (0, f.type)
            if f.type in ("idor_bola", "vertical_privilege_escalation",
                          "credential_exposure"):
                return (1, f.type)
            return (2, f.type)
        self.stats["proofs"] = [build_finding_proof(
                                       f, getattr(f, "state_before", ""),
                                       getattr(f, "state_after", "")) for f in
                                sorted((f for f in final
                                        if f.status == FindingStatus.VERIFIED),
                                       key=_proof_priority)][:40]
        cred_classes = sorted({f.parameter for f in final if f.type == "credential_exposure"})
        if cred_classes or self.cfg.secrets:
            self.stats["secrets"] = {"classes_found": cred_classes,
                                     "findings": sum(1 for f in final
                                                     if f.type == "credential_exposure"),
                                     "masking": ("raw values encrypted into the "
                                                 "credential vault; public reports "
                                                 "show masks only"
                                                 if self.vault is not None else
                                                 "raw values never stored (prefix+length only)")}
        # Phase 57: vault account — masked counts only, plus the audit-visible
        # org/revision (never key material, never record values).
        if self.vault is not None:
            masked_list = self.vault.list()
            self.stats["vault"] = {"org": self.vault.org,
                                   "revision": self.vault.revision,
                                   "records": len(masked_list),
                                   "classes": sorted({r["cls"] for r in masked_list}),
                                   "policy": ("raw values encrypted at rest; "
                                              "reveal requires an authorized key "
                                              "and is audit-logged")}
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
        rep = {
            "run_id": self.run_id, "seed": self.seed, "scanner": SCANNER_VERSION,
            "target": self.target.url, "stats": self.stats,
            "findings": [f.to_dict() | {"risk": self.pipeline.risk(f),
                                        "impact": assess_impact(f)} for f in self.findings
                         if f.status == FindingStatus.VERIFIED],
            "rejected_candidates": [f.to_dict() for f in self.findings
                                    if f.status == FindingStatus.REJECTED],
        }
        # Phase 57: defense in depth — when a vault is armed, scrub the WHOLE
        # report of every known raw value. Findings carry masks by
        # construction; this catches any future accidental leakage path.
        if self.vault is not None:
            rep = self.vault.scrub(rep)
        return rep


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
    # Intelligence Layer (Phase 56): coverage / param-intel / secrets / evidence
    # / appmap / authz modules importable AND their core invariants hold.
    try:
        from .coverage import CoverageTracker
        from .paramintel import ParamIntel
        from .secrets import SecretsScanner, mask
        from .evidence import assess
        from .appmap import build_appmap
        from .authz import AuthzConfig, ROLE_RANK
        from .core import ParamKind          # NOTE: Endpoint stays module-level — a
                                             # local import would shadow it for the
                                             # WHOLE function and break the auth_engine
                                             # check above (live-caught: UnboundLocalError)
        # param-intel: JSON-object value shape is recognized and auditable
        assert ParamIntel.infer("filter", '{"a": 1}') == ParamKind.JSON_OBJECT
        assert ParamIntel.infer("q", "plain") is None
        # coverage: discovered/tested/skip math is exact
        cov = CoverageTracker()
        ep = Endpoint(url="http://x.local/a")
        cov.discover(ep); cov.activity(ep, "passive"); cov.skipped(ep, "demo_reason")
        s = cov.summarize()
        assert s["discovered"] == 1 and s["tested"] == 1 and s["skip_reasons"]["demo_reason"] == 1
        # secrets: signature fires, value is masked, placeholders rejected
        sc = SecretsScanner()
        hits = sc.scan(Endpoint(url="http://x.local/cfg"),
                       type("R", (), {"error": "", "status": 200, "body":
                            '{"aws_access_key_id": "AKIA' + "B" * 16 + '"}',
                            "headers": {}, "request_id": "r1"})())
        assert len(hits) == 1 and "…" in hits[0].evidence[0].detail and "BBBB" not in hits[0].evidence[0].detail
        # evidence: impact assessment maps every registered finding type
        assert assess(type("F", (), {"type": "sql_injection", "evidence": [],
                                     "verification": None, "parameter": "x",
                                     "method": "GET", "endpoint_url": "http://x"})())["grade"] == "proven"
        # authz: role ranking + config parsing
        assert ROLE_RANK["admin"] < ROLE_RANK["user"]
        acfg = AuthzConfig.from_dict({"login_url": "/login", "accounts": [
            {"name": "a", "role": "admin", "username": "u", "password": "p",
             "marker": "m", "object_id": "1"}]}, "http://t.local")
        assert acfg.login_url == "http://t.local/login" and len(acfg.accounts) == 1
        add("intelligence_engines", True,
            "coverage / param-intel / secrets (masked) / evidence-impact / appmap / authz OK")
    except Exception as e:
        add("intelligence_engines", False, str(e)[:120])
    # Credential Vault (Phase 57): crypto self-test — RFC 8439 quarter-round
    # vector, AEAD roundtrip, tamper rejection, purge leaves no plaintext.
    try:
        import tempfile as _tf, os as _os2
        from .vault import Vault, VaultError, keygen, _quarter_round
        w = [0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567]
        _quarter_round(w, 0, 1, 2, 3)
        assert w == [0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb], \
            "ChaCha20 quarter-round vector mismatch"
        with _tf.TemporaryDirectory() as td:
            kf, vp = _os2.path.join(td, "k.json"), _os2.path.join(td, "v.vault")
            keygen(kf, "doctor")
            v = Vault.init(vp, kf, "doctor-selftest")
            probe = "AK" + "IA" + "D" * 16      # aws-shaped probe value
            rid = v.store("aws_access_key", probe,
                          {"url": "http://x/cfg"}, "critical")
            assert v.export(rid)["raw"] == probe
            v.purge(all_records=True)
            data = open(vp, "rb").read()
            assert data.count(probe.encode()) == 0, "plaintext survived purge"
        add("credential_vault", True,
            "ChaCha20+HMAC encrypt-then-MAC OK; audit + purge leave no plaintext")
    except Exception as e:
        add("credential_vault", False, str(e)[:120])
    # Workflow Engine (Phase 58): parser + clustering + synthesis invariants.
    try:
        from .workflow import (WorkflowEngine, parse_forms, _privilege_options,
                               _synth_fresh_resource, CANARY_CREATE)
        html = ('<form action="/wf/x/confirm" method="POST">'
                '<input type="hidden" name="csrfToken" value="t1">'
                '<input type="hidden" name="tid" value="TRF-0007">'
                '<input type="hidden" name="amount" value="1111">'
                '<select name="mode"><option value="ach">ACH</option>'
                '<option value="wire">Wire transfer (admin only)</option></select></form>')
        forms = parse_forms(html)
        assert [f["name"] for f in forms[0]["fields"]] == ["csrfToken", "tid", "amount", "mode"]
        assert _privilege_options(forms) == [("mode", "wire", "Wire transfer (admin only)")]
        we = WorkflowEngine()
        assert dict(we._synth_fields(forms[0]))["mode"] == "ach"          # first option
        assert dict(we._synth_fields(forms[0], overrides={"mode": "wire"}))["mode"] == "wire"
        assert _synth_fresh_resource("TRF-0007") == "TRF-99001"
        # cluster eligibility: root excluded, flat /vuln-style dirs excluded,
        # mixed multi-step clusters qualify (>=2 POST + >=1 GET + >=3 members)
        # NOTE: Endpoint is NOT re-imported here — a local import shadows the
        # module-level name for the WHOLE function and breaks the auth_engine
        # check above (live-caught in v2.8.0, same defect class).
        from .core import ParamLocation, Parameter as _P
        eps = [Endpoint(url="http://t.local/wf/transfer/start"),
               Endpoint(url="http://t.local/wf/transfer/ledger"),
               Endpoint(url="http://t.local/wf/transfer/select", method="POST",
                        parameters=[_P("acct", ParamLocation.BODY, "800001")]),
               Endpoint(url="http://t.local/wf/transfer/create", method="POST",
                        parameters=[_P("amount", ParamLocation.BODY, "")]),
               Endpoint(url="http://t.local/wf/transfer/confirm", method="POST"),
               Endpoint(url="http://t.local/vuln/a.php"), Endpoint(url="http://t.local/vuln/b.php")]
        cl = we._cluster_members(eps, {"http://t.local/doLogin"})
        assert "/wf/transfer" in cl and "/vuln" in cl
        assert we._eligible(cl["/wf/transfer"]) and not we._eligible(cl["/vuln"])
        assert "/" not in cl and all("/wf" != d for d in cl)
        add("workflow_engine", True,
            "flow parser (select/options + privilege labels) + cluster rules + "
            "guided-walk synthesis OK")
    except Exception as e:
        add("workflow_engine", False, str(e)[:120])
    passed = sum(1 for c in checks if c["status"] == "PASS")
    return {"overall": "PASS" if passed == len(checks) else "DEGRADED",
            "passed": passed, "total": len(checks), "checks": checks}

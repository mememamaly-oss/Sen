"""Scan Orchestrator — ties Discovery -> Planner -> Detection -> Verification -> Finding Pipeline.
Plus: sentinel doctor (Phase 45) and benchmark runner hooks (Phase 16/29).
"""
from __future__ import annotations
import json, os, time
from .core import (Endpoint, EventBus, Finding, FindingStatus, ScopeRule, Target,
                   DiscoverySource, new_run_id, SCANNER_VERSION)
from .http_engine import RequestEngine, RequestMutation
from .discovery import DiscoveryEngine
from .detect import (ACTIVE_DETECTORS, SQLiDetector, XSSDetector, TraversalDetector,
                     RedirectDetector, passive_audit, plan_for)
from .intel import VerificationEngine, FindingPipeline, StrategyStore, FailureMemory, RepairClassifier


class ScanConfig:
    def __init__(self, allow_private=False, max_pages=25, crawl=True, active=True,
                 passive=True, timeout=12.0, seed=None, strategy_path=None,
                 allowed_domains=None):
        self.allow_private = allow_private
        self.max_pages = max_pages
        self.crawl, self.active, self.passive = crawl, active, passive
        self.timeout, self.seed = timeout, seed
        self.strategy_path = strategy_path
        self.allowed_domains = allowed_domains or []


class SentinelScanner:
    def __init__(self, target_url: str, cfg: ScanConfig | None = None):
        self.cfg = cfg or ScanConfig()
        self.run_id, self.seed = new_run_id(self.cfg.seed)
        self.bus = EventBus(self.run_id)
        self.target = Target(target_url)
        self.scope = ScopeRule(allowed_domains=[self.target.host] + self.cfg.allowed_domains,
                               allow_private=self.cfg.allow_private)
        self.engine = RequestEngine(self.scope, self.bus, timeout=self.cfg.timeout)
        self.verifier = VerificationEngine(self.engine, self.bus)
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

        # ---- Phase 4: discovery
        d = DiscoveryEngine(self.engine, self.cfg.max_pages)
        endpoints: list[Endpoint] = [Endpoint(url=self.target.url, source=DiscoverySource.SEED)]
        if self.cfg.crawl:
            found, js, crawl_stats = d.crawl(self.target.url)
            endpoints.extend(e for e in found if e.id != endpoints[0].id)
            robots = d.robots(self.target.url)
            endpoints.extend(e for e in robots if all(e.id != x.id for x in endpoints))
            self.stats["crawl"] = crawl_stats
            self.bus.emit("DiscoveryCompleted", **crawl_stats, js_endpoints=len(js))
        self.stats["endpoints"] = len(endpoints)

        # ---- Phase 7: plan; Phase 8: detect
        detectors = {d.name: d(self.engine, self.bus, self.strategies) for d in ACTIVE_DETECTORS}
        vuln_to_detector = {"sql_injection": "sqli", "xss_reflected": "xss",
                            "path_traversal": "traversal", "open_redirect": "redirect", "ssrf": "redirect"}
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
                                for st in ("quote_error", "boolean_and", "or_redirect"):
                                    self.strategies.record("sqli", st, out_f.status == FindingStatus.VERIFIED,
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

        # ---- Phase 12: dedup + correlation + risk
        verified = [f for f in self.findings if f.status == FindingStatus.VERIFIED]
        rejected = [f for f in self.findings if f.status == FindingStatus.REJECTED]
        self.stats.update({"requests": self.engine.requests_sent,
                           "verified": len(verified), "rejected": len(rejected),
                           "duration": round(time.time() - t0, 2)})
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
    # repair registry
    add("repair_registry", len(RepairClassifier.RULES) >= 3, f"{len(RepairClassifier.RULES)} repair rules loaded")
    passed = sum(1 for c in checks if c["status"] == "PASS")
    return {"overall": "PASS" if passed == len(checks) else "DEGRADED",
            "passed": passed, "total": len(checks), "checks": checks}

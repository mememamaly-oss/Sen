"""Phase 9: Verification Engine + Phase 12: Finding Intelligence (dedup/correlation/risk)
+ Phase 19: Strategy Store (deterministic, verified-outcomes-only learning)
+ Phase 20: Failure Memory + Phase 18: Repair Gate infrastructure.
"""
from __future__ import annotations
import json, math, os, time, hashlib
from .core import Endpoint, EventBus, Finding, FindingStatus, Severity, Verification, ParamKind
from .http_engine import RequestEngine, RequestMutation
from .detect import SQLiDetector, XSSDetector, TraversalDetector, passive_audit, SECURITY_HEADERS


# ============================================================ VERIFICATION (Phase 9)
class VerificationEngine:
    """Candidate -> re-test with independent variant -> evidence -> confidence -> verdict.
    A candidate is NEVER a finding until this passes (spec: Candidate != Truth)."""

    def __init__(self, engine: RequestEngine, bus: EventBus, oast=None, browser=None):
        self.engine, self.bus, self.oast = engine, bus, oast
        self.browser = browser     # Phase 50: BrowserEngine | None — xss_dom re-probes

    def _replay(self, ep: Endpoint, param: str, value: str):
        return self.engine.send(RequestMutation(endpoint=ep, param_name=param, param_value=value))

    def verify(self, f: Finding, ep: Endpoint | None = None) -> Finding:
        self.bus.emit("VerificationStarted", finding=f.id, type=f.type)
        if f.type == "sql_injection":
            p = f.parameter
            base = "1"
            if ep and ep.param(p):
                base = ep.param(p).value if ep.param(p).value.isdigit() else "1"
            # PATH A — boolean oracle replay (blind)
            r1 = self._replay(ep, p, f"{base} AND 1=1")
            r2 = self._replay(ep, p, f"{base} AND 1=2")
            stable = (r1.ok and not r2.ok) or abs(len(r1.body or "") - len(r2.body or "")) > 200
            if stable:
                v = Verification(method="oracle:replay-2round", passed=True, confidence=0.95, rounds=2,
                                 notes=f"replay TRUE={r1.status} FALSE={r2.status}")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED
            else:
                # PATH D — VR-04 (live-caught on ginandjuice.shop /catalog?category=):
                # string-context blind SQLi WITHOUT errors and WITHOUT redirects — the
                # OR-tautology changes the RESULT SET (all products vs empty category).
                # Fresh vectors (comparison-based, different from detection payloads)
                # keep this an INDEPENDENT replay: '2'>'1' is TRUE, '1'>'2' is FALSE.
                rd1 = self._replay(ep, p, f"{base}' OR '2'>'1' -- ")
                rd2 = self._replay(ep, p, f"{base}' OR '1'>'2' -- ")
                if (rd1.status and rd1.status == rd2.status and rd1.ok and
                        abs(len(rd1.body or "") - len(rd2.body or "")) > max(200, 0.25 * max(len(rd1.body or "x"), 1))):
                    v = Verification(method="oracle:or-bodydiff-2round", passed=True, confidence=0.95, rounds=2,
                                     notes=f"fresh OR-pair body differential: TRUE {len(rd1.body)}B vs FALSE {len(rd2.body)}B")
                    f.verification, f.confidence = v, v.confidence
                    f.status = FindingStatus.VERIFIED
                else:
                    # PATH C — DETECT-01: OR-tautology redirect differential replay (auth bypass,
                    # string context; live-proven on demo.testfire.net/doLogin)
                    # ENG-01: hop_location() is chain-aware — works even though the engine
                    # auto-follows same-host redirects (old code read only final headers).
                    r5 = self._replay(ep, p, f"{base}' OR '1'='1' -- ")
                    r6 = self._replay(ep, p, f"{base}' OR '1'='2' -- ")
                    l5, l6 = (r5.hop_location() if r5 else ""), (r6.hop_location() if r6 else "")
                    if l5 and l6 and l5 != l6:
                        v = Verification(method="oracle:or-redirect-2round", passed=True, confidence=0.95, rounds=2,
                                         notes=f"replay OR TRUE -> {l5}, FALSE -> {l6}")
                        f.verification, f.confidence = v, v.confidence
                        f.status = FindingStatus.VERIFIED
                    else:
                        # PATH B — error-based replay: quote payload must reproduce DB error (independent variant: double-quote)
                        from .detect import SQL_ERR_PATTERNS
                        import re as _re
                        alt_quot = base + '"' if "'" in str(f.evidence) else base + "'"
                        r3 = self._replay(ep, p, base + '"')
                        r4 = self._replay(ep, p, base + "'")
                        err_repro = any((not r.ok and r.status >= 500) or any(pat.search(r.body or "") for pat in SQL_ERR_PATTERNS)
                                        for r in (r3, r4) if r.status)
                        v = Verification(method="error:replay-2variants", passed=err_repro,
                                         confidence=0.9 if err_repro else 0.15, rounds=2,
                                         notes=f"single+double quote variants reproduce DB error: {err_repro}")
                        f.verification, f.confidence = v, v.confidence
                        f.status = FindingStatus.VERIFIED if err_repro else FindingStatus.REJECTED

        elif f.type == "xss_reflected":
            # VR-02 fix (2026-09-27, live-caught on demo.testfire.net): a single fixed
            # variant payload (<img onerror>) let pattern-blacklist WAFs veto genuinely
            # exploitable reflections (FN). Deterministic fix: VECTOR DIVERSITY — a
            # battery of event-handler-distinct probes; verified if ANY reflects raw,
            # confidence scaled by how many independent contexts confirmed.
            variants = [
                "<img src=x onerror=sentinel42()>",              # classic img/onerror
                "<details open ontoggle=sentinel42()>",          # auto-fires on toggle
                "<svg><animate onbegin=sentinel42() attributeName=x>",  # svg onbegin
                "<svg\nonload=sentinel42()>",                    # newline separator
                "<iframe srcdoc=sentinel42()>",                  # srcdoc context
                "<sentinelxssmarker>vr2</sentinelxssmarker>",    # raw-tag canary re-check
            ]
            passed_vecs = 0
            for alt in variants:
                r = self._replay(ep, f.parameter, alt)
                if r is not None and alt in (r.body or ""):
                    passed_vecs += 1
            executed_ctx = passed_vecs >= 1
            conf = 0.9 if passed_vecs >= 2 else (0.75 if passed_vecs == 1 else 0.15)
            v = Verification(method="re-test:variant-battery-6", passed=executed_ctx,
                             confidence=conf, rounds=len(variants),
                             notes=f"{passed_vecs}/{len(variants)} diverse vectors reflected raw "
                                   "(WAF-resistant verification)")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if executed_ctx else FindingStatus.REJECTED

        elif f.type == "xss_dom":
            # BR-01 (Phase 50): the candidate fired with canary A via a real browser
            # execution proof (window flag set by onerror). Verification = INDEPENDENT
            # re-probe with a FRESH canary B — both must execute. Deterministic:
            # the flag can only be set if the browser parsed our payload as markup.
            if self.browser is None:
                v = Verification(method="re-probe:fresh-canary", passed=False, confidence=0.1,
                                 rounds=0, notes="browser engine unavailable — cannot re-verify DOM execution")
            else:
                import hashlib as _h9
                fresh = ("dom" + _h9.sha1(f"{f.id}|{f.run_id}|br01".encode()).hexdigest()[:8])
                r = self.browser.probe_dom_xss(f.endpoint_url, f.parameter, fresh,
                                               source=next((e.detail.split("source=")[-1].split()[0]
                                                            for e in f.evidence if "source=" in e.detail), "search"))
                ok = bool(r and r.get("fired"))
                v = Verification(method="re-probe:fresh-canary", passed=ok,
                                 confidence=0.9 if ok else 0.15, rounds=1,
                                 notes=f"fresh canary {fresh!r} executed as markup: {ok}")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if v.passed else FindingStatus.REJECTED

        elif f.type == "path_traversal":
            ev = str(f.evidence)
            if "win.ini" in ev or "[fonts]" in ev:
                variants = ["../" * 4 + "windows/win.ini", "../" * 6 + "windows/win.ini", "../" * 8 + "windows/win.ini"]
                markers = ("[fonts]",)
            elif "passwd" in ev or "root:x" in ev:
                variants = ["../" * 6 + "etc/passwd", "../" * 8 + "etc/passwd"]
                markers = ("root:x:0:0:",)
            else:
                variants = ["../" * 4 + "secret.txt", "../" * 6 + "secret.txt"]
                markers = ("SENTINEL-SECRET-FILE",)
            hit = False
            used = ""
            for alt in variants:
                r = self._replay(ep, f.parameter, alt)
                if any(m in (r.body or "") for m in markers):
                    hit, used = True, alt
                    break
            v = Verification(method="re-test:same-marker-alt-depth", passed=hit,
                             confidence=0.9 if hit else 0.15, rounds=len(variants),
                             notes=f"alternative depth payload {used[:40]!r} reproduces leak: {hit}")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if hit else FindingStatus.REJECTED

        elif f.type == "open_redirect":
            r = self._replay(ep, f.parameter, "https://sentinel-redirect-check.example.org/second")
            ok = "sentinel-redirect-check.example.org" in (r.headers.get("location", "") or r.body or "")
            v = Verification(method="re-test:second-host", passed=ok, confidence=0.85 if ok else 0.2, rounds=1)
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok else FindingStatus.REJECTED

        elif f.type == "http_response_header_injection":
            # VR-05 (live-caught on ginandjuice.shop /catalog?category=): re-test with a
            # DIFFERENT header name — if the server still splits our injected header out
            # of the param value, header injection is independently confirmed.
            r = self._replay(ep, f.parameter, "sentinelcrlf2\r\nX-Sentinel-Verify-Hdr: confirmed")
            v2 = (r.headers or {}).get("x-sentinel-verify-hdr", "")
            ok = bool(v2)
            v = Verification(method="re-test:fresh-header-name", passed=ok,
                             confidence=0.9 if ok else 0.15, rounds=1,
                             notes=f"fresh vector split response header x-sentinel-verify-hdr={v2!r}")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok else FindingStatus.REJECTED

        elif f.type == "xxe":
            # VR-07 (Phase 49): OOB-confirmed blind XXE — independent replay with a
            # FRESH interaction id. The first callback proved the target fetches
            # external entities; the second, with a never-used id, proves it is
            # reproducible and not a coincidental single fetch. Response-independent
            # by construction: the evidence channel is the callback itself.
            if any(e.kind == "oob_callback" for e in f.evidence) and self.oast is not None:
                import re as _re7
                ev7 = " ".join(e.detail for e in f.evidence)
                mroot = _re7.search(r"root=(\w+)", ev7)
                root = mroot.group(1) if mroot else "request"
                elem = f.parameter or "storeId"
                from .detect import XxeDetector
                xd = XxeDetector(self.engine, self.bus)
                fields = [(p.name, p.value or "1") for p in ep.parameters] if ep else []
                iid = xd._oob_iid(ep, elem, "verify")
                xml = xd._xml(root, fields, self.oast.url(iid), elem)
                rv = self.engine.send(RequestMutation(
                    endpoint=ep, body_override=xml, method="POST",
                    extra_headers={"Content-Type": "application/xml"}))
                hit = self.oast.poll(iid, timeout=2.0) if not rv.error else None
                ok = hit is not None
                v = Verification(method="re-test:fresh-interaction-id", passed=ok,
                                 confidence=0.9 if ok else 0.15, rounds=1,
                                 notes=f"fresh interaction id {iid} fetched out-of-band: {ok}")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if ok else FindingStatus.REJECTED
                self.bus.emit("VerificationCompleted", finding=f.id, type=f.type,
                              passed=f.verification.passed if f.verification else False,
                              status=f.status.value, confidence=f.confidence)
                return f
            # VR-06 (live-caught on ginandjuice.shop /catalog/product/stock): independent
            # replay with FRESH files (/etc/group, /etc/lsb-release) and a fresh control.
            # Entity resolution is confirmed only if the control is STABLE (probed twice,
            # must match — random-response targets fail here) AND BOTH fresh files change
            # the response relative to that control — same oracle class, disjoint payloads.
            import re as _re2
            evtxt = str(f.evidence)
            mroot = _re2.search(r"root=(\w+)", evtxt)
            root = mroot.group(1) if mroot else "request"
            elem = f.parameter or "storeId"
            from .detect import XxeDetector
            xd = XxeDetector(self.engine, self.bus)
            fields = [(p.name, p.value or "1") for p in ep.parameters] if ep else []
            fresh_ctrl = "file:///nonexistent-sentinel-verify"
            fresh_files = ["file:///etc/group", "file:///etc/lsb-release"]

            def _send_xml(fpath):
                return self.engine.send(RequestMutation(
                    endpoint=ep, body_override=xd._xml(root, fields, fpath, elem),
                    method="POST", extra_headers={"Content-Type": "application/xml"}))
            rc1, rc2 = _send_xml(fresh_ctrl), _send_xml(fresh_ctrl)
            stable_ctrl = (rc1.status == rc2.status and (rc1.body or "") == (rc2.body or ""))
            hits = 0
            if stable_ctrl:
                for ff in fresh_files:
                    rp = _send_xml(ff)
                    if rp.status != rc1.status or (rp.body or "") != (rc1.body or ""):
                        hits += 1
            ok = stable_ctrl and hits >= 2
            v = Verification(method="re-test:fresh-entity-files", passed=ok,
                             confidence=0.9 if ok else 0.15, rounds=4,
                             notes=f"stable control={stable_ctrl}; fresh files differing from fresh control: {hits}/2 "
                                   f"(root={root}, element={elem})")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok else FindingStatus.REJECTED

        else:  # passive findings: single-response evidence, verified by definition of presence
            v = Verification(method="single-response-evidence", passed=True, confidence=0.98, rounds=1)
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED

        self.bus.emit("VerificationCompleted", finding=f.id, type=f.type,
                      passed=f.verification.passed if f.verification else False,
                      status=f.status.value, confidence=f.confidence)
        return f


# ============================================================ FINDING PIPELINE (Phase 12)
RISK_WEIGHTS = {"sql_injection": 9, "xss_reflected": 7, "xss_dom": 7, "path_traversal": 7, "xxe": 9,
                "open_redirect": 4, "http_response_header_injection": 6,
                "missing_security_headers": 2, "server_banner_disclosure": 1,
                "tech_banner_disclosure": 1, "vulnerable_js_dependency": 2}

class FindingPipeline:
    def __init__(self, bus: EventBus):
        self.bus = bus

    def dedup(self, findings: list[Finding]) -> list[Finding]:
        seen: dict[str, Finding] = {}
        for f in findings:
            fp = f.fingerprint()
            if fp in seen:
                seen[fp].evidence.extend(f.evidence)
                self.bus.emit("FindingDeduplicated", fingerprint=fp, kept=seen[fp].id, dropped=f.id)
            else:
                seen[fp] = f
        return list(seen.values())

    def correlate(self, findings: list[Finding]) -> list[Finding]:
        """Merge duplicate evidence for the SAME injection point (type + full path + param).
        Different endpoints/parameters stay distinct findings — they are distinct root causes."""
        roots: dict[str, Finding] = {}
        for f in sorted(findings, key=lambda x: -RISK_WEIGHTS.get(x.type, 1)):
            key = f"{f.type}|{f.endpoint_url.split('?')[0]}|{f.parameter}"
            if key in roots:
                roots[key].evidence.extend(f.evidence[:2])
            else:
                roots[key] = f
        return list(roots.values())

    def risk(self, f: Finding) -> int:
        """technical severity x confidence x exposure, 0-100."""
        base = RISK_WEIGHTS.get(f.type, 3) * 10
        conf = f.confidence or 0.5
        auth_factor = 1.0
        return min(100, int(base * conf * auth_factor))


# ============================================================ STRATEGY STORE (Phase 19/25/26)
def wilson_lower(successes: int, n: int, z: float = 1.96) -> float:
    """Wilson score lower bound — sample-size-aware (spec 26)."""
    if n == 0: return 0.0
    p = successes / n
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n)
    return max(0.0, (centre - margin) / denom)


class StrategyStore:
    """Learning = deterministic statistics from VERIFIED outcomes only (spec 51)."""
    def __init__(self, path: str | None = None):
        self.path = path
        self.stats: dict[str, dict] = {}
        if path and os.path.exists(path):
            self.stats = json.load(open(path))

    def key(self, scanner: str, strategy: str, context: str = "default") -> str:
        return f"{scanner}:{context}:{strategy}"

    def record(self, scanner: str, strategy: str, verified: bool, context: str = "default"):
        k = self.key(scanner, strategy, context)
        s = self.stats.setdefault(k, {"n": 0, "verified": 0, "failed": 0})
        s["n"] += 1
        s["verified" if verified else "failed"] += 1
        self.flush()

    def order(self, scanner: str, strategies: list[str], context: str = "default") -> list[str]:
        """Deterministic ordering by Wilson lower bound; ties broken alphabetically."""
        def lb(st):
            s = self.stats.get(self.key(scanner, st, context), {"n": 0, "verified": 0})
            return (wilson_lower(s["verified"], s["n"]), s["n"])
        return sorted(strategies, key=lambda st: (-lb(st)[0], st))

    def flush(self):
        if self.path:
            json.dump(self.stats, open(self.path, "w"), indent=1)


# ============================================================ FAILURE MEMORY + REPAIR (Phase 18/22)
class FailureMemory:
    """Every failure becomes a permanent record (spec 27) + auto regression case (spec 28)."""
    def __init__(self, path: str | None = None):
        self.path, self.records = path, []
        if path and os.path.exists(path):
            self.records = json.load(open(path))

    def record(self, scanner: str, error: str, context: dict) -> str:
        fid = "fail-" + hashlib.sha1(f"{scanner}{error}{time.time()}".encode()).hexdigest()[:10]
        self.records.append({"id": fid, "scanner": scanner, "error": error[:300],
                             "context": context, "t": time.time()})
        self.flush()
        return fid

    def flush(self):
        if self.path:
            json.dump(self.records, open(self.path, "w"), indent=1)


class RepairClassifier:
    """Deterministic failure -> repair rule mapping (spec 22)."""
    RULES = {
        "timeout_spike": {
            "match": lambda err, ctx: "timeout" in err.lower(),
            "action": {"multiply_timeout": 3.0, "retry": 1},
            "validation": {"benchmark": "local-fixture-v1", "regression": "all"},
        },
        "connection_reset": {
            "match": lambda err, ctx: "ConnectionReset" in err or "RemoteDisconnected" in err,
            "action": {"retry": 2, "backoff_ms": 400},
            "validation": {"benchmark": "local-fixture-v1", "regression": "all"},
        },
        "dns_failure": {
            "match": lambda err, ctx: "gaierror" in err or "Name or service" in err,
            "action": {"skip_endpoint": True, "quarantine_scanner": False},
            "validation": {"regression": "all"},
        },
    }

    def classify(self, error: str, ctx: dict) -> tuple[str, dict] | None:
        for name, rule in self.RULES.items():
            try:
                if rule["match"](error, ctx):
                    return name, rule
            except Exception:
                continue
        return None


class RepairGate:
    """spec 23/38: repair candidates are applied in an isolated copy, tested, benchmarked,
    compared, then accepted or rolled back. Never direct self-modification."""
    def __init__(self, bench_fn, regression_fn):
        self.bench_fn, self.regression_fn = bench_fn, regression_fn

    def attempt(self, failure_id: str, rule_name: str, action: dict, apply_fn, label: str = "") -> dict:
        result = {"failure_id": failure_id, "rule": rule_name, "label": label,
                  "steps": [], "accepted": False}
        for step, fn, ok_check in [
            ("apply_in_isolation", apply_fn, lambda r: r is True),
            ("regression_suite", self.regression_fn, lambda r: r.get("passed") is True),
            ("benchmark_compare", self.bench_fn, lambda r: r.get("acceptable") is True),
        ]:
            try:
                r = fn()
                ok = ok_check(r)
            except Exception as e:
                r, ok = {"error": str(e)}, False
            result["steps"].append({"step": step, "ok": ok, "detail": r if isinstance(r, dict) else r})
            if not ok:
                result["accepted"] = False
                result["rollback_reason"] = f"gate failed at: {step}"
                return result
        result["accepted"] = True
        return result

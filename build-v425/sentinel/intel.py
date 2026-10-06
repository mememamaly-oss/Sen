"""Phase 9: Verification Engine + Phase 12: Finding Intelligence (dedup/correlation/risk)
+ Phase 19: Strategy Store (deterministic, verified-outcomes-only learning)
+ Phase 20: Failure Memory + Phase 18: Repair Gate infrastructure.
"""
from __future__ import annotations
import json, math, os, time, hashlib
from .core import Endpoint, EventBus, Finding, FindingStatus, Severity, Verification, ParamKind
from .http_engine import RequestEngine, RequestMutation
from .detect import SQLiDetector, XSSDetector, TraversalDetector, passive_audit, SECURITY_HEADERS

# ---- VF-01 (v4.2.0) fail-closed verification defaults --------------------------
# The single-response presence classes: the ONLY finding types that may be
# VERIFIED without a replay. Extending this set is a deliberate, reviewable act.
_PRESENCE_VERIFIED_TYPES = frozenset({
    "missing_security_headers",     # absence proven by ONE response (no oracle exists)
    "server_banner_disclosure",     # the banner IS the response content
    "tech_banner_disclosure",       # ditto
    "vulnerable_js_dependency",     # the served asset name/version IS the observation
})


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
            # VF-03 (v4.2.0): the body-diff half used to fire on ANY >200B difference
            # with NO status agreement — a page with volatile content (rotating
            # lists, timestamps, ads) false-positives SQLi. The guard now mirrors
            # PATH D: both responses OK, SAME status, and the difference must
            # exceed max(200, 25% of the larger body).
            r1 = self._replay(ep, p, f"{base} AND 1=1")
            r2 = self._replay(ep, p, f"{base} AND 1=2")
            body_a, body_b = (r1.body or ""), (r2.body or "")
            stable = ((r1.ok and not r2.ok)
                      or (r1.ok and r2.ok and r1.status == r2.status
                          and abs(len(body_a) - len(body_b))
                              > max(200, 0.25 * max(len(body_a), len(body_b), 1))))
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
                        # PATH C' — DETECT-06 (v4.2.2, live-caught on demo.testfire.net/doLogin
                        # 2026-10-03): numeric-tautology OR pair with comment. Target drift
                        # neutralized the string-comparison shapes on doLogin while the numeric
                        # shape still bypassed; verification must replay the family that
                        # detection fired on — replaying string shapes only would REJECT a
                        # live vulnerability. Guards mirror PATH C/PATH A exactly.
                        r7 = self._replay(ep, p, f"{base}' OR 1=1-- ")
                        r8 = self._replay(ep, p, f"{base}' OR 1=2-- ")
                        l7, l8 = (r7.hop_location() if r7 else ""), (r8.hop_location() if r8 else "")
                        b7, b8 = (r7.body or "") if r7 else "", (r8.body or "") if r8 else ""
                        num_redirect = l7 and l8 and l7 != l8
                        num_body = (r7 is not None and r8 is not None and r7.ok and r8.ok
                                    and r7.status == r8.status
                                    and abs(len(b7) - len(b8)) > max(200, 0.25 * max(len(b7), len(b8), 1)))
                        if num_redirect or num_body:
                            note = (f"replay numeric-OR TRUE -> {l7}, FALSE -> {l8}" if num_redirect else
                                    f"fresh numeric-OR body differential: TRUE {len(b7)}B vs FALSE {len(b8)}B")
                            v = Verification(method="oracle:ornum-2round", passed=True, confidence=0.95, rounds=2,
                                             notes=note)
                            f.verification, f.confidence = v, v.confidence
                            f.status = FindingStatus.VERIFIED
                        else:
                            # PATH D2 — MAX-09 (maximum internal test, live-caught on
                            # Juice Shop 20.2.0 /rest/products/search?q=): paren-closing
                            # fresh OR pair. WHERE ((name LIKE '%q%' ...)) contexts only
                            # break out with ')) — the flat AND/OR pairs above stay
                            # literal LIKE terms (no differential) or die as unbalanced
                            # parens. Fresh comparison vectors keep this an INDEPENDENT
                            # replay; guards mirror PATH A/D exactly (both OK, same
                            # status, diff > max(200, 25%)).
                            r9 = self._replay(ep, p, f"{base}')) OR '2'>'1' -- ")
                            r10 = self._replay(ep, p, f"{base}')) OR '1'>'2' -- ")
                            if (r9 is not None and r10 is not None and r9.ok and r10.ok
                                    and r9.status == r10.status
                                    and abs(len(r9.body or "") - len(r10.body or ""))
                                    > max(200, 0.25 * max(len(r9.body or "x"), len(r10.body or "x"), 1))):
                                v = Verification(method="oracle:paren-or-bodydiff-2round",
                                                 passed=True, confidence=0.95, rounds=2,
                                                 notes=(f"fresh paren-closing OR body differential: "
                                                        f"TRUE {len(r9.body)}B vs FALSE {len(r10.body)}B"))
                                f.verification, f.confidence = v, v.confidence
                                f.status = FindingStatus.VERIFIED
                            else:
                                # PATH E — OWSP-16: no-base OR existence-flip replay
                                # (boolean-blind lookup pages: DVWA /sqli_blind/ answers
                                # 200 'exists' vs 404 'MISSING' when the tautology flips).
                                # Fresh comparison vectors (not the detection tautologies):
                                # '2'>'1' TRUE vs '1'>'2' FALSE — an independent replay in
                                # the BR-01 spirit. Guards mirror the detector exactly:
                                # base OK, TRUE OK, FALSE NOT OK.
                                rbE = self._replay(ep, p, base)
                                re1 = self._replay(ep, p, "' OR '2'>'1' -- ")
                                re2 = self._replay(ep, p, "' OR '1'>'2' -- ")
                                if (rbE is not None and re1 is not None and re2 is not None
                                        and rbE.ok and re1.ok and not re2.ok):
                                    v = Verification(method="oracle:existence-flip-2round",
                                                     passed=True, confidence=0.9, rounds=3,
                                                     notes=(f"no-base OR existence flip: base {rbE.status}, "
                                                            f"TRUE {re1.status} ({len(re1.body or '')}B), "
                                                            f"FALSE {re2.status} ({len(re2.body or '')}B)"))
                                    f.verification, f.confidence = v, v.confidence
                                    f.status = FindingStatus.VERIFIED
                                else:
                                    # PATH B — error-based replay (v4.2.3, VF-04 precision
                                    # tightening): the quote replay must reproduce an actual
                                    # DB ERROR STRING. Until v4.2.2 a BARE 5xx counted as
                                    # "error reproduction" — that verified testasp
                                    # Search.asp/Login.asp (tfSearch/tfUName/tfUPass) as
                                    # CRITICAL SQLi on a generic IIS 500 with NO SQL text
                                    # and NO boolean differential (IV13/IV14 comparison
                                    # flagged it; the notes even claimed "reproduce DB
                                    # error" while the evidence said 'no DB string'). A
                                    # status-only signal (DETECT-04) remains a CANDIDATE —
                                    # visible and honest, but never VERIFIED. Endpoints that
                                    # carry a real oracle still verify through PATH A/D/C/C'.
                                    from .detect import SQL_ERR_PATTERNS
                                    import re as _re
                                    alt_quot = base + '"' if "'" in str(f.evidence) else base + "'"
                                    r3 = self._replay(ep, p, base + '"')
                                    r4 = self._replay(ep, p, base + "'")
                                    err_hit = None
                                    for r in (r3, r4):
                                        if r is None or not r.status:
                                            continue
                                        for pat in SQL_ERR_PATTERNS:
                                            mm = pat.search(r.body or "")
                                            if mm:
                                                err_hit = f"{pat.pattern[:40]} matched: {mm.group(0)[:60]}"
                                                break
                                        if err_hit:
                                            break
                                    err_repro = err_hit is not None
                                    v = Verification(method="error:replay-2variants", passed=err_repro,
                                                     confidence=0.9 if err_repro else 0.15, rounds=2,
                                                     notes=(f"quote variants reproduce a DB error string: {err_repro}"
                                                            + (f" [{err_hit}]" if err_hit else "")))
                                    f.verification, f.confidence = v, v.confidence
                                    f.status = FindingStatus.VERIFIED if err_repro else FindingStatus.REJECTED

        elif f.type == "xss_reflected":
            # VR-02 fix (2026-09-27, live-caught on demo.testfire.net): a single fixed
            # variant payload (<img onerror>) let pattern-blacklist WAFs veto genuinely
            # exploitable reflections (FN). Deterministic fix: VECTOR DIVERSITY — a
            # battery of event-handler-distinct probes; verified if ANY reflects raw,
            # confidence scaled by how many independent contexts confirmed.
            # DETECT-14 (Phase 54): the battery is CONTEXT-AWARE — attribute-injection
            # candidates (tag-filtered contexts) are re-verified with no-'<' vectors,
            # Angular-expression candidates with a fresh {{expression}}, so a filter
            # that blocks every tag can no longer veto the very class it produced.
            kinds = {e.kind for e in (f.evidence or [])}
            if "attribute_injection_reflection" in kinds:
                variants = ['pro44" onfocus="vr1', 'pro45" onload="vr2', "pro46' onerror='vr3"]
                passed_vecs = 0
                for alt in variants:
                    r = self._replay(ep, f.parameter, "sentinelxssmarker" + alt)
                    if r is not None and ("sentinelxssmarker" + alt) in (r.body or ""):
                        passed_vecs += 1
                executed_ctx = passed_vecs >= 1
                conf = 0.9 if passed_vecs >= 2 else (0.8 if passed_vecs == 1 else 0.1)
                v = Verification(method="re-test:attr-battery-3", passed=executed_ctx,
                                 confidence=conf, rounds=len(variants),
                                 notes=f"{passed_vecs}/{len(variants)} attribute-injection vectors "
                                       "reflected raw (no '<' — tag-filter resistant verification)")
            elif "ng_expression_reflection" in kinds:
                # VR-14 (v4.2.3, live-caught on ginandjuice.shop /catalog?searchTerm):
                # the fresh {{expression}} must land in a BINDING context — reflected
                # raw AND outside <script>/<style> content. AngularJS never
                # interpolates script/style element content, so a script-string
                # reflection is not client-side evaluation (IV14 adjudicated the
                # searchTerm claim as this exact false positive: {{91*7}} raw inside
                # `var searchText = '...'` while every breakout was neutralized).
                from .detect import in_script_or_style
                fresh = "{{19*3}}sentinelngvr"
                r = self._replay(ep, f.parameter, fresh)
                body = (r.body or "") if r is not None else ""
                i = body.find(fresh)
                executed_ctx = (r is not None and i >= 0 and "ng-app" in body.lower()
                                and not in_script_or_style(body, i))
                v = Verification(method="re-test:fresh-ng-expression", passed=executed_ctx,
                                 confidence=0.85 if executed_ctx else 0.1, rounds=1,
                                 notes=f"fresh Angular expression reflected raw in a BINDING context "
                                       f"(outside script/style) on an ng-app page: {executed_ctx}")
            else:
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

        elif f.type == "xss_stored":
            # DETECT-16 (v4.2.3) verification: full re-execution with a FRESH canary.
            # The detection flow (fresh form fetch -> canary submit -> render surfaces
            # with persistence control) runs AGAIN end-to-end; the fresh marker must
            # persist raw on at least one recorded surface. Never a replay of the
            # detection request — a stored reflection must be reproducible from a
            # clean submit.
            from .detect import stored_xss_flow, StoredXSSDetector
            surfaces = None
            for e in (f.evidence or []):
                if e.kind == "stored_xss_surfaces" and e.detail.startswith("render surfaces: "):
                    surfaces = [s.strip() for s in e.detail[len("render surfaces: "):].split("|")]
            origin_url = StoredXSSDetector._origin_of(ep) if ep is not None else f.endpoint_url
            fresh_canary = "<sentinelstvr2>"
            _o, _s, hits = stored_xss_flow(self.engine, ep, f.parameter, fresh_canary,
                                           origin_url, surfaces=surfaces)
            hit = len(hits) > 0
            v = Verification(method="re-test:fresh-canary-resubmit", passed=hit,
                             confidence=0.9 if hit else 0.15, rounds=2,
                             notes=(f"fresh canary re-submitted via the real form persisted raw on "
                                    f"{hits[0][0]}" if hit else "fresh canary did not persist on any render surface"))
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if hit else FindingStatus.REJECTED

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
            # DETECT-17 (v4.2.3): path-based traversal findings (no parameter — the
            # URL itself carries the payload). Verification = fresh GET of the exact
            # traversal URL; the file marker must appear again. Param-based findings
            # keep the alt-depth replay below.
            kinds = {e.kind for e in (f.evidence or [])}
            if "path_file_marker" in kinds:
                r = self.engine.send(RequestMutation(endpoint=Endpoint(url=f.endpoint_url),
                                                     note="path-trav-verify"))
                from .detect import TraversalDetector as _TD
                body = (r.body or "") if (r is not None and r.status) else ""
                hit = bool(r is not None and r.status and not r.error) \
                      and any(m in body for m, _ in _TD.MARKERS)
                v = Verification(method="re-test:same-path-marker", passed=hit,
                                 confidence=0.9 if hit else 0.15, rounds=1,
                                 notes=f"fresh GET of the traversal URL reproduces the file marker: {hit}")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if hit else FindingStatus.REJECTED
                return f
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
                from .detect import XxeDetector, is_self_callback
                xd = XxeDetector(self.engine, self.bus)
                fields = [(p.name, p.value or "1") for p in ep.parameters] if ep else []
                iid = xd._oob_iid(ep, elem, "verify")
                xml = xd._xml(root, fields, self.oast.url(iid), elem)
                rv = self.engine.send(RequestMutation(
                    endpoint=ep, body_override=xml, method="POST",
                    extra_headers={"Content-Type": "application/xml"}))
                hit = self.oast.poll(iid, timeout=2.0) if not rv.error else None
                if hit and is_self_callback(hit, rv, self.oast.url(iid)):
                    hit = None                         # ENG-08: scanner-initiated fetch
                ok = hit is not None
                # Phase 52 (VR-08): attribution on the verify replay too — the fresh
                # interaction must come back and, on public channels, its source IP
                # is recorded in the verification notes (auditable evidence chain).
                src = ""
                if ok:
                    src = hit[0].get("ip") or ""
                    src = f" src={src}" if src else ""
                v = Verification(method="re-test:fresh-interaction-id", passed=ok,
                                 confidence=0.9 if ok else 0.15, rounds=1,
                                 notes=f"fresh interaction id {iid} fetched out-of-band: {ok}"
                                       f"{src} channel={getattr(self.oast, 'channel', 'local')}")
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

        elif f.type == "ssrf" and any(e.kind == "oob_callback" for e in f.evidence) and self.oast is not None:
            # VR-09 (Phase 53): independent replay with a FRESH interaction id — the
            # first callback proved the app fetches attacker URLs server-side; the
            # second, never-used id proves reproducibility (same channel discipline
            # as VR-07 blind XXE).
            import re as _re9
            ev9 = " ".join(e.detail for e in f.evidence)
            m9 = _re9.search(r"param=([\w.-]+)", ev9)
            param9 = m9.group(1) if m9 else (f.parameter or "url")
            from .detect import SsrfDetector, is_self_callback
            sd = SsrfDetector(self.engine, self.bus)
            iid = sd._iid(ep, param9, "verify")
            rv = self.engine.send(RequestMutation(endpoint=ep, param_name=param9,
                                                  param_value=self.oast.url(iid), note="ssrf-verify"))
            hit = self.oast.poll(iid, timeout=2.0) if (rv is not None and not rv.error) else None
            if hit and is_self_callback(hit, rv, self.oast.url(iid)):
                hit = None                             # ENG-08: scanner-initiated fetch
            ok = hit is not None
            src9 = hit[0].get("ip", "") if hit else ""
            v = Verification(method="re-test:fresh-interaction-id", passed=ok,
                             confidence=0.9 if ok else 0.15, rounds=1,
                             notes=f"fresh interaction id {iid} fetched out-of-band: {ok}"
                                   f"{' src=' + src9 if src9 else ''}"
                                   f" channel={getattr(self.oast, 'channel', 'local')}")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok else FindingStatus.REJECTED

        elif f.type == "command_injection" and any(e.kind == "oob_callback" for e in f.evidence) and self.oast is not None:
            # VR-11 (Phase 53): fresh interaction id + DIFFERENT shell syntax ('|' vs
            # the ';' / '&&' detection battery) — execution must reproduce through an
            # independent separator to be a finding.
            import re as _re11
            ev11 = " ".join(e.detail for e in f.evidence)
            m11 = _re11.search(r"param=([\w.-]+)", ev11)
            param11 = m11.group(1) if m11 else (f.parameter or "host")
            base11 = "localhost"
            if ep is not None and ep.param(param11) is not None and ep.param(param11).value:
                base11 = ep.param(param11).value[:60]
            from .detect import CommandInjectionDetector, is_self_callback
            cd = CommandInjectionDetector(self.engine, self.bus)
            iid = cd._iid(ep, param11, "verify")
            payload = base11 + cd.VERIFY_TEMPLATE.format(u=self.oast.url(iid))
            rv = self.engine.send(RequestMutation(endpoint=ep, param_name=param11,
                                                  param_value=payload, note="cmdi-verify"))
            hit = self.oast.poll(iid, timeout=2.0) if (rv is not None and not rv.error) else None
            if hit and is_self_callback(hit, rv, self.oast.url(iid)):
                hit = None                             # ENG-08: scanner-initiated fetch
            ok = hit is not None
            src11 = hit[0].get("ip", "") if hit else ""
            v = Verification(method="re-test:fresh-interaction-id+alternate-syntax", passed=ok,
                             confidence=0.9 if ok else 0.15, rounds=1,
                             notes=f"fresh id {iid} via alternate '|' syntax executed out-of-band: {ok}"
                                   f"{' src=' + src11 if src11 else ''}"
                                   f" channel={getattr(self.oast, 'channel', 'local')}")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok else FindingStatus.REJECTED

        elif f.type == "cors_misconfig":
            # VR-10 (Phase 53): replay with a FRESH Origin value — arbitrary-origin
            # reflection WITH credentials must repeat on a never-probed origin.
            import hashlib as _hb10
            fresh = "https://cors-vr10-" + _hb10.sha1(f.endpoint_url.encode()).hexdigest()[:8] + ".example"
            r10 = self.engine.send(RequestMutation(endpoint=ep, note="cors-verify",
                                                   extra_headers={"Origin": fresh}))
            ok10 = False
            acao10 = ""
            if r10 is not None and not r10.error:
                acao10 = (r10.headers or {}).get("access-control-allow-origin", "")
                acac10 = (r10.headers or {}).get("access-control-allow-credentials", "")
                ok10 = fresh in acao10 and acac10.strip().lower() == "true"
            v = Verification(method="re-test:fresh-origin", passed=ok10,
                             confidence=0.9 if ok10 else 0.15, rounds=1,
                             notes=f"fresh origin {fresh} reflected with credentials: {ok10} "
                                   f"(acao={acao10[:60]!r})")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok10 else FindingStatus.REJECTED

        elif f.type == "ssti":
            # VR-12 (Phase 55): re-test the SAME syntax family with FRESH operands
            # (12*11 -> 132) — ambient "49"s cannot reproduce a fresh computation.
            import re as _re12
            ev12 = " ".join(e.detail for e in f.evidence)
            m12 = _re12.search(r"syntax=(\S+)", ev12)
            fam = m12.group(1) if m12 else "{{"
            _FAMS = {"{{": ("{{", "}}"), "${": ("${", "}"),
                     "<%=": ("<%= ", " %>"), "#{": ("#{", "}")}
            open_, close = _FAMS.get(fam, ("{{", "}}"))
            fresh = f"{open_}12*11{close}"
            expect = "132"
            r12 = self.engine.send(RequestMutation(endpoint=ep, param_name=f.parameter,
                                                   param_value=fresh, note="ssti-verify"))
            ok12 = False
            if r12 is not None and not r12.error and r12.ok:
                body12 = r12.body or ""
                ok12 = expect in body12 and fresh not in body12
            v = Verification(method="re-test:fresh-expression", passed=ok12,
                             confidence=0.9 if ok12 else 0.15, rounds=1,
                             notes=f"fresh expression {fresh!r} -> {expect} evaluated: {ok12}")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok12 else FindingStatus.REJECTED

        elif f.type == "csrf":
            # VR-13 (v4.2.0 VF-02): the old oracle was `r.ok` — a bare HTTP 2xx
            # from a fresh hostile origin. That proves nothing about CSRF: it
            # never checked that the state-changing request DISCRIMINATES input
            # (a blanket-200 endpoint passes it vacuously). The oracle is now a
            # triple control:
            #   (1) same-origin baseline replay must be accepted (the request
            #       is state-changing and succeeds for the app's own origin),
            #   (2) a FRESH hostile Origin+Referer replay must be accepted with
            #       the SAME status and a similar body (cross-origin acceptance
            #       — the CSRF essence — for a never-probed origin),
            #   (3) a malformed-input control must be REJECTED (the endpoint
            #       validates input, so the 2xx is a real acceptance not blanket).
            # Reproduction failure -> REJECTED; reproduction WITHOUT input
            # discrimination -> CANDIDATE (plausible, unproven — never VERIFIED).
            import hashlib as _hb13
            fresh13 = "https://csrf-vr13-" + _hb13.sha1(f.endpoint_url.encode()).hexdigest()[:8] + ".example"
            r_base = self.engine.send(RequestMutation(endpoint=ep, note="csrf-verify-baseline"))
            r13 = self.engine.send(RequestMutation(endpoint=ep, note="csrf-verify",
                                                   extra_headers={"Origin": fresh13,
                                                                  "Referer": fresh13 + "/x"}))
            mut_p = next((p.name for p in ep.parameters
                          if p.kind != ParamKind.TOKEN), "") if ep is not None else ""
            r_ctrl = (self.engine.send(RequestMutation(endpoint=ep, param_name=mut_p,
                                                      param_value="", note="csrf-verify-control"))
                      if (ep is not None and mut_p) else None)
            ok13 = similar13 = False
            if r_base is not None and r13 is not None and not r_base.error and not r13.error:
                ok13 = r_base.ok and r13.ok and r13.status == r_base.status
                similar13 = abs(len(r13.body or "") - len(r_base.body or "")) \
                    <= max(150, 0.25 * max(len(r_base.body or "x"), 1))
            discriminating = (r_ctrl is None) or \
                (not r_ctrl.ok or r_ctrl.status != (r_base.status if r_base is not None else 0))
            if ok13 and similar13 and discriminating and mut_p:
                v = Verification(method="re-test:fresh-hostile-origin", passed=True,
                                 confidence=0.85, rounds=3,
                                 notes=f"cross-origin replay from {fresh13} accepted "
                                       f"(baseline {r_base.status}, replay {r13.status}); malformed "
                                       f"control rejected ({r_ctrl.status}) — tokenless state-changing "
                                       f"request is cross-origin accepted AND input-discriminating")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED
            elif ok13 and similar13:
                # reproduced acceptance, but the endpoint does not discriminate
                # malformed input: the 2xx cannot be attributed to a real state
                # change — honest CANDIDATE, never VERIFIED on this oracle.
                v = Verification(method="unverified:no-input-discrimination", passed=False,
                                 confidence=0.3, rounds=3,
                                 notes=f"cross-origin replay from {fresh13} accepted "
                                       f"(baseline {r_base.status}, replay {r13.status}) BUT the "
                                       f"malformed control was also accepted "
                                       f"({r_ctrl.status if r_ctrl is not None else 'n/a'}) — "
                                       "a blanket-2xx endpoint cannot prove a state change; "
                                       "CSRF plausible, unproven")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.CANDIDATE
            else:
                v = Verification(method="re-test:fresh-hostile-origin", passed=False,
                                 confidence=0.15, rounds=3,
                                 notes=f"cross-origin replay from {fresh13} did not reproduce "
                                       f"the same-origin baseline (baseline "
                                       f"{getattr(r_base, 'status', 0)}, replay "
                                       f"{getattr(r13, 'status', 0)})")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.REJECTED

        elif f.type == "unrestricted_file_upload":
            # VR-20 (OWSP-18, live-caught on DVWA 3.x /vulnerabilities/upload/):
            # verification by re-execution with a FRESH canary — re-upload a
            # benign sentinel .txt through the same multipart shape, require the
            # filename echoed (acceptance) AND the file fetched back with the
            # fresh canary content intact (servability). Both rounds must carry
            # their own canary; a stale echo proves nothing.
            import hashlib as _hb20
            from .detect import UploadDetector
            f20 = next((p for p in (ep.parameters if ep is not None else [])
                        if getattr(p, "is_file", False)), None)
            if f20 is not None:
                canary20 = "v" + _hb20.sha1((f.id + "|vr20").encode()).hexdigest()[:9]
                ud = UploadDetector(self.engine, self.bus)
                f20b = ud._probe(ep, f20, canary=canary20)
                served20 = any(e.kind == "upload_served" for e in (f20b.evidence if f20b else []))
                accepted20 = f20b is not None
                ok20 = accepted20 and served20
                v = Verification(method="upload:fresh-canary-replay", passed=ok20,
                                 confidence=0.9 if ok20 else 0.15, rounds=2,
                                 notes=(f"fresh canary {canary20}: accepted={accepted20}, "
                                        f"served-with-content={served20}"))
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if ok20 else FindingStatus.REJECTED
            else:
                v = Verification(method="unverified:no-file-param", passed=False,
                                 confidence=0.1, rounds=0,
                                 notes="file param not found on the endpoint at verification time")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.REJECTED

        elif f.type == "nosql_injection":
            # VR-14 (v4.2.0 VF-02): the old oracle was `r.ok` on a single $gt
            # request — an endpoint answering 2xx to ANY body passed it vacuously.
            # The oracle is now a REPRODUCED FLIP: a fresh literal-credential
            # baseline must be REJECTED (4xx), then a FRESH operator ($gt,
            # independent of the detector's $ne) must flip the very same request
            # to ACCEPTED. The failure->success flip IS the injection mechanism;
            # reproducing it through a second operator is the proof.
            from .detect import NosqlDetector
            carrier14 = f.parameter or (next((p.name for p in ep.parameters
                                              if p.kind != ParamKind.TOKEN), "")
                                         if ep is not None else "")
            if ep is None or not carrier14:
                v = Verification(method="re-test:fresh-operator", passed=False,
                                 confidence=0.15, rounds=1,
                                 notes="no carrier parameter observable — cannot re-test")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.REJECTED
            else:
                r_base = self.engine.send(RequestMutation(
                    endpoint=ep, note="nosql-verify-baseline",
                    body_override=NosqlDetector._json_body(ep, carrier14, "sentinel-vr14-wrong")))
                r_op = self.engine.send(RequestMutation(
                    endpoint=ep, note="nosql-verify",
                    body_override=NosqlDetector._json_body(ep, carrier14, {"$gt": ""})))
                base_rejected = (r_base is not None and not r_base.error and not r_base.ok)
                op_accepted = (r_op is not None and not r_op.error and r_op.ok)
                flip = base_rejected and op_accepted
                v = Verification(
                    method="re-test:fresh-operator", passed=flip,
                    confidence=0.9 if flip else 0.15, rounds=2,
                    notes=(f"literal credentials rejected (HTTP {r_base.status}), fresh $gt "
                           f"operator accepted (HTTP {r_op.status}) — the operator bypass "
                           "reproduces through an independent operator (failure->success flip)"
                           if flip else
                           f"flip not reproduced: literal baseline "
                           + ("rejected" if base_rejected else
                              f"ACCEPTED (HTTP {getattr(r_base, 'status', 0)})")
                           + f", $gt probe "
                           + ("accepted" if op_accepted else
                              f"rejected (HTTP {getattr(r_op, 'status', 0)})")))
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if flip else FindingStatus.REJECTED

        elif f.type == "jwt_security":
            # VR-15 (Phase 55): fresh benign replay must issue another alg=none
            # token — reproducible unsigned issuance, not a one-off accident.
            from .detect import JwtDetector
            r15 = self.engine.send(RequestMutation(endpoint=ep, note="jwt-verify"))
            ok15 = False
            alg15 = ""
            if r15 is not None and not r15.error and r15.status:
                hay15 = (r15.body or "") + " ".join(f"{k}={v}" for k, v in (r15.headers or {}).items()
                                                    if k.lower() == "set-cookie")
                m15 = JwtDetector.TOKEN_RE.search(hay15)
                if m15:
                    hdr15 = JwtDetector._decode(m15.group(0).split(".")[0])
                    alg15 = str(hdr15.get("alg", "")).lower()
                    ok15 = alg15 == "none" and not m15.group(1)
            v = Verification(method="re-test:fresh-issuance", passed=ok15,
                             confidence=0.85 if ok15 else 0.15, rounds=1,
                             notes=f"fresh replay issued another unsigned token (alg={alg15!r}): {ok15}")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok15 else FindingStatus.REJECTED

        elif f.type == "host_header_injection":
            # VR-16 (Phase 55): FRESH canary Host — reflection must repeat for a
            # never-probed host value.
            import hashlib as _hb16
            fresh16 = "sentinel-vr16-" + _hb16.sha1(f.endpoint_url.encode()).hexdigest()[:10] + ".example"
            r16 = self.engine.send(RequestMutation(endpoint=ep, note="hostheader-verify",
                                                   extra_headers={"Host": fresh16}))
            ok16 = False
            if r16 is not None and not r16.error and r16.status:
                ok16 = fresh16 in (r16.body or "") or any(fresh16 in str(hv)
                                                          for hv in (r16.headers or {}).values())
            v = Verification(method="re-test:fresh-canary-host", passed=ok16,
                             confidence=0.85 if ok16 else 0.15, rounds=1,
                             notes=f"fresh canary host {fresh16} reflected: {ok16}")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok16 else FindingStatus.REJECTED

        elif f.type == "credential_exposure":
            # VR-19 (Phase 56): a FRESH fetch of the endpoint must re-expose the
            # SAME credential class — reproducible exposure, not a one-off
            # accident (e.g. a transient error page that happened to contain a
            # key-shaped string).
            from .secrets import SecretsScanner
            r19 = self.engine.send(RequestMutation(endpoint=ep, note="secrets-verify"))
            ok19 = False
            if r19 is not None and not r19.error and r19.status:
                for cand in SecretsScanner().scan(ep, r19):
                    if cand.parameter == f.parameter:      # same credential class
                        ok19 = True
                        break
            v = Verification(method="re-test:fresh-fetch-reexposure", passed=ok19,
                             confidence=0.9 if ok19 else 0.15, rounds=1,
                             notes=f"fresh fetch re-exposed credential class "
                                   f"{f.parameter!r}: {ok19}")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok19 else FindingStatus.REJECTED

        elif f.type in _PRESENCE_VERIFIED_TYPES:
            # VF-01 (v4.2.0): explicit allowlist — the ONLY types that may be
            # VERIFIED without a replay. Single-response presence IS the whole
            # evidence class for these (a missing header cannot be "replayed"
            # into existence). Confidence is drastically lowered from the old
            # 0.98 — which was the HIGHEST in the engine, above every replayed
            # class — to 0.70, far below every replay-verified class.
            v = Verification(method="single-response-evidence", passed=True, confidence=0.70, rounds=1,
                             notes="presence-based proof (weakest evidence class in the engine): "
                                   "established from ONE response — no replay oracle exists "
                                   "for this class by nature")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED
        elif f.type in ("ssrf", "command_injection"):
            # VF-02 (v4.2.0) fail-closed: blind classes whose ONLY proof channel is
            # out-of-band. Without an OOB callback + armed OAST there is NO response
            # oracle (a 200/latency differential is ambient noise, live-observed) —
            # these are NEVER response-verified. The old code let them fall into
            # the catch-all else and stamped VERIFIED 0.98 with zero proof.
            v = Verification(method="unverified:blind-class-no-oob", passed=False, confidence=0.3, rounds=0,
                             notes=f"{f.type} is a blind class: no oob_callback evidence and no "
                                   "armed OAST channel — no proof exists; recorded as unverified "
                                   "candidate (VERIFIED requires an out-of-band confirmation)")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.CANDIDATE
        else:
            # VF-01 (v4.2.0): the old catch-all stamped passed=True confidence=0.98
            # for ANY unlisted type — a fail-open default. The default is now
            # FAIL-CLOSED: unknown types are CANDIDATE; VERIFIED requires an
            # explicit branch. Adding a type = a deliberate, reviewable act.
            v = Verification(method="unverified:no-branch", passed=False, confidence=0.3, rounds=0,
                             notes=f"no verification branch for type {f.type!r} — recorded as "
                                   "unverified candidate; add an explicit branch to have this "
                                   "type verified (fail-closed default)")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.CANDIDATE

        self.bus.emit("VerificationCompleted", finding=f.id, type=f.type,
                      passed=f.verification.passed if f.verification else False,
                      status=f.status.value, confidence=f.confidence)
        return f


# ============================================================ FINDING PIPELINE (Phase 12)
RISK_WEIGHTS = {"sql_injection": 9, "xss_reflected": 7, "xss_dom": 7, "path_traversal": 7, "xxe": 9,
                "command_injection": 9, "ssrf": 7, "cors_misconfig": 6,
                "ssti": 9, "nosql_injection": 9, "csrf": 5, "jwt_security": 5,
                "host_header_injection": 5,
                "idor_bola": 8, "vertical_privilege_escalation": 9,
                "credential_exposure": 8,
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

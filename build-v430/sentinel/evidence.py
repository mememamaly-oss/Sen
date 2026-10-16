"""SENTINEL v2.8.0 — Evidence Graph & Impact Assessment (Phase 56).

Every verified finding already carries its raw evidence chain and its
verification record. This module turns those parts into two professional
artifacts:

  1. IMPACT PROOF — a per-class statement of what the vulnerability lets an
     attacker DO, with the grade:
       * "proven"      — the scan demonstrated the impact itself, safely
                         (differential oracles, OOB callbacks, marker reads).
       * "indicated"   — the defect is confirmed but impact was not directly
                         exercised (banner/passive classes).
     The statements are class-accurate and NON-DESTRUCTIVE by construction:
     SENTINEL proves capability (a boolean oracle flips, a callback arrives,
     a computed value appears, a victim's marker is readable) without ever
     extracting real data, writing state, or executing destructive payloads.

  2. CHAIN OF CUSTODY — an ordered, auditable chain from detection to proof:
     request -> evidence -> verification -> impact. The chain rides every
     finding dict (additive "impact" key), so a report reader can walk from
     the vulnerability to exactly what proved it.
"""
from __future__ import annotations

# type -> (grade, impact statement). Statements describe demonstrated
# capability, phrased for report consumers (not payload recipes).
IMPACT_PROFILES: dict[str, tuple[str, str]] = {
    "sql_injection":
        ("proven", "Attacker influence over query evaluation proven by a "
         "non-destructive boolean differential (AND 1=1 vs AND 1=2 yield "
         "different application behavior) — a read-capable oracle. Data was "
         "never extracted; the capability was demonstrated, not exercised."),
    "xss_reflected":
        ("proven", "Arbitrary attacker-supplied markup/JavaScript survives "
         "into the response in an executable context (canary proven) — "
         "session theft, credential capture and action forgery in the victim's "
         "browser are reachable without further preconditions."),
    "xss_dom":
        ("proven", "Attacker-controlled data reaches a dangerous DOM sink and "
         "EXECUTES in a real browser (execution probe fired) — client-side "
         "code execution in victims' sessions."),
    "path_traversal":
        ("proven", "File reads outside the document root proven with a "
         "marker file — arbitrary local file disclosure (configuration, "
         "secrets, source) is reachable."),
    "xxe":
        ("proven", "External entity resolution proven (file content reached "
         "the response, or an out-of-band fetch arrived from the target's own "
         "infrastructure) — local file disclosure and SSRF-via-parser."),
    "ssrf":
        ("proven", "The server made an outbound request to an attacker-chosen "
         "URL, proven by an out-of-band callback from the target's "
         "infrastructure — internal service/metadata access is reachable."),
    "command_injection":
        ("proven", "Operating-system command execution proven by a "
         "non-destructive out-of-band callback fired from the target host "
         "(chained network fetch) — full host-level impact."),
    "ssti":
        ("proven", "Server-side template EVALUATION proven: a fresh "
         "arithmetic expression was computed by the target (49/132-style "
         "oracle) — template-engine code execution context."),
    "code_injection":
        ("proven", "Server-side code EVALUATION proven (V4.3.2, WS message "
         "battery): a fresh arithmetic expression was computed by the "
         "target's eval/code path (42-style oracle, reproduced on a fresh "
         "connection) — application-language code execution context."),
    "graphql_field_suggestions":
        ("indicated", "Schema vocabulary leak: a near-miss field name "
         "answers 'Did you mean <field>?' — the GraphQL API discloses its "
         "field names through error suggestions even when introspection is "
         "disabled (V4.3.3, DVGA solution #8)."),
    "nosql_injection":
        ("proven", "Query operator injection proven: an attacker-supplied "
         "$operator object flipped an authentication rejection into "
         "acceptance — authentication bypass."),
    "csrf":
        ("proven", "A state-changing request from a hostile origin was "
         "accepted exactly like a same-origin one (fresh-origin replay) — "
         "silent cross-site action forgery against authenticated users."),
    "jwt_security":
        ("proven", "Unsigned token issuance (alg=none, empty signature) "
         "reproduced on a fresh request — any party can forge arbitrary "
         "claims if the verifier honors the declared algorithm."),
    "host_header_injection":
        ("proven", "An attacker-controlled Host header value is reflected "
         "into application output (fresh canary host) — password-reset "
         "poisoning and cache-poisoning preconditions."),
    "idor_bola":
        ("proven", "Object-level access control broken: a low-privilege "
         "session retrieved ANOTHER account's private data (victim marker "
         "present in the attacker's response, reproduced with a fresh "
         "victim) — cross-user data exposure."),
    "vertical_privilege_escalation":
        ("proven", "Role boundary broken: a low-privilege session received "
         "the privileged (admin-only) view of a protected surface, "
         "reproduced on a fresh replay — full administrative capability "
         "reachable without the privileged role."),
    "business_logic_step_bypass":
        ("proven", "Business-process order broken: a later step of a learned "
         "multi-step flow created its object although the mandatory "
         "predecessor step never ran (state-oracle proof) — the process "
         "sequence is not enforced server-side."),
    "business_logic_out_of_order":
        ("proven", "Business-process order broken: the FINAL step of a "
         "learned flow EXECUTED a resource that was never created (implicit "
         "creation from request parameters, state-oracle proof) — the "
         "producing step can be skipped entirely."),
    "business_logic_value_tamper":
        ("proven", "Approval binding broken: a value approved at creation "
         "time was REPLACED at execution time (tampered canary visible in "
         "the executed state-oracle record) — execution re-trusts request "
         "data instead of the approved record."),
    "business_logic_duplicate_execution":
        ("proven", "Idempotency broken: replaying the final step of a "
         "learned flow executed the same resource TWICE (state-oracle "
         "occurrence proof) — repeat-submission double-spend class."),
    "business_logic_privilege_escalation":
        ("proven", "Declared privilege not enforced: an option the UI itself "
         "labels privileged ('admin only') was EXECUTED by a lower-privilege "
         "session (state-oracle proof) — the workflow privilege boundary "
         "exists only in the interface, not on the server."),
    "business_logic_cross_user_execution":
        ("proven", "Object ownership not enforced: an identity executed a "
         "workflow object MINTED BY A DIFFERENT identity (state-oracle proof "
         "with the owner's canary visible in the executing identity's result) "
         "— cross-user action forgery inside the business process."),
    "business_logic_cross_object_execution":
        ("proven", "Object boundary not enforced: a workflow step EXECUTED an "
         "object produced by a different flow/context (state-oracle proof) — "
         "type/context confusion lets one process consume another's objects."),
    "business_logic_cross_state_execution":
        ("proven", "State machine not enforced: a workflow object in a "
         "CANCELLED/REJECTED state was EXECUTED anyway (state-oracle proof) — "
         "rollback/cancel paths do not protect the object from execution."),
    "business_logic_branch_bypass":
        ("proven", "Branch condition not enforced: a conditional branch of a "
         "learned flow (option the UI gates behind an earlier step) was "
         "ENTERED by forging the branch value into a later step's hidden "
         "field on a session that never ran the condition step (state-oracle "
         "proof) — the branch exists only in the interface, not on the server."),
    "business_logic_unauthorized_branch":
        ("proven", "Declared membership restriction not enforced: a branch "
         "the UI labels restricted ('premium/verified members only') was "
         "EXECUTED by a lower-privilege session (state-oracle proof) — the "
         "restriction boundary exists only in the interface, not on the server."),
    "business_logic_approval_bypass":
        ("proven", "Approval gate not enforced: a workflow object was "
         "EXECUTED while its approving step never ran (state-oracle proof "
         "with the never-approved state captured before the attack) — "
         "maker-checker separation exists only in the interface."),
    "business_logic_rollback_abuse":
        ("proven", "Rollback reopens approved values: a rolled-back workflow "
         "object was EXECUTED with a NEW value replacing the approved one "
         "(state-oracle proof with the tampered canary in the executed "
         "record) — rollback silently undoes approval binding."),
    "credential_exposure":
        ("proven", "Secret credential material is exposed in a response and "
         "the exposure reproduced on a fresh fetch — direct account/infrastructure "
         "compromise potential (values masked in all reports by design)."),
    "cors_misconfig":
        ("proven", "Arbitrary origins are reflected with credentials allowed "
         "(fresh-origin replay) — any website can read authenticated "
         "cross-origin responses in the victim's browser."),
    "open_redirect":
        ("proven", "Unvalidated redirect to an attacker-controlled "
         "destination (fresh target replay) — phishing/trust laundering."),
    "http_response_header_injection":
        ("proven", "Attacker input reaches a response header (CRLF shape) — "
         "header injection into proxies/browsers."),
    "missing_security_headers":
        ("indicated", "Protective headers absent — defense-in-depth gap "
         "(no browser-enforced XSS/clickjacking/framing protections)."),
    "server_banner_disclosure":
        ("indicated", "Server software version disclosed — reconnaissance aid."),
    "tech_banner_disclosure":
        ("indicated", "Technology stack disclosed — reconnaissance aid."),
    "vulnerable_js_dependency":
        ("indicated", "End-of-life client-side dependency served — known "
         "advisory class applies to every client."),
    "header_injection":
        ("proven", "Attacker input reaches response headers — injection into "
         "intermediaries and browsers."),
    # ---- v4.1.0 GraphQL classes + v4.1.1 gap-validation additions
    "graphql_introspection_enabled":
        ("indicated", "The full GraphQL schema is readable by any client — "
         "the application's complete API surface (queries, mutations, "
         "arguments, sensitive field names) is disclosable for attack "
         "planning."),
    "graphql_anonymous_access":
        ("proven", "An unauthenticated client executed queries and received "
         "sensitive-named data with real values — the sensitive operation "
         "plane is reachable without any credentials."),
    "graphql_bola":
        ("proven", "A caller without rights to the object (low-privilege "
         "identity or anonymous) read another identity's object by id, "
         "marker-proven in the response — object-level authorization is "
         "missing."),
    "graphql_field_authorization":
        ("proven", "A low-privilege identity received sensitive-named fields "
         "with REAL values for its own object — field-level "
         "authorization/exposure control is missing."),
    "graphql_mutation_authorization":
        ("proven", "A mutation executed and returned data for a caller "
         "without its required privilege — state-changing operations are "
         "reachable unauthenticated/under-privileged."),
    "graphql_sql_injection":
        ("proven", "A GraphQL query string argument reaches a backend SQL "
         "predicate unsanitized — proven by a database error signature "
         "(error-based) and/or a boolean differential between a benign "
         "value and an OR-tautology (blind), both through the GraphQL "
         "transport."),
    "graphql_command_execution":
        ("proven", "A query argument reaches an OS command execution sink — "
         "the response carried operating-system command output for a safe "
         "alphanumeric flag probe (no metacharacter was sent)."),
    "websocket_sensitive_data_exposure":
        ("proven", "A WebSocket channel delivered sensitive-named data with "
         "real values to an unauthenticated listener — channel content is "
         "not authorization-gated."),
    "websocket_cross_user_access":
        ("proven", "An unauthorized listener received another identity's "
         "marker data on a WebSocket channel — channel membership is not "
         "enforced."),
    "websocket_message_reflection":
        ("proven", "A WebSocket message field value is reflected back into "
         "the server's response in an HTML/JS-executable context (canary "
         "proven) — content injection through the WS transport into "
         "client-side rendering."),
    "websocket_origin_not_enforced":
        ("indicated", "The WebSocket handshake accepts an arbitrary Origin — "
         "combined with cookie/session authentication this enables "
         "cross-site WebSocket hijacking from any hostile page."),
}

DEFAULT_PROFILE = ("indicated",
                   "Defect confirmed by verification; direct impact "
                   "demonstration not implemented for this class.")


def assess(finding) -> dict:
    """Impact proof for one finding (deterministic, additive to reports)."""
    grade, statement = IMPACT_PROFILES.get(finding.type, DEFAULT_PROFILE)
    ev_kinds = sorted({e.kind for e in finding.evidence})
    oob = any("oob" in k or "callback" in k for k in ev_kinds)
    verified = bool(finding.verification and finding.verification.passed)
    return {
        "grade": grade,
        "statement": statement,
        "safe_proof": ("non-destructive verification: fresh-input replay / "
                       "differential oracle / marker read — no data extraction, "
                       "no state change, no destructive payload"),
        "evidence_chain": {
            "request": finding.method + " " + finding.endpoint_url.split("?")[0],
            "parameter": finding.parameter,
            "evidence_kinds": ev_kinds,
            "out_of_band": oob,
            "verification": (finding.verification.method if finding.verification else ""),
            "verification_passed": verified,
            **({"authz_context": finding.authz_context} if getattr(finding, "authz_context", "") else {}),
        },
    }


# ============================================================================
# Phase 63 (v4.0.0) — Proof Engine / Evidence OS
# ============================================================================
# A finding is no longer a one-line "SQL Injection — High". Every verified
# finding becomes a SELF-CONTAINED PROOF FILE: the attack hypothesis that
# motivated the test, the preconditions, the exact requests/responses (bounded
# snippets), the identity and workflow state before/after, the demonstrated
# impact, and a step-by-step REPRODUCTION recipe an engineer can follow (or a
# CI job can re-run) to see the same proof again. This is the artifact that
# makes "Reproduce Finding" a button instead of an archaeology project.

HYPOTHESIS_BY_CLASS: dict[str, str] = {
    "sql_injection": "attacker-controlled input changes the boolean value of a "
                     "server-side query condition (observable differential)",
    "xss_reflected": "attacker-supplied markup survives into the response in an "
                     "executable context",
    "xss_dom": "attacker-controlled data reaches a DOM sink and executes in a "
               "real browser",
    "path_traversal": "a path parameter escapes the document root and reads a "
                      "marker file",
    "xxe": "an XML parser resolves external entities (file read / OOB fetch)",
    "ssrf": "the server fetches an attacker-chosen URL (OOB callback proves it)",
    "command_injection": "OS command execution observable via a non-destructive "
                         "OOB callback",
    "ssti": "a template engine evaluates a fresh arithmetic expression",
    "code_injection": "an eval/code path evaluates a fresh arithmetic "
                      "expression (WS message battery, 2-round)",
    "graphql_field_suggestions": "a near-miss field name gets a "
                                 "'Did you mean' suggestion (2-round)",
    "nosql_injection": "an injected query-operator object flips an auth decision",
    "csrf": "a hostile-origin state-changing request is accepted like a "
            "same-origin one",
    "jwt_security": "unsigned/alg-none tokens are accepted",
    "host_header_injection": "an attacker-controlled Host is reflected into "
                             "application output",
    "idor_bola": "a low-privilege session retrieves another identity's private "
                 "object (victim marker oracle)",
    "vertical_privilege_escalation": "a low-privilege session receives the "
                                     "privileged view of a protected surface",
    "business_logic_step_bypass": "a later workflow step creates its object "
                                  "without the mandatory predecessor",
    "business_logic_out_of_order": "the final workflow step executes a resource "
                                   "that was never created",
    "business_logic_value_tamper": "an approved value is replaced at execution "
                                   "time",
    "business_logic_duplicate_execution": "replaying the final step executes the "
                                          "same resource twice",
    "business_logic_privilege_escalation": "a UI-declared privileged option is "
                                           "executable by a lower role",
    "business_logic_cross_user_execution": "identity B (another session) executes "
                                           "a workflow object minted by identity A",
    "business_logic_cross_object_execution": "a workflow step executes an object "
                                             "produced by a different flow/context",
    "business_logic_cross_state_execution": "a workflow step executes an object "
                                            "in a cancelled/rejected state",
    "credential_exposure": "secret credential material is exposed in a response",
    "cors_misconfig": "arbitrary origins are reflected with credentials allowed",
    "open_redirect": "an unvalidated redirect to an attacker-controlled "
                     "destination",
    "http_response_header_injection": "attacker input reaches a response header",
    "missing_security_headers": "protective headers are absent",
    "server_banner_disclosure": "server software version disclosed",
    "tech_banner_disclosure": "technology stack disclosed",
    "vulnerable_js_dependency": "end-of-life client-side dependency served",
    "header_injection": "attacker input reaches response headers",
    "graphql_introspection_enabled": "the full GraphQL schema is readable by "
                                     "any client",
    "graphql_anonymous_access": "unauthenticated clients execute sensitive "
                               "queries",
    "graphql_bola": "object-level authorization missing on GraphQL queries",
    "graphql_field_authorization": "sensitive fields with real values reach "
                                   "low-privilege identities",
    "graphql_mutation_authorization": "mutations execute without their "
                                      "required privilege",
    "graphql_sql_injection": "a query argument reaches backend SQL unsanitized",
    "graphql_command_execution": "a query argument reaches an OS command sink",
    "websocket_sensitive_data_exposure": "sensitive data delivered on an "
                                         "ungated channel",
    "websocket_cross_user_access": "another identity's data on a shared channel",
    "websocket_message_reflection": "message fields reflect into executable "
                                    "response contexts",
    "websocket_origin_not_enforced": "the handshake accepts any Origin (CSWSH "
                                     "precondition)",
}
DEFAULT_HYPOTHESIS = "a defect class verified by the engine's oracle"


def _snippet(text: str, limit: int = 400) -> str:
    """A bounded, report-safe snippet (never a data dump)."""
    t = (text or "").strip()
    return t if len(t) <= limit else t[: limit - 3] + "..."


def build_proof(finding, state_before: str = "", state_after: str = "",
                reproduction: list | None = None) -> dict:
    """The Evidence-OS proof file for ONE verified finding.

    state_before/state_after: the workflow-oracle snapshot pair (workflow and
    authz classes); empty for request-level classes whose proof IS the
    differential. reproduction: ordered, human-executable steps (each a dict
    {step, request, expect}) — when omitted, a canonical recipe is derived
    from the evidence chain.
    """
    impact = assess(finding)
    verified = bool(finding.verification and finding.verification.passed)
    evidences = [{"kind": e.kind, "detail": _snippet(e.detail, 300),
                  "request_id": e.request_id} for e in finding.evidence]
    if reproduction is None:
        reproduction = _canonical_reproduction(finding)
    return {
        "finding_id": finding.id,
        "type": finding.type,
        "severity": finding.severity.value,
        "attack_hypothesis": HYPOTHESIS_BY_CLASS.get(finding.type, DEFAULT_HYPOTHESIS),
        "preconditions": _preconditions(finding),
        "requests": [{"method": finding.method,
                      "url": finding.endpoint_url.split("?")[0],
                      "parameter": finding.parameter}],
        "responses": evidences,
        "identity": getattr(finding, "authz_context", "") or "primary scan session",
        "state_before": _snippet(state_before),
        "state_after": _snippet(state_after),
        "impact": impact,
        "reproduction": reproduction,
        "confidence": round(finding.confidence, 3),
        "verification": ({"method": finding.verification.method,
                          "passed": verified,
                          "rounds": finding.verification.rounds,
                          "notes": _snippet(finding.verification.notes, 300)}
                         if finding.verification else None),
        "proof_grade": impact["grade"],
    }


def _preconditions(finding) -> list[str]:
    """What had to be true for this test to even run (honest, class-aware)."""
    pre = ["target reachable within scope"]
    if getattr(finding, "authz_context", ""):
        pre.append("two configured identities with different privileges "
                   "(authz accounts)")
    if finding.type.startswith("business_logic_"):
        pre.append("a learned multi-step flow with resource linkage and a "
                   "state oracle (workflow engine, learn phase)")
        pre.append("explicit operator permission (--logic-active)")
    if finding.type in ("xxe", "ssrf", "command_injection"):
        pre.append("an armed out-of-band (OAST) channel")
    if finding.type in ("xss_dom",):
        pre.append("a real browser engine (playwright) in the loop")
    if finding.type == "idor_bola":
        pre.append("a victim account with a unique marker value")
    return pre


def _canonical_reproduction(finding) -> list[dict]:
    """The default step-by-step recipe: repeat the proving request and expect
    the same oracle outcome. Deterministic, payload-free phrasing (reports
    stay safe to share)."""
    url = finding.endpoint_url.split("?")[0]
    steps = [{
        "step": 1,
        "request": f"authenticate a session with the application (as configured "
                   f"for the scan)",
        "expect": "an authenticated session cookie/header",
    }, {
        "step": 2,
        "request": f"send {finding.method} {url}"
                   + (f" with the tested parameter '{finding.parameter}' and the "
                      "canary value from the evidence chain" if finding.parameter
                      else " as recorded"),
        "expect": "the same evidence kind fires as in the attached proof "
                  f"({', '.join(sorted({e.kind for e in finding.evidence})[:3])})",
    }]
    if finding.type.startswith("business_logic_"):
        steps.insert(1, {
            "step": 2,
            "request": "walk the learned flow up to the step named in the proof, "
                       "on a FRESH session",
            "expect": "the resource id and state oracle observed in the proof",
        })
        steps[-1]["step"] = 3
    return steps


def reproduce_command(proof: dict) -> str:
    """A one-line, copy-pasteable reproduction cue for terminals and CI logs
    (the full recipe rides the proof file; this is the headline)."""
    req = (proof.get("requests") or [{}])[0]
    return (f"sentinel reproduce --finding {proof.get('finding_id', '')} "
            f"({req.get('method', 'GET')} {req.get('url', '')} "
            f"param={req.get('parameter', '') or '-'})")


# ------------------------------------------------------------------ v4.1.0 replay
REPLAYABLE_TYPES = {
    "sql_injection": "sqli", "xss_reflected": "xss", "path_traversal": "traversal",
    "open_redirect": "redirect", "ssrf": "ssrf", "header_injection": "crlf",
    "xxe": "xxe", "command_injection": "cmdi", "csrf": "csrf",
    "nosql_injection": "nosql", "jwt_security": "jwt",
    "host_header_injection": "hostheader", "ssti": "ssti",
    "code_injection": "codei", "graphql_field_suggestions": "gqlsuggest",
}


def replay_finding(proof: dict, scope, bus, timeout: float = 12.0) -> dict:
    """Proof Engine 2.0 (Phase V41-09): re-execute ONE finding's proof from a
    CLEAN engine — no session reuse, no prior state — and report the outcome
    honestly:

        REPRODUCTION_VERIFIED   the same vuln class re-verified on replay
        REPRODUCTION_FAILED     the replay ran but did not reproduce (reason
                                recorded, never hidden)
        NOT_REPLAYABLE          the class needs scan-time context the proof
                                cannot carry (business-logic flows need the
                                authenticated walk) — an honest limit, loudly
                                recorded with the manual recipe

    The replay re-runs the SAME detector + verification pipeline (not a
    simplified re-check), on a fresh RequestEngine scoped to the finding's
    own surface."""
    from .http_engine import RequestEngine
    from .intel import VerificationEngine
    from . import detect as _dm
    from .core import Endpoint, Parameter, ParamLocation, ParamKind
    from .detect import _pseudo_param

    out = {"finding_id": proof.get("finding_id", ""),
           "type": proof.get("type", ""),
           "replay": "NOT_REPLAYABLE", "reason": "", "evidence": ""}
    ftype = proof.get("type", "")
    if ftype.startswith("business_logic_") or ftype in (
            "idor_bola", "vertical_privilege_escalation"):
        out["reason"] = ("this class reproduces through the authenticated "
                         "flow/session context the scan held — follow the "
                         "proof file's manual steps (replay needs the scan's "
                         "credentials configuration)")
        return out
    det_name = REPLAYABLE_TYPES.get(ftype)
    if det_name is None:
        out["reason"] = f"no automated replay implemented for class {ftype}"
        return out
    det_cls = next((d for d in _dm.ACTIVE_DETECTORS if d.name == det_name), None)
    if det_cls is None:
        out["reason"] = f"detector {det_name} unavailable"
        return out
    req = (proof.get("requests") or [{}])[0]
    url, param = req.get("url", ""), req.get("parameter", "")
    try:
        engine = RequestEngine(scope, bus, timeout=timeout)
        verifier = VerificationEngine(engine, bus)
        det = det_cls(engine, bus, None)
        params = [Parameter(param, ParamLocation.QUERY, "1").classify()] \
            if param else []
        ep = Endpoint(url=url, method=req.get("method", "GET"), parameters=params)
        if det_name == "sqli" and param:
            cands = list(det.candidates(ep))
            resp_map = {}
            for strat, m in cands:
                r = engine.send(m)
                if not r.error:
                    resp_map[strat] = r
            if not resp_map:
                out.update(replay="REPRODUCTION_FAILED",
                           reason="no probe could be sent (transport errors)")
                return out
            pobj = next((p for p in ep.parameters if p.name == param), None)
            cand = det.analyze((ep, pobj), resp_map)
        elif det_name in _dm.RUN_STYLE_DETECTORS:
            cand = det.run(ep)
        else:
            cand = None
            for m in det.candidates(ep):
                if isinstance(m, tuple):
                    m = m[1]
                r = engine.send(m)
                if r.error:
                    continue
                # XS-1 (xss recall round, live-caught on the OWASP Benchmark
                # master = v1.2): keep the probe's OWN name when it matches no
                # endpoint param — it is a name-channel probe (payload IS the
                # name); attributing it to ep.parameters[0] mislabels the
                # finding and the replay then probes a channel the app never
                # reads (live: xss resolver candidates carried parameter=answer
                # -> VALUE-channel replay -> REPRODUCTION_FAILED family-wide).
                pobj = next((p for p in ep.parameters if p.name == m.param_name), None) \
                    or _pseudo_param(m.param_name, m.param_value or "1", ParamKind.GENERIC)
                cand = det.analyze((ep, pobj), r)
                if cand:
                    break
        if cand is None:
            out.update(replay="REPRODUCTION_FAILED",
                       reason="the detector no longer produces a candidate on a "
                              "clean replay (target may have changed or the "
                              "finding was context-dependent)")
            return out
        verified = verifier.verify(cand, ep)
        if verified.status and verified.status.value == "verified":
            out.update(replay="REPRODUCTION_VERIFIED",
                       reason="the same vuln class re-verified on a clean engine",
                       evidence=(verified.evidence[0].detail[:200]
                                 if verified.evidence else ""))
        else:
            out.update(replay="REPRODUCTION_FAILED",
                       reason=f"replay produced status "
                              f"{getattr(verified.status, 'value', 'unknown')} "
                              "(the original evidence did not reproduce)",
                       evidence=(verified.evidence[0].detail[:200]
                                 if verified.evidence else ""))
    except Exception as e:
        out.update(replay="REPRODUCTION_FAILED",
                   reason=f"replay engine error: {type(e).__name__}: {e}")
    return out

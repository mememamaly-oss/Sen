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

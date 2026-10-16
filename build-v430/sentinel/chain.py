"""SENTINEL v4.3.0 — L2 Attack-Path Intelligence: the seven-segment chain layer.

Order provenance: the L2 seven-segment chain (trace 1a106a56a9bdb7b9) was built
in a prior session and LOST to an environment rollback (2026-10-05 ground-truth
check: no such module in the tree, no commit, worklog ends before it). This is
the honest REBUILD to the same specification, now anchored to the OWASP
Benchmark / DVWA / Mutillidae campaign so every segment rule cites live-caught
evidence.

THE SEVEN SEGMENTS (every chain walks all of them, in order):

    1. IDENTITY   who is acting          (anonymous / named account / role)
    2. ENTRY      where they get in      (the vulnerable endpoint + method)
    3. ACTION     what operation runs    (read / write / execute / auth)
    4. OBJECT     what it touches        (entity: account, record, file, session)
    5. AUTHORIZATION  did the app's access control allow it (or was it bypassed)
    6. STATE      what changed           (state-oracle evidence, or read-only)
    7. IMPACT     what an attacker gains (L3 capability proof, or projection)

THE WEAKEST-LINK IRON LAW (unchanged from the original spec):
    a chain is VERIFIED only when EVERY segment carries live-fresh evidence
    (a re-executed probe, a journaled request/response pair, a state oracle).
    If ANY segment is projected/inferred, the WHOLE chain is INFERRED — and the
    chain says exactly WHICH segments are projected. There is no such thing as
    a mostly-verified chain: an attacker needs every link, so the honest
    verdict is only as strong as the weakest link.

LIVE-FRESH vs PROJECTION:
    live-fresh   = evidence produced by THIS scan's own requests against the
                   live target (finding evidence chains, journaled pairs,
                   state-oracle before/after snapshots, L3 micro-proofs)
    projection   = everything else (entity inference from names, class-typical
                   impact, assumed identity) — legitimate reasoning, but never
                   stamped VERIFIED.
"""
from __future__ import annotations

import dataclasses
from typing import Optional

from .core import Finding, FindingStatus

SEGMENT_ORDER = ("identity", "entry", "action", "object", "authorization", "state", "impact")

# segment statuses
LIVE = "live"          # live-fresh evidence exists
PROJECTED = "projected"  # reasonable inference, no live evidence
ABSENT = "absent"      # the segment does not apply / no basis even to infer

VERIFIED = "VERIFIED"
INFERRED = "INFERRED"


@dataclasses.dataclass
class ChainSegment:
    kind: str                  # one of SEGMENT_ORDER
    status: str                # LIVE | PROJECTED | ABSENT
    description: str           # plain-language statement of this link
    evidence_refs: list = dataclasses.field(default_factory=list)   # finding ids / proof kinds


@dataclasses.dataclass
class AttackChain:
    title: str
    segments: list = dataclasses.field(default_factory=list)   # in SEGMENT_ORDER
    source_findings: list = dataclasses.field(default_factory=list)

    # -------------------------------------------------- weakest-link verdict
    def verdict(self) -> str:
        """IRON LAW: all LIVE -> VERIFIED; any PROJECTED -> INFERRED (named);
        any ABSENT -> the chain is incomplete (reported as INFERRED with the
        absent segments listed — an absent link is the weakest link of all)."""
        statuses = [s.status for s in self.segments]
        if statuses and all(st == LIVE for st in statuses):
            return VERIFIED
        return INFERRED

    def weak_links(self) -> list:
        return [s.kind for s in self.segments if s.status != LIVE]

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "verdict": self.verdict(),
            "weakest_links": self.weak_links(),
            "segments": [{"kind": s.kind, "status": s.status,
                          "description": s.description, "evidence_refs": s.evidence_refs}
                         for s in self.segments],
            "source_findings": self.source_findings,
        }


# ---------------------------------------------------------------- classification helpers
IMPACT_CAPABILITIES = {
    "sql_injection":        "arbitrary predicate injection into a live SQL query (data-layer reach)",
    "xss_reflected":        "attacker-controlled markup/JS in a victim's browser context",
    "xss_dom":              "attacker-controlled script execution via DOM source->sink",
    "xss_stored":           "persistent attacker-controlled content served to other users",
    "path_traversal":       "file read outside the intended directory",
    "xxe":                  "out-of-band entity resolution from the target's parser",
    "command_injection":    "OS command execution under the application's privileges",
    "ldap_injection":       "arbitrary LDAP filter manipulation against the directory",
    "xpath_injection":      "arbitrary XPath predicate injection into the XML query",
    "nosql_injection":      "operator injection into a NoSQL query",
    "csrf":                 "cross-origin state change in a victim's session",
    "open_redirect":        "redirect of a victim to an attacker-controlled origin",
    "host_header_injection": "host-header manipulation influencing generated URLs",
    "http_response_header_injection": "response header injection (CRLF)",
    "ssti":                 "template expression evaluation (code-adjacent)",
    "ssrf":                 "server-side requests to attacker-influenced URLs",
}


def _live_fresh(f: Finding) -> bool:
    """A finding is live-fresh evidence when it was VERIFIED by re-execution
    in this scan (verification method recorded) — the engine's own standard."""
    return (f.status == FindingStatus.VERIFIED
            and f.verification is not None
            and bool(f.verification.passed))


def _identity_segment(findings: list, authz_context: str = "") -> ChainSegment:
    """Segment 1 — WHO. Live evidence: an authz finding naming the acting
    identity, or an authz_context on a verified finding. Projection: the
    scan's identity when no account was configured = 'any anonymous client'."""
    named = [f for f in findings if f.authz_context]
    if named:
        ctx = named[0].authz_context
        return ChainSegment("identity", LIVE,
                            f"acting identity: {ctx}",
                            [named[0].id])
    if authz_context:
        return ChainSegment("identity", LIVE, f"acting identity: {authz_context}", [])
    return ChainSegment("identity", PROJECTED,
                        "acting identity: any anonymous client (no account context was "
                        "configured for this scan — the vulnerability was reached "
                        "unauthenticated, which is itself the strongest identity claim)",
                        [])


def _entry_segment(f: Finding) -> ChainSegment:
    """Segment 2 — WHERE. Live: the verified finding IS the live-reached entry."""
    return ChainSegment("entry", LIVE,
                        f"{f.method} {f.endpoint_url.split('?')[0]} (param {f.parameter!r}"
                        + (f" via {f.param_location} injection" if getattr(f, 'param_location', '') else "")
                        + ")",
                        [f.id])


def _action_segment(f: Finding) -> ChainSegment:
    """Segment 3 — WHAT operation. Live: the finding's own evidence shows the
    operation executed (probe response differential / callback / reflection)."""
    kinds = {e.kind for e in f.evidence}
    op = "read" if f.type in ("sql_injection", "path_traversal", "xxe", "xpath_injection",
                              "ldap_injection", "xss_reflected", "xss_dom") else \
         "execute" if f.type == "command_injection" else \
         "state-change" if f.type in ("csrf",) or f.type.startswith("business_logic") else "write"
    return ChainSegment("action", LIVE if _live_fresh(f) else PROJECTED,
                        f"{op} operation on the vulnerable surface "
                        f"(evidence kinds: {', '.join(sorted(kinds)) or 'none'})",
                        [f.id])


def _object_segment(f: Finding) -> ChainSegment:
    """Segment 4 — WHAT it touches. Live when the finding names the concrete
    object (parameter = the object handle); the twin's entity inference would
    be a projection (kept for description only)."""
    if f.parameter:
        return ChainSegment("object", LIVE,
                            f"object handle: parameter {f.parameter!r}"
                            + (f" at {f.endpoint_url.split('?')[0].rsplit('/', 1)[-1]!r} surface" if "/" in f.endpoint_url else ""),
                            [f.id])
    return ChainSegment("object", PROJECTED,
                        "object inferred from the endpoint path (no parameter handle)",
                        [])


def _authorization_segment(findings: list, f: Finding) -> ChainSegment:
    """Segment 5 — did access control stop it? Live: an authz-class verified
    finding (idor / vertical escalation) or an authz matrix result for this
    surface. Projection: no authz evidence collected this scan."""
    authz_hits = [x for x in findings if x.type in ("idor_bola", "vertical_privilege_escalation",
                                                    "idor", "broken_access_control")]
    for x in authz_hits:
        if _live_fresh(x) and (x.endpoint_url.split("?")[0] == f.endpoint_url.split("?")[0]):
            return ChainSegment("authorization", LIVE,
                                f"access control BYPASSED on this surface ({x.type}: {x.verification.method if x.verification else ''})",
                                [x.id])
    if authz_hits:
        return ChainSegment("authorization", PROJECTED,
                            "authorization posture inferred from sibling authz findings "
                            "(no direct matrix result for this endpoint)",
                            [x.id for x in authz_hits[:2]])
    return ChainSegment("authorization", PROJECTED,
                        "no authorization boundary was tested on this surface this scan "
                        "(no accounts/matrix configured) — the bypass status is unknown, "
                        "not claimed", [])


def _state_segment(findings: list, f: Finding) -> ChainSegment:
    """Segment 6 — what changed. Live: a state-oracle pair (state_before/
    state_after) on a verified finding. Read-only classes: no state change is
    REQUIRED by the attack — stated as live 'none required' only when the
    finding is live (the probes demonstrably did not depend on state)."""
    if f.state_before or f.state_after:
        return ChainSegment("state", LIVE,
                            f"state oracle: before={f.state_before[:80]!r} after={f.state_after[:80]!r}",
                            [f.id])
    read_only = f.type in ("sql_injection", "xss_reflected", "xss_dom", "path_traversal",
                           "xxe", "open_redirect", "ldap_injection", "xpath_injection",
                           "host_header_injection", "http_response_header_injection",
                           "server_banner", "missing_security_headers")
    if read_only:
        return ChainSegment("state", PROJECTED if not _live_fresh(f) else LIVE,
                            "no application state change required by this class "
                            "(read/reflect oracle — the probes themselves are stateless "
                            "unless the target says otherwise)", [f.id])
    return ChainSegment("state", PROJECTED,
                        "state effect not measured this scan (no state oracle recorded)",
                        [])


def _impact_segment(f: Finding, impact_proofs: dict) -> ChainSegment:
    """Segment 7 — what the attacker gains. Live ONLY with an L3 micro-proof
    (impact.py, safety-capped re-execution). Projection: class-typical impact."""
    proof = impact_proofs.get(f.id)
    if proof is not None:
        return ChainSegment("impact", LIVE if proof.get("verdict") == "PROVEN" else PROJECTED,
                            f"L3 micro-proof: {proof.get('capability', '')} "
                            f"({proof.get('method', '')}; cap: {proof.get('safety_cap', '')})",
                            [f.id, "L3:" + proof.get("method", "")])
    return ChainSegment("impact", PROJECTED,
                        f"class-typical impact (projected, not proven this scan): "
                        f"{IMPACT_CAPABILITIES.get(f.type, f.type)}",
                        [f.id])


# ---------------------------------------------------------------- synthesis
def synthesize_chains(findings: list, impact_proofs: Optional[dict] = None,
                      authz_context: str = "") -> list:
    """Build the seven-segment chain for every VERIFIED finding (candidates and
    rejected findings do not anchor chains — an unproven entry is not a path).
    Chains are per-finding; cross-finding composites (e.g. stored XSS feeding
    session capture) arrive when their segments share evidence anchors."""
    impact_proofs = impact_proofs or {}
    chains = []
    verified = [f for f in findings if f.status == FindingStatus.VERIFIED]
    for f in verified:
        segs = [
            _identity_segment(findings, authz_context),
            _entry_segment(f),
            _action_segment(f),
            _object_segment(f),
            _authorization_segment(findings, f),
            _state_segment(findings, f),
            _impact_segment(f, impact_proofs),
        ]
        chains.append(AttackChain(
            title=f"{f.type} on {f.endpoint_url.split('?')[0].rsplit('/', 1)[-1] or f.endpoint_url}"
                  f" (param {f.parameter})",
            segments=segs,
            source_findings=[f.id]))
    return chains


def chain_summary(chains: list) -> dict:
    verified_n = sum(1 for c in chains if c.verdict() == VERIFIED)
    return {
        "chains_total": len(chains),
        "chains_verified": verified_n,
        "chains_inferred": len(chains) - verified_n,
        "weakest_link_histogram": {
            k: sum(1 for c in chains if k in c.weak_links())
            for k in SEGMENT_ORDER
            if any(k in c.weak_links() for c in chains)
        },
    }

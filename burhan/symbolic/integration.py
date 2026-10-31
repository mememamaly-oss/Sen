"""AXIS-18 Phases 3+4 — payload generation, verification, orchestration.

The ONLY module with engine-adjacent behavior, and even here the engine is
never imported: the orchestrator INJECTS the two callables (sender, url_gate)
through the registration points — dependency inversion, testable in pure
unit space with a fake sender.

  * generate_payload (RP-3): solutions -> ({var: value}, [blocked vars]);
    destructive values are gated out BEFORE anything is sent.
  * verify_and_sign (RP-4): send the computed payload via the injected
    sender, judge path activation strictly (the ORIGINAL error text must be
    absent AND the status must improve below 400), then sign the result
    (Merkle evidence chain + Ed25519) for external verification.
  * run_symbolic_analysis: the full four-phase chain over response sources.

Verification oracle (strict, no false positives by construction):
  activated      = sender returned no error AND status < 400 AND the original
                   validation error text is absent from the new body.
  not_activated  = anything else (the payload satisfied the constraint but
                   the guarded path did not open — recorded honestly, never
                   reported as a vulnerability).
"""
from __future__ import annotations

from .models import (Constraint, Path, SymbolicResult, Solution, sign_result,
                     BOUNDARY_BLOCKED_PLANNER, BOUNDARY_NO_SENDER, BOUNDARY_TRANSPORT)
from .parser import parse_constraints
from .solver import solve_constraints
from .gates import gate_solution


def generate_payload(solutions: dict) -> tuple[dict, list]:
    """RP-3 — the third registration point. Destructive solution values are
    blocked here and NEVER become payloads."""
    payload: dict = {}
    blocked: list[str] = []
    for var, sol in (solutions or {}).items():
        verdict = gate_solution(sol if isinstance(sol, Solution) else Solution(var, sol, "injected"))
        if verdict["allowed"]:
            payload[var] = sol.value if isinstance(sol, Solution) else sol
        else:
            blocked.append(var)
    return payload, blocked


def verify_and_sign(result: SymbolicResult, sender=None, url_gate=None,
                    seed: bytes = b"") -> SymbolicResult:
    """RP-4 — the fourth registration point: verify (via the INJECTED sender)
    and sign. Never touches the engine directly; never raises outward."""
    if result.solution is None or not result.payload:
        sign_result(result, seed)
        return result
    src = result.source or {}
    url, method = src.get("url", ""), (src.get("method") or "GET")
    if url_gate is not None and url:
        g = url_gate(url, method)
        if g and not g.get("allowed", True):
            result.blocked = result.blocked or f"planner gate: {g.get('reason', 'blocked')}"
            result.honest_boundary = BOUNDARY_BLOCKED_PLANNER
            sign_result(result, seed)
            return result
    if sender is None or not url:
        result.honest_boundary = result.honest_boundary or BOUNDARY_NO_SENDER
        sign_result(result, seed)
        return result
    var = result.solution.var
    try:
        resp = sender({"url": url, "method": method,
                       "params": {var: result.payload.get(var)},
                       "note": "symbolic-verify"})
    except Exception as e:                       # injected sender failure = honest boundary
        result.verified = "transport_error"
        result.honest_boundary = f"{BOUNDARY_TRANSPORT}: {type(e).__name__}"
        sign_result(result, seed)
        return result
    status, body = int(resp.get("status", 0) or 0), str(resp.get("body", "") or "")
    if resp.get("error"):
        result.verified = "transport_error"
        result.honest_boundary = f"{BOUNDARY_TRANSPORT}: {str(resp['error'])[:120]}"
    else:
        orig_text = str(src.get("text", "") or "")[:120]
        activated = status < 400 and (not orig_text or orig_text not in body)
        result.verified = "activated" if activated else "not_activated"
        result.solution.note = (result.solution.note or "") + \
            f" | verify: {src.get('status', '?')}->{status}"
    sign_result(result, seed)
    return result


def run_symbolic_analysis(sources: list, sender=None, url_gate=None,
                          seed: str | bytes = "") -> list:
    """The full four-phase chain over response sources (each source:
    {url, method, text, status}). Pure with respect to the engine — sender
    and url_gate are injected by the orchestrator (or a fake, in tests).

    Phase 1 extract -> Phase 2 solve (per variable) -> Phase 3 gated payload
    -> Phase 4 verify+sign. Every result — solved, blocked, or boundary —
    is returned and signed; nothing is silently dropped."""
    seed_b = seed.encode("utf-8") if isinstance(seed, str) else (seed or b"")
    seen: set[tuple] = set()
    all_cons: list[Constraint] = []
    for src in (sources or []):
        for c in parse_constraints(text=str((src or {}).get("text", "") or ""),
                                   context={"url": (src or {}).get("url", ""),
                                            "method": (src or {}).get("method", "GET"),
                                            "status": (src or {}).get("status", 0),
                                            "text": str((src or {}).get("text", "") or "")[:400],
                                            "note": (src or {}).get("note", "")}):
            key = (c.var, c.op, repr(c.value), c.kind)
            if key in seen:
                continue
            seen.add(key)
            all_cons.append(c)

    by_var: dict[str, list[Constraint]] = {}
    for c in all_cons:
        by_var.setdefault(c.var, []).append(c)

    results: list[SymbolicResult] = []
    for var in sorted(by_var):
        vcons = by_var[var]
        src_ctx = next((c.context for c in vcons if c.context), {})
        res = solve_constraints(vcons)
        r = SymbolicResult(constraints=vcons, source=src_ctx)
        sol = res["solutions"].get(var)
        if sol is not None:
            r.solution = sol
            payload, blocked = generate_payload({var: sol})
            if var in blocked:
                r.blocked = "destructive solution value — gate_solution blocked it"
                r.payload = None
                r.path = Path(description=f"guarded path for {var}",
                              expected_effect="NOT PROBED — the computed solution value "
                                              "carries destructive vocabulary",
                              constraints=[c.expr for c in vcons])
            else:
                r.payload = payload
                r.path = Path(description=f"activate the path guarded by: "
                                          f"{'; '.join(c.expr for c in vcons)}",
                              expected_effect="the original validation error disappears "
                                              "and the guarded path opens",
                              constraints=[c.expr for c in vcons])
        else:
            r.honest_boundary = res.get("boundary_by_var", {}).get(var) or res.get("boundary")
        results.append(verify_and_sign(r, sender=sender, url_gate=url_gate, seed=seed_b))
    return results


def summarize(results: list, sources: int = 0) -> dict:
    """Report/stats summary — full transparency, machine-readable counts."""
    boundaries: dict[str, int] = {}
    activated = not_activated = blocked = solved = 0
    for r in results or []:
        if r.solution is not None:
            solved += 1
        if r.blocked:
            blocked += 1
        if r.verified == "activated":
            activated += 1
        elif r.verified == "not_activated":
            not_activated += 1
        if r.honest_boundary:
            boundaries[r.honest_boundary.split(":")[0]] = boundaries.get(r.honest_boundary.split(":")[0], 0) + 1
    return {"enabled": True, "sources": int(sources),
            "constraints_extracted": sum(len(r.constraints) for r in results or []),
            "solved": solved, "blocked": blocked,
            "verified_activated": activated, "not_activated": not_activated,
            "boundaries": boundaries,
            "results": [r.to_dict() for r in results or []]}

"""sentinel.symbolic — AXIS-18 (v4.3.0): Symbolic Execution Engine.

Extracts validation constraints from application responses, solves them
exactly (stdlib only — no Z3, no angr, no external SMT solvers), generates
gated payloads, and verifies path activation — every result signed with a
Merkle+Ed25519 evidence chain for external verification.

THE FOUR REGISTRATION POINTS — the ONLY coupling surface between the core
engine and this package (dependency inversion: the engine calls in; this
package never imports the engine):

  RP-1  parse_constraints(text, observations, context) -> list[Constraint]
        Phase 1 — constraint extraction from error messages / status
        differentials (parser.py).
  RP-2  solve_constraints(constraints) -> {status, solutions, boundary, ...}
        Phase 2 — bounded exact solving with honest boundaries (solver.py).
  RP-3  generate_payload(solutions) -> (payload, blocked_vars)
        Phase 3 — gated payload generation; destructive values never pass
        (gates.py + integration.py).
  RP-4  verify_and_sign(result, sender, url_gate, seed) -> SymbolicResult
        Phase 4 — verification via the INJECTED sender + Merkle/Ed25519
        signature (integration.py + models.py).

run_symbolic_analysis(sources, sender, url_gate, seed) chains all four
phases; summarize() renders the report/stats block. Purely additive: with
the engine flag off, nothing here executes at all.
"""
from .models import (Constraint, Solution, Path, SymbolicResult,
                     sign_result, verify_result_signature, merkle_root,
                     ed25519_keypair, ed25519_sign, ed25519_verify,
                     HONEST_BOUNDARIES)
from .parser import (parse_constraints, parse_expression,
                     extract_from_error_message, extract_from_status_codes)
from .solver import solve_constraints
from .gates import gate_solution, gate_payload, gate_url, DESTRUCTIVE_WORDS
from .integration import (generate_payload, verify_and_sign,
                          run_symbolic_analysis, summarize)

REGISTRATION_POINTS = ("parse_constraints", "solve_constraints",
                       "generate_payload", "verify_and_sign")

__all__ = list(REGISTRATION_POINTS) + [
    "run_symbolic_analysis", "summarize", "parse_expression",
    "extract_from_error_message", "extract_from_status_codes",
    "Constraint", "Solution", "Path", "SymbolicResult",
    "sign_result", "verify_result_signature", "merkle_root",
    "ed25519_keypair", "ed25519_sign", "ed25519_verify",
    "gate_solution", "gate_payload", "gate_url", "DESTRUCTIVE_WORDS",
    "HONEST_BOUNDARIES", "REGISTRATION_POINTS",
]

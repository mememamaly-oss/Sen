"""AXIS-18 safety gates — destructive solutions are blocked BEFORE payload
generation, mirroring the engine's SafeAttackPlanner vocabulary (planner.py
DESTRUCTIVE class = never sent). Two independent layers protect the target:

  1. gate_solution / payload value check (THIS module, package-side):
     a solved VALUE carrying destructive vocabulary (mode == "delete_all")
     never becomes a payload, and the result records WHY it was blocked.
  2. the orchestrator additionally routes every verification send through
     the engine's own planner gate (URL class) — defense in depth; a
     destructive URL class yields honest_boundary blocked_by_planner_gate.

The gate never raises and never mutates its input — it returns a verdict.
"""
from __future__ import annotations

from .models import Solution

# Aligned with sentinel/planner.py DESTRUCTIVE_WORDS (superset where the
# solution VALUE itself names the operation, e.g. "delete_all").
DESTRUCTIVE_WORDS = ("delete", "drop", "purge", "wipe", "truncate", "destroy",
                     "reset", "format", "shutdown", "kill", "erase", "uninstall",
                     "remove_all", "delete_all", "drop_all", "wipe_all")


def _value_terms(value) -> list[str]:
    """Flatten a solution value into lowercase string terms to screen."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value.lower()]
    if isinstance(value, (list, tuple, set)):
        out = []
        for v in value:
            out.extend(_value_terms(v))
        return out
    return [str(value).lower()]


def gate_solution(solution: Solution) -> dict:
    """Verdict for one solved value: {allowed, reason, class}.
    Destructive vocabulary in the VALUE (not the variable name — "mode" is
    innocent, "delete_all" is not) blocks the solution outright."""
    for term in _value_terms(solution.value if solution is not None else None):
        for word in DESTRUCTIVE_WORDS:
            if word in term:
                return {"allowed": False, "class": "DESTRUCTIVE",
                        "reason": f"destructive vocabulary in solution value "
                                  f"('{word}' in '{term[:60]}') — blocked before "
                                  f"payload generation; no request will carry it"}
    return {"allowed": True, "class": "OK", "reason": "solution value carries no destructive vocabulary"}


def gate_payload(payload: dict) -> dict:
    """Verdict for a whole payload dict — blocked iff ANY value is blocked.
    Returns {allowed, blocked_vars: {var: reason}}."""
    blocked = {}
    for var, value in (payload or {}).items():
        v = gate_solution(Solution(var=var, value=value))
        if not v["allowed"]:
            blocked[var] = v["reason"]
    return {"allowed": not blocked, "blocked_vars": blocked}


def gate_url(url: str) -> dict:
    """Package-side URL screen (defense in depth; the engine's planner gate
    remains the authoritative classifier on the orchestrator side)."""
    low = (url or "").lower()
    for word in DESTRUCTIVE_WORDS:
        if word in low:
            return {"allowed": False, "class": "DESTRUCTIVE",
                    "reason": f"destructive vocabulary in URL ('{word}')"}
    return {"allowed": True, "class": "OK", "reason": "url carries no destructive vocabulary"}

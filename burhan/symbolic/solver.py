"""AXIS-18 Phase 2 — Constraint Solving (stdlib only, bounded, honest).

Solves ONE VARIABLE AT A TIME over the constraint set (cross-variable
references like "y < x" are resolved iteratively after their dependencies).

Semantics (documented for the supervisor, encoded in the atom suite):
  * numeric solutions  = the MINIMAL SATISFYING INTEGER (age > 18 -> 19).
  * string solutions   = deterministic generation: (prefix|enum0|varname)
                         + "123", truncated to max-length caps and extended
                         with the digit cycle "456789" until every length
                         bound holds (len(password)>=8 -> "password123";
                         startswith("admin") AND len>10 -> "admin123456").
  * empty numeric interval:
      - every bound came from ONE compound declaration -> "contradiction"
        (a single declaration defeating itself: "x > 5 AND x < 3")
      - otherwise                                     -> "unsatisfiable"
        (an infeasible SET: [x > 10] + [x < 5])
  * tautology (x == x)    -> boundary "tautology", any value valid.
  * non-linear arithmetic -> boundary "complex_solver_unavailable"
    (no root finding is attempted — the honest limit of a stdlib solver).
  * unresolvable cross-references -> "unresolvable_reference".

The solver NEVER raises on unsolvable input — it answers with a boundary.
"""
from __future__ import annotations

from .models import (Constraint, Solution, BOUNDARY_UNSATISFIABLE, BOUNDARY_CONTRADICTION,
                     BOUNDARY_TAUTOLOGY, BOUNDARY_COMPLEX, BOUNDARY_NO_CONSTRAINTS,
                     BOUNDARY_UNRESOLVABLE_REF)

_EXT = "456789"
_MAX_GEN = 200          # hard bound on generated string length
_MAX_PASSES = 6         # hard bound on cross-variable resolution passes


def _num(v):
    """Coerce to int/float for arithmetic; None when impossible."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, str):
        try:
            f = float(v)
            return int(f) if f.is_integer() else f
        except ValueError:
            return None
    return None


def _interval(cons: list[Constraint], resolved: dict):
    """Intersect the integer bounds of one variable. Returns
    (lo, hi, ok, pending) — ok=False means a provably EMPTY interval;
    pending lists numeric_ref constraints whose target is not yet resolved."""
    lo, hi = None, None
    pending = []
    for c in cons:
        bound = None
        if c.kind in ("numeric", "length"):
            bound = _num(c.value)
        elif c.kind == "numeric_ref" and c.value in resolved:
            bound = resolved[c.value]
        elif c.kind == "numeric_ref":
            pending.append(c)
            continue
        if bound is None:
            continue
        if c.op == ">":
            lo = max(lo, bound + 1) if lo is not None else bound + 1
        elif c.op == ">=":
            lo = max(lo, bound) if lo is not None else bound
        elif c.op == "<":
            hi = min(hi, bound - 1) if hi is not None else bound - 1
        elif c.op == "<=":
            hi = min(hi, bound) if hi is not None else bound
        elif c.op == "==":
            lo = bound if lo is None else max(lo, bound)
            hi = bound if hi is None else min(hi, bound)
    ok = not (lo is not None and hi is not None and lo > hi)
    return lo, hi, ok, pending


def _min_int(lo, hi):
    """Minimal satisfying integer in the (possibly one-sided) interval."""
    if lo is not None and hi is not None:
        return lo if lo <= hi else None
    if lo is not None:
        return lo
    if hi is not None:
        return min(1, hi)          # no lower bound: the small deterministic pick
    return 1                        # unconstrained


def _satisfies(c: Constraint, value) -> bool:
    """Check ONE constraint against a concrete candidate value."""
    if c.kind == "length":
        n = len(value) if isinstance(value, str) else None
        b = _num(c.value)
        if n is None or b is None:
            return False
        return {">=": n >= b, ">": n > b, "<": n < b, "<=": n <= b,
                "==": n == b, "!=": n != b}.get(c.op, False)
    if c.kind == "numeric":
        v, b = _num(value), _num(c.value)
        if v is None or b is None:
            return False
        return {">=": v >= b, ">": v > b, "<": v < b, "<=": v <= b,
                "==": v == b, "!=": v != b}.get(c.op, False)
    if c.kind == "string":
        if c.op == "==":
            return value == c.value
        if c.op == "startswith":
            return isinstance(value, str) and value.startswith(c.value)
        if c.op == "endswith":
            return isinstance(value, str) and value.endswith(c.value)
        if c.op == "contains":
            return isinstance(value, str) and c.value in value
        if c.op == "present":
            return bool(value)
        return True
    if c.kind == "enum":
        return value in (c.value or [])
    return True        # tautology/complex/unknown kinds never veto a candidate


def _gen_string(var: str, cons: list[Constraint]):
    """Deterministic string satisfying every length/string/enum constraint,
    or None when provably infeasible under this generator."""
    exact, enum, prefix, suffix = None, None, None, None
    min_len, max_len = 1, None
    for c in cons:
        if c.kind == "string" and c.op == "==":
            exact = c.value
        elif c.kind == "enum" and c.value:
            enum = c.value[0]
        elif c.kind == "string" and c.op == "startswith":
            prefix = c.value
        elif c.kind == "string" and c.op == "endswith":
            suffix = c.value
        elif c.kind == "length":
            b = _num(c.value)
            if b is None:
                continue
            if c.op == ">=":
                min_len = max(min_len, b)
            elif c.op == ">":
                min_len = max(min_len, b + 1)
            elif c.op == "<=":
                max_len = b if max_len is None else min(max_len, b)
            elif c.op == "<":
                cap = b - 1
                max_len = cap if max_len is None else min(max_len, cap)
            elif c.op == "==":
                min_len = max(min_len, b)
                max_len = b if max_len is None else min(max_len, b)
    if exact is not None:
        return exact if all(_satisfies(c, exact) for c in cons) else None
    if enum is not None:
        cand0 = (prefix or "") + enum + (suffix or "")
        if all(_satisfies(c, cand0) for c in cons):
            return cand0                  # the enum value itself satisfies everything
    core = enum if enum is not None else ("" if prefix else var)
    base = (prefix or "") + core + "123"
    if suffix and not base.endswith(suffix):
        base += suffix
    if max_len is not None and len(base) > max_len:
        base = base[:max_len]                     # deterministic truncation under caps
    cand, i = base, 0
    while not all(_satisfies(c, cand) for c in cons):
        if max_len is not None and len(cand) + 1 > max_len:
            return None
        if len(cand) >= _MAX_GEN:
            return None
        cand += _EXT[i % len(_EXT)]
        i += 1
    return cand


def _empty_label(cons: list[Constraint]) -> str:
    """contradiction = every bound came from ONE compound declaration;
    unsatisfiable = an infeasible SET of independently declared bounds."""
    origins = {c.origin for c in cons if c.kind in ("numeric", "length", "numeric_ref")}
    if len(origins) == 1 and next(iter(origins)).startswith("compound:"):
        return BOUNDARY_CONTRADICTION
    return BOUNDARY_UNSATISFIABLE


def solve_constraints(constraints: list) -> dict:
    """RP-2 — the second registration point. Returns
    {"status": "solved"|"boundary"|"mixed", "solutions": {var: Solution},
     "boundary": str|None, "boundary_by_var": {var: str}, "method": str}.
    Never raises; unsolvable input answers with an honest boundary."""
    cons = [c for c in (constraints or []) if isinstance(c, Constraint)]
    if not cons:
        return {"status": "boundary", "solutions": {}, "boundary": BOUNDARY_NO_CONSTRAINTS,
                "boundary_by_var": {}, "method": "empty-set"}
    by_var: dict[str, list[Constraint]] = {}
    for c in cons:
        by_var.setdefault(c.var, []).append(c)

    solutions: dict[str, Solution] = {}
    boundary_by_var: dict[str, str] = {}
    resolved: dict[str, int | float] = {}
    pending_vars = set(by_var)

    for _ in range(_MAX_PASSES):
        progressed = False
        for var in sorted(pending_vars):
            vcons = by_var[var]
            kinds = {c.kind for c in vcons}
            if "tautology" in kinds:
                solutions[var] = Solution(var, 1, "any_value", "tautology — every value satisfies")
                boundary_by_var[var] = BOUNDARY_TAUTOLOGY
                resolved[var] = 1
                pending_vars.discard(var)
                progressed = True
                continue
            if "complex" in kinds:
                boundary_by_var[var] = BOUNDARY_COMPLEX
                pending_vars.discard(var)
                progressed = True
                continue
            if kinds <= {"length", "string", "enum"}:
                # string-shaped variable: generate, with a pre-check of the
                # length interval so infeasible bounds get the precise label
                if all(c.kind == "length" for c in vcons) or any(c.kind == "length" for c in vcons):
                    _, _, ok, _ = _interval(vcons, resolved)
                    if not ok:
                        boundary_by_var[var] = _empty_label(vcons)
                        pending_vars.discard(var)
                        progressed = True
                        continue
                val = _gen_string(var, vcons)
                if val is None:
                    boundary_by_var[var] = BOUNDARY_UNSATISFIABLE
                else:
                    solutions[var] = Solution(var, val, "string_generated", f"len={len(val)}")
                pending_vars.discard(var)
                progressed = True
                continue
            # numeric-shaped variable (with optional cross-refs)
            lo, hi, ok, pend = _interval(vcons, resolved)
            if pend:
                continue                    # wait for referenced variables to resolve
            if not ok:
                boundary_by_var[var] = _empty_label(vcons)
                pending_vars.discard(var)
                progressed = True
                continue
            n = _min_int(lo, hi)
            if n is None:
                boundary_by_var[var] = BOUNDARY_UNSATISFIABLE
                pending_vars.discard(var)
                progressed = True
                continue
            if all(_satisfies(c, n) for c in vcons if c.kind == "numeric"):
                solutions[var] = Solution(var, n, "minimal_satisfying_integer",
                                          f"integer bounds [lo={lo}, hi={hi}]")
                resolved[var] = n
            else:
                boundary_by_var[var] = BOUNDARY_UNSATISFIABLE
            pending_vars.discard(var)
            progressed = True
        if not pending_vars or not progressed:
            break
    for var in sorted(pending_vars):
        boundary_by_var[var] = BOUNDARY_UNRESOLVABLE_REF

    if solutions and not boundary_by_var:
        status, boundary = "solved", None
    elif boundary_by_var and not solutions:
        status, boundary = "boundary", next(iter(sorted(boundary_by_var.values())))
    else:
        status, boundary = "mixed", None
    return {"status": status, "solutions": solutions, "boundary": boundary,
            "boundary_by_var": boundary_by_var, "method": "bounded-interval+string-gen"}

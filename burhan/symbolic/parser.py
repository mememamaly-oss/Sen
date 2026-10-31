"""AXIS-18 Phase 1 — Constraint Extraction (stdlib re + ast only).

Three extraction front-ends, all returning the SAME Constraint model:
  * extract_from_error_message — natural-language validation errors
    ("password must be at least 8 characters" -> len(password) >= 8).
  * extract_from_status_codes  — differential observation of the SAME
    endpoint under different contexts (200 with role=admin vs 403 with
    role=user -> role == "admin").
  * parse_expression           — machine-shaped expressions
    ("len(password) >= 8", 'role == "admin"', "username startswith \"admin\"",
    "x > 5 AND x < 3" — compound strings tag every sub-constraint with the
    shared origin "compound:<full expr>" so the solver can distinguish a
    SELF-contradicting declaration from an infeasible constraint set).

Honesty rule: only patterns with a precise, unambiguous semantics are
extracted. Anything else is left alone (never guessed).
"""
from __future__ import annotations
import ast
import re

from .models import Constraint

# ------------------------------------------------------- error-message patterns
# (regex, kind, op, value_group_is_number) — ordered; matched spans are
# consumed so "must be at least 8 characters" can never ALSO match the bare
# numeric pattern ("password must be at least 8" as a numeric comparison).
_ERROR_PATTERNS = [
    (re.compile(r"\b(\w+)[\s_-]+must be at least\s+(\d+)\s+characters?\b", re.I), "length", ">="),
    (re.compile(r"\b(\w+)[\s_-]+must be a minimum of\s+(\d+)\s+characters?\b", re.I), "length", ">="),
    (re.compile(r"\b(\w+)[\s_-]+must contain at least\s+(\d+)\s+characters?\b", re.I), "length", ">="),
    (re.compile(r"\b(\w+)[\s_-]+must be at most\s+(\d+)\s+characters?\b", re.I), "length", "<="),
    (re.compile(r"\b(\w+)[\s_-]+must be a maximum of\s+(\d+)\s+characters?\b", re.I), "length", "<="),
    (re.compile(r"\b(\w+)[\s_-]+must be (?:longer than|more than)\s+(\d+)\s+characters?\b", re.I), "length", ">"),
    (re.compile(r"\b(\w+)[\s_-]+must be shorter than\s+(\d+)\s+characters?\b", re.I), "length", "<"),
    (re.compile(r"\b(\w+)[\s_-]+must be longer than\s+(\d+)\b", re.I), "length", ">"),
    (re.compile(r"\b(\w+)[\s_-]+must be greater than\s+(-?\d+(?:\.\d+)?)\b", re.I), "numeric", ">"),
    (re.compile(r"\b(\w+)[\s_-]+must be more than\s+(-?\d+(?:\.\d+)?)\b", re.I), "numeric", ">"),
    (re.compile(r"\b(\w+)[\s_-]+must be less than\s+(-?\d+(?:\.\d+)?)\b", re.I), "numeric", "<"),
    (re.compile(r"\b(\w+)[\s_-]+must be at least\s+(-?\d+(?:\.\d+)?)\b", re.I), "numeric", ">="),
    (re.compile(r"\b(\w+)[\s_-]+must be at most\s+(-?\d+(?:\.\d+)?)\b", re.I), "numeric", "<="),
    (re.compile(r"\b(\w+)[\s_-]+must be one of[:\s]+([^\n.;]+)", re.I), "enum", "in"),
    (re.compile(r'\b(\w+)[\s_-]+must start with\s+"([^"]+)"', re.I), "string", "startswith"),
    (re.compile(r"\b(\w+)[\s_-]+must start with\s+([A-Za-z0-9_@.\-]+)", re.I), "string", "startswith"),
    (re.compile(r'\b(\w+)[\s_-]+must end with\s+"([^"]+)"', re.I), "string", "endswith"),
    (re.compile(r"\b(\w+)[\s_-]+must contain\s+([A-Za-z0-9_@.\-]{2,})\b(?!\s+characters)", re.I), "string", "contains"),
    (re.compile(r"\b(\w+)[\s_-]+must be\s+(?!at least|at most|less than|greater than|more than|"
                r"longer than|shorter than|one of|between|a minimum|a maximum|between)([A-Za-z_][\w-]*)\b", re.I),
     "string", "=="),
    (re.compile(r"\b(\w+)[\s_-]+is required\b", re.I), "string", "present"),
]

_ENUM_SPLIT = re.compile(r"[,|/]")


def _mk(var, op, value, kind, source, origin="single", expr=None, context=None) -> Constraint:
    if expr is None:
        if kind == "length":
            expr = f"len({var}) {op} {value}"
        elif kind == "string" and isinstance(value, str):
            expr = f'{var} {op} "{value}"'
        elif kind == "enum":
            expr = f"{var} in {value}"
        else:
            expr = f"{var} {op} {value}"
    return Constraint(var=var, op=op, value=value, kind=kind, expr=expr,
                      source=source, origin=origin, context=context)


def extract_from_error_message(text: str, context: dict | None = None) -> list[Constraint]:
    """Pattern-match validation prose into precise constraints; matched
    spans are consumed so a character-length rule is never misread as a
    numeric comparison on the same words."""
    out: list[Constraint] = []
    if not text:
        return out
    consumed: list[tuple[int, int]] = []
    for rx, kind, op in _ERROR_PATTERNS:
        for m in rx.finditer(text):
            if any(not (m.end() <= s or m.start() >= e) for s, e in consumed):
                continue
            consumed.append((m.start(), m.end()))
            var = m.group(1).lower()
            if kind == "enum":
                value = [v.strip(" .\"'") for v in _ENUM_SPLIT.split(m.group(2)) if v.strip(" .\"'")]
                out.append(_mk(var, "in", value, "enum", "error_message", context=context))
            else:
                raw = m.group(2)
                value = int(raw) if kind == "length" or raw.lstrip("-").isdigit() else raw
                out.append(_mk(var, op, value, kind, "error_message", context=context))
    return out


def extract_from_status_codes(observations: list[dict]) -> list[Constraint]:
    """Differential constraints: a context key whose value differs between
    success (<400) and failure (>=400) observations of the same endpoint is
    a required-value constraint (role == "admin"). Only unambiguous
    single-valued keys are extracted."""
    if not observations:
        return []
    ok = [o for o in observations if int(o.get("status", 0)) < 400]
    bad = [o for o in observations if int(o.get("status", 0)) >= 400]
    if not ok or not bad:
        return []
    keys: set[str] = set()
    for o in ok + bad:
        keys |= set((o.get("context") or {}).keys())
    out: list[Constraint] = []
    for k in sorted(keys):
        ok_map = {repr((o.get("context") or {}).get(k)): (o.get("context") or {}).get(k) for o in ok}
        bad_reprs = {repr((o.get("context") or {}).get(k)) for o in bad}
        if len(ok_map) == 1 and set(ok_map) != bad_reprs:
            value = next(iter(ok_map.values()))
            out.append(_mk(k, "==", value, "string", "status_differential",
                           origin="status_differential", context=None,
                           expr=f'{k} == "{value}"' if isinstance(value, str) else f"{k} == {value}"))
    return out


# ------------------------------------------------------- expression parsing
_OPS = {ast.Gt: ">", ast.GtE: ">=", ast.Lt: "<", ast.LtE: "<=",
        ast.Eq: "==", ast.NotEq: "!="}
_COMPLEX_MARKERS = ("^", "**")
_POLY_RE = re.compile(r"f\s*\(\s*(\w+)\s*\)\s*=\s*(.+)")
_AND_SPLIT = re.compile(r"\s+AND\s+|\s+and\s+", re.I)


def _constraint_from_compare(node: ast.Compare, origin: str, context: dict | None) -> Constraint | None:
    """len(x) OP n / x OP n / x OP "s" / x == x (tautology) / y OP x (ref)."""
    left, right, op = node.left, node.comparators[0], _OPS.get(type(node.ops[0]))
    if op is None:
        return None
    if isinstance(left, ast.Call) and isinstance(left.func, ast.Name) and left.func.id == "len" \
            and len(left.args) == 1 and isinstance(left.args[0], ast.Name) \
            and isinstance(right, ast.Constant) and isinstance(right.value, (int, float)):
        var = left.args[0].id
        return _mk(var, op, right.value, "length", "expression", origin, context=context)
    if isinstance(left, ast.Name):
        var = left.id
        if isinstance(right, ast.Constant):
            v = right.value
            if isinstance(v, bool) or v is None:
                return None
            if isinstance(v, (int, float)):
                return _mk(var, op, v, "numeric", "expression", origin, context=context)
            if isinstance(v, str):
                if isinstance(right, ast.Name):  # unreachable; kept for clarity
                    return None
                return _mk(var, op, v, "string", "expression", origin, context=context)
        if isinstance(right, ast.Name):
            if right.id == var and op == "==":
                return _mk(var, "==", var, "tautology", "expression", origin,
                           expr=f"{var} == {var}", context=context)
            return _mk(var, op, right.id, "numeric_ref", "expression", origin,
                       expr=f"{var} {op} {right.id}", context=context)
    return None


def _constraint_from_call(node: ast.Call, origin: str, context: dict | None) -> Constraint | None:
    """x.startswith("s") / x.endswith("s") — Python-valid method-call form."""
    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) \
            and node.func.attr in ("startswith", "endswith") \
            and len(node.args) == 1 and isinstance(node.args[0], ast.Constant) \
            and isinstance(node.args[0].value, str):
        var, v = node.func.value.id, node.args[0].value
        return _mk(var, node.func.attr, v, "string", "expression", origin, context=context)
    return None


_WORD_STARTSWITH = re.compile(r'\s*(\w+)\s+startswith\s+"([^"]+)"')
_WORD_ENDSWITH = re.compile(r'\s*(\w+)\s+endswith\s+"([^"]+)"')


def parse_expression(expr: str, context: dict | None = None) -> list[Constraint]:
    """Parse one (possibly compound "A AND B") expression string. Every
    sub-constraint of a compound shares origin="compound:<full expr>" —
    the solver's distinction between a self-contradicting declaration
    ("contradiction") and an infeasible SET ("unsatisfiable") depends on it."""
    expr = (expr or "").strip()
    if not expr:
        return []
    parts = [p.strip() for p in _AND_SPLIT.split(expr) if p.strip()]
    origin = f"compound:{expr}" if len(parts) > 1 else "single"
    out: list[Constraint] = []
    for part in parts:
        out.extend(_parse_single(part, origin, context))
    return out


def _parse_single(part: str, origin: str, context: dict | None) -> list[Constraint]:
    # explicit polynomial form -> honestly out of solver scope
    poly = _POLY_RE.match(part)
    if poly:
        return [_mk(poly.group(1), "complex", poly.group(2), "complex", "expression", origin,
                    expr=part, context=context)]
    if any(m in part for m in _COMPLEX_MARKERS):
        return [_mk(part[:40], "complex", part, "complex", "expression", origin,
                    expr=part, context=context)]
    try:
        tree = ast.parse(part, mode="eval")
        node = tree.body
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            c = _constraint_from_compare(node, origin, context)
            return [c] if c else []
        if isinstance(node, ast.Call):
            c = _constraint_from_call(node, origin, context)
            return [c] if c else []
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
            got = []
            for v in node.values:
                if isinstance(v, ast.Compare) and len(v.ops) == 1:
                    c = _constraint_from_compare(v, origin, context)
                    if c:
                        got.append(c)
            return got
        return []
    except SyntaxError:
        pass
    # word-form fallbacks (not valid Python syntax)
    m = _WORD_STARTSWITH.match(part)
    if m:
        return [_mk(m.group(1), "startswith", m.group(2), "string", "expression", origin, context=context)]
    m = _WORD_ENDSWITH.match(part)
    if m:
        return [_mk(m.group(1), "endswith", m.group(2), "string", "expression", origin, context=context)]
    return []


def parse_constraints(text: str = "", observations: list[dict] | None = None,
                      context: dict | None = None) -> list[Constraint]:
    """RP-1 — the first registration point: extract constraints from an
    error-message body and/or status-code differential observations."""
    out = extract_from_error_message(text, context=context)
    out.extend(extract_from_status_codes(observations or []))
    return out

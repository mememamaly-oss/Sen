#!/usr/bin/env python3
"""HARDENING static guard (order 2026-10-15) — AST-level assertion that every
hardened Verification stamp in sentinel/intel.py passes the OBSERVED VARIABLE
into passed=, never the literal constant True. This is the red/green
discriminator of the differential: RED on the pre-fix code (the literal
passed=True sites), GREEN after the fix.

Usage: tb_hardening_static_guard.py"""
import ast
import sys

INTEL = "/home/z/my-project/build-v430/sentinel/intel.py"

# method string -> the observed variable that must appear in passed=
EXPECTED = {
    "oracle:replay-2round": "stable",            # sql PATH A
    "oracle:or-bodydiff-2round": "okD",          # sql PATH D
    "oracle:or-redirect-2round": "okC",          # sql PATH C
    "oracle:ornum-2round": "okC2",               # sql PATH C'
    "oracle:paren-or-bodydiff-2round": "okD2",   # sql PATH D2
    "oracle:existence-flip-2round": "okE",       # sql PATH E
    "re-test:fresh-hostile-origin": "ok_csrf",   # csrf
    "oracle:js-or-2round": "js_flip",            # nosql js-or
}


def passed_expr(call):
    for kw in call.keywords:
        if kw.arg == "passed":
            return kw.value
    return None


def main():
    tree = ast.parse(open(INTEL).read())
    found = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if not (isinstance(f, ast.Name) and f.id == "Verification"):
            continue
        mk = next((kw.value.value for kw in node.keywords
                   if kw.arg == "method" and isinstance(kw.value, ast.Constant)), None)
        if mk in EXPECTED:
            found.setdefault(mk, []).append(passed_expr(node))
    problems = []
    for method, var in EXPECTED.items():
        if method not in found:
            problems.append(f"{method}: no Verification call found")
            continue
        exprs = found[method]
        has_var = any(isinstance(e, ast.Name) and e.id == var for e in exprs)
        literal_true = [e for e in exprs if isinstance(e, ast.Constant) and e.value is True]
        if has_var and not literal_true:
            print(f"OK    {method:<38} passed={var} ({len(exprs)} call site(s))")
        elif literal_true:
            problems.append(f"{method}: passed= is the LITERAL True at "
                            f"{len(literal_true)} site(s) (expected the observed "
                            f"variable '{var}')")
        else:
            problems.append(f"{method}: passed= is "
                            f"{ast.dump(exprs[0])[:60]} (expected Name '{var}')")
    for p in problems:
        print("RED   " + p)
    print(f"\nstatic guard: {'GREEN (all 8 hardened)' if not problems else 'RED'} "
          f"({len(EXPECTED) - len(problems)}/{len(EXPECTED)} pass)")
    sys.exit(0 if not problems else 1)


if __name__ == "__main__":
    main()

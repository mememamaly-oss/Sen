#!/usr/bin/env python3
"""AXIS-18 (v4.3.0) — Symbolic Execution Engine. TDD suite (ORD-003).

M1 RED  : the 10 mandated failing tests (all fail pre-implementation —
          sentinel/symbolic does not exist yet) + 2 integration tests
          (flag-off zero-call proof, flag-on end-to-end proof).
M3 ATOMS: appended AFTER M2 GREEN (see the atom section below).

Semantic decisions documented here for the supervisor (design, not guesses):
  * "unsatisfiable"    = a SET of independently-declared constraints has an
                         empty numeric interval (no value satisfies all).
  * "contradiction"    = ONE compound declaration ("x > 5 AND x < 3" parsed as
                         a single expression) is infeasible against itself.
  * numeric solutions  = the MINIMAL SATISFYING INTEGER (age > 18 -> 19).
  * string solutions   = deterministic generation: (prefix|varname) + "123",
                         extended with the digit cycle "456789" until every
                         length bound holds (len(password)>=8 -> "password123";
                         startswith("admin") AND len>10 -> "admin123456").
  * bench-unchanged    : the structural bench x3 = (38,0,0,37) IDENTICAL gate
                         runs in M4 (results/axis18/); the in-suite case below
                         proves the WIRING is inert without --symbolic (zero
                         package invocations — bomb test — plus no stats key,
                         no report section).
Usage: python3 tests/test_axis18_symbolic.py  -> JSON verdict on the last line.
"""
import json, os, sys, threading, traceback

RESULTS = {"suite": "axis18", "total": 0, "failed": 0, "cases": []}


def case(fn):
    RESULTS["total"] += 1
    t0 = os.times().elapsed if hasattr(os.times(), "elapsed") else 0.0
    import time as _t; t0 = _t.time()
    try:
        fn()
        RESULTS["cases"].append({"name": fn.__name__, "ok": True, "ms": round((_t.time() - t0) * 1000)})
    except Exception as e:
        RESULTS["cases"].append({"name": fn.__name__, "ok": False,
                                 "ms": round((_t.time() - t0) * 1000),
                                 "error": f"{type(e).__name__}: {e}",
                                 "trace": traceback.format_exc()[-400:]})
        RESULTS["failed"] += 1
    return fn


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# pytest interop (their gate runs `pytest` over tests/): this suite executes
# at import under the house @case protocol — importing the module IS the run.
# The skip-marker keeps pytest from re-invoking the 10 test_* bodies a second
# time (double execution is harmless but wasteful and muddies the count);
# import-time failures still surface as pytest collection errors.
try:
    import pytest
    pytestmark = pytest.mark.skip(reason="AXIS-18 runs under its own @case protocol: "
                                         "python3 tests/test_axis18_symbolic.py")
except ImportError:
    pass


def _sym():
    """Lazy import — pre-implementation every case fails cleanly with
    ModuleNotFoundError (the M1 RED proof), post-implementation it binds."""
    import sentinel.symbolic
    return sentinel.symbolic


# ============================================================ helpers
# (defined BEFORE the @case tests — the runner executes cases at import)

class _MiniValAppHandler(__import__("http.server", fromlist=["BaseHTTPRequestHandler"]).BaseHTTPRequestHandler):
    """GET /register?password=X -> 400 'Error: password must be at least 8
    characters' when short, 200 'Welcome, validated user' otherwise. The
    guarded path (200) is exactly what a computed payload should activate."""

    def do_GET(self):
        import urllib.parse
        u = urllib.parse.urlsplit(self.path)
        if u.path == "/register":
            pw = (urllib.parse.parse_qs(u.query).get("password") or [""])[0]
            if len(pw) < 8:
                status, body = 400, "Error: password must be at least 8 characters"
            else:
                status, body = 200, "Welcome, validated user"
        else:
            status, body = 404, "not found"
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def _with_mini_app(fn):
    import http.server
    srv = http.server.HTTPServer(("127.0.0.1", 0), _MiniValAppHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        fn(f"http://127.0.0.1:{srv.server_port}")
    finally:
        srv.shutdown()
        srv.server_close()


def _scan_mini_app(symbolic: bool) -> dict:
    """Full SentinelScanner pass over a local validation app (the exact
    error message the order mandates) with the flag on/off."""
    from sentinel.orchestrator import SentinelScanner, ScanConfig
    rep = {}

    def run(base: str):
        cfg = ScanConfig(allow_private=True, max_pages=2, crawl=False, active=False,
                         browser=False, openapi=False, secrets=False, graphql=False,
                         websocket=False, workflow=False, logic_active=False,
                         symbolic=symbolic)
        rep.update(SentinelScanner(base + "/register?password=ab", cfg).run())

    _with_mini_app(run)
    return rep


def _render_report_html(rep: dict) -> str:
    from sentinel.report import build_html
    from sentinel.store import Store
    import tempfile
    st = Store(os.path.join(tempfile.mkdtemp(), "t.db"))
    st.save_run(rep)
    return build_html(st, rep["run_id"])


# ============================================================ M1 RED (ORD-003)

@case
def test_symbolic_module_exists():
    sym = _sym()
    # the four registration points (the ONLY core->symbolic coupling surface)
    for attr in ("parse_constraints", "solve_constraints", "generate_payload",
                 "verify_and_sign"):
        assert hasattr(sym, attr), f"registration point missing: {attr}"
    assert len(sym.REGISTRATION_POINTS) == 4, sym.REGISTRATION_POINTS
    assert set(sym.REGISTRATION_POINTS) == {"parse_constraints", "solve_constraints",
                                            "generate_payload", "verify_and_sign"}


@case
def test_constraint_extraction_from_error_message():
    sym = _sym()
    cons = sym.parse_constraints(text="Error: password must be at least 8 characters")
    assert cons, "no constraints extracted"
    assert any(c.expr == "len(password) >= 8" for c in cons), [c.expr for c in cons]


@case
def test_constraint_extraction_from_status_codes():
    sym = _sym()
    obs = [{"status": 200, "context": {"role": "admin"}},
           {"status": 403, "context": {"role": "user"}}]
    cons = sym.parse_constraints(observations=obs)
    assert any(c.expr == 'role == "admin"' for c in cons), [c.expr for c in cons]


@case
def test_simple_constraint_solving():
    sym = _sym()
    res = sym.solve_constraints(sym.parse_expression("age > 18"))
    assert res["status"] == "solved", res
    assert res["solutions"]["age"].value == 19, res["solutions"]


@case
def test_text_constraint_solving():
    sym = _sym()
    res = sym.solve_constraints(sym.parse_expression("len(password) >= 8"))
    assert res["status"] == "solved", res
    v = res["solutions"]["password"].value
    assert isinstance(v, str) and len(v) >= 8, v


@case
def test_payload_generation():
    sym = _sym()
    res = sym.solve_constraints(sym.parse_expression('username == "admin"'))
    assert res["status"] == "solved", res
    payload, blocked = sym.generate_payload(res["solutions"])
    assert payload.get("username") == "admin", payload
    assert "username" not in blocked, blocked


@case
def test_destructive_solution_blocked():
    sym = _sym()
    res = sym.solve_constraints(sym.parse_expression('mode == "delete_all"'))
    payload, blocked = sym.generate_payload(res["solutions"])
    assert "mode" in blocked and "mode" not in payload, (payload, blocked)
    from sentinel.symbolic.gates import gate_solution
    from sentinel.symbolic.models import Solution
    verdict = gate_solution(Solution(var="mode", value="delete_all"))
    assert verdict["allowed"] is False and "destructive" in verdict["reason"].lower(), verdict


@case
def test_result_serialization():
    sym = _sym()
    from sentinel.symbolic.models import Constraint, SymbolicResult
    r = SymbolicResult(constraints=[Constraint(var="password", op=">=", value=8,
                                               kind="length", expr="len(password) >= 8")])
    d = r.to_dict()
    for key in ("constraint", "solution", "payload", "path",
                "evidence_chain", "honest_boundary"):
        assert key in d, f"serialized result missing key: {key}"


@case
def test_no_engine_import():
    """sentinel/symbolic/ must never import core-engine modules directly —
    the package communicates ONLY through the four registration points
    (dependency inversion: the engine injects senders/gates as callables)."""
    import ast, pathlib
    pkg = pathlib.Path(__file__).resolve().parent.parent / "sentinel" / "symbolic"
    assert pkg.is_dir(), f"package dir missing: {pkg}"
    offenders = []
    for py in sorted(pkg.glob("*.py")):
        tree = ast.parse(py.read_text(), filename=str(py))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.level >= 2:                       # from ..core import X
                    offenders.append(f"{py.name}:{node.lineno} relative-parent import")
                elif node.level == 0 and node.module and node.module.split(".")[0] == "sentinel":
                    offenders.append(f"{py.name}:{node.lineno} absolute sentinel import")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] == "sentinel":
                        offenders.append(f"{py.name}:{node.lineno} import sentinel.*")
    assert not offenders, offenders


@case
def test_bench_unchanged():
    """Without --symbolic the feature is DEAD CODE: ScanConfig default False,
    zero package invocations (bomb test), no stats key, no report section.
    The structural bench x3 = (38,0,0,37) IDENTICAL gate runs in M4 and its
    artifacts land in results/axis18/."""
    from sentinel.orchestrator import ScanConfig
    assert ScanConfig().symbolic is False, "symbolic must default to disabled"
    sym = _sym()
    orig = sym.run_symbolic_analysis

    def _bomb(*a, **k):
        raise AssertionError("sentinel.symbolic invoked without --symbolic")

    sym.run_symbolic_analysis = _bomb
    try:
        rep = _scan_mini_app(symbolic=False)
    finally:
        sym.run_symbolic_analysis = orig
    assert "symbolic" not in (rep.get("stats") or {}), "symbolic stats leaked without the flag"
    html = _render_report_html(rep)
    assert "Symbolic Execution" not in html, "symbolic report section leaked without the flag"


# ============================================================ integration

@case
def integ_symbolic_flag_off_zero_calls():
    """Flag OFF: full scan of the validation app — the package is never
    invoked (proven by the bomb) and nothing symbolic appears anywhere."""
    sym = _sym()
    orig = sym.run_symbolic_analysis

    def _bomb(*a, **k):
        raise AssertionError("run_symbolic_analysis called with the flag OFF")

    sym.run_symbolic_analysis = _bomb
    try:
        rep = _scan_mini_app(symbolic=False)
    finally:
        sym.run_symbolic_analysis = orig
    assert "symbolic" not in (rep.get("stats") or {})


@case
def integ_symbolic_flag_on_end_to_end():
    """Flag ON: the full four-phase chain fires against the live mini app —
    extraction (len(password) >= 8) -> solving (>= 8 chars) -> gated payload
    -> verification send (400 -> 200 = activated) -> signed result -> stats
    -> report section present."""
    sym = _sym()
    rep = _scan_mini_app(symbolic=True)
    st = rep.get("stats", {}).get("symbolic") or {}
    assert st.get("enabled") is True, st
    assert st.get("constraints_extracted", 0) >= 1, st
    assert st.get("solved", 0) >= 1, st
    results = st.get("results") or []
    assert results, "no symbolic results recorded"
    hit = [r for r in results if r.get("constraint") and "len(password)" in str(r["constraint"])]
    assert hit, [r.get("constraint") for r in results]
    r = hit[0]
    assert r.get("payload", {}).get("password") and len(r["payload"]["password"]) >= 8, r
    assert r.get("verified") == "activated", r
    assert r.get("signature") and r["signature"].get("ed25519"), r
    html = _render_report_html(rep)
    assert "Symbolic Execution" in html, "report section missing with the flag ON"
    # external verifiability: the signature checks out against the EMBEDDED key
    from sentinel.symbolic.models import verify_result_signature
    assert verify_result_signature(r) is True, "signature failed external verification"


# ============================================================ M3 ATOMS
# (appended AFTER M2 GREEN per ORD-003; hostile/adversarial inputs)

@case
def atom_symbolic_unsatisfiable_constraint():
    """An infeasible SET of independently-declared constraints (x > 10 with
    x < 5) answers the honest boundary 'unsatisfiable' — never a guess."""
    sym = _sym()
    res = sym.solve_constraints([sym.parse_expression("x > 10")[0],
                                 sym.parse_expression("x < 5")[0]])
    assert res["status"] == "boundary", res
    assert res["boundary"] == "unsatisfiable", res
    assert not res["solutions"], res


@case
def atom_symbolic_complex_constraint():
    """Non-linear arithmetic (a cubic) is honestly out of the stdlib
    solver's scope — 'complex_solver_unavailable', no root guessing."""
    sym = _sym()
    res = sym.solve_constraints(sym.parse_expression("f(x) = x^3 + 2x^2 - 5x + 1 == 0"))
    assert res["status"] == "boundary", res
    assert res["boundary"] == "complex_solver_unavailable", res


@case
def atom_symbolic_tautology():
    """x == x constrains nothing: boundary 'tautology' + any-value solution."""
    sym = _sym()
    res = sym.solve_constraints(sym.parse_expression("x == x"))
    assert res["boundary_by_var"].get("x") == "tautology", res
    assert "x" in res["solutions"] and res["solutions"]["x"].method == "any_value", res


@case
def atom_symbolic_contradiction():
    """ONE compound declaration defeating itself ("x > 5 AND x < 3" parsed
    as a single expression) is labeled 'contradiction' — distinct from an
    infeasible SET (see atom_symbolic_unsatisfiable_constraint)."""
    sym = _sym()
    res = sym.solve_constraints(sym.parse_expression("x > 5 AND x < 3"))
    assert res["status"] == "boundary", res
    assert res["boundary"] == "contradiction", res
    assert not res["solutions"], res


@case
def atom_symbolic_nested_constraints():
    """Cross-variable references resolve in dependency order: x > 5, y < x,
    y > 0 -> the minimal satisfying integers x=6, y=1."""
    sym = _sym()
    res = sym.solve_constraints([sym.parse_expression("x > 5")[0],
                                 sym.parse_expression("y < x")[0],
                                 sym.parse_expression("y > 0")[0]])
    assert res["status"] == "solved", res
    assert res["solutions"]["x"].value == 6, res["solutions"]
    assert res["solutions"]["y"].value == 1, res["solutions"]


@case
def atom_symbolic_string_constraints():
    """String generation satisfies every bound deterministically:
    username startswith "admin" AND len(username) > 10 -> "admin123456"."""
    sym = _sym()
    res = sym.solve_constraints(sym.parse_expression('username startswith "admin"')
                                + [sym.parse_expression("len(username) > 10")[0]])
    assert res["status"] == "solved", res
    v = res["solutions"]["username"].value
    assert v == "admin123456", v
    assert v.startswith("admin") and len(v) > 10


@case
def atom_symbolic_no_false_positive():
    """A computed payload that satisfies the EXTRACTED constraint but does
    NOT open the guarded path is reported 'not_activated' — never a
    vulnerability. (Hidden second gate: the app demands admin regardless.)"""
    sym = _sym()
    src = [{"url": "http://t/transfer", "method": "GET",
            "text": "Error: amount must be greater than 100", "status": 400}]

    def sender(m):
        # the extracted constraint is satisfied (amount=101) but a second,
        # unmodeled gate (role check) still refuses: same error family, 403
        return {"status": 403, "body": "Error: user must be admin", "error": ""}

    res = sym.run_symbolic_analysis(src, sender=sender, seed="atom7")
    s = sym.summarize(res, sources=1)
    assert s["solved"] == 1 and s["constraints_extracted"] == 1, s
    assert s["verified_activated"] == 0, s
    assert s["not_activated"] == 1, s
    r = s["results"][0]
    assert r["payload"] and int(r["payload"]["amount"]) > 100, r
    assert r["verified"] == "not_activated", r


@case
def atom_symbolic_report_signature():
    """Every result is signed (Merkle root + Ed25519, RFC 8032, stdlib) and
    externally verifiable with the EMBEDDED public key; tampering any signed
    field, any evidence digest, the root, or the signature itself fails."""
    sym = _sym()
    from sentinel.symbolic.models import verify_result_signature
    src = [{"url": "http://t/register?password=ab", "method": "GET",
            "text": "Error: password must be at least 8 characters", "status": 400}]

    def sender(m):
        pw = m["params"].get("password", "")
        ok = len(pw) >= 8
        return {"status": 200 if ok else 400,
                "body": "Welcome" if ok else "Error: password must be at least 8 characters",
                "error": ""}

    res = sym.run_symbolic_analysis(src, sender=sender, seed="atom8")
    s = sym.summarize(res, sources=1)
    d = s["results"][0]
    sig = d["signature"]
    assert sig["algo"] == "ed25519-sha512-merkle", sig
    assert len(sig["merkle_root"]) == 64 and len(sig["ed25519"]) == 128, sig
    assert verify_result_signature(d) is True, "valid signature failed"
    # hostile tampering, one field at a time — every variant must fail
    import copy
    for mutate in (
        lambda x: x["payload"].update({"password": "tampered"}),
        lambda x: x["solution"].update({"value": "tampered"}),
        lambda x: x["evidence_chain"].__setitem__(0, "00" * 32),
        lambda x: x["signature"].__setitem__("merkle_root", "00" * 32),
        lambda x: x["signature"].__setitem__("ed25519", "00" * 64),
        lambda x: x.update({"verified": "not_activated"}),
    ):
        bad = copy.deepcopy(d)
        mutate(bad)
        assert verify_result_signature(bad) is False, \
            f"tampering not caught: {mutate.__code__.co_consts}"


def main():
    RESULTS["passed"] = RESULTS["failed"] == 0
    print(json.dumps(RESULTS, indent=1))
    sys.exit(0 if RESULTS["passed"] else 1)


if __name__ == "__main__":
    main()

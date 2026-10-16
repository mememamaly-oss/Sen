#!/usr/bin/env python3
"""HARDENING differential battery (order 2026-10-15) — behavioral scenarios for
every branch whose Verification stamp is being hardened from the literal
`passed=True` to the observed variable itself:

  sql PATH A  oracle:replay-2round            -> stable
  sql PATH D  oracle:or-bodydiff-2round       -> okD
  sql PATH C  oracle:or-redirect-2round       -> okC
  sql PATH C' oracle:ornum-2round             -> okC2
  sql PATH D2 oracle:paren-or-bodydiff-2round -> okD2
  sql PATH E  oracle:existence-flip-2round    -> okE
  csrf        re-test:fresh-hostile-origin    -> ok_csrf
  nosql js-or oracle:js-or-2round             -> js_flip

For each branch: a TRUE scenario (the observation holds -> the branch stamps
VERIFIED) and the fall-through scenarios (the observation fails -> the verdict
comes from the next path / the honest reject). The battery output must be
IDENTICAL before and after the hardening edit — every case migrates to the
same correct value (the stamp change is behavior-preserving by construction,
because the guard IS the observation).

Usage: tb_hardening_battery.py <out.json>"""
import json
import sys

sys.path.insert(0, "/home/z/my-project/build-v430")
from sentinel.core import (Endpoint, EventBus, Evidence, Finding, ParamKind,
                           ParamLocation, Parameter)
from sentinel.intel import VerificationEngine


class R:
    """Fake Response — the http_engine.Response surface verify() touches."""
    def __init__(self, status=200, body="", error=False, location=""):
        self.status, self.body, self.error = status, body, error
        self.ok = 200 <= status < 300
        self.request_id = "fake"
        self.redirect_chain = []
        self._loc = location

    def hop_location(self):
        return self._loc


class Scripted:
    """FakeEngine — responses keyed by (note, param_value)."""
    def __init__(self, script, default=None):
        self.script = script
        self.default = default or R(200, "x" * 50)
        self.sent = []

    def send(self, m):
        self.sent.append((m.note, m.param_name, m.param_value))
        for (note, val), r in self.script.items():
            if (m.note or "") == note and (m.param_value or "") == val:
                return r
        return self.default


def run(engine, f, ep):
    ve = VerificationEngine(engine, EventBus("hardening-battery"))
    out = ve.verify(f, ep)
    return {"status": out.status.value,
            "method": out.verification.method,
            "passed": bool(out.verification.passed),
            "confidence": round(out.confidence, 2)}


def sql_finding():
    return Finding(type="sql_injection", endpoint_url="https://t.local/sqli",
                   parameter="p", method="POST",
                   evidence=[Evidence("status_oracle", "hardening battery")])


def sql_ep():
    return Endpoint(url="https://t.local/sqli", method="POST",
                    parameters=[Parameter("p", ParamLocation.BODY, "1").classify()])


B = 2000 * "z"   # big body
S = 100 * "y"    # small body

SCENARIOS = {
    # ---- sql PATH A: boolean oracle replay (blind) ----
    "sql-A-TRUE": Scripted({
        ("", "1 AND 1=1"): R(200, B), ("", "1 AND 1=2"): R(500, "err")}),
    # ---- sql PATH D: fresh OR-pair body differential ----
    "sql-D-TRUE": Scripted({
        ("", "1' OR '2'>'1' -- "): R(200, B), ("", "1' OR '1'>'2' -- "): R(200, S)}),
    # ---- sql PATH C: OR-tautology redirect differential ----
    "sql-C-TRUE": Scripted({
        ("", "1' OR '1'='1' -- "): R(200, "ok", location="/home"),
        ("", "1' OR '1'='2' -- "): R(200, "ok", location="/away")}),
    # ---- sql PATH C': numeric-tautology redirect differential ----
    "sql-Cp-TRUE": Scripted({
        ("", "1' OR 1=1-- "): R(200, "ok", location="/a"),
        ("", "1' OR 1=2-- "): R(200, "ok", location="/b")}),
    # ---- sql PATH D2: paren-closing fresh OR pair ----
    "sql-D2-TRUE": Scripted({
        ("", "1')) OR '2'>'1' -- "): R(200, B), ("", "1')) OR '1'>'2' -- "): R(200, S)}),
    # ---- sql PATH E: no-base OR existence flip ----
    "sql-E-TRUE": Scripted({
        ("", "1"): R(200, "base"), ("", "' OR '2'>'1' -- "): R(200, "exists"),
        ("", "' OR '1'>'2' -- "): R(404, "missing")}),
    # ---- everything fails -> PATH B honest reject (already variable-driven) ----
    "sql-ALLFALSE-B-REJECT": Scripted({}),
    # ---- csrf: cross-origin accepted + input-discriminating ----
    "csrf-TRUE": Scripted({
        ("csrf-verify-baseline", ""): R(200, "b" * 500),
        ("csrf-verify", ""): R(200, "b" * 500),
        ("csrf-verify-control", ""): R(400, "bad input")}),
    # ---- csrf: reproduced acceptance but NO input discrimination -> CANDIDATE ----
    "csrf-NODISCRIM-CANDIDATE": Scripted({
        ("csrf-verify-baseline", ""): R(200, "b" * 500),
        ("csrf-verify", ""): R(200, "b" * 500),
        ("csrf-verify-control", ""): R(200, "b" * 500)}),
    # ---- nosql js-or: the JS-evaluation flip reproduces ----
    "nosql-JSOR-TRUE": Scripted({
        ("", "1' || '2'>'1"): R(200, "rows"), ("", "1' && '1'>'2"): R(404, "none")}),
    # ---- nosql js-or: no flip, no mongo error -> honest reject ----
    "nosql-JSOR-FALSE-REJECT": Scripted({}),
}

EXPECT = {
    "sql-A-TRUE":      ("verified", "oracle:replay-2round", True),
    "sql-D-TRUE":      ("verified", "oracle:or-bodydiff-2round", True),
    "sql-C-TRUE":      ("verified", "oracle:or-redirect-2round", True),
    "sql-Cp-TRUE":     ("verified", "oracle:ornum-2round", True),
    "sql-D2-TRUE":     ("verified", "oracle:paren-or-bodydiff-2round", True),
    "sql-E-TRUE":      ("verified", "oracle:existence-flip-2round", True),
    "sql-ALLFALSE-B-REJECT": ("rejected", "error:replay-2variants", False),
    "csrf-TRUE":       ("verified", "re-test:fresh-hostile-origin", True),
    "csrf-NODISCRIM-CANDIDATE": ("candidate", "unverified:no-input-discrimination", False),
    "nosql-JSOR-TRUE": ("verified", "oracle:js-or-2round", True),
    "nosql-JSOR-FALSE-REJECT": ("rejected", "error:mongo-replay-2variants", False),
}


def main():
    out_path = sys.argv[1]
    results = {}
    ok_all = True
    for name, engine in SCENARIOS.items():
        if name.startswith("csrf"):
            f = Finding(type="csrf", endpoint_url="https://t.local/csrf",
                        parameter="amount", method="POST",
                        evidence=[Evidence("no_token", "hardening battery")])
            ep = Endpoint(url="https://t.local/csrf", method="POST",
                          parameters=[Parameter("amount", ParamLocation.BODY, "5").classify()])
        elif name.startswith("nosql"):
            f = Finding(type="nosql_injection", endpoint_url="https://t.local/alloc",
                        parameter="threshold", method="GET",
                        evidence=[Evidence("js_or_differential", "hardening battery")])
            ep = Endpoint(url="https://t.local/alloc", method="GET",
                          parameters=[Parameter("threshold", ParamLocation.QUERY, "1").classify()])
        else:
            f, ep = sql_finding(), sql_ep()
        try:
            r = run(engine, f, ep)
        except Exception as e:
            r = {"status": "EXCEPTION", "method": f"{type(e).__name__}: {e}",
                 "passed": None, "confidence": 0.0}
        exp = EXPECT[name]
        match = (r["status"], r["method"], r["passed"]) == exp
        ok_all &= match
        results[name] = {"got": r, "expect": {"status": exp[0], "method": exp[1],
                                              "passed": exp[2]}, "match": match}
        print(f"{'PASS' if match else 'FAIL'}  {name:<28} -> {r['status']:<10} "
              f"{r['method']:<38} passed={r['passed']}")
    print(f"\nbattery verdict: {'ALL MATCH' if ok_all else 'MISMATCH'} "
          f"({sum(1 for v in results.values() if v['match'])}/{len(results)})")
    json.dump(results, open(out_path, "w"), indent=1)
    print("saved:", out_path)
    sys.exit(0 if ok_all else 1)


if __name__ == "__main__":
    main()

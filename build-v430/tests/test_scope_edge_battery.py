#!/usr/bin/env python3
"""SENTINEL scope-gate edge battery — _scope_ok domain-matching boundaries.

Standalone by design (same discipline as the axis suites): NOT registered as
@case in run_tests.py, so the core suite contract (227 registered x 19 chunks
= 4313) stays byte-identical while this battery runs as its own standing gate
item (supervisor order 2026-10-16, step 4 item 4).

PROVENANCE (step 1 of the same order — live diagnostic, raw evidence):
run on the as-is disk gate (sentinel/http_engine.py sha256 53b36c404cfeb3cf
e4adb73c1f2ea48a2e1db3f000cfcdc1c3c9c34b042dd74e), the three ordered probes
returned False under BOTH scope shapes:
    _scope_ok('https://nottestfire.net/x')            -> False
    _scope_ok('https://eviltestfire.net/x')           -> False
    _scope_ok('https://demo.testfire.net.attacker.com/x') -> False
=> NO VULNERABILITY: the gate already enforces the dot boundary
   (host == d or host.endswith("." + d), http_engine.py:362-365).
   Production code was NOT touched ("do not fix what is not broken").
   This battery LOCKS that state so any future regression of the class is
   caught automatically on every run.

Coverage contract (the supervisor's ordered three + their opposite, then the
same-class family locks):
  C01  probe 1 — suffix-string collision host 'nottestfire.net' REJECTED
       under BOTH shapes (A: allowed=['demo.testfire.net'] the
       orchestrator.py:117 default; B: allowed=['testfire.net'] the
       registered-domain form — the shape a bare endswith() would betray)
  C02  probe 2 — suffix-string collision host 'eviltestfire.net' REJECTED
       (both shapes)
  C03  probe 3 — suffix-embedded attacker domain
       'demo.testfire.net.attacker.com' REJECTED (both shapes) + the
       same-class variants sub.demo.testfire.net.attacker.com and
       demo.testfire.net.evil.invalid
  C04  THE OPPOSITE (the ordered counter-case) — legitimate subdomains stay
       ACCEPTED: demo.testfire.net + sub.demo.testfire.net +
       a.b.demo.testfire.net under shape A; testfire.net + www.testfire.net
       under shape B. A regression here (over-tight gate) is caught too.
  C05  same-class typosquat family (the phase-0 T4 set, now permanent):
       o->0, i->1, truncated TLD, dot->hyphen, substring host, prefix-embedded
       (+ the semantic boundary the battery's own first run caught: under
       shape B, <anything>.testfire.net is a GENUINE subdomain of the allowed
       registered zone and stays accepted — v1 wrongly expected rejection
       there; the gate was right, the v1 expectation was not; boundary now
       locked as a must_accept)
  C06  allowed_hosts exact-membership semantics (the other half of the same
       host-matching logic, OWSP-22's independent-gate fix): exact members
       pass, non-members and would-be 'sub.<member>' do NOT (hosts list is
       exact identity, never suffix)

--red-proof: differential sabotage mode. Two deliberately broken gates are
monkeypatched IN-PROCESS ONLY (the production file is never modified):
  sabotage A = bare host.endswith(d)   (no dot boundary)
  sabotage B = substring (d in host)
The mode exits 0 iff EACH sabotage is caught by >= 1 battery case (i.e. the
battery provably detects the exact bug forms the order hypothesized). This is
the RED half of the differential: GREEN battery on real code + RED detection
on sabotaged code = the lock actually holds.

Usage: python3 tests/test_scope_edge_battery.py [--out results/scope_edge/battery_GREEN.json]
       python3 tests/test_scope_edge_battery.py --red-proof [--out results/scope_edge/battery_REDPROOF.json]
"""
import argparse
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.core import EventBus, ScopeRule        # noqa: E402
from sentinel.http_engine import RequestEngine       # noqa: E402

SHAPE_A = ["demo.testfire.net"]   # orchestrator.py:117 default for the target
SHAPE_B = ["testfire.net"]        # registered-domain form


def engine_for(allowed_domains):
    return RequestEngine(ScopeRule(allowed_domains=list(allowed_domains)),
                         EventBus("scope-edge-battery"), timeout=5.0)


ENG_A = engine_for(SHAPE_A)
ENG_B = engine_for(SHAPE_B)


def must_reject(eng, url, why):
    ok, reason = eng._scope_ok(url)
    assert not ok, f"VULNERABLE: {url} was ACCEPTED by {why} ({reason!r})"


def must_accept(eng, url, why):
    ok, reason = eng._scope_ok(url)
    assert ok, f"OVER-TIGHT: legitimate {url} was REJECTED by {why} ({reason!r})"


# ---- the battery: name -> callable (ordered case list) ----------------------

def c01_probe1_nottestfire():
    """The ordered probe 1: a different registered domain that shares the
    'testfire.net' SUFFIX STRING must be refused under both scope shapes."""
    must_reject(ENG_A, "https://nottestfire.net/x", "shape A [demo.testfire.net]")
    must_reject(ENG_B, "https://nottestfire.net/x", "shape B [testfire.net]")


def c02_probe2_eviltestfire():
    """The ordered probe 2: 'eviltestfire.net' — same suffix-collision class."""
    must_reject(ENG_A, "https://eviltestfire.net/x", "shape A [demo.testfire.net]")
    must_reject(ENG_B, "https://eviltestfire.net/x", "shape B [testfire.net]")


def c03_probe3_suffix_embedded_attacker():
    """The ordered probe 3 (reverse-direction confirm): the target hostname
    embedded inside an ATTACKER domain must be refused — plus the same-class
    variants (deeper subdomain of the attacker domain; .invalid TLD)."""
    for url in ("https://demo.testfire.net.attacker.com/x",
                "https://sub.demo.testfire.net.attacker.com/x",
                "https://demo.testfire.net.evil.invalid/x"):
        must_reject(ENG_A, url, "shape A [demo.testfire.net]")
        must_reject(ENG_B, url, "shape B [testfire.net]")


def c04_legitimate_subdomains_stay_accepted():
    """The ordered OPPOSITE (the counter-case): genuine subdomains of the
    allowed domain must REMAIN accepted — the fix class must never
    over-tighten into refusing the target's own tree."""
    for url in ("https://demo.testfire.net/bank/main.jsp",
                "https://sub.demo.testfire.net/bank/main.jsp",
                "https://a.b.demo.testfire.net/x"):
        must_accept(ENG_A, url, "shape A [demo.testfire.net]")
    for url in ("https://testfire.net/x",
                "https://www.testfire.net/x"):
        must_accept(ENG_B, url, "shape B [testfire.net]")


def c05_typosquat_family():
    """Same-class family lock (the phase-0 T4 set, now permanent): character
    substitutions and boundary tricks against the target hostname."""
    must_reject(ENG_A, "https://dem0.testfire.net/x", "o->0")
    must_reject(ENG_A, "https://demo.testf1re.net/x", "i->1")
    must_reject(ENG_A, "https://demo.testfire.ne/x", "truncated TLD")
    must_reject(ENG_A, "https://demo-testfire.net/x", "dot->hyphen")
    must_reject(ENG_A, "https://evildemo.testfire.net/x", "substring host")
    must_reject(ENG_A, "https://xdemo.testfire.net/x", "prefix-embedded")
    # SEMANTIC BOUNDARY (caught by the battery's own first run — the v1
    # expectation here was wrong, the gate was right): under shape B the
    # whole REGISTERED ZONE testfire.net is allowed, so evildemo.testfire.net
    # is a GENUINE subdomain of the allowed zone and MUST be accepted. The
    # suffix-collision attack class is hosts whose own registered domain
    # DIFFERS (nottestfire.net / eviltestfire.net — C01/C02), never
    # oddly-named subdomains inside the allowed zone.
    must_accept(ENG_B, "https://evildemo.testfire.net/x",
                "genuine subdomain of the allowed registered domain (shape B)")
    must_reject(ENG_B, "https://testfire.net.evil.invalid/x", "suffix-embedded, shape B")


def c06_allowed_hosts_exact_membership():
    """The other half of the same host-matching logic: allowed_hosts is EXACT
    identity (OWSP-22's independent gate) — members pass, non-members fail,
    and 'sub.<member>' is NOT a member (suffix semantics belong to
    allowed_domains only)."""
    eng = RequestEngine(ScopeRule(allowed_hosts=["a.local"], allow_private=True),
                        EventBus("scope-edge-battery-h"), timeout=5.0)
    must_accept(eng, "http://a.local/x", "allowed_hosts exact member")
    must_reject(eng, "http://b.local/x", "allowed_hosts non-member")
    must_reject(eng, "http://sub.a.local/x", "allowed_hosts is never suffix")


BATTERY = [
    ("c01_probe1_nottestfire", c01_probe1_nottestfire),
    ("c02_probe2_eviltestfire", c02_probe2_eviltestfire),
    ("c03_probe3_suffix_embedded_attacker", c03_probe3_suffix_embedded_attacker),
    ("c04_legitimate_subdomains_stay_accepted", c04_legitimate_subdomains_stay_accepted),
    ("c05_typosquat_family", c05_typosquat_family),
    ("c06_allowed_hosts_exact_membership", c06_allowed_hosts_exact_membership),
]

# probe set the red-proof saboteurs must be caught by (url, shape-engine)
DETECTION_PROBES = [
    ("https://nottestfire.net/x", ENG_B, "shape B"),
    ("https://eviltestfire.net/x", ENG_B, "shape B"),
    ("https://demo.testfire.net.attacker.com/x", ENG_A, "shape A"),
    ("https://demo.testfire.net.attacker.com/x", ENG_B, "shape B"),
    ("https://evildemo.testfire.net/x", ENG_A, "shape A"),
]


def sabotage_bare_endswith(eng, url):
    """Saboteur A — the exact hypothesized bug: bare suffix, no dot boundary."""
    import urllib.parse
    p = urllib.parse.urlsplit(url)
    host = p.hostname or ""
    if p.scheme not in eng.scope.allowed_schemes:
        return False, "scheme"
    ok = any(host == d or host.endswith(d) for d in eng.scope.allowed_domains)
    return (ok, "" if ok else "host outside allowed set")


def sabotage_substring(eng, url):
    """Saboteur B — the substring bug form: 'allowed in host'."""
    import urllib.parse
    p = urllib.parse.urlsplit(url)
    host = p.hostname or ""
    if p.scheme not in eng.scope.allowed_schemes:
        return False, "scheme"
    ok = any(d in host or host in d for d in eng.scope.allowed_domains)
    return (ok, "" if ok else "host outside allowed set")


def run_red_proof():
    """Differential RED half: each saboteur must be caught by >= 1 probe.
    Catches = the saboteur WRONGLY ACCEPTS a probe the real gate rejects."""
    results = []
    all_caught = True
    for name, sab in (("bare_endswith", sabotage_bare_endswith),
                      ("substring", sabotage_substring)):
        caught_by = []
        for url, eng, shape in DETECTION_PROBES:
            real_ok, _ = eng._scope_ok(url)
            sab_ok, _ = sab(eng, url)
            if real_ok is False and sab_ok is True:
                caught_by.append(url)
        caught = bool(caught_by)
        all_caught = all_caught and caught
        results.append({"saboteur": name, "caught": caught,
                        "wrongly_accepted": caught_by})
        print(f"{'CAUGHT' if caught else 'MISSED '} saboteur {name}: "
              f"{len(caught_by)} probe(s) wrongly accepted "
              f"(battery detects this bug form: {caught})")
    # and the legitimate-subdomain guard must NOT be a saboteur victim:
    # (a correct-behaving gate keeps accepting the target tree — the
    # saboteurs here are LOOSER than the real gate, so controls still pass;
    # recorded for completeness, not a pass condition)
    for url, eng, shape in (("https://sub.demo.testfire.net/x", ENG_A, "A"),
                            ("https://www.testfire.net/x", ENG_B, "B")):
        sab_ok, _ = sabotage_bare_endswith(eng, url)
        results.append({"saboteur": "bare_endswith-control", "url": url,
                        "still_accepted": bool(sab_ok)})
    return all_caught, results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    ap.add_argument("--red-proof", action="store_true",
                    help="run the in-process sabotage differential instead of "
                         "the GREEN battery")
    args = ap.parse_args()

    if args.red_proof:
        out = args.out or "results/scope_edge/battery_REDPROOF.json"
        t0 = time.monotonic()
        all_caught, results = run_red_proof()
        report = {"suite": "scope-edge-battery-redproof",
                  "mode": "red-proof (in-process saboteurs; production file untouched)",
                  "all_saboteurs_caught": all_caught, "saboteurs": results,
                  "dur_s": round(time.monotonic() - t0, 4)}
        os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
        with open(out, "w") as fh:
            json.dump(report, fh, indent=1)
        print(f"red-proof: all saboteurs caught = {all_caught} -> {out}")
        sys.exit(0 if all_caught else 1)

    out = args.out or "results/scope_edge/battery_GREEN.json"
    cases = []
    for name, fn in BATTERY:
        entry = {"name": name, "ok": False}
        t0 = time.monotonic()
        try:
            fn()
            entry["ok"] = True
        except Exception as e:  # noqa: BLE001 — record every failure mode
            entry["error"] = f"{type(e).__name__}: {e}"[:400]
        entry["dur_s"] = round(time.monotonic() - t0, 4)
        cases.append(entry)
        print(("PASS " if entry["ok"] else "FAIL ") + entry["name"]
              + ("" if entry["ok"] else f"  -> {entry.get('error')}"))
    failed = sum(1 for c in cases if not c["ok"])
    digest = hashlib.sha256(json.dumps(
        [{"name": c["name"], "ok": c["ok"]} for c in cases],
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    report = {"suite": "scope-edge-battery",
              "ordered_probes": ["nottestfire.net", "eviltestfire.net",
                                 "demo.testfire.net.attacker.com"],
              "total": len(cases), "failed": failed, "passed": failed == 0,
              "cases": cases, "digest": digest}
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w") as fh:
        json.dump(report, fh, indent=1)
    print(f"scope-edge-battery: {len(cases) - failed}/{len(cases)} passed "
          f"(failed={failed}) digest={digest[:16]} -> {out}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()

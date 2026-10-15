#!/usr/bin/env python3
"""SENTINEL Axis-2 suite — Formal State Machine (spec §2.1–§2.8).

Standalone by design (same discipline as Axis-1): NOT registered as @case
in run_tests.py, so the core suite contract (227 registered x 19 chunks =
4313) stays untouched while the axis mounts per the supervisor's phase plan.

Coverage contract = the supervisor's 24-case table (H2_01..H2_24):
  01-03   S exactly seven states / s0 = s_init / Sigma complete
  04-05   delta: the eight-transition table literally / unknown (s,sigma)
          rejected atomically
  06-11   constraints C1..C6 one by one (inverse, monotone, tradeoff,
          deterministic, reachable, safe)
  12-15   Lambda in R^4 / normalization sum(w)=1 / V range [0,1] /
          weight effects
  16-18   A*: golden optimal path / admissible h <= true cost /
          consistency h(s) <= c + h(s')
  19-22   replay returns the state sequence / verify_invariants catches a
          polluted state / the interface contract surface / Gamma per state
  23-24   illegal transition recorded in the boundary log (one of the 14
          categories) / digest stability for the same trace

Red/green discipline: run BEFORE sentinel/statemachine.py exists -> every
case fails with the import error (RED evidence, results/axis2/axis2_RED.json);
implement -> 24/24 (GREEN). Determinism rule R3: identical digest x3 runs.

Atoms mode (--atoms): the M3 atom-verification battery — 3a state atoms,
3b transition atoms, 3c value atoms — -> results/axis2/axis2_ATOMS.json.

Usage: python3 tests/test_axis2_statemachine.py [--out results/axis2/axis2_GREEN.json]
       python3 tests/test_axis2_statemachine.py --atoms [--out results/axis2/axis2_ATOMS.json]
"""
import argparse
import hashlib
import inspect
import json
import math
import os
import sys
import time
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from sentinel.statemachine import (
        BOUNDARY_CATEGORIES, DEFAULT_ILLEGAL_CATEGORY, DEFAULT_LAMBDA,
        EVENTS, FINAL_STATES, INITIAL_STATE, LAMBDA_DIM, MAIN_CHAIN, STATES,
        STATE_FEATURES, TRANSITION_COSTS, TRANSITIONS, InvariantViolation,
        StateMachine, StateMachineError, astar, gamma, heuristic, replay,
        value,
    )
    _IMPORT_ERROR = None
except Exception as _e:  # RED phase: module absent/incomplete
    _IMPORT_ERROR = f"{type(_e).__name__}: {_e}"

RESULTS = []


def case(fn):
    RESULTS.append(fn)
    return fn


def _guard_red():
    if _IMPORT_ERROR is not None:
        raise AssertionError(f"RED — sentinel.statemachine unavailable: {_IMPORT_ERROR}")


# --------------------------------------------------------------------------
# The golden literals — the test-side contract, independent of the module.
# The formal machine M = (S, Sigma, delta, s0, F, Lambda, Gamma, Theta):
#   S   = 7 attack-phase states, s0 = s_init, F = {exfiltration}
#   Sigma = exactly the 8 events appearing in delta (complete + closed)
#   delta = the literal 8-transition table below (spec §2.2)
#   Theta = per-transition costs (A* edge weights)
# --------------------------------------------------------------------------
GOLDEN_STATES = ("s_init", "recon", "foothold", "elevation", "traversal",
                 "objective", "exfiltration")
GOLDEN_FINAL = {"exfiltration"}
GOLDEN_DELTA = {
    ("s_init", "recon_complete"): "recon",
    ("s_init", "valid_creds_acquired"): "foothold",
    ("recon", "foothold_gained"): "foothold",
    ("recon", "initial_access_exploit"): "elevation",
    ("foothold", "privilege_escalated"): "elevation",
    ("elevation", "network_traversed"): "traversal",
    ("traversal", "objective_captured"): "objective",
    ("objective", "data_exfiltrated"): "exfiltration",
}
GOLDEN_COSTS = {
    ("s_init", "recon_complete"): 10.0,
    ("s_init", "valid_creds_acquired"): 19.0,
    ("recon", "foothold_gained"): 10.0,
    ("recon", "initial_access_exploit"): 21.0,
    ("foothold", "privilege_escalated"): 10.0,
    ("elevation", "network_traversed"): 10.0,
    ("traversal", "objective_captured"): 10.0,
    ("objective", "data_exfiltrated"): 10.0,
}
# The golden optimal path (unique): cost 19 + 10*4 = 59 < full chain 60 < 61.
GOLDEN_PATH = ["s_init", "foothold", "elevation", "traversal", "objective",
               "exfiltration"]
GOLDEN_PATH_COST = 59.0
GOLDEN_PATH_EVENTS = ["valid_creds_acquired", "privilege_escalated",
                      "network_traversed", "objective_captured",
                      "data_exfiltrated"]
CHAIN_EVENTS = ["recon_complete", "foothold_gained", "privilege_escalated",
                "network_traversed", "objective_captured", "data_exfiltrated"]
FULL_CHAIN = list(GOLDEN_STATES)
LAMBDA_GRID = [
    (0.40, 0.30, 0.15, 0.15),  # default: access, persistence, stealth, efficiency
    (1.0, 0.0, 0.0, 0.0),
    (0.0, 1.0, 0.0, 0.0),
    (0.0, 0.0, 1.0, 0.0),
    (0.0, 0.0, 0.0, 1.0),
    (0.25, 0.25, 0.25, 0.25),
    (0.70, 0.10, 0.10, 0.10),
    (0.10, 0.70, 0.10, 0.10),
    (0.10, 0.10, 0.70, 0.10),
    (0.10, 0.10, 0.10, 0.70),
    (0.55, 0.25, 0.10, 0.10),
]


def _walk_events(target):
    """Deterministic BFS over GOLDEN_DELTA: shortest event list s_init->target."""
    if target == "s_init":
        return []
    prev = {"s_init": None}  # state -> (event, from_state)
    q = deque(["s_init"])
    while q:
        s = q.popleft()
        for (s2, sigma), t in sorted(GOLDEN_DELTA.items()):
            if s2 != s or t in prev:
                continue
            prev[t] = (sigma, s)
            if t == target:
                out = []
                cur = t
                while prev[cur] is not None:
                    ev, src = prev[cur]
                    out.append(ev)
                    cur = src
                return list(reversed(out))
            q.append(t)
    raise AssertionError(f"state {target} unreachable in the golden delta")


def _machine_at(target, lam=None):
    m = StateMachine(lam)
    for e in _walk_events(target):
        assert m.step(e), (target, e)
    assert m.state == target
    return m


def _all_simple_paths(src, dst):
    """Enumerate every simple path src->dst over GOLDEN_DELTA (small graph)."""
    out = []
    def dfs(node, path):
        if node == dst:
            out.append(list(path))
            return
        for (s2, sigma), t in sorted(GOLDEN_DELTA.items()):
            if s2 == node and t not in path:
                path.append(t)
                dfs(t, path)
                path.pop()
    dfs(src, [src])
    return out


def _path_cost(path):
    c = 0.0
    for a, b in zip(path, path[1:]):
        edge = [(k, v) for k, v in GOLDEN_DELTA.items() if k[0] == a and v == b]
        assert edge, (a, b)
        c += GOLDEN_COSTS[edge[0][0]]
    return c


def _zero_h(_s):
    return 0.0


# ---------------------------------------------------------------- H2_01..03

@case
def test_h2_01_states_exactly_seven():
    _guard_red()
    assert tuple(STATES) == GOLDEN_STATES, STATES
    assert len(STATES) == 7 and len(set(STATES)) == 7
    # every state name is a non-empty identifier string
    assert all(isinstance(s, str) and s for s in STATES)


@case
def test_h2_02_initial_state_s_init():
    _guard_red()
    assert INITIAL_STATE == "s_init"
    assert INITIAL_STATE in STATES
    m = StateMachine()
    assert m.state == "s_init"
    assert m.history == ["s_init"]
    # F: non-empty, subset of S, and the start is not accepting
    assert FINAL_STATES and isinstance(FINAL_STATES, frozenset)
    assert set(FINAL_STATES) == GOLDEN_FINAL
    assert set(FINAL_STATES) <= set(STATES)
    assert INITIAL_STATE not in FINAL_STATES


@case
def test_h2_03_sigma_complete():
    _guard_red()
    used = {sigma for (_, sigma) in TRANSITIONS}
    assert isinstance(EVENTS, frozenset)
    assert set(EVENTS) == used, (sorted(EVENTS), sorted(used))
    assert len(EVENTS) == 8
    # closure: no event outside the delta alphabet
    assert set(EVENTS) == {sigma for (_, sigma) in GOLDEN_DELTA}


# ---------------------------------------------------------------- H2_04..05

@case
def test_h2_04_delta_literal_eight():
    _guard_red()
    assert dict(TRANSITIONS) == GOLDEN_DELTA, TRANSITIONS
    assert len(TRANSITIONS) == 8
    # Theta covers exactly the delta domain
    assert set(TRANSITION_COSTS) == set(GOLDEN_DELTA)
    for k, v in TRANSITION_COSTS.items():
        assert v == GOLDEN_COSTS[k], (k, v)


@case
def test_h2_05_unknown_pair_rejected():
    _guard_red()
    # named samples: skip-ahead, terminal regression, fabricated event
    for state, event in (("s_init", "data_exfiltrated"),
                         ("exfiltration", "recon_complete"),
                         ("traversal", "privilege_escalated"),
                         ("s_init", "not_an_event_at_all")):
        m = _machine_at(state)
        hist, evlog, blen = list(m.history), list(m.event_log), len(m.boundary)
        assert m.step(event) is False, (state, event)
        assert m.state == state
        assert m.history == hist and m.event_log == evlog
        assert len(m.boundary) == blen + 1
    # exhaustive: EVERY (s, sigma) in S x Sigma not in delta is rejected
    for s in STATES:
        for sigma in EVENTS:
            if (s, sigma) in TRANSITIONS:
                continue
            m = _machine_at(s)
            assert m.step(sigma) is False, (s, sigma)
            assert m.state == s and len(m.history) == 1 + len(m.event_log)


# ---------------------------------------------------------------- H2_06..11

@case
def test_h2_06_c1_inverse():
    """C1 (inverse): V strictly rises along the chain while h strictly
    falls; stealth strictly falls while coverage strictly rises."""
    _guard_red()
    lam = DEFAULT_LAMBDA
    vs = [value(s, lam) for s in MAIN_CHAIN]
    hs = [heuristic(s) for s in MAIN_CHAIN]
    for a, b in zip(vs, vs[1:]):
        assert b > a, vs
    for a, b in zip(hs, hs[1:]):
        assert b < a, hs
    st = [gamma(s)["stealth"] for s in MAIN_CHAIN]
    cv = [gamma(s)["coverage"] for s in MAIN_CHAIN]
    for a, b in zip(st, st[1:]):
        assert b < a, st
    for a, b in zip(cv, cv[1:]):
        assert b > a, cv


@case
def test_h2_07_c2_monotone():
    """C2 (monotone): progress features never regress across ANY delta
    transition; V never decreases along any transition under default Lambda."""
    _guard_red()
    for (s, _sigma), t in TRANSITIONS.items():
        fs, ft = STATE_FEATURES[s], STATE_FEATURES[t]
        assert ft[0] >= fs[0], ("access regressed", s, t)
        assert ft[1] >= fs[1], ("persistence regressed", s, t)
        assert value(t, DEFAULT_LAMBDA) >= value(s, DEFAULT_LAMBDA), (s, t)


@case
def test_h2_08_c3_tradeoff():
    """C3 (tradeoff): stealth + coverage <= 1 for every state."""
    _guard_red()
    saw_slack = False
    for s in STATES:
        g = gamma(s)
        total = g["stealth"] + g["coverage"]
        assert total <= 1.0 + 1e-9, (s, total)
        assert 0.0 <= g["stealth"] <= 1.0 and 0.0 <= g["coverage"] <= 1.0
        if total < 1.0 - 1e-9:
            saw_slack = True
    assert saw_slack, "tradeoff frontier trivial (all sums == 1)"


@case
def test_h2_09_c4_deterministic():
    """C4 (deterministic): delta is a function; repeated application is
    stable; identical traces yield identical machines (digest-equal)."""
    _guard_red()
    assert len(set(TRANSITIONS)) == len(TRANSITIONS)  # unique (s,sigma) keys
    for (s, sigma), t in TRANSITIONS.items():
        targets = set()
        for _ in range(3):
            m = _machine_at(s)
            assert m.step(sigma) is True
            targets.add(m.state)
        assert targets == {t}, (s, sigma, targets)
    a, b = StateMachine(), StateMachine()
    for e in CHAIN_EVENTS:
        a.step(e)
        b.step(e)
    assert a.history == b.history and a.event_log == b.event_log
    assert a.digest() == b.digest()
    # rejection determinism: same illegal event twice -> identical records
    m1, m2 = StateMachine(), StateMachine()
    m1.step("data_exfiltrated")
    m2.step("data_exfiltrated")
    assert m1.boundary == m2.boundary


@case
def test_h2_10_c5_reachable():
    """C5 (reachable): every state is reachable from s0, and every state
    can reach the accepting state (progress guarantee)."""
    _guard_red()
    seen = {"s_init"}
    q = deque(["s_init"])
    while q:
        s = q.popleft()
        for (s2, _sigma), t in TRANSITIONS.items():
            if s2 == s and t not in seen:
                seen.add(t)
                q.append(t)
    assert seen == set(STATES), seen
    # co-reachability: reverse BFS from exfiltration
    radj = {s: set() for s in STATES}
    for (s2, _sigma), t in TRANSITIONS.items():
        radj[t].add(s2)
    rseen = set(FINAL_STATES)
    q = deque(rseen)
    while q:
        s = q.popleft()
        for p in radj[s]:
            if p not in rseen:
                rseen.add(p)
                q.append(p)
    assert rseen == set(STATES), rseen


@case
def test_h2_11_c6_safe():
    """C6 (safe): exfiltration is enterable ONLY from objective; illegal
    steps are atomic (no partial mutation); every reachable configuration
    passes verify_invariants."""
    _guard_red()
    preds = {s2 for (s2, _sigma), t in TRANSITIONS.items() if t == "exfiltration"}
    assert preds == {"objective"}, preds
    for (_s, _sigma), t in TRANSITIONS.items():
        assert t in STATES  # closure: delta never leaves S
    # atomic rejection: nothing advances on an illegal step
    m = _machine_at("traversal")
    snap = m.snapshot()
    d_before = m.digest()
    assert m.step("recon_complete") is False
    assert m.state == "traversal"
    assert m.history == snap["history"] and m.event_log == snap["event_log"]
    assert m.digest() != d_before  # boundary grew (that is the ONLY change)
    # every state along the full chain verifies clean
    mm = StateMachine()
    assert mm.verify_invariants()
    for e in CHAIN_EVENTS:
        mm.step(e)
        assert mm.verify_invariants(), mm.state


# ---------------------------------------------------------------- H2_12..15

@case
def test_h2_12_lambda_r4():
    _guard_red()
    assert LAMBDA_DIM == 4
    assert len(DEFAULT_LAMBDA) == 4
    v = value("recon", (1.0, 0.0, 0.0, 0.0))
    assert isinstance(v, float)
    for bad in ((), (1.0,), (1.0, 2.0), (1.0, 2.0, 3.0), (1.0, 2.0, 3.0, 4.0, 5.0)):
        try:
            value("recon", bad)
            raise AssertionError(f"dim {len(bad)} accepted")
        except StateMachineError:
            pass


@case
def test_h2_13_normalization_sum_w1():
    _guard_red()
    base = (0.4, 0.3, 0.1, 0.2)
    for scale in (1.0, 0.5, 2.0, 5.0, 7.0):
        lam = tuple(x * scale for x in base)
        for s in STATES:
            assert abs(value(s, lam) - value(s, base)) < 1e-12, (s, scale)
    # non-normalizable inputs are rejected, not silently coerced
    for bad in ((0.0, 0.0, 0.0, 0.0), (-0.1, 0.5, 0.3, 0.3),
                (1.0, -1.0, 0.5, 0.5)):
        try:
            value("recon", bad)
            raise AssertionError(f"bad lambda accepted: {bad}")
        except StateMachineError:
            pass
    # default weights are themselves normalized (within float tolerance)
    assert abs(sum(DEFAULT_LAMBDA) - 1.0) < 1e-9


@case
def test_h2_14_v_range_0_1():
    _guard_red()
    for lam in LAMBDA_GRID:
        for s in STATES:
            v = value(s, lam)
            assert 0.0 <= v <= 1.0, (s, lam, v)
    # endpoint anchors: the pre-engagement and terminal states stay in range
    assert 0.0 <= value("s_init", DEFAULT_LAMBDA) <= 1.0
    assert 0.0 <= value("exfiltration", DEFAULT_LAMBDA) <= 1.0


@case
def test_h2_15_weight_effects():
    _guard_red()
    # pure access: V == access feature, chain-ascending
    for s in STATES:
        assert abs(value(s, (1.0, 0.0, 0.0, 0.0)) - STATE_FEATURES[s][0]) < 1e-12
    # pure stealth: V == stealth feature, chain-DESCENDING (the inverse)
    for s in STATES:
        assert abs(value(s, (0.0, 0.0, 1.0, 0.0)) - STATE_FEATURES[s][2]) < 1e-12
    assert value("exfiltration", (1.0, 0.0, 0.0, 0.0)) > value("s_init", (1.0, 0.0, 0.0, 0.0))
    assert value("exfiltration", (0.0, 0.0, 1.0, 0.0)) < value("s_init", (0.0, 0.0, 1.0, 0.0))
    # sensitivity: distinct states differ under the default weights
    assert value("recon", DEFAULT_LAMBDA) != value("foothold", DEFAULT_LAMBDA)


# ---------------------------------------------------------------- H2_16..18

@case
def test_h2_16_astar_golden_path():
    _guard_red()
    # complete optimality proof by enumeration: exactly three simple paths
    paths = _all_simple_paths("s_init", "exfiltration")
    costs = sorted(_path_cost(p) for p in paths)
    assert len(paths) == 3 and costs == [59.0, 60.0, 61.0], (paths, costs)
    best = min(paths, key=_path_cost)
    assert best == GOLDEN_PATH and _path_cost(best) == GOLDEN_PATH_COST
    # A* with the admissible heuristic returns exactly the golden path
    path, cost = astar("s_init", "exfiltration")
    assert path == GOLDEN_PATH and cost == GOLDEN_PATH_COST, (path, cost)
    # Dijkstra cross-check (h == 0) agrees
    path0, cost0 = astar("s_init", "exfiltration", heuristic=_zero_h)
    assert path0 == GOLDEN_PATH and cost0 == GOLDEN_PATH_COST
    # a mid-chain start: from recon the via-foothold route (50) beats 51
    path_r, cost_r = astar("recon", "exfiltration")
    assert path_r == ["recon", "foothold", "elevation", "traversal",
                      "objective", "exfiltration"] and cost_r == 50.0
    # trivial and impossible queries
    assert astar("s_init", "s_init") == (["s_init"], 0.0)
    try:
        astar("exfiltration", "s_init")
        raise AssertionError("unreachable goal accepted")
    except StateMachineError:
        pass


@case
def test_h2_17_admissible_heuristic():
    _guard_red()
    for s in STATES:
        true_cost = astar(s, "exfiltration", heuristic=_zero_h)[1]
        h = heuristic(s)
        assert h <= true_cost + 1e-9, (s, h, true_cost)
    # tight anchor points of the rank-scaled bound
    assert heuristic("exfiltration") == 0.0
    assert heuristic("s_init") == 30.0 and 30.0 <= GOLDEN_PATH_COST


@case
def test_h2_18_consistent_heuristic():
    _guard_red()
    for (s, sigma), t in TRANSITIONS.items():
        c = TRANSITION_COSTS[(s, sigma)]
        assert heuristic(s) <= c + heuristic(t) + 1e-9, (s, sigma, t)


# ---------------------------------------------------------------- H2_19..22

@case
def test_h2_19_replay_sequence():
    _guard_red()
    assert replay(GOLDEN_PATH_EVENTS) == GOLDEN_PATH
    assert replay(CHAIN_EVENTS) == FULL_CHAIN
    assert replay([]) == ["s_init"]
    # replay agrees with a step-by-step machine
    m = StateMachine()
    for e in CHAIN_EVENTS:
        m.step(e)
    assert replay(CHAIN_EVENTS) == m.history
    # mid-trace illegal event: machine continues, history shows the skip
    seq = replay(["recon_complete", "data_exfiltrated", "foothold_gained"])
    assert seq == ["s_init", "recon", "foothold"], seq


@case
def test_h2_20_invariants_catch_pollution():
    _guard_red()
    m = StateMachine()
    m.step("recon_complete")
    assert m.verify_invariants()
    snap = m.snapshot()
    # polluted current state
    m.current_state = "bogus_state"
    assert not m.verify_invariants()
    m.restore(snap)
    assert m.verify_invariants()
    # polluted history (a state with no matching event)
    m2 = StateMachine()
    m2.history.append("exfiltration")
    assert not m2.verify_invariants()
    # polluted event log (length mismatch)
    m3 = StateMachine()
    m3.event_log.append("data_exfiltrated")
    assert not m3.verify_invariants()
    # assert variant raises
    m4 = StateMachine()
    m4.current_state = "bogus"
    try:
        m4.assert_invariants()
        raise AssertionError("polluted state passed assert_invariants")
    except InvariantViolation:
        pass
    # a mid-chain machine is clean
    assert _machine_at("traversal").verify_invariants()


@case
def test_h2_21_interface_contract():
    _guard_red()
    sig = inspect.signature
    # module-level surface
    assert tuple(STATES) == GOLDEN_STATES
    assert isinstance(EVENTS, frozenset) and len(EVENTS) == 8
    assert isinstance(FINAL_STATES, frozenset)
    assert LAMBDA_DIM == 4 and len(DEFAULT_LAMBDA) == 4
    assert isinstance(BOUNDARY_CATEGORIES, frozenset)
    assert len(BOUNDARY_CATEGORIES) == 14
    assert "OUT_OF_SCOPE" in BOUNDARY_CATEGORIES
    assert "UNSUPPORTED_PLATFORM" in BOUNDARY_CATEGORIES
    assert DEFAULT_ILLEGAL_CATEGORY in BOUNDARY_CATEGORIES
    assert len(STATE_FEATURES) == 7
    for s, f in STATE_FEATURES.items():
        assert len(f) == 4 and all(0.0 <= x <= 1.0 for x in f), (s, f)
    # function arities (required params, self excluded)
    fn_required = {"value": 1, "heuristic": 1, "astar": 2, "gamma": 1,
                   "replay": 1}
    for name, argc in fn_required.items():
        fn = globals().get(name)
        assert callable(fn), f"missing module function {name}"
        params = [p for p in sig(fn).parameters.values()
                  if p.default is inspect.Parameter.empty
                  and p.kind in (p.POSITIONAL_OR_KEYWORD, p.POSITIONAL_ONLY)]
        assert len(params) == argc, (name, params)
    # class surface
    methods = {"step": 1, "run": 1, "verify_invariants": 0,
               "assert_invariants": 0, "snapshot": 0, "restore": 1,
               "digest": 0}
    for name, argc in methods.items():
        fn = getattr(StateMachine, name, None)
        assert callable(fn), f"missing StateMachine.{name}"
        params = [p for p in sig(fn).parameters.values()
                  if p.name != "self" and p.default is inspect.Parameter.empty]
        assert len(params) == argc, (name, params)
    assert isinstance(StateMachine().state, str)
    assert issubclass(StateMachineError, ValueError)
    assert issubclass(InvariantViolation, StateMachineError)


@case
def test_h2_22_gamma_per_state():
    _guard_red()
    phases = set()
    for s in STATES:
        g = gamma(s)
        assert isinstance(g, dict) and g
        for key in ("phase", "coverage", "stealth", "guards", "events"):
            assert key in g, (s, key)
        assert isinstance(g["phase"], str) and g["phase"]
        assert isinstance(g["coverage"], float) and 0.0 <= g["coverage"] <= 1.0
        assert isinstance(g["stealth"], float) and 0.0 <= g["stealth"] <= 1.0
        assert isinstance(g["guards"], list)
        expected = sorted(sigma for (s2, sigma) in TRANSITIONS if s2 == s)
        assert g["events"] == expected, (s, g["events"], expected)
        phases.add(g["phase"])
    assert len(phases) == 7  # injective phase naming


# ---------------------------------------------------------------- H2_23..24

@case
def test_h2_23_illegal_boundary_log():
    _guard_red()
    assert len(BOUNDARY_CATEGORIES) == 14
    m = StateMachine()
    before = len(m.boundary)
    assert m.step("data_exfiltrated") is False  # illegal from s_init
    assert len(m.boundary) == before + 1
    entry = m.boundary[-1]
    for key in ("seq", "category", "state", "event", "reason"):
        assert key in entry, (entry, key)
    assert entry["category"] in BOUNDARY_CATEGORIES
    assert entry["category"] == DEFAULT_ILLEGAL_CATEGORY
    assert entry["state"] == "s_init" and entry["event"] == "data_exfiltrated"
    assert isinstance(entry["reason"], str) and entry["reason"]
    # seq monotone; legal steps write nothing; boundary survives snapshots
    assert m.step("recon_complete") is True
    assert len(m.boundary) == before + 1
    assert m.step("privilege_escalated") is False
    assert m.boundary[-1]["seq"] > entry["seq"]
    snap = m.snapshot()
    assert snap["boundary"] == m.boundary
    m.restore(snap)
    assert m.boundary == snap["boundary"]


@case
def test_h2_24_digest_stability():
    _guard_red()
    # same trace -> identical digest, always
    d1 = _machine_at("exfiltration").digest()
    d2 = _machine_at("exfiltration").digest()
    assert d1 == d2 and len(d1) == 64
    # a different trace -> a different digest
    d3 = StateMachine().digest()
    m4 = StateMachine()
    for e in CHAIN_EVENTS:
        m4.step(e)
    assert m4.digest() != d1 and m4.digest() != d3
    m5 = StateMachine()
    for e in CHAIN_EVENTS:
        m5.step(e)
    assert m4.digest() == m5.digest()  # same trace (full chain), same digest
    # interleaved illegal events keep the digest deterministic
    def mixed():
        m = StateMachine()
        m.step("recon_complete")
        m.step("data_exfiltrated")  # rejected + logged
        m.step("foothold_gained")
        return m.digest()
    assert mixed() == mixed()
    # snapshot/restore preserves the digest exactly
    m6 = _machine_at("objective")
    snap = m6.snapshot()
    m6.step("data_exfiltrated")
    assert m6.state == "exfiltration"
    m6.restore(snap)
    assert m6.digest() == _machine_at("objective").digest()


# ============================================================== atoms mode
# The M3 battery: exhaustive per-atom verification (3a / 3b / 3c). Where the
# 24 cases sample, the atoms enumerate EVERY state, EVERY transition, EVERY
# rejected pair, EVERY admissible-lambda vector in the grid.

ATOM_CHECKS = []


def _atom(atom_id, description, ok, detail=""):
    ATOM_CHECKS.append({"atom": atom_id, "what": description,
                        "ok": bool(ok), "detail": str(detail)[:200]})


def _atoms_3a_state_atoms():
    for s in STATES:
        f = STATE_FEATURES[s]
        _atom("3a", f"{s}: in S", s in STATES)
        _atom("3a", f"{s}: features R^4 in [0,1]",
              len(f) == 4 and all(0.0 <= x <= 1.0 for x in f), f)
        g = gamma(s)
        _atom("3a", f"{s}: Gamma well-formed",
              all(k in g for k in ("phase", "coverage", "stealth", "guards", "events"))
              and 0.0 <= g["coverage"] <= 1.0 and 0.0 <= g["stealth"] <= 1.0)
        _atom("3a", f"{s}: C3 tradeoff",
              g["stealth"] + g["coverage"] <= 1.0 + 1e-9,
              g["stealth"] + g["coverage"])
        _atom("3a", f"{s}: reachable from s0", bool(_walk_events(s)))
        m = _machine_at(s)
        _atom("3a", f"{s}: parked machine verifies invariants",
              m.verify_invariants(), m.state)
        _atom("3a", f"{s}: h admissible vs Dijkstra",
              heuristic(s) <= astar(s, "exfiltration", heuristic=_zero_h)[1] + 1e-9)
        for lam in LAMBDA_GRID:
            v = value(s, lam)
            _atom("3a", f"{s}: V in [0,1] under {lam}", 0.0 <= v <= 1.0, v)


def _atoms_3b_transition_atoms():
    for (s, sigma), t in sorted(TRANSITIONS.items()):
        c = TRANSITION_COSTS[(s, sigma)]
        _atom("3b", f"{s} -{sigma}-> {t}: endpoints in S, sigma in Sigma",
              s in STATES and t in STATES and sigma in EVENTS)
        _atom("3b", f"{s} -{sigma}-> {t}: Theta cost > 0 finite",
              c > 0.0 and math.isfinite(c), c)
        digests = set()
        for _ in range(3):
            m = _machine_at(s)
            ok = m.step(sigma)
            digests.add(m.digest())
            _atom("3b", f"{s} -{sigma}-> {t}: applies cleanly", ok and m.state == t)
        _atom("3b", f"{s} -{sigma}-> {t}: deterministic x3", len(digests) == 1)
        fs, ft = STATE_FEATURES[s], STATE_FEATURES[t]
        _atom("3b", f"{s} -{sigma}-> {t}: C2 progress features",
              ft[0] >= fs[0] and ft[1] >= fs[1])
        m = _machine_at(s)
        blen = len(m.boundary)
        m.step(sigma)
        _atom("3b", f"{s} -{sigma}-> {t}: no boundary write on legal step",
              len(m.boundary) == blen)
        _atom("3b", f"{s} -{sigma}-> {t}: h consistent over edge",
              heuristic(s) <= c + heuristic(t) + 1e-9)
    # rejection atoms: EVERY (s, sigma) in S x Sigma not in delta
    for s in STATES:
        for sigma in sorted(EVENTS):
            if (s, sigma) in TRANSITIONS:
                continue
            m = _machine_at(s)
            hist, evlog = list(m.history), list(m.event_log)
            blen = len(m.boundary)
            ok = m.step(sigma)
            e = m.boundary[-1] if len(m.boundary) == blen + 1 else {}
            _atom("3b", f"reject ({s}, {sigma}): rejected atomically",
                  ok is False and m.state == s and m.history == hist
                  and m.event_log == evlog)
            _atom("3b", f"reject ({s}, {sigma}): exactly one boundary entry",
                  len(m.boundary) == blen + 1
                  and e.get("category") in BOUNDARY_CATEGORIES)
    # fabricated events: never in Sigma, always rejected + logged
    for s in STATES:
        for ev in ("__nope__", ""):
            m = _machine_at(s)
            blen = len(m.boundary)
            ok = m.step(ev)
            _atom("3b", f"fabricated ({s}, {ev!r}): rejected + logged",
                  ok is False and len(m.boundary) == blen + 1)


def _atoms_3c_value_atoms():
    for lam in LAMBDA_GRID:
        for s in STATES:
            _atom("3c", f"V({s}) in [0,1] under {lam}",
                  0.0 <= value(s, lam) <= 1.0)
    base = (0.4, 0.3, 0.1, 0.2)
    for k in (0.5, 2.0, 7.0):
        scaled = tuple(x * k for x in base)
        for s in STATES:
            _atom("3c", f"normalization invariance k={k} at {s}",
                  abs(value(s, scaled) - value(s, base)) < 1e-12)
    bad_lams = [(), (1.0,), (1.0, 2.0), (1.0, 2.0, 3.0),
                (1.0, 2.0, 3.0, 4.0, 5.0), (0.0, 0.0, 0.0, 0.0),
                (-0.1, 0.5, 0.3, 0.3)]
    for bad in bad_lams:
        try:
            value("recon", bad)
            _atom("3c", f"malformed lambda rejected {bad}", False)
        except StateMachineError:
            _atom("3c", f"malformed lambda rejected {bad}", True)
    try:
        value("bogus_state", DEFAULT_LAMBDA)
        _atom("3c", "unknown state rejected", False)
    except StateMachineError:
        _atom("3c", "unknown state rejected", True)
    # A* atoms: golden path reproduced identically three times
    results = {astar("s_init", "exfiltration") for _ in range(3)}
    _atom("3c", "golden path stable x3 (path, cost)",
          len(results) == 1 and results == {(GOLDEN_PATH, GOLDEN_PATH_COST)})
    _atom("3c", "Dijkstra cross-check equals A* golden",
          astar("s_init", "exfiltration", heuristic=_zero_h)
          == (GOLDEN_PATH, GOLDEN_PATH_COST))
    for s in STATES:
        true_cost = astar(s, "exfiltration", heuristic=_zero_h)[1]
        _atom("3c", f"h({s}) admissible", heuristic(s) <= true_cost + 1e-9)
    for (s, sigma), t in sorted(TRANSITIONS.items()):
        _atom("3c", f"h consistent on edge {s}->{t}",
              heuristic(s) <= TRANSITION_COSTS[(s, sigma)] + heuristic(t) + 1e-9)


def run_atoms():
    _guard_red()
    ATOM_CHECKS.clear()
    _atoms_3a_state_atoms()
    _atoms_3b_transition_atoms()
    _atoms_3c_value_atoms()
    return list(ATOM_CHECKS)


# ------------------------------------------------------------------ runner

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join("results", "axis2",
                                                  "axis2_suite.json"))
    ap.add_argument("--atoms", action="store_true",
                    help="run the M3 atom battery (3a/3b/3c) instead of the "
                         "24-case suite")
    args = ap.parse_args()
    if args.atoms:
        checks = run_atoms()
        failed = sum(1 for c in checks if not c["ok"])
        per_atom = {}
        for c in checks:
            per_atom.setdefault(c["atom"], [0, 0])
            per_atom[c["atom"]][0] += 1
            per_atom[c["atom"]][1] += 0 if c["ok"] else 1
        digest = hashlib.sha256(json.dumps(
            [{"atom": c["atom"], "what": c["what"], "ok": c["ok"]}
             for c in checks],
            sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        report = {"suite": "axis2-atoms", "total": len(checks),
                  "failed": failed, "passed": failed == 0,
                  "atoms": [{"id": a, "checks": n, "failed": f}
                              for a, (n, f) in sorted(per_atom.items())],
                  "checks": checks, "digest": digest}
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w") as fh:
            json.dump(report, fh, indent=1)
        print(f"axis2 atoms: {len(checks) - failed}/{len(checks)} checks "
              f"(failed={failed}) digest={digest[:16]} -> {args.out}")
        sys.exit(0 if failed == 0 else 1)
    cases = []
    for fn in RESULTS:
        entry = {"name": fn.__name__, "ok": False, "error": ""}
        t0 = time.monotonic()
        try:
            fn()
            entry["ok"] = True
        except Exception as e:  # noqa: BLE001 — record every failure mode
            entry["error"] = f"{type(e).__name__}: {e}"[:400]
        entry["dur_s"] = round(time.monotonic() - t0, 4)
        cases.append(entry)
        print(("PASS " if entry["ok"] else "FAIL ") + entry["name"]
              + ("" if entry["ok"] else f"  -> {entry['error']}"))
    failed = sum(1 for c in cases if not c["ok"])
    digest = hashlib.sha256(json.dumps(
        [{"name": c["name"], "ok": c["ok"]} for c in cases],
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    report = {"suite": "axis2-statemachine", "total": len(cases),
              "failed": failed, "passed": failed == 0, "cases": cases,
              "digest": digest}
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(report, fh, indent=1)
    print(f"axis2: {len(cases) - failed}/{len(cases)} passed "
          f"(failed={failed}) digest={digest[:16]} -> {args.out}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""SENTINEL Axis-2 — the formal attack state machine (spec §2.1–§2.8).

§2.1  The formal machine M = (S, Σ, δ, s₀, F, Λ, Γ, Θ):
        S   — exactly seven attack-phase states (the canonical chain)
        Σ   — the event alphabet: exactly the events appearing in δ
        δ   — the transition table (§2.2)
        s₀  — s_init (pre-engagement)
        F   — {exfiltration} (the accepting state)
        Λ   — the value-weight vector in ℝ⁴ (§2.4)
        Γ   — the per-state tactical profile function (§2.6)
        Θ   — the per-transition cost map (A* edge weights, §2.5)
§2.2  δ: the literal 8-transition table — six chain edges plus two
       shortcut edges — with total rejection semantics for unknown (s,σ).
§2.3  The six well-formedness constraints C1–C6, machine-checkable:
        C1 inverse      — V strictly rises along the chain while h strictly
                          falls; stealth strictly falls while coverage
                          strictly rises (the two inverse orderings)
        C2 monotone     — the progress features (access, persistence) never
                          regress across ANY transition; V is non-decreasing
                          under the default Λ
        C3 tradeoff     — stealth + coverage ≤ 1 for every state
        C4 deterministic— δ is a function; identical inputs give identical
                          machines (digest-equal)
        C5 reachable    — every state is reachable from s₀ AND can reach F
        C6 safe         — exfiltration is enterable ONLY from objective;
                          δ never leaves S; rejection is atomic (no partial
                          mutation, one boundary entry)
§2.4  Λ ∈ ℝ⁴ with Σw=1 normalization (non-negative, sum > 0 enforced);
       V(s) = Σ wᵢ·fᵢ(s) with fᵢ ∈ [0,1] ⇒ V ∈ [0,1]. The four feature
       dimensions mirror the Axis-9 reward axes as state achievements:
       access gain, persistence, stealth (1 − detection risk), efficiency
       (1 − normalized cost).
§2.5  A* over (S, Θ) with the rank-scaled heuristic
       h(s) = c_min · (r_goal − r_s) / 2 — admissible (every edge spans at
       most two chain ranks at cost ≥ c_min) and consistent (an edge of
       rank-span d drops h by exactly c_min·d/2 ≤ c_min ≤ c(edge)).
§2.6  Runtime: the StateMachine class (step/run + replay) and Γ(s).
§2.7  Invariants: verify_invariants/assert_invariants, snapshot/restore,
       semantic digests over the LOGICAL stream only (current state,
       history, event log, boundary records) — no wall timings ever enter
       a digest, so determinism is exact, not statistical (Axis-11 rule).
§2.8  The boundary log: illegal (s,σ) attempts append one record with a
       category drawn from the Axis-12 14-category taxonomy (mirrors
       sentinel/xgraph.py — the shared boundary contract).

Standalone by construction: sentinel/__init__.py stays empty and the core
hot path never imports this module, so the accepted core contract
(suite 4313/4313, doctor 17/17, bench run-3c0652b6be) cannot drift.
"""
import hashlib
import heapq
import json
import math

# ------------------------------------------------------------- §2.1 the set S
STATES = ("s_init", "recon", "foothold", "elevation", "traversal",
          "objective", "exfiltration")
MAIN_CHAIN = tuple(STATES)          # the canonical progression order
INITIAL_STATE = "s_init"
FINAL_STATES = frozenset({"exfiltration"})
_STATE_INDEX = {s: i for i, s in enumerate(MAIN_CHAIN)}

PHASE_NAMES = {
    "s_init": "pre-engagement",
    "recon": "reconnaissance",
    "foothold": "initial-foothold",
    "elevation": "privilege-elevation",
    "traversal": "lateral-traversal",
    "objective": "objective-capture",
    "exfiltration": "data-exfiltration",
}

# ------------------------------------------------------------ §2.2 delta + Θ
# The literal 8-transition table: six chain edges (recon→…→exfiltration)
# plus two shortcut edges (skip-recon via acquired credentials; exploit-
# first straight to elevation). Costs make the shortcut route the unique
# golden optimum: 19 + 4×10 = 59 < full chain 60 < 10 + 21 + 3×10 = 61.
TRANSITIONS = {
    ("s_init", "recon_complete"): "recon",
    ("s_init", "valid_creds_acquired"): "foothold",
    ("recon", "foothold_gained"): "foothold",
    ("recon", "initial_access_exploit"): "elevation",
    ("foothold", "privilege_escalated"): "elevation",
    ("elevation", "network_traversed"): "traversal",
    ("traversal", "objective_captured"): "objective",
    ("objective", "data_exfiltrated"): "exfiltration",
}
TRANSITION_COSTS = {
    ("s_init", "recon_complete"): 10.0,
    ("s_init", "valid_creds_acquired"): 19.0,
    ("recon", "foothold_gained"): 10.0,
    ("recon", "initial_access_exploit"): 21.0,
    ("foothold", "privilege_escalated"): 10.0,
    ("elevation", "network_traversed"): 10.0,
    ("traversal", "objective_captured"): 10.0,
    ("objective", "data_exfiltrated"): 10.0,
}
# Σ: complete and closed over exactly the delta alphabet.
EVENTS = frozenset(sigma for (_, sigma) in TRANSITIONS)

# --------------------------------------------------- §2.4 features and Lambda
# f(s) ∈ [0,1]⁴: (access, persistence, stealth, efficiency).
STATE_FEATURES = {
    "s_init": (0.00, 0.00, 1.00, 1.00),
    "recon": (0.15, 0.00, 0.90, 0.80),
    "foothold": (0.35, 0.20, 0.80, 0.65),
    "elevation": (0.55, 0.40, 0.70, 0.55),
    "traversal": (0.70, 0.60, 0.55, 0.45),
    "objective": (0.90, 0.80, 0.40, 0.35),
    "exfiltration": (1.00, 1.00, 0.25, 0.25),
}
# Coverage — the C3 tradeoff partner of stealth (stealth + coverage ≤ 1).
STATE_COVERAGE = {
    "s_init": 0.00, "recon": 0.10, "foothold": 0.15, "elevation": 0.25,
    "traversal": 0.35, "objective": 0.50, "exfiltration": 0.65,
}
# Γ aux: per-state guard conditions (the tactical preconditions).
STATE_GUARDS = {
    "s_init": ["standing-authorization", "scope-lock"],
    "recon": ["passive-only"],
    "foothold": ["evidence-capture"],
    "elevation": ["oplog-write"],
    "traversal": ["hop-budget"],
    "objective": ["impact-proof"],
    "exfiltration": ["owner-consent"],
}

LAMBDA_DIM = 4
DEFAULT_LAMBDA = (0.40, 0.30, 0.15, 0.15)   # access, persistence, stealth, efficiency

# --------------------------------------------- §2.8 the Axis-12 taxonomy (14)
BOUNDARY_CATEGORIES = frozenset({
    "OUT_OF_SCOPE", "PRECONDITION_FAILED", "RESOURCE_EXHAUSTED",
    "DETECTION_AVOIDED", "TIME_LIMIT", "SAFETY_GUARD", "UNKNOWN_PROTOCOL",
    "AUTH_REQUIRED", "ENCRYPTION_UNTRAVERSABLE", "HARDWARE_LIMIT",
    "NETWORK_ISOLATED", "POLICY_RESTRICTED", "CAPABILITY_MISSING",
    "UNSUPPORTED_PLATFORM",
})
DEFAULT_ILLEGAL_CATEGORY = "PRECONDITION_FAILED"


# ------------------------------------------------------------------- errors
class StateMachineError(ValueError):
    """Malformed machine input: unknown state, bad Λ, unreachable goal…"""


class InvariantViolation(StateMachineError):
    """verify_invariants() found a polluted machine (§2.7)."""


# ------------------------------------------------------ canonical digests
def _canonical(payload) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _digest(payload) -> str:
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


# --------------------------------------------------------- §2.4 Λ and V(s)
def _validate_lambda(lam=None):
    """Validate and NORMALIZE Λ to Σw=1 (non-negative, sum > 0 enforced)."""
    if lam is None:
        lam = DEFAULT_LAMBDA
    try:
        lam = tuple(float(x) for x in lam)
    except (TypeError, ValueError):
        raise StateMachineError(f"Λ must be numeric, got {lam!r}") from None
    if len(lam) != LAMBDA_DIM:
        raise StateMachineError(
            f"Λ must be in ℝ^{LAMBDA_DIM}, got dimension {len(lam)}")
    if any(x < 0.0 for x in lam):
        raise StateMachineError(f"Λ must be non-negative, got {lam}")
    total = math.fsum(lam)
    if total <= 0.0:
        raise StateMachineError(f"Λ must sum > 0, got {lam}")
    return tuple(x / total for x in lam)


def value(state, lam=None):
    """V(s) = Σ wᵢ·fᵢ(s) with Λ normalized to Σw=1 ⇒ V ∈ [0,1]."""
    if state not in _STATE_INDEX:
        raise StateMachineError(f"unknown state: {state!r}")
    w = _validate_lambda(lam)
    f = STATE_FEATURES[state]
    return float(math.fsum(wi * fi for wi, fi in zip(w, f)))


# ------------------------------------------------------ §2.5 A* machinery
def _successors(state):
    """Deterministic (sorted-by-event) successor list of (event, target)."""
    return sorted((sigma, target)
                  for (src, sigma), target in TRANSITIONS.items()
                  if src == state)


def heuristic(state):
    """Rank-scaled remaining-cost estimate to the accepting state.

    h(s) = c_min · (r_goal − r_s) / 2 with r = the main-chain rank and
    c_min = min Θ. Admissible: any edge spans ≤ 2 ranks at cost ≥ c_min,
    so the true remaining cost is ≥ c_min·Δr/2. Consistent: an edge of
    rank-span d reduces h by exactly c_min·d/2 ≤ c_min ≤ c(edge).
    """
    if state not in _STATE_INDEX:
        raise StateMachineError(f"unknown state: {state!r}")
    c_min = min(TRANSITION_COSTS.values())
    goal_rank = len(MAIN_CHAIN) - 1          # exfiltration = chain terminus
    return c_min * (goal_rank - _STATE_INDEX[state]) / 2.0


def _zero_h(_state):
    return 0.0


def astar(start, goal, heuristic_fn=None):
    """A* over (S, Θ). Returns (path, cost); raises if unreachable.

    Deterministic: successor expansion is event-sorted and the open heap
    tie-breaks by insertion counter. heuristic_fn defaults to the module
    heuristic when the goal is the accepting state, else to Dijkstra (0).
    """
    for name, node in (("start", start), ("goal", goal)):
        if node not in _STATE_INDEX:
            raise StateMachineError(f"unknown {name} state: {node!r}")
    h = heuristic_fn
    if h is None:
        h = heuristic if goal in FINAL_STATES else _zero_h
    if start == goal:
        return [start], 0.0
    g = {start: 0.0}
    came = {}
    counter = 0
    open_heap = [(h(start), counter, start)]
    done = set()
    while open_heap:
        _f, _tie, s = heapq.heappop(open_heap)
        if s in done:
            continue
        if s == goal:
            path = [s]
            while path[-1] in came:
                path.append(came[path[-1]])
            return list(reversed(path)), g[s]
        done.add(s)
        for sigma, t in _successors(s):
            ng = g[s] + TRANSITION_COSTS[(s, sigma)]
            if t not in g or ng < g[t] - 1e-12:
                g[t] = ng
                came[t] = s
                counter += 1
                heapq.heappush(open_heap, (ng + h(t), counter, t))
    raise StateMachineError(f"no path from {start!r} to {goal!r}")


# ------------------------------------------------------------ §2.6 Γ(s)
def gamma(state):
    """The per-state tactical profile (Γ): phase, C3 pair, guards, events."""
    if state not in _STATE_INDEX:
        raise StateMachineError(f"unknown state: {state!r}")
    return {
        "phase": PHASE_NAMES[state],
        "coverage": float(STATE_COVERAGE[state]),
        "stealth": float(STATE_FEATURES[state][2]),
        "guards": list(STATE_GUARDS[state]),
        "events": [sigma for sigma, _t in _successors(state)],
    }


# ----------------------------------------------------- §2.6 the machine
class StateMachine:
    """The runtime M: total step semantics, replay, invariants, digests."""

    def __init__(self, lam=None):
        self._lam = _validate_lambda(lam)
        self.current_state = INITIAL_STATE
        self.history = [INITIAL_STATE]
        self.event_log = []
        self.boundary = []

    @property
    def state(self):
        return self.current_state

    # ------------------------------------------------------------ §2.2 step
    def step(self, event):
        """Apply σ in the current state. Legal → True (machine advances);
        illegal → False and ATOMIC rejection: state, history and event log
        untouched, exactly one boundary record appended (§2.8)."""
        if not isinstance(event, str):
            self._log_illegal(event, "non-string event")
            return False
        key = (self.current_state, event)
        if key not in TRANSITIONS:
            self._log_illegal(
                event, f"no δ transition from {self.current_state!r} "
                       f"on event {event!r}")
            return False
        target = TRANSITIONS[key]
        self.current_state = target
        self.history.append(target)
        self.event_log.append(event)
        return True

    def _log_illegal(self, event, reason):
        self.boundary.append({
            "seq": len(self.boundary) + 1,
            "category": DEFAULT_ILLEGAL_CATEGORY,
            "state": self.current_state,
            "event": event if isinstance(event, str) else repr(event),
            "reason": reason,
        })

    def run(self, events):
        """Apply a sequence; returns the full state history (s₀ included)."""
        for e in events:
            self.step(e)
        return list(self.history)

    # ------------------------------------------------------ §2.7 invariants
    def _invariant_violations(self):
        v = []
        if self.current_state not in _STATE_INDEX:
            v.append(f"current_state {self.current_state!r} not in S")
        if not isinstance(self.history, list) or not self.history:
            v.append("history must be a non-empty list")
        else:
            if self.history[0] != INITIAL_STATE:
                v.append(f"history must start at {INITIAL_STATE!r}")
            if any(s not in _STATE_INDEX for s in self.history):
                v.append("history contains states outside S")
        if not isinstance(self.event_log, list):
            v.append("event_log must be a list")
        elif isinstance(self.history, list) and self.history:
            if len(self.event_log) != len(self.history) - 1:
                v.append(f"event_log length {len(self.event_log)} != "
                         f"len(history)-1 ({len(self.history) - 1})")
            else:
                for i, ev in enumerate(self.event_log):
                    src, dst = self.history[i], self.history[i + 1]
                    if TRANSITIONS.get((src, ev)) != dst:
                        v.append(f"history walk broken at step {i}: "
                                 f"({src!r}, {ev!r}) ↛ {dst!r}")
                        break
        # Λ well-formedness (stored normalized: dim 4, ≥ 0, Σ ≈ 1)
        try:
            lam = tuple(float(x) for x in self._lam)
            if (len(lam) != LAMBDA_DIM or any(x < 0.0 for x in lam)
                    or abs(math.fsum(lam) - 1.0) > 1e-9):
                v.append("Λ not a normalized ℝ⁴ vector")
        except Exception:
            v.append("Λ malformed")
        # C3 tradeoff at the current state
        if self.current_state in _STATE_INDEX:
            stealth = STATE_FEATURES[self.current_state][2]
            coverage = STATE_COVERAGE[self.current_state]
            if stealth + coverage > 1.0 + 1e-9:
                v.append(f"C3 tradeoff violated at {self.current_state!r}")
        # boundary log shape: contiguous seq from 1, categories in taxonomy
        if not isinstance(self.boundary, list):
            v.append("boundary must be a list")
        else:
            for i, entry in enumerate(self.boundary):
                if (not isinstance(entry, dict)
                        or entry.get("seq") != i + 1
                        or entry.get("category") not in BOUNDARY_CATEGORIES):
                    v.append(f"boundary entry {i} malformed")
                    break
        return v

    def verify_invariants(self):
        """True iff every §2.7 invariant holds (pollution → False)."""
        return not self._invariant_violations()

    def assert_invariants(self):
        """Raise InvariantViolation with the full violation list if dirty."""
        v = self._invariant_violations()
        if v:
            raise InvariantViolation("; ".join(v))
        return True

    # ------------------------------------------- §2.7 snapshot / digest
    def snapshot(self):
        """A deep-logical copy (lists/dicts copied; no live references)."""
        return {
            "version": 1,
            "current": self.current_state,
            "history": list(self.history),
            "event_log": list(self.event_log),
            "boundary": [dict(e) for e in self.boundary],
            "lam": tuple(self._lam),
        }

    def restore(self, snapshot):
        if not isinstance(snapshot, dict):
            raise StateMachineError("snapshot must be a dict")
        for key in ("current", "history", "event_log", "boundary", "lam"):
            if key not in snapshot:
                raise StateMachineError(f"snapshot missing key {key!r}")
        if snapshot["current"] not in _STATE_INDEX:
            raise StateMachineError("snapshot current not in S")
        self.current_state = snapshot["current"]
        self.history = list(snapshot["history"])
        self.event_log = list(snapshot["event_log"])
        self.boundary = [dict(e) for e in snapshot["boundary"]]
        self._lam = tuple(snapshot["lam"])
        return self

    def digest(self):
        """Semantic digest over the LOGICAL stream only — wall timings and
        object identities never enter it, so identical traces digest
        identically (the Axis-11 exact-determinism discipline)."""
        return _digest({
            "current": self.current_state,
            "history": list(self.history),
            "event_log": list(self.event_log),
            "boundary": [dict(e) for e in self.boundary],
        })


# ------------------------------------------------------------- §2.6 replay
def replay(events, lam=None):
    """Replay an event sequence on a FRESH machine; returns the state
    sequence [s₀, s₁, …]. Illegal events are skipped (logged to that
    machine's boundary) — the trace continues, matching step semantics."""
    m = StateMachine(lam)
    m.run(events)
    return list(m.history)


__all__ = [
    "BOUNDARY_CATEGORIES", "DEFAULT_ILLEGAL_CATEGORY", "DEFAULT_LAMBDA",
    "EVENTS", "FINAL_STATES", "INITIAL_STATE", "LAMBDA_DIM", "MAIN_CHAIN",
    "STATES", "STATE_FEATURES", "TRANSITION_COSTS", "TRANSITIONS",
    "InvariantViolation", "StateMachine", "StateMachineError",
    "astar", "gamma", "heuristic", "replay", "value",
]

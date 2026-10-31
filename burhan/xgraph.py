"""Burhan Axis-1 — Execution-Graph Engine (DAG orchestration core).

Implements engineering-spec Axis 1 (المحور الأول):

  G = (V, E, phi, psi, Omega, Sigma, Pi, Delta)                     §1.1
  W1..W6 well-formedness conditions                                 §1.2
  Kahn topological sort, Theta(|V|+|E|)                             §1.3
  Layered decomposition L(v) = max{L(u)+1 : (u,v) in E} u {0}       §1.4
  BSP parallel execution (supersteps + barrier)                     §1.5
  Speculative branching on Copy-on-Write context, argmax merge      §1.6
  Adaptive pruning k_adaptive = ceil(ceil(log2|V|) * (1+eps))       §1.7
  Interface contract (add_node .. restore)                          §1.8

Design notes (honest):
- Delta (V x S -> V x S) is carried by each Node.op: it maps a fork of the
  session context S to a NodeResult; the engine threads S through the DAG.
- Omega is the engine-provided topological rank (index in Kahn order); W2
  monotonicity is checked against it in validate().
- The 14-category boundary taxonomy and the Lamport-style logical clock are
  forward-compatible mounts for Axis 12 / Axis 3.
- Wall-clock timings are observability metadata ONLY: trace digests cover the
  logical event stream (run-local order), the merged context, the psi map and
  the deterministic boundary fields — never timings — so determinism claims
  are exact, not statistical (Axis-11 discipline).
"""
from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

MAX_NODES = 10 ** 6  # spec §1.1: |V| <= 10^6
PROJECTION_DIM = 17  # spec §1.1: Pi: V -> R^17 (W6)

# ------------------------------------------------------------------ §1.1 Sigma

class Event:
    GRAPH_READY = "graph_ready"
    NODE_START = "node_start"
    NODE_END = "node_end"
    LAYER_BARRIER = "layer_barrier"
    BRANCH_FORK = "branch_fork"
    BRANCH_PRUNED = "branch_pruned"
    BRANCH_MERGE = "branch_merge"
    SNAPSHOT_TAKEN = "snapshot_taken"
    RESTORE_APPLIED = "restore_applied"


SIGMA = frozenset({
    Event.GRAPH_READY, Event.NODE_START, Event.NODE_END, Event.LAYER_BARRIER,
    Event.BRANCH_FORK, Event.BRANCH_PRUNED, Event.BRANCH_MERGE,
    Event.SNAPSHOT_TAKEN, Event.RESTORE_APPLIED,
})

# ------------------------------------------- Axis-12 preview: boundary taxonomy

BOUNDARY_CATEGORIES = frozenset({
    "OUT_OF_SCOPE", "PRECONDITION_FAILED", "RESOURCE_EXHAUSTED",
    "DETECTION_AVOIDED", "TIME_LIMIT", "SAFETY_GUARD", "UNKNOWN_PROTOCOL",
    "AUTH_REQUIRED", "ENCRYPTION_UNTRAVERSABLE", "HARDWARE_LIMIT",
    "NETWORK_ISOLATED", "POLICY_RESTRICTED", "CAPABILITY_MISSING",
    "UNSUPPORTED_PLATFORM",
})

DEFAULT_PRUNE_CATEGORY = "SAFETY_GUARD"


# ------------------------------------------------------------------- errors

class WellFormednessError(ValueError):
    """A W1..W6 condition was violated (§1.2)."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


# ------------------------------------------------------------------- §1.1 phi / Pi

@dataclass
class Cost:
    """phi: V -> R+ x R+ x R+  (time, compute, bytes)."""
    time: float
    compute: float
    bytes: float = 0.0

    def total(self) -> float:
        return self.time + self.compute + self.bytes

    def as_list(self) -> List[float]:
        return [self.time, self.compute, self.bytes]


Projection = Tuple[float, ...]


@dataclass
class NodeResult:
    """Result of applying a node's Delta operator to a context fork."""
    ok: bool
    note: str = ""


@dataclass
class Node:
    """A procedural vertex. op = the Delta carrier (§1.1)."""
    name: str
    op: Callable[["COWContext"], NodeResult]
    cost: Cost
    projection: Projection
    psi: Optional[int] = None  # W1: None until executed, then 0/1
    meta: Dict[str, Any] = field(default_factory=dict)


# ------------------------------------------------------------------- §1.6 COW

class COWContext:
    """Copy-on-write session context: fork() is O(1) structural sharing.

    Invariant: the parent stays quiescent while any fork is active (the BSP
    executor merges only at barriers; speculate merges only at argmax), so a
    fork's own overlay IS its full diff vs the parent.
    """

    __slots__ = ("_base", "_overlay", "_lock")

    def __init__(self, base: Optional["COWContext"] = None,
                 overlay: Optional[Dict[str, Any]] = None):
        self._base = base
        self._overlay: Dict[str, Any] = {} if overlay is None else overlay
        self._lock = threading.Lock()

    def fork(self) -> "COWContext":
        return COWContext(base=self)

    def set(self, key: str, val: Any) -> None:
        with self._lock:
            self._overlay[key] = val

    def get(self, key: str, default: Any = None) -> Any:
        ctx = self
        while ctx is not None:
            with ctx._lock:
                if key in ctx._overlay:
                    return ctx._overlay[key]
            ctx = ctx._base
        return default

    def own_keys(self) -> List[str]:
        with self._lock:
            return sorted(self._overlay)

    def diff(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._overlay)

    def flatten(self) -> Dict[str, Any]:
        chain: List["COWContext"] = []
        ctx = self
        while ctx is not None:
            chain.append(ctx)
            ctx = ctx._base
        out: Dict[str, Any] = {}
        for c in reversed(chain):
            with c._lock:
                out.update(c._overlay)
        return out

    def merge_from(self, fork: "COWContext") -> None:
        """Parent absorbs a child's own writes (superstep-4 / argmax merge)."""
        with fork._lock:
            items = dict(fork._overlay)
        with self._lock:
            self._overlay.update(items)


# ------------------------------------------------------------- §1.7 / §12.1 records

@dataclass
class PruningRecord:
    """Boundary-log entry (Axis-12 §12.1 shape; written by §1.7 pruning)."""
    branch_id: str
    node: int
    reason: str
    category: str
    timestamp: str
    confidence: float
    logical_ts: int

    def deterministic_fields(self) -> Dict[str, Any]:
        return {"branch_id": self.branch_id, "node": self.node,
                "reason": self.reason, "category": self.category,
                "confidence": self.confidence}


BoundaryRecord = PruningRecord  # Axis-12 name, same shape


# ------------------------------------------------------------------- §2.5 preview

FEATURE_KEYS = ("access", "persistence", "stealth", "coverage")
DEFAULT_WEIGHTS = (0.25, 0.25, 0.25, 0.25)


def _check_weights(weights: Sequence[float]) -> Tuple[float, float, float, float]:
    w = tuple(float(x) for x in weights)
    if len(w) != 4 or any(x < 0 for x in w) or abs(sum(w) - 1.0) > 1e-9:
        raise ValueError(
            f"weights must be 4 non-negative reals summing to 1 (got {weights!r})")
    return w  # type: ignore[return-value]


def value(state: Mapping[str, Any], weights: Sequence[float]) -> float:
    """V(s) = sum_i w_i * f_i(s) with sum w_i = 1 (spec §1.6 / §2.5)."""
    w = _check_weights(weights)
    feats = [float(state.get(k, 0.0)) for k in FEATURE_KEYS]
    return sum(wi * fi for wi, fi in zip(w, feats))


# ------------------------------------------------------------------- §1.8 trace

def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _digest(payload: Any) -> str:
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


@dataclass
class ExecutionTrace:
    """One execute_parallel() run. Timings are metadata; digest is logical."""
    events: List[Dict[str, Any]]
    node_timings: Dict[int, Dict[str, float]]
    layer_walls: List[float]
    summary: Dict[str, Any]
    _context: Dict[str, Any]
    _psi: Dict[str, Optional[int]]
    _boundary: List[Dict[str, Any]]

    def digest(self) -> str:
        logical = []
        for i, e in enumerate(self.events):
            logical.append({"index": i, "type": e["type"],
                            "node": e.get("node"), "layer": e.get("layer"),
                            "psi": e.get("psi"), "branch": e.get("branch")})
        return _digest({"events": logical, "context": self._context,
                        "psi": self._psi, "boundary_log": self._boundary})


@dataclass
class GraphSnapshot:
    """§1.8 snapshot — semantic state; ops stay live in-process references."""
    node_state: List[Dict[str, Any]]
    edge_list: List[Tuple[int, int]]
    context: Dict[str, Any]
    boundary_log: List[Dict[str, Any]]
    ops: List[Callable[[COWContext], NodeResult]]
    lamport: int
    rng_state: Any

    def serialize(self) -> Dict[str, Any]:
        return {"version": 1, "nodes": self.node_state,
                "edges": [list(e) for e in self.edge_list],
                "context": self.context, "boundary_log": self.boundary_log}

    def digest(self) -> str:
        return _digest(self.serialize())


# ------------------------------------------------------------------- §1.8 engine

class _NodeRun:
    __slots__ = ("ok", "fork", "start", "end", "dur", "note")

    def __init__(self, ok: bool, fork: COWContext, start: float, end: float,
                 note: str = ""):
        self.ok = ok
        self.fork = fork
        self.start = start
        self.end = end
        self.dur = end - start
        self.note = note


class ExecutionGraph:
    """The Axis-1 engine: DAG + W-conditions + Kahn + layers + BSP + COW."""

    def __init__(self, seed: Optional[int] = None, eps: float = 0.25,
                 weights: Sequence[float] = DEFAULT_WEIGHTS,
                 max_nodes: int = MAX_NODES):
        import random
        if not (0.0 <= eps <= 0.5):
            raise ValueError(f"eps must lie in [0, 0.5] (got {eps})")
        self._eps = eps
        self._weights = _check_weights(weights)
        self._max_nodes = max_nodes
        self._rng = random.Random(seed)
        self._nodes: List[Node] = []
        self._ops: List[Callable[[COWContext], NodeResult]] = []
        self._adj: List[List[int]] = []
        self._edge_list: List[Tuple[int, int]] = []
        self._edgeset: set = set()
        self._context = COWContext()
        self._events: List[Dict[str, Any]] = []
        self._lamport = 0
        self._boundary_log: List[PruningRecord] = []
        self._names: Dict[str, int] = {}
        self.last_speculate: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------- properties

    @property
    def nodes(self) -> List[Node]:
        return self._nodes

    @property
    def context(self) -> COWContext:
        return self._context

    @property
    def events(self) -> List[Dict[str, Any]]:
        return self._events

    @property
    def boundary_log(self) -> List[PruningRecord]:
        return self._boundary_log

    @property
    def k_adaptive(self) -> int:
        """§1.7: ceil(ceil(log2|V|) * (1 + eps)), |V| floored at 2."""
        base = math.ceil(math.log2(max(len(self._nodes), 2)))
        return math.ceil(base * (1.0 + self._eps))

    # ------------------------------------------------------------- §1.8 build

    def add_node(self, node: Node) -> int:
        if len(self._nodes) >= self._max_nodes:
            raise ValueError(
                f"max_nodes={self._max_nodes} exceeded (spec: |V| <= 10^6)")
        if node.name in self._names:
            raise ValueError(f"duplicate node name: {node.name!r}")
        if node.psi not in (None, 0, 1):  # W1
            raise WellFormednessError(
                "W1", f"node {node.name!r}: psi={node.psi!r} not in {{0,1}}")
        if (node.cost.time < 0 or node.cost.compute < 0 or node.cost.bytes < 0
                or node.cost.total() <= 0):  # W5
            raise WellFormednessError(
                "W5", f"node {node.name!r}: cost {node.cost.as_list()} "
                      "must be non-negative with positive total")
        if len(node.projection) != PROJECTION_DIM:  # W6
            raise WellFormednessError(
                "W6", f"node {node.name!r}: |Pi(v)|={len(node.projection)} "
                      f"!= {PROJECTION_DIM}")
        nid = len(self._nodes)
        self._names[node.name] = nid
        self._nodes.append(node)
        self._ops.append(node.op)
        self._adj.append([])
        return nid

    def add_edge(self, u: int, v: int) -> int:
        for x in (u, v):
            if not (0 <= x < len(self._nodes)):
                raise ValueError(f"node id {x} out of range")
        if u == v:  # a self-loop is a cycle -> W4
            raise WellFormednessError("W4", f"self-loop on node {u}")
        if (u, v) in self._edgeset:
            raise ValueError(f"duplicate edge {u}->{v}")
        eid = len(self._edge_list)
        self._edgeset.add((u, v))
        self._edge_list.append((u, v))
        self._adj[u].append(v)
        return eid

    # ------------------------------------------------------------- §1.2 validate

    def validate(self) -> Dict[str, Any]:
        violations: List[Dict[str, str]] = []
        # W1 / W5 / W6 — node-level conditions (catch post-add corruption too)
        for i, n in enumerate(self._nodes):
            if n.psi not in (None, 0, 1):
                violations.append(
                    {"code": "W1",
                     "detail": f"node {i}({n.name}): psi={n.psi!r}"})
            if (n.cost.time < 0 or n.cost.compute < 0 or n.cost.bytes < 0
                    or n.cost.total() <= 0):
                violations.append(
                    {"code": "W5",
                     "detail": f"node {i}({n.name}): cost "
                               f"{n.cost.as_list()}"})
            if len(n.projection) != PROJECTION_DIM:
                violations.append(
                    {"code": "W6",
                     "detail": f"node {i}({n.name}): |Pi|="
                               f"{len(n.projection)}"})
        # W4 — acyclicity (Kahn completeness)
        indeg = [0] * len(self._nodes)
        for u, v in self._edge_list:
            indeg[v] += 1
        sources = [i for i in range(len(self._nodes)) if indeg[i] == 0]
        from collections import deque
        q = deque(i for i in range(len(self._nodes)) if indeg[i] == 0)
        seen = 0
        omega: Dict[int, int] = {}
        while q:
            x = q.popleft()
            omega[x] = seen
            seen += 1
            for y in self._adj[x]:
                indeg[y] -= 1
                if indeg[y] == 0:
                    q.append(y)
        if seen < len(self._nodes):
            violations.append(
                {"code": "W4",
                 "detail": f"cycle detected: {len(self._nodes) - seen} "
                           "nodes unresolved"})
        else:
            # W2 — Omega monotone along every edge
            for u, v in self._edge_list:
                if omega[u] >= omega[v]:
                    violations.append(
                        {"code": "W2",
                         "detail": f"edge {u}->{v}: Omega(u)={omega[u]} "
                                   f">= Omega(v)={omega[v]}"})
        # W3 — exactly one source, all nodes reachable from it
        # (uses the PRE-Kahn source list; Kahn above mutates indeg to zero)
        if len(sources) != 1:
            violations.append(
                {"code": "W3",
                 "detail": f"expected exactly 1 source (v0), found "
                           f"{len(sources)}: {sources[:8]}"})
        elif seen == len(self._nodes):  # BFS reachability from the source
            stack = [sources[0]]
            visited = set(stack)
            while stack:
                x = stack.pop()
                for y in self._adj[x]:  # successors: walk DOWNSTREAM
                    if y not in visited:
                        visited.add(y)
                        stack.append(y)
            if len(visited) != len(self._nodes):
                violations.append(
                    {"code": "W3",
                     "detail": f"{len(self._nodes) - len(visited)} nodes "
                               "unreachable from v0"})
        return {"well_formed": not violations, "violations": violations,
                "nodes": len(self._nodes), "edges": len(self._edge_list)}

    # ------------------------------------------------------------- §1.3 Kahn

    def topological_sort(self) -> List[int]:
        from collections import deque
        indeg = [0] * len(self._nodes)
        for _u, v in self._edge_list:
            indeg[v] += 1
        q = deque(i for i in range(len(self._nodes)) if indeg[i] == 0)
        order: List[int] = []
        while q:
            x = q.popleft()
            order.append(x)
            for y in self._adj[x]:
                indeg[y] -= 1
                if indeg[y] == 0:
                    q.append(y)
        if len(order) < len(self._nodes):
            raise WellFormednessError(
                "W4", f"cycle detected: {len(self._nodes) - len(order)} "
                      "nodes unresolved by Kahn")
        return order

    # ------------------------------------------------------------- §1.4 layers

    def layer_decompose(self) -> List[List[int]]:
        order = self.topological_sort()
        layer_of: Dict[int, int] = {}
        preds: List[List[int]] = [[] for _ in self._nodes]
        for u, v in self._edge_list:
            preds[v].append(u)
        for x in order:  # L(v) = max{L(u)+1 : (u,v) in E} u {0}
            layer_of[x] = 0
            for u in preds[x]:
                cand = layer_of[u] + 1
                if cand > layer_of[x]:
                    layer_of[x] = cand
        if not self._nodes:
            return []
        depth = max(layer_of.values())
        layers: List[List[int]] = [[] for _ in range(depth + 1)]
        for x in sorted(layer_of):  # ascending node id within a layer
            layers[layer_of[x]].append(x)
        return layers

    # ------------------------------------------------------------- §1.5 BSP

    def _emit(self, etype: str, **fields: Any) -> Dict[str, Any]:
        if etype not in SIGMA:
            raise ValueError(f"event {etype!r} not in Sigma")
        self._lamport += 1
        ev = {"seq": self._lamport, "type": etype}
        ev.update(fields)
        self._events.append(ev)
        return ev

    def _run_node(self, nid: int) -> _NodeRun:
        fork = self._context.fork()
        t0 = time.monotonic()
        try:
            res = self._ops[nid](fork)
            if not isinstance(res, NodeResult):
                raise TypeError(f"op of node {nid} returned "
                                f"{type(res).__name__}, expected NodeResult")
            ok, note = bool(res.ok), res.note
        except Exception as e:  # noqa: BLE001 — psi=0, engine stays alive
            ok, note = False, f"{type(e).__name__}: {e}"[:200]
        t1 = time.monotonic()
        return _NodeRun(ok, fork, t0, t1, note)

    def execute_parallel(self, concurrency: int) -> ExecutionTrace:
        """BSP model: per layer — distribute / execute / barrier / merge."""
        if concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        start_idx = len(self._events)
        self._emit(Event.GRAPH_READY, nodes=len(self._nodes),
                   concurrency=concurrency)
        layers = self.layer_decompose()
        node_timings: Dict[int, Dict[str, float]] = {}
        layer_walls: List[float] = []
        t_serial = 0.0
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            for li, layer in enumerate(layers):
                wall0 = time.monotonic()
                futures = {ex.submit(self._run_node, nid): nid
                           for nid in layer}
                runs = {futures[f]: f.result() for f in futures}  # barrier
                wall1 = time.monotonic()
                # superstep 4: deterministic merge in ascending node id
                for nid in sorted(layer):
                    run = runs[nid]
                    node = self._nodes[nid]
                    node.psi = 1 if run.ok else 0
                    node_timings[nid] = {"start": run.start, "end": run.end,
                                         "dur": run.dur}
                    if run.note:
                        node_timings[nid]["note"] = run.note  # type: ignore
                    self._emit(Event.NODE_START, node=nid, layer=li)
                    self._emit(Event.NODE_END, node=nid, layer=li,
                               psi=node.psi)
                    self._context.merge_from(run.fork)
                    t_serial += run.dur
                self._emit(Event.LAYER_BARRIER, layer=li,
                           wall_s=round(wall1 - wall0, 6))
                layer_walls.append(wall1 - wall0)
        t_parallel = sum(layer_walls)
        efficiency = (t_serial / (concurrency * t_parallel)) if t_parallel > 0 \
            else 0.0
        run_events = [dict(e) for e in self._events[start_idx:]]
        return ExecutionTrace(
            events=run_events,
            node_timings=node_timings,
            layer_walls=layer_walls,
            summary={"layers": len(layers), "concurrency": concurrency,
                     "nodes": len(self._nodes), "t_serial": round(t_serial, 6),
                     "t_parallel": round(t_parallel, 6),
                     "efficiency": round(efficiency, 6),
                     "pruned": len(self._boundary_log),
                     "events": len(run_events)},
            _context=self._context.flatten(),
            _psi={n.name: n.psi for n in self._nodes},
            _boundary=[r.deterministic_fields() for r in self._boundary_log],
        )

    # --------------------------------------------------- §1.6 + §1.7 speculate

    def _record_prune(self, branch_id: str, anchor: int, reason: str,
                      category: str = DEFAULT_PRUNE_CATEGORY) -> PruningRecord:
        rec = PruningRecord(
            branch_id=branch_id, node=anchor, reason=reason, category=category,
            timestamp=datetime.now(timezone.utc).isoformat(), confidence=1.0,
            logical_ts=self._lamport)
        self._boundary_log.append(rec)
        self._emit(Event.BRANCH_PRUNED, branch=branch_id, node=anchor,
                   reason=reason, category=category)
        return rec

    def speculate(self, anchor: int, branches: List[List[Node]]) -> int:
        """Fork COW per branch, execute isolated chains, argmax-V merge.

        Adaptive pruning (§1.7): a chain hitting k_adaptive consecutive
        psi=0 results is pruned, logged in the boundary log, and its
        remaining nodes are never executed.
        """
        if not (0 <= anchor < len(self._nodes)):
            raise ValueError(f"anchor {anchor} out of range")
        if not branches:
            raise ValueError("speculate needs at least one branch")
        k = self.k_adaptive
        report: List[Dict[str, Any]] = []
        completed: List[Tuple[float, int, COWContext]] = []
        for bi, chain in enumerate(branches):
            branch_id = f"b{anchor}.{bi}"
            self._emit(Event.BRANCH_FORK, branch=branch_id, node=anchor)
            fork = self._context.fork()
            consec = 0
            executed = 0
            pruned = False
            for node in chain:
                executed += 1
                self._emit(Event.NODE_START, node=anchor, layer=None,
                           branch=branch_id)
                try:
                    res = node.op(fork)
                    ok = isinstance(res, NodeResult) and bool(res.ok)
                except Exception:  # noqa: BLE001
                    ok = False
                node.psi = 1 if ok else 0
                self._emit(Event.NODE_END, node=anchor, psi=node.psi,
                           branch=branch_id)
                consec = 0 if ok else consec + 1
                if consec >= k:
                    pruned = True
                    self._record_prune(
                        branch_id, anchor,
                        f"k_adaptive={k} consecutive psi=0 "
                        "(adaptive pruning, spec §1.7)")
                    break
            val = None if pruned else value(fork.flatten(), self._weights)
            report.append({"id": branch_id, "executed": executed,
                           "pruned": pruned, "value": val})
            if not pruned:
                completed.append((float(val), bi, fork))  # type: ignore[arg-type]
        if not completed:
            raise RuntimeError("all speculative branches were pruned")
        best_val, best_bi, best_fork = completed[0]
        for val, bi, fork in completed[1:]:
            if val > best_val:  # ties keep the lowest index (deterministic)
                best_val, best_bi, best_fork = val, bi, fork
        self._context.merge_from(best_fork)
        self._emit(Event.BRANCH_MERGE, branch=report[best_bi]["id"],
                   value=best_val)
        self.last_speculate = {"anchor": anchor, "k_adaptive": k,
                               "branches": report, "winner": best_bi}
        return best_bi

    def prune(self, branch_id: str) -> PruningRecord:
        """Explicit orchestrator prune of a completed branch from the last
        speculate() session (the adaptive rule fires internally)."""
        last = self.last_speculate
        if last is None:
            raise KeyError("no speculate() session to prune from")
        for bi, entry in enumerate(last["branches"]):
            if entry["id"] == branch_id:
                if entry["pruned"]:
                    raise ValueError(f"branch {branch_id} already pruned")
                entry["pruned"] = True
                return self._record_prune(
                    branch_id, last["anchor"],
                    "explicit orchestrator prune (spec §1.8 prune())")
        raise KeyError(f"unknown branch {branch_id!r}")

    # ------------------------------------------------------------- §1.8 snap

    def snapshot(self) -> GraphSnapshot:
        snap = GraphSnapshot(
            node_state=[{"name": n.name, "cost": n.cost.as_list(),
                         "projection": list(n.projection), "psi": n.psi}
                        for n in self._nodes],
            edge_list=list(self._edge_list),
            context=self._context.flatten(),
            boundary_log=[r.deterministic_fields()
                          for r in self._boundary_log],
            ops=list(self._ops),
            lamport=self._lamport,
            rng_state=self._rng.getstate(),
        )
        self._emit(Event.SNAPSHOT_TAKEN, digest=snap.digest())
        return snap

    def restore(self, snapshot: GraphSnapshot) -> None:
        if len(snapshot.node_state) != len(snapshot.ops):
            raise ValueError("snapshot ops/node count mismatch")
        self._nodes = []
        self._ops = []
        self._adj = []
        self._names = {}
        for i, st in enumerate(snapshot.node_state):
            node = Node(name=st["name"],
                        op=snapshot.ops[i],  # type: ignore[arg-type]
                        cost=Cost(*st["cost"]),
                        projection=tuple(st["projection"]),
                        psi=st["psi"])
            self._names[node.name] = i
            self._nodes.append(node)
            self._ops.append(node.op)
            self._adj.append([])
        self._edge_list = []
        self._edgeset = set()
        for u, v in snapshot.edge_list:
            self._edgeset.add((u, v))
            self._edge_list.append((u, v))
            self._adj[u].append(v)
        self._context = COWContext()
        for k, v in snapshot.context.items():
            self._context.set(k, v)
        self._boundary_log = [PruningRecord(
            branch_id=r["branch_id"], node=r["node"], reason=r["reason"],
            category=r["category"], timestamp="", confidence=r["confidence"],
            logical_ts=0) for r in snapshot.boundary_log]
        self._lamport = snapshot.lamport
        self._rng.setstate(snapshot.rng_state)
        self.last_speculate = None
        self._emit(Event.RESTORE_APPLIED, nodes=len(self._nodes))

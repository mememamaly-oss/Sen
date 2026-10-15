#!/usr/bin/env python3
"""SENTINEL Axis-1 suite — Execution-Graph Engine (spec §1.1–§1.8).

Standalone by design: NOT registered as @case in run_tests.py, so the core
suite contract (227 registered x 19 chunks = 4313) stays untouched while the
axis is mounted axis-by-axis per the supervisor's phase plan.

Red/green discipline: run BEFORE sentinel/xgraph.py exists -> every case fails
with the import error (RED evidence); implement -> 22/22 (GREEN evidence).
Determinism rule R3: the suite digest must be identical across 3 runs.

Usage: python3 tests/test_axis1_xgraph.py [--out results/axis1/axis1_suite.json]
"""
import argparse
import hashlib
import inspect
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from sentinel.xgraph import (
        BOUNDARY_CATEGORIES, SIGMA, Cost, COWContext, ExecutionGraph,
        ExecutionTrace, Event, Node, NodeResult, PruningRecord,
        WellFormednessError, value,
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
        raise AssertionError(f"RED — sentinel.xgraph unavailable: {_IMPORT_ERROR}")


def _mkop(ok=True, writes=None, dur=0.0, features=None):
    def op(ctx):
        if dur:
            time.sleep(dur)
        for k, v in (writes or {}).items():
            ctx.set(k, v)
        for k, v in (features or {}).items():
            ctx.set(k, v)
        return NodeResult(ok=ok)
    return op


def _mknode(name, ok=True, writes=None, dur=0.0, cost=None, projection=None,
            psi=None):
    return Node(
        name=name,
        op=_mkop(ok=ok, writes=writes, dur=dur),
        cost=cost if cost is not None else Cost(1.0, 1.0, 1.0),
        projection=projection if projection is not None else (0.0,) * 17,
        psi=psi,
    )


# ---------------------------------------------------------------- W-conditions

@case
def test_w1_psi_binary_domain():
    _guard_red()
    g = ExecutionGraph()
    g.add_node(_mknode("a"))
    # preset non-binary psi must be rejected at the door (W1)
    try:
        g.add_node(_mknode("bad", psi=2))
        raise AssertionError("psi=2 accepted at add_node")
    except WellFormednessError as e:
        assert e.code == "W1", e.code
    # post-add corruption is caught by validate()
    g.nodes[0].psi = 2
    rep = g.validate()
    assert not rep["well_formed"]
    assert any(v["code"] == "W1" for v in rep["violations"]), rep
    # legal binary values pass
    g.nodes[0].psi = 1
    assert all(v["code"] != "W1" for v in g.validate()["violations"])


@case
def test_w2_omega_monotone():
    _guard_red()
    g = ExecutionGraph()
    ids = [g.add_node(_mknode(f"n{i}")) for i in range(5)]
    for u, v in ((0, 1), (0, 2), (1, 3), (2, 3), (3, 4)):
        g.add_edge(ids[u], ids[v])
    order = g.topological_sort()
    omega = {n: i for i, n in enumerate(order)}
    for u, v in ((0, 1), (0, 2), (1, 3), (2, 3), (3, 4)):
        assert omega[ids[u]] < omega[ids[v]], (u, v, order)
    rep = g.validate()
    assert rep["well_formed"], rep
    assert not any(v["code"] == "W2" for v in rep["violations"])


@case
def test_w3_single_source_reachability():
    _guard_red()
    # two disconnected sources -> W3 violation
    g = ExecutionGraph()
    a = g.add_node(_mknode("a"))
    b = g.add_node(_mknode("b"))
    c = g.add_node(_mknode("c"))
    g.add_edge(a, c)
    rep = g.validate()
    assert not rep["well_formed"]
    assert any(v["code"] == "W3" for v in rep["violations"]), rep
    # single source reachable everywhere -> no W3 violation
    g2 = ExecutionGraph()
    a2 = g2.add_node(_mknode("a"))
    b2 = g2.add_node(_mknode("b"))
    c2 = g2.add_node(_mknode("c"))
    g2.add_edge(a2, b2)
    g2.add_edge(a2, c2)
    rep2 = g2.validate()
    assert rep2["well_formed"], rep2


@case
def test_w4_acyclicity():
    _guard_red()
    # 2-cycle
    g = ExecutionGraph()
    a = g.add_node(_mknode("a"))
    b = g.add_node(_mknode("b"))
    g.add_edge(a, b)
    g.add_edge(b, a)
    try:
        g.topological_sort()
        raise AssertionError("2-cycle not detected by topological_sort")
    except WellFormednessError as e:
        assert e.code == "W4", e.code
    assert any(v["code"] == "W4" for v in g.validate()["violations"])
    # 3-cycle
    g3 = ExecutionGraph()
    x = g3.add_node(_mknode("x"))
    y = g3.add_node(_mknode("y"))
    z = g3.add_node(_mknode("z"))
    g3.add_edge(x, y)
    g3.add_edge(y, z)
    g3.add_edge(z, x)
    try:
        g3.topological_sort()
        raise AssertionError("3-cycle not detected")
    except WellFormednessError as e:
        assert e.code == "W4"
    # self-loop rejected immediately at add_edge
    g4 = ExecutionGraph()
    s = g4.add_node(_mknode("s"))
    try:
        g4.add_edge(s, s)
        raise AssertionError("self-loop accepted")
    except WellFormednessError as e:
        assert e.code == "W4"
    # duplicate edge rejected (would corrupt in-degree accounting)
    t = g4.add_node(_mknode("t"))
    g4.add_edge(s, t)
    try:
        g4.add_edge(s, t)
        raise AssertionError("duplicate edge accepted")
    except ValueError:
        pass


@case
def test_w5_positive_cost():
    _guard_red()
    g = ExecutionGraph()
    try:
        g.add_node(_mknode("zero", cost=Cost(0.0, 0.0, 0.0)))
        raise AssertionError("zero cost accepted")
    except WellFormednessError as e:
        assert e.code == "W5", e.code
    try:
        g.add_node(_mknode("neg", cost=Cost(-1.0, 1.0, 1.0)))
        raise AssertionError("negative cost component accepted")
    except WellFormednessError as e:
        assert e.code == "W5"
    # post-add corruption caught by validate
    g2 = ExecutionGraph()
    g2.add_node(_mknode("ok"))
    g2.nodes[0].cost = Cost(0.0, 0.0, 0.0)
    assert any(v["code"] == "W5" for v in g2.validate()["violations"])


@case
def test_w6_projection_dimension():
    _guard_red()
    g = ExecutionGraph()
    try:
        g.add_node(_mknode("p16", projection=(0.0,) * 16))
        raise AssertionError("16-dim projection accepted")
    except WellFormednessError as e:
        assert e.code == "W6", e.code
    try:
        g.add_node(_mknode("p18", projection=(0.0,) * 18))
        raise AssertionError("18-dim projection accepted")
    except WellFormednessError as e:
        assert e.code == "W6"
    n17 = g.add_node(_mknode("p17", projection=tuple(float(i) for i in range(17))))
    assert g.nodes[n17].projection[16] == 16.0
    # post-add corruption caught by validate
    g.nodes[n17].projection = (0.0,) * 16
    assert any(v["code"] == "W6" for v in g.validate()["violations"])


# ------------------------------------------------------------ Kahn + layers

@case
def test_topological_sort_kahn_correctness():
    _guard_red()
    g = ExecutionGraph()
    ids = [g.add_node(_mknode(f"n{i}")) for i in range(6)]
    edges = ((0, 1), (0, 2), (0, 3), (1, 4), (2, 4), (3, 5), (4, 5))
    for u, v in edges:
        g.add_edge(ids[u], ids[v])
    o1 = g.topological_sort()
    assert sorted(o1) == sorted(ids), "order must cover every node exactly once"
    pos = {n: i for i, n in enumerate(o1)}
    for u, v in edges:
        assert pos[ids[u]] < pos[ids[v]]
    # deterministic: FIFO + insertion-order ties
    assert o1 == g.topological_sort() == g.topological_sort()
    assert o1[0] == ids[0], "single source must come first"


@case
def test_layer_decompose_exact():
    _guard_red()
    g = ExecutionGraph()
    n0 = g.add_node(_mknode("n0"))
    n1 = g.add_node(_mknode("n1"))
    n2 = g.add_node(_mknode("n2"))
    n3 = g.add_node(_mknode("n3"))
    n4 = g.add_node(_mknode("n4"))
    for u, v in ((n0, n1), (n0, n2), (n1, n3), (n2, n3), (n3, n4)):
        g.add_edge(u, v)
    layers = g.layer_decompose()
    assert layers == [[n0], [n1, n2], [n3], [n4]], layers
    # L(v) = max(L(u)+1) over predecessors, 0 for the source
    # intra-layer independence: no edge inside a layer
    lidx = {n: i for i, lay in enumerate(layers) for n in lay}
    for u, v in ((n0, n1), (n0, n2), (n1, n3), (n2, n3), (n3, n4)):
        assert lidx[u] < lidx[v]
    # flat cover
    assert sorted(n for lay in layers for n in lay) == sorted([n0, n1, n2, n3, n4])


# ------------------------------------------------------------ BSP execution

def _build_wide_graph(nodes_per_layer=8, layers=3, dur=0.02, root_dur=0.005):
    g = ExecutionGraph()
    root = g.add_node(_mknode("root", writes={"root": 1}, dur=root_dur))
    prev = [root]
    for li in range(layers):
        cur = []
        for i in range(nodes_per_layer):
            nid = g.add_node(_mknode(f"L{li}_{i}", writes={f"k_L{li}_{i}": li},
                                     dur=dur))
            cur.append(nid)
        # each node depends on two predecessors of the previous layer
        for i, nid in enumerate(cur):
            a = prev[i % len(prev)]
            b = prev[(i + 1) % len(prev)]
            g.add_edge(a, nid)
            if b != a:  # root layer has a single predecessor
                g.add_edge(b, nid)
        prev = cur
    return g


@case
def test_bsp_parallel_execution():
    _guard_red()
    g = _build_wide_graph()
    trace = g.execute_parallel(concurrency=4)
    # every node executed exactly once and merged into the shared context
    assert len(g.context.flatten()) == 1 + 3 * 8, g.context.flatten().keys()
    # barrier property: max(end in layer i) <= min(start in layer i+1)
    layers = g.layer_decompose()
    for li in range(len(layers) - 1):
        end_max = max(trace.node_timings[n]["end"] for n in layers[li])
        start_min = min(trace.node_timings[n]["start"] for n in layers[li + 1])
        assert end_max <= start_min + 1e-9, f"barrier violated at layer {li}"
    # all psi = 1 (all ops succeeded)
    assert all(n.psi == 1 for n in g.nodes)


@case
def test_bsp_efficiency_bounds():
    _guard_red()
    g = _build_wide_graph()
    trace = g.execute_parallel(concurrency=4)
    s = trace.summary
    for key in ("layers", "concurrency", "nodes", "t_serial", "t_parallel",
                "efficiency", "pruned", "events"):
        assert key in s, f"summary missing {key}: {s}"
    assert s["layers"] == 4 and s["nodes"] == 25 and s["concurrency"] == 4
    assert s["t_serial"] > 0 and s["t_parallel"] > 0
    assert 0.0 < s["efficiency"] <= 1.0 + 1e-6, s["efficiency"]


@case
def test_event_alphabet():
    _guard_red()
    g = _build_wide_graph(nodes_per_layer=2, layers=1, dur=0.0)
    g.execute_parallel(concurrency=2)
    assert set(e["type"] for e in g.events) <= SIGMA
    assert "node_start" in set(e["type"] for e in g.events)
    assert "node_end" in set(e["type"] for e in g.events)
    assert "layer_barrier" in set(e["type"] for e in g.events)
    # sequence numbers are monotonic and unique
    seqs = [e["seq"] for e in g.events]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)
    # unknown event rejected by the emitter
    try:
        g._emit("definitely_not_an_event")
        raise AssertionError("unknown event accepted")
    except ValueError:
        pass


# ------------------------------------------------------------ COW + branching

@case
def test_cow_fork_isolation():
    _guard_red()
    base = COWContext()
    base.set("shared", 1)
    a = base.fork()
    b = base.fork()
    a.set("only_a", 2)
    b.set("only_b", 3)
    assert base.get("shared") == 1 and base.get("only_a") is None
    assert a.get("shared") == 1 and a.get("only_a") == 2 and a.get("only_b") is None
    assert b.get("only_b") == 3 and b.get("only_a") is None
    assert a.flatten() == {"shared": 1, "only_a": 2}
    assert b.diff() == {"only_b": 3}
    # parent absorbs a child's writes only on explicit merge
    base.merge_from(a)
    assert base.get("only_a") == 2 and base.get("only_b") is None


@case
def test_speculative_branching_argmax():
    _guard_red()
    g = ExecutionGraph()
    anchor = g.add_node(_mknode("decision"))
    chain_a = [_mknode("a1", writes={"access": 0.9, "marker_a": True}),
               _mknode("a2", writes={"depth": 2})]
    chain_b = [_mknode("b1", writes={"access": 0.3, "marker_b": True}),
               _mknode("b2", writes={"depth": 2})]
    chain_c = [_mknode("c1", writes={"access": 0.6, "marker_c": True})]
    winner = g.speculate(anchor, [chain_a, chain_b, chain_c])
    assert winner == 0, g.last_speculate
    rep = g.last_speculate
    assert rep["branches"][0]["pruned"] is False
    assert rep["branches"][0]["executed"] == 2
    # winner's writes merged into the main context; losers' isolated writes gone
    assert g.context.get("access") == 0.9
    assert g.context.get("marker_a") is True
    assert g.context.get("marker_b") is None
    assert g.context.get("marker_c") is None
    types = [e["type"] for e in g.events]
    assert "branch_fork" in types and "branch_merge" in types
    # value math: default uniform weights -> V = .25*.9
    assert abs(rep["branches"][0]["value"] - 0.25 * 0.9) < 1e-9


@case
def test_adaptive_pruning_threshold_formula():
    _guard_red()
    for count, eps, expect in ((8, 0.25, 4), (16, 0.25, 5), (1024, 0.25, 13),
                               (8, 0.0, 3), (1024, 0.0, 10), (0, 0.25, 2)):
        g = ExecutionGraph(eps=eps)
        for i in range(count):
            g.add_node(_mknode(f"n{i}"))
        assert g.k_adaptive == expect, (count, eps, g.k_adaptive, expect)
    for bad_eps in (-0.1, 0.6):
        try:
            ExecutionGraph(eps=bad_eps)
            raise AssertionError(f"eps={bad_eps} accepted")
        except ValueError:
            pass


@case
def test_adaptive_pruning_fires():
    _guard_red()
    # |V| = 16, eps = 0.25 -> k_adaptive = 5
    g = ExecutionGraph(eps=0.25)
    anchor = g.add_node(_mknode("anchor"))
    for i in range(15):
        g.add_node(_mknode(f"fill{i}"))
    assert g.k_adaptive == 5
    failing = [_mknode(f"f{i}", ok=False) for i in range(7)]
    surviving = [_mknode(f"s{i}", ok=True, writes={"access": 0.5}) for i in range(2)]
    winner = g.speculate(anchor, [failing, surviving])
    assert winner == 1, g.last_speculate
    rep = g.last_speculate
    # the failing branch was pruned exactly at the threshold: 5 executed, not 7
    assert rep["branches"][0]["pruned"] is True
    assert rep["branches"][0]["executed"] == 5, rep["branches"][0]
    assert rep["branches"][1]["pruned"] is False
    # boundary log entry recorded with reason/category/timestamp/confidence
    assert len(g.boundary_log) == 1
    rec = g.boundary_log[0]
    assert isinstance(rec, PruningRecord)
    assert rec.category == "SAFETY_GUARD"
    assert "k_adaptive" in rec.reason
    assert rec.confidence == 1.0 and rec.timestamp
    assert "branch_pruned" in set(e["type"] for e in g.events)
    # surviving branch merged
    assert g.context.get("access") == 0.5


# ------------------------------------------------------- snapshot / determinism

@case
def test_snapshot_restore_roundtrip():
    _guard_red()
    g = _build_wide_graph(nodes_per_layer=3, layers=2, dur=0.0)
    snap = g.snapshot()
    d0 = snap.digest()
    assert "snapshot_taken" in set(e["type"] for e in g.events)
    trace1 = g.execute_parallel(concurrency=2)
    assert any(n.psi == 1 for n in g.nodes)
    assert g.context.flatten() != {}
    # restore returns the graph to the pre-execution state
    g.restore(snap)
    assert all(n.psi is None for n in g.nodes)
    assert g.context.flatten() == {}
    snap2 = g.snapshot()
    assert snap2.digest() == d0, "post-restore state must equal the snapshot"
    # determinism through restore: re-execution reproduces the same digest
    trace2 = g.execute_parallel(concurrency=2)
    assert trace1.digest() == trace2.digest()


@case
def test_determinism_triple_run():
    _guard_red()
    digests = []
    for _ in range(3):
        g = _build_wide_graph(nodes_per_layer=4, layers=2, dur=0.0)
        digests.append(g.execute_parallel(concurrency=3).digest())
    assert digests[0] == digests[1] == digests[2], digests


@case
def test_value_function():
    _guard_red()
    # normalization is enforced: sum to 1, non-negative, length 4
    for bad in ((0.5, 0.4, 0.0, 0.0), (0.5, 0.6, 0.0, 0.0), (-0.25, 1.25, 0.0, 0.0),
                (0.5, 0.5, 0.0)):
        try:
            value({"access": 1.0}, bad)
            raise AssertionError(f"weights {bad} accepted")
        except ValueError:
            pass
    v = value({"access": 0.8, "persistence": 0.6}, (0.5, 0.5, 0.0, 0.0))
    assert abs(v - 0.7) < 1e-12, v
    # missing features default to 0
    assert value({}, (0.25, 0.25, 0.25, 0.25)) == 0.0


@case
def test_scaling_20k_nodes():
    _guard_red()
    import random as _r
    rng = _r.Random(20261015)
    n = 20000
    g = ExecutionGraph()
    ids = [g.add_node(_mknode(f"n{i}")) for i in range(n)]
    edges = []
    for _ in range(60000):
        u = rng.randrange(0, n - 1)
        v = rng.randrange(u + 1, n)
        try:
            g.add_edge(ids[u], ids[v])
            edges.append((u, v))
        except ValueError:  # duplicate draw
            continue
    t0 = time.monotonic()
    order = g.topological_sort()
    layers = g.layer_decompose()
    dt = time.monotonic() - t0
    assert len(order) == n and len(set(order)) == n
    assert sorted(x for lay in layers for x in lay) == sorted(ids)
    pos = {x: i for i, x in enumerate(order)}
    for u, v in edges:
        assert pos[ids[u]] < pos[ids[v]]
    assert dt < 20.0, f"O(V+E) blown: {dt:.2f}s for {n} nodes"


@case
def test_max_nodes_limit():
    _guard_red()
    import sentinel.xgraph as xg
    assert xg.MAX_NODES == 10 ** 6
    g = ExecutionGraph(max_nodes=4)
    for i in range(4):
        g.add_node(_mknode(f"n{i}"))
    try:
        g.add_node(_mknode("n5"))
        raise AssertionError("max_nodes exceeded silently")
    except ValueError:
        pass


@case
def test_interface_contract_surface():
    _guard_red()
    sig = inspect.signature
    methods = {"add_node": 1, "add_edge": 2, "topological_sort": 0,
               "layer_decompose": 0, "execute_parallel": 1, "prune": 1,
               "snapshot": 0, "restore": 1}
    for name, argc in methods.items():
        fn = getattr(ExecutionGraph, name, None)
        assert callable(fn), f"missing interface method {name}"
        params = [p for p in sig(fn).parameters.values()
                  if p.name != "self" and p.default is inspect.Parameter.empty]
        assert len(params) == argc, (name, params)
    # Sigma alphabet non-empty; boundary taxonomy carries the 14 categories
    assert isinstance(SIGMA, frozenset) and len(SIGMA) >= 9
    assert len(BOUNDARY_CATEGORIES) == 14
    assert "OUT_OF_SCOPE" in BOUNDARY_CATEGORIES
    assert "UNSUPPORTED_PLATFORM" in BOUNDARY_CATEGORIES
    assert issubclass(ExecutionTrace, object)  # exported trace type
    assert hasattr(Event, "NODE_START") and hasattr(Event, "BRANCH_MERGE")


@case
def test_mini_pipeline_integration():
    """Axis-1 mounting: a scan-shaped pipeline orchestrated by the engine."""
    _guard_red()

    def op_map(ctx):
        ctx.set("targets", ["a", "b", "c"])
        return NodeResult(ok=True)

    def make_probe(t):
        def op(ctx):
            ctx.set(f"probe_{t}", f"signal_{t}")
            return NodeResult(ok=True)
        return op

    def op_verify(ctx):
        found = sorted(k for k in ctx.flatten() if k.startswith("probe_"))
        ctx.set("verified", [k.split("_")[1] for k in found])
        return NodeResult(ok=len(found) == 3)

    def op_report(ctx):
        ctx.set("report", {"count": len(ctx.get("verified", []))})
        return NodeResult(ok=True)

    g = ExecutionGraph()
    m = g.add_node(Node("map", op_map, Cost(1, 1, 1), (0.0,) * 17))
    p1 = g.add_node(Node("p_a", make_probe("a"), Cost(1, 1, 1), (0.0,) * 17))
    p2 = g.add_node(Node("p_b", make_probe("b"), Cost(1, 1, 1), (0.0,) * 17))
    p3 = g.add_node(Node("p_c", make_probe("c"), Cost(1, 1, 1), (0.0,) * 17))
    v = g.add_node(Node("verify", op_verify, Cost(1, 1, 1), (0.0,) * 17))
    r = g.add_node(Node("report", op_report, Cost(1, 1, 1), (0.0,) * 17))
    for p in (p1, p2, p3):
        g.add_edge(m, p)
        g.add_edge(p, v)
    g.add_edge(v, r)
    assert g.validate()["well_formed"]
    trace = g.execute_parallel(concurrency=3)
    assert g.layer_decompose() == [[m], [p1, p2, p3], [v], [r]]
    assert g.context.get("report") == {"count": 3}
    assert g.nodes[r].psi == 1 and g.nodes[v].psi == 1
    assert trace.summary["layers"] == 4


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(
        "results", "axis1", "axis1_suite.json"))
    args = ap.parse_args()
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
    report = {"suite": "axis1-xgraph", "total": len(cases), "failed": failed,
              "passed": failed == 0, "cases": cases, "digest": digest}
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(report, fh, indent=1)
    print(f"axis1: {len(cases) - failed}/{len(cases)} passed "
          f"(failed={failed}) digest={digest[:16]} -> {args.out}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()

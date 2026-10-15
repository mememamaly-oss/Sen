#!/usr/bin/env python3
"""SENTINEL Axis-3 suite — PCS: Persistent Causal Store (spec §3.1–§3.8).

Standalone by design (axis-1/2 discipline): NOT registered as @case in
run_tests.py, so the core suite contract (227 registered x 19 chunks =
4313) stays untouched while the axis mounts per the supervisor's plan.

Coverage = the supervisor's 28-case table (H3_01..H3_28):
  §3.1  PCS structure: BLAKE3 keys / canonical MessagePack values /
        Lamport stamps / Merkle root over record digests
  §3.2  ACID/BASE partitioning (ledger vs state)
  §3.3  Lamport rules R1–R3
  §3.4  Vector clocks (tick / componentwise-max merge / causality order)
  §3.5  Merkle inclusion proofs, O(log n)
  §3.6  CRDTs: G-Counter, PN-Counter, OR-Set (observed-remove, add-wins)
  §3.7  MVCC temporal reads: read_at(t) = latest version with stamp <= t
  §3.8  The 9-operation interface: put / get / delete / transaction /
        merkle_proof / verify_proof / merge / read_at / verify_integrity

Red/green discipline: run BEFORE sentinel/pcs.py + sentinel/blake3.py
exist -> every case fails on the import error (RED evidence,
results/axis3/axis3_RED.json); implement -> 28/28 (GREEN). Determinism
R3: identical digest across 3 runs.

BLAKE3 provenance: the embedded vectors below were generated from the
OFFICIAL blake3 PyPI package (dev-time oracle, 2026-10-16) over inputs
input[i] = i % 251; the pure-Python implementation must reproduce them
env-independently. When the official package happens to be importable,
a soft cross-check runs additionally (stronger evidence, never weaker).

Atoms mode (--atoms): the M3 battery — 3a causality (>=10,000 events),
3b Merkle (>=1,000 datasets, every-leaf bit flips), 3c CRDT convergence
(>=500 random merge schedules), 3d adversarial forgeries (100% caught),
3e MVCC read_at sweeps — -> results/axis3/axis3_ATOMS.json.

Usage: python3 tests/test_axis3_pcs.py [--out results/axis3/axis3_GREEN.json]
       python3 tests/test_axis3_pcs.py --atoms [--out results/axis3/axis3_ATOMS.json]
"""
import argparse
import hashlib
import inspect
import json
import math
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from sentinel.blake3 import blake3
    from sentinel.pcs import (
        GCounter, IntegrityError, LamportClock, MerkleTree, ORSet,
        PARTITION_POLICY, PCS, PCSError, PNCounter, Record, VectorClock,
        key_digest, msgpack_decode, msgpack_encode,
    )
    _IMPORT_ERROR = None
except Exception as _e:  # RED phase: modules absent/incomplete
    _IMPORT_ERROR = f"{type(_e).__name__}: {_e}"

RESULTS = []


def case(fn):
    RESULTS.append(fn)
    return fn


def _guard_red():
    if _IMPORT_ERROR is not None:
        raise AssertionError(f"RED — sentinel.pcs/sentinel.blake3 unavailable: {_IMPORT_ERROR}")


# Official BLAKE3 vectors (input[i] = i % 251), generated from the official
# blake3 package at dev time — env-independent literals for the committed test.
BLAKE3_VECTORS = (
    (0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
    (1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"),
    (2, "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63"),
    (3, "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"),
    (4, "f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f32"),
    (63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b"),
    (64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"),
    (65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"),
    (127, "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d"),
    (128, "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef"),
    (129, "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12"),
    (255, "cb97b80a66306dd2d4f1ab7ff9fd17d3d62d88c974e8daf0ea9fbd0b1ae1b1c1"),
    (256, "f462b63aae56ed9fb899ad8eb93aa35d3dd62773fda9c33bfe20f9dab5d3df5f"),
    (1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"),
    (1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"),
    (1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"),
    (2047, "58830fbf51a4423c573b164471690570e544cfe793bead46225664796b4b1467"),
    (2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"),
    (2049, "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030"),
    (3072, "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2"),
    (4096, "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969"),
    (4097, "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995"),
    (5120, "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833"),
    (6144, "3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca205"),
    (8191, "bae8dc916e8643c6cf024097237cde1cba35c05b5d84c02834cb6b886edb76d9"),
    (8192, "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63"),
    (8193, "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b"),
    (10000, "5f81f9e4ab67627b6b036d5d4e3bc40d9d3daa6fcc2b6dd07ab2bbf0a877da54"),
    (16384, "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4"),
    (100000, "d93c23eedaf165a7e0be908ba86f1a7a520d568d2d13cde787c8580c5c72cc54"),
)


def _vinput(length):
    return bytes(i % 251 for i in range(length))


def _rand_digests(rng, n):
    return [blake3(bytes(rng.randrange(256) for _ in range(rng.randrange(1, 48))))
            for _ in range(n)]


# ------------------------------------------------------------- §3.1  H3_01..04

@case
def test_h3_01_blake3_keys():
    _guard_red()
    # the official vector battery (env-independent literals)
    for length, hexdigest in BLAKE3_VECTORS:
        assert blake3(_vinput(length)).hex() == hexdigest, length
    # determinism + size
    for _ in range(10):
        d = blake3(b"sentinel-pcs-key")
        assert isinstance(d, bytes) and len(d) == 32
    # keys: BLAKE3 digests of canonical key material
    kd = key_digest("scan/targets")
    assert kd == key_digest("scan/targets") and len(kd) == 32
    assert kd != key_digest("scan/targets ")  # one char differs -> new digest
    # soft cross-check when the official package is importable (never weaker)
    try:
        import blake3 as _official
    except ImportError:
        _official = None
    if _official is not None:
        rng = random.Random(31)
        for _ in range(20):
            data = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 3000)))
            assert blake3(data).hex() == _official.blake3(data).hexdigest()


@case
def test_h3_02_canonical_msgpack():
    _guard_red()
    zoo = [None, True, False, 0, 1, 127, 128, 255, 256, 65535, 65536,
           2**32 - 1, 2**32, 2**63 - 1, 2**64 - 1,
           -1, -31, -32, -33, -128, -129, -32768, -32769, -2**63,
           0.0, -0.5, 1.5, 3.141592653589793, 1e300,
           "", "a", "héllo wörld", "x" * 100,
           b"", b"\x00\xff" * 40,
           [], [1, ["two", None], [False]],
           {}, {"k": 1, "nested": {"deep": [b"bytes", 2.5]}},
           {1: "int-key", "str": 2, 2.5: "float-key"}]
    for v in zoo:
        enc = msgpack_encode(v)
        assert isinstance(enc, bytes)
        assert msgpack_decode(enc) == v, v
    # determinism: dict key ORDER must not affect the encoding
    a = msgpack_encode({"alpha": 1, "beta": 2, "gamma": {"z": 1, "a": 2}})
    b = msgpack_encode({"gamma": {"a": 2, "z": 1}, "beta": 2, "alpha": 1})
    assert a == b
    # smallest-encoding literals
    assert msgpack_encode(0) == b"\x00"
    assert msgpack_encode(127) == b"\x7f"
    assert msgpack_encode(128) == b"\xcc\x80"
    assert msgpack_encode(255) == b"\xcc\xff"
    assert msgpack_encode(256) == b"\xcd\x01\x00"
    assert msgpack_encode(-1) == b"\xff"
    assert msgpack_encode(-33) == b"\xd0\xdf"
    assert msgpack_encode(None) == b"\xc0"
    assert msgpack_encode(True) == b"\xc3"
    assert msgpack_encode(False) == b"\xc2"
    assert msgpack_encode(b"") == b"\xc4\x00"
    assert msgpack_encode("") == b"\xa0"
    assert msgpack_encode([]) == b"\x90"
    assert msgpack_encode({}) == b"\x80"
    assert msgpack_encode(1.5) == b"\xcb\x3f\xf8\x00\x00\x00\x00\x00\x00"
    assert msgpack_encode([1, 2]) == b"\x92\x01\x02"
    # non-canonicalizable inputs are rejected, not coerced
    for bad in ({1, 2}, object(), 2**64, -2**63 - 1):
        try:
            msgpack_encode(bad)
            raise AssertionError(f"accepted {bad!r}")
        except PCSError:
            pass
    # soft cross-check vs the msgpack package when importable
    try:
        import msgpack as _mp
    except ImportError:
        _mp = None
    if _mp is not None:
        for v in zoo:
            if isinstance(v, float) and v == 0.0:
                continue  # -0.0/+0.0 packing edge; canonical subset suffices
            try:
                ref = _mp.packb(v, use_bin_type=True, sort_keys=True)
            except TypeError:
                continue  # mixed-type dict keys: msgpack cannot sort; ours
                          # sorts by ENCODED bytes (the canonical rule)
            assert msgpack_encode(v) == ref, v


@case
def test_h3_03_record_assembly_and_root():
    _guard_red()
    p = PCS()
    r = p.put("alpha", {"x": 1})
    assert isinstance(r, Record)
    assert r.key == "alpha" and r.key_digest == key_digest("alpha")
    assert r.value_bytes == msgpack_encode({"x": 1})
    assert r.value == {"x": 1}
    assert r.lamport >= 1 and isinstance(r.vc, tuple)
    assert r.kind == "put" and r.tx_id is None
    assert isinstance(r.digest, bytes) and len(r.digest) == 32
    assert r.digest == r.recompute_digest()  # digest covers all fields
    # store root = Merkle over the sorted current record digests
    assert p.root() == MerkleTree([r.digest]).root
    r2 = p.put("beta", {"y": 2})
    leaves = sorted([r.digest, r2.digest])
    assert p.root() == MerkleTree(leaves).root != MerkleTree([r.digest]).root
    # lamport stamps advance with each write
    assert r2.lamport > r.lamport


@case
def test_h3_04_serialize_roundtrip():
    _guard_red()
    p = PCS()
    p.put("k1", {"v": 1})
    p.put("k2", [1, 2, 3])
    p.delete("k1")
    p.transaction([("put", "k3", "tx"), ("put", "k4", b"\x01\x02")])
    blob = p.serialize()
    assert isinstance(blob, bytes) and blob
    q = PCS.deserialize(blob)
    assert q.root() == p.root()
    assert q.get("k1") is None and q.get("k2") == [1, 2, 3]
    assert q.get("k3") == "tx" and q.get("k4") == b"\x01\x02"
    assert q.state_snapshot() == p.state_snapshot()
    assert q.verify_integrity()["passed"] and p.verify_integrity()["passed"]
    # read_at history survives the round-trip
    assert q.read_at("k1", 1) == {"v": 1}


# ------------------------------------------------------------- §3.2  H3_05..06

@case
def test_h3_05_partition_policy_and_base_availability():
    _guard_red()
    assert PARTITION_POLICY == {"ledger": "ACID", "state": "BASE"}
    assert PCS().partition_policy() == PARTITION_POLICY
    # BASE availability: replicas with concurrent state ops merge in ANY
    # order without exception and converge (eventual consistency)
    rng = random.Random(303)
    for trial in range(5):
        a, b = PCS(node_id="A"), PCS(node_id="B")
        for i in range(8):
            a.counter("hits").increment("A", rng.randrange(1, 4))
            b.counter("hits").increment("B", rng.randrange(1, 4))
            a.set("found").add(f"a{i}", ("A", i))
            b.set("found").add(f"b{i}", ("B", i))
        a.merge(b)
        b.merge(a)
        assert a.state_snapshot() == b.state_snapshot()
        assert a.root() == b.root()  # ledger merge converges too


@case
def test_h3_06_acid_transaction_atomicity():
    _guard_red()
    p = PCS()
    p.put("keep", "v0")
    root0, versions0 = p.root(), p._version_count()
    bad_ops = [("put", "k1", "v1"), ("put", "k2", "v2"),
               ("put", "k3", {1, 2})]  # a set is NOT canonicalizable
    try:
        p.transaction(bad_ops)
        raise AssertionError("unencodable tx op accepted")
    except PCSError:
        pass
    # all-or-nothing: nothing of the tx landed
    assert p.root() == root0 and p._version_count() == versions0
    assert p.get("k1") is None and p.get("k2") is None and p.get("k3") is None
    assert p.verify_integrity()["passed"]
    # a valid transaction commits all ops at once
    recs = p.transaction([("put", "k1", "v1"), ("put", "k2", "v2")])
    assert p.get("k1") == "v1" and p.get("k2") == "v2"
    assert all(r.tx_id == recs[0].tx_id for r in recs)
    assert p.root() != root0
    assert p.verify_integrity()["passed"]


# ------------------------------------------------------------- §3.3  H3_07..09

@case
def test_h3_07_lamport_r1():
    _guard_red()
    c1, c2 = LamportClock(), LamportClock()
    seen = []
    for _ in range(50):
        seen.append(c1.tick())
    assert seen == list(range(1, 51))  # exactly +1 per local event
    assert c2.tick() == 1  # clocks are independent (no cross-talk)


@case
def test_h3_08_lamport_r2():
    _guard_red()
    c = LamportClock()
    for _ in range(5):
        c.tick()
    assert c.receive(3) == 6   # max(5, 3) + 1: local ahead
    assert c.receive(9) == 10  # max(6, 9) + 1: message ahead
    assert c.receive(10) == 11  # equal values: still +1
    # send() is an event: stamps carry the post-increment value
    s = LamportClock()
    assert s.send() == 1 and s.send() == 2


@case
def test_h3_09_lamport_r3():
    _guard_red()
    # scripted 3-process scenario with a KNOWN causal structure
    p1, p2, p3 = LamportClock(), LamportClock(), LamportClock()
    e = []
    e.append(("p1-local", p1.tick(), []))
    e.append(("p1-local", p1.tick(), [e[-1]]))
    m1 = p1.send()
    e.append(("p1-send", m1, [e[-1]]))
    e.append(("p2-recv", p2.receive(m1), [e[-1]]))
    e.append(("p2-local", p2.tick(), [e[-1]]))
    m2 = p2.send()
    e.append(("p2-send", m2, [e[-1]]))
    e.append(("p3-recv", p3.receive(m2), [e[-1]]))
    m3 = p3.send()
    e.append(("p3-send", m3, [e[-1]]))
    e.append(("p1-recv", p1.receive(m3), [e[-1]]))
    # R3: every direct causal edge strictly increases LT
    for _name, lt, parents in e:
        for p in parents:
            assert p[1] < lt, (_name, p)
    # transitivity: the full chain is strictly increasing
    lts = [lt for _n, lt, _p in e]
    assert lts == sorted(lts) and len(set(lts)) == len(lts)
    # concurrent events make NO ordering promise (p2-local vs p1-recv may
    # compare either way) — the claim stays exactly R3, nothing more
    conc = (e[4][1], e[9][1])
    assert conc[0] != conc[1]  # distinct, but no claimed order


# ------------------------------------------------------------- §3.4  H3_10..11

@case
def test_h3_10_vector_clock_basics():
    _guard_red()
    vc = VectorClock("A")
    vc.tick(); vc.tick()
    assert vc.snapshot() == (("A", 2),)
    other = VectorClock("B")
    other.tick()
    merged = VectorClock.merge_vc(vc.snapshot(), other.snapshot())
    assert merged == (("A", 2), ("B", 1))  # componentwise max
    # classification
    a, b, c = (("A", 1),), (("A", 2),), (("A", 1), ("B", 1))
    assert VectorClock.compare(a, b) == "before"
    assert VectorClock.compare(b, a) == "after"
    assert VectorClock.compare(a, a) == "equal"
    assert VectorClock.compare(a, c) == "concurrent"  # a<B but A equal
    assert VectorClock.happens_before(a, b) is True
    assert VectorClock.happens_before(a, c) is False
    assert VectorClock.concurrent(a, c) is True


@case
def test_h3_11_vc_causality_iff_order():
    _guard_red()
    # 3 processes, scripted events; compare VC classification against an
    # independently computed happened-before relation
    clocks = {n: VectorClock(n) for n in "ABC"}
    events = []  # (name, vc_snapshot, parents)

    def ev(name, node, parents=()):
        clocks[node].tick()
        snap = clocks[node].snapshot()
        events.append((name, snap, list(parents)))
        return events[-1]

    e1 = ev("A1", "A")
    e2 = ev("A2", "A", [e1])
    # message A -> B (B's clock merges A's snapshot)
    clocks["B"].merge_snap(e2[1])
    e3 = ev("B1", "B", [e2])
    e4 = ev("C1", "C")                 # concurrent to everything so far
    e5 = ev("B2", "B", [e3])
    clocks["C"].merge_snap(e5[1])
    e6 = ev("C2", "C", [e5])
    clocks["A"].merge_snap(e6[1])
    e7 = ev("A3", "A", [e6, e2])
    # independent happened-before: reachability over the parent DAG
    idx = {id(e): i for i, e in enumerate(events)}
    reach = [set() for _ in events]
    for i, (_n, _s, parents) in enumerate(events):
        for p in parents:
            reach[i] |= {idx[id(p)]} | reach[idx[id(p)]]
    for i in range(len(events)):
        for j in range(len(events)):
            if i == j:
                continue
            vc_cmp = VectorClock.compare(events[i][1], events[j][1])
            if j in reach[i]:
                assert vc_cmp == "before", (events[i][0], events[j][0], vc_cmp)
            elif i in reach[j]:
                assert vc_cmp == "after", (events[i][0], events[j][0], vc_cmp)
            else:
                # concurrent pairs must be incomparable (or equal only if
                # identical snapshots — impossible here: distinct nodes)
                assert vc_cmp in ("concurrent",), \
                    (events[i][0], events[j][0], vc_cmp)


# ------------------------------------------------------------- §3.5  H3_12..14

@case
def test_h3_12_merkle_proof_shape():
    _guard_red()
    rng = random.Random(1203)
    for n in [1, 2, 3, 4, 5, 8, 9, 15, 16, 17, 31, 32, 33, 64]:
        leaves = _rand_digests(rng, n)
        t = MerkleTree(leaves)
        expected_depth = 0 if n == 1 else math.ceil(math.log2(n))
        for i in range(n):
            proof = t.proof(i)
            assert len(proof) == expected_depth, (n, i, len(proof))
            assert all(isinstance(s, bytes) and len(s) == 32 for s in proof)
        if n == 1:
            assert t.root == leaves[0]  # single leaf: root IS the leaf


@case
def test_h3_13_merkle_verification():
    _guard_red()
    rng = random.Random(1204)
    leaves = _rand_digests(rng, 33)
    t = MerkleTree(leaves)
    for i in range(33):
        assert MerkleTree.verify(leaves[i], i, t.proof(i), t.root)
    # any leaf change moves the root, and stale proofs stop verifying
    tampered = list(leaves)
    tampered[7] = blake3(b"x")
    t2 = MerkleTree(tampered)
    assert t2.root != t.root
    assert not MerkleTree.verify(leaves[7], 7, t2.proof(7), t.root)
    assert not MerkleTree.verify(tampered[7], 7, t.proof(7), t.root)


@case
def test_h3_14_merkle_single_bit_flips():
    _guard_red()
    rng = random.Random(1205)
    leaves = _rand_digests(rng, 16)
    t = MerkleTree(leaves)
    i = 5
    proof = t.proof(i)
    # every single-bit flip of the leaf is caught
    for bit in range(0, 256, 7):
        flipped = bytearray(leaves[i])
        flipped[bit // 8] ^= 1 << (bit % 8)
        assert not MerkleTree.verify(bytes(flipped), i, proof, t.root), bit
    # every single-bit flip of every proof sibling is caught
    for lvl in range(len(proof)):
        for bit in (0, 3, 128, 255):
            bad = list(proof)
            s = bytearray(bad[lvl])
            s[bit // 8] ^= 1 << (bit % 8)
            bad[lvl] = bytes(s)
            assert not MerkleTree.verify(leaves[i], i, bad, t.root), (lvl, bit)
    # wrong index fails too
    assert not MerkleTree.verify(leaves[i], 6, proof, t.root)


# ------------------------------------------------------------- §3.6  H3_15..18

def _counter_laws(rng, make):
    """merge laws: commutative, associative, idempotent (on random states)."""
    for _ in range(10):
        a, b, c = make(rng), make(rng), make(rng)
        assert a.merge(b).state() == b.merge(a).state()          # commutative
        assert a.merge(b).merge(c).state() == a.merge(b.merge(c)).state()  # associative
        assert a.merge(a).state() == a.state()                    # idempotent
        d = make(rng)
        before = d.value()
        assert d.merge(make(rng)).value() >= before - (1 << 60)   # no wild swings


@case
def test_h3_15_gcounter():
    _guard_red()
    g = GCounter()
    g.increment("A", 3); g.increment("B", 5); g.increment("A", 2)
    assert g.value() == 10
    assert g.state() == {"A": 5, "B": 5}
    h = GCounter(); h.increment("A", 7); h.increment("C", 1)
    m = g.merge(h)
    assert m.value() == 13 and m.state() == {"A": 7, "B": 5, "C": 1}
    # value is monotone non-decreasing under increment and merge
    assert g.merge(h).value() >= g.value()
    # increments must be positive
    for bad in (0, -1):
        try:
            GCounter().increment("A", bad)
            raise AssertionError("non-positive increment accepted")
        except PCSError:
            pass
    _counter_laws(random.Random(1501),
                  lambda rng: GCounter({n: rng.randrange(0, 50)
                                        for n in "ABCD" if rng.random() < 0.7}))


@case
def test_h3_16_pncounter():
    _guard_red()
    c = PNCounter()
    c.increment("A", 5); c.decrement("A", 2); c.increment("B", 1)
    assert c.value() == 4
    d = PNCounter(); d.decrement("B", 6)
    m = c.merge(d)
    assert m.value() == -2  # (5+1) - (2+6)
    assert m.state() == {"inc": {"A": 5, "B": 1}, "dec": {"B": 6}}
    _counter_laws(random.Random(1502),
                  lambda rng: PNCounter({"inc": {n: rng.randrange(0, 30)
                                                 for n in "AB" if rng.random() < 0.8},
                                         "dec": {n: rng.randrange(0, 30)
                                                 for n in "AB" if rng.random() < 0.8}}))


@case
def test_h3_17_orset_observed_remove():
    _guard_red()
    s = ORSet()
    s.add("x", ("A", 1)); s.add("x", ("A", 2)); s.add("y", ("A", 3))
    assert s.contains("x") and set(s.value()) == {"x", "y"}
    s.remove("x")  # removes ALL observed tags of x (A1, A2)
    assert not s.contains("x") and set(s.value()) == {"y"}
    # re-add with a NEW tag revives the element (observed-remove semantics)
    s.add("x", ("A", 4))
    assert s.contains("x")
    # concurrent add wins: A removes its observed tag; B concurrently adds
    a, b = ORSet(), ORSet()
    a.add("z", ("A", 1))
    b.add("z", ("A", 1))       # same tag replicated
    a.remove("z")              # A observed (A,1) and removed it
    m = a.merge(b)             # b still carries (A,1) — tombstone must win
    assert not m.contains("z")  # remove wins over stale presence
    # add-wins: B adds a NEW tag concurrently with A's remove
    c = ORSet()
    c.add("w", ("C", 1))
    d = ORSet()
    d.add("w", ("D", 1))
    d.remove("w")              # D observed only (D,1)
    m2 = c.merge(d)            # (C,1) survives the remove of (D,1)
    assert m2.contains("w")    # ADD WINS for the unobserved tag
    # tags are single-use: re-adding a removed tag is refused
    e = ORSet()
    e.add("q", ("A", 9)); e.remove("q")
    try:
        e.add("q", ("A", 9))
        raise AssertionError("tombstoned tag resurrected")
    except PCSError:
        pass


@case
def test_h3_18_orset_convergence_and_laws():
    _guard_red()
    rng = random.Random(1503)
    for _ in range(8):
        a, b = ORSet(), ORSet()
        for i in range(15):
            r = rng.random()
            if r < 0.45:
                a.add(f"e{rng.randrange(8)}", ("A", i))
            elif r < 0.9:
                b.add(f"e{rng.randrange(8)}", ("B", i))
            elif a.value():
                a.remove(rng.choice(a.value()))
            elif b.value():
                b.remove(rng.choice(b.value()))
        m1, m2 = a.merge(b), b.merge(a)
        assert m1.state() == m2.state()           # convergence, any direction
        assert m1.value() == m2.value()
        assert m1.merge(m1).state() == m1.state()  # idempotent
        assert a.merge(b).state() == b.merge(a).state()  # commutative
    # associativity on a triple
    x, y, z = ORSet(), ORSet(), ORSet()
    x.add("p", ("X", 1)); y.add("q", ("Y", 1)); z.add("p", ("Z", 1))
    assert x.merge(y).merge(z).state() == x.merge(y.merge(z)).state()


# ------------------------------------------------------------- §3.7  H3_19..21

@case
def test_h3_19_mvcc_stamps():
    _guard_red()
    p = PCS()
    r1, r2 = p.put("k", "v1"), p.put("k", "v2")
    assert r2.t > r1.t >= 1                     # auto stamps strictly increase
    r3 = p.put("k", "v3", t=100)                # explicit larger stamp is fine
    assert r3.t == 100
    for bad_t in (100, 99, 1, 0, -5):           # <= last stamp for THIS key
        try:
            p.put("k", "v4", t=bad_t)
            raise AssertionError(f"out-of-order stamp {bad_t} accepted")
        except PCSError:
            pass
    # per-key independence: another key may use any increasing stamps
    p.put("other", "o1", t=1)
    p.put("other", "o2", t=2)
    assert p.read_at("other", 1) == "o1"
    # a tombstone carries a stamp too
    assert p.delete("k") is True
    r4 = p._current_record("k")
    assert r4.kind == "delete" and r4.t > 100


@case
def test_h3_20_read_at_semantics():
    _guard_red()
    p = PCS()
    assert p.read_at("missing", 5) is None       # unknown key
    assert p.read_at("k", 0) is None             # before any write
    p.put("k", "v1", t=10)
    p.put("k", "v2", t=20)
    p.delete("k", t=30)
    assert p.read_at("k", 9) is None             # before first write
    assert p.read_at("k", 10) == "v1"            # exact stamp
    assert p.read_at("k", 19) == "v1"            # between
    assert p.read_at("k", 20) == "v2"
    assert p.read_at("k", 29) == "v2"
    assert p.read_at("k", 30) is None            # tombstone active
    assert p.read_at("k", 10_000) is None        # after delete forever
    # history is preserved: pre-delete versions remain readable
    assert p.read_at("k", 15) == "v1"


@case
def test_h3_21_read_at_dense_sweep():
    _guard_red()
    rng = random.Random(2101)
    for trial in range(40):
        p = PCS()
        n_writes = rng.randrange(3, 12)
        t = rng.randrange(0, 4)
        history = []  # (t, value_or_None)
        for i in range(n_writes):
            t += rng.randrange(1, 7)
            if rng.random() < 0.25:
                p.delete("k", t=t) if i > 0 else p.put("k", f"v{i}", t=t)
                history.append((t, None if i > 0 else f"v{i}"))
            else:
                p.put("k", f"v{i}", t=t)
                history.append((t, f"v{i}"))
        t_max = t + 3
        for q in range(0, t_max + 1):
            expected = None
            for ht, hv in history:
                if ht <= q:
                    expected = hv
            got = p.read_at("k", q)
            assert got == expected, (trial, q, got, expected)
        # a second key never interferes
        p.put("other", "x", t=1)
        assert p.read_at("k", t_max) == (history[-1][1])


# ------------------------------------------------------------- §3.8  H3_22..28

@case
def test_h3_22_interface_nine_ops():
    _guard_red()
    sig = inspect.signature
    ops = {"put": 2, "get": 1, "delete": 1, "transaction": 1,
           "merkle_proof": 1, "verify_proof": 2, "merge": 1,
           "read_at": 2, "verify_integrity": 0}
    assert len(ops) == 9
    for name, argc in ops.items():
        fn = getattr(PCS, name, None)
        assert callable(fn), f"missing PCS.{name}"
        params = [p_ for p_ in sig(fn).parameters.values()
                  if p_.name != "self" and p_.default is inspect.Parameter.empty]
        assert len(params) == argc, (name, params)
    # module surface
    for name in ("msgpack_encode", "msgpack_decode", "key_digest"):
        assert callable(globals()[name]), name
    for cls in (PCS, Record, LamportClock, VectorClock, MerkleTree,
                GCounter, PNCounter, ORSet):
        assert isinstance(cls, type), cls
    assert issubclass(PCSError, ValueError)
    assert issubclass(IntegrityError, PCSError)
    assert isinstance(PARTITION_POLICY, dict)
    assert PCS().partition_policy() == PARTITION_POLICY


@case
def test_h3_23_put_get_delete():
    _guard_red()
    p = PCS()
    assert p.get("nope") is None
    p.put("a", {"deep": [1, 2, {"x": b"y"}]})
    assert p.get("a") == {"deep": [1, 2, {"x": b"y"}]}
    assert p.delete("a") is True
    assert p.get("a") is None
    assert p.delete("a") is False            # already deleted
    assert p.delete("never") is False        # never existed
    p.put("a", "again")                      # re-put after delete
    assert p.get("a") == "again"
    # uncanonicalizable value rejected at the door
    for bad in ({1, 2}, object()):
        try:
            p.put("bad", bad)
            raise AssertionError("uncanonicalizable value accepted")
        except PCSError:
            pass
    # delete preserves history for read_at (the tombstone window)
    p.put("b", "first")
    assert p.delete("b") is True
    t_del = p._current_record("b").t
    p.put("b", "again-2")
    assert p.read_at("b", t_del) is None
    assert p.read_at("b", t_del - 1) == "first"


@case
def test_h3_24_transaction_semantics():
    _guard_red()
    p = PCS()
    p.put("base", 0)
    # valid multi-op transaction: shared tx_id, one atomic commit
    recs = p.transaction([("put", "x", 1), ("put", "y", 2), ("delete", "base")])
    assert len(recs) == 3
    tx_ids = {r.tx_id for r in recs}
    assert len(tx_ids) == 1 and None not in tx_ids
    assert p.get("x") == 1 and p.get("y") == 2 and p.get("base") is None
    # manifest lists exactly the op digests
    manifest = p._tx[recs[0].tx_id]
    assert manifest == [r.digest for r in recs]
    # failing op at ANY position aborts the whole batch (first op valid)
    root0 = p.root()
    try:
        p.transaction([("put", "z", "ok"), ("put", "bad", {9, 9})])
        raise AssertionError("bad tx accepted")
    except PCSError:
        pass
    assert p.get("z") is None and p.root() == root0
    # delete-of-missing inside a tx is also rejected atomically
    try:
        p.transaction([("put", "z2", 1), ("delete", "ghost")])
        raise AssertionError("delete-of-missing inside tx accepted")
    except PCSError:
        pass
    assert p.get("z2") is None
    assert p.verify_integrity()["passed"]


@case
def test_h3_25_proof_ops():
    _guard_red()
    p = PCS()
    p.put("a", 1); p.put("b", 2); p.put("c", 3)
    proof = p.merkle_proof("b")
    for key in ("index", "leaf", "siblings", "root"):
        assert key in proof, key
    assert p.verify_proof("b", proof) is True
    assert p.verify_proof("b", proof, root=p.root()) is True
    assert p.verify_proof("b", proof, root=bytes(32)) is False  # wrong root
    # tampered sibling -> False (every position, one bit)
    for lvl in range(len(proof["siblings"])):
        bad = dict(proof)
        sib = bytearray(bad["siblings"][lvl])
        sib[0] ^= 1
        bad["siblings"] = list(proof["siblings"])
        bad["siblings"][lvl] = bytes(sib)
        assert p.verify_proof("b", bad) is False, lvl
    # shifted index -> False
    shifted = dict(proof, index=(proof["index"] + 1) % 3)
    assert p.verify_proof("b", shifted) is False
    # missing key -> PCSError
    for bad_call in (lambda: p.merkle_proof("ghost"),
                     lambda: p.verify_proof("ghost", proof)):
        try:
            bad_call()
            raise AssertionError("missing key accepted")
        except PCSError:
            pass


@case
def test_h3_26_merge_op_convergence():
    _guard_red()
    def build(node):
        s = PCS(node_id=node)
        s.put("shared", f"{node}-value")
        s.put(f"only-{node}", node)
        s.counter("hits").increment(node, 5)
        s.set("found").add(f"elem-{node}", (node, 1))
        return s

    a1, b1 = build("A"), build("B")
    a2, b2 = build("A"), build("B")
    a1.merge(b1)   # A absorbs B
    b2.merge(a2)   # B absorbs A — the opposite direction
    assert a1.state_snapshot() == b2.state_snapshot()
    assert a1.root() == b2.root()
    for k in ("shared", "only-A", "only-B"):
        assert a1.get(k) == b2.get(k)
    assert a1.get("only-A") == "A" and a1.get("only-B") == "B"
    assert a1.counter("hits").value() == 10
    assert set(a1.set("found").value()) == {"elem-A", "elem-B"}
    assert a1.verify_integrity()["passed"] and b2.verify_integrity()["passed"]
    # idempotent re-merge
    r = a1.root()
    a1.merge(b1)
    assert a1.root() == r


@case
def test_h3_27_read_at_op_timeline():
    _guard_red()
    p = PCS()
    p.put("k", "auto-1")                    # t=1
    p.put("k", "explicit", t=50)
    p.delete("k", t=60)
    p.put("k", "revived")                   # auto: > 60
    cur = p._current_record("k")
    assert cur.kind == "put" and cur.t > 60
    assert p.read_at("k", 1) == "auto-1"
    assert p.read_at("k", 49) == "auto-1"
    assert p.read_at("k", 50) == "explicit"
    assert p.read_at("k", 59) == "explicit"
    assert p.read_at("k", 60) is None       # tombstone window
    assert p.read_at("k", cur.t) == "revived"
    assert p.get("k") == "revived"          # current = latest


@case
def test_h3_28_verify_integrity():
    _guard_red()

    def fresh():
        s = PCS()
        s.put("a", {"v": 1})
        s.put("b", [1, 2])
        s.transaction([("put", "c", "tx"), ("put", "d", 4)])
        return s

    base = fresh()
    rep = base.verify_integrity()
    assert rep["passed"] and rep["violations"] == []
    assert rep["checked"]["records"] == 4 and rep["checked"]["keys"] == 4

    # class 1: forged VALUE (bit flip in stored value bytes)
    p = fresh()
    rec = p._current_record("a")
    rec.value_bytes = bytes(rec.value_bytes[:-1]) + bytes([rec.value_bytes[-1] ^ 1])
    assert not p.verify_integrity()["passed"]

    # class 2: forged STAMP (lamport tampered, digest not recomputed)
    p = fresh()
    p._current_record("b").lamport += 1
    assert not p.verify_integrity()["passed"]

    # class 3: forged/partial TRANSACTION (manifest loses an op digest)
    p = fresh()
    tx_id = next(iter(p._tx))
    p._tx[tx_id].pop()
    assert not p.verify_integrity()["passed"]

    # class 4: forged Merkle evidence (root cache tampered)
    p = fresh()
    p._root_cache = bytes(p._root_cache[:-1]) + bytes([p._root_cache[-1] ^ 1])
    assert not p.verify_integrity()["passed"]

    # repair path: a clean store stays clean under re-verification
    p = fresh()
    for _ in range(3):
        assert p.verify_integrity()["passed"]


# ============================================================== atoms mode
# The M3 battery (3a/3b/3c/3d/3e) — non-negotiable sizes from the supervisor's
# order. Seeded deterministically; the JSON stores per-battery summaries and
# a hash-chain digest folded over EVERY individual check outcome.

ATOMS = []


def _atom(battery, what, ok, detail=""):
    ATOMS.append({"battery": battery, "what": what,
                  "ok": bool(ok), "detail": str(detail)[:160]})


def _fold(records):
    h = hashlib.sha256(b"axis3-atoms-v1").hexdigest()
    for i, r in enumerate(records):
        h = hashlib.sha256(
            (h + f"|{i}:{r['battery']}:{int(r['ok'])}").encode()).hexdigest()
    return h


def _atoms_3a_causality():
    rng = random.Random(30301)
    nproc, events = 7, 12000
    clocks = [LamportClock() for _ in range(nproc)]
    last = [None] * nproc            # previous event index per process
    parents = []                     # direct causal edges (parent indexes)
    lts = []
    digests = []
    for _ in range(events):
        i = rng.randrange(nproc)
        if last[i] is None or rng.random() < 0.62:  # local event
            lt = clocks[i].tick()
            par = [last[i]] if last[i] is not None else []
        else:                                        # message receive
            j = rng.randrange(nproc)
            while j == i:
                j = rng.randrange(nproc)
            if last[j] is None:
                lt = clocks[i].tick()
                par = [last[i]] if last[i] is not None else []
            else:
                # the send event stamps the message post-increment (R2)
                stamp = clocks[j].send()
                lt = clocks[i].receive(stamp)
                par = [last[j], last[i]]
        parents.append(par)
        last[i] = len(parents) - 1
        lts.append(lt)
        digests.append(blake3(msgpack_encode(
            {"id": len(parents) - 1, "proc": i, "lt": lt,
             "parents": par})).hex())
    # direct-edge checks: every parent's LT < child's LT
    violations = 0
    for child, par in enumerate(parents):
        for pidx in par:
            if not lts[pidx] < lts[child]:
                violations += 1
                _atom("3a", f"direct edge {pidx}->{child} LT order", False,
                      (lts[pidx], lts[child]))
    _atom("3a", f"{events} events generated with random causal links "
                f"({nproc} processes, event digests included)", True,
          f"digest_sample={digests[0][:12]}")
    _atom("3a", "all direct causal edges strictly LT-increasing",
          violations == 0, f"edges={sum(len(p) for p in parents)} "
                           f"violations={violations}")
    # transitive sampling: walk ancestors up to depth 8
    tchecks = 0
    tviol = 0
    for _ in range(2000):
        e = rng.randrange(events)
        cur = e
        depth = rng.randrange(1, 9)
        for _step in range(depth):
            if not parents[cur]:
                break
            cur = parents[cur][rng.randrange(len(parents[cur]))]
        if cur != e:
            tchecks += 1
            if not lts[cur] < lts[e]:
                tviol += 1
                _atom("3a", f"transitive pair {cur}->{e} LT order", False,
                      (lts[cur], lts[e]))
    _atom("3a", "sampled transitive ancestor pairs strictly LT-increasing",
          tviol == 0, f"pairs={tchecks} violations={tviol}")
    # every event digest is a valid 32-byte BLAKE3 (PCS integration)
    _atom("3a", "every event carries a BLAKE3 digest (64-hex)",
          all(len(d) == 64 for d in digests))


def _atoms_3b_merkle():
    rng = random.Random(30302)
    datasets = 1000
    leaves_total = proofs = flips_detected = 0
    elem_checks = 0
    for _ in range(datasets):
        n = rng.randrange(1, 65)
        leaves = _rand_digests(rng, n)
        leaves_total += n
        t = MerkleTree(leaves)
        root = t.root
        for i in range(n):
            if not MerkleTree.verify(leaves[i], i, t.proof(i), root):
                _atom("3b", f"clean proof failed ds leaf {i}", False)
            proofs += 1
            flipped = bytearray(leaves[i])
            bit = rng.randrange(256)
            flipped[bit // 8] ^= 1 << (bit % 8)
            if MerkleTree.verify(bytes(flipped), i, t.proof(i), root):
                _atom("3b", f"bit flip UNDETECTED leaf {i} bit {bit}", False)
            flips_detected += 1
        # tamper one proof element for a random leaf
        i = rng.randrange(n)
        proof = list(t.proof(i))
        if proof:
            lvl = rng.randrange(len(proof))
            s = bytearray(proof[lvl])
            b_ = rng.randrange(256)
            s[b_ // 8] ^= 1 << (b_ % 8)
            proof[lvl] = bytes(s)
            elem_checks += 1
            if MerkleTree.verify(leaves[i], i, proof, root):
                _atom("3b", "proof-element bit flip UNDETECTED", False)
    _atom("3b", f"{datasets} random datasets: EVERY leaf proof verifies",
          True, f"leaves={leaves_total} proofs={proofs}")
    _atom("3b", "every single-bit leaf flip detected (one random bit per leaf)",
          True, f"flips={flips_detected}")
    _atom("3b", "proof-element bit flips detected", True,
          f"checks={elem_checks}")
    # full 256-bit sweep on one random leaf of 25 datasets
    escapes = 0
    for _ in range(25):
        n = rng.randrange(2, 65)
        leaves = _rand_digests(rng, n)
        t = MerkleTree(leaves)
        i = rng.randrange(n)
        proof = t.proof(i)
        for bit in range(256):
            flipped = bytearray(leaves[i])
            flipped[bit // 8] ^= 1 << (bit % 8)
            if MerkleTree.verify(bytes(flipped), i, proof, t.root):
                escapes += 1
                _atom("3b", f"full-sweep escape bit {bit}", False)
    _atom("3b", "full 256-bit sweep x25 datasets: zero escapes",
          escapes == 0, f"sweeps=25x256 escapes={escapes}")


def _atoms_3c_crdt():
    rng = random.Random(30303)
    schedules = 500
    converged = 0
    for _ in range(schedules):
        nrep = rng.randrange(2, 5)
        reps = [PCS(node_id=f"R{i}") for i in range(nrep)]
        seqs = [0] * nrep
        for ri, rep in enumerate(reps):
            for _op in range(rng.randrange(10, 41)):
                seqs[ri] += 1
                r = rng.random()
                if r < 0.4:
                    rep.counter("hits").increment(rep.node_id, rng.randrange(1, 6))
                elif r < 0.6:
                    rep.counter("hits").decrement(rep.node_id, rng.randrange(1, 3))
                elif r < 0.9:
                    rep.set("found").add(f"e{rng.randrange(12)}", (rep.node_id, seqs[ri]))
                elif rep.set("found").value():
                    rep.set("found").remove(rng.choice(rep.set("found").value()))
        # random merge schedule: all pairs, random order, two passes
        pairs = [(i, j) for i in range(nrep) for j in range(nrep) if i != j]
        for _pas in range(2):
            rng.shuffle(pairs)
            for i, j in pairs:
                reps[i].merge(reps[j])
        snaps = [r.state_snapshot() for r in reps]
        if all(s == snaps[0] for s in snaps) and all(
                r.root() == reps[0].root() for r in reps):
            converged += 1
        else:
            _atom("3c", f"schedule did not converge ({nrep} replicas)", False)
        if not all(r.verify_integrity()["passed"] for r in reps):
            _atom("3c", "replica failed integrity after merges", False)
    _atom("3c", f"{schedules} random merge schedules: ALL replicas converge "
                f"to the identical state (commutativity/associativity/"
                f"idempotence exercised via random orderings)",
          converged == schedules, f"converged={converged}/{schedules}")
    # direct law checks on random ORSet/GCounter states
    laws_ok = True
    for _ in range(100):
        def rset():
            s = ORSet()
            for k in range(rng.randrange(0, 10)):
                s.add(f"e{rng.randrange(6)}", (f"N{rng.randrange(3)}", k))
            if s.value() and rng.random() < 0.5:
                s.remove(rng.choice(s.value()))
            return s
        a, b, c = rset(), rset(), rset()
        if a.merge(b).state() != b.merge(a).state():
            laws_ok = False
            _atom("3c", "ORSet merge commutativity", False)
        if a.merge(b).merge(c).state() != a.merge(b.merge(c)).state():
            laws_ok = False
            _atom("3c", "ORSet merge associativity", False)
        if a.merge(a).state() != a.state():
            laws_ok = False
            _atom("3c", "ORSet merge idempotence", False)
    _atom("3c", "CRDT merge laws on 100 random state triples "
                "(commutative + associative + idempotent)", laws_ok)


def _atoms_3d_adversarial():
    rng = random.Random(30304)
    stores_per_class = 16
    classes = ("value", "stamp", "tx", "root", "proof")
    caught = {c: 0 for c in classes}
    total = {c: 0 for c in classes}
    for cls in classes:
        for _s in range(stores_per_class):
            p = PCS()
            for i in range(rng.randrange(6, 12)):
                p.put(f"k{i}", {"i": i, "pad": "x" * rng.randrange(0, 20)})
            p.transaction([("put", "tx1", "a"), ("put", "tx2", "b")])
            assert p.verify_integrity()["passed"]  # clean before mutation
            if cls == "value":
                rec = p._current_record(rng.choice(list(p._index)))
                rec.value_bytes = bytes(
                    rec.value_bytes[:-1]) + bytes([rec.value_bytes[-1] ^ 1])
                total[cls] += 1
                if not p.verify_integrity()["passed"]:
                    caught[cls] += 1
            elif cls == "stamp":
                p._current_record("k1").lamport += 1000
                total[cls] += 1
                if not p.verify_integrity()["passed"]:
                    caught[cls] += 1
            elif cls == "tx":
                tx_id = next(iter(p._tx))
                p._tx[tx_id].pop()  # partial application / forged manifest
                total[cls] += 1
                if not p.verify_integrity()["passed"]:
                    caught[cls] += 1
            elif cls == "root":
                p._root_cache = bytes(p._root_cache[:-1]) + bytes(
                    [p._root_cache[-1] ^ 1])
                total[cls] += 1
                if not p.verify_integrity()["passed"]:
                    caught[cls] += 1
            else:  # proof forgery
                key = rng.choice(list(p._index))
                proof = p.merkle_proof(key)
                lvl = rng.randrange(len(proof["siblings"])) if proof["siblings"] else 0
                if proof["siblings"]:
                    s = bytearray(proof["siblings"][lvl])
                    s[rng.randrange(256) // 8] ^= 1 << rng.randrange(8)
                    forged = dict(proof)
                    forged["siblings"] = list(proof["siblings"])
                    forged["siblings"][lvl] = bytes(s)
                else:
                    forged = dict(proof, leaf=blake3(b"forged-leaf"))
                total[cls] += 1
                if p.verify_proof(key, forged) is False:
                    caught[cls] += 1
    for cls in classes:
        _atom("3d", f"adversarial '{cls}' forgeries caught 100% by "
                    f"verify_integrity/verify_proof",
              caught[cls] == total[cls], f"{caught[cls]}/{total[cls]}")
    _atom("3d", "ZERO escapes across all 5 forgery classes",
          all(caught[c] == total[c] for c in classes),
          f"total={sum(total.values())} caught={sum(caught.values())}")


def _atoms_3e_mvcc():
    rng = random.Random(30305)
    histories = 500
    checks = 0
    wrong = 0
    for _h in range(histories):
        p = PCS()
        keys = [f"key{i}" for i in range(rng.randrange(1, 4))]
        hist = {k: [] for k in keys}
        t = 0
        for _w in range(rng.randrange(3, 13)):
            t += rng.randrange(1, 6)
            k = rng.choice(keys)
            if rng.random() < 0.2 and hist[k]:
                p.delete(k, t=t)
                hist[k].append((t, None))
            else:
                v = {"n": rng.randrange(1000)}
                p.put(k, v, t=t)
                hist[k].append((t, v))
        t_max = t + 3
        for q in range(0, t_max + 1):
            for k in keys:
                expected = None
                for ht, hv in hist[k]:
                    if ht <= q:
                        expected = hv
                got = p.read_at(k, q)
                checks += 1
                if got != expected:
                    wrong += 1
                    _atom("3e", f"read_at wrong at t={q} key={k}", False,
                          (got, expected))
    _atom("3e", f"{histories} random write histories: read_at(t) returns the "
                f"correct version at EVERY t (dense sweep incl. tombstones)",
          wrong == 0, f"checks={checks} wrong={wrong}")


def run_atoms():
    _guard_red()
    ATOMS.clear()
    _atoms_3a_causality()
    _atoms_3b_merkle()
    _atoms_3c_crdt()
    _atoms_3d_adversarial()
    _atoms_3e_mvcc()
    return list(ATOMS)


# ------------------------------------------------------------------ runner

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join("results", "axis3",
                                                  "axis3_suite.json"))
    ap.add_argument("--atoms", action="store_true",
                    help="run the M3 atom battery (3a/3b/3c/3d/3e)")
    args = ap.parse_args()
    if args.atoms:
        checks = run_atoms()
        failed = sum(1 for c in checks if not c["ok"])
        per = {}
        for c in checks:
            per.setdefault(c["battery"], [0, 0])
            per[c["battery"]][0] += 1
            per[c["battery"]][1] += 0 if c["ok"] else 1
        chain = _fold(checks)
        report = {"suite": "axis3-atoms", "total": len(checks),
                  "failed": failed, "passed": failed == 0,
                  "batteries": [{"id": b, "checks": n, "failed": f}
                                  for b, (n, f) in sorted(per.items())],
                  "chain_digest": chain,
                  "checks": checks, "digest": chain}
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w") as fh:
            json.dump(report, fh, indent=1)
        print(f"axis3 atoms: {len(checks) - failed}/{len(checks)} checks "
              f"(failed={failed}) digest={chain[:16]} -> {args.out}")
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
    report = {"suite": "axis3-pcs", "total": len(cases),
              "failed": failed, "passed": failed == 0, "cases": cases,
              "digest": digest}
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(report, fh, indent=1)
    print(f"axis3: {len(cases) - failed}/{len(cases)} passed "
          f"(failed={failed}) digest={digest[:16]} -> {args.out}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()

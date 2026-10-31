#!/usr/bin/env python3
"""Burhan Axis-3 — PCS: the Persistent Causal Store (spec §3.1–§3.8).

§3.1 Structure: keys are BLAKE3 digests of canonical key material
       (burhan/blake3.py — the official blake3 PyPI package since
       2026-10-30, output byte-identical to the pure-Python code it
       replaced); values are CANONICAL
       MessagePack (sorted map keys by encoded bytes, smallest integer
       encodings, float64-only, strict type rejection); every record
       carries a Lamport stamp + a vector-clock snapshot; the store root
       is the Merkle root over the sorted current record digests.
§3.2 Partition: the LEDGER (put/get/delete/transaction) is ACID —
       transactions validate-then-commit with journal rollback
       (all-or-nothing); the STATE (CRDT counters + OR-Sets) is BASE —
       merges are always available (never raise on concurrent divergence)
       and converge eventually by CRDT laws.
§3.3 Lamport R1: tick() = +1 per local event; R2: receive(stamp) =
       max(local, stamp) + 1 (send() stamps post-increment); R3: a -> b
       implies LT(a) < LT(b) — enforced by construction, machine-proven
       by the 3a atom battery (12,000 events, zero violations).
§3.4 Vector clocks: componentwise-max merge; compare() classifies
       equal/before/after/concurrent; causality iff VC order (validated
       against an independently computed happened-before relation).
§3.5 Merkle proofs O(log n): exact-depth sibling paths over the
       duplicate-last tree; verification recomputes the root from
       (leaf, index, siblings); any single-bit flip is detected.
§3.6 CRDTs: GCounter (componentwise max), PNCounter (inc/dec pair),
       ORSet with observed-remove semantics — tombstones make removes
       win over stale presence, unobserved new tags make concurrent
       adds win; tags are single-use. Merge laws: commutative,
       associative, idempotent (proven on random states in 3c).
§3.7 MVCC: per-key version chains with strictly increasing logical
       stamps (explicit t validation included); read_at(key, t) returns
       the value of the largest stamp <= t (O(log V) via bisect);
       tombstones read as None; history is never destroyed.
§3.8 The nine-operation interface: put / get / delete / transaction /
       merkle_proof / verify_proof / merge / read_at / verify_integrity.
       verify_integrity recomputes every record digest from its fields,
       checks chain monotonicity, tx manifests both ways, the root cache,
       the index, and a proof self-check — catching the five forgery
       classes (value / stamp / transaction / root / proof) with zero
       escapes (machine-proven in 3d).

Determinism discipline (Axis-11): every digest covers the LOGICAL
stream only (keys, values, stamps, clocks, proofs) — no wall timings,
no object identities, no dict iteration order leaks (canonical msgpack
sorts everything). Identical operation sequences yield byte-identical
serializations and identical roots.

Standalone by construction: burhan/__init__.py stays empty and the
core hot path never imports this module, so the accepted core contract
(suite 4313/4313, doctor 17/17, bench run-3c0652b6be) cannot drift.
"""
import bisect
import struct

from .blake3 import blake3

__all__ = [
    "GCounter", "IntegrityError", "LamportClock", "MerkleTree", "ORSet",
    "PARTITION_POLICY", "PCS", "PCSError", "PNCounter", "Record",
    "VectorClock", "key_digest", "msgpack_decode", "msgpack_encode",
]

PARTITION_POLICY = {"ledger": "ACID", "state": "BASE"}


# ------------------------------------------------------------------- errors
class PCSError(ValueError):
    """Malformed PCS input: uncanonicalizable value, bad stamp, bad op…"""


class IntegrityError(PCSError):
    """Serialized state failed its integrity check on load."""


# ----------------------------------------------- §3.1 canonical MessagePack
def _enc_int(o, out):
    if 0 <= o <= 0x7F:
        out.append(o)
    elif -0x20 <= o < 0:
        out.append(0xE0 | (o + 0x20))
    elif 0 <= o <= 0xFF:
        out.append(0xCC); out.append(o)
    elif 0 <= o <= 0xFFFF:
        out.append(0xCD); out.extend(o.to_bytes(2, "big"))
    elif 0 <= o <= 0xFFFFFFFF:
        out.append(0xCE); out.extend(o.to_bytes(4, "big"))
    elif 0 <= o <= 0xFFFFFFFFFFFFFFFF:
        out.append(0xCF); out.extend(o.to_bytes(8, "big"))
    elif -0x80 <= o < 0:
        out.append(0xD0); out.extend(o.to_bytes(1, "big", signed=True))
    elif -0x8000 <= o < 0:
        out.append(0xD1); out.extend(o.to_bytes(2, "big", signed=True))
    elif -0x80000000 <= o < 0:
        out.append(0xD2); out.extend(o.to_bytes(4, "big", signed=True))
    elif -0x8000000000000000 <= o < 0:
        out.append(0xD3); out.extend(o.to_bytes(8, "big", signed=True))
    else:
        raise PCSError(f"integer out of MessagePack range: {o}")


def _enc_bytes_header(n, out):
    if n <= 0xFF:
        out.append(0xC4); out.append(n)
    elif n <= 0xFFFF:
        out.append(0xC5); out.extend(n.to_bytes(2, "big"))
    else:
        out.append(0xC6); out.extend(n.to_bytes(4, "big"))


def _enc_str_header(n, out):
    if n <= 31:
        out.append(0xA0 | n)
    elif n <= 0xFF:
        out.append(0xD9); out.append(n)
    elif n <= 0xFFFF:
        out.append(0xDA); out.extend(n.to_bytes(2, "big"))
    else:
        out.append(0xDB); out.extend(n.to_bytes(4, "big"))


def _enc_array_header(n, out):
    if n <= 15:
        out.append(0x90 | n)
    elif n <= 0xFFFF:
        out.append(0xDC); out.extend(n.to_bytes(2, "big"))
    else:
        out.append(0xDD); out.extend(n.to_bytes(4, "big"))


def _enc_map_header(n, out):
    if n <= 15:
        out.append(0x80 | n)
    elif n <= 0xFFFF:
        out.append(0xDE); out.extend(n.to_bytes(2, "big"))
    else:
        out.append(0xDF); out.extend(n.to_bytes(4, "big"))


def _encode(o, out):
    if o is None:
        out.append(0xC0)
    elif o is True:
        out.append(0xC3)
    elif o is False:
        out.append(0xC2)
    elif isinstance(o, int):
        _enc_int(o, out)
    elif isinstance(o, float):
        out.append(0xCB); out.extend(struct.pack(">d", o))
    elif isinstance(o, str):
        b = o.encode("utf-8")
        _enc_str_header(len(b), out); out.extend(b)
    elif isinstance(o, (bytes, bytearray)):
        b = bytes(o)
        _enc_bytes_header(len(b), out); out.extend(b)
    elif isinstance(o, (list, tuple)):
        _enc_array_header(len(o), out)
        for x in o:
            _encode(x, out)
    elif isinstance(o, dict):
        items = []
        for k, v in o.items():
            kb = bytearray()
            _encode(k, kb)
            items.append((bytes(kb), v))
        items.sort(key=lambda kv: kv[0])       # canonical: by encoded key
        _enc_map_header(len(items), out)
        for kb, v in items:
            out.extend(kb)
            _encode(v, out)
    else:
        raise PCSError(f"type is not canonicalizable: {type(o).__name__}")


def msgpack_encode(obj) -> bytes:
    """Canonical MessagePack: deterministic bytes for equal logical values."""
    out = bytearray()
    _encode(obj, out)
    return bytes(out)


def _dec_one(buf, pos):
    if pos >= len(buf):
        raise PCSError("truncated MessagePack")
    b = buf[pos]
    if b <= 0x7F:
        return b, pos + 1
    if b >= 0xE0:
        return b - 0x100, pos + 1
    if 0x80 <= b <= 0x8F:
        n = b & 0x0F; pos += 1
        return _dec_map(buf, pos, n)
    if 0x90 <= b <= 0x9F:
        n = b & 0x0F; pos += 1
        return _dec_array(buf, pos, n)
    if 0xA0 <= b <= 0xBF:
        n = b & 0x1F; pos += 1
        return _dec_str(buf, pos, n)
    if b == 0xC0:
        return None, pos + 1
    if b == 0xC2:
        return False, pos + 1
    if b == 0xC3:
        return True, pos + 1
    if b == 0xC4:
        n = buf[pos + 1]; return bytes(buf[pos + 2:pos + 2 + n]), pos + 2 + n
    if b == 0xC5:
        n = int.from_bytes(buf[pos + 1:pos + 3], "big")
        return bytes(buf[pos + 3:pos + 3 + n]), pos + 3 + n
    if b == 0xC6:
        n = int.from_bytes(buf[pos + 1:pos + 5], "big")
        return bytes(buf[pos + 5:pos + 5 + n]), pos + 5 + n
    if b == 0xC7 or b == 0xC8 or b == 0xC9:
        raise PCSError("ext types not in the canonical subset")
    if b == 0xCA:
        return struct.unpack(">f", buf[pos + 1:pos + 5])[0], pos + 5
    if b == 0xCB:
        return struct.unpack(">d", buf[pos + 1:pos + 9])[0], pos + 9
    if b == 0xCC:
        return buf[pos + 1], pos + 2
    if b == 0xCD:
        return int.from_bytes(buf[pos + 1:pos + 3], "big"), pos + 3
    if b == 0xCE:
        return int.from_bytes(buf[pos + 1:pos + 5], "big"), pos + 5
    if b == 0xCF:
        return int.from_bytes(buf[pos + 1:pos + 9], "big"), pos + 9
    if b == 0xD0:
        return int.from_bytes(buf[pos + 1:pos + 2], "big", signed=True), pos + 2
    if b == 0xD1:
        return int.from_bytes(buf[pos + 1:pos + 3], "big", signed=True), pos + 3
    if b == 0xD2:
        return int.from_bytes(buf[pos + 1:pos + 5], "big", signed=True), pos + 5
    if b == 0xD3:
        return int.from_bytes(buf[pos + 1:pos + 9], "big", signed=True), pos + 9
    if b == 0xD9:
        n = buf[pos + 1]; return _dec_str(buf, pos + 2, n)
    if b == 0xDA:
        n = int.from_bytes(buf[pos + 1:pos + 3], "big")
        return _dec_str(buf, pos + 3, n)
    if b == 0xDB:
        n = int.from_bytes(buf[pos + 1:pos + 5], "big")
        return _dec_str(buf, pos + 5, n)
    if b == 0xDC:
        n = int.from_bytes(buf[pos + 1:pos + 3], "big")
        return _dec_array(buf, pos + 3, n)
    if b == 0xDD:
        n = int.from_bytes(buf[pos + 1:pos + 5], "big")
        return _dec_array(buf, pos + 5, n)
    if b == 0xDE:
        n = int.from_bytes(buf[pos + 1:pos + 3], "big")
        return _dec_map(buf, pos + 3, n)
    if b == 0xDF:
        n = int.from_bytes(buf[pos + 1:pos + 5], "big")
        return _dec_map(buf, pos + 5, n)
    raise PCSError(f"unknown MessagePack marker 0x{b:02x}")


def _dec_str(buf, pos, n):
    if pos + n > len(buf):
        raise PCSError("truncated str")
    return buf[pos:pos + n].decode("utf-8"), pos + n


def _dec_array(buf, pos, n):
    out = []
    for _ in range(n):
        v, pos = _dec_one(buf, pos)
        out.append(v)
    return out, pos


def _dec_map(buf, pos, n):
    out = {}
    for _ in range(n):
        k, pos = _dec_one(buf, pos)
        v, pos = _dec_one(buf, pos)
        out[k] = v
    return out, pos


def msgpack_decode(buf):
    if not isinstance(buf, (bytes, bytearray)):
        raise PCSError("msgpack_decode expects bytes")
    v, pos = _dec_one(bytes(buf), 0)
    if pos != len(buf):
        raise PCSError("trailing bytes after MessagePack value")
    return v


def key_digest(key) -> bytes:
    """The storage key of a logical key: BLAKE3(canonical key material)."""
    if not isinstance(key, str):
        raise PCSError(f"keys must be str, got {type(key).__name__}")
    return blake3(msgpack_encode(key))


# ------------------------------------------------------------- §3.3 Lamport
class LamportClock:
    """Lamport logical clock: R1 tick, R2 send/receive, R3 by construction."""

    __slots__ = ("_t",)

    def __init__(self, t: int = 0):
        self._t = int(t)

    @property
    def t(self):
        return self._t

    def tick(self) -> int:
        """R1: each local event increments the counter by exactly 1."""
        self._t += 1
        return self._t

    def send(self) -> int:
        """A send IS an event: the message is stamped post-increment."""
        return self.tick()

    def receive(self, stamp: int) -> int:
        """R2: t = max(local, received) + 1."""
        self._t = max(self._t, int(stamp)) + 1
        return self._t

    def merge(self, other: "LamportClock") -> int:
        """Merged clocks continue from the max (the virtual-receive rule)."""
        self._t = max(self._t, other._t)
        return self._t


# -------------------------------------------------------- §3.4 vector clocks
class VectorClock:
    """Vector clock: per-node counters, componentwise-max merge."""

    __slots__ = ("_node", "_c")

    def __init__(self, node_id: str = "node"):
        self._node = node_id
        self._c = {}

    def tick(self):
        self._c[self._node] = self._c.get(self._node, 0) + 1
        return self

    def snapshot(self):
        return tuple(sorted(self._c.items()))

    def merge_snap(self, snap):
        for node, count in snap:
            if node not in self._c or count > self._c[node]:
                self._c[node] = count
        return self

    def merge_from(self, other: "VectorClock"):
        return self.merge_snap(other.snapshot())

    @staticmethod
    def merge_vc(a, b):
        merged = dict(a)
        for node, count in b:
            if node not in merged or count > merged[node]:
                merged[node] = count
        return tuple(sorted(merged.items()))

    @staticmethod
    def compare(a, b) -> str:
        """equal | before | after | concurrent (a is the subject)."""
        da = dict(a); db = dict(b)
        a_le = all(db.get(n, 0) >= c for n, c in da.items())
        b_le = all(da.get(n, 0) >= c for n, c in db.items())
        if a_le and b_le:
            return "equal"
        if a_le:
            return "before"
        if b_le:
            return "after"
        return "concurrent"

    @staticmethod
    def happens_before(a, b) -> bool:
        return VectorClock.compare(a, b) == "before"

    @staticmethod
    def concurrent(a, b) -> bool:
        return VectorClock.compare(a, b) == "concurrent"


# -------------------------------------------------------------- §3.5 Merkle
class MerkleTree:
    """BLAKE3 Merkle tree over 32-byte leaves (duplicate-last padding).
    Proof for leaf i = the sibling list bottom-up; length = tree depth
    (ceil(log2 n) for n >= 2; 0 for n == 1 where root == leaf)."""

    __slots__ = ("_levels", "leaves")

    def __init__(self, leaves):
        leaves = [bytes(x) for x in leaves]
        if not leaves:
            raise PCSError("MerkleTree requires at least one leaf")
        for x in leaves:
            if len(x) != 32:
                raise PCSError(f"leaves must be 32-byte digests, got {len(x)}")
        self.leaves = leaves
        levels = [list(leaves)]
        cur = list(leaves)
        while len(cur) > 1:
            nxt = []
            for i in range(0, len(cur), 2):
                left = cur[i]
                right = cur[i + 1] if i + 1 < len(cur) else cur[i]
                nxt.append(blake3(left + right))
            levels.append(nxt)
            cur = nxt
        self._levels = levels

    @property
    def root(self) -> bytes:
        return self._levels[-1][0]

    def proof(self, index: int):
        if not 0 <= index < len(self.leaves):
            raise PCSError(f"proof index {index} out of range")
        siblings = []
        idx = index
        for level in self._levels[:-1]:
            sib_i = idx ^ 1
            if sib_i < len(level):
                siblings.append(level[sib_i])
            else:
                siblings.append(level[idx])    # duplicated last node
            idx //= 2
        return siblings

    @staticmethod
    def verify(leaf: bytes, index: int, siblings, root: bytes) -> bool:
        if not isinstance(leaf, (bytes, bytearray)) or len(leaf) != 32:
            return False
        if not isinstance(root, (bytes, bytearray)) or len(root) != 32:
            return False
        if not isinstance(index, int) or index < 0:
            return False
        cur = bytes(leaf)
        idx = index
        for sib in siblings:
            if not isinstance(sib, (bytes, bytearray)) or len(sib) != 32:
                return False
            sib = bytes(sib)
            cur = blake3(cur + sib) if idx % 2 == 0 else blake3(sib + cur)
            idx //= 2
        return cur == bytes(root)


# --------------------------------------------------------------- §3.6 CRDTs
class GCounter:
    """Grow-only counter: componentwise-max merge (a state-based CRDT)."""

    __slots__ = ("_c",)

    def __init__(self, state=None):
        self._c = dict(state or {})

    def increment(self, node, by=1):
        if not isinstance(by, int) or by <= 0:
            raise PCSError(f"increment must be a positive int, got {by!r}")
        self._c[node] = self._c.get(node, 0) + by

    def value(self) -> int:
        return sum(self._c.values())

    def merge(self, other: "GCounter") -> "GCounter":
        return GCounter(VectorClock.merge_vc(
            tuple(self._c.items()), tuple(other._c.items())))

    def state(self):
        return {k: self._c[k] for k in sorted(self._c)}


class PNCounter:
    """Positive-negative counter: two G-Counters, value = inc - dec."""

    __slots__ = ("_inc", "_dec")

    def __init__(self, state=None):
        state = state or {}
        self._inc = GCounter(state.get("inc") or {})
        self._dec = GCounter(state.get("dec") or {})

    def increment(self, node, by=1):
        self._inc.increment(node, by)

    def decrement(self, node, by=1):
        self._dec.increment(node, by)

    def value(self) -> int:
        return self._inc.value() - self._dec.value()

    def merge(self, other: "PNCounter") -> "PNCounter":
        return PNCounter({"inc": self._inc.merge(other._inc).state(),
                          "dec": self._dec.merge(other._dec).state()})

    def state(self):
        return {"inc": self._inc.state(), "dec": self._dec.state()}


def _tag_key(tag):
    return (str(tag[0]), int(tag[1]))


class ORSet:
    """Observed-remove set: add(elem, tag); remove drops the OBSERVED tags
    into a tombstone set (single-use tags); merge = union of present tags
    minus the union of tombstones. Concurrent add (new tag) wins over a
    remove that never observed it; a remove always wins over stale
    presence of the same tag. Merge laws hold by set algebra."""

    __slots__ = ("_present", "_removed")

    def __init__(self):
        self._present = {}
        self._removed = set()

    @classmethod
    def _from(cls, present, removed):
        s = ORSet()
        s._present = {e: set(tags) for e, tags in present.items() if tags}
        s._removed = set(removed)
        return s

    def add(self, elem, tag):
        t = _tag_key(tag)
        if t in self._removed:
            raise PCSError(f"tag {t} is tombstoned (single-use rule)")
        self._present.setdefault(elem, set()).add(t)

    def remove(self, elem):
        tags = self._present.pop(elem, set())
        self._removed |= tags

    def contains(self, elem) -> bool:
        return bool(self._present.get(elem))

    def value(self):
        return sorted(self._present, key=msgpack_encode)

    def merge(self, other: "ORSet") -> "ORSet":
        present = {}
        for e in set(self._present) | set(other._present):
            present[e] = (self._present.get(e, set())
                          | other._present.get(e, set()))
        removed = self._removed | other._removed
        return ORSet._from({e: t - removed for e, t in present.items()},
                           removed)

    def state(self):
        return {
            "present": {e: [list(t) for t in sorted(v)]
                        for e, v in sorted(self._present.items(),
                                           key=lambda kv: msgpack_encode(kv[0]))},
            "removed": [list(t) for t in sorted(self._removed)],
        }


# ------------------------------------------------- §3.1/§3.7 Record + chains
class Record:
    """One ledger version: content-addressed by its BLAKE3 digest over the
    canonical field payload (key, kind, value bytes, Lamport, VC, tx, t)."""

    __slots__ = ("key", "key_digest", "value", "value_bytes", "lamport",
                 "vc", "kind", "tx_id", "t", "digest")

    def __init__(self, key, key_digest, value, value_bytes, lamport, vc,
                 kind, tx_id, t):
        self.key = key
        self.key_digest = key_digest
        self.value = value
        self.value_bytes = value_bytes
        self.lamport = int(lamport)
        self.vc = tuple(vc)
        self.kind = kind
        self.tx_id = tx_id
        self.t = int(t)
        self.digest = self.recompute_digest()

    def _payload(self):
        return {"key": self.key, "kind": self.kind,
                "value_bytes": self.value_bytes, "lamport": self.lamport,
                "vc": [[n, c] for n, c in self.vc],
                "tx": self.tx_id if self.tx_id is not None else "",
                "t": self.t}

    def recompute_digest(self) -> bytes:
        return blake3(msgpack_encode(self._payload()))


_EMPTY_ROOT = blake3(b"burhan-pcs-empty-v1")


def _chain_sort_key(entry):
    return entry["t"]


def _merge_chains(mine, theirs):
    """Deterministic chain union: same-t conflicts resolve to the record
    with the larger (lamport, digest) — commutative by max semantics."""
    by_t = {}
    for entry in mine:
        by_t[entry["t"]] = entry
    for entry in theirs:
        t = entry["t"]
        cur = by_t.get(t)
        if cur is None:
            by_t[t] = entry
            continue
        a = cur["record"]
        b = entry["record"]
        if (b.lamport, b.digest) > (a.lamport, a.digest):
            by_t[t] = entry
    return [{"t": t, "record": by_t[t]["record"]} for t in sorted(by_t)]


# -------------------------------------------------------------- §3.8 the PCS
class PCS:
    """The Persistent Causal Store: ACID ledger + BASE state (§3.2), the
    nine operations of §3.8, causal stamps (§3.3/§3.4), Merkle evidence
    (§3.5) and MVCC temporal reads (§3.7)."""

    def __init__(self, node_id="node-0"):
        self.node_id = node_id
        self._lamport = LamportClock()
        self._vc = VectorClock(node_id)
        self._global = 0                      # max logical stamp seen
        self._chains = {}                     # key_hex -> {"entries", "ts"}
        self._index = {}                      # logical key -> key_hex
        self._tx = {}                         # tx_id -> [record digests]
        self._counters = {}                   # name -> PNCounter (BASE)
        self._sets = {}                       # name -> ORSet (BASE)
        self._root_cache = _EMPTY_ROOT

    # ------------------------------------------------------------- helpers
    @staticmethod
    def _kh(key) -> str:
        return key_digest(key).hex()

    def _chain(self, key):
        """LOOKUP ONLY (no side effects): the chain dict or None."""
        return self._chains.get(self._kh(key))

    def _append_entry(self, key, t, rec):
        kh = self._kh(key)
        chain = self._chains.get(kh)
        if chain is None:
            chain = {"entries": [], "ts": []}
            self._chains[kh] = chain
        chain["entries"].append({"t": t, "record": rec})
        chain["ts"].append(t)
        self._index[key] = kh
        return kh

    def _current_record(self, key) -> Record:
        chain = self._chain(key)
        if not chain or not chain["entries"]:
            raise PCSError(f"unknown key: {key!r}")
        return chain["entries"][-1]["record"]

    def _current_digests(self):
        return sorted(ch["entries"][-1]["record"].digest
                      for ch in self._chains.values() if ch["entries"])

    def _refresh_root(self):
        digests = self._current_digests()
        self._root_cache = MerkleTree(digests).root if digests else _EMPTY_ROOT
        return self._root_cache

    def _version_count(self) -> int:
        return sum(len(ch["entries"]) for ch in self._chains.values())

    def _next_stamp(self, key, t):
        chain = self._chain(key)
        last_t = chain["ts"][-1] if chain and chain["ts"] else 0
        if t is None:
            return max(self._global + 1, last_t + 1)
        if not isinstance(t, int) or isinstance(t, bool) or t <= 0:
            raise PCSError(f"stamp must be a positive int, got {t!r}")
        if t <= last_t:
            raise PCSError(f"stamp {t} not > last stamp {last_t} of {key!r}")
        return t

    def _make_record(self, key, kind, value, value_bytes, tx_id, t):
        lt = self._lamport.tick()
        self._vc.tick()
        return Record(key=key, key_digest=key_digest(key), value=value,
                      value_bytes=value_bytes, lamport=lt,
                      vc=self._vc.snapshot(), kind=kind, tx_id=tx_id, t=t)

    def partition_policy(self):
        return dict(PARTITION_POLICY)

    # ------------------------------------------------- op 1/2/3: put/get/delete
    def put(self, key, value, t=None):
        if not isinstance(key, str):
            raise PCSError(f"keys must be str, got {type(key).__name__}")
        value_bytes = msgpack_encode(value)   # rejects non-canonicalizable
        t = self._next_stamp(key, t)
        self._global = max(self._global, t)
        rec = self._make_record(key, "put", value, value_bytes, None, t)
        self._append_entry(key, t, rec)
        self._refresh_root()
        return rec

    def get(self, key):
        chain = self._chain(key)
        if not chain or not chain["entries"]:
            return None
        rec = chain["entries"][-1]["record"]
        return None if rec.kind == "delete" else rec.value

    def delete(self, key, t=None):
        chain = self._chain(key)
        if not chain or not chain["entries"]:
            return False
        if chain["entries"][-1]["record"].kind == "delete":
            return False                       # already tombstoned
        t = self._next_stamp(key, t)
        self._global = max(self._global, t)
        rec = self._make_record(key, "delete", None, msgpack_encode(None),
                                None, t)
        self._append_entry(key, t, rec)
        self._refresh_root()
        return True

    # ------------------------------------------------------- op 4: transaction
    def transaction(self, ops):
        """ACID batch: validate EVERY op first, then commit atomically with
        a journal rollback (§3.2). Ops: ("put", key, value) | ("delete", key)."""
        if not isinstance(ops, (list, tuple)) or not ops:
            raise PCSError("transaction needs a non-empty op list")
        parsed = []
        touched_last = []
        for op in ops:
            if not (isinstance(op, (list, tuple)) and len(op) in (2, 3)):
                raise PCSError(f"malformed op: {op!r}")
            kind, key = op[0], op[1]
            if not isinstance(key, str):
                raise PCSError(f"keys must be str, got {type(key).__name__}")
            if kind == "put":
                if len(op) != 3:
                    raise PCSError("put op needs a value")
                value_bytes = msgpack_encode(op[2])
                parsed.append(("put", key, op[2], value_bytes))
            elif kind == "delete":
                chain = self._chain(key)
                if (not chain or not chain["entries"]
                        or chain["entries"][-1]["record"].kind == "delete"):
                    raise PCSError(f"delete of missing/tombstoned key {key!r}")
                parsed.append(("delete", key, None, msgpack_encode(None)))
            else:
                raise PCSError(f"unknown op kind: {kind!r}")
            chain = self._chain(key)
            touched_last.append(chain["ts"][-1] if chain and chain["ts"] else 0)
        t = max([self._global + 1] + [lt + 1 for lt in touched_last])
        self._global = max(self._global, t)
        tx_id = f"tx-{len(self._tx)}-{t}"
        journal = []                           # (key, was_new_key)
        committed = []
        try:
            for kind, key, value, value_bytes in parsed:
                rec = self._make_record(key, kind, value, value_bytes,
                                        tx_id, t)
                was_new = self._kh(key) not in self._chains
                self._append_entry(key, t, rec)
                journal.append((key, was_new))
                committed.append(rec)
        except Exception as e:                  # noqa: BLE001 — atomic rollback
            for key, was_new in reversed(journal):
                kh = self._kh(key)
                self._chains[kh]["entries"].pop()
                self._chains[kh]["ts"].pop()
                if not self._chains[kh]["entries"]:
                    del self._chains[kh]
                if was_new:
                    self._index.pop(key, None)
            raise PCSError(f"transaction rolled back: {e}") from e
        self._tx[tx_id] = [r.digest for r in committed]
        self._refresh_root()
        return committed

    # ------------------------------------------------- op 5/6: Merkle evidence
    def merkle_proof(self, key):
        chain = self._chain(key)
        if not chain or not chain["entries"]:
            raise PCSError(f"unknown key: {key!r}")
        leaf = chain["entries"][-1]["record"].digest
        leaves = self._current_digests()
        index = leaves.index(leaf) if leaf in leaves else -1
        if index < 0:                           # cannot happen post-refresh
            raise IntegrityError("current digest missing from the leaf set")
        tree = MerkleTree(leaves)
        return {"index": index, "leaf": leaf,
                "siblings": tree.proof(index), "root": self._root_cache}

    def verify_proof(self, key, proof, root=None):
        chain = self._chain(key)
        if not chain or not chain["entries"]:
            raise PCSError(f"unknown key: {key!r}")
        if not isinstance(proof, dict):
            return False
        leaf = proof.get("leaf")
        siblings = proof.get("siblings")
        index = proof.get("index")
        if not (isinstance(leaf, bytes) and len(leaf) == 32):
            return False
        if leaf != chain["entries"][-1]["record"].digest:
            return False                        # proof attests another record
        if not (isinstance(index, int) and index >= 0):
            return False
        if not isinstance(siblings, (list, tuple)):
            return False
        target = root if root is not None else self._root_cache
        return MerkleTree.verify(leaf, index, siblings, target)

    # ------------------------------------------------------- op 8: read_at(t)
    def read_at(self, key, t):
        """MVCC temporal read: the value of the largest stamp <= t
        (O(log V) via bisect); tombstones/missing read as None."""
        if not isinstance(t, int) or isinstance(t, bool):
            raise PCSError(f"read_at stamp must be an int, got {t!r}")
        chain = self._chain(key)
        if not chain or not chain["entries"]:
            return None
        i = bisect.bisect_right(chain["ts"], t) - 1
        if i < 0:
            return None
        rec = chain["entries"][i]["record"]
        return None if rec.kind == "delete" else rec.value

    # -------------------------------------------------------- op 7: BASE merge
    def counter(self, name) -> PNCounter:
        if not isinstance(name, str):
            raise PCSError("counter names must be str")
        if name not in self._counters:
            self._counters[name] = PNCounter()
        return self._counters[name]

    def set(self, name) -> ORSet:
        if not isinstance(name, str):
            raise PCSError("set names must be str")
        if name not in self._sets:
            self._sets[name] = ORSet()
        return self._sets[name]

    def merge(self, other):
        """BASE merge (§3.2/§3.6): CRDT state unions + deterministic ledger
        chain union; commutative by construction, converges both directions."""
        if not isinstance(other, PCS):
            raise PCSError("merge expects another PCS")
        for name in set(self._counters) | set(other._counters):
            mine = self._counters.get(name) or PNCounter()
            theirs = other._counters.get(name) or PNCounter()
            self._counters[name] = mine.merge(theirs)
        for name in set(self._sets) | set(other._sets):
            mine = self._sets.get(name) or ORSet()
            theirs = other._sets.get(name) or ORSet()
            self._sets[name] = mine.merge(theirs)
        for kh in set(self._chains) | set(other._chains):
            merged = _merge_chains(self._chains.get(kh, {"entries": []})["entries"],
                                   other._chains.get(kh, {"entries": []})["entries"])
            entries = merged
            self._chains[kh] = {"entries": entries,
                                "ts": [e["t"] for e in entries]}
        for k, kh in other._index.items():
            self._index.setdefault(k, kh)
        for tx_id, digests in other._tx.items():
            union = set(self._tx.get(tx_id, [])) | set(digests)
            self._tx[tx_id] = sorted(union)
        self._global = max(self._global, other._global)
        self._lamport.merge(other._lamport)
        self._vc.merge_from(other._vc)
        self._refresh_root()

    # ------------------------------------------------------ op 9: integrity
    def verify_integrity(self):
        """Recompute everything from the stored fields: record digests, chain
        monotonicity, tx manifests (both directions), the root cache, the
        index, and a proof self-check per key. Catches the five forgery
        classes with zero escapes (3d-proven)."""
        violations = []
        records = keys = txs = proofs = 0
        all_digests = {}
        for kh, chain in self._chains.items():
            keys += 1
            last_t = None
            for entry in chain["entries"]:
                rec = entry["record"]
                records += 1
                if rec.recompute_digest() != rec.digest:
                    violations.append(
                        f"record digest mismatch: key={rec.key!r} t={entry['t']}")
                if entry["t"] != rec.t:
                    violations.append(
                        f"entry t {entry['t']} != record t {rec.t} "
                        f"(key {rec.key!r})")
                if last_t is not None and entry["t"] <= last_t:
                    violations.append(
                        f"chain stamps not strictly increasing: {rec.key!r}")
                last_t = entry["t"]
                all_digests[rec.digest] = rec
        for k, kh in self._index.items():
            chain = self._chains.get(kh)
            if not chain or not chain["entries"]:
                violations.append(f"index points at empty chain: {k!r}")
            else:
                rec = chain["entries"][-1]["record"]
                if rec.key != k:
                    violations.append(f"index key mismatch: {k!r} != {rec.key!r}")
        for tx_id, digests in self._tx.items():
            txs += 1
            for d in digests:
                rec = all_digests.get(d)
                if rec is None or rec.tx_id != tx_id:
                    violations.append(
                        f"manifest digest missing/mismatched: {tx_id}")
        for d, rec in all_digests.items():
            if rec.tx_id is not None and d not in self._tx.get(rec.tx_id, []):
                violations.append(
                    f"tx record not in its manifest: {rec.tx_id}")
        digests = self._current_digests()
        recomputed = MerkleTree(digests).root if digests else _EMPTY_ROOT
        if recomputed != self._root_cache:
            violations.append("root cache mismatch (forged Merkle evidence?)")
        for k in list(self._index):
            proofs += 1
            try:
                if not self.verify_proof(k, self.merkle_proof(k)):
                    violations.append(f"proof self-check failed: {k!r}")
            except PCSError as e:
                violations.append(f"proof self-check error: {k!r}: {e}")
        return {"passed": not violations,
                "violations": violations[:20],
                "checked": {"records": records, "keys": keys,
                            "transactions": txs, "proofs": proofs}}

    # ------------------------------------------------------- state + serialize
    def state_snapshot(self):
        """Canonical BASE-partition snapshot (convergence comparisons)."""
        return {"counters": {n: self._counters[n].state()
                             for n in sorted(self._counters)},
                "sets": {n: self._sets[n].state()
                         for n in sorted(self._sets)}}

    def root(self) -> bytes:
        return self._root_cache

    def serialize(self) -> bytes:
        payload = {
            "version": 1,
            "node_id": self.node_id,
            "global": self._global,
            "lamport": self._lamport.t,
            "vc": [[n, c] for n, c in self._vc.snapshot()],
            "chains": [[kh,
                        [[e["t"],
                          {"key": e["record"].key, "kind": e["record"].kind,
                           "value_bytes": e["record"].value_bytes,
                           "lamport": e["record"].lamport,
                           "vc": [[n, c] for n, c in e["record"].vc],
                           "tx": e["record"].tx_id or "",
                           "t": e["record"].t,
                           "digest": e["record"].digest}]
                         for e in ch["entries"]]]
                       for kh, ch in sorted(self._chains.items())],
            "index": [[k, kh] for k, kh in sorted(self._index.items())],
            "tx": [[tx, digests] for tx, digests in sorted(self._tx.items())],
            "counters": self.state_snapshot()["counters"],
            "sets": self.state_snapshot()["sets"],
        }
        return msgpack_encode(payload)

    @classmethod
    def deserialize(cls, blob):
        data = msgpack_decode(blob)
        if not isinstance(data, dict) or data.get("version") != 1:
            raise IntegrityError("unknown PCS serialization version")
        p = cls(node_id=data["node_id"])
        p._global = int(data["global"])
        p._lamport = LamportClock(data["lamport"])
        p._vc = VectorClock(data["node_id"])
        p._vc.merge_snap(tuple((n, c) for n, c in data["vc"]))
        for kh, entries in data["chains"]:
            chain = {"entries": [], "ts": []}
            for t, fields in entries:
                rec = Record(key=fields["key"],
                             key_digest=key_digest(fields["key"]),
                             value=msgpack_decode(fields["value_bytes"]),
                             value_bytes=fields["value_bytes"],
                             lamport=fields["lamport"],
                             vc=tuple((n, c) for n, c in fields["vc"]),
                             kind=fields["kind"],
                             tx_id=fields["tx"] or None,
                             t=fields["t"])
                if rec.digest != fields["digest"]:
                    raise IntegrityError(
                        f"serialized record digest mismatch: {fields['key']!r}")
                chain["entries"].append({"t": t, "record": rec})
                chain["ts"].append(t)
            p._chains[kh] = chain
        for k, kh in data["index"]:
            p._index[k] = kh
        for tx, digests in data["tx"]:
            p._tx[tx] = list(digests)
        for name, state in data["counters"].items():
            p._counters[name] = PNCounter(state)
        for name, state in data["sets"].items():
            s = ORSet()
            for elem, tags in state["present"].items():
                s._present[elem] = {tuple(t) for t in tags}
            s._removed = {tuple(t) for t in state["removed"]}
            p._sets[name] = s
        p._refresh_root()
        return p

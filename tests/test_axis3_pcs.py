"""SENTINEL Axis-3 — BLAKE3 + PCS test suite (official vectors).

Vector provenance — the BLAKE3 reference repository's official
test_vectors.json (35 cases, input lengths 0..102400 covering every
block/chunk/tree boundary):
https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
(fetched 2026-10-30). The 'hash' field there is the 131-byte extended
output; the standard 32-byte hash-mode digest embedded below is its first
32 bytes. Input rule, quoted from that file: "The input in each case is
filled with a repeating sequence of 251 bytes: 0, 1, 2, ..., 249, 250,
0, 1, ..." i.e. input[i] = i % 251.

This file is ALSO the correction of the stale reference that used to sit
in sentinel/blake3.py's docstring: vectors were claimed to live in
tests/test_axis3_pcs.py while no such file had ever been committed
(verified: git log --all on the path was empty). The vectors now
genuinely live at this exact path, and the suite additionally covers the
pcs.py consumers of the primitive (key_digest, MerkleTree nodes and
proofs, record digests, serialize/deserialize round-trips, determinism
of the store root).
"""
import pytest

from sentinel.blake3 import blake3
from sentinel.pcs import (PCS, MerkleTree, PCSError, key_digest,
                          msgpack_encode)


def _gen(n):
    """Official input rule: input[i] = i % 251."""
    return bytes(i % 251 for i in range(n))


# ---- the 35 official vectors (input_len -> first 32 bytes of 'hash') ----
OFFICIAL_VECTORS = [
    (0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
    (1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"),
    (2, "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63"),
    (3, "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"),
    (4, "f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f32"),
    (5, "b40b44dfd97e7a84a996a91af8b85188c66c126940ba7aad2e7ae6b385402aa2"),
    (6, "06c4e8ffb6872fad96f9aaca5eee1553eb62aed0ad7198cef42e87f6a616c844"),
    (7, "3f8770f387faad08faa9d8414e9f449ac68e6ff0417f673f602a646a891419fe"),
    (8, "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb"),
    (63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b"),
    (64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"),
    (65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"),
    (127, "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d"),
    (128, "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef"),
    (129, "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12"),
    (1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"),
    (1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"),
    (1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"),
    (2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"),
    (2049, "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030"),
    (3072, "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2"),
    (3073, "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3"),
    (4096, "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969"),
    (4097, "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995"),
    (5120, "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833"),
    (5121, "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff"),
    (6144, "3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca205"),
    (6145, "f1323a8631446cc50536a9f705ee5cb619424d46887f3c376c695b70e0f0507f"),
    (7168, "61da957ec2499a95d6b8023e2b0e604ec7f6b50e80a9678b89d2628e99ada77a"),
    (7169, "a003fc7a51754a9b3c7fae0367ab3d782dccf28855a03d435f8cfe74605e7817"),
    (8192, "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63"),
    (8193, "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b"),
    (16384, "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4"),
    (31744, "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47"),
    (102400, "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085"),
]


@pytest.mark.parametrize("length,expected_hex", OFFICIAL_VECTORS,
                         ids=[f"len-{l}" for l, _ in OFFICIAL_VECTORS])
def test_official_blake3_vector(length, expected_hex):
    assert blake3(_gen(length)) == bytes.fromhex(expected_hex)


def test_type_contract_unchanged():
    with pytest.raises(TypeError):
        blake3("not-bytes")
    with pytest.raises(TypeError):
        blake3(42)
    assert blake3(bytearray(b"abc")) == blake3(b"abc")
    assert blake3(memoryview(b"abc")) == blake3(b"abc")
    assert len(blake3(b"")) == 32


# ---- pcs.py consumers ---------------------------------------------------

def test_key_digest_is_blake3_of_canonical_msgpack():
    # canonical msgpack of the short str "abc" is the fixstr b"\xa3abc"
    assert key_digest("abc") == blake3(b"\xa3abc")
    assert key_digest("abc") == blake3(msgpack_encode("abc"))
    assert len(key_digest("k")) == 32


def test_merkle_tree_matches_direct_blake3_recompute():
    leaves = [blake3(_gen(n)) for n in (0, 1, 2, 64, 1024)]
    t = MerkleTree(leaves)
    # manual duplicate-last recompute with the raw primitive
    cur = list(leaves)
    while len(cur) > 1:
        nxt = []
        for i in range(0, len(cur), 2):
            left = cur[i]
            right = cur[i + 1] if i + 1 < len(cur) else cur[i]
            nxt.append(blake3(left + right))
        cur = nxt
    assert t.root == cur[0]
    # proof/verify roundtrip for every leaf + tamper detection
    for i, leaf in enumerate(leaves):
        sib = t.proof(i)
        assert MerkleTree.verify(leaf, i, sib, t.root)
        assert not MerkleTree.verify(bytes(b ^ 1 for b in leaf), i, sib,
                                     t.root)


def test_single_leaf_tree_root_is_leaf():
    leaf = blake3(b"solo")
    t = MerkleTree([leaf])
    assert t.root == leaf
    assert t.proof(0) == []
    assert MerkleTree.verify(leaf, 0, [], leaf)


def test_tree_rejects_non_32byte_leaves():
    with pytest.raises(PCSError):
        MerkleTree([b"short"])
    with pytest.raises(PCSError):
        MerkleTree([])


def test_pcs_end_to_end_with_library_digests():
    s = PCS(node_id="vec-node")
    r = s.put("alpha", {"v": 1})
    assert s.get("alpha") == {"v": 1}
    # record digest is content-addressed over ALL fields via blake3
    assert r.digest == r.recompute_digest()
    s.put("beta", [1, 2, 3])
    s.delete("alpha")
    assert s.get("alpha") is None
    # MVCC read at the put's stamp still sees the value
    assert s.read_at("alpha", r.t) == {"v": 1}
    # merkle proof for a live key verifies; a forged root does not
    proof = s.merkle_proof("beta")
    assert s.verify_proof("beta", proof)
    assert not s.verify_proof("beta", proof, bytes(32))
    # integrity over the whole store: zero violations
    assert s.verify_integrity()["violations"] == []
    # serialize/deserialize roundtrip preserves values and root
    blob = s.serialize()
    s2 = PCS.deserialize(blob)
    assert s2.get("beta") == [1, 2, 3]
    assert s2.root() == s.root()


def test_pcs_root_determinism_same_op_sequence():
    def build():
        s = PCS(node_id="det-node")
        for i in range(7):
            s.put(f"k{i}", {"i": i, "pad": "x" * (i % 5)})
        s.delete("k2")
        s.transaction([("put", "tx1", {"ok": True}),
                       ("put", "tx2", {"ok": False})])
        return s

    a, b = build(), build()
    assert a.root() == b.root()
    assert a.serialize() == b.serialize()


def test_fresh_store_root_anchor():
    from sentinel import pcs as _pcs
    assert PCS().root() == _pcs._EMPTY_ROOT
    assert _pcs._EMPTY_ROOT == blake3(b"sentinel-pcs-empty-v1")

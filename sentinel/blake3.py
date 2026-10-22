#!/usr/bin/env python3
"""SENTINEL Axis-3 — pure-Python BLAKE3 (hash mode, 32-byte output).

The key/digest primitive of the PCS layer (spec §3.1). Self-contained by
design: zero external dependencies, so the store cannot break on
environment rollbacks (a lesson this project has paid for eight times).

Implements the BLAKE3 specification faithfully for arbitrary input
lengths: the compression function (7 rounds, the message permutation,
the IV = the SHA-256 IV words), 1024-byte chunks / 64-byte blocks with
CHUNK_START/CHUNK_END flags, the binary-counter CV stack for chunk
merging, PARENT nodes over (left_cv ++ right_cv), and the ROOT flag on
the final node. Only the first 8 output words (32 bytes) are exposed —
the standard hash mode; no XOF, no keyed mode (the PCS uses plain
content-addressed keys).

Validation provenance (dev time, 2026-10-16): 0 mismatches against the
OFFICIAL blake3 PyPI package over 30 official-pattern vectors
(input[i] = i % 251 at lengths 0,1,2,3,4,63,64,65,127,128,129,255,256,
1023,1024,1025,2047,2048,2049,3072,4096,4097,5120,6144,8191,8192,8193,
10000,16384,100000 — covering every block/chunk/tree boundary) plus 200
seeded random inputs up to 20 KB. Those vectors are embedded as literals
in tests/test_axis3_pcs.py, so the committed suite re-proves the
implementation env-independently (the empty-input anchor is
af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262).
"""
import struct

__all__ = ["blake3"]

_IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
       0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
_CHUNK_START, _CHUNK_END, _PARENT, _ROOT = 1, 2, 4, 8
_PERM = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
_M32 = 0xFFFFFFFF
_CHUNK_LEN = 1024
_BLOCK_LEN = 64


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _M32


def _g(s, a, b, c, d, mx, my):
    s[a] = (s[a] + s[b] + mx) & _M32
    s[d] = _rotr(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _M32
    s[b] = _rotr(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + my) & _M32
    s[d] = _rotr(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & _M32
    s[b] = _rotr(s[b] ^ s[c], 7)


def _round(s, m):
    # columns
    _g(s, 0, 4, 8, 12, m[0], m[1])
    _g(s, 1, 5, 9, 13, m[2], m[3])
    _g(s, 2, 6, 10, 14, m[4], m[5])
    _g(s, 3, 7, 11, 15, m[6], m[7])
    # diagonals
    _g(s, 0, 5, 10, 15, m[8], m[9])
    _g(s, 1, 6, 11, 12, m[10], m[11])
    _g(s, 2, 7, 8, 13, m[12], m[13])
    _g(s, 3, 4, 9, 14, m[14], m[15])


def _compress(cv, block, counter, block_len, flags):
    """The BLAKE3 compression function. Returns the 16-word output state
    (words 0..7 = the chaining value; the full state = root XOF prefix)."""
    s = [cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
         _IV[0], _IV[1], _IV[2], _IV[3],
         counter & _M32, (counter >> 32) & _M32, block_len, flags]
    m = list(block)
    _round(s, m)
    for _ in range(6):
        m = [m[_PERM[i]] for i in range(16)]
        _round(s, m)
    for i in range(8):
        s[i] ^= s[i + 8]
        s[i + 8] = cv[i]
    return s


def _words(b):
    return list(struct.unpack("<16I", b))


def _bytes8(w8):
    return struct.pack("<8I", *w8)


def _chunk_cv(chunk, counter, root_last):
    """Process one chunk; return the final state's first 8 words.
    root_last=True adds ROOT to the final block (single-chunk inputs)."""
    cv = _IV
    nblocks = max(1, (len(chunk) + _BLOCK_LEN - 1) // _BLOCK_LEN)
    for i in range(nblocks):
        b = chunk[i * _BLOCK_LEN:(i + 1) * _BLOCK_LEN]
        blen = len(b)
        if blen < _BLOCK_LEN:
            b = b + b"\x00" * (_BLOCK_LEN - blen)
        flags = (_CHUNK_START if i == 0 else 0) | \
                (_CHUNK_END if i == nblocks - 1 else 0)
        if root_last and i == nblocks - 1:
            flags |= _ROOT
        state = _compress(cv, _words(b), counter, blen, flags)
        cv = state[:8]
    return cv


def _parent_cv(left, right, flags):
    return _compress(_IV, list(left) + list(right), 0, _BLOCK_LEN,
                     _PARENT | flags)[:8]


def blake3(data: bytes) -> bytes:
    """BLAKE3-256 of `data` (arbitrary length) -> 32 bytes."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"blake3 expects bytes, got {type(data).__name__}")
    data = bytes(data)
    if len(data) <= _CHUNK_LEN:
        return _bytes8(_chunk_cv(data, 0, True))
    chunks = [data[i:i + _CHUNK_LEN] for i in range(0, len(data), _CHUNK_LEN)]
    m = len(chunks)
    stack = []
    for idx in range(m - 1):
        cv = _chunk_cv(chunks[idx], idx, False)
        n = idx + 1
        while n % 2 == 0:
            cv = _parent_cv(stack.pop(), cv, 0)
            n //= 2
        stack.append(cv)
    cur = _chunk_cv(chunks[m - 1], m - 1, False)
    while stack:
        left = stack.pop()
        cur = _parent_cv(left, cur, _ROOT if not stack else 0)
    return _bytes8(cur)

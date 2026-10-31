#!/usr/bin/env python3
"""Burhan Axis-3 — BLAKE3 (hash mode, 32-byte output).

# ============================================================ 2026-10-30 swap
# VERSION MARKER 2026-10-30: the hand-rolled pure-Python implementation
# (_rotr/_g/_round/_compress, the message-permutation table, the
# binary-counter CV stack, PARENT/ROOT chunk merging) was REPLACED by the
# official `blake3` PyPI package — the Python bindings of the BLAKE3
# reference implementation (Rust). This is the reference implementation
# itself, not a second hand-rolled version. The module keeps its exact
# public surface: one function, blake3(data: bytes) -> 32 bytes, TypeError
# on non-bytes input (bytes/bytearray/memoryview all accepted as before).
#
# Output is byte-identical to the old implementation, proven two ways:
#   1. all 35 cases of the reference repo's official test_vectors.json
#      (input lengths 0..102400, every block/chunk/tree boundary) —
#      captured from the OLD implementation before deletion and matched
#      byte-for-byte by the library after the swap
#      (scripts/crypto_remediation/blake3_preswap_capture.json);
#   2. the same vectors, embedded as literals, run live in
#      tests/test_axis3_pcs.py together with the pcs.py consumers.
#
# DOCSTRING CORRECTION (same date): the previous docstring claimed the
# dev-time validation vectors were "embedded as literals in
# tests/test_axis3_pcs.py" — that file had never been committed to this
# repository (git log --all on the path is empty). The claim is now
# true: the real official vectors live at exactly that path.
#
# The old "zero external dependencies" property is intentionally
# dropped: the dependency is declared in requirements.txt
# (blake3==1.0.11). The empty-input anchor is unchanged:
# af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
# ============================================================
"""
import blake3 as _blake3_pkg   # the official PyPI package (reference
                               # implementation bindings) — NOT this module

__all__ = ["blake3"]


def blake3(data: bytes) -> bytes:
    """BLAKE3-256 of `data` (arbitrary length) -> 32 bytes (hash mode).

    Deterministic, collision- and preimage-resistant per the BLAKE3
    specification; computed by the official reference implementation.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"blake3 expects bytes, got {type(data).__name__}")
    return _blake3_pkg.blake3(bytes(data)).digest()

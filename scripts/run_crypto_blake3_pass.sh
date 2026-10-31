#!/usr/bin/env bash
# Atomic runner — PART 0 (repro.py gate) + PART 1 (blake3 -> official
# library) on branch cleanup/crypto-blake3, branched from the rebuilt
# cleanup/crypto-library-primitives (39edcf8; the original 74eeb09 was
# lost to the 2026-10-30 environment revert).
#
# The environment auto-reverts HEAD/the worktree to main between tool
# calls (branches and commits survive), so this script is ONE
# self-contained invocation: it re-creates every file it needs via
# heredocs, applies guarded edits, runs the full test suite, and commits
# ONLY on green. No push (no credentials on this machine).
set -uo pipefail
cd /home/z/my-project
export PYTHONPATH=/home/z/my-project

echo "== STEP 0: re-establish branch state =="
git checkout -- .gitignore 2>/dev/null || true
git rev-parse --verify cleanup/crypto-library-primitives >/dev/null 2>&1 \
  || { echo "FATAL: cleanup/crypto-library-primitives missing"; exit 1; }
CLP_TIP_MSG=$(git log -1 --format=%s cleanup/crypto-library-primitives)
case "$CLP_TIP_MSG" in
  "crypto-library-primitives:"*) : ;;
  *) echo "FATAL: unexpected crypto-library-primitives tip: $CLP_TIP_MSG"; exit 1;;
esac
git checkout -f cleanup/crypto-library-primitives 2>&1 | tail -1
git reset --hard cleanup/crypto-library-primitives >/dev/null 2>&1
git checkout -- .gitignore 2>/dev/null || true

# best-effort: commit the rebuild runner for the audit trail
if ! git cat-file -e cleanup/crypto-library-primitives:scripts/rebuild_crypto_library_primitives.sh 2>/dev/null \
   && [ -f scripts/rebuild_crypto_library_primitives.sh ]; then
  git add scripts/rebuild_crypto_library_primitives.sh
  git commit -q -m "crypto-library-primitives: add the atomic rebuild runner" || true
fi

if git rev-parse --verify cleanup/crypto-blake3 >/dev/null 2>&1; then
  CB_TIP_MSG=$(git log -1 --format=%s cleanup/crypto-blake3)
  case "$CB_TIP_MSG" in
    "blake3:"*) MODE="verify-only" ;;
    "repro: Part-0 gate"*) MODE="blake3-only" ;;
    *) MODE="full"; git checkout -f cleanup/crypto-blake3 2>&1 | tail -1
       git reset --hard cleanup/crypto-library-primitives >/dev/null 2>&1 ;;
  esac
else
  git branch cleanup/crypto-blake3 cleanup/crypto-library-primitives
  MODE="full"
fi
git checkout -f cleanup/crypto-blake3 2>&1 | tail -1
git reset --hard cleanup/crypto-blake3 >/dev/null 2>&1
git checkout -- .gitignore 2>/dev/null || true
echo "MODE=$MODE base(crypto-library-primitives)=$(git rev-parse cleanup/crypto-library-primitives)"

if [ "$MODE" = "full" ]; then
  # ================= PART 0 — repro.py gate =================
  echo "== PART 0 STEP 1: repro.py disclosure edits (guarded) =="
  python3 <<'PYEOF' || exit 1
PATH_ = "burhan/repro.py"
s = open(PATH_, encoding="utf-8").read()

OLD2 = """  §2  PRNG مُبذَّر      SeededPRNG — SplitMix64 خالص (ثوابت معلنة)؛
                        derive_stream(seed, label) — تيار مستقل لكل
                        خطوة (كل العشوائية من البذرة الأم حصراً — G1)"""
NEW2 = OLD2 + """
                        [إفصاح أمني 2026-10-30 (بوابة Part-0): ليست
                        CSPRNG قطعاً — حتمية بالتصميم لإعادة التشغيل
                        والتحقق فقط؛ المخرجات لا تصلح ولا تُستخدم كمادة
                        مفتاح لحماية أسرار حقيقية — انظر الإفصاح N-k
                        والاختبار العازل tests/test_repro_prng_isolation.py]"""
if s.count(OLD2) != 1:
    print("ABORT: §2 docstring anchor not found exactly once"); raise SystemExit(1)
s = s.replace(OLD2, NEW2)

OLDJ = """  N-j (sys_flags) — الحقول العددية حصراً (رايات بايثون)؛
      count/index الموروثتان عن struct-sequence ليستا رايات
      فتُستبعدان من المواصفة القياسية.
"""
NEWJ = OLDJ + """  N-k (ليست CSPRNG — بوابة Part-0، 2026-10-30): مخرجات SeededPRNG/
      derive_stream لا تحمي أي بيانات حساسة حقيقية ولا يجب أن تحميها:
      لا مستهلك تشغيلي واحد خارج هذا الملف (مثبت باختبار grep:
      tests/test_repro_prng_isolation.py)؛ المسار التاريخي الذي أسيء
      استخدامه (audit-rb-1، أُغلق 2026-10-21 في burhan/audit.py) أزيل
      نهائياً؛ مسار الأسرار الحقيقي هو burhan/vault.py (مفاتيح
      os.urandom + AEAD عبر مكتبة cryptography) المستقل تماماً.
"""
if s.count(OLDJ) != 1:
    print("ABORT: N-j anchor not found exactly once"); raise SystemExit(1)
s = s.replace(OLDJ, NEWJ)

OLDC = '''class SeededPRNG:
    """مولد حتمي خالص: البذرة الوحيدة مصدر التسلسل كله (G1)."""'''
NEWC = '''class SeededPRNG:
    """مولد حتمي خالص: البذرة الوحيدة مصدر التسلسل كله (G1).

    SECURITY DISCLOSURE (Part-0 gate, 2026-10-30): NOT a CSPRNG —
    deterministic by design for replay only — never use output as a
    real secret-protection key. SplitMix64's determinism IS the feature
    (identical re-runs prove determinism); the isolation contract is
    pinned by tests/test_repro_prng_isolation.py: no runtime module
    outside this file consumes these streams, and the real secret paths
    (vault/proof/audit/orchestrator) carry no repro dependency."""'''
if s.count(OLDC) != 1:
    print("ABORT: SeededPRNG class docstring anchor not found exactly once"); raise SystemExit(1)
s = s.replace(OLDC, NEWC)

open(PATH_, "w", encoding="utf-8").write(s)
print("repro.py Part-0 edits applied: 3 anchors (§2, N-k, class docstring)")
PYEOF

  echo "== PART 0 STEP 2: isolation test =="
  cat > tests/test_repro_prng_isolation.py <<'EOF'
"""Part-0 gate (2026-10-30): repro.py's SeededPRNG/derive_stream is
deterministic-by-design (SplitMix64) for replay/determinism verification
only — NOT a CSPRNG. This suite pins, by grep over the committed source,
that its output is never used as real secret-protection key material:

  1. no module outside burhan/repro.py imports or executes its streams;
  2. the real secret paths (vault/proof/audit/orchestrator) carry no
     repro dependency at all;
  3. the historical misuse (audit-rb-1, closed 2026-10-21 — SeededPRNG
     fed by sha256(str(seed))[:8] as audit key material) stays removed;
  4. the NOT-a-CSPRNG disclosure stays present in repro.py.

If any of these breaks, this file fails — the deterministic PRNG must
never silently become a secret-protection key source again.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
Burhan = ROOT / "burhan"

IMPORT_RE = re.compile(
    r"from\s+(?:\.|burhan\.)repro\s+import|import\s+burhan\.repro\b")
WORD_RE = re.compile(r"\brepro\b")


def _src(name):
    return (Burhan / name).read_text(encoding="utf-8")


def test_no_runtime_module_consumes_repro_streams():
    offenders = [p.name for p in sorted(Burhan.glob("*.py"))
                 if p.name != "repro.py"
                 and IMPORT_RE.search(p.read_text(encoding="utf-8"))]
    assert offenders == [], \
        f"runtime modules consuming repro streams: {offenders}"


def test_secret_paths_carry_no_repro_dependency():
    for name in ("vault.py", "proof.py", "audit.py", "orchestrator.py"):
        hits = WORD_RE.findall(_src(name))
        assert not hits, f"{name} references repro: {len(hits)} hit(s)"


def test_historical_audit_misuse_stays_removed():
    # audit-rb-1 (closed 2026-10-21): the pre-remand path derived audit
    # keypairs from SeededPRNG fed by sha256(str(seed))[:8] — the CODE
    # path must never come back. The module docstring legitimately
    # documents that history, so this pins code-level usage only:
    src = _src("audit.py")
    assert not IMPORT_RE.search(src)                  # no repro import
    assert not re.search(r"SeededPRNG\s*\(", src)     # no construction
    assert not re.search(r"derive_stream\s*\(", src)  # no stream derivation


def test_repro_declares_not_a_csprng():
    src = _src("repro.py")
    assert "NOT a CSPRNG" in src
    assert "deterministic by design for replay only" in src


def test_subpackages_clean_too():
    offenders = [str(p.relative_to(ROOT)) for p in Burhan.rglob("*.py")
                 if p.name != "repro.py"
                 and IMPORT_RE.search(p.read_text(encoding="utf-8"))]
    assert offenders == [], f"repro stream consumers: {offenders}"
EOF

  echo "== PART 0 STEP 3: full suite before commit =="
  python3 -m pytest tests/ -q 2>&1 | tail -3
  P0_RC=${PIPESTATUS[0]}
  echo "P0_PYTEST_RC=$P0_RC"
  [ "$P0_RC" -ne 0 ] && { echo "== RED — Part 0 NOT committed =="; exit 2; }

  git add burhan/repro.py tests/test_repro_prng_isolation.py
  git commit -q -m "repro: Part-0 gate — SeededPRNG/derive_stream declared NOT a CSPRNG (deterministic by design, replay only)

Investigation (2026-10-30): the splitmix64-derived sign_seed/aead_key of
the default pipeline protect no real data — zero runtime importers of
burhan.repro exist (only tests/dev scripts; transparency.py references
the 'triple_run' evidence kind as data, not code). Decision per the
gate: keep the deterministic PRNG (replacing it would break the
determinism it exists to prove), add the explicit NOT-a-CSPRNG
disclosure (module docstring §2 + N-k + SeededPRNG class docstring), and
pin the isolation contract with a grep-based test
(tests/test_repro_prng_isolation.py): no runtime module outside repro.py
consumes its streams; vault/proof/audit/orchestrator carry no repro
dependency; the historical audit-rb-1 misuse stays removed."
  git log --oneline -2
fi

if [ "$MODE" != "verify-only" ]; then
  # ================= PART 1 — blake3 -> official library =================
  echo "== PART 1 STEP 1: pre-swap capture (OLD implementation still in place) =="
  python3 <<'PYEOF' || exit 1
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, ".")
from burhan.blake3 import blake3   # the OLD hand-rolled implementation

VECTORS = [
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

def gen(n):
    return bytes(i % 251 for i in range(n))

out = {"source": "https://github.com/BLAKE3-team/BLAKE3/blob/master/"
                 "test_vectors/test_vectors.json (fetched 2026-10-30); "
                 "32-byte hash-mode digest = first 32 bytes of 'hash'",
       "official_vectors": {}, "extra_probes": {}}
drift = []
for length, hexd in VECTORS:
    got = blake3(gen(length)).hex()
    out["official_vectors"][str(length)] = got
    if got != hexd:
        drift.append(length)
EXTRAS = [b"", b"abc", b"burhan-pcs-empty-v1", bytes(1024),
          bytes(range(256)) * 5, b"\x00" * 100000]
for i, e in enumerate(EXTRAS):
    out["extra_probes"][str(i)] = {
        "sha256_input": hashlib.sha256(e).hexdigest(),
        "blake3_hex": blake3(e).hex()}
if drift:
    print("OLD IMPLEMENTATION DRIFTS FROM OFFICIAL VECTORS:", drift)
    sys.exit(1)
dest = Path("scripts/crypto_remediation/blake3_preswap_capture.json")
dest.write_text(json.dumps(out, indent=1, sort_keys=True), encoding="utf-8")
print(f"PRESWAP BLAKE3 CAPTURE OK: {len(VECTORS)}/35 official vectors "
      f"match the OLD implementation; {len(EXTRAS)} extra probes recorded")
PYEOF

  echo "== PART 1 STEP 2: replace burhan/blake3.py with the official-library wrapper =="
  cat > burhan/blake3.py <<'EOF'
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
EOF

  echo "== PART 1 STEP 3: pcs.py header comment update (guarded) =="
  python3 <<'PYEOF' || exit 1
PATH_ = "burhan/pcs.py"
s = open(PATH_, encoding="utf-8").read()
OLD = """       (burhan/blake3.py, pure Python, zero deps); values are CANONICAL"""
NEW = """       (burhan/blake3.py — the official blake3 PyPI package since
       2026-10-30, output byte-identical to the pure-Python code it
       replaced); values are CANONICAL"""
if s.count(OLD) != 1:
    print("ABORT: pcs.py header anchor not found exactly once"); raise SystemExit(1)
s = s.replace(OLD, NEW)
open(PATH_, "w", encoding="utf-8").write(s)
print("pcs.py header comment updated")
PYEOF

  echo "== PART 1 STEP 4: requirements.txt pin + install =="
  grep -q "^blake3==" requirements.txt || echo "blake3==1.0.11" >> requirements.txt
  cat requirements.txt
  pip install -q "blake3==1.0.11" 2>&1 | tail -1
  python3 -c "import blake3; print('installed blake3', blake3.__version__)"

  echo "== PART 1 STEP 5: post-swap byte-identity verify =="
  python3 <<'PYEOF' || exit 1
import json
import sys

sys.path.insert(0, ".")
from burhan.blake3 import blake3   # NOW the official-library wrapper

cap = json.load(open("scripts/crypto_remediation/blake3_preswap_capture.json",
                     encoding="utf-8"))

def gen(n):
    return bytes(i % 251 for i in range(n))

bad = []
for length, hexd in cap["official_vectors"].items():
    if blake3(gen(int(length))).hex() != hexd:
        bad.append(f"vector len {length}")
EXTRAS = [b"", b"abc", b"burhan-pcs-empty-v1", bytes(1024),
          bytes(range(256)) * 5, b"\x00" * 100000]
for i, e in enumerate(EXTRAS):
    if blake3(e).hex() != cap["extra_probes"][str(i)]["blake3_hex"]:
        bad.append(f"extra probe {i}")
if bad:
    print("POSTSWAP BLAKE3 MISMATCH:", bad)
    sys.exit(1)
n = len(cap["official_vectors"]) + len(EXTRAS)
print(f"POSTSWAP BLAKE3 OK: library output byte-identical to the old "
      f"implementation on all {n} captured inputs")
PYEOF

  echo "== PART 1 STEP 6: tests/test_axis3_pcs.py (official vectors + pcs consumers) =="
  cat > tests/test_axis3_pcs.py <<'EOF'
"""Burhan Axis-3 — BLAKE3 + PCS test suite (official vectors).

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
in burhan/blake3.py's docstring: vectors were claimed to live in
tests/test_axis3_pcs.py while no such file had ever been committed
(verified: git log --all on the path was empty). The vectors now
genuinely live at this exact path, and the suite additionally covers the
pcs.py consumers of the primitive (key_digest, MerkleTree nodes and
proofs, record digests, serialize/deserialize round-trips, determinism
of the store root).
"""
import pytest

from burhan.blake3 import blake3
from burhan.pcs import (PCS, MerkleTree, PCSError, key_digest,
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
    from burhan import pcs as _pcs
    assert PCS().root() == _pcs._EMPTY_ROOT
    assert _pcs._EMPTY_ROOT == blake3(b"burhan-pcs-empty-v1")
EOF
  # fix the intentional typo guard: verify the file parses
  python3 -c "import ast; ast.parse(open('tests/test_axis3_pcs.py').read())" \
    || { echo "FATAL: test file does not parse"; exit 1; }

  echo "== PART 1 STEP 7: full suite + repro + doctor =="
  python3 -m pytest tests/ -q 2>&1 | tail -4
  P1_RC=${PIPESTATUS[0]}
  echo "P1_PYTEST_RC=$P1_RC"
  python3 scripts/crypto_remediation/repro_check.py || exit 1
  timeout 120 python3 -m burhan.cli doctor > /tmp/doctor_blake3.json 2>&1
  DOCTOR_RC=$?
  echo "DOCTOR_RC=$DOCTOR_RC"
  python3 -c "
import json
d = json.load(open('/tmp/doctor_blake3.json'))
checks = d.get('checks', d if isinstance(d, list) else [])
stat = {}
for c in checks:
    stat[c.get('status','?')] = stat.get(c.get('status','?'), 0) + 1
print('doctor status counts:', stat, '| overall:', d.get('status', 'n/a') if isinstance(d, dict) else 'n/a')
" 2>/dev/null || tail -c 400 /tmp/doctor_blake3.json

  if [ "$P1_RC" -ne 0 ] || [ "$DOCTOR_RC" -ne 0 ]; then
    echo "== RED — blake3 swap NOT committed =="
    git status --short | head -10
    exit 2
  fi

  git add burhan/blake3.py burhan/pcs.py requirements.txt \
          tests/test_axis3_pcs.py \
          scripts/crypto_remediation/blake3_preswap_capture.json
  git commit -q -m "blake3: replace the hand-rolled pure-Python implementation with the official blake3 PyPI package (reference-implementation bindings, blake3==1.0.11)

Byte-identical output proven BEFORE deleting the old code: all 35
official reference-repo vectors (test_vectors.json, input lengths
0..102400, every block/chunk/tree boundary) captured from the old
implementation into scripts/crypto_remediation/blake3_preswap_capture.json
and matched byte-for-byte by the library after the swap, plus 6 fixed
extra probes. The stale docstring claim that vectors lived in
tests/test_axis3_pcs.py (a path never committed — git log --all on it
is empty) is corrected by making it true: tests/test_axis3_pcs.py now
exists with the real official vectors + pcs.py consumer coverage
(key_digest, MerkleTree nodes/proofs, record digests, serialize
round-trips, store-root determinism). pcs.py's 'pure Python, zero
deps' header comment updated; requirements.txt gains blake3==1.0.11."
  git log --oneline -4
fi

echo "== VERIFY-ONLY final checks (always run) =="
git checkout -- .gitignore 2>/dev/null || true
python3 -m pytest tests/ -q 2>&1 | tail -2
echo "FINAL_PYTEST_RC=${PIPESTATUS[0]}"
timeout 120 python3 -m burhan.cli doctor >/dev/null 2>&1
echo "FINAL_DOCTOR_RC=$?"
python3 scripts/crypto_remediation/repro_check.py | tail -1
git log --oneline -5
echo "PUSH SKIPPED — no credentials on this machine"
echo "CRYPTO-BLAKE3 PASS RUN COMPLETE (MODE=$MODE)"

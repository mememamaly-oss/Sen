"""SENTINEL v4.4.1 — Axis 14: the independently-auditable report layer.

The competitive claim the supervisor ordered (docs/SPEC_AXES_13_16.md §14,
banked verbatim): the report carries a Merkle root + an Ed25519 public key,
so ANY external auditor verifies EVERY result with OPEN tools and NO access
to the code — a property neither Burp Suite nor OWASP ZAP carries.

Built ON the committed closed axes, never reimplementing them:
  - the Ed25519 RFC 8032 primitives and the §8.2 Merkle convention
    (Leaf=SHA-256(data), Node=SHA-256(L||R), dup-last-on-odd) come from
    axis-8's sentinel/proof.py, closed through its five-station gates;
  - the deterministic keypair derivation comes from axis-11's
    SeededPRNG (derive_stream), closed through its five-station gates.

Design rules (all pinned by the axis-14 wing):
  1. ADDITIVE ONLY — enrich_report adds one "audit" section; it changes no
     finding, adds no request, touches no stats.
  2. VOLATILE FIELDS NEVER ENTER THE ROOT — the declared volatile set
     (notes + wall times + measured constraints) is stripped RECURSIVELY at
     every depth, so timing-bearing verification notes can never move the
     root: one seed -> the same root, always.
  3. THE ROOT DEPENDS ONLY ON THE FINDINGS; THE KEYPAIR ONLY ON THE SEED —
     a different seed keeps the root and changes the signature (pinned).
  4. THE EMPTY SET is the declared constant sha256(b"") — never passed to
     the axis-8 primitive (which rejects empty lists by its own contract).
  5. THE SIGNED MESSAGE is the SHA-256 digest of
     run_id \\x00 merkle_root \\x00 findings_count \\x00 header_canonical
     (the separator makes field-content collisions impossible); the
     Ed25519 signature covers the 32-byte digest.
  6. A RANDOM SEED (no seed passed) makes no reproducibility claim — the
     signature stays honest for that run alone; the scanner always passes
     its effective seed string.
  7. THE RECIPE IS THE PRODUCT — the literal verification commands are
     embedded in every enriched report (audit.recipe) and in
     docs/AUDIT_VERIFICATION.md.
"""
from __future__ import annotations

import base64
import hashlib
import json

from .proof import (ValidationError as _VE, ed25519_public_key,
                     ed25519_sign, merkle_root)
from .repro import derive_stream

__all__ = [
    "EMPTY_ROOT_HEX", "ALGORITHM", "LEAF_SPEC", "SIGNATURE_SCHEME",
    "SIGNED_MESSAGE_SPEC", "RECIPE_DOC", "AUDIT_RECIPE", "VOLATILE_KEYS",
    "canonical_finding", "finding_leaf", "merkle_root_of_records",
    "header_canonical", "signed_message", "derive_keypair",
    "audit_block", "enrich_report",
]

# ---- the declared constants (spec §14.1/§14.2, literal) --------------------
EMPTY_ROOT_HEX = ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca"
                  "495991b7852b855")            # sha256(b"") — the empty-set root
ALGORITHM = "sha256-merkle-dup-last-on-odd"
LEAF_SPEC = "canonical-json-sorted-compact-utf8-volatile-excluded"
SIGNATURE_SCHEME = "Ed25519-RFC8032-pure-stdlib"
SIGNED_MESSAGE_SPEC = (
    "sha256(run_id \\x00 merkle_root \\x00 findings_count \\x00 "
    "header_canonical) — the 32-byte digest; the Ed25519 signature "
    "covers the digest")
RECIPE_DOC = "AUDIT_VERIFICATION.md"

# المجموعة الطائرة المعلنة (N3): أي مفتاح منها يُحذف عودياً في كل عمق —
# ملاحظات التحقق قد تحمل أرقاماً مقاسة؛ أزمنة الحائط والإحصاءات طائرة
# بالطبيعة. لا شيء منها يدخل الجذر أبداً.
VOLATILE_KEYS = frozenset({
    "notes", "duration", "duration_s", "wall_time", "wall", "elapsed",
    "timestamp", "dur_s", "latency", "latency_ms", "time_ms", "time",
    "generated_at", "date", "stats", "requests", "started_at",
    "finished_at", "verified_at",
})

AUDIT_RECIPE = (
    "INDEPENDENT VERIFICATION RECIPE (open tools only, no code access):\n"
    "1) For each verified finding record in report.findings, compute "
    "leaf_i = sha256(canonical(record)) where canonical = JSON with "
    "SORTED keys, separators (',', ':'), UTF-8, and the declared volatile "
    "keys (notes, durations, wall times, stats, requests...) removed "
    "recursively at every depth.\n"
    "2) Build the Merkle tree: pair leaves bottom-up, node = "
    "sha256(left || right); when a level has an ODD count, duplicate its "
    "last hash once. The empty findings set has the root "
    "sha256(b'') = e3b0c44298fc1c14...55. The result must equal "
    "report.audit.merkle_root.\n"
    "3) Compute the signed message digest: sha256 of the four fields "
    "joined by a single 0x00 byte each: run_id, merkle_root, "
    "findings_count, then the canonical header JSON "
    "{'run_id','seed','scanner','target'} (sorted keys, compact).\n"
    "4) Verify the Ed25519 signature (RFC 8032) of that digest with the "
    "embedded public key (report.audit.public_key_b64, 32 raw bytes): "
    "python cryptography: Ed25519PublicKey.from_public_bytes("
    "base64.b64decode(public_key_b64)).verify(base64.b64decode("
    "signature_b64), digest); openssl: build the SPKI PEM "
    "302a300506032b6570032100||pubkey and run "
    "openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in msg.bin "
    "-sig sig.bin. Any mismatch in (2) or (4) means the report was "
    "altered after signing — tampering is DETECTED, not trusted."
)


# ---- §1 the canonical form ---------------------------------------------------
def _strip_volatile(obj):
    """حذف المجموعة الطائرة عودياً في كل عمق (N3) — القاعدة المعلنة."""
    if isinstance(obj, dict):
        return {k: _strip_volatile(v) for k, v in obj.items()
                if k not in VOLATILE_KEYS}
    if isinstance(obj, (list, tuple)):
        return [_strip_volatile(x) for x in obj]
    return obj


def canonical_finding(rec: dict) -> str:
    """الـcanonical لحقل واحد: JSON مرتب المفاتيح، فواصل ,/:، UTF-8،
    والمجموعة الطائرة محذوفة عودياً."""
    return json.dumps(_strip_volatile(rec), sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False)


def finding_leaf(rec: dict) -> bytes:
    """الورقة = sha256(canonical) — نفس قاعدة §8.2 (Leaf=SHA-256(data))."""
    return hashlib.sha256(canonical_finding(rec).encode("utf-8")).digest()


def merkle_root_of_records(records) -> str:
    """الجذر فوق سجلات النتائج بترتيبها؛ الفارغة = الثابت المعلن (N4 —
    لا تُمرَّر قائمة فارغة إلى بدائية المحور-8 التي ترفضها بعقدها)."""
    records = list(records or [])
    if not records:
        return EMPTY_ROOT_HEX
    return merkle_root(
        [canonical_finding(r).encode("utf-8") for r in records]).hex()


# ---- §2 the header and the signed message ------------------------------------
def header_canonical(report: dict) -> str:
    """رأس التقرير الـcanonical: الهوية الأربعة حصراً (الإحصاءات طائرة
    بطبيعتها — خارج التوقيت)."""
    hdr = {"run_id": str(report.get("run_id", "")),
           "seed": str(report.get("seed", "")),
           "scanner": str(report.get("scanner", "")),
           "target": str(report.get("target", ""))}
    return json.dumps(hdr, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def signed_message(run_id: str, root_hex: str, count: int,
                   report: dict) -> bytes:
    """هضم الرسالة الموقَّعة (N6): الحقول بفاصل 0x00. المحصّن (M3 قبل
    البطاريات — يُعلن): أي حقل يحوي 0x00 يُرفض ذرياً — وإلا لتمكن تراكب
    الترميز (x\x00y|z ≡ x|y\x00z) من إنتاج نفس الهضم لقيم مختلفة."""
    parts = [str(run_id), str(root_hex), str(int(count)),
             header_canonical(report)]
    for f in parts:
        if "\x00" in f:
            raise _VE(
                "signed_message: NUL byte in a field — the \\x00 "
                "joined encoding would be ambiguous")
    return hashlib.sha256(b"\x00".join(p.encode("utf-8") for p in parts)).digest()


# ---- §3 the deterministic keypair (spec §14.2) --------------------------------
def derive_keypair(seed):
    """نفس البذرة → نفس الزوج بالبايت (N7: بلا بذرة لا ادعاء تكرار —
    التوقيع صادق لتلك التشغيلة وحدها)."""
    seed_key = str(seed) if seed is not None else "unseeded"
    n = int.from_bytes(
        hashlib.sha256(seed_key.encode("utf-8")).digest()[:8], "big")
    if n == 0:            # الحدث النظري 2^-64 — مُعلن
        n = 1
    priv = derive_stream(n, "axis14-ed25519-keypair").next_bytes(32)
    return priv, ed25519_public_key(priv)


# ---- §4 the audit block -------------------------------------------------------
def audit_block(report: dict, seed=None) -> dict:
    """قسم التدقيق الكامل — إضافة فقط؛ لا يغير شيئاً في التقرير."""
    raw = report.get("findings")
    # fail-closed (المحصّن في M3 قبل البطاريات — يُعلن): السجلات قائمة
    # حصراً؛ أي شكل آخر (dict/tuple/None) = مجموعة فارغة صادقة — لا
    # مفاتيح dict تتحول أوراقاً بلا إعلان.
    findings = list(raw) if isinstance(raw, list) else []
    root = merkle_root_of_records(findings)
    effective_seed = seed if seed is not None else report.get("seed")
    priv, pub = derive_keypair(effective_seed)
    msg = signed_message(report.get("run_id", ""), root, len(findings), report)
    sig = ed25519_sign(priv, msg)
    return {
        "merkle_root": root,
        "findings_count": len(findings),
        "algorithm": ALGORITHM,
        "leaf_spec": LEAF_SPEC,
        "signature_scheme": SIGNATURE_SCHEME,
        "signed_message_spec": SIGNED_MESSAGE_SPEC,
        "public_key_b64": base64.b64encode(pub).decode("ascii"),
        "signature_b64": base64.b64encode(sig).decode("ascii"),
        "recipe": AUDIT_RECIPE,
    }


def enrich_report(report: dict, seed=None, run_id=None) -> dict:
    """يضيف قسم audit وحده (N1: إضافة فقط — لا نتائج تُغير ولا طلبات
    تُضاف ولا إحصاءات تُمس)."""
    if run_id is not None and not report.get("run_id"):
        report = dict(report)
        report["run_id"] = run_id
    report["audit"] = audit_block(
        report, seed=seed if seed is not None else report.get("seed"))
    return report

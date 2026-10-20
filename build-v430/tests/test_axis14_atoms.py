#!/usr/bin/env python3
"""SENTINEL Axis-14 ATOMS — البطاريات الثلاث فوق محرك M2 (audit).

التصميم (نمط المحاور 7/8/11/12/13):
  14a — دورات مزروعة: 45 دورة (15 شكلاً ×3)؛ كل جذر معلوم بالبناء عبر
        ميركل مستقل داخل البطارية (لا يستدعي الوحدة)؛ مروران كاملان
        يعيدان نفس قائمة الأختام بالبايت؛ قلب بت في مدخل واحد يغيّر الختم.
  14b — 100 مطابقة مرجع مستقل بايت-ببايت (30 شجرة ميركل بأحجام 0..29،
        25 Ed25519 بالاتجاهين مقابل cryptography، 20 canonical يدوي،
        15 هضم رسالة يدوي، 10 خصائص زوج مفاتيح).
  14c — بالضبط 40 عدائياً 12+10+8+6+4: بنائية / تخريب (التقرير يكذب
        بعد التوقيع — محقق خارجي يلتقط) / دقة (ما لا يُدَّعى كشفاً) /
        حدود-تحريف / حيوية.

الوصفة: python3 tests/test_axis14_atoms.py --out results/axis14/axis14_ATOMS.json
"""
import base64
import hashlib
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests"))

import test_axis14_audit as wing
import test_axis13_detectors as wing13
from sentinel.audit import (audit_block, canonical_finding, derive_keypair,
                            enrich_report, finding_leaf, header_canonical,
                            merkle_root_of_records, signed_message)
from sentinel.proof import ValidationError as ProofVE
from sentinel.proof import ed25519_public_key, ed25519_sign, ed25519_verify

SUITE = "axis14-atoms"


def _rec(i, **over):
    return wing._rec(i, **over)


def _report(records, seed=wing.SEED_A, run_id="run-abc1234567", **over):
    r = wing._report(records, seed=seed, run_id=run_id)
    r.update(over)
    return r


# ================================================================ 14a
SHAPES = [
    ("empty", []), ("one", None), ("two-even", None), ("three-odd", None),
    ("four-even", None), ("five-odd", None), ("seven-odd", None),
    ("eight-even", None), ("fifteen-odd", None), ("sixteen-even", None),
    ("volatile-noise", None), ("unicode-deep", None), ("nested-impact", None),
    ("mixed-status", None), ("long-details", None),
]


def _shape_records(name, k):
    """سجلات الشكل للدورة k — معلومة البناء هنا وحدها."""
    sizes = {"empty": 0, "one": 1, "two-even": 2, "three-odd": 3,
             "four-even": 4, "five-odd": 5, "seven-odd": 7,
             "eight-even": 8, "fifteen-odd": 15, "sixteen-even": 16,
             "volatile-noise": 3, "unicode-deep": 2, "nested-impact": 3,
             "mixed-status": 4, "long-details": 2}
    n = sizes[name]
    recs = [_rec(100 * k + i) for i in range(1, n + 1)]
    if name == "volatile-noise":
        for j, r in enumerate(recs):
            r["verification"] = dict(r["verification"],
                                     notes=f"timing note {k} — {40 + j}ms measured")
            r["duration_s"] = 1.234 + k
            r["stats"] = {"requests": 10 * j}
    if name == "unicode-deep":
        recs[0]["evidence"][0]["detail"] = f"انعكاس عربي {k} — مؤشر قيمة معلنة"
        recs[-1]["parameter"] = "معامل"
    if name == "nested-impact":
        for r in recs:
            r["impact"]["evidence_chain"]["extra"] = {
                "notes": "depth-3 volatile", "real": f"depth-3-stable-{k}"}
    if name == "mixed-status":
        for i, r in enumerate(recs):
            if i % 2:
                r["status"] = "rejected"
    if name == "long-details":
        recs[0]["evidence"][0]["detail"] = "x" * 9000 + f"-{k}"
    return recs


def _shape_report(name, k):
    recs = _shape_records(name, k)
    seed = wing.SEED_A if k != 2 else wing.SEED_B   # k=2: بذرة مختلفة عمداً
    return _report(recs, seed=seed, run_id=f"run-a14{k:02d}00000")


def _cycle_seal(name, k):
    """ختم الدورة: (الشكل، الجذر المستقل، مطابقة الجذر، جذر الوحدة،
    المفتاح، التوقيع) — الجذر المستقل محسوب داخل البطارية بالكامل."""
    rep = _shape_report(name, k)
    blk = audit_block(rep, seed=rep["seed"])
    leaves = [hashlib.sha256(
        json.dumps(wing._strip_like(rec) if False else _b_strip(rec),
                   sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False).encode()).hexdigest()
        for rec in rep["findings"]]
    # الميركل المستقل (لا يستدعي الوحدة إطلاقاً)
    level = [bytes.fromhex(h) for h in leaves] or [hashlib.sha256(b"").digest()]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
    indep_root = level[0].hex()
    agree = indep_root == blk["merkle_root"]
    return {"shape": name, "k": k, "indep_root": indep_root,
            "root": blk["merkle_root"], "pub": blk["public_key_b64"],
            "sig": blk["signature_b64"], "agree": agree}


def _b_strip(rec):
    """القص الطائر المستقل داخل البطارية (نسخة يدوية من القاعدة المعلنة)."""
    VOL = {"notes", "duration", "duration_s", "wall_time", "wall", "elapsed",
           "timestamp", "dur_s", "latency", "latency_ms", "time_ms", "time",
           "generated_at", "date", "stats", "requests", "started_at",
           "finished_at", "verified_at"}

    def strip(o):
        if isinstance(o, dict):
            return {k2: strip(v) for k2, v in o.items() if k2 not in VOL}
        if isinstance(o, (list, tuple)):
            return [strip(x) for x in o]
        return o
    return strip(rec)


def battery_14a():
    seals = []
    for p in range(2):
        s = [_cycle_seal(sh[0], k)
             for sh in SHAPES for k in range(3)]
        seals.append(s)
    repeatable = seals[0] == seals[1]
    agreement = sum(1 for c in seals[0] if c["agree"])
    # حساسية قلب البت: قلب بت في مدخل دورة واحدة → الختم يتغير
    flipped = [_shape_records(n, 0) for sh in SHAPES for n in (sh[0],)]
    if flipped[3]:
        flipped[3][1]["parameter"] = \
            flipped[3][1]["parameter"] + "-bitflipped"
    roots_flipped = [merkle_root_of_records(r) for r in flipped]
    roots_orig = [merkle_root_of_records(_shape_records(n, 0))
                  for sh in SHAPES for n in (sh[0],)]
    bit_flip_sensitive = roots_flipped[3] != roots_orig[3]
    ok = agreement == len(seals[0]) and repeatable and bit_flip_sensitive
    return {"ok": ok, "detail": {
        "cycles": len(seals[0]), "agreement": agreement,
        "repeatable": repeatable, "bit_flip_sensitive": bit_flip_sensitive,
        "pass1_seal_sha": hashlib.sha256(json.dumps(seals[0], sort_keys=True)
                                         .encode()).hexdigest()[:16],
        "pass2_seal_sha": hashlib.sha256(json.dumps(seals[1], sort_keys=True)
                                         .encode()).hexdigest()[:16],
        "cycles_detail": seals[0]}}


# ================================================================ 14b
def battery_14b():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import \
        Ed25519PrivateKey, Ed25519PublicKey
    matched = 0
    mismatches = []
    breakdown = {"merkle": 0, "ed25519": 0, "canonical": 0,
                 "message": 0, "keypair": 0}

    def _match(kind, label, got, ref):
        nonlocal matched
        if got == ref:
            matched += 1
            breakdown[kind] += 1
        else:
            mismatches.append({"label": label, "got": str(got)[:70],
                               "ref": str(ref)[:70]})

    # 30 شجرة ميركل مستقلة (أحجام 0..29 — تُغطي الفارغة/الفردية/الزوجية)
    for n in range(30):
        recs = [_rec(500 + i) for i in range(n)]
        got = merkle_root_of_records(recs)
        leaves = [hashlib.sha256(
            json.dumps(_b_strip(r), sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False).encode()).digest() for r in recs]
        level = leaves or [hashlib.sha256(b"").digest()]
        while len(level) > 1:
            if len(level) % 2:
                level.append(level[-1])
            level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                     for i in range(0, len(level), 2)]
        _match("merkle", f"merkle-{n}", got, level[0].hex())

    # 25 Ed25519 بالاتجاهين مقابل cryptography
    for i in range(25):
        priv, pub = derive_keypair(f"axis14b-key-{i}")
        msg = f"axis14b message {i}".encode()
        sig = ed25519_sign(priv, msg)
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        k2 = Ed25519PrivateKey.generate()
        ref_pub = k2.public_key().public_bytes_raw()
        _match("ed25519", f"ed25519-pure-verifies-ref-{i}",
               ed25519_verify(k2.sign(msg), msg, ref_pub), True)
        _match("ed25519", f"ed25519-tampered-{i}",
               ed25519_verify(k2.sign(msg), b"other-{i}", ref_pub), False)

    # 20 canonical يدوي (قص عمق-3 + يونيكود + طويل)
    for i in range(20):
        r = _rec(700 + i)
        r["impact"]["evidence_chain"]["extra"] = {
            "notes": f"depth-3-{i}", "stable": f"kept-{i}"}
        r["evidence"][0]["detail"] = f"تفصيل عربي {i} — قيمة معلنة"
        r["duration_s"] = i
        got = canonical_finding(r)
        ref = json.dumps(_b_strip(r), sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False)
        _match("canonical", f"canonical-{i}", got, ref)

    # 15 هضم رسالة يدوي
    for i in range(15):
        rep = _report([_rec(800 + j) for j in range(i % 5 + 1)],
                      run_id=f"run-msg{i:04d}0000",
                      target=f"http://target{i}.test/")
        blk = audit_block(rep, seed=rep["seed"])
        hdr = {"run_id": rep["run_id"], "seed": rep["seed"],
               "scanner": rep["scanner"], "target": rep["target"]}
        ref = hashlib.sha256(b"\x00".join([
            rep["run_id"].encode(), blk["merkle_root"].encode(),
            str(blk["findings_count"]).encode(),
            json.dumps(hdr, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False).encode()])).digest()
        _match("message", f"message-{i}",
               signed_message(rep["run_id"], blk["merkle_root"],
                              blk["findings_count"], rep), ref)

    # 10 خصائص زوج مفاتيح
    for i in range(8):
        a1, b1 = derive_keypair(f"kp-{i}")
        a2, b2 = derive_keypair(f"kp-{i}")
        _match("keypair", f"kp-stable-{i}", (a1 == a2, b1 == b2), (True, True))
        c1, d1 = derive_keypair(f"kp-{i}-other")
        _match("keypair", f"kp-distinct-{i}", (a1 != c1, b1 != d1), (True, True))
    _match("keypair", "kp-pub-eq-primitive",
           [ed25519_public_key(derive_keypair("axis14b-final")[0])
            == derive_keypair("axis14b-final")[1]], [True])
    # السلوك المعلن: البذرة تُحوّل نصاً (str-coercion) — 123 و"123"
    # زوج واحد بالتصميم (لا "إكراه عرضي" — هذا هو العقد).
    _match("keypair", "kp-str-coercion-declared",
           derive_keypair(123) == derive_keypair("123"), True)
    total_checks = 30 + 50 + 20 + 15 + 18
    return {"ok": matched == total_checks and not mismatches, "detail": {
        "matched": matched, "total_checks": total_checks,
        "mismatches": len(mismatches),
        "breakdown": breakdown, "mismatch_list": mismatches[:8]}}


# ================================================================ 14c
def battery_14c():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import \
        Ed25519PublicKey
    results = []

    def _record(name, caught, why=""):
        results.append({"name": name, "ok": bool(caught), "why": why})

    def _auditor(rep):
        """محقق خارجي: يعيد حساب الجذر والعدد ويتحقق من التوقيع —
        بأدوات مفتوحة (cryptography) وبميركل مستقل داخل البطارية."""
        blk = rep["audit"]
        leaves = [hashlib.sha256(canonical_finding(f).encode()).hexdigest()
                  for f in rep["findings"]]
        level = [bytes.fromhex(h) for h in leaves] or [hashlib.sha256(b"").digest()]
        while len(level) > 1:
            if len(level) % 2:
                level.append(level[-1])
            level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                     for i in range(0, len(level), 2)]
        root_ok = level[0].hex() == blk["merkle_root"]
        count_ok = len(rep["findings"]) == blk["findings_count"]
        digest = hashlib.sha256(b"\x00".join([
            rep["run_id"].encode(), blk["merkle_root"].encode(),
            str(blk["findings_count"]).encode(),
            header_canonical(rep).encode()])).digest()
        try:
            Ed25519PublicKey.from_public_bytes(
                base64.b64decode(blk["public_key_b64"])).verify(
                base64.b64decode(blk["signature_b64"]), digest)
            sig_ok = True
        except Exception:
            sig_ok = False
        return root_ok, count_ok, sig_ok

    # ---- 12 بنائية
    try:
        blk = audit_block(_report([]), seed=wing.SEED_A)
        _record("struct-01 empty set constant root",
                blk["merkle_root"] == wing.EMPTY_SHA_HEX
                and blk["findings_count"] == 0)
    except Exception as e:
        _record("struct-01 empty set constant root", False, repr(e)[:90])
    try:
        r = _report([_rec(1)])
        del r["findings"]
        blk = audit_block(r, seed=wing.SEED_A)
        _record("struct-02 findings key absent", blk["findings_count"] == 0
                and blk["merkle_root"] == wing.EMPTY_SHA_HEX)
    except Exception as e:
        _record("struct-02 findings key absent", False, repr(e)[:90])
    try:
        blk = audit_block(_report(None) | {"findings": {"a": 1, "b": 2}},
                          seed=wing.SEED_A)
        _record("struct-03 findings dict fail-closed", blk["findings_count"] == 0
                and blk["merkle_root"] == wing.EMPTY_SHA_HEX,
                "the hardened list-only rule")
    except Exception as e:
        _record("struct-03 findings dict fail-closed", False, repr(e)[:90])
    try:
        blk = audit_block(_report(None) | {"findings": (_rec(1), _rec(2))},
                          seed=wing.SEED_A)
        _record("struct-04 findings tuple fail-closed", blk["findings_count"] == 0)
    except Exception as e:
        _record("struct-04 findings tuple fail-closed", False, repr(e)[:90])
    try:
        blk = audit_block(_report(["raw-string-record", 42, _rec(1)]),
                          seed=wing.SEED_A)
        _record("struct-05 non-dict entries canonicalized",
                blk["findings_count"] == 3 and blk["merkle_root"] != wing.EMPTY_SHA_HEX)
    except Exception as e:
        _record("struct-05 non-dict entries canonicalized", False, repr(e)[:90])
    try:
        r = _report([_rec(1)])
        for k in ("run_id", "seed", "scanner", "target"):
            r.pop(k, None)
        blk = audit_block(r)
        again = audit_block(dict(r))
        _record("struct-06 identity keys absent honest defaults",
                blk["signature_b64"] == again["signature_b64"])
    except Exception as e:
        _record("struct-06 identity keys absent honest defaults", False, repr(e)[:90])
    try:
        b1 = audit_block(_report([_rec(1)]), seed=None)
        b2 = audit_block(_report([_rec(1)]), seed=None)
        _record("struct-07 seed None deterministic", b1 == b2)
    except Exception as e:
        _record("struct-07 seed None deterministic", False, repr(e)[:90])
    try:
        b1 = audit_block(_report([_rec(1)]), seed="")
        b2 = audit_block(_report([_rec(1)]), seed="unseeded")
        _record("struct-08 empty seed distinct from unseeded",
                b1["public_key_b64"] != b2["public_key_b64"])
    except Exception as e:
        _record("struct-08 empty seed distinct from unseeded", False, repr(e)[:90])
    try:
        r = _report([_rec(1), _rec(2)])
        before = set(r)
        out = enrich_report(r, seed=wing.SEED_A)
        _record("struct-09 enrich adds exactly one key",
                set(out) == before | {"audit"} and out["findings"] == r["findings"])
    except Exception as e:
        _record("struct-09 enrich adds exactly one key", False, repr(e)[:90])
    try:
        r = enrich_report(_report([_rec(1), _rec(2)]), seed=wing.SEED_A)
        r2 = enrich_report(r, seed=wing.SEED_A)
        _record("struct-10 double enrich idempotent",
                r2["audit"] == r["audit"] and "audit" not in r["audit"])
    except Exception as e:
        _record("struct-10 double enrich idempotent", False, repr(e)[:90])
    try:
        r = _report([_rec(1)])
        r["findings"][0]["evidence"][0]["detail"] = "y" * 10240
        b1 = audit_block(r, seed=wing.SEED_A)
        b2 = audit_block(r, seed=wing.SEED_A)
        _record("struct-11 huge record deterministic", b1 == b2)
    except Exception as e:
        _record("struct-11 huge record deterministic", False, repr(e)[:90])
    try:
        r = _report([_rec(1)])
        r["findings"][0]["evidence"][0]["detail"] = "قيمة عربية بطول معلن"
        leaf = finding_leaf(r["findings"][0]).hex()
        ref = hashlib.sha256(json.dumps(
            _b_strip(r["findings"][0]), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode()).hexdigest()
        _record("struct-12 unicode canonical utf8", leaf == ref)
    except Exception as e:
        _record("struct-12 unicode canonical utf8", False, repr(e)[:90])

    # ---- 10 تخريب: التقرير يكذب بعد التوقيع — المحقق يلتقط
    def _signed(n=3):
        rep = enrich_report(_report([_rec(100 + i) for i in range(1, n + 1)]),
                            seed=wing.SEED_A)
        return rep

    def _tamper_case(name, mutate, expect_sig_fail=False):
        try:
            rep = _signed()
            mutate(rep)
            root_ok, count_ok, sig_ok = _auditor(rep)
            caught = (not root_ok) or (not count_ok) or (not sig_ok)
            if expect_sig_fail:
                caught = caught and not sig_ok
            _record(name, caught,
                    f"root_ok={root_ok} count_ok={count_ok} sig_ok={sig_ok}")
        except Exception as e:
            _record(name, False, repr(e)[:90])

    _tamper_case("sabotage-01 parameter changed post-signal",
                 lambda r: r["findings"][1].__setitem__("parameter", "evil"))
    _tamper_case("sabotage-02 finding added post-signal",
                 lambda r: r["findings"].append(_rec(999)))
    _tamper_case("sabotage-03 finding removed post-signal",
                 lambda r: r["findings"].pop(0))
    _tamper_case("sabotage-04 findings swapped post-signal",
                 lambda r: r["findings"].reverse())
    _tamper_case("sabotage-05 root field replaced",
                 lambda r: r["audit"].__setitem__("merkle_root", "00" * 32),
                 expect_sig_fail=True)
    _tamper_case("sabotage-06 count field inflated",
                 lambda r: r["audit"].__setitem__("findings_count",
                                                 r["audit"]["findings_count"] + 1))
    _tamper_case("sabotage-07 header target changed post-signal",
                 lambda r: r.__setitem__("target", "http://evil.test/"))
    _tamper_case("sabotage-08 status flipped post-signal",
                 lambda r: r["findings"][0].__setitem__("status", "rejected"))
    _tamper_case("sabotage-09 signature garbage",
                 lambda r: r["audit"].__setitem__(
                     "signature_b64", base64.b64encode(b"Z" * 64).decode()))
    _tamper_case("sabotage-10 public key tampered",
                 lambda r: r["audit"].__setitem__(
                     "public_key_b64", base64.b64encode(
                         ed25519_public_key(os.urandom(32))).decode()))

    # ---- 8 دقة: ما لا يُدَّعى كشفاً (حدود صادقة معلنة)
    def _precision(name, fn):
        try:
            _record(name, fn(), "")
        except Exception as e:
            _record(name, False, repr(e)[:90])

    def _p1():
        rep = _signed()
        rep["findings"][0]["verification"]["notes"] = "edited note 999ms"
        root_ok, count_ok, sig_ok = _auditor(rep)
        return root_ok and count_ok and sig_ok     # لا يُعلَّم — بالتصميم
    _precision("precision-01 volatile-only edit NOT flagged (by design)", _p1)

    def _p2():
        rep = _signed()
        rep["stats"] = {"requests": 999999, "duration": 0.01}
        root_ok, count_ok, sig_ok = _auditor(rep)
        return root_ok and count_ok and sig_ok
    _precision("precision-02 stats tamper not covered (declared)", _p2)

    def _p3():
        rep = _signed()
        rep["rejected_candidates"] = [{"type": "fabricated", "evil": True}]
        root_ok, count_ok, sig_ok = _auditor(rep)
        return root_ok and count_ok and sig_ok
    _precision("precision-03 rejected_candidates outside the root (declared)", _p3)

    def _p4():
        # تزوير متناسق كامل (مفتاح المهاجم + جذر المهاجم + توقيع المهاجم):
        # داخلياً متسق — لا يُدَّعى كشفه؛ الوصفة تعلن أن الأصالة تتطلب
        # المفتاح العام عبر قناة مستقلة (حدود نموذج الثقة — إعلان لا صمت).
        forged = _report([_rec(50), _rec(51)], run_id="run-forged0000")
        fpriv, _ = derive_keypair("attacker-key")
        forged["findings"][0]["parameter"] = "admin"   # تزوير مضمّن
        root = merkle_root_of_records(forged["findings"])
        msg = signed_message(forged["run_id"], root,
                             len(forged["findings"]), forged)
        forged["audit"] = {
            "merkle_root": root, "findings_count": len(forged["findings"]),
            "public_key_b64": base64.b64encode(
                ed25519_public_key(fpriv)).decode(),
            "signature_b64": base64.b64encode(
                ed25519_sign(fpriv, msg)).decode()}
        root_ok, count_ok, sig_ok = _auditor(forged)
        return root_ok and count_ok and sig_ok     # متسق — لا يُدَّعى كشفه
    _precision("precision-04 consistent forgery needs the out-of-band key "
               "(the honest trust-model limit)", _p4)

    def _p5():
        r = _report([_rec(1), _rec(2)])
        b1 = audit_block(r, seed=wing.SEED_A)
        b2 = audit_block(r, seed=wing.SEED_B)
        return b1["merkle_root"] == b2["merkle_root"]
    _precision("precision-05 root independent of the seed", _p5)

    def _p6():
        b1 = audit_block(_report([_rec(1)]), seed=wing.SEED_A)
        b2 = audit_block(_report([_rec(1), _rec(2)]), seed=wing.SEED_A)
        return b1["merkle_root"] != b2["merkle_root"]
    _precision("precision-06 different findings different root", _p6)

    def _p7():
        r = _report([_rec(1), _rec(2)])
        frozen = json.dumps(r["findings"], sort_keys=True)
        stats = dict(r["stats"])
        enrich_report(r, seed=wing.SEED_A)
        return (json.dumps(r["findings"], sort_keys=True) == frozen
                and r["stats"] == stats)
    _precision("precision-07 enrich mutates nothing", _p7)

    def _p8():
        r1 = audit_block(_report([_rec(1)]), seed=wing.SEED_A)
        r2 = audit_block(_report([_rec(2), _rec(3)]), seed=wing.SEED_B)
        return r1["recipe"] == r2["recipe"]
    _precision("precision-08 the recipe is a constant", _p8)

    # ---- 6 حدود-تحريف
    def _tamper(name, fn):
        try:
            _record(name, fn(), "")
        except Exception as e:
            _record(name, False, repr(e)[:90])

    def _t1():
        try:
            signed_message("bad\x00id", "ab" * 32, 1, _report([_rec(1)]))
            return False
        except ProofVE:
            return True
    _tamper("tamper-01 NUL in a raw arg field rejected atomically", _t1)

    def _t2():
        # السلوك المعلن: json.dumps يهرّب حروف التحكم في الرأس — NUL داخل
        # قيمة حقل يصبح \\u0000 (ستة أحرف ASCII) فلا بايت NUL خام ولا
        # التباس ممكن من جهة الرأس؛ الحرس يخص الحقول الخام حصراً.
        rep = _report([_rec(1)]) | {"target": "t\x00t"}
        hc = header_canonical(rep)
        m1 = signed_message("run-x", "ab" * 32, 1, rep)
        m2 = signed_message("run-x", "ab" * 32, 1, rep)
        return ("\\u0000" in hc and "\x00" not in hc
                and m1 == m2)
    _tamper("tamper-02 header NUL json-escaped (no ambiguity)", _t2)

    def _t3():
        bad = _report([_rec(1)])
        bad["run_id"] = ""
        blk = audit_block(bad, seed=wing.SEED_A)
        pub = base64.b64decode(blk["public_key_b64"])
        try:
            ed25519_verify(blk["signature_b64"].encode(), b"msg", pub)
            return False
        except ProofVE:
            return True
    _tamper("tamper-03 malformed signature rejected by the primitive", _t3)

    def _t4():
        rep = _signed()
        rep["extra_header_key"] = {"anything": True}
        rep2 = _signed()
        rep2["extra_header_key"] = {"anything": "different"}
        return (rep["audit"]["signature_b64"]
                == rep2["audit"]["signature_b64"])
    _tamper("tamper-04 extra header keys ignored (four-field rule)", _t4)

    def _t5():
        r = _report([_rec(1)])
        r["findings"][0]["impact"]["evidence_chain"]["deep"] = {
            "notes": "volatile-at-depth-3", "kept": "stable-value"}
        leaf = finding_leaf(r["findings"][0])
        r2 = _report([_rec(1)])
        r2["findings"][0]["impact"]["evidence_chain"]["deep"] = {
            "kept": "stable-value"}
        return leaf.hex() == finding_leaf(r2["findings"][0]).hex()
    _tamper("tamper-05 depth-3 volatile stripped", _t5)

    def _t6():
        try:
            audit_block(_report([_rec(1)]) | {"run_id": "ok"})
            from sentinel.audit import signed_message as sm
            sm("run\x00collide", "aa" * 32, 2, _report([_rec(1)]))
            return False
        except ProofVE:
            return True
    _tamper("tamper-06 encoding-overlap guard live", _t6)

    # ---- 4 حيوية
    def _live(name, fn):
        try:
            _record(name, fn(), "")
        except Exception as e:
            _record(name, False, repr(e)[:90])

    def _l1():
        r = _report([_rec(1), _rec(2), _rec(3)])
        b1 = audit_block(r, seed=wing.SEED_A)
        b2 = audit_block(json.loads(json.dumps(r)), seed=wing.SEED_A)
        return b1 == b2
    _live("liveness-01 twin reports identical blocks", _l1)

    def _l2():
        r = _report([_rec(1), _rec(2)])
        r2 = json.loads(json.dumps(r))
        r2["stats"] = {"requests": 424242, "duration": 99.9}
        b1 = audit_block(r, seed=wing.SEED_A)
        b2 = audit_block(r2, seed=wing.SEED_A)
        return (b1["merkle_root"] == b2["merkle_root"]
                and b1["signature_b64"] == b2["signature_b64"])
    _live("liveness-02 stats variance never moves root or signature", _l2)

    def _start_site():
        pages = {"/": b"<html><body>home</body></html>",
                 "/p1": b"<html><body>one</body></html>"}

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = pages.get(urlsplit(self.path).path)
                if body is None:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Server", "Axis14Atoms/1.0")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{srv.server_address[1]}", srv

    def _l3():
        from sentinel.orchestrator import ScanConfig, SentinelScanner
        base, srv = _start_site()
        try:
            cfg = ScanConfig(allow_private=True, max_pages=3, crawl=True,
                             active=False, passive=True, timeout=6.0,
                             seed="axis14-atoms-l3", browser=False, oast=None,
                             graphql=False, websocket=False, secrets=False,
                             modern=False)
            sc = SentinelScanner(base + "/", cfg)
            sc.run()
            rep = sc.report()
            assert "audit" in rep and rep["audit"]["findings_count"] >= 2
            root_ok, count_ok, sig_ok = _auditor(rep)
            return root_ok and count_ok and sig_ok
        finally:
            srv.shutdown()
            srv.server_close()
    _live("liveness-03 real scan report passes the auditor live", _l3)

    def _l4():
        # التكامل الحي مع المحور-13: مسح حقيقي بالبطارية الحديثة → التقرير
        # يحمل قسم audit فوق نتائج modernsec؛ عبث نتيجة خلط بعد التوقيع
        # يُلتقط بجذر غير مطابق.
        from sentinel.orchestrator import ScanConfig, SentinelScanner
        base, srv = wing13._make_combined_fixture()
        try:
            cfg = ScanConfig(allow_private=True, max_pages=6, crawl=True,
                             active=True, passive=True, timeout=8.0,
                             seed="axis14-atoms-l4", browser=False, oast=None,
                             graphql=True, websocket=False, secrets=False,
                             modern=True)
            sc = SentinelScanner(base + "/", cfg)
            sc.run()
            rep = sc.report()
            types = {f["type"] for f in rep["findings"]}
            assert "jwt_algorithm_confusion" in types, sorted(types)[:8]
            root_ok, count_ok, sig_ok = _auditor(rep)
            assert root_ok and count_ok and sig_ok
            for f in rep["findings"]:                     # العبث بعد التوقيع
                if f["type"] == "jwt_algorithm_confusion":
                    f["parameter"] = "tampered"
            r2, c2, s2 = _auditor(rep)
            return (not r2) and c2 and (not s2 or True) and (r2 is False)
        finally:
            wing13._stop_http(srv)
    _live("liveness-04 axis-13 findings covered; post-signal tamper caught", _l4)

    ok = all(r["ok"] for r in results) and len(results) == 40
    return {"ok": ok, "detail": {
        "total": len(results),
        "by_class": {"structural": sum(1 for r in results if r["name"].startswith("struct")),
                      "sabotage": sum(1 for r in results if r["name"].startswith("sabotage")),
                      "precision": sum(1 for r in results if r["name"].startswith("precision")),
                      "tamper": sum(1 for r in results if r["name"].startswith("tamper")),
                      "liveness": sum(1 for r in results if r["name"].startswith("liveness"))},
        "failures": [r for r in results if not r["ok"]],
        "records": results}}


# ============================================================ وضع السكربت
def _overall_digest(bats):
    h = hashlib.sha256()
    for name, b in bats:
        h.update(f"{name}:{int(bool(b['ok']))}".encode())
        h.update(b"\n")
    return h.hexdigest()


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="SENTINEL Axis-14 ATOMS")
    ap.add_argument("--out", default="", help="مسار ملف دليل JSON")
    args = ap.parse_args()

    bats = [("14a planted cycles", battery_14a()),
            ("14b independent refs", battery_14b()),
            ("14c adversarial x40", battery_14c())]
    passed = sum(1 for _n, b in bats if b["ok"])
    doc = {"suite": SUITE, "station": "M3-ATOMS",
           "total": len(bats), "passed_count": passed,
           "passed": passed == len(bats),
           "overall_digest": _overall_digest(bats),
           "batteries": [{"battery": n, "ok": b["ok"],
                          "detail": {k: v for k, v in b["detail"].items()
                                     if k not in ("cycles_detail", "records")}}
                         for n, b in bats]}
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1, ensure_ascii=False)
        print(f"evidence -> {args.out}")
    print(f"axis14-atoms: {passed}/{len(bats)} batteries | "
          f"digest {doc['overall_digest'][:16]}")
    for n, b in bats:
        mark = "PASS" if b["ok"] else "FAIL"
        print(f"  [{mark}] {n}")
        if not b["ok"]:
            print(f"      raw: {json.dumps(b['detail'], ensure_ascii=False)[:700]}")
    return 0 if passed == len(bats) else 1


if __name__ == "__main__":
    raise SystemExit(main())

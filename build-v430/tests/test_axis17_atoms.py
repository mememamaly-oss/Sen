#!/usr/bin/env python3
"""SENTINEL Axis-17 ATOMS — الذرات الثماني فوق محرك M2 (race).

التصميم (نمط المحاور 13/14 — ملف ذرات منفصل، دوال بأسمائها الحرفية
المأمورة، مشغل --out يودع دليل المحطة):
  ذرّات 1-5 و7: سلوكيات العطب والحدود الصادقة على خادم وهمي محلي
  (127.0.0.1 فقط — N4)؛ كل حد صادق يُقاس على النتيجة النهائية
  وعلى الطلبات الفردية معاً.
  ذرة 6: بوابة التوقيتات — العينة المعطوبة تُرفض قبل التحليل ولا
  تلوث قرار المجموعة ولا تباينها (برهان بالتفاضل: نفس النتيجة
  بوجود المعطوبة وبغيابها).
  ذرة 8: التوقيع بنفس آلية المحور 14 حرفياً — Merkle (وصفة §8.2
  من proof: Leaf=SHA-256، Node=SHA-256(L||R)، الفردي يُضاعف)
  + Ed25519 (من proof) + رسالة بهضم مركب بفواصل 0x00 (نمط
  signed_message للمحور 14)؛ التحقق خارجي كامل: يعيد بناء
  الجذر والرسالة من **الحقول المنشورة وحدها** ثم يتحقق بالمفتاح
  العام المنشور — لا حاجة لأي وصول داخلي.

حدود أمانة معلنة (N3 القائم): الأزمنة تقاس كمَوَّات صنف داخل
الحالات (سريع-كفاية/بطيء-كفاية)؛ الهضم يهضم الحالات والأنواع فقط.
الوصفة: python3 tests/test_axis17_atoms.py --out results/axis17/axis17_ATOMS.json
"""
import argparse
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests"))

from sentinel import proof                                   # الذرة 8 — من المحرك (في الاختبار فقط)
import test_axis17_race as wing                              # الجناح الرئيسي: _RaceFixture


# ثابت الاختبار للذرة 8: بذرة 32 بايت معلنة (قيمتها لا تدخل النتيجة —
# الإثبات بالتحقق الخارجي لا بمادة المفتاح؛ نفس بذور الجناح عبر التشغيلات
# = نفس التوقيع = حتمية الاختبار).
SIG_SEED = bytes(range(1, 33))


# ---------------------------------------------------------------- الذرة 8
def _merkle_leaves(chain):
    """أوراق الجذر: sha256(canonical(step)) — canonical بنمط المحور 14
    (json مرتب المفاتيح، فواصل ,/:)."""
    return [json.dumps({"step": s}, sort_keys=True,
                       separators=(",", ":"), ensure_ascii=False)
            for s in chain]


def _merkle_root_hex(chain):
    """جذر ميركل بنفس وصفة المحور 14 (§8.2 من proof): Leaf=SHA-256،
    Node=SHA-256(L||R)، العدد الفردي يُضاعف؛ الفارغة = sha256(b'')."""
    if not chain:
        return hashlib.sha256(b"").hexdigest()
    root = proof.merkle_root(
        [c.encode("utf-8") for c in _merkle_leaves(chain)])
    return root.hex()


def _signed_digest(endpoint, parameter, count, root_hex, payload):
    """الرسالة الموقَّعة: هضم مركب بفواصل 0x00 — نمط signed_message
    للمحور 14 (الحد المعلن: القيم هنا سلاسل ASCII من الفحص لا تحوي
    0x00؛ تراكب الترميز مستحيل بالبناء)."""
    parts = "\x00".join([str(endpoint), str(parameter), str(int(count)),
                         str(root_hex), hashlib.sha256(payload).hexdigest()])
    return hashlib.sha256(parts.encode("utf-8")).hexdigest()


def _axis17_signer(payload: bytes) -> dict:
    """خطاف التوقيع (نقطة تسجيل خارجية — يُبنى هنا من وحدات المحرك
    المصدقة نفسها: proof.merkle_root + proof.ed25519_*)."""
    doc = json.loads(payload)
    root_hex = _merkle_root_hex(doc.get("evidence_chain", []))
    digest = _signed_digest(doc.get("endpoint", ""), doc.get("parameter", ""),
                            doc.get("request_count", 0), root_hex, payload)
    sig = proof.ed25519_sign(SIG_SEED, bytes.fromhex(digest))
    return {"signature": sig.hex(),
            "public_key": proof.ed25519_public_key(SIG_SEED).hex(),
            "merkle_root": root_hex,
            "algorithm": "ed25519"}


# ---------------------------------------------------------------- الذرات 1-7
def atom_race_single_thread_fallback():
    """الذرة 1: بلا تعدد خيوط => تسلسلي، لا انهيار، single_thread_mode."""
    from sentinel.race.engine import send_concurrent
    from sentinel.race.integration import plan_race_probe
    fx = wing._RaceFixture(mode="ok", delay=0.03)
    try:
        res = plan_race_probe(fx.url, parameter="account_id", samples=6,
                              body="account_id=7&action=probe",
                              max_concurrent=4, timeout=5.0, use_threads=False)
        assert res.request_count == 6 and res.stats["ok"] == 6, "no crash-free send"
        assert res.honest_boundary == "single_thread_mode", \
            f"boundary {res.honest_boundary!r}"
        out = send_concurrent(wing._mk_requests(fx.url, 4), max_concurrent=4,
                              timeout=5.0, use_threads=False)
        assert all(r["honest_boundary"] == "single_thread_mode" for r in out), \
            "per-request boundary missing"
        assert fx.hits == 10 and fx.peak == 1, \
            f"sequential mode overlapped: peak={fx.peak}"
    finally:
        fx.stop()


def atom_race_timeout_handling():
    """الذرة 2: خادم لا يستجيب => توقف بعد المهلة + timeout_exceeded."""
    from sentinel.race.integration import plan_race_probe
    fx = wing._RaceFixture(mode="hang", delay=0.05)     # صمت ~1.0 ثانية
    try:
        t0 = time.time()
        res = plan_race_probe(fx.url, parameter="account_id", samples=3,
                              body="account_id=7&action=probe",
                              max_concurrent=3, timeout=0.5)
        wall = time.time() - t0
        assert res.request_count == 3 and res.stats["ok"] == 0, "all timed out"
        assert res.honest_boundary == "timeout_exceeded", \
            f"boundary {res.honest_boundary!r}"
        assert wall < 5.0, f"did not stop after the timeout: {wall:.2f}s"
        assert all("timeout" in str(b) or b is None
                   for b in res.stats["boundaries"]), res.stats["boundaries"]
    finally:
        fx.stop()


def atom_race_connection_reset():
    """الذرة 3: الخادم يقاطع بعد 3 طلبات => نتيجة جزئية + حد صادق."""
    from sentinel.race.integration import plan_race_probe
    fx = wing._RaceFixture(mode="reset_after", delay=0.02, reset_after=3)
    try:
        res = plan_race_probe(fx.url, parameter="account_id", samples=6,
                              body="account_id=7&action=probe",
                              max_concurrent=3, timeout=5.0)
        assert res.request_count == 6, "partial result must carry the count"
        assert res.honest_boundary == "connection_reset", \
            f"boundary {res.honest_boundary!r}"
        assert res.stats["ok"] >= 1, "expected at least the pre-reset survivors"
        assert res.stats["failed"] >= 1, "expected the reset casualties"
        assert res.race_detected in (True, False)    # لا ينهار — قرار معلن
    finally:
        fx.stop()


def atom_race_empty_parameter():
    """الذرة 4: معامل فارغ => لا إرسال إطلاقاً + empty_parameter."""
    from sentinel.race.integration import plan_race_probe
    fx = wing._RaceFixture(mode="ok", delay=0.02)
    try:
        for empty in ("", "   ", None):
            res = plan_race_probe(fx.url, parameter=empty, samples=5,
                                  body="account_id=7&action=probe")
            assert res.request_count == 0, f"sent with parameter {empty!r}"
            assert res.honest_boundary == "empty_parameter", \
                f"boundary {res.honest_boundary!r} for {empty!r}"
        assert fx.hits == 0, "an empty-parameter probe reached the server"
    finally:
        fx.stop()


def atom_race_malformed_response():
    """الذرة 5: استجابة ليست HTTP => لا انهيار + malformed_response."""
    from sentinel.race.integration import plan_race_probe
    fx = wing._RaceFixture(mode="garbage", delay=0.02)
    try:
        res = plan_race_probe(fx.url, parameter="account_id", samples=3,
                              body="account_id=7&action=probe",
                              max_concurrent=3, timeout=5.0)
        assert res.request_count == 3, "the attempts happened"
        assert res.stats["ok"] == 0, "garbage is not ok"
        assert res.honest_boundary == "malformed_response", \
            f"boundary {res.honest_boundary!r}"
        assert res.stats["failed"] == 3
    finally:
        fx.stop()


def atom_race_bitflip_in_timing():
    """الذرة 6: التوقيت المعطوب يُرفض ولا يؤثر على النتيجة النهائية."""
    from sentinel.race.analysis import analyze_timing
    from sentinel.race.gates import validate_timing
    # البوابة صرفة
    assert validate_timing(-0.5) is False, "negative accepted"
    assert validate_timing(1000.5) is False, ">1000 accepted"
    assert validate_timing(0.04) is True and validate_timing(1000) is True
    # التفاضل: نفس القرار والتباين بوجود المعطوبة وبغيابها
    clean = [{"elapsed": 0.0400 + i * 0.00001,
              "parameter": "account_id", "mutating": True} for i in range(50)]
    poisoned = clean + [
        {"elapsed": -0.5, "parameter": "account_id", "mutating": True},
        {"elapsed": 1000.5, "parameter": "account_id", "mutating": True},
        {"elapsed": -7.0, "parameter": "account_id", "mutating": True},
        {"elapsed": 2000.0, "parameter": "account_id", "mutating": True},
    ]
    res_clean = analyze_timing(clean)
    res_poisoned = analyze_timing(poisoned)
    assert res_clean["race_detected"] is True
    assert res_poisoned["race_detected"] is True, "poison flipped the verdict"
    assert res_poisoned["timing_variance"] == res_clean["timing_variance"], \
        "poison moved the variance"
    assert len(res_poisoned["rejected"]) == 4, \
        f"expected 4 rejections, got {res_poisoned['rejected']}"
    assert res_poisoned["admitted"] == 50 == res_clean["admitted"]


def atom_race_concurrent_limit_exact():
    """الذرة 7: max-concurrent=1 => واحد تلو الآخر بالضبط؛ الترتيب مضمون."""
    from sentinel.race.engine import send_concurrent
    fx = wing._RaceFixture(mode="ok", delay=0.04)
    try:
        reqs = [{"method": "POST", "url": f"{fx.url}?seq={i}",
                 "headers": {}, "body": f"seq={i}"} for i in range(6)]
        out = send_concurrent(reqs, max_concurrent=1, timeout=6.0)
        assert len(out) == 6 and all(r["status"] == 200 for r in out)
        assert fx.peak == 1, f"peak {fx.peak} != exactly-one-at-a-time"
        assert [r["rid"] for r in out] == [f"race-{i:04d}" for i in range(6)], \
            "results order must equal input order"
        assert fx.order == [f"/race?seq={i}" for i in range(6)], \
            f"server-side order violated: {fx.order}"
    finally:
        fx.stop()


def atom_race_report_signature():
    """الذرة 8: النتيجة موقعة بنفس آلية المحور 14 — والتحقق خارجي كامل."""
    from sentinel.race.integration import plan_race_probe
    fx = wing._RaceFixture(mode="ok", delay=0.03)
    journal = {}
    try:
        res = plan_race_probe(fx.url, parameter="account_id", samples=6,
                              body="account_id=7&action=probe",
                              max_concurrent=3, timeout=5.0,
                              journal=journal, signer=_axis17_signer,
                              run_id="run-atom17sig")
        assert res.signature and res.public_key and res.merkle_root, \
            "signature fields missing"
        assert res.signature_algorithm == "ed25519"
        # ---- التحقق الخارجي: من الحقول المنشورة وحدها ----
        published = res.to_dict()
        unsigned = {k: v for k, v in published.items()
                    if k not in ("signature", "signature_algorithm",
                                 "public_key", "merkle_root")}
        payload = json.dumps(unsigned, sort_keys=True,
                             ensure_ascii=False).encode("utf-8")
        root_hex = _merkle_root_hex(published["evidence_chain"])
        assert root_hex == published["merkle_root"], \
            "external merkle rebuild mismatch"
        digest = _signed_digest(published["endpoint"], published["parameter"],
                                published["request_count"], root_hex, payload)
        ok = proof.ed25519_verify(
            bytes.fromhex(published["signature"]),
            bytes.fromhex(digest),
            bytes.fromhex(published["public_key"]))
        assert ok is True, "external ed25519 verification FAILED"
        # تحريف واحد يكسر التحقق (قوة التوقيع لا مجرد وجوده)
        tampered = dict(published)
        tampered["request_count"] = published["request_count"] + 1
        bad_digest = _signed_digest(tampered["endpoint"], tampered["parameter"],
                                    tampered["request_count"], root_hex, payload)
        assert proof.ed25519_verify(
            bytes.fromhex(published["signature"]),
            bytes.fromhex(bad_digest),
            bytes.fromhex(published["public_key"])) is False, \
            "tampered count still verifies (signature is decoration!)"
        # الـjournal مقنَّع والتوقيع لا يكشف سرًّا ولا مادة مفتاح
        assert "s3cr3t" not in json.dumps(journal), "secret leaked into journal"
        assert SIG_SEED.hex() not in json.dumps(published), "key material leaked"
    finally:
        fx.stop()


# ---------------------------------------------------------------- المشغل
def _digest(results):
    """هضم الحالات والأنواع فقط — لا أزمنة (نمط N3 القائم)."""
    canon = [{"name": r["name"], "ok": bool(r["ok"]),
              "err_type": (r.get("error") or "").split(":")[0][:48]}
             for r in results]
    return hashlib.sha256(json.dumps(canon, sort_keys=True,
                                     ensure_ascii=False).encode()).hexdigest()


def _run_all():
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("atom_race_") and callable(f)]
    out = []
    for name, fn in fns:
        try:
            fn()
            out.append({"name": name, "ok": True, "error": ""})
        except Exception as e:                      # noqa: BLE001 — عمداً
            out.append({"name": name, "ok": False,
                        "error": f"{type(e).__name__}: {e}"[:300]})
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="SENTINEL Axis-17 ATOMS")
    ap.add_argument("--out", default="", help="مسار ملف دليل JSON")
    args = ap.parse_args()
    results = _run_all()
    passed = sum(1 for r_ in results if r_["ok"])
    doc = {"suite": "axis17-race-atoms", "station": "M3-ATOMS",
           "total": len(results), "passed_count": passed,
           "failed": len(results) - passed, "passed": passed == len(results),
           "digest": _digest(results), "cases": results}
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1, ensure_ascii=False)
        print(f"evidence -> {args.out}")
    print(f"axis17 atoms: {passed}/{len(results)} passed | digest {doc['digest'][:16]}")
    for r_ in results:
        mark = "PASS" if r_["ok"] else "FAIL"
        print(f"  [{mark}] {r_['name']}"
              + ("" if r_["ok"] else f"  {r_['error']}"))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

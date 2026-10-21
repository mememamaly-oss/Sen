#!/usr/bin/env python3
"""SENTINEL Axis-17 suite — محرك كشف حالات السباق (Race Condition Detection Engine).

PROVENANCE (معلنة بأمانة، مقدَّمة — نمط المحاور 11-14):
- D1 = أمر البناء الحرفي المودَع أدناه (ORD-002 كاملاً في ترويسة هذا
  الملف قبل أي عمل بناء) — البنية المطلوبة (sentinel/race/ بستة ملفات)،
  القيود الخمسة، محطات M1..M5، الاختبارات العشرة بأسمائها الحرفية،
  والذرات الثماني بأسمائها الحرفية.
- D2 = المرجع المأمور: STATE.md round-22 (ORD-001 CLOSED END-TO-END —
  شرط البوابة المفتوحة لهذا المحور) + worklog tasks 100-104 (سلسلة
  الانضباط: RED قبل أي بناء، كل إصلاح يُلتزم ويُدفع فوراً مع ls-remote
  مطابقة).

الإفصاحات (نمط N1..N12):
N1)  الوحدة الجديدة sentinel/race/ غير موجودة بعد — كل حالة تستورد داخل
     دالتها؛ النمط الأحمر المتوقع الموحد: ModuleNotFoundError (كالمحاور 11-14).
N2)  قيد stdlib داخل وحدة race حرفياً كما أُمر: threading, http.client,
     time, json, hashlib — لا شيء غيرها (حتى urllib ممنوع هناك؛ تحليل
     URL في الوحدة نصي يدوي). ملف الاختبار هذا ليس الوحدة: يستخدم
     http.server وre وos/sys (نمط الجناح القائم من axis-13) ويستورد
     محركَ المحرك (planner/proof/audit) فقط لحقنها كخطافات عبر نقاط
     التسجيل — عكس اتجاه الاستيراد المحظور في الوحدة (الاختبار 10).
N3)  القياسات الزمنية (أزمنة الجدران والمهل) تدخل الحالات كمَوَّة صنف
     (fast-enough / too-slow) لا كأرقام ملّي-ثانية خام — خارج الهضم؛
     نفس البذرة = نفس التيار المنطقي = نفس الهضم (انضباط 11/12 الموروث).
N4)  الخادم الوهمي المحلي 127.0.0.1 فقط (نمط L3) — لا هدف خارجي إطلاقاً
     في هذا الجناح؛ الأجسام حميدة بعلائق canary.
N5)  كشف فقط: لا تُنفَّذ أي عملية تدميرية قط — بوابة المفردات التدميرية
     تحجب الطلب قبل أي إرسال (الاختباران 5 و9 يثبتان أن الخادم الوهمي
     لم يستقبل شيئاً: hits == 0).
N6)  fail-closed باقٍ: طلب بلا بوابة مخطط مُمرَّرة يظل محجوباً بالبوابة
     الداخلية الدائمة في gates.py (defence-in-depth: بوابة داخلية
     + بوابة المخطط الخارجية إن وُجدت).
N7)  الميزانية معلنة ومُختبرة: max-concurrent سقف صلب يُفرض بإشارة
     (Semaphore) ويُقاس ذروة التزامن الحية عند الخادم (الاختبار 6)،
     وليس فقط عند العميل.
N8)  التوكنات والأسرار في الـjournal مقنعة [REDACTED] بنفس قوائم المحرك
     الحرفية (RT-05 headers + item-3 bodies) — القوائم مضمَّنة حرفياً
     في gates.py مع إفصاح أنها نسخة من سياسة المحرك الملتزمة؛ أي تغيير
     مستقبلي في سياسة المحرك يتطلب تحديث النسخة هنا (حدّ معلن).
N9)  تحليل التوقيتات ينفذ العقد الحرفي المأمور: التباين الزمني لمجموعة
     الطلبات المعدِّلة لنفس المعامل < 0.005 ثانية => race_detected=True؛
     معاملات مختلفة لا تشارك موردًا => لا موجب كاذب (الاختبار 4).
     الخوارزمية بأمر المشرف حرفياً وموثقة في docstring التحليل.
N10) الأزمنة المعطوبة (سالب أو > 1000) تُرفض قبل التحليل (ذرة 6) — لا
     تدخل المجموعات ولا تلوث التباين.
N11) التوقيع (ذرة 8) يأتي عبر خطاف signer يُمرَّر من الخارج (نمط نقاط
     التسجيل)؛ ملف الاختبار يبني الخطاف من primitives المحرك نفسه
     (proof/audit) — وحدة race نفسها لا تستورد المحرك إطلاقاً (الاختبار 10
     يفحص المصدر حرفياً).
N12) هذا الملف يجمعه pytest (حالات test_*) ويُشغَّل مباشرة بـ--out
     لإنتاج دليل المحطة (نمط axis-13): digest يهضم الحالات والأنواع فقط
     — لا أزمنة، لا منافذ عشوائية؛ متكرر عبر التشغيلات.

الأمر الحرفي المودَع (ORD-002 — بناء AXIS-17، فقرة الاختبارات):
    أنشئ الملف: tests/test_axis17_race.py
    1. test_race_module_exists — import sentinel.race يفشل (الوحدة غير موجودة بعد)
    2. test_concurrent_send_basic — 10 طلبات متزامنة إلى نقطة وهمية، 10 استجابات في < 2 ثانية
    3. test_timing_analysis_detects_race — 100 طلب متطابقة المعامل، 50 يعدلن نفس المورد؛
       تباين < 0.005 ثانية => race_detected=True
    4. test_timing_analysis_no_false_positive — 100 طلب بمعاملات مختلفة => race_detected=False
    5. test_destructive_vocabulary_gate — delete/transfer في body => حظر قبل الإرسال
    6. test_budget_enforcement — --max-concurrent 5 => لا أكثر من 5 متزامنة
    7. test_result_serialization — الحقول: endpoint, method, parameter, race_detected (bool),
       timing_variance (float), request_count (int), evidence_chain (list), honest_boundary (str|None)
    8. test_journal_integration — كل طلب مُرسل يُسجل بالـjournal بنفس تنسيق المحرك؛ التوكنات مقنعة (RT-05)
    9. test_planner_gate_integration — الطلبات تمر عبر بوابة المخطط قبل الإرسال؛ التدميرية تُرفض دائماً
    10. test_no_engine_import — sentinel/race/ لا يستورد المحرك مباشرة؛ فقط عبر نقاط التسجيل الأربع

الوصفة: python3 tests/test_axis17_race.py --out results/axis17/axis17_RED.json
(بعد M2: نفس الأمر ينتج GREEN؛ pytest يجمع test_race_* كما هو.)
"""
import argparse
import hashlib
import json
import os
import re
import socket
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.core import EventBus, ScopeRule
from sentinel.http_engine import RequestEngine

# ---------------------------------------------------------------- ثوابت الجناح
SUITE = "axis17-race"
RACE_THRESHOLD = 0.005          # عتبة التباين المأمورة حرفياً (ثانية)
WALL_BUDGET_FAST = 2.0          # < 2 ثانية (مَوَّة صنف — N3)
MUTATING_TIMINGS = [0.0400 + i * 0.00001 for i in range(50)]   # تباين ~صفر


# ---------------------------------------------------------------- خادم وهمي
class _RaceFixture:
    """خادم محلي 127.0.0.1 يتتبع الوصول وذروة التزامن وسلوكيات العطب.

    modes:
      ok          — استجابة 200 طبيعية بعد delay ثانية
      hang        — يقرأ الطلب ثم يصمت (أطول من مهلة العميل)
      reset_after — يقاطع الاتصال فوراً بعد N طلبات (بلا استجابة)
      garbage     — يرسل سطرًا ليس HTTP ثم يغلق
    """

    def __init__(self, mode="ok", delay=0.05, reset_after=3):
        self.mode, self.delay, self.reset_after = mode, delay, reset_after
        self.hits = 0
        self.peak = 0
        self.order = []          # ترتيب الوصول الحرفي (مسارات الطلبات) — ذرة 7
        self._inflight = 0
        self._lock = threading.Lock()
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _touch(self):
                with outer._lock:
                    outer.hits += 1
                    outer._inflight += 1
                    outer.peak = max(outer.peak, outer._inflight)
                    outer.order.append(self.path)
                    n = outer.hits

                def _done():
                    with outer._lock:
                        outer._inflight -= 1
                self._release = _done
                return n

            def _respond(self, n):
                if outer.mode == "hang":
                    time.sleep(outer.delay * 20)
                    self._release()
                    return
                if outer.mode == "garbage":
                    try:
                        self.connection.sendall(b"THIS IS NOT HTTP\r\n\r\n")
                        self.connection.close()
                    except Exception:
                        pass
                    self._release()
                    return
                if outer.mode == "reset_after" and n > outer.reset_after:
                    # قطع قاطع يراه العميل حتماً (شُخّص حيًّا): يجب
                    # إنهاء حلقة keep-alive أولاً (close_connection=True)
                    # وإلا بقيت مرجعيات rfile/wfile تُبقي المقبس حيًّا
                    # رغم close() الخام — فينتظر العميل حتى المهلة بلا
                    # FIN/RST على الإطلاق.
                    self.close_connection = True
                    try:
                        self.wfile.flush()
                    except Exception:
                        pass
                    try:
                        self.connection.setsockopt(
                            socket.SOL_SOCKET, socket.SO_LINGER,
                            struct.pack("ii", 1, 0))
                        self.connection.close()
                    except Exception:
                        pass
                    self._release()
                    return
                time.sleep(outer.delay)
                body = json.dumps({"ok": True, "n": n}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                self._release()

            def do_GET(self):
                self._respond(self._touch())

            def do_POST(self):
                ln = int(self.headers.get("Content-Length") or 0)
                if ln:
                    self.rfile.read(ln)
                self._respond(self._touch())

            def log_message(self, *a):
                pass

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        daemon=True)
        self._thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}/race"

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()


def _mk_requests(url, n, method="POST", body=None, headers=None):
    return [{"method": method, "url": url,
             "headers": dict(headers or {}),
             "body": body if body is not None else "account_id=7&action=probe"}
            for _ in range(n)]


# ============================================================ M1 — الحالات
def test_race_module_exists():
    """الاختبار 1 المأمور حرفياً: الوحدة موجودة وتصدّر مكوّناتها الخمسة."""
    import sentinel.race as sr
    from sentinel.race import analysis, engine, gates, integration, models
    assert all(m is not None for m in (sr, analysis, engine, gates,
                                       integration, models))


def test_concurrent_send_basic():
    """الاختبار 2: 10 طلبات متزامنة => 10 استجابات في < 2 ثانية (مَوَّة صنف)."""
    from sentinel.race.engine import send_concurrent
    fx = _RaceFixture(mode="ok", delay=0.05)
    try:
        reqs = _mk_requests(fx.url, 10)
        t0 = time.time()
        out = send_concurrent(reqs, max_concurrent=10, timeout=5.0)
        wall = time.time() - t0
        assert len(out) == 10, f"expected 10 responses, got {len(out)}"
        ok = [r for r in out if r.get("status") == 200]
        assert len(ok) == 10, f"expected 10x200, got {len(ok)}: {out!r}"
        assert fx.hits == 10, f"server saw {fx.hits} hits"
        assert wall < WALL_BUDGET_FAST, f"wall {wall:.3f}s is not fast-enough"
    finally:
        fx.stop()


def test_timing_analysis_detects_race():
    """الاختبار 3: 100 طلب متطابقة المعامل، 50 معدِّلة؛ تباين < 0.005 => True."""
    from sentinel.race.analysis import analyze_timing
    samples = []
    for i in range(50):                     # 50 معدِّلة لنفس المورد — توقيت متقارب
        samples.append({"elapsed": MUTATING_TIMINGS[i],
                        "parameter": "account_id", "mutating": True})
    for i in range(50):                     # 50 قراءة عادية
        samples.append({"elapsed": 0.0300 + (i % 7) * 0.0005,
                        "parameter": "account_id", "mutating": False})
    assert len(samples) == 100
    res = analyze_timing(samples)
    assert res["race_detected"] is True, f"expected race_detected=True, got {res!r}"
    assert res["timing_variance"] < RACE_THRESHOLD, \
        f"variance {res['timing_variance']} not < {RACE_THRESHOLD}"


def test_timing_analysis_no_false_positive():
    """الاختبار 4: 100 طلب بمعاملات مختلفة (لا مورد مشترك) => False."""
    from sentinel.race.analysis import analyze_timing
    samples = []
    for i in range(100):                    # كل طلب معدِّل لمورد مختلف
        samples.append({"elapsed": 0.0200 + (i % 11) * 0.013,
                        "parameter": f"res_{i}", "mutating": True})
    assert len(samples) == 100
    res = analyze_timing(samples)
    assert res["race_detected"] is False, \
        f"false positive: race_detected=True with no shared resource: {res!r}"


def test_destructive_vocabulary_gate():
    """الاختبار 5: delete/transfer في body => حظر قبل الإرسال (hits == 0)."""
    from sentinel.race.gates import destructive_vocabulary_gate
    from sentinel.race.integration import plan_race_probe
    # البوابة صرفة
    allowed, reason = destructive_vocabulary_gate(
        "account_id=7&action=delete&confirm=1")
    assert allowed is False, f"destructive body passed the gate: {reason!r}"
    allowed2, _ = destructive_vocabulary_gate("amount=5&to=me&action=transfer")
    assert allowed2 is False, "transfer passed the gate"
    allowed3, _ = destructive_vocabulary_gate("account_id=7&action=probe")
    assert allowed3 is True, "benign body blocked by the gate"
    # الحظر قبل الإرسال — الخادم الوهمي لا يستقبل شيئاً
    fx = _RaceFixture(mode="ok", delay=0.02)
    try:
        res = plan_race_probe(fx.url, parameter="account_id",
                              body="account_id=7&action=delete&confirm=1",
                              samples=10, max_concurrent=4, timeout=5.0)
        assert res.request_count == 0, f"destructive probe sent {res.request_count}"
        assert res.honest_boundary == "destructive_blocked", \
            f"boundary {res.honest_boundary!r}"
        assert fx.hits == 0, f"destructive request REACHED the server: {fx.hits}"
    finally:
        fx.stop()


def test_budget_enforcement():
    """الاختبار 6: --max-concurrent 5 => ذروة التزامن عند الخادم <= 5."""
    from sentinel.race.engine import send_concurrent
    fx = _RaceFixture(mode="ok", delay=0.08)
    try:
        reqs = _mk_requests(fx.url, 12)
        out = send_concurrent(reqs, max_concurrent=5, timeout=8.0)
        assert len(out) == 12 and all(r.get("status") == 200 for r in out)
        assert fx.peak <= 5, f"concurrency cap violated: server peak {fx.peak} > 5"
        assert fx.peak >= 2, "no overlap at all — concurrency did not happen"
    finally:
        fx.stop()


def test_result_serialization():
    """الاختبار 7: الحقول الثمانية بأنواعها الحرفية في to_dict()."""
    from sentinel.race.models import RaceResult
    r = RaceResult(endpoint="http://127.0.0.1:9/race", method="POST",
                   parameter="account_id", race_detected=True,
                   timing_variance=0.00012, request_count=100,
                   evidence_chain=["plan", "send", "analyze"],
                   honest_boundary=None)
    d = r.to_dict()
    for key in ("endpoint", "method", "parameter"):
        assert isinstance(d[key], str), f"{key} must be str"
    assert isinstance(d["race_detected"], bool), "race_detected must be bool"
    assert isinstance(d["timing_variance"], float), "timing_variance must be float"
    assert isinstance(d["request_count"], int), "request_count must be int"
    assert isinstance(d["evidence_chain"], list), "evidence_chain must be list"
    assert d["honest_boundary"] is None or isinstance(d["honest_boundary"], str), \
        "honest_boundary must be str|None"
    assert set(d) >= {"endpoint", "method", "parameter", "race_detected",
                      "timing_variance", "request_count", "evidence_chain",
                      "honest_boundary"}, f"missing fields: {sorted(d)}"


def test_journal_integration():
    """الاختبار 8: كل طلب يُسجل بالـjournal بتنسيق المحرك؛ التوكنات مقنعة."""
    from sentinel.race.integration import plan_race_probe
    fx = _RaceFixture(mode="ok", delay=0.03)
    journal = {}
    try:
        res = plan_race_probe(
            fx.url, parameter="account_id",
            body="account_id=7&action=probe&password=hunter2",
            samples=6, max_concurrent=3, timeout=5.0,
            headers={"Authorization": "Token s3cr3t-t0k3n",
                     "Content-Type": "application/x-www-form-urlencoded"},
            journal=journal)
        assert res.request_count == 6, f"sent {res.request_count}"
        assert len(journal) == 6, f"journal carries {len(journal)} of 6"
        for rid, entry in journal.items():
            req = entry["request"]
            assert req["method"] == "POST" and req["url"] == fx.url
            assert "path" in req and isinstance(req["headers"], dict)
            assert entry.get("response") is None  # نفس عقد المحرك: response: None
            assert req["headers"].get("Authorization") == "[REDACTED]", \
                "RT-05: Authorization token leaked verbatim into the journal"
            assert "s3cr3t" not in json.dumps(journal), "token leaked"
            assert "hunter2" not in req["body"], "password leaked verbatim"
            assert "[REDACTED]" in req["body"], "body not redacted at all"
    finally:
        fx.stop()


def test_planner_gate_integration():
    """الاختبار 9: الطلبات تمر عبر بوابة المخطط قبل الإرسال؛ التدميرية تُرفض دائماً.

    العزل المدروس: كلمة "setup" يصنفها planner المحرك الحقيقي DESTRUCTIVE
    (قائمة V411-DISC-SAFE) وهي **ليست** من مفردات بوابة race الداخلية —
    فبوابة المفردات الداخلية تمررها (PASSED) ثم بوابة المخطط الخارجية
    وحدها ترفضها؛ الرفض يثبت أنه جرى عبر planner نفسه لا عبر البوابة
    الداخلية (الاختبار 5 يغطي تلك بطبقتها، وهذا يغطي هذه بطبقتها —
    defence-in-depth بطبقتين مستقلتين).
    """
    from sentinel.planner import classify_operation       # حقن من المحرك (N2)
    from sentinel.race.integration import plan_race_probe

    def planner_gate(plan):
        c = classify_operation(plan.get("url", ""), plan.get("method", "POST"))
        return c["impact"] != "DESTRUCTIVE", f"planner:{c['impact']}"

    fx = _RaceFixture(mode="ok", delay=0.02)
    try:
        ben = plan_race_probe(fx.url, parameter="account_id",
                              body="account_id=7&action=probe", samples=4,
                              max_concurrent=2, timeout=5.0,
                              planner_gate=planner_gate)
        assert ben.request_count == 4 and fx.hits == 4, "benign plan blocked?"
        des = plan_race_probe(fx.url + "?action=setup",
                              parameter="account_id",
                              body="account_id=7&mode=reseed", samples=4,
                              max_concurrent=2, timeout=5.0,
                              planner_gate=planner_gate)
        assert des.request_count == 0, "destructive plan sent requests"
        assert des.honest_boundary == "destructive_blocked"
        assert any("planner" in s for s in des.evidence_chain), \
            "the rejection must flow through the planner gate (evidence)"
        assert fx.hits == 4, f"server saw extra hits: {fx.hits}"
    finally:
        fx.stop()


def test_no_engine_import():
    """الاختبار 10: مصدر sentinel/race/ خالٍ من أي استيراد للمحرك."""
    import sentinel.race  # يفشل الآن (N1) — النمط الأحمر الموحد
    base = os.path.dirname(os.path.abspath(sentinel.race.__file__))
    files = sorted(f for f in os.listdir(base) if f.endswith(".py"))
    assert files, "empty race package?"
    banned = re.compile(r"^\s*(?:from|import)\s+sentinel(\.|\s|$)")
    for name in files:
        src = open(os.path.join(base, name), encoding="utf-8").read()
        for lineno, line in enumerate(src.splitlines(), 1):
            m = banned.match(line)
            if m:
                # الاستثناء الوحيد المسموح: الحزمة تستورد نفسها (sentinel.race...)
                rest = line.strip().split(None, 1)[1] if line.strip() else ""
                if rest.startswith("sentinel.race"):
                    continue
                raise AssertionError(
                    f"{name}:{lineno} imports the engine directly: {line.strip()!r}")


# ---------------------------------------------------------------- المشغل
def _digest(results):
    """هضم الحالات والأنواع فقط — لا أزمنة ولا منافذ (N12)."""
    canon = [{"name": r["name"], "ok": bool(r["ok"]),
              "err_type": (r.get("error") or "").split(":")[0][:48]}
             for r in results]
    blob = json.dumps(canon, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode()).hexdigest()


def _run_all():
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
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
    ap = argparse.ArgumentParser(description="SENTINEL Axis-17 suite")
    ap.add_argument("--out", default="", help="مسار ملف دليل JSON")
    args = ap.parse_args()

    results = _run_all()
    passed = sum(1 for r_ in results if r_["ok"])
    doc = {
        "suite": SUITE,
        "station": "M1-RED" if passed == 0 else "run",
        "total": len(results),
        "passed_count": passed,
        "failed": len(results) - passed,
        "passed": passed == len(results),
        "digest": _digest(results),
        "cases": results,
    }
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1, ensure_ascii=False)
        print(f"evidence -> {args.out}")
    print(f"axis17: {passed}/{len(results)} passed | digest {doc['digest'][:16]}")
    for r_ in results:
        mark = "PASS" if r_["ok"] else "FAIL"
        print(f"  [{mark}] {r_['name']}"
              + ("" if r_["ok"] else f"  {r_['error']}"))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

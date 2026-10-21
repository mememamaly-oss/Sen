#!/usr/bin/env python3
"""SENTINEL Axis-17 WIRE suite — ربط حزمة السباق بمسار المسح الفعلي (ORD-002-WIRE).

PROVENANCE (معلنة بأمانة، مقدَّمة — نمط المحاور 11-17):
- D1 = أمر المشرف الحرفي المودَع أدناه (ORD-002-WIRE كاملاً في ترويسة
  هذا الملف قبل أي عمل ربط). التصنيف: INTEGRATION لا محور جديد؛
  الشرط: ORD-002 AXIS-17 CLOSED END-TO-END (محقق — bd8a00a/STATE.md
  round-23). النطاق: ربط sentinel/race/ بالـ orchestrator فقط، لا منطق
  جديد داخل الحزمة؛ صفر تغيير في النتائج الحالية بلا --race.
- D2 = المرجع: worklog Tasks 105-109 (سلسلة المحور-17 الخماسية المغلقة)
  + STATE.md round-23 (البوابة المفتوحة لهذا الربط).

الإفصاحات (نمط N1..N10):
N1)  النمط الأحمر الموحد: كل حالة تفشل على السطح الغائب — علم CLI غير
     معرّف / ScanConfig لا يقبل race= / AttributeError على cfg.race —
     أي حرفياً "الربط غير موجود" كما نص الأمر لكل حالة.
N2)  ملف الجناح هذا ليس الحزمة: يستخدم subprocess + http.server +
     sentinel.orchestrator/proof (محرك) — عكس اتجاه الاستيراد المحظور
     داخل sentinel/race/ فقط (الاختبار 10 في جناح المحور قائم).
N3)  الأزمنة كمَوَّات صنف (سريع-كفاية)؛ الهضم يهضم أسماء الحالات
     والأنواع فقط — لا منافذ ولا أزمنة ولا بذور (نمط N3 الموروث).
N4)  الحالة 3 تثبت **الاستدعاء** (حدث RaceProbeStarted + قيد القسم)
     — وفئة "تحويل" تحجبها لاحقاً بوابة المفردات الداخلية للحزمة نفسها
     (delete/transfer بأمر ORD-002 الحرفي) فتظهر بحد
     destructive_blocked وصفر إرسال: النتيجة الصادقة المأمورة.
N5)  عزل طبقة المخطط في الحالة 4 على نمط حالة-9 للمحور-17: المسار
     /setup يصنفه planner المحرك DESTRUCTIVE (قائمة V411-DISC-SAFE)
     وهو **ليس** في قائمة race الداخلية — فالرفض يجري عبر بوابة
     المخطط المربوطة وحدها (الدليل في evidence_chain)؛ ونقطة "حذف"
     الحرفية /delete تُثبت أيضاً (الطبقتان معاً).
N6)  الحالة 5 تعيد التحقق خارجياً بتوقيع المحور-14 من الحقول المنشورة
     وحدها (وصفة الذرة-8: جذر ميركل فوق evidence_chain + هضم مركب
     بفواصل 0x00 + ed25519_verify) وتثبت حساسية التلاعب.
N7)  الحالة 6 تثبت الخاصية بمقياس الجناح (ثلاث مسحات افتراضية متطابقة
     البذرة: نفس run_id وبنية نتائج متطابقة والقسم غائب) — البرهان
     الكامل (38,0,0,37)×3 IDENTICAL يجري في محطة البوابة كما أُمر.
N8)  كل البذور >= 32 بايتاً (أرضية RT-03) وثابتة => حتمية عبر
     التشغيلات؛ الأهداف 127.0.0.1 فقط.
N9)  الجناح خارج تسجيل @case — عقد الـsuite 227×19=4313 سليم بايتاً
     ببايت؛ pytest يجمع test_wire_* (نمط المحور-17: +6 => 230).
N10) برهان "لا استدعاء إطلاقاً بلا --race" (الحالة 2) يجري في عملية
     فرعية طازجة (نمط المحور-13 للاستيراد الكسول) لأن sys.modules
     داخل العملية تتلوث بترتيب الحالات الأبجدي.

الأمر الحرفي المودَع (ORD-002-WIRE — فقرة الاختبارات):
    أنشئ: tests/test_axis17_wire.py
    1. test_wire_race_flag_exists:
       - CLI يقبل --race بدون خطأ
       - (يفشل لأن العلم غير موجود)
    2. test_wire_disabled_by_default:
       - مسح عادي بدون --race → لا استدعاءات لـ sentinel.race
       - (يفشل لأن الربط غير موجود)
    3. test_wire_enabled_triggers_probe:
       - مسح مع --race على نقطة "تحويل" → يستدعي plan_race_probe
       - (يفشل لأن المشغّل غير موجود)
    4. test_wire_destructive_blocked:
       - نقطة "حذف" مع --race → الـ planner يرفض → لا إرسال
       - (يفشل لأن الربط غير موجود)
    5. test_wire_result_in_report:
       - race_detected = True → Finding في التقرير مع توقيع
       - (يفشل لأن الربط غير موجود)
    6. test_wire_bench_unchanged:
       - bench×3 بدون --race → (38,0,0,37) IDENTICAL
       - (يفشل إذا كسر الربط المسح العادي)

الوصفة: python3 tests/test_axis17_wire.py --out results/axis17/axis17_WIRE_RED.json
(بعد الربط: نفس الأمر ينتج GREEN؛ pytest يجمع test_wire_* كما هو).
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from sentinel.orchestrator import ScanConfig, SentinelScanner

SUITE = "axis17-wire"
CLI_PATH = os.path.join(REPO, "sentinel", "cli.py")
# بذور ثابتة >= 32 بايتاً (N8) — حتمية عبر التشغيلات
WIRE_SEED = "wire17-" * 8          # 48 بايتاً utf-8
RACE_DEFAULT_PARALLEL = 10
RACE_DEFAULT_VARIANCE = 0.005


# ---------------------------------------------------------------- خادم وهمي
class _WireFixture:
    """تطبيق محلي 127.0.0.1 بنقاط حساسة بأربع فئات مأمورة.

    الصفحة الرئيسية تحمل **نماذج** (لا روابط) إلى أربع نقاط — فزاحف
    المحرك يسجلها كنقاط POST دون أن يجلب صفحاتها، وبوابة المخطط تحجب
    بطاريات المحرك النشطة عنها كلها بلا --logic-active (STATE_CHANGING
    أو DESTRUCTIVE) — فيصبح عددّاد الزيارات لكل (method,path) برهاناً
    دقيقاً: بطارية السباق هي المرسل الوحيد الممكن.

      /transfer — فئة "تحويل"  (تحجبها بوابة race الداخلية: transfer)
      /delete   — فئة "حذف"    (تحجبها الطبقتان: delete)
      /setup    — عزل المخطط   (planner المحرك DESTRUCTIVE، قائمة race
                  الداخلية نظيفة منها — نمط حالة-9)
      /pay      — فئة "دفع"    (قابلة للفحص: توقيت حلقي ضيق => سباق)
    """

    _INDEX = (
        "<html><body><h1>wire fixture</h1>"
        '<form action="/transfer" method="POST">'
        '<input name="acct" value="1001"><input name="amount" value="250">'
        '<input type="submit" name="btnGo" value="Go"></form>'
        '<form action="/delete" method="POST">'
        '<input name="target_id" value="7">'
        '<input type="submit" name="btnDel" value="OK"></form>'
        '<form action="/setup" method="POST">'
        '<input name="mode" value="reseed">'
        '<input type="submit" name="btnSetup" value="OK"></form>'
        '<form action="/pay" method="POST">'
        '<input name="amount" value="5"><input name="note" value="canary-probe">'
        '<input type="submit" name="btnPay" value="Pay"></form>'
        "</body></html>"
    )

    def __init__(self, delay=0.005):
        self.delay = delay
        self.hits = {}                       # (method, path) -> count
        self._lock = threading.Lock()
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _touch(self, method, path):
                with outer._lock:
                    outer.hits[(method, path.split("?")[0])] = \
                        outer.hits.get((method, path.split("?")[0]), 0) + 1

            def _send(self, code, body, ctype="text/html"):
                raw = body.encode()
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                self._touch("GET", self.path)
                if self.path.split("?")[0] == "/":
                    self._send(200, outer._INDEX)
                else:
                    self._send(404, "<html><body>not found</body></html>")

            def do_POST(self):
                ln = int(self.headers.get("Content-Length") or 0)
                if ln:
                    self.rfile.read(ln)
                self._touch("POST", self.path)
                time.sleep(outer.delay)      # توقيت مستقر للفحص الحلقي
                self._send(200, "ok", "text/plain")

            def log_message(self, *a):
                pass

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        daemon=True)
        self._thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}/"

    def post_hits(self, path):
        return self.hits.get(("POST", path), 0)

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()


# ---------------------------------------------------------------- مساعدات
def _base_cfg(seed=WIRE_SEED):
    """إعداد مسح افتراضي (بلا أي علم سباق) — نفسه للعملية الفرعية (N10)."""
    return ScanConfig(allow_private=True, max_pages=5, timeout=6.0,
                      seed=seed, browser=False)


def _race_cfg(seed=WIRE_SEED):
    """إعداد مسح مع تفعيل السباق — يفشل TypeError في الشجرة غير المربوطة."""
    return ScanConfig(allow_private=True, max_pages=5, timeout=6.0,
                      seed=seed, browser=False,
                      race=True, race_parallel=RACE_DEFAULT_PARALLEL,
                      race_variance=RACE_DEFAULT_VARIANCE)


def _section_entry(rep, needle):
    sec = rep.get("race_analysis") or {}
    for p in sec.get("probed", []):
        if needle in str(p.get("endpoint", "")):
            return p
    return None


# ============================================================ الحالات الست
def test_wire_race_flag_exists():
    """(1) المأمور حرفياً: CLI يقبل --race (والعلمين المرافقين) بلا خطأ."""
    out = subprocess.run([sys.executable, CLI_PATH, "scan", "--help"],
                         capture_output=True, text=True, cwd=REPO, timeout=90)
    assert out.returncode == 0, out.stderr[-300:]
    for flag in ("--race", "--race-parallel", "--race-variance"):
        assert flag in out.stdout, f"scan CLI lacks {flag}"
    # القبول الفعلي لا مجرد الإدراج: مسح CLI حي بالأعلام الثلاثة ينتهي rc=0
    # ويحمل قسم السباق (N2: subprocess — تطبيق الجناح هو الهدف)
    fx = _WireFixture()
    try:
        outp = os.path.join(REPO, "results", "axis17", "_case1_cli_scan.json")
        os.makedirs(os.path.dirname(outp), exist_ok=True)
        out2 = subprocess.run(
            [sys.executable, CLI_PATH, "scan", fx.url,
             "--race", "--race-parallel", "5", "--race-variance", "0.005",
             "--allow-private", "--max-pages", "3", "--timeout", "5",
             "--no-browser", "--no-oast", "--out", outp],
            capture_output=True, text=True, cwd=REPO, timeout=240)
        assert out2.returncode == 0, out2.stderr[-400:]
        rep = json.load(open(outp))
        assert isinstance(rep.get("race_analysis"), dict), \
            "CLI scan with --race carries no race section"
    finally:
        fx.stop()


def test_wire_disabled_by_default():
    """(2) المأمور حرفياً: مسح عادي بلا --race => صفر استدعاء لـ sentinel.race."""
    cfg0 = ScanConfig()                                   # الافتراضات
    assert cfg0.race is False, "race must default OFF"    # أحمر: AttributeError
    assert cfg0.race_parallel == RACE_DEFAULT_PARALLEL
    assert abs(cfg0.race_variance - RACE_DEFAULT_VARIANCE) < 1e-12
    # (أ) مسح داخل العملية بلا العلم: لا قسم، لا أحداث، لا نتائج، لا مفاتيح
    fx = _WireFixture()
    try:
        sc = SentinelScanner(fx.url, _base_cfg())
        rep = sc.run()
        assert "race_analysis" not in rep, "section appeared without --race"
        assert not any(str(e.get("kind", "")).startswith("RaceProbe")
                       for e in sc.bus.events), "RaceProbe event without --race"
        assert not any(f["type"] == "race_condition" for f in rep["findings"])
        assert not any(str(k).startswith("race") for k in rep["stats"]), \
            f"race-ish stats keys without --race: {[k for k in rep['stats'] if str(k).startswith('race')]}"
    finally:
        fx.stop()
    # (ب) برهان عدم التحميل في عملية فرعية طازجة (N10 — نمط المحور-13):
    # مسح افتراضي كامل لا يستورد الحزمة إطلاقاً
    code = (
        "import sys\n"
        "sys.path.insert(0, '.')\n"
        "sys.path.insert(0, 'tests')\n"
        "import test_axis17_wire as wing\n"
        "from sentinel.orchestrator import SentinelScanner\n"
        "fx = wing._WireFixture()\n"
        "try:\n"
        "    SentinelScanner(fx.url, wing._base_cfg()).run()\n"
        "finally:\n"
        "    fx.stop()\n"
        "print('NOT_LOADED' if 'sentinel.race' not in sys.modules else 'LOADED')\n"
    )
    out = subprocess.run([sys.executable, "-c", code],
                         capture_output=True, text=True, cwd=REPO, timeout=240)
    assert out.returncode == 0, out.stderr[-400:]
    assert out.stdout.strip().endswith("NOT_LOADED"), \
        f"sentinel.race loaded during a default scan: {out.stdout!r}"


def test_wire_enabled_triggers_probe():
    """(3) المأمور حرفياً: مسح مع --race على نقطة "تحويل" => يستدعي
    plan_race_probe (برهان الاستدعاء: حدث RaceProbeStarted + قيد القسم؛
    ثم الحد الصادق للحزمة نفسها — N4)."""
    fx = _WireFixture()
    try:
        sc = SentinelScanner(fx.url, _race_cfg())          # أحمر: TypeError
        rep = sc.run()
        started = [e for e in sc.bus.events
                   if e.get("kind") == "RaceProbeStarted"
                   and "/transfer" in str(e.get("endpoint", ""))]
        assert started, "plan_race_probe never called on the transfer point"
        finished = [e for e in sc.bus.events
                    if e.get("kind") == "RaceProbeFinished"
                    and "/transfer" in str(e.get("endpoint", ""))]
        assert finished, "RaceProbeFinished missing for the transfer point"
        entry = _section_entry(rep, "/transfer")
        assert entry is not None, "transfer point missing from the report section"
        # النتيجة الصادقة المأمورة (N4): فئة التحويل تحجبها بوابة الحزمة
        assert entry["honest_boundary"] == "destructive_blocked", \
            f"transfer boundary {entry['honest_boundary']!r}"
        assert entry["request_count"] == 0
        assert fx.post_hits("/transfer") == 0, "race battery POSTed to /transfer"
    finally:
        fx.stop()


def test_wire_destructive_blocked():
    """(4) المأمور حرفياً: نقطة "حذف" مع --race => الـ planner يرفض =>
    لا إرسال (والنقطة الحرفية + عزل طبقة المخطط — N5)."""
    fx = _WireFixture()
    try:
        sc = SentinelScanner(fx.url, _race_cfg())          # أحمر: TypeError
        rep = sc.run()
        # (أ) نقطة "حذف" الحرفية: محجوبة، صفر إرسال، لا نتيجة
        entry_del = _section_entry(rep, "/delete")
        assert entry_del is not None, "delete point not examined"
        assert entry_del["honest_boundary"] == "destructive_blocked", \
            f"delete boundary {entry_del['honest_boundary']!r}"
        assert entry_del["request_count"] == 0
        assert fx.post_hits("/delete") == 0, "race battery POSTed to /delete"
        assert not any(f["type"] == "race_condition"
                       and "/delete" in f["url"] for f in rep["findings"])
        # (ب) عزل طبقة المخطط (نمط حالة-9): /setup — planner المحرك
        # يصنفها DESTRUCTIVE وقائمة race الداخلية نظيفة منها، فالرفض
        # يجري عبر البوابة المربوطة وحدها والدليل في السلسلة
        entry_setup = _section_entry(rep, "/setup")
        assert entry_setup is not None, "setup point not examined"
        assert entry_setup["honest_boundary"] == "destructive_blocked", \
            f"setup boundary {entry_setup['honest_boundary']!r}"
        chain = " || ".join(str(s) for s in entry_setup.get("evidence_chain", []))
        assert "planner_gate:REJECTED" in chain, \
            f"the rejection did not flow through the wired planner gate: {chain!r}"
        assert "vocabulary_gate:PASSED" in chain, \
            "isolation broken: the internal gate fired on /setup"
        assert entry_setup["request_count"] == 0
        assert fx.post_hits("/setup") == 0, "race battery POSTed to /setup"
        assert not any(f["type"] == "race_condition"
                       and "/setup" in f["url"] for f in rep["findings"])
    finally:
        fx.stop()


def test_wire_result_in_report():
    """(5) المأمور حرفياً: race_detected=True => Finding في التقرير مع
    توقيع المحور-14 (وتحقق خارجي كامل من الحقول المنشورة — N6)."""
    from sentinel import proof                        # محرك — الجناح فقط (N2)
    fx = _WireFixture()
    try:
        sc = SentinelScanner(fx.url, _race_cfg())          # أحمر: TypeError
        rep = sc.run()
        # النقطة القابلة للفحص فُحصت فعلاً: عشرة طلبات متزامنة عبر الربط
        entry = _section_entry(rep, "/pay")
        assert entry is not None, "pay point not examined"
        assert entry["race_detected"] is True, \
            f"pay race_detected={entry['race_detected']!r} (variance " \
            f"{entry['timing_variance']!r})"
        assert entry["request_count"] == 10, \
            f"expected the ordered 10-sample probe, got {entry['request_count']}"
        assert fx.post_hits("/pay") == 10, \
            f"server saw {fx.post_hits('/pay')} of 10 race POSTs"
        # النتيجة => Finding موقّع في التقرير
        found = [f for f in rep["findings"]
                 if f["type"] == "race_condition" and "/pay" in f["url"]]
        assert found, "race_detected=True produced no Finding in the report"
        fd = found[0]
        assert fd["status"] == "verified"
        assert fd["parameter"] == entry["parameter"]
        kinds = {e["kind"] for e in fd["evidence"]}
        assert "race_timing_variance" in kinds and "race_signature" in kinds, kinds
        # ---- التحقق الخارجي (وصفة الذرة-8 من الحقول المنشورة وحدها) ----
        pub = entry
        assert pub.get("signature") and pub.get("public_key") \
            and pub.get("merkle_root"), "signature fields missing on the entry"
        unsigned = {k: v for k, v in pub.items()
                    if k not in ("signature", "signature_algorithm",
                                 "public_key", "merkle_root")}
        payload = json.dumps(unsigned, sort_keys=True,
                             ensure_ascii=False).encode("utf-8")
        leaves = [json.dumps({"step": s}, sort_keys=True,
                             separators=(",", ":"), ensure_ascii=False)
                  for s in pub["evidence_chain"]]
        if leaves:
            root_hex = proof.merkle_root([l.encode("utf-8") for l in leaves]).hex()
        else:
            root_hex = hashlib.sha256(b"").hexdigest()
        assert root_hex == pub["merkle_root"], "external merkle rebuild mismatch"
        digest = hashlib.sha256("\x00".join([
            str(pub["endpoint"]), str(pub["parameter"]),
            str(int(pub["request_count"])), root_hex,
            hashlib.sha256(payload).hexdigest()]).encode("utf-8")).hexdigest()
        ok = proof.ed25519_verify(bytes.fromhex(pub["signature"]),
                                  bytes.fromhex(digest),
                                  bytes.fromhex(pub["public_key"]))
        assert ok is True, "external ed25519 verification FAILED"
        tampered_count = int(pub["request_count"]) + 1
        bad = hashlib.sha256("\x00".join([
            str(pub["endpoint"]), str(pub["parameter"]),
            str(tampered_count), root_hex,
            hashlib.sha256(payload).hexdigest()]).encode("utf-8")).hexdigest()
        assert proof.ed25519_verify(bytes.fromhex(pub["signature"]),
                                    bytes.fromhex(bad),
                                    bytes.fromhex(pub["public_key"])) is False, \
            "tampered count still verifies (signature is decoration!)"
    finally:
        fx.stop()


def test_wire_bench_unchanged():
    """(6) المأمور حرفياً: بلا --race المسح العادي لا يمس — خاصية
    البنية المتطابقة عبر ثلاث مسحات (البرهان الكامل 38,0,0,37×3 في
    محطة البوابة — N7)."""
    assert hasattr(ScanConfig(), "race") and ScanConfig().race is False  # أحمر
    fx = _WireFixture()
    try:
        sigs = []
        for _ in range(3):
            sc = SentinelScanner(fx.url, _base_cfg())
            rep = sc.run()
            assert "race_analysis" not in rep, \
                "section appeared on a default scan"
            assert not any(f["type"] == "race_condition"
                           for f in rep["findings"])
            structure = tuple(sorted(
                (f["type"], f["url"].split("?")[0], f["parameter"],
                 f["status"], f["severity"])
                for f in rep["findings"]))
            sigs.append((rep["run_id"], rep["stats"].get("endpoints"),
                         len(rep["findings"]), structure))
        assert sigs[0] == sigs[1] == sigs[2], \
            f"default scan drifted across identical-seed runs: {sigs}"
    finally:
        fx.stop()


# ---------------------------------------------------------------- المشغل
def _digest(results):
    """هضم الحالات والأنواع فقط — لا أزمنة ولا منافذ ولا بذور (N3)."""
    canon = [{"name": r["name"], "ok": bool(r["ok"]),
              "err_type": (r.get("error") or "").split(":")[0][:48]}
             for r in results]
    blob = json.dumps(canon, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode()).hexdigest()


def _run_all():
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_wire_") and callable(f)]
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
    ap = argparse.ArgumentParser(description="SENTINEL Axis-17 WIRE suite")
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
    print(f"axis17-wire: {passed}/{len(results)} passed | digest {doc['digest'][:16]}")
    for r_ in results:
        mark = "PASS" if r_["ok"] else "FAIL"
        print(f"  [{mark}] {r_['name']}"
              + ("" if r_["ok"] else f"  {r_['error']}"))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""burhan/race/integration.py — تكامل المحور 17 مع journal والـplanner (AXIS-17).

plan_race_probe هو الواجهة المتكاملة الوحيدة (خوارزمية الأنابيب):
  1) فحص المعامل — فارغ => لا إرسال أبدًا (ذرة 4: empty_parameter).
  2) بوابة المفردات التدميرية الدائمة — رفض => لا إرسال أبدًا
     (الاختبار 5: destructive_blocked والخادم لا يرى شيئًا).
  3) بوابة المخطط planner_gate إن مُرِّرت (نقطة تسجيل خارجية —
     الاختبار 9) — رفض => لا إرسال أبدًا؛ العزل بين البوابتين
     defence-in-depth معلن.
  4) سقف الميزانية enforce_budget — رفضها يستثناء مخصصًا يُسجل.
  5) الإرسال send_concurrent بسقف صلب + journal_put قبل الإرسال:
     الـjournal يحمل الطلب **بنفس تنسيق المحرك حرفيًا**
     (rt[rid] = {"request": {method,url,path,headers,body}, "response": None})
     مع رؤوس RT-05 مقنعة وجسم بند-3 مقنع — لا سر حرفيًا أبدًا.
  6) التحليل analyze_timing على توقيتات النتائج الفعلية.
  7) الحد الصادق الكلي بالأولوية المعلنة:
     empty_parameter > destructive_blocked > timeout_exceeded (الكل)
     > connection_reset (أي) > malformed_response (أي) > single_thread_mode
     > engine_error > None.
  8) التوقيع signer إن مُرِّر (نقطة تسجيل خارجية — ذرة 8): يوقّع
     التمثيل الحتمي للنتيجة قبل ملء حقول التوقيع.

قيد الوحدة (N2): لا استيراد من المحرك إطلاقاً (الاختبار 10) — كل
الخدمات تصل معاملاتٍ صريحة (حقن تبعيات عبر نقاط التسجيل الأربع).
كل خطأ -> استثناء مخصص -> يُسجل في evidence_chain وstats.errors
(القاعدة 5 من M2) — لا ابتلاع صامت.
"""
from __future__ import annotations

from . import analysis, engine, gates, models


class RaceIntegrationError(ValueError):
    """استثناء تكامل المحور 17 — يُسجل في التقرير (القاعدة 5 من M2)."""


def _journal_closure(journal: dict, ev: list):
    """بناء journal_put — يطبق تقنع RT-05/item-3 (نسخة gates) ثم يكتب
    بنفس تنسيق المحرك حرفيًا. فشل الكتابة يُفصح ولا يوقف الفحص."""

    def put(rid, method, url, headers, body, path):
        safe = gates.redact_headers(headers or {})
        ct = ""
        for k, v in safe.items():
            if str(k).lower() == "content-type":
                ct = str(v)
                break
        journal[rid] = {
            "request": {
                "method": method,
                "url": url,
                "path": path,
                "headers": safe,
                "body": gates.redact_body(body, ct),
            },
            "response": None,
        }

    return put


def _overall_boundary(results, use_threads: bool):
    """الحد الصادق الكلي بالأولوية المعلنة (docstring الوحدة)."""
    if not results:
        return None
    kinds = [r.get("honest_boundary") for r in results]
    if all(k == "timeout_exceeded" for k in kinds):
        return "timeout_exceeded"
    if any(k == "connection_reset" for k in kinds):
        return "connection_reset"
    if any(k == "malformed_response" for k in kinds):
        return "malformed_response"
    if all(k == "timeout_exceeded" or k == "engine_error" for k in kinds):
        return "timeout_exceeded"
    if not use_threads:
        return "single_thread_mode"
    return None


def plan_race_probe(endpoint: str, *, parameter: str, samples: int = 10,
                    body: str = "", headers: dict = None, method: str = "POST",
                    max_concurrent: int = 5, timeout: float = 10.0,
                    use_threads: bool = True, threshold: float = 0.005,
                    journal: dict = None, planner_gate=None, signer=None,
                    mutating: bool = True, run_id: str = None) -> models.RaceResult:
    """فحص سباق واحد متكامل — من البوابة إلى النتيجة الموقعة (إن وُجد signer)."""
    ev = []
    errors = []
    stats = {}

    # 1) المعامل — ذرة 4
    if parameter is None or str(parameter).strip() == "":
        return models.RaceResult(
            endpoint=str(endpoint or ""), method=str(method), parameter="",
            race_detected=False, timing_variance=0.0, request_count=0,
            evidence_chain=["plan:rejected empty_parameter",
                            "boundary:empty_parameter"],
            honest_boundary="empty_parameter",
            stats={"sent": 0, "ok": 0, "failed": 0}, run_id=run_id)

    parameter = str(parameter)
    try:
        parts = engine.split_url(endpoint or "")
        path_q = parts["target"]
    except engine.RaceEngineError as e:
        return models.RaceResult(
            endpoint=str(endpoint or ""), method=str(method), parameter=parameter,
            race_detected=False, timing_variance=0.0, request_count=0,
            evidence_chain=[f"plan:rejected bad url ({e})",
                            "boundary:engine_error"],
            honest_boundary="engine_error",
            stats={"sent": 0, "ok": 0, "failed": 0, "errors": [str(e)]},
            run_id=run_id)

    plan = {"url": str(endpoint), "method": str(method).upper(),
            "path": parts["path"], "query": parts["query"],
            "body": body or "", "parameter": parameter}

    # 2) بوابة المفردات الدائمة — الاختبار 5
    allowed, why = gates.destructive_vocabulary_gate(body or "", path_q)
    ev.append(f"vocabulary_gate:{'PASSED' if allowed else 'REJECTED ' + why}")
    if not allowed:
        return models.RaceResult(
            endpoint=str(endpoint), method=plan["method"], parameter=parameter,
            race_detected=False, timing_variance=0.0, request_count=0,
            evidence_chain=ev + ["boundary:destructive_blocked"],
            honest_boundary="destructive_blocked",
            stats={"sent": 0, "ok": 0, "failed": 0}, run_id=run_id)

    # 3) بوابة المخطط (نقطة تسجيل خارجية) — الاختبار 9
    if planner_gate is not None:
        try:
            p_allowed, p_why = planner_gate(plan)
            ev.append(f"planner_gate:{'PASSED' if p_allowed else 'REJECTED ' + str(p_why)}")
            if not p_allowed:
                return models.RaceResult(
                    endpoint=str(endpoint), method=plan["method"], parameter=parameter,
                    race_detected=False, timing_variance=0.0, request_count=0,
                    evidence_chain=ev + ["boundary:destructive_blocked"],
                    honest_boundary="destructive_blocked",
                    stats={"sent": 0, "ok": 0, "failed": 0}, run_id=run_id)
        except Exception as e:                                  # noqa: BLE001
            errors.append(f"planner_gate:{type(e).__name__}: {e}"[:200])
            ev.append("planner_gate:ERROR (fail-closed: no send without a verdict)")
            return models.RaceResult(
                endpoint=str(endpoint), method=plan["method"], parameter=parameter,
                race_detected=False, timing_variance=0.0, request_count=0,
                evidence_chain=ev + ["boundary:planner_gate_error"],
                honest_boundary="planner_gate_error",
                stats={"sent": 0, "ok": 0, "failed": 0, "errors": errors},
                run_id=run_id)

    # 4) السقف — استثناء مخصص يُسجل (القاعدة 5)
    try:
        cap = gates.enforce_budget(max_concurrent)
    except gates.RaceGateError as e:
        errors.append(str(e))
        return models.RaceResult(
            endpoint=str(endpoint), method=plan["method"], parameter=parameter,
            race_detected=False, timing_variance=0.0, request_count=0,
            evidence_chain=ev + [f"budget:REJECTED {e}", "boundary:budget_error"],
            honest_boundary="budget_error",
            stats={"sent": 0, "ok": 0, "failed": 0, "errors": errors},
            run_id=run_id)
    ev.append(f"budget:cap={cap}")
    stats["cap"] = cap

    # 5) الإرسال — مع journal قبل كل طلب
    n = int(samples) if samples and int(samples) > 0 else 0
    if n == 0:
        return models.RaceResult(
            endpoint=str(endpoint), method=plan["method"], parameter=parameter,
            race_detected=False, timing_variance=0.0, request_count=0,
            evidence_chain=ev + ["send:skipped zero samples", "boundary:empty_parameter"],
            honest_boundary="empty_parameter",
            stats={"sent": 0, "ok": 0, "failed": 0, "errors": errors},
            run_id=run_id)

    reqs = [{"method": plan["method"], "url": str(endpoint),
             "headers": dict(headers or {}), "body": body or ""}
            for _ in range(n)]
    journal_put = _journal_closure(journal, ev) if journal is not None else None
    if journal_put is not None:
        ev.append(f"journal:enabled dict#{id(journal):x}")

    try:
        results = engine.send_concurrent(
            reqs, max_concurrent=cap, timeout=timeout,
            use_threads=use_threads, journal_put=journal_put)
    except (engine.RaceEngineError, gates.RaceGateError) as e:
        errors.append(f"send:{type(e).__name__}: {e}"[:200])
        ev.append(f"send:ERROR {e}")
        return models.RaceResult(
            endpoint=str(endpoint), method=plan["method"], parameter=parameter,
            race_detected=False, timing_variance=0.0, request_count=0,
            evidence_chain=ev + ["boundary:engine_error"],
            honest_boundary="engine_error",
            stats={"sent": 0, "ok": 0, "failed": 0, "errors": errors},
            run_id=run_id)

    ok = [r for r in results if r.get("status") == 200]
    failed = [r for r in results if r.get("status") != 200]
    ev.append(f"send:{len(results)} sent, {len(ok)} ok, {len(failed)} failed")
    if journal_put is not None and journal is not None:
        ev.append(f"journal:{len(journal)} entries")

    # 6) التحليل على التوقيتات الفعلية — كلها معدِّلة (فحص سباق)
    timing_samples = analysis.samples_from_results(
        results, parameter=parameter, mutating=mutating)
    ana = analysis.analyze_timing(timing_samples, threshold=threshold)
    ev.append(f"analysis:variance={ana['timing_variance']:.8f} "
              f"race={ana['race_detected']} groups={ana['groups']}")
    stats.update({"sent": len(results), "ok": len(ok), "failed": len(failed),
                  "threshold": float(threshold),
                  "boundaries": sorted({str(r.get('honest_boundary'))
                                         for r in results if r.get('honest_boundary')})})
    if errors:
        stats["errors"] = errors

    boundary = _overall_boundary(results, use_threads)
    if boundary:
        ev.append(f"boundary:{boundary}")

    result = models.RaceResult(
        endpoint=str(endpoint), method=plan["method"], parameter=parameter,
        race_detected=bool(ana["race_detected"]),
        timing_variance=float(ana["timing_variance"]),
        request_count=len(results),
        evidence_chain=ev, honest_boundary=boundary,
        stats=stats, run_id=run_id)

    # 7) التوقيع (نقطة تسجيل خارجية — ذرة 8): يوقّع الحالة النهائية
    # المنشورة كما هي. النجاح لا يعدّل evidence_chain إطلاقاً — أي
    # إضافة لاحقة للسلسلة تبطل التوقيع، لذلك التوقيع الناجح يُعلن في
    # حقوله الخاصة (signature/public_key/merkle_root/algorithm)؛
    # الفشل وحده يُفصح داخل السلسلة (نتيجة غير موقعة — حد صادق).
    if signer is not None:
        try:
            sig = signer(models.serialize(result).encode("utf-8"))
            result.signature = sig.get("signature")
            result.public_key = sig.get("public_key")
            result.merkle_root = sig.get("merkle_root")
            result.signature_algorithm = sig.get("algorithm", "ed25519")
        except Exception as e:                                  # noqa: BLE001
            errors.append(f"signer:{type(e).__name__}: {e}"[:200])
            result.evidence_chain = list(result.evidence_chain) + [
                "signature:ERROR (unsigned — disclosed)"]
            result.stats["errors"] = result.stats.get("errors", []) + errors
    return result

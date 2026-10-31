#!/usr/bin/env python3
"""burhan/race/__init__.py — نقطة التسجيل في المحرك (AXIS-17).

البند الحرفي من بنية ORD-002: "__init__.py  # نقطة التسجيل في
المحرك". هذه هي النقطة الوحيدة التي يلمسها المحرك: يستدعي
register() مرة (lazy — من نقاط التسجيل الأربع عند الربط) فيحصل
على سياق خدمات الميزة؛ ثم يستدعي integration.plan_race_probe()
بخدمات ذلك السياق عند كل فحص سباق.

نقاط التسجيل الأربع (كل الخدمات تصل **معاملات صريحة** — لا استيراد
من المحرك داخل هذه الحزمة إطلاقًا؛ الاختبار 10):
  1) journal        — قاموس سجل الطلبات (تنسيق المحرك حرفيًا + تقنع
                      RT-05/item-3 عبر نسخة gates المعلنة).
  2) planner_gate   — بوابة المخطط (classify_operation من planner
                      المحرك تُمرَّر من الخارج).
  3) signer         — خطاف التوقيع (Merkle + Ed25519 من وحدات
                      المحرك المصدّقة تُمرَّر من الخارج — ذرة 8).
  4) bus/orchestrator — سياق التشغيل وeventbus عند الربط.

لا حالة عامة (القاعدة 4): register() يُرجع سياقًا يحتفظ به المستدعي.
"""
from __future__ import annotations

from . import analysis, engine, gates, integration, models

__version__ = "1.0.0"
__all__ = ["analysis", "engine", "gates", "integration", "models",
           "register", "wire_plan"]


def register(bus=None, *, journal=None, planner_gate=None, signer=None) -> dict:
    """التسجيل عبر النقاط الأربع — يُرجع سياق خدمات لا حالة داخل الحزمة.

    المحرك يستدعيها مرة (عند الربط lazy) ويحتفظ بالسياق؛ ثم يمرر
    أجزاءه إلى plan_race_probe عند كل فحص. غياب أي خدمة = الميزة
    تعمل بحدودها المعلنة (بلا journal/بلا بوابة مخطط/بلا توقيع)
    — كل غياب يظهر في evidence_chain للنتيجة.
    """
    return {
        "suite": "axis17-race",
        "version": __version__,
        "bus": bus,
        "journal": journal,
        "planner_gate": planner_gate,
        "signer": signer,
        "engine": "burhan.race.engine.send_concurrent",
        "probe": "burhan.race.integration.plan_race_probe",
        "limits": gates.gate_summary(),
    }


def wire_plan(ctx: dict, endpoint: str, **probe_kwargs):
    """تشغيل فحص سباق واحد بسياق تسجيل جاهز — مسار المحرك عند الربط.

    يبث أحداثًا على bus إن وُجد (RaceProbeStarted/Finished) بلا افتراضات.
    """
    probe_kwargs.setdefault("journal", ctx.get("journal"))
    probe_kwargs.setdefault("planner_gate", ctx.get("planner_gate"))
    probe_kwargs.setdefault("signer", ctx.get("signer"))
    bus = ctx.get("bus")
    if bus is not None and hasattr(bus, "emit"):
        try:
            bus.emit("RaceProbeStarted", endpoint=endpoint,
                     parameter=probe_kwargs.get("parameter", ""))
        except Exception:                                      # noqa: BLE001
            pass
    result = integration.plan_race_probe(endpoint, **probe_kwargs)
    if bus is not None and hasattr(bus, "emit"):
        try:
            bus.emit("RaceProbeFinished", endpoint=endpoint,
                     race_detected=result.race_detected,
                     request_count=result.request_count,
                     honest_boundary=result.honest_boundary)
        except Exception:                                      # noqa: BLE001
            pass
    return result

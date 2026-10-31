#!/usr/bin/env python3
"""burhan/race/models.py — نماذج بيانات المحور 17 (AXIS-17).

RaceResult: الحقول الثمانية المأمورة حرفيًا بالاختبار 7 —
endpoint, method, parameter, race_detected (bool), timing_variance
(float), request_count (int), evidence_chain (list), honest_boundary
(str|None) — مع حقول التوقيع الاختيارية (ذرة 8: Merkle + Ed25519
عبر خطاف signer خارجي؛ الوحدة نفسها لا تستورد المحرك).

RaceEvidence: خطوة إثبات واحدة (step/detail/at).

قيد الوحدة (N2): stdlib فقط — json/hashlib؛ لا حالة عامة؛ الدوال
نقية؛ كل خطأ -> RaceModelError -> يُسجل في التقرير.
"""
from __future__ import annotations

import hashlib
import json


class RaceModelError(ValueError):
    """استثناء نماذج المحور 17 — يُسجل في التقرير (القاعدة 5 من M2)."""


_REQUIRED_FIELDS = ("endpoint", "method", "parameter", "race_detected",
                    "timing_variance", "request_count", "evidence_chain",
                    "honest_boundary")

_TYPE_OK = {
    "endpoint": str, "method": str, "parameter": str,
    "race_detected": bool, "timing_variance": float,
    "request_count": int, "evidence_chain": list,
}


class RaceEvidence:
    """خطوة إثبات واحدة في سلسلة الأدلة — قابلة للتسلسل نقية."""

    __slots__ = ("step", "detail", "at")

    def __init__(self, step: str, detail: str, at: float):
        self.step = str(step)
        self.detail = str(detail)
        self.at = float(at)

    def to_dict(self) -> dict:
        return {"step": self.step, "detail": self.detail, "at": self.at}

    @staticmethod
    def from_dict(d: dict) -> "RaceEvidence":
        return RaceEvidence(d.get("step", ""), d.get("detail", ""),
                            float(d.get("at", 0.0)))


def _coerce(field, value):
    """تطبيع نوع الحقل بأمانة — الأنواع الحرفية لعقد الاختبار 7."""
    if field == "honest_boundary":                  # str|None — قبل أي وصول لجدول الأنواع
        if value is not None and not isinstance(value, str):
            raise RaceModelError(f"honest_boundary must be str|None, got {type(value).__name__}")
        return value
    t = _TYPE_OK[field]
    if field == "timing_variance" and not isinstance(value, (int, float)):
        raise RaceModelError(f"timing_variance must be a number, got {type(value).__name__}")
    if field == "request_count":
        if not isinstance(value, int) or isinstance(value, bool):
            raise RaceModelError(f"request_count must be int, got {type(value).__name__}")
    if field in ("endpoint", "method", "parameter") and not isinstance(value, str):
        raise RaceModelError(f"{field} must be str, got {type(value).__name__}")
    if field == "evidence_chain":
        if not isinstance(value, list):
            raise RaceModelError(f"evidence_chain must be list, got {type(value).__name__}")
    if field == "race_detected" and not isinstance(value, bool):
        raise RaceModelError(f"race_detected must be bool, got {type(value).__name__}")
    if t is float:
        return float(value)
    return value


class RaceResult:
    """نتيجة فحص سباق واحدة — قيمة معلنة لا كائن حي (لا حالة عامة)."""

    __slots__ = _REQUIRED_FIELDS + ("stats", "run_id", "merkle_root",
                                    "public_key", "signature",
                                    "signature_algorithm")

    def __init__(self, endpoint: str, method: str, parameter: str,
                 race_detected: bool, timing_variance: float,
                 request_count: int, evidence_chain: list,
                 honest_boundary=None, stats: dict = None,
                 run_id: str = None, merkle_root: str = None,
                 public_key: str = None, signature: str = None,
                 signature_algorithm: str = None):
        self.endpoint = _coerce("endpoint", endpoint)
        self.method = _coerce("method", method)
        self.parameter = _coerce("parameter", parameter)
        self.race_detected = _coerce("race_detected", race_detected)
        self.timing_variance = _coerce("timing_variance", timing_variance)
        self.request_count = _coerce("request_count", request_count)
        self.evidence_chain = _coerce("evidence_chain", list(evidence_chain or []))
        self.honest_boundary = _coerce("honest_boundary", honest_boundary)
        self.stats = dict(stats or {})
        self.run_id = run_id
        self.merkle_root = merkle_root
        self.public_key = public_key
        self.signature = signature
        self.signature_algorithm = signature_algorithm

    # ------------------------------------------------------------- تسلسل
    def evidence_dicts(self) -> list:
        """سلسلة الأدلة كقواميس — العناصر النصية تُلف كخطوات معلنة."""
        out = []
        for item in self.evidence_chain:
            if isinstance(item, RaceEvidence):
                out.append(item.to_dict())
            elif isinstance(item, dict):
                out.append({"step": item.get("step", ""),
                            "detail": item.get("detail", ""),
                            "at": item.get("at", 0.0)})
            else:
                out.append({"step": str(item), "detail": "", "at": 0.0})
        return out

    def to_dict(self) -> dict:
        """الحقول الثمانية الحرفية + الإحصاء والتوقيع إن وُجد."""
        d = {
            "endpoint": self.endpoint,
            "method": self.method,
            "parameter": self.parameter,
            "race_detected": bool(self.race_detected),
            "timing_variance": float(self.timing_variance),
            "request_count": int(self.request_count),
            "evidence_chain": list(self.evidence_chain),
            "honest_boundary": self.honest_boundary,
            "stats": dict(self.stats),
        }
        if self.run_id is not None:
            d["run_id"] = self.run_id
        if self.merkle_root is not None:
            d["merkle_root"] = self.merkle_root
        if self.public_key is not None:
            d["public_key"] = self.public_key
        if self.signature is not None:
            d["signature"] = self.signature
            d["signature_algorithm"] = self.signature_algorithm or "ed25519"
        return d

    @staticmethod
    def from_dict(d: dict) -> "RaceResult":
        """بناء نتيجة من قاموس — يرفض نقص الحقول الثمانية (fail-closed)."""
        missing = [f for f in _REQUIRED_FIELDS if f not in d]
        if missing:
            raise RaceModelError(f"RaceResult missing fields: {missing}")
        return RaceResult(
            endpoint=d["endpoint"], method=d["method"],
            parameter=d["parameter"], race_detected=d["race_detected"],
            timing_variance=d["timing_variance"],
            request_count=d["request_count"],
            evidence_chain=list(d["evidence_chain"]),
            honest_boundary=d.get("honest_boundary"),
            stats=d.get("stats") or {},
            run_id=d.get("run_id"),
            merkle_root=d.get("merkle_root"),
            public_key=d.get("public_key"),
            signature=d.get("signature"),
            signature_algorithm=d.get("signature_algorithm"))


def serialize(result: RaceResult) -> str:
    """تسلسل حتمي للنتيجة — canon: sorted keys، بلا مسافات زائدة."""
    return json.dumps(result.to_dict(), sort_keys=True, ensure_ascii=False)


def result_digest(result: RaceResult) -> str:
    """هضم sha256 للتمثيل المتسلسل — لأدلة المحطة (دالة نقية)."""
    return hashlib.sha256(serialize(result).encode("utf-8")).hexdigest()

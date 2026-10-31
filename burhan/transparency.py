"""Burhan Axis-12 — الحدود والشفافية (Boundaries & Transparency).

PROVENANCE (عقد M2 المُسجَّل — tests/test_axis12_transparency.py):
- العقد مُشتق من المواصفة المؤرشفة §12 (D1) + نطاق ترتيب البناء (D2)،
  مُعلن وقابل للإحلال عند أي حد محطة (سابقة المحور-4/8/11).
- المحرك نقي stdlib حصراً: hashlib + json + time. لا استيراد خارجي في
  هذا الملف حصراً — لا scipy ولا pyca ولا أي وحدة منصة أخرى.
- burhan/__init__.py يبقى فارغاً؛ المسار الساخن (المحاور 1-4) لا
  يستورد transparency أبداً؛ عقد النواة 227×19=4313 لا يُمس.
- مسار الوحدة transparency.py لا boundary.py: الأخير محرك v4.1.0
  (Phase V41-05) مغطى بجناح النواة في tests/run_tests.py — لا يُمس.
- validation-before-mutation: الأشكال البنيوية تُرفض بـValidationError
  قبل أي أثر؛ التقييمات تُسجَّل في سجل تدقيق إلحاقي (الكشف لا الصمت).

الأقسام:
  §1  أخطاء            TransparencyError → ValidationError
  §2  الفئات           الأربع عشرة الحرفية §12.1 + دلالاتها الموثقة
  §3  سجل الحدود       BoundaryRecord = (Node, Reason, Category,
                        Timestamp, Confidence) — معرّف محتوى-عنوان،
                        seq ترتيبي، الطابع حقل طائر خارج كل هضم
  §4  مخزن الأدلة      attach/resolve — معرّفات محتوى-عنوان «E-»
  §5  الادعاءات        make_claim + التحقق الشكلي
  §6  القواعد الست     RULES R1-R6 بنصوص §12.2 الحرفية + فحوص الأنواع
                        (إعادة الحساب من المواد الخام — لا ثقة بالتسميات)
  §7  المحرك           BoundaryEngine — الواجهة الحرفية §12.3:
                        record/query/coverage/verify_claim/
                        detect_hallucination/export + attach/resolve
  §8  التصدير والاستيراد export (ختم boundary_digest فوق السجلات حصراً)
                        + import_export (دورة كاملة بفحص سلامة المعرّفات)

إفصاحات الوحدة (معلنة لا مخفية — N1..N8 في عقد الجناح):
  N1  الواجهة الحرفية §12.3 بتوقيعاتها؛ attach/resolve/make_claim/
      import_export آلية التغذية المعلنة (بدونها لا حلّ آلي للدليل).
  N2  فحص تناقض كوني: حد مسجل على موضوع الادعاء (مطابقة حرفية)
      يسقط الادعاء الإيجابي أياً كان شكل أدلته — جرد الحدود هو
      حقيقة «ما لم يحدث».
  N3  الساعة: time.time() في موضع واحد معلن — record() بطابع None؛
      مع قيد رتابة داخل المحرك (لا رجوع). الطابع حقل طائر: يحمله
      السجل والتصدير ويستثنيه boundary_digest حصراً.
  N4  تخطيط واحد-لواحد: verification→R1 … completeness→R6.
  N5  إعادة الحساب: triple_run تُفحص بياناتها لا علمها؛ inventory
      يُطابق هضمه وعدده الحيّين؛ measurement تُقارن قيمتها حرفياً.
  N6  O(1) للتسجيل: إلحاق + فهرس قاموسي (لا مسح)؛ O(|Records|)
      لquery/coverage/export.
  N7  سجل تدقيق إلحاقي: كل verify_claim وكل detect_hallucination
      يُسجَّل بنتيجته؛ خارج boundary_digest؛ لا خصم بالمعرّف.
  N8  موضوعية الدليل: artifact يحمل subject يجب أن يطابق موضوع
      الادعاء حرفياً؛ inventory بلا subject يُفحص حيّاً (N5).
"""
from __future__ import annotations

import hashlib
import json
import time

# ============================================================ §1 الأخطاء


class TransparencyError(ValueError):
    """قاعدة أخطاء المحور-12."""


class ValidationError(TransparencyError):
    """رفض شكلي قبل أي أثر (validation-before-mutation)."""


# ============================================================ §2 الفئات

OUT_OF_SCOPE = "OUT_OF_SCOPE"
PRECONDITION_FAILED = "PRECONDITION_FAILED"
RESOURCE_EXHAUSTED = "RESOURCE_EXHAUSTED"
DETECTION_AVOIDED = "DETECTION_AVOIDED"
TIME_LIMIT = "TIME_LIMIT"
SAFETY_GUARD = "SAFETY_GUARD"
UNKNOWN_PROTOCOL = "UNKNOWN_PROTOCOL"
AUTH_REQUIRED = "AUTH_REQUIRED"
ENCRYPTION_UNTRAVERSABLE = "ENCRYPTION_UNTRAVERSABLE"
HARDWARE_LIMIT = "HARDWARE_LIMIT"
NETWORK_ISOLATED = "NETWORK_ISOLATED"
POLICY_RESTRICTED = "POLICY_RESTRICTED"
CAPABILITY_MISSING = "CAPABILITY_MISSING"
UNSUPPORTED_PLATFORM = "UNSUPPORTED_PLATFORM"

CATEGORIES = (
    OUT_OF_SCOPE, PRECONDITION_FAILED, RESOURCE_EXHAUSTED,
    DETECTION_AVOIDED, TIME_LIMIT, SAFETY_GUARD, UNKNOWN_PROTOCOL,
    AUTH_REQUIRED, ENCRYPTION_UNTRAVERSABLE, HARDWARE_LIMIT,
    NETWORK_ISOLATED, POLICY_RESTRICTED, CAPABILITY_MISSING,
    UNSUPPORTED_PLATFORM,
)

CATEGORY_MEANINGS = {
    OUT_OF_SCOPE: "خارج النطاق",
    PRECONDITION_FAILED: "شرط مسبق فشل",
    RESOURCE_EXHAUSTED: "موارد مستنفدة",
    DETECTION_AVOIDED: "تجنب كشف",
    TIME_LIMIT: "حد زمني",
    SAFETY_GUARD: "حارس أمان",
    UNKNOWN_PROTOCOL: "بروتوكول غير معروف",
    AUTH_REQUIRED: "مصادقة مطلوبة",
    ENCRYPTION_UNTRAVERSABLE: "تشفير غير قابل للاجتياز",
    HARDWARE_LIMIT: "حد عتادي",
    NETWORK_ISOLATED: "شبكة معزولة",
    POLICY_RESTRICTED: "سياسة مقيّدة",
    CAPABILITY_MISSING: "قدرة مفقودة",
    UNSUPPORTED_PLATFORM: "منصة غير مدعومة",
}

# الحقول الطائرة: يحملها السجل والتصدير ويستثنيها boundary_digest (N3)
VOLATILE_FIELDS = ("timestamp",)

# القواعد الست — النصوص الحرفية §12.2 (بوابة عدم الادعاء)
RULES = {
    "R1": {"kind": "verification",
           "text": "لا ادعاء تحقق بدون دليل"},
    "R2": {"kind": "coverage",
           "text": "لا ادعاء تغطية بدون قياس"},
    "R3": {"kind": "determinism",
           "text": "لا ادعاء حتمية بدون 3 تشغيلات"},
    "R4": {"kind": "honesty",
           "text": "لا ادعاء أمانة بدون مقارنة بخط أساس"},
    "R5": {"kind": "capability",
           "text": "لا ادعاء قدرة بدون شرط مسبق مُتحقق"},
    "R6": {"kind": "completeness",
           "text": "لا ادعاء اكتمال بدون جرد حدود"},
}

CLAIM_KINDS = ("verification", "coverage", "determinism", "honesty",
               "capability", "completeness")

EVIDENCE_KINDS = ("observation", "measurement", "triple_run",
                  "baseline_comparison", "precondition", "inventory")

_KIND_TO_RULE = {spec["kind"]: rid for rid, spec in RULES.items()}


# ============================================================ أدوات داخلية


def _canon(obj) -> str:
    """التمثيل القانوني: JSON قياسي مفاتيحه مرتبة — أساس كل معرّف
    وهضم في هذه الوحدة."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"))


def _is_real_number(v) -> bool:
    """رقم حقيقي حصراً — bool ليس رقماً هنا (عقد معلن)."""
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _rid(node: str, reason: str, category: str) -> str:
    """معرّف سجل الحدود: محتوى-عنوان (N6 — بلا عدّادات)."""
    return "B12-" + hashlib.sha256(
        f"{node}|{reason}|{category}".encode("utf-8")).hexdigest()[:12]


def _aid(kind: str, content) -> str:
    """معرّف الدليل: محتوى-عنوان فوق (kind, content)."""
    return "E-" + hashlib.sha256(
        _canon({"kind": kind, "content": content}).encode(
            "utf-8")).hexdigest()[:12]


def _cid(claim_core: dict) -> str:
    """معرّف الادعاء: محتوى-عنوان فوق جوهر الادعاء (بلا المعرّف)."""
    return "C-" + hashlib.sha256(
        _canon(claim_core).encode("utf-8")).hexdigest()[:12]


# ============================================================ §3 سجل الحدود


class BoundaryRecord:
    """حد معرفة واحد — البيانات الخمسة الحرفية §12.1 + معرّف وترتيب.

    Plain data, JSON-safe؛ timestamp حقل طائر (خارج كل هضم — N3)."""

    __slots__ = ("node", "reason", "category", "timestamp", "confidence",
                 "id", "seq")

    def __init__(self, node: str, reason: str, category: str,
                 timestamp: float, confidence: float, seq: int):
        self.node = node
        self.reason = reason
        self.category = category
        self.timestamp = timestamp
        self.confidence = confidence
        self.seq = seq
        self.id = _rid(node, reason, category)

    def to_dict(self) -> dict:
        return {"id": self.id, "seq": self.seq, "node": self.node,
                "reason": self.reason, "category": self.category,
                "confidence": self.confidence, "timestamp": self.timestamp}

    def __repr__(self) -> str:  # pragma: no cover — تشخيصي فقط
        return (f"BoundaryRecord({self.id}, node={self.node!r}, "
                f"category={self.category}, seq={self.seq})")


# ============================================================ §5 الادعاءات

_RESERVED_CLAIM_KEYS = {"claim_id", "supported", "rule", "reasons",
                        "is_hallucination", "evidence_total",
                        "evidence_resolved"}


def make_claim(kind: str, statement: str, evidence=(), subject: str = "",
               **fields) -> dict:
    """بناء ادعاء مُتحقق شكلاً (الرفض قبل أي أثر). الحقول الإضافية
    JSON-safe ولا تطأ مفاتيح النتيجة المحجوزة."""
    if kind not in CLAIM_KINDS:
        raise ValidationError(
            f"unknown claim kind {kind!r} (valid: {', '.join(CLAIM_KINDS)})")
    if not isinstance(statement, str) or not statement:
        raise ValidationError("claim statement must be a non-empty string")
    if isinstance(evidence, str) or not isinstance(evidence, (list, tuple)):
        raise ValidationError(
            "claim evidence must be a list/tuple of artifact ids")
    ev = list(evidence)
    for ref in ev:
        if not isinstance(ref, str):
            raise ValidationError(f"evidence ref {ref!r} is not a string")
    if not isinstance(subject, str):
        raise ValidationError("claim subject must be a string")
    for k in fields:
        if k in _RESERVED_CLAIM_KEYS:
            raise ValidationError(f"claim field {k!r} is reserved")
    core = {"kind": kind, "statement": statement, "evidence": ev,
            "subject": subject}
    core.update(fields)
    try:
        _canon(core)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"claim fields must be JSON-safe: {exc}")
    core["claim_id"] = _cid({"kind": kind, "statement": statement,
                             "evidence": ev, "subject": subject,
                             "extra": {k: v for k, v in fields.items()}})
    return core


# ============================================================ §7 المحرك


class BoundaryEngine:
    """سجل الحدود + مخزن الأدلة + بوابة عدم الادعاء + سجل تدقيق.

    الواجهة الحرفية §12.3: record/query/coverage/verify_claim/
    detect_hallucination/export — وآلية التغذية المعلنة N1:
    attach/resolve. التسجيل O(1) (إلحاق + فهرس — N6)."""

    def __init__(self):
        self.records: list[BoundaryRecord] = []
        self._index: dict = {}
        self._evidence: dict = {}
        self._evidence_order: list[str] = []
        self.claims: list[dict] = []

    # -------------------------------------------------- §3 record
    def record(self, node: str, reason: str, category: str, *,
               confidence: float = 1.0, timestamp=None) -> BoundaryRecord:
        """تسجيل حد — §12.1. قابل للتكرار: نفس الثلاثة يعيد السجل
        نفسه (الأول يفوز — O(1) بلا مسح)."""
        if not isinstance(node, str) or not node:
            raise ValidationError("node must be a non-empty string")
        if not isinstance(reason, str) or not reason:
            raise ValidationError("reason must be a non-empty string")
        if category not in CATEGORIES:
            raise ValidationError(
                f"unknown category {category!r} "
                f"(valid: {', '.join(CATEGORIES)})")
        if not _is_real_number(confidence) or not (0.0 <= confidence <= 1.0):
            raise ValidationError(
                f"confidence must be a real number in [0,1], "
                f"got {confidence!r}")
        if timestamp is None:
            ts = time.time()
            if self.records and ts < self.records[-1].timestamp:
                ts = self.records[-1].timestamp   # رتابة داخل المحرك (N3)
        else:
            if not _is_real_number(timestamp) or timestamp < 0:
                raise ValidationError(
                    f"timestamp must be a non-negative real, "
                    f"got {timestamp!r}")
            ts = timestamp
        key = (node, reason, category)
        hit = self._index.get(key)
        if hit is not None:
            return hit
        rec = BoundaryRecord(node, reason, category, ts, float(confidence),
                             len(self.records))
        self._index[key] = rec
        self.records.append(rec)
        return rec

    # -------------------------------------------------- query
    def query(self, category: str) -> list:
        """سجلات فئة بعينها بترتيب الإدراج؛ الفئة المجهولة تُرفض."""
        if category not in CATEGORIES:
            raise ValidationError(
                f"unknown category {category!r} "
                f"(valid: {', '.join(CATEGORIES)})")
        return [r for r in self.records if r.category == category]

    # -------------------------------------------------- coverage
    def coverage(self) -> dict:
        """تقرير التغطية — قياس للسجل حصراً لا شهادة (R2 من الأساس):
        الأصفار حاضرة والغياب معلن بترتيب المواصفة."""
        per = {c: 0 for c in CATEGORIES}
        for r in self.records:
            per[r.category] += 1
        return {
            "per_category": per,
            "total_records": len(self.records),
            "distinct_nodes": len({r.node for r in self.records}),
            "empty_categories": [c for c in CATEGORIES if per[c] == 0],
            "measured_from": "boundary-registry",
        }

    # -------------------------------------------------- §4 evidence
    def attach(self, kind: str, content) -> str:
        """إيداع دليل — معرّف محتوى-عنوان؛ قابل للتكرار (نفس المحتوى
        = نفس المعرّف، لا تكرار في المخزن)."""
        if kind not in EVIDENCE_KINDS:
            raise ValidationError(
                f"unknown evidence kind {kind!r} "
                f"(valid: {', '.join(EVIDENCE_KINDS)})")
        try:
            _canon(content)
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"evidence content must be JSON-safe: {exc}")
        aid = _aid(kind, content)
        if aid not in self._evidence:
            self._evidence[aid] = {"id": aid, "kind": kind,
                                   "content": content}
            self._evidence_order.append(aid)
        return aid

    def resolve(self, ref: str):
        """فكّ مرجع دليل — None إذا لم يحلّ (الكشف لا الانفجار)."""
        if not isinstance(ref, str):
            return None
        art = self._evidence.get(ref)
        if art is None:
            return None
        return {"id": art["id"], "kind": art["kind"],
                "content": art["content"]}

    # -------------------------------------------------- §6 البوابة
    def _boundary_digest(self) -> str:
        """ختم جرد الحدود: sha256 فوق التمثيل القانوني للسجلات بحقول
        ثابتة حصراً — الطابع الطائر مستثنى (N3)، الأدلة والادعاءات
        خارج الختم (لا دائرية — N7)."""
        core = [{"id": r.id, "seq": r.seq, "node": r.node,
                 "reason": r.reason, "category": r.category,
                 "confidence": r.confidence} for r in self.records]
        return hashlib.sha256(_canon(core).encode("utf-8")).hexdigest()

    @staticmethod
    def _validate_claim_shape(claim) -> None:
        """التحقق الشكلي قبل أي أثر — الادعاءات الخام تُفحص هنا
        (make_claim يفحص عند البناء، والمحرك يفحص عند التقييم)."""
        if not isinstance(claim, dict):
            raise ValidationError("claim must be a dict")
        if claim.get("kind") not in CLAIM_KINDS:
            raise ValidationError(
                f"unknown claim kind {claim.get('kind')!r} "
                f"(valid: {', '.join(CLAIM_KINDS)})")
        st = claim.get("statement")
        if not isinstance(st, str) or not st:
            raise ValidationError("claim statement must be a non-empty string")
        ev = claim.get("evidence", [])
        if isinstance(ev, str) or not isinstance(ev, (list, tuple)):
            raise ValidationError(
                "claim evidence must be a list/tuple of artifact ids")
        for ref in ev:
            if not isinstance(ref, str):
                raise ValidationError(f"evidence ref {ref!r} is not a string")
        if not isinstance(claim.get("subject", ""), str):
            raise ValidationError("claim subject must be a string")
        try:
            _canon(claim)
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"claim must be JSON-safe: {exc}")

    def _evaluate(self, claim: dict) -> dict:
        """تقييم الادعاء بلا كتابة — قلب البوابة §12.2: «إذا ادعاء ∉
        {مدعوم بدليل}: أبلغ عن Hallucination». أربع طبقات معلنة:
        حلّ الأدلة → موضوعية الدليل (N8) → تناقض الحدود (N2) →
        قاعدة النوع (N4/N5 — إعادة حساب من المواد الخام)."""
        reasons: list[str] = []
        rule = _KIND_TO_RULE[claim["kind"]]
        # (1) حلّ الأدلة
        resolved = []
        for ref in claim.get("evidence", []):
            art = self.resolve(ref)
            if art is None:
                reasons.append(f"evidence does not resolve: {ref}")
            else:
                resolved.append(art)
        # (2) موضوعية الدليل (N8)
        subject = claim.get("subject", "")
        for art in resolved:
            content = art["content"]
            sub = content.get("subject") if isinstance(content, dict) \
                else None
            if sub is not None and subject and sub != subject:
                reasons.append(
                    f"evidence {art['id']} is about subject {sub!r}, "
                    f"not the claim subject {subject!r}")
        # (3) تناقض الحدود (N2) — الحد المسجل على الموضوع نفسه يسقط
        #     الادعاء الإيجابي عنه، أياً كان شكل أدلته
        if subject:
            for r in self.records:
                if r.node == subject:
                    reasons.append(
                        f"boundary {r.id} ({r.category}: "
                        f"{CATEGORY_MEANINGS[r.category]}) contradicts "
                        f"any positive claim on node {subject!r}")
                    break
        # (4) قاعدة النوع — إعادة الحساب من المواد الخام (N5)
        kind = claim["kind"]
        if kind == "verification":
            if not any(a["kind"] == "observation" for a in resolved):
                reasons.append(
                    "R1: no resolvable observation evidence "
                    "(لا ادعاء تحقق بدون دليل)")
        elif kind == "coverage":
            meas = [a for a in resolved if a["kind"] == "measurement"]
            if not meas:
                reasons.append(
                    "R2: no resolvable measurement artifact "
                    "(لا ادعاء تغطية بدون قياس)")
            elif "value" in claim:
                vals = [a["content"].get("value") for a in meas
                        if isinstance(a["content"], dict)]
                if not any(v == claim["value"] for v in vals):
                    reasons.append(
                        f"R2: claimed value {claim['value']!r} does not "
                        f"match any measured value {vals!r}")
        elif kind == "determinism":
            tris = [a for a in resolved if a["kind"] == "triple_run"]
            if not tris:
                reasons.append(
                    "R3: no resolvable triple_run artifact "
                    "(لا ادعاء حتمية بدون 3 تشغيلات)")
            else:
                ok = False
                for a in tris:
                    runs = a["content"].get("runs") \
                        if isinstance(a["content"], dict) else None
                    if (isinstance(runs, list) and len(runs) >= 3
                            and len({json.dumps(x, sort_keys=True)
                                     for x in runs}) == 1):
                        ok = True
                if not ok:
                    reasons.append(
                        "R3: no triple_run artifact with >=3 identical "
                        "runs — recomputed from raw runs, labels ignored")
        elif kind == "honesty":
            baselines = [a for a in resolved
                         if a["kind"] == "baseline_comparison"]
            if not baselines:
                reasons.append(
                    "R4: no resolvable baseline_comparison artifact "
                    "(لا ادعاء أمانة بدون مقارنة بخط أساس)")
            elif not any(
                    isinstance(a["content"], dict)
                    and a["content"].get("compare_rc") == 0
                    for a in baselines):
                reasons.append(
                    "R4: the baseline comparison measured drift "
                    "(compare_rc != 0) — honesty is refuted by measurement")
        elif kind == "capability":
            pres = [a for a in resolved if a["kind"] == "precondition"]
            if not pres:
                reasons.append(
                    "R5: no resolvable precondition artifact "
                    "(لا ادعاء قدرة بدون شرط مسبق مُتحقق)")
            elif not any(
                    isinstance(a["content"], dict)
                    and a["content"].get("status") == "verified"
                    for a in pres):
                reasons.append(
                    "R5: no artifact with a verified precondition "
                    "(شرط مسبق مُتحقق)")
        elif kind == "completeness":
            invs = [a for a in resolved if a["kind"] == "inventory"]
            if not invs:
                reasons.append(
                    "R6: no resolvable boundary inventory artifact "
                    "(لا ادعاء اكتمال بدون جرد حدود)")
            else:
                if not self.records:
                    reasons.append(
                        "R6: the boundary registry is empty — completeness "
                        "over zero known limits is not claimable")
                else:
                    cur = self._boundary_digest()
                    n = len(self.records)
                    live = any(
                        isinstance(a["content"], dict)
                        and a["content"].get("digest") == cur
                        and a["content"].get("records") == n
                        for a in invs)
                    if not live:
                        reasons.append(
                            "R6: no LIVE inventory — digest/count must "
                            "match the current registry (recomputed)")
        return {
            "claim_id": claim.get("claim_id", ""),
            "kind": kind,
            "statement": claim["statement"],
            "subject": subject,
            "supported": not reasons,
            "rule": rule,
            "reasons": reasons,
            "evidence_total": len(claim.get("evidence", [])),
            "evidence_resolved": len(resolved),
        }

    def verify_claim(self, claim) -> dict:
        """§12.3 — تقييم الادعاء وتسجيل النتيجة في سجل التدقيق (N7)."""
        self._validate_claim_shape(claim)
        verdict = self._evaluate(claim)
        self.claims.append(dict(verdict))
        return verdict

    def detect_hallucination(self, claim) -> dict:
        """§12.3 — «إذا ادعاء ∉ {مدعوم بدليل}: أبلغ عن Hallucination».
        التقرير يسجَّل في سجل التدقيق أيضاً (الكشف نفسه دليل — N7)."""
        self._validate_claim_shape(claim)
        verdict = self._evaluate(claim)
        report = {
            "claim_id": verdict["claim_id"],
            "is_hallucination": not verdict["supported"],
            "rule": verdict["rule"],
            "statement": verdict["statement"],
            "reasons": verdict["reasons"],
        }
        self.claims.append(dict(report))
        return report

    # -------------------------------------------------- §8 export
    def export(self) -> dict:
        """التصدير الكامل — JSON-safe؛ ختم boundary_digest فوق جرد
        الحدود حصراً (الطوابع الطائرة خارجه — N3/N7)."""
        return {
            "module": "burhan.transparency",
            "version": 1,
            "records": [r.to_dict() for r in self.records],
            "coverage": self.coverage(),
            "evidence": [dict(self._evidence[aid])
                         for aid in self._evidence_order],
            "claims": [dict(c) for c in self.claims],
            "boundary_digest": self._boundary_digest(),
        }


# ============================================================ §8 الاستيراد


def import_export(dump: dict) -> BoundaryEngine:
    """الدورة الكاملة: إعادة بناء المحرك من تصديره — بفحص سلامة
    المعرّفات (المعرّف = هاش المحتوى؛ التحريف دون إصلاح المعرّف
    يُرفض قبل أي أثر)."""
    if not isinstance(dump, dict):
        raise ValidationError("export dump must be a dict")
    eng = BoundaryEngine()
    # السجلات — بترتيب التصدير (ترتيب الإدراج) وفحص سلامة كل معرّف
    for rd in dump.get("records", []):
        try:
            node, reason, category = rd["node"], rd["reason"], rd["category"]
            confidence = rd.get("confidence", 1.0)
            timestamp = rd.get("timestamp")
        except (KeyError, TypeError) as exc:
            raise ValidationError(f"malformed record entry: {exc}")
        if rd.get("id") != _rid(node, reason, category):
            raise ValidationError(
                f"record id {rd.get('id')!r} does not match its content — "
                f"tampered export rejected")
        eng.record(node, reason, category, confidence=confidence,
                   timestamp=timestamp)
    # الأدلة — فحص سلامة المعرّف قبل الإيداع
    for a in dump.get("evidence", []):
        try:
            kind, content = a["kind"], a["content"]
        except (KeyError, TypeError) as exc:
            raise ValidationError(f"malformed evidence entry: {exc}")
        if a.get("id") != _aid(kind, content):
            raise ValidationError(
                f"evidence id {a.get('id')!r} does not match its content — "
                f"tampered export rejected")
        eng.attach(kind, content)
    # سجل التدقيق — يُستعاد كما هو (بيانات، لا إعادة حساب)
    for c in dump.get("claims", []):
        if not isinstance(c, dict):
            raise ValidationError("ledger entries must be dicts")
        eng.claims.append(dict(c))
    return eng

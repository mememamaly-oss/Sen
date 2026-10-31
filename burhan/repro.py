"""Burhan Axis-11 — الحتمية والقابلية للتكرار (Determinism &
Reproducibility).

PROVENANCE (عقد M2 المُسجَّل — تصحيح الوثائق 2026-10-31: المرجع القديم "tests/test_axis11_repro.py" أشار إلى ملف لم يُودَع قط في هذا المستودع (git log --all على المسار فارغ)؛ المثبِّت المُودَع فعلاً منذ بوابة Part-0 (2026-10-30) هو tests/test_repro_prng_isolation.py):
- العقد مُشتق من المواصفة المؤرشفة §11 (D1) + قائمة نطاق أمر البناء
  (D2)، مُعلن وقابل للإحلال عند أي حد محطة (سابقة المحور-4/8).
- المحرك نقي stdlib حصراً: hashlib + json + os + sys + platform +
  importlib.metadata (للتثبيت G3). لا scipy ولا pyca ولا أي استيراد
  خارجي في هذا الملف حصراً — burhan.proof يُستورد داخل أقسام
  default_pipeline وحدها (وحدة مغلقة، المحور-8).
- burhan/__init__.py يبقى فارغاً؛ المسار الساخن لا يستورد repro
  أبداً؛ عقد النواة 227×19=4313 لا يُمس.
- validation-before-mutation: العقود البنيوية تُرفض بـValidationError
  قبل أي أثر؛ الانحراف الدلالي (حتمية مكسورة) يُرفع DriftError أو
  يُكشف بالاسم — لا صمت.
- لا ساعة نظام في أي مسار حتمي هنا (عقد when صريح في proof عند
  الحاجة)؛ لا زمن حائطي في أي هضم (انضباط المحور-11 على نفسه).

الأقسام:
  §1  أخطاء            ReproError → ValidationError / DriftError
  §2  PRNG مُبذَّر      SeededPRNG — SplitMix64 خالص (ثوابت معلنة)؛
                        derive_stream(seed, label) — تيار مستقل لكل
                        خطوة (كل العشوائية من البذرة الأم حصراً — G1)
                        [إفصاح أمني 2026-10-30 (بوابة Part-0): ليست
                        CSPRNG قطعاً — حتمية بالتصميم لإعادة التشغيل
                        والتحقق فقط؛ المخرجات لا تصلح ولا تُستخدم كمادة
                        مفتاح لحماية أسرار حقيقية — انظر الإفصاح N-k
                        والاختبار العازل tests/test_repro_prng_isolation.py]
  §3  قياسية المدخلات  canonical_input / input_digest (G5) — bytes
                        كما هي؛ غيرها JSON قياسي
  §4  هضم التدفق       flow_lines / flow_digest / flow_merkle
                        (أوراق = SHA-256(سطر الخطوة)؛ جذر §8.2 —
                        مضاعفة الأخيرة للفرد، اصطلاح CT المعلن)
  §5  فروق وتحقيق     diff / investigate / verify_determinism /
                        require_determinism (§11.3: إذا Diff≠∅ →
                        تحقيق آلي)
  §6  البيئة           PINNED_PACKAGES / freeze_environment /
                        restore_environment (G3+G4)
  §7  المنفّذ          DeterministicExecutor — خطوات نقية
                        fn(payload, rng)->bytes؛ بذرة الحالة أو
                        المعامل الصريح (لا يغير الحالة)
  §8  التدفق الافتراضي default_pipeline — ست خطوات فوق
                        burhan.proof (المحور-8 المغلق)

إفصاحات الوحدة (معلنة لا مخفية):
  N-a (SplitMix64) — ثوابت عيدرون المنشورة: GOLDEN=0x9E3779B97F4A7C15،
      C1=0xBF58476D1CE4E5B9 (بعد >>30)، C2=0x94D049BB133111EB (بعد
      >>27)، الإزاحة الختامية >>31. حتمي خالص عبر أي بايثون/منصة.
      randbelow عقد مبسط معلن: u64 % n.
  N-b (الاشتقاق) — البذرة الأولية لتيار الخطوة = أول 8 بايت من
      SHA-256(f"{seed}:{label}") — قد تكون 0 نظرياً (2^-64): المسار
      الداخلي _from_raw يقبلها (عقد الاشتقاق)؛ عقد الاستخدام العام
      لSeededPRNG يظل [1, 2^64).
  N-c (التثبيت) — record_sha256 يُحتسب من ملف RECORD داخل dist-info
      عبر importlib.metadata (السمة _path — الوصول الوحيد المتاح في
      stdlib لمسار المثبت؛ مستقر عبر 3.8+).
  N-d (الاستعادة) — restore_environment يضبط PYTHONHASHSEED من
      المواصفة (None→"0": القيمة الحتمية الافتراضية — معلن) ويرجع
      أوجه اختلاف البيئة الحالية عن المواصفة بعد الضبط؛ hash_seed
      لا يُدرج في الاختلافات أبداً (يضبط حتماً). cwd/python/pinned
      لا تُضبط داخل عملية قائمة — تُكشف بالاسم (الكشف لا الصمت).
  N-e (first_diff) — ترتيب المسارات المفحوصة: input_sha256 → seed →
      steps → flow_digest → flow_merkle_hex → final_payload.
  N-f (verify_determinism) — يتطلب قائمة بطول 2+ (قائمة أقصر →
      ValidationError؛ الحتمية برهان مقارنة لا إعلان).
  N-g (الخطوة canonical) — identity مُعلنة: أول ما يُهضم في السجل هو
      المدخل القانوني نفسه (نقطة الربط)؛ الخطوات قد تتجاهل rng.
  N-h (AAD في default_pipeline) — aad = أول 16 بايت من
      SHA-256(الحمولة الحالية بعد التوقيع) — أي انحراف في الخطوات
      السابقة يكسر فك التشفير في verify (ربط تسلسلي مقصود).
  N-i (diff حي) — merkle_equal/digest_equal يُعاد حسابهما من سجل
      الخطوات الحالي في كل مقارنة (لا ثقة بالحقول المجمّعة):
      تحريف متزامن للسجل والجذر المخزن يُكشف من المواد الخام.
  N-j (sys_flags) — الحقول العددية حصراً (رايات بايثون)؛
      count/index الموروثتان عن struct-sequence ليستا رايات
      فتُستبعدان من المواصفة القياسية.
  N-k (ليست CSPRNG — بوابة Part-0، 2026-10-30): مخرجات SeededPRNG/
      derive_stream لا تحمي أي بيانات حساسة حقيقية ولا يجب أن تحميها:
      لا مستهلك تشغيلي واحد خارج هذا الملف (مثبت باختبار grep:
      tests/test_repro_prng_isolation.py)؛ المسار التاريخي الذي أسيء
      استخدامه (audit-rb-1، أُغلق 2026-10-21 في burhan/audit.py) أزيل
      نهائياً؛ مسار الأسرار الحقيقي هو burhan/vault.py (مفاتيح
      os.urandom + AEAD عبر مكتبة cryptography) المستقل تماماً.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

__all__ = [
    "ReproError", "ValidationError", "DriftError",
    "SeededPRNG", "derive_stream",
    "canonical_input", "input_digest",
    "flow_lines", "flow_digest", "flow_merkle",
    "diff", "investigate", "verify_determinism", "require_determinism",
    "PINNED_PACKAGES", "freeze_environment", "restore_environment",
    "DeterministicExecutor", "default_pipeline",
]


# ============================================================ §1 الأخطاء
class ReproError(ValueError):
    """قاعدة أخطاء طبقة الحتمية (ValueError عمداً — عقد M1)."""


class ValidationError(ReproError):
    """رفض ذري لعقد بنيوي فاسد (نوع/طول/حدود) قبل أي أثر حالة."""


class DriftError(ReproError):
    """انحراف حتمية مُثبت (تشغيلان يجب أن يتطابقا ولم يتطابقا)."""


_MASK64 = (1 << 64) - 1


def _require_seed(value, name="seed") -> int:
    """int في [1, 2^64) — bool مرفوض (صنو int لكنه ليس بذرة)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(
            f"{name}: expected int, got {type(value).__name__}")
    if not 1 <= value <= _MASK64:
        raise ValidationError(f"{name}: expected int in [1, 2^64), got {value}")
    return value


def _require_label(value) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError(
            f"label: expected non-empty str, got {type(value).__name__}")
    return value


# ============================================================ §2 PRNG
# SplitMix64 — ثوابت عيدرون المنشورة (إفصاح N-a).
_GOLDEN = 0x9E3779B97F4A7C15
_MIX1 = 0xBF58476D1CE4E5B9
_MIX2 = 0x94D049BB133111EB


class SeededPRNG:
    """مولد حتمي خالص: البذرة الوحيدة مصدر التسلسل كله (G1).

    SECURITY DISCLOSURE (Part-0 gate, 2026-10-30): NOT a CSPRNG —
    deterministic by design for replay only — never use output as a
    real secret-protection key. SplitMix64's determinism IS the feature
    (identical re-runs prove determinism); the isolation contract is
    pinned by tests/test_repro_prng_isolation.py: no runtime module
    outside this file consumes these streams, and the real secret paths
    (vault/proof/audit/orchestrator) carry no repro dependency."""

    __slots__ = ("_s",)

    def __init__(self, seed: int):
        seed = _require_seed(seed, "seed")
        self._s = seed & _MASK64

    @classmethod
    def _from_raw(cls, u64: int):
        """مسار داخلي للاشتقاق — يقبل 0 (إفصاح N-b): القيمة المشتقة
        نظرياً 2^-64 قد تكون صفراً؛ عقد الاستخدام العام يظل [1,2^64)."""
        obj = cls.__new__(cls)
        if not isinstance(u64, int) or isinstance(u64, bool) \
                or not 0 <= u64 <= _MASK64:
            raise ValidationError("derive: raw seed out of range")
        obj._s = u64
        return obj

    def _advance(self) -> int:
        s = (self._s + _GOLDEN) & _MASK64
        self._s = s
        z = s
        z = ((z ^ (z >> 30)) * _MIX1) & _MASK64
        z = ((z ^ (z >> 27)) * _MIX2) & _MASK64
        return z ^ (z >> 31)

    def next_u64(self) -> int:
        """القيمة التالية في [0, 2^64)."""
        return self._advance()

    def next_bytes(self, n: int) -> bytes:
        """n بايت: قيم u64 متتالية big-endian (آخر قيمة تُقتطع)."""
        if isinstance(n, bool) or not isinstance(n, int) or n < 0:
            raise ValidationError(f"n: expected int >= 0, got {n!r}")
        out = bytearray()
        while len(out) < n:
            out += self._advance().to_bytes(8, "big")
        return bytes(out[:n])

    def randbelow(self, n: int) -> int:
        """عقد مبسط معلن (N-a): u64 % n — n >= 1."""
        if isinstance(n, bool) or not isinstance(n, int) or n < 1:
            raise ValidationError(f"n: expected int >= 1, got {n!r}")
        return self._advance() % n


def derive_stream(seed: int, label: str) -> SeededPRNG:
    """تيار مستقل لكل خطوة: البذرة الأولية = أول 8 بايت من
    SHA-256(f"{seed}:{label}") big-endian (إفصاح N-b)."""
    _require_seed(seed, "seed")
    _require_label(label)
    h = hashlib.sha256(f"{seed}:{label}".encode("utf-8")).digest()
    return SeededPRNG._from_raw(int.from_bytes(h[:8], "big"))


# ============================================================ §3 قياسية
def canonical_input(obj) -> bytes:
    """G5: bytes تمر كما هي (مدخل قانوني بذاته — عقد M1 N3)؛ غيرها
    JSON قياسي (sort_keys، بلا فراغات، ensure_ascii=False، UTF-8)."""
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj)
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")
    except TypeError as exc:
        raise ValidationError(f"input not canonically representable: {exc}")


def input_digest(obj) -> bytes:
    return hashlib.sha256(canonical_input(obj)).digest()


# ============================================================ §4 هضم التدفق
def _require_steps(steps) -> list:
    if not isinstance(steps, (list, tuple)) or not steps:
        raise ValidationError("steps: expected non-empty list of step dicts")
    out = []
    for s in steps:
        if not isinstance(s, dict) or not {"name", "in_sha256",
                                           "out_sha256"} <= set(s):
            raise ValidationError("step: expected dict with name/in_sha256/"
                                  "out_sha256")
        for k in ("name", "in_sha256", "out_sha256"):
            if not isinstance(s[k], str):
                raise ValidationError(f"step.{k}: expected str")
        out.append({"name": s["name"], "in_sha256": s["in_sha256"],
                    "out_sha256": s["out_sha256"]})
    return out


def flow_lines(steps) -> list:
    """أسطر التدفق المنطقي: "name:in_sha:out_sha" — أساس كل هضم."""
    return [f"{s['name']}:{s['in_sha256']}:{s['out_sha256']}"
            for s in _require_steps(steps)]


def flow_digest(steps) -> str:
    """هضم التدفق: SHA-256 فوق (سطر + \\n) لكل خطوة — سداسي."""
    h = hashlib.sha256()
    for line in flow_lines(steps):
        h.update(line.encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def flow_merkle(steps) -> bytes:
    """جذر Merkle للتدفق: أوراق = SHA-256(سطر الخطوة)؛ Node =
    SHA-256(L||R)؛ الفرد → مضاعفة الأخيرة (اصطلاح §8.2/CT — N5)."""
    leaves = [hashlib.sha256(l.encode("utf-8")).digest()
              for l in flow_lines(steps)]
    level = leaves
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(hashlib.sha256(level[i] + level[i + 1]).digest())
        if len(level) % 2:
            nxt.append(hashlib.sha256(level[-1] + level[-1]).digest())
        level = nxt
    return level[0]

# ============================================================ §5 الفروق
_DIFF_ORDER = ("input_sha256", "seed", "steps", "flow_digest",
               "flow_merkle_hex", "final_payload")   # إفصاح N-e


def _require_record(r, name="run") -> dict:
    if not isinstance(r, dict) or not set(_DIFF_ORDER) <= set(r):
        raise ValidationError(
            f"{name}: expected RunRecord dict with {_DIFF_ORDER}")
    return r


def diff(a, b) -> dict:
    """§11.3: DiffReport — الحرفية: MerkleRoot(a)==MerkleRoot(b) هي
    الفيصل. إعادة حساب حية (إفصاح N-i): الجذر/الهضم دالة لسجل
    الخطوات الحالي — لا ثقة بالحقول المجمّعة؛ تحريف متزامن للحقول
    المخزنة يُكشف من المواد الخام."""
    _require_record(a, "a")
    _require_record(b, "b")
    first = None
    for k in _DIFF_ORDER:
        if a[k] != b[k]:
            first = k
            break
    return {
        "merkle_equal": flow_merkle(a["steps"]) == flow_merkle(b["steps"]),
        "digest_equal": flow_digest(a["steps"]) == flow_digest(b["steps"]),
        "payload_equal": a["final_payload"] == b["final_payload"],
        "first_diff": first,
    }


def investigate(a, b) -> dict:
    """«إذا Diff≠∅ → تحقيق آلي»: أول خطوة منحرفة بأول فهرس —
    in_match/out_match يسمّيان وجه الانحراف بدقة."""
    _require_record(a, "a")
    _require_record(b, "b")
    sa, sb = a["steps"], b["steps"]
    n = min(len(sa), len(sb))
    fd = None
    reason = None
    for i in range(n):
        in_m = sa[i]["in_sha256"] == sb[i]["in_sha256"]
        out_m = sa[i]["out_sha256"] == sb[i]["out_sha256"]
        if not in_m or not out_m:
            fd = {"index": i, "name": sa[i]["name"],
                  "in_match": in_m, "out_match": out_m}
            break
    if fd is None and len(sa) != len(sb):
        reason = "steps_length"
    elif fd is None:
        reason = None if a["final_payload"] == b["final_payload"] \
            else "payload_only"
    return {
        "first_divergent_step": fd,
        "reason": reason,
        "steps_compared": n,
        "payload_equal": a["final_payload"] == b["final_payload"],
        "merkle_equal": a["flow_merkle_hex"] == b["flow_merkle_hex"],
        "digest_equal": a["flow_digest"] == b["flow_digest"],
    }


def verify_determinism(runs) -> bool:
    """كل التشغيلات متطابقة بالقيمة (يتطلب 2+ — إفصاح N-f)."""
    if not isinstance(runs, (list, tuple)) or len(runs) < 2:
        raise ValidationError(
            "verify_determinism: expected list of 2+ runs")
    for r in runs:
        _require_record(r)
    first = runs[0]
    return all(r == first for r in runs[1:])


def require_determinism(runs) -> None:
    """وإلا DriftError — يحمل أول مسار مختلف وأول خطوة منحرفة."""
    if verify_determinism(runs):
        return
    a, b = runs[0], runs[1]
    d = diff(a, b)
    inv = investigate(a, b)
    fd = inv["first_divergent_step"]
    raise DriftError(
        f"determinism drift: first_diff={d['first_diff']!r}; "
        f"divergent_step="
        f"{(fd['index'], fd['name']) if fd else None}")


# ============================================================ §6 البيئة
PINNED_PACKAGES = ("scipy", "cryptography", "pytest")


def _sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def _record_path(pkg: str) -> Path:
    """dist-info/RECORD عبر importlib.metadata (إفصاح N-c)."""
    import importlib.metadata as _md
    dist = _md.distribution(pkg)
    return Path(dist._path) / "RECORD"


def freeze_environment() -> dict:
    """G3+G4: مواصفة قياسية حتمية (مروران نفس البايت على نفس
    البيئة) — التبعيات مثبتة بهاش ملف RECORD الفعلي."""
    import platform as _pl
    import importlib.metadata as _md
    pinned = {}
    for pkg in PINNED_PACKAGES:
        pinned[pkg] = {
            "version": _md.version(pkg),
            "record_sha256": _sha256_file(_record_path(pkg)),
        }
    return {
        "python": {"version": sys.version.split()[0],
                   "implementation": sys.implementation.name},
        "platform": {"system": sys.platform, "machine": _pl.machine()},
        "hash_seed": os.environ.get("PYTHONHASHSEED"),
        "sys_flags": {k: v for k, v in
                      ((k, getattr(sys.flags, k)) for k in dir(sys.flags))
                      if not k.startswith("_") and isinstance(v, int)},
        "pinned": pinned,
        "cwd": os.getcwd(),
    }


_SPEC_PATHS = (
    ("python.version", lambda s: s["python"]["version"]),
    ("python.implementation", lambda s: s["python"]["implementation"]),
    ("platform.system", lambda s: s["platform"]["system"]),
    ("platform.machine", lambda s: s["platform"]["machine"]),
    ("cwd", lambda s: s["cwd"]),
)


def _require_spec(spec) -> dict:
    """تحقق بنيوي ذري قبل أي أثر (restore)."""
    if not isinstance(spec, dict):
        raise ValidationError("spec: expected dict")
    try:
        for key, ctor in (("version", str), ("implementation", str)):
            if not isinstance(spec["python"][key], ctor):
                raise ValidationError(f"spec.python.{key}: expected str")
        for key in ("system", "machine"):
            if not isinstance(spec["platform"][key], str):
                raise ValidationError(f"spec.platform.{key}: expected str")
        if not isinstance(spec.get("hash_seed"), (str, type(None))):
            raise ValidationError("spec.hash_seed: expected str|None")
        if not isinstance(spec["sys_flags"], dict):
            raise ValidationError("spec.sys_flags: expected dict")
        if not isinstance(spec["cwd"], str):
            raise ValidationError("spec.cwd: expected str")
        pinned = spec["pinned"]
        if not isinstance(pinned, dict) or set(pinned) != set(PINNED_PACKAGES):
            raise ValidationError("spec.pinned: expected the pinned map")
        for pkg in PINNED_PACKAGES:
            ent = pinned[pkg]
            if not isinstance(ent, dict):
                raise ValidationError(f"spec.pinned.{pkg}: expected dict")
            for key in ("version", "record_sha256"):
                if not isinstance(ent[key], str):
                    raise ValidationError(
                        f"spec.pinned.{pkg}.{key}: expected str")
    except (KeyError, TypeError) as exc:
        raise ValidationError(f"spec: malformed ({exc})")
    return spec


def restore_environment(spec) -> list:
    """G4: يضبط PYTHONHASHSEED من المواصفة (None→"0" — إفصاح N-d)
    ويرجع أوجه اختلاف البيئة الحالية عن المواصفة (بعد الضبط) —
    الكشف بالاسم لا الصمت؛ القيم غير القابلة للضبط داخل عملية
    قائمة (python/pinned/cwd) تُكشف ولا تُدّعى."""
    _require_spec(spec)
    current = freeze_environment()
    mism = []
    for path, getter in _SPEC_PATHS:
        if getter(current) != getter(spec):
            mism.append(f"{path}: {getter(current)!r} != {getter(spec)!r}")
    for field in sorted(current["sys_flags"]):
        if current["sys_flags"].get(field) != spec["sys_flags"].get(field):
            mism.append(f"sys_flags.{field}: "
                        f"{current['sys_flags'].get(field)!r} != "
                        f"{spec['sys_flags'].get(field)!r}")
    for pkg in PINNED_PACKAGES:
        for key in ("version", "record_sha256"):
            cv = current["pinned"][pkg][key]
            sv = spec["pinned"][pkg][key]
            if cv != sv:
                mism.append(f"pinned.{pkg}.{key}: {cv!r} != {sv!r}")
    # الضبط الاستعادي الحتمي (hash_seed لا يُدرج في الاختلافات أبداً)
    os.environ["PYTHONHASHSEED"] = str(spec.get("hash_seed") or "0")
    return mism


# ============================================================ §7 المنفّذ
def _require_steps_spec(steps) -> tuple:
    if not isinstance(steps, (list, tuple)) or not steps:
        raise ValidationError("steps: expected non-empty list of (name, fn)")
    seen = set()
    out = []
    for item in steps:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise ValidationError("step: expected (name, fn) pair")
        name, fn = item
        if not isinstance(name, str) or not name:
            raise ValidationError("step name: expected non-empty str")
        if not callable(fn):
            raise ValidationError(f"step {name!r}: fn not callable")
        if name in seen:
            raise ValidationError(f"step name {name!r}: duplicate")
        seen.add(name)
        out.append((name, fn))
    return tuple(out)


class DeterministicExecutor:
    """تنفيذ حتمي: كل خطوة نقية fn(payload, rng)->bytes؛ rng مشتق
    حصراً من (البذرة، اسم الخطوة) — كل العشوائية من البذرة الأم
    (G1+G2). المعامل الصريح في execute لا يغير بذرة الحالة."""

    def __init__(self, steps, name: str = "custom"):
        self._steps = _require_steps_spec(steps)
        if not isinstance(name, str) or not name:
            raise ValidationError("name: expected non-empty str")
        self._name = name
        self._seed = None

    def set_seed(self, seed: int) -> None:
        self._seed = _require_seed(seed, "seed")

    def _resolve_seed(self, seed):
        if seed is None:
            if self._seed is None:
                raise ValidationError(
                    "no seed: set_seed first or pass seed explicitly")
            return self._seed
        return _require_seed(seed, "seed")

    def execute(self, input, seed=None) -> dict:
        use = self._resolve_seed(seed)
        canon = canonical_input(input)
        payload = canon
        log = []
        for name, fn in self._steps:
            rng = derive_stream(use, name)
            out = fn(payload, rng)
            if not isinstance(out, (bytes, bytearray)):
                raise ValidationError(
                    f"step {name!r}: output must be bytes, "
                    f"got {type(out).__name__}")
            out = bytes(out)
            log.append({"name": name,
                        "in_sha256": hashlib.sha256(payload).hexdigest(),
                        "out_sha256": hashlib.sha256(out).hexdigest()})
            payload = out
        return {
            "schema": "axis11-run-v1",
            "pipeline": self._name,
            "input_sha256": hashlib.sha256(canon).hexdigest(),
            "seed": use,
            "steps": log,
            "flow_digest": flow_digest(log),
            "flow_merkle_hex": flow_merkle(log).hex(),
            "final_payload": payload,
        }

    def triple_run(self, input) -> tuple:
        """§11.2 الحرفية: ثلاث تنفيذيات كاملة بنفس بذرة الحالة."""
        use = self._resolve_seed(None)
        return (self.execute(input, use), self.execute(input, use),
                self.execute(input, use))


# ============================================================ §8 التدفق الافتراضي
def _jdump(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _jload(b: bytes) -> dict:
    return json.loads(b.decode("utf-8"))


def _step_canonical(payload, rng):
    """identity مُعلنة (N-g): أول ما يُهضم في السجل هو المدخل
    القانوني نفسه — نقطة الربط، لا تحويل."""
    return bytes(payload)


def _step_derive(payload, rng):
    """كل مواد التدفق من rng المشتق من (seed, 'derive') حصراً — G1."""
    import burhan.proof as proof
    sign_seed = rng.next_bytes(32)
    aead_key = rng.next_bytes(32)
    nonce = rng.next_bytes(12)
    return _jdump({
        "canon": payload.hex(),
        "sign_seed": sign_seed.hex(),
        "pub": proof.ed25519_public_key(sign_seed).hex(),
        "aead_key": aead_key.hex(),
        "nonce": nonce.hex(),
    })


def _step_sign(payload, rng):
    import burhan.proof as proof
    d = _jload(payload)
    sig = proof.ed25519_sign(bytes.fromhex(d["sign_seed"]),
                             bytes.fromhex(d["canon"]))
    return _jdump({**d, "sig": sig.hex()})


def _step_aead(payload, rng):
    """AAD = أول 16 بايت من SHA-256(الحمولة الموقعة) — ربط تسلسلي
    مقصود (N-h): أي انحراف سابق يكسر فك التشفير في verify."""
    import burhan.proof as proof
    d = _jload(payload)
    aad = hashlib.sha256(payload).digest()[:16]
    ct = proof.chacha20poly1305_encrypt(
        bytes.fromhex(d["aead_key"]), bytes.fromhex(d["nonce"]),
        bytes.fromhex(d["canon"]), aad)
    return _jdump({**d, "aad": aad.hex(), "ct": ct.hex()})


def _step_merkle(payload, rng):
    import burhan.proof as proof
    d = _jload(payload)
    root = proof.merkle_root([bytes.fromhex(d["canon"]),
                               bytes.fromhex(d["sig"]),
                               bytes.fromhex(d["ct"])])
    return _jdump({**d, "root": root.hex()})


def _step_verify(payload, rng):
    """الدورة كاملة تُتحقق وتُفك — أي فشل DriftError (رفض لا صمت)."""
    import burhan.proof as proof
    try:
        d = _jload(payload)
        canon = bytes.fromhex(d["canon"])
        sig = bytes.fromhex(d["sig"])
        pub = bytes.fromhex(d["pub"])
        key = bytes.fromhex(d["aead_key"])
        nonce = bytes.fromhex(d["nonce"])
        ct = bytes.fromhex(d["ct"])
        aad = bytes.fromhex(d["aad"])
        root = bytes.fromhex(d["root"])
    except Exception as exc:  # noqa: BLE001 — التحويل مُعلن
        raise DriftError(f"verify: malformed boxed payload: {exc!r}")
    if not proof.ed25519_verify(sig, canon, pub):
        raise DriftError("verify: signature check failed")
    try:
        pt = proof.chacha20poly1305_decrypt(key, nonce, ct, aad)
    except proof.IntegrityError as exc:
        raise DriftError(f"verify: AEAD integrity failed: {exc}")
    if pt != canon:
        raise DriftError("verify: decrypted plaintext != canonical input")
    if proof.merkle_root([canon, sig, ct]) != root:
        raise DriftError("verify: merkle root mismatch")
    return pt


def default_pipeline():
    """ست خطوات فوق burhan.proof (المحور-8 المغلق) — العقد المعلن
    في M1: canonical → derive → sign → aead → merkle → verify."""
    return [("canonical", _step_canonical),
            ("derive", _step_derive),
            ("sign", _step_sign),
            ("aead", _step_aead),
            ("merkle", _step_merkle),
            ("verify", _step_verify)]


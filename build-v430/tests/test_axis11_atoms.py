#!/usr/bin/env python3
"""SENTINEL Axis-11 — M3 ATOMS: البطاريات الإجبارية الثلاث.

PROVENANCE والعقد (معلنة بأمانة، مقدَّمة — نمط سابقة المحور-7/8):
- جدول بطاريات أمر البناء الحرفي غير مسترد من أي سجل ملتزم (ضاع مع
  قطع الجلسة)؛ البطاريات الثلاث أدناه مُشتقة من عقد M1 المُسجَّل
  (tests/test_axis11_repro.py — D1 المواصفة §11 + D2 قائمة النطاق)
  ومن نمط البطاريات المعتمد في المحاور 4/7/8 (عشوائية مزروعة ×
  مرجع مستقل × سيناريوهات عدائية بالضبط-عدد) — قابلة للإحلال عند
  أي حد محطة.
- تُنفَّذ فوق sentinel/repro.py (M2 GREEN عند 9eb0514) — لا تعديل
  في المحرك ولا لمس للنواة 227×19=4313 (جناح مستقل، غير مُسجَّل في
  @case، كل بطارية تستورد sentinel.repro داخل جسمها).
- انضباط الهضم: التيار المنطقي فقط (battery, what, ok) — أزمنة
  الحائط في detail ولا تدخل الهضم أبداً (انضباط المحور-11 على
  نفسه). كل العشوائية ببذور ثابتة معلَنة — لا عشوائية حرة.

البطاريات الثلاث (مُشتقة من عقد M1 — مُعلنة):
  11a — 400 دورة مزروعة (G1+G2+انعكاس البت):
        كل دورة (input, seed) مزروعة: triple_run → ثلاث متطابقة
        (require_determinism لا يرفع) + قلب بت واحد في input
        (موقع مزروع من rng الدورة) → الجذر يختلف + قلب بت في
        seed → الجذر يختلف؛ البطارية كلها مروران → نفس قائمة
        الجذور بالبايت (هضم قابل للتكرار — برهان لا ادعاء).
  11b — 150 مطابقة مرجع مستقل (بايت-ببايت — الحتمية قاطعة):
        (75) SeededPRNG مقابل إعادة تنفيذ SplitMix64 مستقلة
        داخل البطارية (لا تستدعي المحرك)؛ (25) canonical_input
        مقابل json.dumps القياسي المستقل (sort_keys/bلا فراغات)؛
        (50) flow_merkle + flow_digest مقابل إعادة تركيب جذر
        مستقل بقواعد §8.2 (hashlib مباشرة) → 150/150.
  11c — بالضبط 40 سيناريو عدائي (تصنيف معلن لكل فئة):
        (20 بنيوي) عقود فاسدة → ValidationError المعلن؛
        (8 غير حتمية) خطوات مفتعلة (time/urandom/id/عداد عام/
        random بلا بذرة/بيئة حية تتبدل/استهلاك rng مشروط) →
        كلها تُكشف: require_determinism يرفع DriftError؛
        (4 تحريف) سجلات محرفة — بماذا الموقف المتزامن (تحريف
        الحقل المخزن مع بقاء المواد سليمة والعكس) → الكشف الحي
        من المواد الخام (N-i) وfirst_diff بالمسار؛
        (4 استعادة) specs محرفة → mismatches بالاسم، لا صمت؛
        (4 حدود) قيم الحدود 1 و2^64-1 مقبولة و2^64 مرفوضة.
        بعد الأربعين: فحص حي (لا تسمم حالة) — دورة صالحة تعطي
        نفس قيم ما قبل البطارية.

ملاحظات الصدق (الفروقات المُعلنة — لا مخفية):
  N1 (11a) — «عشوائية» = مولَّدة ببذور ثابتة معلَنة (seed=500000+i
      للتنفيذ وrandom.Random(400000+i) لصناعة المداخيل): عشوائية
      التوليد حتمية الإعادة — هذا ما يجعل «قائمة الجذور قابلة
      للتكرار» برهاناً لا ادعاءً. سجل كل دورة يحمل جذر التدفق
      (سداسي 64) — كافٍ للهضم الحتمي دون تضخيم الدليل.
  N2 (11b) — المراجع المستقلة داخل البطارية حصراً (إعادة تنفيذ
      SplitMix64 بثوابت معلنة؛ json.dumps القياسي؛ تركيب Merkle
      مستقل) — لا واحدة منها تستدعي المحرك.
  N3 (11c) — التصنيف معلن لكل فئة بالعدد؛ «صفر انهيار» يعني: لا
      استثناء من نوع غير معلن، ولا سيناريو سلك غير ما صُرِّح له.
      الفحص الحي بعد الأربعين هجوماً يثبت عدم تسمم الحالة.

Usage:
  python3 -m pytest tests/test_axis11_atoms.py --tb=short -q
  python3 tests/test_axis11_atoms.py --out results/axis11/axis11_ATOMS.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _repro():
    import sentinel.repro as repro
    return repro


def _ref_splitmix_seq(state: int, count: int) -> list[int]:
    """مرجع مستقل — إعادة تنفيذ SplitMix64 (لا يستدعي المحرك)."""
    out = []
    s = state
    for _ in range(count):
        s = (s + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        z = s
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
        out.append(z ^ (z >> 31))
    return out


# ============================================================ البطارية 11a
def battery_11a(repro) -> dict:
    """400 دورة مزروعة: triple متطابقة + قلب بت المدخل/البذرة →
    جذر مختلف، والبطارية كلها مرورين → نفس قائمة الجذور."""
    detail = {"cycles": 400, "crash_count": 0, "triple_identical": 0,
              "input_flips_diverged": 0, "seed_flips_diverged": 0,
              "repeatable": None, "root_lists_hex": []}
    try:
        for run_idx in (1, 2):
            roots = []
            for sid in range(400):
                ex = repro.DeterministicExecutor(repro.default_pipeline())
                seed = 500000 + sid
                gen = random.Random(400000 + sid)     # مزروعة معلَنة N1
                inp = bytes(gen.randrange(256)
                            for _ in range(gen.randint(16, 64)))
                # Triple-Run الحرفي §11.2
                ex.set_seed(seed)
                t = ex.triple_run(inp)
                repro.require_determinism(list(t))   # يرفع عند أي انحراف
                if t[0] == t[1] == t[2]:
                    detail["triple_identical"] += 1
                # قلب بت واحد في المدخل (موقع مزروع من rng الدورة)
                pos = gen.randrange(0, len(inp) * 8)
                bi, bit = divmod(pos, 8)
                flipped = bytearray(inp)
                flipped[bi] ^= 1 << bit
                rec = ex.execute(bytes(flipped), seed)
                if rec["flow_merkle_hex"] != t[0]["flow_merkle_hex"]:
                    detail["input_flips_diverged"] += 1
                # قلب بت واحد في البذرة
                seed2 = seed ^ (1 << (sid % 63))
                rec2 = ex.execute(inp, seed2)
                if rec2["flow_merkle_hex"] != t[0]["flow_merkle_hex"]:
                    detail["seed_flips_diverged"] += 1
                roots.append(t[0]["flow_merkle_hex"])
            detail["root_lists_hex"].append(
                hashlib.sha256("\n".join(roots).encode()).hexdigest()[:16])
            if run_idx == 2:
                detail["repeatable"] = (
                    detail["root_lists_hex"][0] == detail["root_lists_hex"][1])
        ok = (detail["crash_count"] == 0
              and detail["triple_identical"] == 800      # 400 × مروران
              and detail["input_flips_diverged"] == 800
              and detail["seed_flips_diverged"] == 800
              and detail["repeatable"] is True)
    except BaseException as exc:  # noqa: BLE001 — الدليل يلتقط خاماً
        detail["crash_count"] += 1
        detail["crash_repr"] = repr(exc)[:400]
        ok = False
    return {"battery": "11a", "what": "400 seeded cycles: triple identical "
            "+ bit-flip divergence + repeatable digest", "ok": ok,
            "detail": detail}


# ============================================================ البطارية 11b
def battery_11b(repro) -> dict:
    """150 مطابقة مرجع مستقل بايت-ببايت (الحتمية قاطعة)."""
    detail = {"matched": {"prng": 0, "canonical": 0, "flow": 0},
              "mismatch_total": 0, "mismatches": []}
    try:
        # (75) SeededPRNG مقابل إعادة تنفيذ مستقلة (12 قيمة u64 ثم
        # next_bytes(n) = أول n بايت من القيم التالية big-endian)
        for i in range(75):
            seed = 600000 + i
            n = 7 + (i % 23)
            need = 12 + (n + 7) // 8
            ref_all = _ref_splitmix_seq(seed, need)
            ref = ref_all[:12]
            pr = repro.SeededPRNG(seed)
            got = [pr.next_u64() for _ in range(12)]
            ref_nb = b"".join(v.to_bytes(8, "big")
                              for v in ref_all[12:])[:n]
            if got == ref and pr.next_bytes(n) == ref_nb:
                detail["matched"]["prng"] += 1
            else:
                detail["mismatches"].append(f"prng seed {seed}")
        # (25) canonical_input مقابل json.dumps القياسي المستقل
        for i in range(25):
            gen = random.Random(700000 + i)
            obj = {"z": gen.randrange(1000), "a": [gen.randrange(9),
                    {"k": str(gen.randrange(50))}], "m": "x" * (i + 1)}
            ref = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False).encode("utf-8")
            if repro.canonical_input(obj) == ref:
                detail["matched"]["canonical"] += 1
            else:
                detail["mismatches"].append(f"canonical #{i}")
        # (50) flow_merkle + flow_digest مقابل تركيب مستقل §8.2
        def _indep_root(leaves: list) -> bytes:
            ls = list(leaves)
            while len(ls) > 1:
                nxt = []
                for j in range(0, len(ls) - 1, 2):
                    nxt.append(hashlib.sha256(ls[j] + ls[j + 1]).digest())
                if len(ls) % 2:
                    nxt.append(hashlib.sha256(ls[-1] + ls[-1]).digest())
                ls = nxt
            return ls[0]
        for i in range(50):
            n = 1 + i
            steps = [{"name": f"s{k}",
                      "in_sha256": hashlib.sha256(f"in{k}:{i}".encode())
                                  .hexdigest(),
                      "out_sha256": hashlib.sha256(f"out{k}:{i}".encode())
                                   .hexdigest()} for k in range(n)]
            lines = [f"{s['name']}:{s['in_sha256']}:{s['out_sha256']}"
                     for s in steps]
            leaves = [hashlib.sha256(l.encode()).digest() for l in lines]
            h = hashlib.sha256()
            for l in lines:
                h.update(l.encode())
                h.update(b"\n")
            if (repro.flow_merkle(steps) == _indep_root(leaves)
                    and repro.flow_digest(steps) == h.hexdigest()):
                detail["matched"]["flow"] += 1
            else:
                detail["mismatches"].append(f"flow n={n}")
        detail["mismatch_total"] = len(detail["mismatches"])
        ok = (detail["matched"]["prng"] == 75
              and detail["matched"]["canonical"] == 25
              and detail["matched"]["flow"] == 50
              and detail["mismatch_total"] == 0)
    except BaseException as exc:  # noqa: BLE001
        detail["mismatch_total"] = -1
        detail["crash_repr"] = repr(exc)[:400]
        ok = False
    return {"battery": "11b", "what": "150 independent-reference matches "
            "(75 SplitMix64 + 25 canonical JSON + 50 flow merkle/digest)",
            "ok": ok, "detail": detail}

# ============================================================ البطارية 11c
def battery_11c(repro) -> dict:
    """بالضبط 40 سيناريو عدائي (تصنيف معلن) + فحص حي (لا تسمم)."""
    detail = {"adversarial_total": 40, "behaved_as_declared": 0,
              "crash_count": 0,
              "by_class": {"structural": 20, "nondeterminism": 8,
                           "tamper": 4, "restore": 4, "boundary": 4},
              "deviations": [], "state_poisoning_check": False}
    import copy
    import itertools
    base_inp = b"axis11c-live-baseline-input"
    base_seed = 4313
    ex0 = repro.DeterministicExecutor(repro.default_pipeline())
    baseline = ex0.execute(base_inp, base_seed)   # قبل البطارية (فحص حي)

    def case(cls, desc, fn):
        try:
            behaved = bool(fn())
        except repro.ValidationError:
            # رفض ذري معلن قبوله في فئته (structural/restore/boundary)
            behaved = True
        except BaseException as exc:  # noqa: BLE001 — نوع غير معلن
            detail["crash_count"] += 1
            detail["deviations"].append(f"{cls}:{desc}: {exc!r}"[:300])
            return
        if not behaved:
            detail["deviations"].append(f"{cls}:{desc}"[:300])
        else:
            detail["behaved_as_declared"] += 1
        # ملاحظة: الرجوع المعلن يُحتسب ضمن behaved — انظر _expect*

    # ---- (1-20) بنيوية: رفض ذري ValidationError قبل أي أثر ---------
    def _ve(fn):
        """يجب أن ترفع ValidationError (وليس أي شيء آخر)."""
        try:
            fn()
            return False                    # قُبل ما لا يجب قبوله
        except repro.ValidationError:
            return True
        except BaseException as exc:        # نوع غير معلن = انهيار
            detail["deviations"].append(f"WRONG-EXC: {exc!r}"[:300])
            detail["crash_count"] += 1
            return True

    _idfn = lambda p, rng: p                # noqa: E731
    _clean = repro.DeterministicExecutor(repro.default_pipeline())
    _rec_ok = _clean.execute(base_inp, base_seed)
    structural = [
        lambda: _ve(lambda: repro.SeededPRNG(0)),
        lambda: _ve(lambda: repro.SeededPRNG(-1)),
        lambda: _ve(lambda: repro.SeededPRNG(True)),
        lambda: _ve(lambda: repro.SeededPRNG("77")),
        lambda: _ve(lambda: repro.SeededPRNG(1.5)),
        lambda: _ve(lambda: repro.derive_stream(0, "a")),
        lambda: _ve(lambda: repro.derive_stream(1, "")),
        lambda: _ve(lambda: repro.derive_stream(1, 5)),
        lambda: _ve(lambda: repro.derive_stream(True, "a")),
        lambda: _ve(lambda: repro.DeterministicExecutor([])),
        lambda: _ve(lambda: repro.DeterministicExecutor([("x", "nc")])),
        lambda: _ve(lambda: repro.DeterministicExecutor([("", _idfn)])),
        lambda: _ve(lambda: repro.DeterministicExecutor(
            [("dup", _idfn), ("dup", _idfn)])),
        lambda: _ve(lambda: repro.DeterministicExecutor("notalist")),
        lambda: _ve(lambda: repro.DeterministicExecutor(
            [("t", _idfn, "extra")])),
        lambda: _ve(lambda: _clean.execute(base_inp)),          # بلا بذرة
        lambda: _ve(lambda: _clean.execute(object(), base_seed)),
        lambda: _ve(lambda: _clean.execute(lambda: 1, base_seed)),
        lambda: _ve(lambda: repro.flow_merkle([])),
        lambda: _ve(lambda: repro.diff(_rec_ok, "notarecord")),
    ]
    for i, fn in enumerate(structural, 1):
        case("structural", f"#{i}", fn)

    # ---- (21-28) غير حتمية مفتعلة: DriftError يُرفع (كشف لا صمت) --
    def _drift(step_fn, second_mutator=None):
        ex = repro.DeterministicExecutor(
            [("probe", step_fn)])
        a = ex.execute(base_inp, base_seed)
        if second_mutator is not None:
            second_mutator()
        b = ex.execute(base_inp, base_seed)
        if a == b:
            return False                     # انحراف صامت!
        try:
            repro.require_determinism([a, b])
            return False                     # قبول درفت = فشل
        except repro.DriftError:
            return True

    _KEEP = []
    _FLAG = [False]
    _TOGGLE = [False]
    nondet = [
        lambda: _drift(lambda p, rng: p + int(time.time_ns())
                       .to_bytes(8, "big")),
        lambda: _drift(lambda p, rng: p + int(time.monotonic_ns())
                       .to_bytes(8, "big")),
        lambda: _drift(lambda p, rng: p + os.urandom(8)),
        lambda: _drift(lambda p, rng: (_KEEP.append(object()) or
                       p + id(_KEEP[-1]).to_bytes(8, "big"))),
        lambda: _drift(lambda p, rng: p + next(_COUNTER[0])
                       .to_bytes(8, "big")),
        lambda: _drift(lambda p, rng: p + __import__("random")
                       .SystemRandom().getrandbits(64).to_bytes(8, "big")),
        lambda: _drift(
            lambda p, rng: p + os.environ.get("AX11C_PROBE", "").encode()
            + b"-tail",
            second_mutator=lambda: os.environ.__setitem__("AX11C_PROBE",
                                                          "mutated")),
        lambda: _drift(
            lambda p, rng: p + (rng.next_u64() if _FLAG[0] else 0)
            .to_bytes(8, "big"),
            second_mutator=lambda: _FLAG.__setitem__(0, True)),
    ]
    _COUNTER = [itertools.count()]
    for i, fn in enumerate(nondet, 21):
        case("nondeterminism", f"#{i}", fn)

    # ---- (29-32) تحريف: الكشف الحي من المواد الخام + المسار -------
    def _tamper_final():
        bad = copy.deepcopy(_rec_ok)
        bad["final_payload"] = bytes(bad["final_payload"][:-1]) + b"z"
        d = repro.diff(_rec_ok, bad)
        return d["payload_equal"] is False and \
            d["first_diff"] == "final_payload"

    def _tamper_steps_synced():
        bad = copy.deepcopy(_rec_ok)
        bad["steps"][1]["out_sha256"] = "00" * 32   # الجذر المخزن سليم
        d = repro.diff(_rec_ok, bad)
        return d["merkle_equal"] is False and d["digest_equal"] is False

    def _tamper_stored_root():
        bad = copy.deepcopy(_rec_ok)
        bad["flow_merkle_hex"] = "00" * 32          # المواد سليمة
        d = repro.diff(_rec_ok, bad)
        return d["first_diff"] == "flow_merkle_hex"

    def _require_raises():
        bad = copy.deepcopy(_rec_ok)
        bad["final_payload"] = bytes(bad["final_payload"][:-1]) + b"z"
        try:
            repro.require_determinism([_rec_ok, bad])
            return False
        except repro.DriftError:
            return True

    for i, fn in enumerate(
            (_tamper_final, _tamper_steps_synced, _tamper_stored_root,
             _require_raises), 29):
        case("tamper", f"#{i}", fn)

    # ---- (33-36) استعادة: mismatches بالاسم (الكشف لا الصمت) -------
    def _restore_tampered(mutate, needle):
        spec = repro.freeze_environment()
        mutate(spec)
        mm = repro.restore_environment(spec)
        return any(needle in m for m in mm)

    def _restore_broken():
        try:
            repro.restore_environment({"python": "notadict"})
            return False
        except repro.ValidationError:
            return True

    for i, fn in enumerate((
        lambda: _restore_tampered(
            lambda s: s["python"].__setitem__("version", "9.9.9"),
            "python.version"),
        lambda: _restore_tampered(
            lambda s: s["pinned"]["scipy"].__setitem__(
                "record_sha256", "11" * 32),
            "pinned.scipy.record_sha256"),
        lambda: _restore_tampered(
            lambda s: s.__setitem__("cwd", "/nonexistent"),
            "cwd"),
        _restore_broken), 33):
        case("restore", f"#{i}", fn)

    # ---- (37-40) حدود صلبة: الحدود مقبولة وما جاوزها مرفوض ---------
    def _edge_min():
        v = repro.SeededPRNG(1).next_u64()
        ex = repro.DeterministicExecutor(repro.default_pipeline())
        ex.set_seed(1)
        return 0 <= v < 2 ** 64 and ex.triple_run(base_inp)[0]["seed"] == 1

    def _edge_max():
        repro.SeededPRNG(2 ** 64 - 1).next_u64()
        ex = repro.DeterministicExecutor(repro.default_pipeline())
        ex.set_seed(2 ** 64 - 1)
        return len(ex.execute(base_inp)["steps"]) == 6

    def _edge_over():
        try:
            repro.SeededPRNG(2 ** 64)
            return False
        except repro.ValidationError:
            return True

    def _edge_derive():
        repro.derive_stream(2 ** 64 - 1, "edge")
        try:
            repro.derive_stream(2 ** 64, "x")
            return False
        except repro.ValidationError:
            return True

    for i, fn in enumerate((_edge_min, _edge_max, _edge_over,
                            _edge_derive), 37):
        case("boundary", f"#{i}", fn)

    # ---- الفحص الحي (بعد الأربعين): لا تسمم حالة الوحدة -----------
    ex_after = repro.DeterministicExecutor(repro.default_pipeline())
    after = ex_after.execute(base_inp, base_seed)
    detail["state_poisoning_check"] = (after == baseline)
    os.environ.pop("AX11C_PROBE", None)

    ok = (detail["behaved_as_declared"] == 40
          and detail["crash_count"] == 0
          and detail["state_poisoning_check"] is True)
    return {"battery": "11c", "what": "exactly 40 adversarial scenarios "
            "(20 structural + 8 nondeterminism + 4 tamper + 4 restore "
            "+ 4 boundary) + live state check", "ok": ok, "detail": detail}


# ============================================================ pytest
def test_battery_11a():
    """11a — 400 دورة مزروعة: triple متطابقة + انعكاس بت + تكرار."""
    assert battery_11a(_repro())["ok"]


def test_battery_11b():
    """11b — 150 مطابقة مرجع مستقل بايت-ببايت."""
    assert battery_11b(_repro())["ok"]


def test_battery_11c():
    """11c — 40 سيناريو عدائي بالضبط: رفض ذري، كشف لا صمت، لا تسمم."""
    assert battery_11c(_repro())["ok"]


# ============================================================ وضع الدليل
_BATTERIES = [("11a", battery_11a), ("11b", battery_11b),
              ("11c", battery_11c)]


def _overall_digest(bats: list[dict]) -> str:
    """هضم التيار المنطقي الكلي: (بطارية، ماذا، نجحت) فقط (انضباط 11)."""
    h = hashlib.sha256()
    for b in bats:
        h.update(f"{b['battery']}:{b['what']}:{int(b['ok'])}"
                 .encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="SENTINEL Axis-11 ATOMS")
    ap.add_argument("--out", default="", help="مسار ملف دليل JSON")
    args = ap.parse_args()

    p = _repro()
    bats = [fn(p) for _, fn in _BATTERIES]
    total = len(bats)
    passed = sum(1 for b in bats if b["ok"])
    doc = {
        "suite": "axis11-atoms",
        "station": "M3-ATOMS",
        "total": total,
        "passed_count": passed,
        "failed": total - passed,
        "passed": passed == total,
        "overall_digest": _overall_digest(bats),
        "batteries": bats,
    }
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1, ensure_ascii=False)
        print(f"evidence -> {args.out}")
    print(f"axis11-atoms: {passed}/{total} batteries | "
          f"digest {doc['overall_digest'][:16]}")
    for b in bats:
        mark = "PASS" if b["ok"] else "FAIL"
        extra = ""
        if b["battery"] == "11a":
            extra = (f" | crashes={b['detail']['crash_count']}"
                     f" repeatable={b['detail']['repeatable']}")
        elif b["battery"] == "11b":
            extra = (f" | matched={sum(b['detail']['matched'].values())}"
                     f" mismatches={b['detail']['mismatch_total']}")
        elif b["battery"] == "11c":
            extra = (f" | behaved={b['detail']['behaved_as_declared']}/40"
                     f" crashes={b['detail']['crash_count']}"
                     f" state_clean={b['detail']['state_poisoning_check']}")
        print(f"  [{mark}] battery {b['battery']}: {b['what']}{extra}")
        if not b["ok"]:
            print(f"      raw: "
                  f"{json.dumps(b['detail'], ensure_ascii=False)[:600]}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())

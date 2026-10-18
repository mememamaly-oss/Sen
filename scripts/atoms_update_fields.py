"""الخطوة 7 — تحديث حقول axis10_ATOMS.json حرفياً وفق أمر المشرف.

- total/failed: من التشغيل الفعلي الطازج (102/0) — لا تعديل يدوي.
- passed: بنية المولّد قيمة منطقية (true = كل الفحوص ناجحة) — التكييف
  معلن في التقرير؛ 102/102 يعبَّر عنها بـ total=102 + failed=0.
- honest_notes: قائمة المشرف الست حرفياً (الرقم المقاس 44485 msg/s من
  دليل M2 GREEN: pool_4_msgs_per_s).
ثم إعادة حساب هضم الملف الكامل بأمر المشرف الحرفي.
"""
import hashlib
import json

PATH = "results/axis10/axis10_ATOMS.json"

d = json.load(open(PATH, encoding="utf-8"))

d["honest_notes"] = [
    "E4_fixed: CancelledError recovery in infra.py — each tell() now "
    "independent",
    "E1: SHA256 wrapper over blake2b-16 in writer",
    "E2: unbounded output queue (_UNBOUNDED=1<<62) prevents pipeline "
    "deadlock",
    "E3: pre-check ValueError before delta_encode (dead check in block.py)",
    "F1: axis4 SHA256SUMS regenerated — logical digest 7448f95e verified "
    "intact",
    "H10_17: arch-relative floor 20k documented; measured 44485 msg/s",
]

with open(PATH, "w", encoding="utf-8") as f:
    json.dump(d, f, indent=1, ensure_ascii=False)

print("fields after update:")
for k in ("suite", "station", "total", "failed", "passed"):
    print(f"  {k} = {d[k]}")
print("  honest_notes:")
for n in d["honest_notes"]:
    print(f"    - {n}")

d2 = json.load(open(PATH, encoding="utf-8"))
print("whole-file SHA256:",
      hashlib.sha256(
          json.dumps(d2, ensure_ascii=False,
                     sort_keys=True).encode()).hexdigest())

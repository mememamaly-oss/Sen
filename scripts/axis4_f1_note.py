"""الخطوة 6 — إضافة f1_note إلى axis4_GREEN.json (نص المشرف حرفياً).

يحافظ على أسلوب تنسيق الملف (indent=1) ويضيف المفتاح في نهاية الجذر.
بعدها: sha256sum -c (متوقع فشل GREEN — المرسى تولد قبل الملاحظة) ثم
إعادة توليد SUMS ثم تحقق نهائي.
"""
import hashlib
import json

PATH = "results/axis4/axis4_GREEN.json"

d = json.load(open(PATH, encoding="utf-8"))
d["f1_note"] = (
    "SHA256SUMS regenerated 2026-10-18: original anchors in commit "
    "91267c5 drifted (wall-time bytes included in hash at generation). "
    "Logical digest 7448f95ebd58be25 verified intact via gate log + "
    "fresh rerun 26/26 same digest."
)
with open(PATH, "w", encoding="utf-8") as f:
    json.dump(d, f, indent=1, ensure_ascii=False)
    f.write("\n")

print("f1_note added. tail of file:")
print(open(PATH, encoding="utf-8").read()[-320:])
print("new GREEN sha256:",
      hashlib.sha256(open(PATH, "rb").read()).hexdigest())

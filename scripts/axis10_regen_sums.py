"""الخطوة 8 — إعادة توليد SHA256SUMS لمجلد أدلة axis10.

نفس مجموعة الملفات الثمانية المراسيّة سابقاً؛ التغييران:
1. المسارات نسبية إلى build-v430 (بدل الأسماء المجردة) ليصادق أمر
   التحقق الحرفي للمشرف: sha256sum -c results/axis10/SHA256SUMS
2. مرسى axis10_ATOMS.json محدَّث لبايتات ما بعد إصلاح E4 وإغلاق M3
   (102/102 + ملاحظات الصدق الست).
"""
import hashlib
import os

FILES = [
    "results/axis10/axis10_RED.json",
    "results/axis10/axis10_RED_pytest.txt",
    "results/axis10/axis10_GREEN.json",
    "results/axis10/axis10_GREEN_pytest.txt",
    "results/axis10/axis10_GREEN_scriptmode.json",
    "results/axis10/axis10_ATOMS.json",
    "results/axis10/axis10_ATOMS_pytest.txt",
    "results/axis10/axis10_ATOMS_pytest_run1_RED.txt",
]

lines = []
for f in FILES:
    if os.path.exists(f):
        h = hashlib.sha256(open(f, "rb").read()).hexdigest()
        lines.append(f"{h}  {f}")
    else:
        print(f"MISSING: {f}")

with open("results/axis10/SHA256SUMS", "w") as out:
    out.write("\n".join(lines) + "\n")

print("axis10 SHA256SUMS regenerated:")
for l in lines:
    print(l)

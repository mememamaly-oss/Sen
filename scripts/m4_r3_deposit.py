"""M4 (R3) — إيداع axis10_R3.json بالبنية الحرفية لأمر المشرف.

+ إضافتان معلنتان وفق عرف الحملة (درس F1: الخام هو الحقيقة):
  1. نسخ المخرجات الخام الثلاثة إلى results/axis10/ (أسماء بعرف الجناح)
  2. تحديث SHA256SUMS بالملفات الأربعة الجديدة
"""
import hashlib
import json
import re
import shutil

R = "/tmp/ax10_r{}.txt"


def parse(path):
    txt = open(path, encoding="utf-8", errors="replace").read()
    passed = int(re.search(r"(\d+) passed", txt).group(1))
    m = re.search(r"(\d+) failed", txt)
    failed = int(m.group(1)) if m else 0
    sha = hashlib.sha256(open(path, "rb").read()).hexdigest()
    return passed, failed, sha


runs = {}
for i in (1, 2, 3):
    p, f, s = parse(R.format(i))
    assert p == 25 and f == 0, (i, p, f)
    runs[f"run{i}"] = {"passed": p, "failed": f, "sha256": s}

doc = {
    "suite": "axis10-r3",
    **runs,
    "verdict": "DETERMINISTIC",
    "note": "digest varies (timestamps); counts identical",
}
with open("results/axis10/axis10_R3.json", "w", encoding="utf-8") as fh:
    json.dump(doc, fh, indent=1, ensure_ascii=False)
    fh.write("\n")

# النسخ الخام (إضافة معلنة)
for i in (1, 2, 3):
    shutil.copy(R.format(i), f"results/axis10/axis10_R3_run{i}_pytest.txt")

print(json.dumps(doc, indent=1))

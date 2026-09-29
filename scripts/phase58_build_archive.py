#!/usr/bin/env python3
"""Rebuild the SENTINEL FULL ARCHIVE as v3.0.0 (the one save-everything file).
Replaces the v2.9.0 archive per the user's single-archive directive."""
import os, shutil, subprocess, zipfile

DL = "/home/z/my-project/download"
STAGE = "/tmp/archive300"
NAME = "SENTINEL-FULL-ARCHIVE-v3.0.0.zip"

if os.path.exists(STAGE):
    shutil.rmtree(STAGE)
os.makedirs(STAGE)

# 1. everything in download/ except the old full archive + the new one itself
for item in os.listdir(DL):
    if item.startswith("SENTINEL-FULL-ARCHIVE"):
        continue
    src = os.path.join(DL, item)
    dst = os.path.join(STAGE, item)
    if os.path.isdir(src):
        shutil.copytree(src, dst)
    else:
        shutil.copy(src, dst)

# 2. the live working tree (full source + fixtures + benchmarks + tests + results)
shutil.copytree("/home/z/my-project/verify-live", os.path.join(STAGE, "working-tree-v3.0.0"),
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.db-shm", "*.db-wal"))

# 3. Arabic master README at the archive root
open(os.path.join(STAGE, "00-README-FULL-ARCHIVE-AR.md"), "w").write(
"""# أرشيف SENTINEL الكامل — الإصدار 3.0.0 (ذكاء سير العمل)

**SENTINEL** منصة فحص أمني حتمية (DAST) مكتوبة ببايثون القياسية الخالصة — بلا أي مكتبات خارجية.
كل نتيجة مُقفلة بالتحقق: لا تُعتبر أي ثغرة "مؤكدة" إلا بعد إعادة تشغيل مستقلة تثبتها.

## هذا الأرششيف يحتوي على كل شيء

| المسار | المحتوى |
|--------|---------|
| `sentinel-3.0.0-source.zip` | المصدر الكامل للإصدار 3.0.0 |
| `sentinel-3.0.0-complete-bundle.zip` | الحزمة الكاملة (المصدر + كل النتائج القياسية) |
| `sentinel-{1..3}-*-source.zip` | المصدر لكل إصدار في تاريخ المشروع |
| `sentinel-results/` | كل المصنفات: اختبارات، معايير، فحوص حية، سجل العمل، سجل التغييرات |
| `working-tree-v3.0.0/` | شجرة العمل الحية (المصدر + الـ fixture + نتائج التشغيل) |
| `00-README-FULL-ARCHIVE-AR.md` | هذا الملف |

## الإصدار 3.0.0 — ذكاء منطق الأعمال / سير العمل

حتى الإصدار 2.9 كان SENTINEL يفكر في **الطلبات**: نقطة واحدة، معامل واحد، استجابة واحدة.
الإصدار 3.0.0 يفكر في **العمليات**: التسلسلات المتعددة الخطوات التي يقوم بها التطبيق
لإنجاز عمل حقيقي (دخول ← اختيار حساب ← إدخال مبلغ ← إنشاء التحويل ← التأكيد).

### المحرك الجديد (sentinel/workflow.py)

**التعلّم** (`--workflow`، آمن): تجميع الأسطح في مجلدات التدفقات، إيجاد نقطة الارتكاز،
ثم **مشي موجّه** يتبع السلسلة التي يرسمها التطبيق نفسه — بما في ذلك الخطوات التي لا
يراها أي زاحف لأنها تعيش خلف صفحات استجابة POST. يتعلم: سلسلة الخطوات، **ربط الموارد**
(المعرفات التي تُولّدها خطوة وتستهلكها خطوة لاحقة)، **أوراكل الحالة** (الصفحة التي تُظهر
تلك المعرفات)، و**مفردات علامات التنفيذ** (الفرق اللغوي لسطر المورد قبل/بعد الخطوة
الأخيرة: PENDING ← EXECUTED).

**الهجوم** (`--logic-active`، خيار صريح بتحذير مرتفع): الثوابت الخمسة التي يختبرها
مختبر الاختراق البشري:

1. **تجاوز خطوة إلزامية** — الإنشاء دون الخطوة السابقة
2. **التنفيذ خارج الترتيب** — الخطوة الأخيرة تنفّذ موردًا لم يُنشأ أبدًا
3. **تلاعب بالقيمة بعد الموافقة** — المبلغ المعتمد يُستبدل وقت التنفيذ
4. **تنفيذ مزدوج** — إعادة الخطوة الأخيرة تنفّذ العملية مرة ثانية
5. **تجاوز صلاحية معلنة** — خيار يصفه الواجهة نفسها بـ"للمدير فقط" ينفّذه مستخدم عادي

### عقيدة الإثبات (VR-20)

لا تُبلَّغ أي تلاعب إلا إذا **أثبت أوراكل الحالة النتيجة فعليًا**: كائن جديد يحمل القيمة
الكنارية، أو تنفيذ ثانٍ لنفس المورد، أو سطر منفَّذ يحمل المبلغ المتلاعب به. الخادم الذي
مجرد "لم يرفض" ليس ثغرة أبدًا. كل هجوم بجلسة معزولة جديدة وقيم كنارية وميزانيات محدودة.

## الأرقام النهائية للإصدار

- **الاختبارات: 71/71** خضراء (منها بطاريتا المرحلة 58 الجديدتان)
- **Doctor: 15/15** (منها فحص workflow_engine الذاتي الجديد)
- **المعيار: F1 = 1.000** في 3 تشغيلات متطابقة تمامًا (35 TP / 0 FP / 0 FN / 29 TN،
  run-3c0652b6be، 1622 طلبًا، 5 نتائج منطق أعمال مؤكدة في كل تشغيل)
- **التحقق الحي (testfire.net، استراتيجية خفيفة، وضع التعلّم فقط)**: السالب الصادق
  تمامًا كما توقعنا — `/bank:chain_too_short`، صفر تدفقات متعلمة، صفر نتائج منطق أعمال،
  وكل النتائج السابقة سليمة (95 مؤكدة / 0 مرفوضة)
- **التاريخ الحقيقي التراكمي: 4 منصات، 33 ثغرة نشطة مؤكدة، 0 إنذار زائف** عبر 21+ فئة

## التشغيل السريع

```bash
unzip sentinel-3.0.0-source.zip && cd sentinel-3.0.0
python3 sentinel/cli.py doctor                                # 15/15
python3 sentinel/cli.py benchmark                             # F1 = 1.000
python3 sentinel/cli.py scan <هدف-مصرح-به> --auth-user ... --auth-pass ... \
    --auth-url .../login.jsp --workflow                        # تعلّم التدفقات فقط
# البطارية الهجومية (تغيّر حالة التطبيق — خيار صريح):
python3 sentinel/cli.py scan <هدف> ... --logic-active
```
""")

out = os.path.join(DL, NAME)
if os.path.exists(out):
    os.remove(out)
subprocess.run(["zip", "-rq", out, "."], cwd=STAGE, check=True)
n = len(zipfile.ZipFile(out).namelist())
size = os.path.getsize(out) / 1e6
print(f"FULL ARCHIVE v3.0.0: {n} files, {size:.1f} MB")

# integrity check: open + read every member
with zipfile.ZipFile(out) as z:
    bad = z.testzip()
    assert bad is None, f"corrupt member: {bad}"
print("integrity: OK (every member readable)")

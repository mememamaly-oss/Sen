# SENTINEL — الأرشيف الكامل v2.9.0 (من البداية حتى النهاية)

**منصة فحص أمني حتمية (Deterministic DAST) — اعتماديات صفرية، بايثون قياسي خالص.
كل نتيجة مُتحقق منها: لا يُقبل أي مرشح كنتيجة إلا بعد إعادة تشغيل مستقلة تؤكده.**

---

## محتويات الأرشيف

| القسم | المحتوى |
|------|---------|
| `01-versions/` | **23 حزمة** — كل الإصدارات 2.0.0 → 2.9.0 (مصدر + حزمة كاملة لكل إصدار) |
| `02-results/` | **138 ملفاً** — كل نتائج الفحوص الحقيقية: JSON التقارير، SARIF، قواعد البيانات، تقرير PDF عربي، الخطوط، سكربتات الاختبار، أدلة الـ Vault المشفرة وسجل تدقيقه |
| `03-source-v2.9.0/` | **شجرة المصدر النهائية** — 27 وحدة محرك (بينها `vault.py`)، جناح 69 اختباراً، fixture v8، ground truth v8، CHANGELOG، وقالب `.gitignore-vault` |
| `04-docs/` | WORKLOG.md (سجل البناء الكامل للمهام 1–15) + CHANGELOG.md |

---

## الجدول الزمني للإصدارات

| الإصدار | المرحلة | أبرز ما أضاف |
|---------|---------|--------------|
| 2.0.0 → 2.0.3 | الأساس | المحرك، 9 كواشف، التحقق المرجعي، OAST |
| 2.1.0 → 2.2.0 | التوسع | SSRF/CORS، محرك المتصفح/DOM، REST API |
| 2.3.0 → 2.4.0 | الميدان | OAST عام، Auth، تسلسل الحقول، OP gates |
| 2.5.0 | الجودة | F1=1.000 حتمي، محرك الاستراتيجية |
| 2.6.0 | التخفي والعمليات | WAF fingerprint، token auth، OpenAPI، SARIF |
| 2.7.0 | خمسة كواشف | SSTI/CSRF/NoSQL/JWT/Host-header |
| 2.8.0 | طبقة الذكاء | 6 محركات: AuthZ متعدد المستخدمين، كشف الأسرار، param-intel، coverage، appmap، الأثر |
| **2.9.0** | **ذكاء الاعتمادات** | **Credential Vault: تشفير ChaCha20+HMAC، مفاتيح مصرح بها فقط، سجل تدقيق مشفر، تقارير مقنعة، إتلاف مُثبت، عزل مؤسسات، مفاتيح خارج Git** |

---

## إجماليات الحملة الميدانية (أهداف مصرح بها)

| المقياس | القيمة |
|---------|--------|
| المنصات المفحوصة حقيقةً | **4** (ginandjuice.shop، demo.testfire.net، testasp.vulnweb.com، testaspnet.vulnweb.com) |
| الثغرات النشطة المؤكدة تراكمياً | **33** (صفر إنذار كاذب) |
| فئات الثغرات المغطاة | **17** |
| فحص v2.9.0 الحي (testfire بـ Vault مسلّح) | 673 طلباً / 37 نقطة نهاية / **74 مؤكدة / 0 مرفوضة** |

## بوابات الجودة v2.9.0 (كلها خضراء)

| البوابة | النتيجة |
|---------|---------|
| الاختبارات | **69/69** (منها بطارية الـ Vault: متجهات RFC 8439 + KAT من مكتبة مرجعية مستقلة) |
| Doctor | **14/14** (بينها فحص credential_vault الذاتي) |
| Benchmark | **F1 = 1.000** (TP=30 / FP=0 / FN=0 / TN=24) — **حتمي ×3 متطابق** (run-3c0652b6be) |

---

## عيوب المحرك التي اصطادها البناء نفسه (مذهلة العقاب)

- **ENG-08** (v2.5.0): كاشف XXE الجديد كشف خلل تصيير JSON
- **ENG-10** (v2.8.0): فحص testfire الحي كشف عمى الـ AuthZ عن قوائم الهبوط العميقة
- **ENG-11** (v2.9.0): واجهة CLI الجديدة كشفت خطر تظليل `import secrets` في وضع السكربت — أُصلح بمصدر عشوائية غير قابل للتظليل

---

## البدء السريع (من `03-source-v2.9.0/`)

```bash
python3 -m sentinel.cli doctor                    # 14/14
python3 -m sentinel.cli benchmark                 # F1 = 1.000

# فحص مع تسليح الـ Vault:
python3 -m sentinel.cli vault keygen --out k.json --label designer
python3 -m sentinel.cli vault init --vault v.vault --key-file k.json --org my-org
python3 -m sentinel.cli scan https://target/ --vault v.vault --vault-key-file k.json

# التقارير:
python3 -m sentinel.cli vault list   --vault v.vault --key-file k.json   # مقنّع دائماً
python3 -m sentinel.cli vault report --vault v.vault --key-file k.json   # كشف المالك (مُدقّق)
python3 -m sentinel.cli vault purge  --vault v.vault --key-file k.json --all   # إتلاف بعد التسليم
```

**المفاتيح لا تُشحن مع أي مخرجات أبداً** — انسخ `.gitignore-vault` إلى مستودعك قبل إنشاء أي Vault.

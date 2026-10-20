# AUDIT VERIFICATION — التحقق المستقل من تقرير SENTINEL

> أي محقق خارجي يتحقق من **كل نتيجة** في تقرير SENTINEL بأدوات مفتوحة،
> **بلا أي وصول للكود** — الميزة التي لا يحملها Burp Suite ولا OWASP ZAP.
> كل تقرير غني (scanner report) يحمل قسم `audit`:
> `merkle_root` + `public_key_b64` (Ed25519، 32 بايتاً خاماً) +
> `signature_b64` (64 بايتاً) + الوصفة نفسها.

## ما الذي يوقَّع؟

- **الجذر**: شجرة Merkle فوق سجلات النتائج المؤكدة (`report.findings`)
  بترتيبها في التقرير:
  - الورقة: `leaf_i = sha256(canonical(record_i))` حيث الـcanonical =
    JSON بمفاتيح مرتبة، فواصل `","`/`":"`، UTF-8، مع حذف **المجموعة
    الطائرة** عودياً في كل عمق (المفاتيح المعلنة: `notes` وأزمنة الحائط
    والإحصاءات وكل قيود التوقيت — لا شيء منها يدخل الجذر أبداً).
  - العقدة: `node = sha256(left || right)`؛ المستوى ذو العدد الفردي
    يُضاعف أخيره مرة واحدة. المجموعة الفارغة جذرها الثابت المعلن
    `sha256(b'')`.
- **الرسالة الموقَّعة**: `sha256(run_id \x00 merkle_root \x00 findings_count \x00 header_canonical)`
  حيث `header_canonical` = JSON مرتب مضغوط لمفاتيح الهوية الأربعة حصراً:
  `{"run_id","seed","scanner","target"}`.
- **التوقيع**: Ed25519 (RFC 8032) فوق هضم الرسالة (32 بايتاً)، بالمفتاح
  العام المضمّن في التقرير. الزوج المفتاحي مشتق حتمياً من بذرة الجولة:
  نفس البذرة = نفس المفتاح = نفس التوقيع (قابلية تكرار كاملة للتقرير).

## الوصفة الحرفية (Python بأداة مفتوحة)

```python
import base64, hashlib, json

def canonical(rec, VOLATILE):
    def strip(o):
        if isinstance(o, dict):
            return {k: strip(v) for k, v in o.items() if k not in VOLATILE}
        if isinstance(o, (list, tuple)):
            return [strip(x) for x in o]
        return o
    return json.dumps(strip(rec), sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False)

VOLATILE = {"notes", "duration", "duration_s", "wall_time", "wall", "elapsed",
            "timestamp", "dur_s", "latency", "latency_ms", "time_ms", "time",
            "generated_at", "date", "stats", "requests", "started_at",
            "finished_at", "verified_at"}

report = json.load(open("report.json"))
blk = report["audit"]

# (1) الأوراق من سجلات التقرير نفسها
leaves = [hashlib.sha256(canonical(f).encode()).digest()
          for f in report["findings"]]
# (2) الشجرة — مضاعفة الأخير للعدد الفردي؛ الفارغة = sha256(b'')
level = leaves or [hashlib.sha256(b"").digest()]
while len(level) > 1:
    if len(level) % 2:
        level.append(level[-1])
    level = [hashlib.sha256(level[i] + level[i+1]).digest()
             for i in range(0, len(level), 2)]
assert level[0].hex() == blk["merkle_root"], "TAMPERED — root mismatch"

# (3) هضم الرسالة
hdr = {"run_id": report["run_id"], "seed": report.get("seed", ""),
       "scanner": report.get("scanner", ""), "target": report.get("target", "")}
hdr_canon = json.dumps(hdr, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False)
digest = hashlib.sha256(b"\x00".join([
    report["run_id"].encode(), blk["merkle_root"].encode(),
    str(blk["findings_count"]).encode(), hdr_canon.encode()])).digest()

# (4) التحقق من التوقيع بأداة مفتوحة (cryptography)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
Ed25519PublicKey.from_public_bytes(base64.b64decode(blk["public_key_b64"])) \
    .verify(base64.b64decode(blk["signature_b64"]), digest)
print("AUDIT OK — every finding is covered by the signed Merkle root")
```

## الوصفة الحرفية (openssl — بلا بايثون إطلاقاً)

```sh
# المفتاح العام خام 32B → SPKI PEM (ثابت البادئة لـEd25519)
python3 - <<'EOF' > pub.pem
import base64
pub = base64.b64decode(open("pub.b64").read())
spki = bytes.fromhex("302a300506032b6570032100") + pub
b = base64.encodebytes(spki).decode().strip()
print("-----BEGIN PUBLIC KEY-----"); print(b); print("-----END PUBLIC KEY-----")
EOF
# الرسالة (msg.bin = هضم SHA-256 المحسوب بالوصفة أعلاه) والتوقيع خاماً
openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in msg.bin -sig sig.bin
# → "Signature Verified Successfully" وإلا فالتقرير حُرِّف بعد التوقيع
```

## حدود صادقة (معلنة — لا صمت)

- التوقيع يغطي **النتائج المؤكدة + هوية التقرير** (run_id/seed/scanner/
  target). لا يدعي تغطية المرشحات المرفوضة ولا الإحصاءات (طائرة بطبيعتها).
- بذرة عشوائية (بلا بذرة معلنة) = لا ادعاء قابلية تكرار؛ التوقيع صادق
  لتلك التشغيلة وحدها.
- عدم تطابق الجذر أو التوقيع = **التقرير حُرِّف بعد التوقيع** — يُكتشف
  ولا يُوثَق.

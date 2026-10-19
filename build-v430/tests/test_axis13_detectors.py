#!/usr/bin/env python3
"""SENTINEL Axis-13 suite — كاشفات الثغرات الحديثة (Modern vulnerability detectors).

PROVENANCE (معلنة بأمانة، مقدَّمة — نمط سابقة 4/8/11/12):
- D1 = المواصفة المرجعية الملتزمة docs/SPEC_AXES_13_16.md §13 (المودعة 5544f9a
  قبل أي عمل بناء؛ الأمر الحرفي للمشرف مودَع حرفياً في ترويستها) —
  البنود 13.1 (العائلات الست + المعرفات + المستويات) و13.2 (العقد التفصيلي)
  و13.3 (التكامل في النقاط الأربع + الحتمية + اللا-انحدار).
- D2 = نطاق أمر البناء: «إضافة كاشفات لـ JWT (alg:none وخلط الخوارزمية)،
  GraphQL (introspection وbatching)، request smuggling بالتوقيت، mass
  assignment، prototype pollution» — والموجود مسبقاً (jwt_security جانب
  الإصدار + graphql_introspection_enabled) معلَن في §0.2 من المواصفة ولا
  يُعاد بناؤه.

الإفصاحات (نمط N1-N8):
N1) الوحدة الجديدة sentinel/modernsec.py — كل حالة تستوردها داخل دالتها؛
    النمط الأحمر المتوقع الموحد: ModuleNotFoundError (كالمحاور 11/12).
N2) زوج مفاتيح RSA يولَّد **لكل تشغيلة** (جانب الاختبار فقط؛ حزمة cryptography
    في الاختبار لا في المحرك) — لا تدخل أي مادة مفاتيح في النتائج: الإثبات
    بالتفاضل (مقبول/مرفوض) لا بمادة الرمز — الحتمية محفوظة عبر التيار المنطقي.
N3) القيود الزمنية المقاسة (توقيت التهريب) تدخل الحالات **كمَوَّة صنف**
    (desync / below-threshold / rejected-ambiguous) لا كأرقام ملّي-ثانية —
    خارج الهضم (انضباط المحور-11/12 الموروث).
N4) مجسات التهريب على socket خام خاص بالوحدة — ضمن scope، أجسام حميدة
    ببذور canary، **ولا إفساد أنبوب إطلاقاً** (لا بادئة طلب ثانٍ مهرباً).
N5) كشف فقط: قيم canary ليست امتيازاً حقيقياً؛ الكتابات في جلسة الفحص
    الذاتية على كائنات الفحص نفسها (نمط L3 القائم).
N6) fail-closed باقٍ: النوع غير المسجل يظل مرفوضاً (الحالة 18 تختبره).
N7) الميزانيات ثابتة معلنة وprobe_counts تُحسب وتُختبر — صفر مجسات عند
    غياب متطلبات العائلة (الأمانة الميزانية).
N8) الحتمية: النقاط تُعالج بترتيب (url, method) المصنّف؛ نفس البذرة =
    نفس الـcanaries = نفس التيار المنطقي؛ الترتيب حتمي داخل العائلة.

الوصفة: python3 tests/test_axis13_detectors.py --out results/axis13/axis13_RED.json
(بعد M2: نفس الأمر ينتج GREEN؛ pytest يجمع test_H13_* كما هو.)
"""
import argparse
import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.core import (Endpoint, EventBus, Evidence, Finding, FindingStatus,
                           ParamLocation, ScopeRule, Severity)
from sentinel.http_engine import RequestEngine

# ---------------------------------------------------------------- ثوابت الجناح
SUITE = "axis13-modernsec"
SEED = 13                       # بذرة ثابتة للجناح — نفس البذرة = نفس الـcanaries
SMUG_BACK_TIMEOUT = 1.2         # مهلة جوع الطبقة الخلفية في الـfixture (ثانية)
SMUG_K = 16                     # المتبقي المقطوع (بايت) في شكل desync
FIXED_CLAIMS = {"sub": "sentinel-session", "note": "axis13-fixed-test-claims"}
HS_SECRET = b"axis13-fixture-hs-secret"   # ثابت الاختبار — قيمته لا تدخل النتائج


def _engine(run: str, timeout: float = 8.0) -> tuple:
    """محرك طلبات حقيقي + ناقل أحداث (كأنماط run_tests.py)."""
    bus = EventBus(run)
    eng = RequestEngine(ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True),
                        bus, timeout=timeout)
    return eng, bus


def _one(res, ftype):
    hits = [f for f in res.findings if f.type == ftype]
    assert len(hits) == 1, f"{ftype}: expected exactly 1 finding, got {len(hits)}"
    return hits[0]


def _none(res, ftype):
    hits = [f for f in res.findings if f.type == ftype]
    assert not hits, f"{ftype}: expected 0 findings, got {len(hits)}"


def _bnd(res, family, kind):
    bs = [b for b in res.boundaries
          if b.get("family") == family and b.get("kind") == kind]
    assert bs, f"missing boundary {family}/{kind}; have {res.boundaries}"
    return bs[0]


def _sent(res, family):
    return int(res.probe_counts.get(family, {}).get("sent", -1))


# ================================================================ الـfixtures
def _start_http(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_address[1]}", srv


def _stop_http(srv):
    srv.shutdown()
    srv.server_close()


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


class _JsonMixin:
    def log_message(self, *a):
        pass

    def _send_json(self, code: int, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _body(self) -> bytes:
        n = int(self.headers.get("Content-Length", "0") or 0)
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            buf = b""
            while b"0\r\n\r\n" not in buf:
                chunk = self.rfile.read(4096)
                if not chunk:
                    break
                buf += chunk
            return buf
        if n:
            return self.rfile.read(n)
        return b""


def _make_jwt_fixture(mode: str):
    """أنماط: confusion-vuln / confusion-neg / none-vuln / none-neg / any-sig / no-jwks.
    زوج مفاتيح RSA لكل تشغيلة (N2). الباب المفتوح حسب النمط فقط."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as cpad
    from cryptography.hazmat.primitives.asymmetric import rsa
    import cryptography.hazmat.primitives.asymmetric.rsa as _rsa
    import hmac as _hmac

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    pub_body = "".join(pub_pem.strip().splitlines()[1:-1])   # جسم PEM مجرد — مادة الخلط
    nums = key.public_key().public_numbers()
    jwks = {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256",
                      "kid": "sentinel-test-key",
                      "n": _b64u(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")),
                      "e": _b64u(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big"))}]}

    def _seg(d: dict) -> str:
        return _b64u(json.dumps(d, separators=(",", ":")).encode())

    def _rs256() -> str:
        hp = _seg({"alg": "RS256", "typ": "JWT", "kid": "sentinel-test-key"}) \
            + "." + _seg(FIXED_CLAIMS)
        sig = key.sign(hp.encode(), cpad.PKCS1v15(), hashes.SHA256())
        return hp + "." + _b64u(sig)

    def _hs256() -> str:
        hp = _seg({"alg": "HS256", "typ": "JWT"}) + "." + _seg(FIXED_CLAIMS)
        sig = _hmac.new(HS_SECRET, hp.encode(), hashlib.sha256).digest()
        return hp + "." + _b64u(sig)

    def _verify(tok: str) -> bool:
        parts = tok.split(".")
        if len(parts) != 3:
            return False
        try:
            hdr = json.loads(_b64d(parts[0]))
        except Exception:
            return False
        alg = str(hdr.get("alg", "")).upper()
        sig = _b64d(parts[2]) if parts[2] else b""
        hp = parts[0] + "." + parts[1]
        if mode == "any-sig":
            return True
        if mode in ("confusion-vuln", "confusion-neg", "no-jwks"):
            if alg == "RS256":
                try:
                    key.public_key().verify(sig, hp.encode(), cpad.PKCS1v15(),
                                            hashes.SHA256())
                    return True
                except Exception:
                    return False
            if mode == "confusion-vuln" and alg == "HS256":
                mac = _hmac.new(pub_body.encode(), hp.encode(), hashlib.sha256).digest()
                return _hmac.compare_digest(mac, sig)
            return False
        if mode in ("none-vuln", "none-neg"):
            if alg == "NONE" and sig == b"":
                return mode == "none-vuln"
            if alg == "HS256":
                mac = _hmac.new(HS_SECRET, hp.encode(), hashlib.sha256).digest()
                return _hmac.compare_digest(mac, sig)
            return False
        return False

    class H(_JsonMixin, BaseHTTPRequestHandler):
        def do_GET(self):
            p = urlsplit(self.path).path
            if p == "/login":
                if mode in ("confusion-vuln", "confusion-neg", "no-jwks"):
                    return self._send_json(200, {"token": _rs256()})
                return self._send_json(200, {"token": _hs256()})
            if p in ("/.well-known/jwks.json", "/jwks.json", "/oauth/discovery/keys"):
                if mode == "no-jwks":
                    return self._send_json(404, {"error": "not found"})
                return self._send_json(200, jwks)
            if p == "/.well-known/openid-configuration":
                if mode == "no-jwks":
                    return self._send_json(404, {"error": "not found"})
                return self._send_json(200, {
                    "issuer": "fixture", "jwks_uri":
                        f"http://127.0.0.1:{self.server.server_address[1]}"
                        f"/.well-known/jwks.json"})
            if p == "/protected":
                auth = self.headers.get("Authorization", "")
                tok = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
                ok = bool(tok) and _verify(tok)
                return self._send_json(200 if ok else 401, {"ok": ok})
            self._send_json(404, {"error": "not found"})

        do_POST = do_GET

    return _start_http(H)


def _make_gql_fixture(mode: str):
    """batch-enabled: مصفوفة العمليات تُنفَّذ جميعاً؛ batch-reject: 400."""
    class H(_JsonMixin, BaseHTTPRequestHandler):
        def do_POST(self):
            if urlsplit(self.path).path != "/graphql":
                return self._send_json(404, {"error": "not found"})
            try:
                doc = json.loads(self._body() or b"{}")
            except Exception:
                return self._send_json(400, {"errors": [{"message": "bad json"}]})
            if isinstance(doc, list):
                if mode == "batch-reject" or not doc:
                    return self._send_json(400, {"errors": [{"message": "batching not allowed"}]})
                return self._send_json(200, [{"data": {"__typename": "Query"}} for _ in doc])
            if isinstance(doc, dict):
                return self._send_json(200, {"data": {"__typename": "Query"}})
            self._send_json(400, {"errors": [{"message": "unsupported body"}]})
    return _start_http(H)


def _make_smug_fixture(mode: str):
    """خادم socket خام. desync: CL+TE معاً → الجسم يُقرأ كاملاً من السلك ثم
    يُمرَّر أول CL بايت فقط للطبقة الخلفية (محاكاة انفصال الأمام/الخلف) —
    إن لم يكن المنتهي 0\r\n\r\n داخل الممرَّر: الخلفية تجوع SMUG_BACK_TIMEOUT.
    compliant-400: الشكل الغامض → 400 فوري. slow-guard: بطء دون العتبة."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.4)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def _handle(conn):
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            head, rest = data.split(b"\r\n\r\n", 1)
            headers = {}
            for line in head.decode("latin-1").split("\r\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            cl = int(headers.get("content-length", "0") or 0)
            te = (headers.get("transfer-encoding") or "").lower()
            body = rest
            if "chunked" in te:
                while b"0\r\n\r\n" not in body:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    body += chunk
            elif cl:
                while len(body) < cl:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    body += chunk
            both = bool(cl) and ("chunked" in te)
            if mode == "compliant-400":
                status, delay = (400, 0.0) if both else (200, 0.0)
            elif mode == "slow-guard":
                status, delay = 200, (0.6 if both else 0.4)
            else:
                status, delay = 200, 0.0
                if both and b"0\r\n\r\n" not in body[:cl]:
                    delay = SMUG_BACK_TIMEOUT
            if delay:
                time.sleep(delay)
            payload = b"smug-fixture-ok"
            conn.sendall(
                f"HTTP/1.1 {status} {'OK' if status == 200 else 'Bad Request'}\r\n"
                "Content-Type: text/plain\r\n"
                f"Content-Length: {len(payload)}\r\n"
                "Connection: close\r\n\r\n".encode() + payload)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _loop():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=_handle, args=(conn,), daemon=True).start()

    threading.Thread(target=_loop, daemon=True).start()

    def _teardown():
        stop.set()
        srv.close()

    return f"http://127.0.0.1:{port}", _teardown


def _make_profile_fixture(mode: str):
    """bind-all: أي حقل يُربط في النموذج؛ whitelist: name/email فقط؛
    no-oracle: لا GET قابل للقراءة (UNTESTABLE)."""
    state = {"name": "sentinel", "email": "s@example.test", "role": "user"}

    class H(_JsonMixin, BaseHTTPRequestHandler):
        def do_GET(self):
            if urlsplit(self.path).path == "/profile":
                if mode == "no-oracle":
                    return self._send_json(404, {"error": "no readable state"})
                return self._send_json(200, state)
            self._send_json(404, {"error": "not found"})

        def do_POST(self):
            if urlsplit(self.path).path != "/profile":
                return self._send_json(404, {"error": "not found"})
            try:
                doc = json.loads(self._body() or b"{}")
            except Exception:
                return self._send_json(400, {"error": "bad json"})
            if mode == "bind-all":
                state.update(doc)
            else:
                for k in ("name", "email"):
                    if k in doc:
                        state[k] = doc[k]
            return self._send_json(200, {"saved": True})

    return _start_http(H)


def _make_settings_fixture(mode: str):
    """node-like: دمج عميق يكتب __proto__ في النموذج المشترك؛ sanitized: يتخطاه.
    الأوراكل: GET /settings يعكس {**proto, **own}."""
    proto: dict = {}
    own = {"theme": "light", "lang": "en"}

    class H(_JsonMixin, BaseHTTPRequestHandler):
        def do_GET(self):
            if urlsplit(self.path).path == "/settings":
                return self._send_json(200, {**proto, **own})
            self._send_json(404, {"error": "not found"})

        def do_POST(self):
            if urlsplit(self.path).path != "/settings":
                return self._send_json(404, {"error": "not found"})
            try:
                doc = json.loads(self._body() or b"{}")
            except Exception:
                return self._send_json(400, {"error": "bad json"})
            for k, v in doc.items():
                if k == "__proto__":
                    if mode == "node-like" and isinstance(v, dict):
                        proto.update(v)
                    continue
                own[k] = v
            return self._send_json(200, {"saved": True})

    return _start_http(H)


def _make_combined_fixture():
    """هدف واحد بأسطح الزناد الست: /login (RS256) + jwks + /protected
    (أبواب confusion وnone معاً؛ التحكم الفاسد مرفوض) + /graphql (batch-enabled)
    + /profile (bind-all بأوراكل) + /settings (node-like) + /smoke (desync على
    POST) + صفحة جذر بروابط ونماذج ليكتشفها الزحف."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as cpad
    from cryptography.hazmat.primitives.asymmetric import rsa
    import hmac as _hmac

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    pub_body = "".join(pub_pem.strip().splitlines()[1:-1])
    nums = key.public_key().public_numbers()
    jwks = {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256",
                      "kid": "sentinel-test-key",
                      "n": _b64u(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")),
                      "e": _b64u(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big"))}]}
    prof = {"name": "sentinel", "email": "s@example.test", "role": "user"}
    proto: dict = {}
    own = {"theme": "light", "lang": "en"}
    ROOT = (b"<html><body>"
            b"<a href='/login'>login</a><a href='/protected'>protected</a>"
            b"<form action='/graphql' method='post'><input name='query'/></form>"
            b"<form action='/profile' method='post'><input name='name'/></form>"
            b"<form action='/settings' method='post'><input name='theme'/></form>"
            b"<form action='/smoke' method='post'><input name='q'/></form>"
            b"</body></html>")

    def _seg(d: dict) -> str:
        return _b64u(json.dumps(d, separators=(",", ":")).encode())

    def _rs256() -> str:
        hp = _seg({"alg": "RS256", "typ": "JWT", "kid": "sentinel-test-key"}) \
            + "." + _seg(FIXED_CLAIMS)
        return hp + "." + _b64u(key.sign(hp.encode(), cpad.PKCS1v15(), hashes.SHA256()))

    def _verify(tok: str) -> bool:
        parts = tok.split(".")
        if len(parts) != 3:
            return False
        try:
            hdr = json.loads(_b64d(parts[0]))
        except Exception:
            return False
        alg = str(hdr.get("alg", "")).upper()
        sig = _b64d(parts[2]) if parts[2] else b""
        hp = parts[0] + "." + parts[1]
        if alg == "RS256":
            try:
                key.public_key().verify(sig, hp.encode(), cpad.PKCS1v15(),
                                        hashes.SHA256())
                return True
            except Exception:
                return False
        if alg == "HS256":
            mac = _hmac.new(pub_body.encode(), hp.encode(), hashlib.sha256).digest()
            return _hmac.compare_digest(mac, sig)   # باب الخلط
        if alg == "NONE" and sig == b"":
            return True                              # باب none
        return False

    class H(_JsonMixin, BaseHTTPRequestHandler):
        def do_GET(self):
            p = urlsplit(self.path).path
            if p == "/":
                b = ROOT
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
                return
            if p == "/login":
                return self._send_json(200, {"token": _rs256()})
            if p in ("/.well-known/jwks.json", "/jwks.json", "/oauth/discovery/keys"):
                return self._send_json(200, jwks)
            if p == "/.well-known/openid-configuration":
                return self._send_json(200, {
                    "issuer": "fixture", "jwks_uri":
                        f"http://127.0.0.1:{self.server.server_address[1]}"
                        f"/.well-known/jwks.json"})
            if p == "/protected":
                auth = self.headers.get("Authorization", "")
                tok = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
                ok = bool(tok) and _verify(tok)
                return self._send_json(200 if ok else 401, {"ok": ok})
            if p == "/profile":
                return self._send_json(200, prof)
            if p == "/settings":
                return self._send_json(200, {**proto, **own})
            self._send_json(404, {"error": "not found"})

        def do_POST(self):
            p = urlsplit(self.path).path
            if p == "/protected":
                return self.do_GET()
            if p == "/graphql":
                try:
                    doc = json.loads(self._body() or b"{}")
                except Exception:
                    return self._send_json(400, {"errors": [{"message": "bad json"}]})
                if isinstance(doc, list):
                    if not doc:
                        return self._send_json(400, {"errors": [{"message": "empty batch"}]})
                    return self._send_json(200, [{"data": {"__typename": "Query"}} for _ in doc])
                if isinstance(doc, dict):
                    return self._send_json(200, {"data": {"__typename": "Query"}})
                return self._send_json(400, {"errors": [{"message": "unsupported body"}]})
            if p == "/profile":
                try:
                    doc = json.loads(self._body() or b"{}")
                except Exception:
                    return self._send_json(400, {"error": "bad json"})
                prof.update(doc)                     # bind-all
                return self._send_json(200, {"saved": True})
            if p == "/settings":
                try:
                    doc = json.loads(self._body() or b"{}")
                except Exception:
                    return self._send_json(400, {"error": "bad json"})
                for k, v in doc.items():
                    if k == "__proto__":
                        if isinstance(v, dict):
                            proto.update(v)          # node-like
                        continue
                    own[k] = v
                return self._send_json(200, {"saved": True})
            if p == "/smoke":
                cl = int(self.headers.get("Content-Length", "0") or 0)
                te = (self.headers.get("Transfer-Encoding") or "").lower()
                body = self._body()
                if cl and "chunked" in te and b"0\r\n\r\n" not in body[:cl]:
                    time.sleep(SMUG_BACK_TIMEOUT)     # الخلفية تجوع — التوقيت
                return self._send_json(200, {"ok": True})
            self._send_json(404, {"error": "not found"})

    return _start_http(H)


# ================================================================ الحالات
def test_H13_01():
    """خلط الخوارزمية — الوضع الضعيف: RS256 يصدر، HS256 بمفتاح PEM العام يُقبل،
    والتحكم الفاسد يُرفض — التفاضل الإلزامي (positive)."""
    from sentinel.modernsec import run_modern_battery
    base, srv = _make_jwt_fixture("confusion-vuln")
    try:
        eng, _bus = _engine("axis13-01")
        eps = [Endpoint(url=base + "/login", method="GET"),
               Endpoint(url=base + "/protected", method="GET")]
        res = run_modern_battery(eng, eps, seed=SEED)
        f = _one(res, "jwt_algorithm_confusion")
        assert f.severity == Severity.HIGH, f.severity
        assert f.endpoint_url.endswith("/protected"), f.endpoint_url
        det = " ".join(e.detail for e in f.evidence)
        assert "HS256" in det and "200" in det and "401" in det, det
        assert 2 <= _sent(res, "jwt_algorithm_confusion") <= 12, res.probe_counts
    finally:
        _stop_http(srv)


def test_H13_02():
    """خلط الخوارزمية — الوضع السليم: المتحقق يقبل RS256 الصحيح فقط؛
    المجس المزور مرفوض والتحكم مرفوض → لا نتيجة + TESTED_NEGATIVE."""
    from sentinel.modernsec import run_modern_battery
    base, srv = _make_jwt_fixture("confusion-neg")
    try:
        eng, _bus = _engine("axis13-02")
        eps = [Endpoint(url=base + "/login", method="GET"),
               Endpoint(url=base + "/protected", method="GET")]
        res = run_modern_battery(eng, eps, seed=SEED)
        _none(res, "jwt_algorithm_confusion")
        _bnd(res, "jwt_algorithm_confusion", "TESTED_NEGATIVE")
        assert _sent(res, "jwt_algorithm_confusion") >= 2, res.probe_counts
    finally:
        _stop_http(srv)


def test_H13_03():
    """خلط الخوارزمية — لا مفتاح قابل للاكتشاف (كل مسارات JWKS 404):
    UNTESTABLE + صفر مجسات (الأمانة الميزانية N7)."""
    from sentinel.modernsec import run_modern_battery
    base, srv = _make_jwt_fixture("no-jwks")
    try:
        eng, _bus = _engine("axis13-03")
        eps = [Endpoint(url=base + "/login", method="GET"),
               Endpoint(url=base + "/protected", method="GET")]
        res = run_modern_battery(eng, eps, seed=SEED)
        _none(res, "jwt_algorithm_confusion")
        _bnd(res, "jwt_algorithm_confusion", "UNTESTABLE")
        assert _sent(res, "jwt_algorithm_confusion") == 0, res.probe_counts
    finally:
        _stop_http(srv)


def test_H13_04():
    """قبول none عند المتحقق — الوضع الضعيف: none بلا توقيع مقبول والفاسد
    مرفوض → النتيجة (positive)."""
    from sentinel.modernsec import run_modern_battery
    base, srv = _make_jwt_fixture("none-vuln")
    try:
        eng, _bus = _engine("axis13-04")
        eps = [Endpoint(url=base + "/login", method="GET"),
               Endpoint(url=base + "/protected", method="GET")]
        res = run_modern_battery(eng, eps, seed=SEED)
        f = _one(res, "jwt_none_acceptance")
        assert f.severity == Severity.HIGH, f.severity
        det = " ".join(e.detail for e in f.evidence)
        assert "none" in det.lower() and "200" in det and "401" in det, det
    finally:
        _stop_http(srv)


def test_H13_05():
    """قبول none — الوضع السليم: المتحقق يرفض none والفاسد معاً →
    لا نتيجة + TESTED_NEGATIVE."""
    from sentinel.modernsec import run_modern_battery
    base, srv = _make_jwt_fixture("none-neg")
    try:
        eng, _bus = _engine("axis13-05")
        eps = [Endpoint(url=base + "/login", method="GET"),
               Endpoint(url=base + "/protected", method="GET")]
        res = run_modern_battery(eng, eps, seed=SEED)
        _none(res, "jwt_none_acceptance")
        _bnd(res, "jwt_none_acceptance", "TESTED_NEGATIVE")
        assert _sent(res, "jwt_none_acceptance") >= 2, res.probe_counts
    finally:
        _stop_http(srv)


def test_H13_06():
    """التحكم الصارم للتفاضل: متحقق يقبل كل شيء (none والفاسد معاً) →
    ليست نتيجة؛ تسجَّل OBSERVED_ANOMALY (لا تصنيفاً كاذباً)."""
    from sentinel.modernsec import run_modern_battery
    base, srv = _make_jwt_fixture("any-sig")
    try:
        eng, _bus = _engine("axis13-06")
        eps = [Endpoint(url=base + "/login", method="GET"),
               Endpoint(url=base + "/protected", method="GET")]
        res = run_modern_battery(eng, eps, seed=SEED)
        _none(res, "jwt_none_acceptance")
        _none(res, "jwt_algorithm_confusion")
        b = _bnd(res, "jwt_none_acceptance", "OBSERVED_ANOMALY")
        assert "signature" in b.get("detail", "").lower(), b
    finally:
        _stop_http(srv)


def test_H13_07():
    """GraphQL batching — الوضع المفعَّل: مصفوفة عمليتين تُنفَّذان معاً →
    النتيجة (positive)."""
    from sentinel.modernsec import run_modern_battery
    base, srv = _make_gql_fixture("batch-enabled")
    try:
        eng, _bus = _engine("axis13-07")
        eps = [Endpoint(url=base + "/graphql", method="POST")]
        res = run_modern_battery(eng, eps, seed=SEED)
        f = _one(res, "graphql_batching_enabled")
        assert f.severity == Severity.LOW, f.severity
        det = " ".join(e.detail for e in f.evidence)
        assert "batch" in det.lower(), det
    finally:
        _stop_http(srv)


def test_H13_08():
    """GraphQL batching — الوضع السليم: المصفوفة تُرفض 400 → لا نتيجة."""
    from sentinel.modernsec import run_modern_battery
    base, srv = _make_gql_fixture("batch-reject")
    try:
        eng, _bus = _engine("axis13-08")
        eps = [Endpoint(url=base + "/graphql", method="POST")]
        res = run_modern_battery(eng, eps, seed=SEED)
        _none(res, "graphql_batching_enabled")
        _bnd(res, "graphql_batching_enabled", "TESTED_NEGATIVE")
    finally:
        _stop_http(srv)


def test_H13_09():
    """التهريب بالتوقيت — الوضع الضعيف: CL+TE معاً → الخلفية تجوع
    SMUG_BACK_TIMEOUT والتحكم سريع → النتيجة بصنف مؤَزَّن desync (N3)."""
    from sentinel.modernsec import run_modern_battery
    base, teardown = _make_smug_fixture("desync")
    try:
        eng, _bus = _engine("axis13-09")
        eps = [Endpoint(url=base + "/smoke", method="POST")]
        res = run_modern_battery(eng, eps, seed=SEED)
        f = _one(res, "http_request_smuggling")
        assert f.severity == Severity.MEDIUM, f.severity
        det = " ".join(e.detail for e in f.evidence)
        assert "desync" in det, det
    finally:
        teardown()


def test_H13_10():
    """التهريب — الخادم الممتثل: الشكل الغامض يُرفض 400 فوراً → لا نتيجة
    (لا ادعاء توقيت على رفض صريح)."""
    from sentinel.modernsec import run_modern_battery
    base, teardown = _make_smug_fixture("compliant-400")
    try:
        eng, _bus = _engine("axis13-10")
        eps = [Endpoint(url=base + "/smoke", method="POST")]
        res = run_modern_battery(eng, eps, seed=SEED)
        _none(res, "http_request_smuggling")
        b = _bnd(res, "http_request_smuggling", "TESTED_NEGATIVE")
        assert "ambiguous" in b.get("detail", "").lower(), b
    finally:
        teardown()


def test_H13_11():
    """التهريب — حارس ضد FP: بطء عام دون العتبة (تحكم 0.4s / مجس 0.6s؛
    العتبة max(3×التحكم, 500ms)=1.2s) → لا نتيجة below-threshold."""
    from sentinel.modernsec import run_modern_battery
    base, teardown = _make_smug_fixture("slow-guard")
    try:
        eng, _bus = _engine("axis13-11")
        eps = [Endpoint(url=base + "/smoke", method="POST")]
        res = run_modern_battery(eng, eps, seed=SEED)
        _none(res, "http_request_smuggling")
        b = _bnd(res, "http_request_smuggling", "TESTED_NEGATIVE")
        assert "below-threshold" in b.get("detail", ""), b
    finally:
        teardown()


def test_H13_12():
    """Mass assignment — الوضع الضعيف: الحقل الامتيازي الشكل يُربط ويُخزَّن
    (state-oracle على كائن الجلسة الذاتية) → النتيجة (positive)."""
    from sentinel.modernsec import run_modern_battery
    base, srv = _make_profile_fixture("bind-all")
    try:
        eng, _bus = _engine("axis13-12")
        eps = [Endpoint(url=base + "/profile", method="POST")]
        res = run_modern_battery(eng, eps, seed=SEED)
        f = _one(res, "mass_assignment")
        assert f.severity == Severity.HIGH, f.severity
        det = " ".join(e.detail for e in f.evidence)
        assert "role" in det and "canary" in det.lower(), det
    finally:
        _stop_http(srv)


def test_H13_13():
    """Mass assignment — الوضع السليم: القائمة البيضاء تتجاهل الحقل →
    لا نتيجة + TESTED_NEGATIVE."""
    from sentinel.modernsec import run_modern_battery
    base, srv = _make_profile_fixture("whitelist")
    try:
        eng, _bus = _engine("axis13-13")
        eps = [Endpoint(url=base + "/profile", method="POST")]
        res = run_modern_battery(eng, eps, seed=SEED)
        _none(res, "mass_assignment")
        _bnd(res, "mass_assignment", "TESTED_NEGATIVE")
        assert _sent(res, "mass_assignment") >= 2, res.probe_counts
    finally:
        _stop_http(srv)


def test_H13_14():
    """Mass assignment — بلا أوراكل حالة (GET 404): UNTESTABLE + صفر مجسات."""
    from sentinel.modernsec import run_modern_battery
    base, srv = _make_profile_fixture("no-oracle")
    try:
        eng, _bus = _engine("axis13-14")
        eps = [Endpoint(url=base + "/profile", method="POST")]
        res = run_modern_battery(eng, eps, seed=SEED)
        _none(res, "mass_assignment")
        _bnd(res, "mass_assignment", "UNTESTABLE")
        assert _sent(res, "mass_assignment") == 0, res.probe_counts
    finally:
        _stop_http(srv)


def test_H13_15():
    """Prototype pollution — الوضع الضعيف: __proto__ يكتب في النموذج المشترك
    والأوراكل يعكس الـcanary في موضع لم يرسله العميل → النتيجة (positive)."""
    from sentinel.modernsec import run_modern_battery
    base, srv = _make_settings_fixture("node-like")
    try:
        eng, _bus = _engine("axis13-15")
        eps = [Endpoint(url=base + "/settings", method="POST")]
        res = run_modern_battery(eng, eps, seed=SEED)
        f = _one(res, "prototype_pollution")
        assert f.severity == Severity.HIGH, f.severity
        det = " ".join(e.detail for e in f.evidence)
        assert "__proto__" in det and "canary" in det.lower(), det
    finally:
        _stop_http(srv)


def test_H13_16():
    """Prototype pollution — الوضع السليم: الدمج يتخطى __proto__ →
    لا نتيجة + TESTED_NEGATIVE."""
    from sentinel.modernsec import run_modern_battery
    base, srv = _make_settings_fixture("sanitized")
    try:
        eng, _bus = _engine("axis13-16")
        eps = [Endpoint(url=base + "/settings", method="POST")]
        res = run_modern_battery(eng, eps, seed=SEED)
        _none(res, "prototype_pollution")
        _bnd(res, "prototype_pollution", "TESTED_NEGATIVE")
        assert _sent(res, "prototype_pollution") >= 2, res.probe_counts
    finally:
        _stop_http(srv)


def test_H13_17():
    """تثبيت التسجيل في النقاط الأربع (13.3): SARIF + IMPACT + HYPOTHESIS +
    REPLAYABLE + RISK — بالمعرفات والمستويات الحرفية من المواصفة §13.1."""
    from sentinel.modernsec import MODERN_TYPES
    from sentinel.report import SARIF_RULES
    from sentinel.evidence import IMPACT_PROFILES, HYPOTHESIS_BY_CLASS, REPLAYABLE_TYPES
    from sentinel.intel import RISK_WEIGHTS
    ids = {"jwt_algorithm_confusion": "SEN-JWT-002",
           "jwt_none_acceptance": "SEN-JWT-003",
           "graphql_batching_enabled": "SEN-GQL-008",
           "http_request_smuggling": "SEN-SMK-001",
           "mass_assignment": "SEN-MA-001",
           "prototype_pollution": "SEN-PP-001"}
    levels = {"jwt_algorithm_confusion": "proven", "jwt_none_acceptance": "proven",
              "graphql_batching_enabled": "indicated",
              "http_request_smuggling": "indicated",
              "mass_assignment": "proven", "prototype_pollution": "proven"}
    assert MODERN_TYPES == ("jwt_algorithm_confusion", "jwt_none_acceptance",
                            "graphql_batching_enabled", "http_request_smuggling",
                            "mass_assignment", "prototype_pollution"), MODERN_TYPES
    for t in ids:
        assert SARIF_RULES[t] == ids[t], (t, SARIF_RULES.get(t))
        assert IMPACT_PROFILES[t][0] == levels[t], (t, IMPACT_PROFILES[t][0])
        assert t in HYPOTHESIS_BY_CLASS, t
        assert t in REPLAYABLE_TYPES, t
        assert t in RISK_WEIGHTS, t


def test_H13_18():
    """توجيه VR + fail-closed: نتيجة confusion تُوجَّه لفرعها وتصير VERIFIED
    بعد إعادة التفاضل الحي؛ والنوع غير المسجل يظل مرفوضاً (v4.2.0 باقٍ)."""
    from sentinel.modernsec import run_modern_battery
    from sentinel.intel import VerificationEngine
    base, srv = _make_jwt_fixture("confusion-vuln")
    try:
        eng, bus = _engine("axis13-18")
        eps = [Endpoint(url=base + "/login", method="GET"),
               Endpoint(url=base + "/protected", method="GET")]
        res = run_modern_battery(eng, eps, seed=SEED)
        f = _one(res, "jwt_algorithm_confusion")
        ver = VerificationEngine(eng, bus)
        out = ver.verify(f, eps[1])
        assert out.status == FindingStatus.VERIFIED, (out.status, out.verification)
        assert out.verification.passed, out.verification.notes
        fake = Finding("totally_unregistered_type", Severity.LOW,
                       base + "/protected", "-", "GET",
                       [Evidence("x", "unregistered", "none")],
                       status=FindingStatus.CANDIDATE)
        out2 = ver.verify(fake, eps[1])
        assert out2.status == FindingStatus.REJECTED, out2.status
    finally:
        _stop_http(srv)


def test_H13_19():
    """التوصيل الكامل عبر الماسح الحقيقي: هدف مركّب واحد → المسح يطلق
    البطارية (التوصيل الكسول) والست كلها تصل VERIFIED؛ ونفس البذرة =
    نفس النتائج (الحتمية) — مسحاً مستقلين."""
    from sentinel.modernsec import MODERN_TYPES
    from sentinel.orchestrator import ScanConfig, SentinelScanner
    base, srv = _make_combined_fixture()
    try:
        def _scan():
            cfg = ScanConfig(allow_private=True, max_pages=6, crawl=True, active=True,
                             passive=True, timeout=8.0, seed="axis13-e2e", browser=False,
                             oast=None, graphql=True, websocket=False, secrets=False)
            sc = SentinelScanner(base + "/", cfg)
            sc.run()
            return sc

        sc1 = _scan()
        sc2 = _scan()

        def _sig(sc):
            return sorted((f.type, f.parameter, urlsplit(f.endpoint_url).path)
                          for f in sc.findings if f.status == FindingStatus.VERIFIED)

        sig1, sig2 = _sig(sc1), _sig(sc2)
        got = {t for t, _p, _u in sig1}
        for t in MODERN_TYPES:
            assert t in got, f"missing {t} in verified set: {sorted(got)}"
        assert sig1 == sig2, "determinism: same seed must give the same verified set"
    finally:
        _stop_http(srv)


def test_H13_20():
    """انضباط الوحدة: استيراد كسول (orchestrator لا يسحب modernsec على مستوى
    الوحدة — عملية فرعية نظيفة)، المفردات الحرفية، POST_BUDGET، وحتمية
    derive_canary."""
    from sentinel.modernsec import (JWKS_PATHS, MERGE_NAMES, POST_BUDGET,
                                    PRIV_NAMES, UPDATE_NAMES, derive_canary)
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    probe = subprocess.run(
        [sys.executable, "-c",
         "import sys, sentinel.orchestrator; "
         "print('sentinel.modernsec' in sys.modules)"],
        cwd=here, capture_output=True, text=True, timeout=120)
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.strip() == "False", (
        "the orchestrator must import modernsec LAZILY (the graphql/wsattack pattern), "
        f"got: {probe.stdout!r}")
    assert JWKS_PATHS == ("/.well-known/jwks.json", "/jwks.json",
                          "/.well-known/openid-configuration",
                          "/oauth/discovery/keys"), JWKS_PATHS
    for w in ("role", "is_admin", "isAdmin", "admin", "account_type",
              "user_type", "privilege", "permissions"):
        assert w in PRIV_NAMES, w
    for w in ("profile", "settings", "account", "user"):
        assert w in UPDATE_NAMES, w
    assert any("settings" in w for w in MERGE_NAMES) and MERGE_NAMES
    assert POST_BUDGET == 8, POST_BUDGET
    c1, c2 = derive_canary(SEED, "ma"), derive_canary(SEED, "ma")
    c3, c4 = derive_canary(SEED, "pp"), derive_canary(SEED + 1, "ma")
    assert c1 == c2 and c1 != c3 and c1 != c4, (c1, c2, c3, c4)
    assert c1.startswith("sentinel-"), c1


# ============================================================ وضع السكربت
def _run_all() -> list:
    names = [n for n in sorted(globals())
             if n.startswith("test_H13_") and callable(globals()[n])]
    results = []
    for name in names:
        fn = globals()[name]
        t0 = time.perf_counter()
        try:
            fn()
            results.append({"name": name, "ok": True, "error": None,
                            "dur_s": round(time.perf_counter() - t0, 6)})
        except BaseException as exc:  # noqa: BLE001 — الدليل يلتقط كل شيء
            results.append({"name": name, "ok": False, "error": repr(exc),
                            "dur_s": round(time.perf_counter() - t0, 6)})
    return results


def _digest(results: list) -> str:
    """هضم التيار المنطقي: (اسم الحالة، نجحت؟) فقط — الأزمنة والقيود
    المقاسة خارج الهضم (N3 + انضباط المحور-11 الموروث)."""
    h = hashlib.sha256()
    for r_ in results:
        h.update(f"{r_['name']}:{int(r_['ok'])}".encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="SENTINEL Axis-13 suite")
    ap.add_argument("--out", default="", help="مسار ملف دليل JSON")
    args = ap.parse_args()

    results = _run_all()
    passed = sum(1 for r_ in results if r_["ok"])
    total = len(results)
    doc = {
        "suite": SUITE,
        "station": "M1-RED" if passed == 0 else "run",
        "total": total,
        "passed_count": passed,
        "failed": total - passed,
        "passed": passed == total,
        "digest": _digest(results),
        "cases": results,
    }
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1, ensure_ascii=False)
        print(f"evidence -> {args.out}")
    print(f"axis13: {passed}/{total} passed | digest {doc['digest'][:16]}")
    for r_ in results:
        mark = "PASS" if r_["ok"] else "FAIL"
        print(f"  [{mark}] {r_['name']}"
              + ("" if r_["ok"] else f"  {r_['error']}"))
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())

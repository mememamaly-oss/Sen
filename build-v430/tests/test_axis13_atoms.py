#!/usr/bin/env python3
"""SENTINEL Axis-13 ATOMS — البطاريات الثلاث فوق محرك M2 (modernsec).

التصميم (نمط المحاور 7/8/11/12):
  13a — 48 دورة مزروعة (16 نمطاً ×3): تصنيف كل عائلة معلوم بالبناء؛
        مروران كاملان يعيدان نفس قائمة الأختام بالبايت؛ قلب بت في توقع
        واحد يغيّر الختم.
  13b — 100 مطابقة مرجع مستقل بايت-ببايت (25 بناء PEM مقابل cryptography،
        25 derive_canary، 20 _corrupt_sig، 15 recipe_of، 15 المفردات).
  13c — بالضبط 40 عدائياً 12+10+8+6+4: بنائية / تخريب (الكذب بين المجس
        والتحقق يُلتقط بالـVR fail-closed) / دقة / حدود-تحريف / حيوية.

الوصفة: python3 tests/test_axis13_atoms.py --out results/axis13/axis13_ATOMS.json
"""
import hashlib
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests"))

import test_axis13_detectors as wing
from sentinel.core import Endpoint, Evidence, Finding, FindingStatus, Severity
from sentinel.http_engine import RequestEngine, RequestMutation
from sentinel.intel import VerificationEngine
from sentinel.modernsec import (JWKS_PATHS, MERGE_NAMES, MODERN_TYPES, POST_BUDGET,
                                PRIV_NAMES, UPDATE_NAMES, _corrupt_sig, derive_canary,
                                recipe_of, run_modern_battery,
                                rsa_pem_body_from_jwks)

SMUG_BACK_TIMEOUT = wing.SMUG_BACK_TIMEOUT

SUITE = "axis13-atoms"
SEED = 13


def _engine(run):
    return wing._engine(run)


# ------------------------------------------------- مصانع إضافية للـ13c فقط
def _make_unsigned_login_fixture():
    """يصدر رمز alg=none بلا توقيع — عائلة none: UNTESTABLE (already unsigned)."""
    from http.server import BaseHTTPRequestHandler

    class H(wing._JsonMixin, BaseHTTPRequestHandler):
        def do_GET(self):
            p = urlsplit(self.path).path
            if p == "/login":
                seg = wing._b64u(json.dumps({"alg": "none", "typ": "JWT"},
                                            separators=(",", ":")).encode()) + "." + \
                    wing._b64u(json.dumps(wing.FIXED_CLAIMS,
                                          separators=(",", ":")).encode()) + "."
                return self._send_json(200, {"token": seg})
            if p == "/protected":
                return self._send_json(401, {"ok": False})
            self._send_json(404, {"error": "nf"})

    return wing._start_http(H)


def _make_lying_http_fixture(kind: str):
    """أبواب تكذب بين المجس والتحقق: تقبل الأول ثم تُغلق (أو تعكس الشكل)."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as cpad
    from cryptography.hazmat.primitives.asymmetric import rsa
    import hmac as _hmac
    import socket as _s

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    pub_body = "".join(pub_pem.strip().splitlines()[1:-1])
    nums = key.public_key().public_numbers()
    jwks = {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "sentinel-test-key",
                      "n": wing._b64u(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")),
                      "e": wing._b64u(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big"))}]}
    hit = {"n": 0}
    state = {"name": "sentinel", "role": "user"}
    proto: dict = {}
    own = {"theme": "light"}

    def _seg(d):
        return wing._b64u(json.dumps(d, separators=(",", ":")).encode())

    def _rs256():
        hp = _seg({"alg": "RS256", "typ": "JWT", "kid": "sentinel-test-key"}) + "." + \
            _seg(wing.FIXED_CLAIMS)
        return hp + "." + wing._b64u(
            key.sign(hp.encode(), cpad.PKCS1v15(), hashes.SHA256()))

    def _verify(tok):
        parts = tok.split(".")
        if len(parts) != 3:
            return False
        try:
            hdr = json.loads(wing._b64d(parts[0]))
        except Exception:
            return False
        alg = str(hdr.get("alg", "")).upper()
        sig = wing._b64d(parts[2]) if parts[2] else b""
        hp = parts[0] + "." + parts[1]
        if kind == "confusion" and alg == "HS256" and hit["n"] < 1:
            mac = _hmac.new(pub_body.encode(), hp.encode(), hashlib.sha256).digest()
            if _hmac.compare_digest(mac, sig):
                hit["n"] += 1
                return True
        if kind == "none" and alg == "NONE" and sig == b"" and hit["n"] < 1:
            hit["n"] += 1
            return True
        if alg == "RS256":
            try:
                key.public_key().verify(sig, hp.encode(), cpad.PKCS1v15(), hashes.SHA256())
                return True
            except Exception:
                return False
        if alg == "HS256":
            mac = _hmac.new(b"axis13-fixture-hs-secret", hp.encode(), hashlib.sha256).digest()
            return _hmac.compare_digest(mac, sig)
        return False

    class H(wing._JsonMixin, BaseHTTPRequestHandler):
        def do_GET(self):
            p = urlsplit(self.path).path
            if p == "/login" and kind in ("confusion", "none"):
                return self._send_json(200, {"token": _rs256()})
            if p in ("/.well-known/jwks.json", "/jwks.json", "/oauth/discovery/keys") \
                    and kind in ("confusion", "none"):
                return self._send_json(200, jwks)
            if p == "/protected" and kind in ("confusion", "none"):
                auth = self.headers.get("Authorization", "")
                tok = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
                ok = bool(tok) and _verify(tok)
                return self._send_json(200 if ok else 401, {"ok": ok})
            if p == "/profile" and kind == "profile":
                return self._send_json(200, state)
            if p == "/settings" and kind == "settings":
                return self._send_json(200, {**proto, **own})
            self._send_json(404, {"error": "nf"})

        def do_POST(self):
            p = urlsplit(self.path).path
            if p == "/protected" and kind in ("confusion", "none"):
                return self.do_GET()
            if p == "/graphql" and kind in ("gql-counter", "gql-shape"):
                try:
                    doc = json.loads(self._body() or b"{}")
                except Exception:
                    return self._send_json(400, {"errors": [{"message": "bad json"}]})
                if isinstance(doc, list):
                    if kind == "gql-counter":
                        if hit["n"] < 1:
                            hit["n"] += 1
                            return self._send_json(
                                200, [{"data": {"__typename": "Query"}} for _ in doc])
                        return self._send_json(400, {"errors": [{"message": "no"}]})
                    if kind == "gql-shape":
                        if len(doc) == 2 and all(q.get("query") == "{__typename}" for q in doc):
                            return self._send_json(
                                200, [{"data": {"__typename": "Query"}} for _ in doc])
                        return self._send_json(400, {"errors": [{"message": "shape"}]})
                if isinstance(doc, dict):
                    return self._send_json(200, {"data": {"__typename": "Query"}})
                return self._send_json(400, {"errors": [{"message": "unsupported"}]})
            if p == "/profile" and kind == "profile":
                try:
                    doc = json.loads(self._body() or b"{}")
                except Exception:
                    return self._send_json(400, {"error": "bad json"})
                if "role" in doc and hit["n"] < 1:      # يقبل الأول ثم يُغلق
                    hit["n"] += 1
                    state.update(doc)
                else:
                    for k in ("name", "email"):
                        if k in doc:
                            state[k] = doc[k]
                return self._send_json(200, {"saved": True})
            if p == "/settings" and kind == "settings":
                try:
                    doc = json.loads(self._body() or b"{}")
                except Exception:
                    return self._send_json(400, {"error": "bad json"})
                pp = doc.get("__proto__")
                if isinstance(pp, dict) and hit["n"] < 1:
                    hit["n"] += 1
                    proto.update(pp)
                    doc = {k: v for k, v in doc.items() if k != "__proto__"}
                for k, v in doc.items():
                    if k != "__proto__":
                        own[k] = v
                return self._send_json(200, {"saved": True})
            self._send_json(404, {"error": "nf"})

    return wing._start_http(H)


def _make_lying_smug(kind: str):
    """خادم خام يكذب: ينام للـCL+TE مرة/مرتين فقط، أو يستيقظ لـcanary الـVR تحديداً."""
    import socket as _s
    srv = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
    srv.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.4)
    port = srv.getsockname()[1]
    stop = threading.Event()
    hits = {"n": 0}

    def _handle(conn):
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                c = conn.recv(4096)
                if not c:
                    return
                data += c
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
                    c = conn.recv(4096)
                    if not c:
                        break
                    body += c
            elif cl:
                while len(body) < cl:
                    c = conn.recv(4096)
                    if not c:
                        break
                    body += c
            delay = 0.0
            if cl and "chunked" in te:
                if kind == "once" and hits["n"] < 1:
                    hits["n"] += 1
                    delay = SMUG_BACK_TIMEOUT
                elif kind == "vr-aware" and b"sentinel-vr32" not in body[:80] \
                        and b"smug-probe" in body[:80]:
                    delay = SMUG_BACK_TIMEOUT
                elif kind == "len-aware" and cl >= 25:
                    delay = SMUG_BACK_TIMEOUT
            if delay:
                time.sleep(delay)
            payload = b"smug-late-ok"
            conn.sendall(
                f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
                + payload)
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
            except (TimeoutError, OSError):
                continue
            threading.Thread(target=_handle, args=(conn,), daemon=True).start()

    threading.Thread(target=_loop, daemon=True).start()

    def _teardown():
        stop.set()
        srv.close()

    return f"http://127.0.0.1:{port}", _teardown


# ================================================================ 13a
CYCLE_PLAN = [
    ("confusion-vuln", "jwt", {"jwt_algorithm_confusion": "FINDING",
                               "jwt_none_acceptance": "TESTED_NEGATIVE"}),
    ("confusion-neg", "jwt", {"jwt_algorithm_confusion": "TESTED_NEGATIVE",
                              "jwt_none_acceptance": "TESTED_NEGATIVE"}),
    ("none-vuln", "jwt", {"jwt_algorithm_confusion": "NOT_DISCOVERED",
                          "jwt_none_acceptance": "FINDING"}),
    ("none-neg", "jwt", {"jwt_algorithm_confusion": "NOT_DISCOVERED",
                         "jwt_none_acceptance": "TESTED_NEGATIVE"}),
    ("no-jwks", "jwt", {"jwt_algorithm_confusion": "UNTESTABLE",
                        "jwt_none_acceptance": "TESTED_NEGATIVE"}),
    ("any-sig", "jwt", {"jwt_algorithm_confusion": "NOT_DISCOVERED",
                        "jwt_none_acceptance": "OBSERVED_ANOMALY"}),
    ("batch-enabled", "gql", {"graphql_batching_enabled": "FINDING",
                              "http_request_smuggling": "UNTESTABLE"}),
    ("batch-reject", "gql", {"graphql_batching_enabled": "TESTED_NEGATIVE",
                             "http_request_smuggling": "UNTESTABLE"}),
    ("desync", "smug", {"http_request_smuggling": "FINDING"}),
    ("compliant-400", "smug", {"http_request_smuggling": "TESTED_NEGATIVE"}),
    ("slow-guard", "smug", {"http_request_smuggling": "TESTED_NEGATIVE"}),
    ("bind-all", "profile", {"mass_assignment": "FINDING",
                              "http_request_smuggling": "UNTESTABLE"}),
    ("whitelist", "profile", {"mass_assignment": "TESTED_NEGATIVE",
                               "http_request_smuggling": "UNTESTABLE"}),
    ("no-oracle", "profile", {"mass_assignment": "UNTESTABLE",
                               "http_request_smuggling": "UNTESTABLE"}),
    ("node-like", "settings", {"prototype_pollution": "FINDING",
                                "mass_assignment": "FINDING",
                                "http_request_smuggling": "UNTESTABLE"}),
    ("sanitized", "settings", {"prototype_pollution": "TESTED_NEGATIVE",
                                "mass_assignment": "FINDING",
                                "http_request_smuggling": "UNTESTABLE"}),
]


def _classification(res, fam):
    if any(f.type == fam for f in res.findings):
        return "FINDING"
    for b in res.boundaries:
        if b["family"] == fam:
            return b["kind"]
    return "NONE"


def _expected_full(partial):
    full = dict(partial)
    for fam in MODERN_TYPES:
        full.setdefault(fam, "NOT_DISCOVERED")
    return full


def _one_cycle(mode, cls, i):
    """دورة واحدة: fixture + بطارية + التقاء. يعيد سجل الدورة."""
    if cls == "jwt":
        base, srv = wing._make_jwt_fixture(mode)
        eps = [Endpoint(url=base + "/login", method="GET"),
               Endpoint(url=base + "/protected", method="GET")]
    elif cls == "gql":
        base, srv = wing._make_gql_fixture(mode)
        eps = [Endpoint(url=base + "/graphql", method="POST")]
    elif cls == "smug":
        base, srv = wing._make_smug_fixture(mode)
        eps = [Endpoint(url=base + "/smoke", method="POST")]
    elif cls == "profile":
        base, srv = wing._make_profile_fixture(mode)
        eps = [Endpoint(url=base + "/profile", method="POST")]
    else:
        base, srv = wing._make_settings_fixture(mode)
        eps = [Endpoint(url=base + "/settings", method="POST")]
    try:
        eng, bus = _engine(f"atoms-13a-{mode}-{i}")
        res = run_modern_battery(eng, eps, seed=SEED)
        partial = next(p for m, c, p in CYCLE_PLAN if m == mode)
        full = _expected_full(partial)
        got = {fam: _classification(res, fam) for fam in MODERN_TYPES}
        agree = got == full
        return {"mode": mode, "i": i, "expected": full, "got": got, "agree": agree}
    finally:
        if callable(srv):
            srv()
        elif isinstance(srv, tuple):
            srv[1]()
        else:
            wing._stop_http(srv)


def _seal_sha(records):
    h = hashlib.sha256()
    for r in records:
        h.update(json.dumps({k: r[k] for k in ("mode", "i")}, sort_keys=True).encode())
        h.update(json.dumps(r["expected"], sort_keys=True).encode())
        h.update(json.dumps(r["got"], sort_keys=True).encode())
        h.update(str(r["agree"]).encode())
        h.update(b"\n")
    return h.hexdigest()


def battery_13a():
    """48 دورة × مرورين + حساسية قلب البت."""
    records, passes = [], []
    for p in range(2):
        recs = []
        for mode, cls, _partial in CYCLE_PLAN:
            for i in range(3):
                recs.append(_one_cycle(mode, cls, i))
        passes.append(_seal_sha(recs))
        if p == 0:
            records = recs
    repeatable = passes[0] == passes[1]
    agreement = sum(1 for r in records if r["agree"])
    # حساسية قلب البت: قلب توقع واحد (النتيجة 1) يغيّر الختم
    flipped = [dict(r) for r in records]
    if flipped:
        flipped[0] = dict(flipped[0])
        flipped[0]["expected"] = dict(flipped[0]["expected"])
        flipped[0]["expected"]["jwt_none_acceptance"] = "FINDING" \
            if flipped[0]["expected"]["jwt_none_acceptance"] != "FINDING" else "TESTED_NEGATIVE"
    bit_flip_sensitive = _seal_sha(flipped) != passes[0] if flipped else False
    ok = agreement == len(records) and repeatable and bit_flip_sensitive
    return {"ok": ok, "detail": {
        "cycles": len(records), "agreement": agreement,
        "repeatable": repeatable, "bit_flip_sensitive": bit_flip_sensitive,
        "seal_list_sha": passes[0][:16], "second_pass_sha": passes[1][:16],
        "records": records}}


# ================================================================ 13b
def battery_13b():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    matched = 0
    mismatches = []
    breakdown = {"pem": 0, "canary": 0, "corrupt_sig": 0, "recipe": 0, "vocab": 0}

    def _match(kind, label, got, ref):
        nonlocal matched
        if got == ref:
            matched += 1
            breakdown[kind] = breakdown.get(kind, 0) + 1
        else:
            mismatches.append({"label": label, "got": str(got)[:80], "ref": str(ref)[:80]})

    # 25 بناء PEM مقابل cryptography (مرجع مستقل)
    for i in range(25):
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        nums = k.public_key().public_numbers()
        pem = k.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        ref = "".join(pem.strip().splitlines()[1:-1])
        _match("pem", f"pem-{i}", rsa_pem_body_from_jwks(nums.n, nums.e), ref)

    # 25 derive_canary مقابل إعادة اشتقاق مستقلة
    for i in range(25):
        seed, ns = 13 + i, f"ns-{i}"
        ref = "sentinel-" + hashlib.sha256(f"{seed}|{ns}".encode()).hexdigest()[:12]
        _match("canary", f"canary-{i}", derive_canary(seed, ns), ref)

    # 20 _corrupt_sig: البايتات المفكوكة تتغير حتماً والرأس/الادعاءات كما هي
    import base64 as _b
    for i in range(20):
        hp = f"h{i}." + "p" * 20 + "."
        sig = wing._b64u(hashlib.sha256(f"sig-{i}".encode()).digest())
        tok = f"h{i}." + "p" * 20 + "." + sig
        bad = _corrupt_sig(tok)
        orig_bytes = _b.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
        bad_bytes = _b.urlsafe_b64decode(bad.split(".")[2] + "=" * (-len(bad.split(".")[2]) % 4))
        head_unchanged = bad.split(".")[0] == tok.split(".")[0] and bad.split(".")[1] == tok.split(".")[1]
        _match("corrupt_sig", f"corrupt-{i}",
               (orig_bytes != bad_bytes, head_unchanged), (True, True))

    # 15 recipe_of على أدلة مركبة
    for i in range(15):
        f = Finding("jwt_algorithm_confusion", Severity.HIGH, f"http://x/{i}/protected",
                    "-", "GET",
                    [Evidence("probe_recipe",
                              f"auth=http://x/{i}/login; protected=http://x/{i}/protected; jwks=http://x/{i}/jwks",
                              ""),
                     Evidence("other", "noise", "")],
                    status=FindingStatus.CANDIDATE)
        ref = {"auth": f"http://x/{i}/login", "protected": f"http://x/{i}/protected",
               "jwks": f"http://x/{i}/jwks"}
        _match("recipe", f"recipe-{i}", recipe_of(f), ref)

    # 15 المفردات الحرفية (مرجع مستقل مكتوب يدوياً)
    _match("vocab", "vocab-types", MODERN_TYPES,
           ("jwt_algorithm_confusion", "jwt_none_acceptance", "graphql_batching_enabled",
            "http_request_smuggling", "mass_assignment", "prototype_pollution"))
    _match("vocab", "vocab-jwks", JWKS_PATHS,
           ("/.well-known/jwks.json", "/jwks.json", "/.well-known/openid-configuration",
            "/oauth/discovery/keys"))
    _match("vocab", "vocab-priv", PRIV_NAMES,
           ("role", "is_admin", "isAdmin", "admin", "account_type", "user_type",
            "privilege", "permissions"))
    _match("vocab", "vocab-update", UPDATE_NAMES, ("profile", "settings", "account", "user"))
    _match("vocab", "vocab-merge", MERGE_NAMES,
           ("settings", "config", "preferences", "save", "update"))
    _match("vocab", "vocab-budget", POST_BUDGET, 8)
    for i in range(9):
        _match("vocab", f"vocab-canary-sep-{i}",
               (derive_canary(13, f"a{i}") != derive_canary(13, f"b{i}"),
                derive_canary(13, f"a{i}") == derive_canary(13, f"a{i}")),
               (True, True))
    return {"ok": matched == 100 and not mismatches, "detail": {
        "matched": matched, "mismatches": len(mismatches), "breakdown": breakdown,
        "mismatch_list": mismatches[:10]}}


# ================================================================ 13c
def battery_13c():
    results = []

    def _record(name, caught, why=""):
        results.append({"name": name, "ok": bool(caught), "why": why})

    # ---- 12 بنائية
    try:
        res = run_modern_battery(_engine("c-struct-1")[0], None, seed=SEED)
        _record("struct-01 endpoints=None", all(
            b["kind"] == "NOT_DISCOVERED" for b in res.boundaries) and not res.findings)
    except Exception as e:
        _record("struct-01 endpoints=None", False, repr(e))
    try:
        eng = _engine("c-struct-2")[0]
        res = run_modern_battery(eng, [Endpoint(url="::::bad", method="POST")], seed=SEED)
        _record("struct-02 unparsable url", not res.findings)
    except Exception as e:
        _record("struct-02 unparsable url", False, repr(e))
    try:
        eng = _engine("c-struct-3")[0]
        res = run_modern_battery(eng, [Endpoint(url="https://127.0.0.1:1/x", method="POST")],
                                 seed=SEED)
        b = next((x for x in res.boundaries if x["family"] == "http_request_smuggling"
                  and "http-only" in x["detail"]), None)
        _record("struct-03 https smuggling skip", b is not None and not res.findings)
    except Exception as e:
        _record("struct-03 https smuggling skip", False, repr(e))
    try:
        eng = _engine("c-struct-4")[0]
        res = run_modern_battery(eng, [Endpoint(url="http://example.test/x", method="POST")],
                                 seed=SEED)
        b = next((x for x in res.boundaries if x["family"] == "http_request_smuggling"
                  and "scope" in x["detail"]), None)
        _record("struct-04 out-of-scope host", b is not None and not res.findings)
    except Exception as e:
        _record("struct-04 out-of-scope host", False, repr(e))
    try:
        base, srv = _make_unsigned_login_fixture()
        try:
            eng = _engine("c-struct-5")[0]
            res = run_modern_battery(eng, [Endpoint(url=base + "/login", method="GET"),
                                           Endpoint(url=base + "/protected", method="GET")], seed=SEED)
            b = next((x for x in res.boundaries if x["family"] == "jwt_none_acceptance"
                      and "unsigned" in x["detail"]), None)
            _record("struct-05 unsigned harvest", b is not None and not res.findings)
        finally:
            wing._stop_http(srv)
    except Exception as e:
        _record("struct-05 unsigned harvest", False, repr(e))
    try:
        eng = _engine("c-struct-6")[0]
        res = run_modern_battery(eng, [Endpoint(url="http://127.0.0.1:1/nope", method="GET")],
                                 seed=SEED)
        b = next((x for x in res.boundaries if x["family"] == "jwt_algorithm_confusion"
                  and x["kind"] == "NOT_DISCOVERED"), None)
        b2 = next((x for x in res.boundaries if x["family"] == "jwt_none_acceptance"
                   and x["kind"] == "NOT_DISCOVERED"), None)
        _record("struct-06 no auth-shaped endpoint", b is not None and b2 is not None
                and not res.findings)
    except Exception as e:
        _record("struct-06 no JWT in flight", False, repr(e))
    try:
        eng = _engine("c-struct-7")[0]
        res = run_modern_battery(eng, [Endpoint(url="http://127.0.0.1:1/graphql", method="GET")],
                                 seed=SEED)
        _record("struct-07 graphql GET-only", next(
            (x for x in res.boundaries if x["family"] == "graphql_batching_enabled"
             and x["kind"] == "NOT_DISCOVERED"), None) is not None)
    except Exception as e:
        _record("struct-07 graphql GET-only", False, repr(e))
    try:
        eng = _engine("c-struct-8")[0]
        res = run_modern_battery(eng, [Endpoint(url="http://127.0.0.1:1/profile", method="GET")],
                                 seed=SEED)
        _record("struct-08 update GET-only", next(
            (x for x in res.boundaries if x["family"] == "mass_assignment"
             and x["kind"] == "NOT_DISCOVERED"), None) is not None)
    except Exception as e:
        _record("struct-08 update GET-only", False, repr(e))
    try:
        base, srv = wing._make_settings_fixture("node-like")
        try:
            eng = _engine("c-struct-9")[0]
            res = run_modern_battery(eng, [Endpoint(url=base + "/settings", method="POST")],
                                     seed=SEED)
            _record("struct-09 pp live", any(f.type == "prototype_pollution" for f in res.findings))
        finally:
            wing._stop_http(srv)
    except Exception as e:
        _record("struct-09 pp live", False, repr(e))
    try:
        base, td = wing._make_smug_fixture("desync")
        try:
            eng = _engine("c-struct-10")[0]
            res = run_modern_battery(eng, [Endpoint(url=base + "/smoke", method="POST")], seed=SEED)
            _record("struct-10 smug live", any(
                f.type == "http_request_smuggling" for f in res.findings))
        finally:
            td()
    except Exception as e:
        _record("struct-10 smug live", False, repr(e))
    try:
        eng = _engine("c-struct-11")[0]
        eps = [Endpoint(url=f"http://127.0.0.1:1/smoke{i}", method="POST") for i in range(12)]
        res = run_modern_battery(eng, eps, seed=SEED)
        _record("struct-11 budget cap", res.probe_counts["http_request_smuggling"]["sent"] <= 16)
    except Exception as e:
        _record("struct-11 budget cap", False, repr(e))
    try:
        eng = _engine("c-struct-12")[0]
        res = run_modern_battery(eng, [], seed=SEED)
        _record("struct-12 empty list", not res.findings and res.requests >= 0)
    except Exception as e:
        _record("struct-12 empty list", False, repr(e))

    # ---- 10 تخريب: الباب يقبل للمجس ثم يكذب للتحقق — VR يرفض
    def _lying_case(name, kind, family, eps_mode, replay):
        try:
            if eps_mode == "http":
                base, srv = _make_lying_http_fixture(kind)
                if family in ("jwt_algorithm_confusion", "jwt_none_acceptance"):
                    eps = [Endpoint(url=base + "/login", method="GET"),
                           Endpoint(url=base + "/protected", method="GET")]
                elif family == "mass_assignment":
                    eps = [Endpoint(url=base + "/profile", method="POST")]
                elif family == "prototype_pollution":
                    eps = [Endpoint(url=base + "/settings", method="POST")]
                else:
                    eps = [Endpoint(url=base + "/graphql", method="POST")]
                teardown = lambda: wing._stop_http(srv)
            else:
                base, teardown = _make_lying_smug(kind)
                eps = [Endpoint(url=base + "/smoke", method="POST")]
            try:
                eng, bus = _engine(f"c-lie-{name}")
                res = run_modern_battery(eng, eps, seed=SEED)
                f = next((x for x in res.findings if x.type == family), None)
                if f is None:
                    _record(name, False, "the lie never even opened the door")
                    return
                ver = VerificationEngine(eng, bus)
                out = ver.verify(f, next((e for e in eps if e.url == f.endpoint_url), None))
                _record(name, out.status == FindingStatus.REJECTED,
                        (out.verification.notes or "")[:110])
            finally:
                teardown()
        except Exception as e:
            _record(name, False, repr(e)[:110])

    _lying_case("sabotage-01 lying confusion", "confusion", "jwt_algorithm_confusion", "http", None)
    _lying_case("sabotage-02 lying none", "none", "jwt_none_acceptance", "http", None)
    _lying_case("sabotage-03 lying smug once", "once", "http_request_smuggling", "raw", None)
    _lying_case("sabotage-04 lying smug len-aware", "len-aware", "http_request_smuggling", "raw", None)
    _lying_case("sabotage-05 lying smug vr-aware", "vr-aware", "http_request_smuggling", "raw", None)
    _lying_case("sabotage-06 lying gql counter", "gql-counter", "graphql_batching_enabled", "http", None)
    _lying_case("sabotage-07 lying gql shape", "gql-shape", "graphql_batching_enabled", "http", None)
    _lying_case("sabotage-08 lying profile first-only", "profile", "mass_assignment", "http", None)

    def _prefix_aware_profile():
        """يقبل قيماً تبدأ بـsentinel-ma- فقط (كاناري البطارية) لا كاناري الـVR."""
        from http.server import BaseHTTPRequestHandler
        state = {"name": "sentinel", "role": "user"}

        class H(wing._JsonMixin, BaseHTTPRequestHandler):
            def do_GET(self):
                if urlsplit(self.path).path == "/profile":
                    return self._send_json(200, state)
                self._send_json(404, {"error": "nf"})

            def do_POST(self):
                if urlsplit(self.path).path != "/profile":
                    return self._send_json(404, {"error": "nf"})
                try:
                    doc = json.loads(self._body() or b"{}")
                except Exception:
                    return self._send_json(400, {"error": "bad json"})
                for k, v in doc.items():
                    if k == "role" and isinstance(v, str) and v.startswith("sentinel-") \
                            and "vr33" not in v:
                        state[k] = v
                    elif k in ("name", "email"):
                        state[k] = v
                return self._send_json(200, {"saved": True})

        return wing._start_http(H)

    try:
        base, srv = _prefix_aware_profile()
        try:
            eng, bus = _engine("c-lie-09")
            res = run_modern_battery(eng, [Endpoint(url=base + "/profile", method="POST")], seed=SEED)
            f = next((x for x in res.findings if x.type == "mass_assignment"), None)
            if f is None:
                _record("sabotage-09 prefix-aware profile", False, "door never opened")
            else:
                out = VerificationEngine(eng, bus).verify(
                    f, Endpoint(url=base + "/profile", method="POST"))
                _record("sabotage-09 prefix-aware profile", out.status == FindingStatus.REJECTED,
                        (out.verification.notes or "")[:110])
        finally:
            wing._stop_http(srv)
    except Exception as e:
        _record("sabotage-09 prefix-aware profile", False, repr(e)[:110])

    def _echo_store_settings():
        """يعكس آخر جسم POST فقط (echo) — ليس تلوثاً؛ الدقة تتطلب عدم التصنيف.
        لكن للمخرب: يقبل __proto__ للمجس (hit الأول) ثم يصبح sanitized."""
        from http.server import BaseHTTPRequestHandler
        last = {"body": {"theme": "light"}}
        hit = {"n": 0}

        class H(wing._JsonMixin, BaseHTTPRequestHandler):
            def do_GET(self):
                if urlsplit(self.path).path == "/settings":
                    return self._send_json(200, last["body"])
                self._send_json(404, {"error": "nf"})

            def do_POST(self):
                if urlsplit(self.path).path != "/settings":
                    return self._send_json(404, {"error": "nf"})
                try:
                    doc = json.loads(self._body() or b"{}")
                except Exception:
                    return self._send_json(400, {"error": "bad json"})
                if hit["n"] < 1 and isinstance(doc.get("__proto__"), dict):
                    hit["n"] += 1
                    doc = {**doc.get("__proto__"), **{k: v for k, v in doc.items()
                                                      if k != "__proto__"}}
                last["body"] = doc
                return self._send_json(200, {"saved": True})

        return wing._start_http(H)

    try:
        base, srv = _echo_store_settings()
        try:
            eng, bus = _engine("c-lie-10")
            res = run_modern_battery(eng, [Endpoint(url=base + "/settings", method="POST")], seed=SEED)
            f = next((x for x in res.findings if x.type == "prototype_pollution"), None)
            if f is None:
                _record("sabotage-10 lying settings", False, "door never opened")
            else:
                out = VerificationEngine(eng, bus).verify(
                    f, Endpoint(url=base + "/settings", method="POST"))
                _record("sabotage-10 lying settings", out.status == FindingStatus.REJECTED,
                        (out.verification.notes or "")[:110])
        finally:
            wing._stop_http(srv)
    except Exception as e:
        _record("sabotage-10 lying settings", False, repr(e)[:110])

    # ---- 8 دقة: ما لا يُصنَّق نتيجة
    def _precision(name, fn):
        try:
            _record(name, fn(), "")
        except Exception as e:
            _record(name, False, repr(e)[:110])

    def _prec_any_sig():
        base, srv = wing._make_jwt_fixture("any-sig")
        try:
            res = run_modern_battery(_engine("c-prec-1")[0],
                                     [Endpoint(url=base + "/login", method="GET"),
                                      Endpoint(url=base + "/protected", method="GET")], seed=SEED)
            return not res.findings and any(
                b["kind"] == "OBSERVED_ANOMALY" for b in res.boundaries)
        finally:
            wing._stop_http(srv)

    _precision("precision-01 both-accepted anomaly not finding", _prec_any_sig)

    def _prec_slow():
        base, td = wing._make_smug_fixture("slow-guard")
        try:
            res = run_modern_battery(_engine("c-prec-2")[0],
                                     [Endpoint(url=base + "/smoke", method="POST")], seed=SEED)
            return not any(f.type == "http_request_smuggling" for f in res.findings)
        finally:
            td()

    _precision("precision-02 slow below threshold", _prec_slow)

    def _prec_400():
        base, td = wing._make_smug_fixture("compliant-400")
        try:
            res = run_modern_battery(_engine("c-prec-3")[0],
                                     [Endpoint(url=base + "/smoke", method="POST")], seed=SEED)
            return not any(f.type == "http_request_smuggling" for f in res.findings)
        finally:
            td()

    _precision("precision-03 compliant 400", _prec_400)

    def _prec_batch_shape():
        from http.server import BaseHTTPRequestHandler

        class H(wing._JsonMixin, BaseHTTPRequestHandler):
            def do_POST(self):
                if urlsplit(self.path).path != "/graphql":
                    return self._send_json(404, {"error": "nf"})
                try:
                    doc = json.loads(self._body() or b"{}")
                except Exception:
                    return self._send_json(400, {"errors": [{"message": "bad json"}]})
                if isinstance(doc, list):
                    return self._send_json(200, {"data": {"__typename": "Query"}})
                if isinstance(doc, dict):
                    return self._send_json(200, {"data": {"__typename": "Query"}})
                return self._send_json(400, {"errors": [{"message": "unsupported"}]})

        base, srv = wing._start_http(H)
        try:
            res = run_modern_battery(_engine("c-prec-4")[0],
                                     [Endpoint(url=base + "/graphql", method="POST")], seed=SEED)
            return not any(f.type == "graphql_batching_enabled" for f in res.findings)
        finally:
            wing._stop_http(srv)

    _precision("precision-04 batch accepted not array-shaped", _prec_batch_shape)

    def _prec_ma_wrong_key():
        from http.server import BaseHTTPRequestHandler
        state = {"name": "sentinel", "role": "user"}

        class H(wing._JsonMixin, BaseHTTPRequestHandler):
            def do_GET(self):
                if urlsplit(self.path).path == "/profile":
                    return self._send_json(200, state)
                self._send_json(404, {"error": "nf"})

            def do_POST(self):
                if urlsplit(self.path).path != "/profile":
                    return self._send_json(404, {"error": "nf"})
                try:
                    doc = json.loads(self._body() or b"{}")
                except Exception:
                    return self._send_json(400, {"error": "bad json"})
                if "role" in doc:
                    state["sentinel-role"] = doc["role"]     # تحت مفتاح خاطئ
                for k in ("name", "email"):
                    if k in doc:
                        state[k] = doc[k]
                return self._send_json(200, {"saved": True})

        base, srv = wing._start_http(H)
        try:
            res = run_modern_battery(_engine("c-prec-5")[0],
                                     [Endpoint(url=base + "/profile", method="POST")], seed=SEED)
            return not any(f.type == "mass_assignment" for f in res.findings)
        finally:
            wing._stop_http(srv)

    _precision("precision-05 ma canary under wrong key", _prec_ma_wrong_key)

    def _prec_ma_confirm_500():
        from http.server import BaseHTTPRequestHandler
        state = {"name": "sentinel", "role": "user", "hits": 0}

        class H(wing._JsonMixin, BaseHTTPRequestHandler):
            def do_GET(self):
                p = urlsplit(self.path).path
                if p == "/profile":
                    state["hits"] += 1
                    if state["hits"] > 1:
                        return self._send_json(500, {"error": "boom"})
                    return self._send_json(200, state)
                self._send_json(404, {"error": "nf"})

            def do_POST(self):
                if urlsplit(self.path).path != "/profile":
                    return self._send_json(404, {"error": "nf"})
                try:
                    doc = json.loads(self._body() or b"{}")
                except Exception:
                    return self._send_json(400, {"error": "bad json"})
                state.update(doc)
                return self._send_json(200, {"saved": True})

        base, srv = wing._start_http(H)
        try:
            res = run_modern_battery(_engine("c-prec-6")[0],
                                     [Endpoint(url=base + "/profile", method="POST")], seed=SEED)
            return not any(f.type == "mass_assignment" for f in res.findings)
        finally:
            wing._stop_http(srv)

    _precision("precision-06 ma confirm oracle 500", _prec_ma_confirm_500)

    def _prec_pp_echo():
        from http.server import BaseHTTPRequestHandler
        last = {"body": {"theme": "light"}}

        class H(wing._JsonMixin, BaseHTTPRequestHandler):
            def do_GET(self):
                if urlsplit(self.path).path == "/settings":
                    return self._send_json(200, last["body"])
                self._send_json(404, {"error": "nf"})

            def do_POST(self):
                if urlsplit(self.path).path != "/settings":
                    return self._send_json(404, {"error": "nf"})
                try:
                    doc = json.loads(self._body() or b"{}")
                except Exception:
                    return self._send_json(400, {"error": "bad json"})
                last["body"] = doc                    # مجرد صدى للطلب — ليس تلوثاً
                return self._send_json(200, {"saved": True})

        base, srv = wing._start_http(H)
        try:
            res = run_modern_battery(_engine("c-prec-7")[0],
                                     [Endpoint(url=base + "/settings", method="POST")], seed=SEED)
            return not any(f.type == "prototype_pollution" for f in res.findings)
        finally:
            wing._stop_http(srv)

    _precision("precision-07 pp echo is not pollution", _prec_pp_echo)

    def _prec_conf_all_reject():
        base, srv = wing._make_jwt_fixture("confusion-neg")
        try:
            res = run_modern_battery(_engine("c-prec-8")[0],
                                     [Endpoint(url=base + "/login", method="GET"),
                                      Endpoint(url=base + "/protected", method="GET")], seed=SEED)
            return not res.findings
        finally:
            wing._stop_http(srv)

    _precision("precision-08 all-reject verifier", _prec_conf_all_reject)

    # ---- 6 حدود/تحريف
    def _tamper_case(name, fn):
        try:
            _record(name, fn(), "")
        except Exception as e:
            _record(name, False, repr(e)[:110])

    def _t1():
        base, srv = wing._make_jwt_fixture("confusion-vuln")
        try:
            eng, bus = _engine("c-t1")
            res = run_modern_battery(eng, [Endpoint(url=base + "/login", method="GET"),
                                           Endpoint(url=base + "/protected", method="GET")], seed=SEED)
            f = next(x for x in res.findings if x.type == "jwt_algorithm_confusion")
            f.evidence = [e for e in f.evidence if e.kind != "probe_recipe"]  # التحريف
            out = VerificationEngine(eng, bus).verify(f, None)
            return out.status == FindingStatus.REJECTED
        finally:
            wing._stop_http(srv)

    _tamper_case("tamper-01 recipe removed", _t1)

    def _t2():
        base, srv = wing._make_jwt_fixture("confusion-vuln")
        try:
            eng, bus = _engine("c-t2")
            res = run_modern_battery(eng, [Endpoint(url=base + "/login", method="GET"),
                                           Endpoint(url=base + "/protected", method="GET")], seed=SEED)
            f = next(x for x in res.findings if x.type == "jwt_algorithm_confusion")
            f.endpoint_url = base + "/login"      # وجهة محرفة
            for e in f.evidence:                   # والوصفة تُفرَّغ من protected
                if e.kind == "probe_recipe":
                    e.detail = f"auth={base}/login"
            out = VerificationEngine(eng, bus).verify(f, Endpoint(url=base + "/login", method="GET"))
            return out.status == FindingStatus.REJECTED
        finally:
            wing._stop_http(srv)

    _tamper_case("tamper-02 endpoint url tampered", _t2)

    def _t3():
        base, srv = wing._make_jwt_fixture("confusion-vuln")
        try:
            eng, bus = _engine("c-t3")
            res = run_modern_battery(eng, [Endpoint(url=base + "/login", method="GET"),
                                           Endpoint(url=base + "/protected", method="GET")], seed=SEED)
            f = next(x for x in res.findings if x.type == "jwt_algorithm_confusion")
            for e in f.evidence:
                if e.kind == "probe_recipe":
                    e.detail = "auth=http://127.0.0.1:9/dead; protected=none"  # وصفة محرفة
            out = VerificationEngine(eng, bus).verify(f, None)
            return out.status == FindingStatus.REJECTED
        finally:
            wing._stop_http(srv)

    _tamper_case("tamper-03 recipe poisoned", _t3)

    def _t4():
        eng = _engine("c-t4")[0]
        eps = [Endpoint(url=f"http://127.0.0.1:1/smoke{i}", method="POST") for i in range(20)]
        res = run_modern_battery(eng, eps, seed=SEED)
        return res.probe_counts["http_request_smuggling"]["sent"] == 16 \
            and res.probe_counts["http_request_smuggling"]["cap"] == 16

    _tamper_case("tamper-04 budget exactly capped", _t4)

    def _t5():
        base, srv = wing._make_profile_fixture("bind-all")
        try:
            eng1 = _engine("c-t5a")[0]
            eng2 = _engine("c-t5b")[0]
            eps = [Endpoint(url=base + "/profile", method="POST")]
            r1 = run_modern_battery(eng1, eps, seed=SEED)
            r2 = run_modern_battery(eng2, eps, seed=None)      # بذرة None
            k1 = {(f.type, f.parameter) for f in r1.findings}
            k2 = {(f.type, f.parameter) for f in r2.findings}
            return k1 == k2 and "mass_assignment" in {t for t, _ in k1}
        finally:
            wing._stop_http(srv)

    _tamper_case("tamper-05 seed None deterministic", _t5)

    def _t6():
        base, srv = wing._make_jwt_fixture("confusion-vuln")
        try:
            eng = _engine("c-t6")[0]
            ordered = [Endpoint(url=base + "/login", method="GET"),
                       Endpoint(url=base + "/protected", method="GET")]
            shuffled = list(reversed(ordered))
            r1 = run_modern_battery(eng, ordered, seed=SEED)
            r2 = run_modern_battery(eng, shuffled, seed=SEED)
            sig1 = sorted((f.type, f.endpoint_url, f.parameter) for f in r1.findings)
            sig2 = sorted((f.type, f.endpoint_url, f.parameter) for f in r2.findings)
            return sig1 == sig2 and len(sig1) >= 1
        finally:
            wing._stop_http(srv)

    _tamper_case("tamper-06 order-insensitive determinism", _t6)

    # ---- 4 حيوية
    def _live_case(name, fn):
        try:
            _record(name, fn(), "")
        except Exception as e:
            _record(name, False, repr(e)[:110])

    def _l1():
        base1, srv1 = wing._make_jwt_fixture("confusion-vuln")
        base2, srv2 = wing._make_jwt_fixture("confusion-vuln")
        try:
            r1 = run_modern_battery(_engine("c-l1a")[0],
                                    [Endpoint(url=base1 + "/login", method="GET"),
                                     Endpoint(url=base1 + "/protected", method="GET")], seed=SEED)
            r2 = run_modern_battery(_engine("c-l1b")[0],
                                    [Endpoint(url=base2 + "/login", method="GET"),
                                     Endpoint(url=base2 + "/protected", method="GET")], seed=SEED)
            s1 = sorted((f.type, f.parameter, f.status.value,
                         tuple(e.kind for e in f.evidence)) for f in r1.findings)
            s2 = sorted((f.type, f.parameter, f.status.value,
                         tuple(e.kind for e in f.evidence)) for f in r2.findings)
            b1 = sorted(json.dumps(b, sort_keys=True) for b in r1.boundaries)
            b2 = sorted(json.dumps(b, sort_keys=True) for b in r2.boundaries)
            return s1 == s2 and b1 == b2 and len(s1) >= 1
        finally:
            wing._stop_http(srv1)
            wing._stop_http(srv2)

    _live_case("liveness-01 twin fixtures identical", _l1)

    def _l2():
        base, srv = wing._make_profile_fixture("bind-all")
        try:
            r1 = run_modern_battery(_engine("c-l2a")[0],
                                    [Endpoint(url=base + "/profile", method="POST")], seed=13)
            r2 = run_modern_battery(_engine("c-l2b")[0],
                                    [Endpoint(url=base + "/profile", method="POST")], seed=14)
            can1 = derive_canary(13, "ma|" + base + "/profile")
            can2 = derive_canary(14, "ma|" + base + "/profile")
            # الحالة النهائية للـfixture: كاناري البذرة الثانية هو الأخير
            import urllib.request as _rq
            with _rq.urlopen(base + "/profile", timeout=5) as resp:
                state = json.loads(resp.read())
            return (state.get("role") == can2 and can1 != can2
                    and any(f.type == "mass_assignment" for f in r1.findings)
                    and any(f.type == "mass_assignment" for f in r2.findings))
        finally:
            wing._stop_http(srv)

    _live_case("liveness-02 different seed different canary same class", _l2)

    def _l3():
        res = run_modern_battery(_engine("c-l3")[0], None, seed=SEED)
        return res.requests == 0 and not res.findings

    _live_case("liveness-03 empty surface zero requests", _l3)

    def _l4():
        base, srv = wing._make_combined_fixture()
        try:
            eng, bus = _engine("c-l4")
            eps = [Endpoint(url=base + "/login", method="GET"),
                   Endpoint(url=base + "/protected", method="GET"),
                   Endpoint(url=base + "/graphql", method="POST"),
                   Endpoint(url=base + "/profile", method="POST"),
                   Endpoint(url=base + "/settings", method="POST"),
                   Endpoint(url=base + "/smoke", method="POST")]
            res = run_modern_battery(eng, eps, seed=SEED)
            keys = [(f.type, f.endpoint_url) for f in res.findings]
            return len(keys) == len(set(keys)) and len(keys) >= 6
        finally:
            wing._stop_http(srv)

    _live_case("liveness-04 no duplicate findings", _l4)

    ok = all(r["ok"] for r in results) and len(results) == 40
    return {"ok": ok, "detail": {
        "total": len(results),
        "by_class": {"structural": sum(1 for r in results if r["name"].startswith("struct")),
                      "sabotage": sum(1 for r in results if r["name"].startswith("sabotage")),
                      "precision": sum(1 for r in results if r["name"].startswith("precision")),
                      "tamper": sum(1 for r in results if r["name"].startswith("tamper")),
                      "liveness": sum(1 for r in results if r["name"].startswith("liveness"))},
        "failures": [r for r in results if not r["ok"]],
        "records": results}}


# ============================================================ وضع السكربت
def _overall_digest(bats):
    h = hashlib.sha256()
    for name, b in bats:
        h.update(f"{name}:{int(bool(b['ok']))}".encode())
        h.update(b"\n")
    return h.hexdigest()


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="SENTINEL Axis-13 ATOMS")
    ap.add_argument("--out", default="", help="مسار ملف دليل JSON")
    args = ap.parse_args()

    bats = [("13a planted cycles", battery_13a()),
            ("13b independent refs", battery_13b()),
            ("13c adversarial x40", battery_13c())]
    passed = sum(1 for _n, b in bats if b["ok"])
    doc = {"suite": SUITE, "station": "M3-ATOMS",
           "total": len(bats), "passed_count": passed,
           "passed": passed == len(bats),
           "overall_digest": _overall_digest(bats),
           "batteries": [{"battery": n, "ok": b["ok"],
                          "detail": {k: v for k, v in b["detail"].items()
                                     if k != "records"}}
                         for n, b in bats],
           "records": {n: b["detail"].get("records", []) for n, b in bats}}
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1, ensure_ascii=False)
        print(f"evidence -> {args.out}")
    print(f"axis13-atoms: {passed}/{len(bats)} batteries | "
          f"digest {doc['overall_digest'][:16]}")
    for n, b in bats:
        mark = "PASS" if b["ok"] else "FAIL"
        print(f"  [{mark}] {n}")
        if not b["ok"]:
            print(f"      raw: {json.dumps(b['detail'], ensure_ascii=False)[:600]}")
    return 0 if passed == len(bats) else 1


if __name__ == "__main__":
    raise SystemExit(main())

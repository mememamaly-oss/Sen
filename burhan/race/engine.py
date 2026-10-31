#!/usr/bin/env python3
"""burhan/race/engine.py — محرك الإرسال المتزامن (AXIS-17).

قيد الوحدة الحرفي (N2): stdlib فقط — threading, http.client, time,
json, hashlib (تُستخدم فعليًا: threading/http.client/time/json من
أجل حدود الجسم)؛ **لا urllib**: تحليل URL نصي يدوي أدناه.

عقد send_concurrent:
  - المدخل: قائمة طلبات [{"method","url","headers","body"}, ...]
    (dicts عادية؛ لا نماذج — نقاء الواجهة).
  - المخرج: قائمة نتائج **بنفس ترتيب المدخل** — كل نتيجة:
    {"rid","idx","method","url","path","status","elapsed","error",
     "honest_boundary"} — status=0 عند أي فشل؛ honest_boundary يحمل
    آخر حد صادق للطلب (timeout_exceeded / connection_reset /
    malformed_response / single_thread_mode / engine_error).
  - السقف: عمال=min(cap, n) فقط؛ الذروة الحية عند الهدف <= cap
    بالبناء (الاختبار 6 يقيسها عند الخادم نفسه).
  - use_threads=False: مسار تسلسلي واحدًا واحدًا بالترتيب — ذرة 7
    (الترتيب مضمون) وذرة 1 (single_thread_mode).
  - journal_put(rid, method, url, headers, body, path): يُستدعى
    لكل طلب **قبل الإرسال** إن وُجد — التقنع مسؤولية الطبقة الأعلى
    (integration تبني closure يطبق gates.redact_*).

حدود أمانة معلنة:
  - IPv6 فقط بصيغة الأقواس [::1]؛ عنوان خام بلا أقواس مع منفذ يُعد
    خطأ مدخلًا (رفض صريح لا تخمين).
  - المهلة مهلة مقبس لكل اتصال؛ join بلا مهلة إجمالية (أسوأ حالة
    معلقة بسقف ceil(n/cap)*timeout — موثقة، لا ساعة إجمالية).
"""
from __future__ import annotations

import http.client
import json
import threading
import time

from . import gates


class RaceEngineError(ValueError):
    """استثناء محرك الإرسال — يُسجل في التقرير (القاعدة 5 من M2)."""


_BODY_LIMIT = 2_000_000          # حد قراءة الاستجابة — كحد المحرك نفسه
_METHODS_WITH_BODY = ("POST", "PUT", "PATCH")


# ---------------------------------------------------------------- تحليل URL
def split_url(url: str) -> dict:
    """تحليل URL نصيًا يدويًا (لا urllib — N2). fail-closed عند الشكل السيئ."""
    u = (url or "").strip()
    if not u:
        raise RaceEngineError("empty url")
    scheme = "http"
    rest = u
    if "://" in u:
        scheme, _, rest = u.partition("://")
        scheme = (scheme or "http").lower()
        if scheme not in ("http", "https"):
            raise RaceEngineError(f"unsupported scheme: {scheme!r}")
    authority, _, tail = rest.partition("/")
    if not authority:
        raise RaceEngineError(f"no authority in url: {url!r}")
    if "@" in authority:                       # تجاهل userinfo
        authority = authority.rsplit("@", 1)[1]
    host, port = authority, None
    if host.startswith("["):                   # IPv6 بالأقواس فقط (معلن)
        host = host.strip("[]")
    if ":" in host:
        h, _, p = host.rpartition(":")
        if h and ":" not in h:                # host:port
            host, port_s = h, p
            if port_s == "":
                raise RaceEngineError(f"empty port in url: {url!r}")
            try:
                port = int(port_s)
            except ValueError as e:
                raise RaceEngineError(f"bad port {port_s!r} in {url!r}") from e
            if not (0 < port < 65536):
                raise RaceEngineError(f"port {port} out of range in {url!r}")
        elif not host.startswith("["):         # نقطتان بلا أقواس: IPv6 خام — مرفوض
            raise RaceEngineError(
                f"bare multi-colon host (use [::1] form): {authority!r}")
    if port is None:
        port = 443 if scheme == "https" else 80
    path_query = "/" + tail if tail else "/"
    path, _, query = path_query.partition("?")
    return {"scheme": scheme, "host": host, "port": port,
            "path": path or "/", "query": query,
            "target": (path or "/") + (("?" + query) if query else "")}


def build_request(raw: dict, idx: int) -> dict:
    """تطبيع طلب واحد إلى الشكل الكامل — دالة نقية (نسخ، لا تقاسم)."""
    if not isinstance(raw, dict):
        raise RaceEngineError(f"request {idx} must be dict, got {type(raw).__name__}")
    url = raw.get("url") or raw.get("endpoint") or ""
    parts = split_url(url)
    method = str(raw.get("method") or "POST").upper()
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"):
        raise RaceEngineError(f"unsupported method: {method!r}")
    headers = dict(raw.get("headers") or {})
    headers.setdefault("Host", f"{parts['host']}:{parts['port']}"
                      if parts["port"] not in (80, 443) else parts["host"])
    headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    body = raw.get("body")
    body = "" if body is None else (body if isinstance(body, str) else str(body))
    if method in _METHODS_WITH_BODY:
        headers.setdefault("Content-Length", str(len(body.encode("utf-8"))))
    return {"rid": f"race-{idx:04d}", "idx": idx, "method": method,
            "url": url, "headers": headers, "body": body, **parts}


# ---------------------------------------------------------------- إرسال واحد
def send_one(req: dict, timeout: float = 10.0) -> dict:
    """إرسال طلب واحد عبر http.client — نتيجة معلنة بحدودها الصادقة."""
    t0 = time.time()
    status, err, boundary = 0, "", None
    cls = (http.client.HTTPSConnection if req["scheme"] == "https"
           else http.client.HTTPConnection)
    conn = cls(req["host"], req["port"], timeout=timeout)
    try:
        body = req["body"] if req["method"] in _METHODS_WITH_BODY else None
        conn.request(req["method"], req["target"], body=body,
                     headers=req["headers"])
        resp = conn.getresponse()
        resp.read(_BODY_LIMIT)
        status = resp.status
    except TimeoutError as e:                                  # مقبس جاع
        boundary, err = "timeout_exceeded", f"timeout: {e}"[:200]
    except http.client.RemoteDisconnected as e:                # قطع بلا استجابة
        boundary, err = "connection_reset", f"reset: {e}"[:200]
    except http.client.BadStatusLine as e:                     # ليس HTTP
        boundary, err = "malformed_response", f"bad status line: {e}"[:200]
    except ConnectionError as e:                               # رفض/قطع وصل
        boundary, err = "connection_reset", f"connect: {e}"[:200]
    except (http.client.HTTPException, OSError) as e:          # ما تبقى
        boundary = "engine_error"
        err = f"{type(e).__name__}: {e}"[:200]
    finally:
        try:
            conn.close()
        except Exception:                                      # noqa: BLE001
            pass
    return {"rid": req["rid"], "idx": req["idx"], "method": req["method"],
            "url": req["url"], "path": req["path"], "query": req["query"],
            "status": status,
            "elapsed": round(time.time() - t0, 6),
            "error": err, "honest_boundary": boundary}


# ---------------------------------------------------------------- الإرسال المتزامن
def send_concurrent(requests, *, max_concurrent: int = 5, timeout: float = 10.0,
                    use_threads: bool = True, journal_put=None) -> list:
    """إرسال متزامن بسقف صلب — النتائج بترتيب المدخل حرفيًا (ذرة 7).

    لا حالة عامة: كل حالة محلية داخل هذا الاستدعاء (القاعدة 4 من M2).
    journal_put يُستدعى قبل الإرسال لكل طلب (نفس عقد المحرك: السجل
    يحمل الطلب كما صدر).
    """
    cap = gates.enforce_budget(max_concurrent)
    if timeout is None or float(timeout) <= 0:
        raise RaceEngineError(f"timeout must be positive, got {timeout!r}")
    timeout = float(timeout)

    raws = list(requests or [])
    reqs = [build_request(r, i) for i, r in enumerate(raws)]
    n = len(reqs)
    if n == 0:
        return []
    results = [None] * n

    def _journal(req):
        """تسجيل الطلب قبل الإرسال — فشل التسجيل لا يوقف الفحص
        (يظهر في الـjournal ذاته؛ عقد المحرك نفسه: السجل أفضل جهد)."""
        if journal_put is not None:
            try:
                journal_put(req["rid"], req["method"], req["url"],
                            dict(req["headers"]), req["body"], req["target"])
            except Exception:                                  # noqa: BLE001
                pass

    def _run_range():
        """عامل واحد: يستهلك المؤشر المشترك تحت قفل — حتمي الترتيب."""
        while True:
            with cursor_lock:
                if cursor[0] >= n:
                    return
                i = cursor[0]
                cursor[0] += 1
            req = reqs[i]
            _journal(req)
            results[i] = send_one(req, timeout=timeout)

    if not use_threads:
        # ذرة 1 + ذرة 7: مسار تسلسلي واحدًا واحدًا بالترتيب المضمون؛
        # النجاح يحمل single_thread_mode (حدًا صادقًا معلنًا)
        for req in reqs:
            _journal(req)
            res = send_one(req, timeout=timeout)
            if res["honest_boundary"] is None:
                res["honest_boundary"] = "single_thread_mode"
            results[req["idx"]] = res
        return results

    cursor = [0]
    cursor_lock = threading.Lock()
    workers = [threading.Thread(target=_run_range, daemon=True)
               for _ in range(min(cap, n))]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    return results

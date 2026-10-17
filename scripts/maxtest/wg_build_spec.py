#!/usr/bin/env python3
"""maxtest — build the WebGoat operator OpenAPI spec from the app's OWN form
templates (extracted from the lesson jars: action + method + fields).
Authorized local target: WebGoat 8.2.2 (localhost:8080/WebGoat).
The spec is a LEAD for the engine (scope-gated like every seed) — this is the
operator-surface pattern the engine already supports (DISC-13), with the
surface map taken from the application's own declared templates, never guessed.
"""
import json
import re
import zipfile

JAR = "/home/z/my-project/live-targets/webgoat-server-8.2.2.jar"
OUT = "/home/z/my-project/live-targets/webgoat_surface_maxtest.json"
BASE = "http://localhost:8080"  # actions are absolute from host root (no /WebGoat prefix here)

z = zipfile.ZipFile(JAR)
paths = {}
for name in sorted(z.namelist()):
    if not (name.endswith(".jar") and re.search(r"BOOT-INF/lib/[a-z0-9-]+-8\.2\.2\.jar$", name)):
        continue
    try:
        inner = zipfile.ZipFile(zipfile.io.BytesIO(z.read(name))) if hasattr(zipfile, "io") else None
    except Exception:
        inner = None
    if inner is None:
        import io as _io
        inner = zipfile.ZipFile(_io.BytesIO(z.read(name)))
    for n in inner.namelist():
        if not n.endswith(".html"):
            continue
        html = inner.read(n).decode("utf-8", "replace")
        for fm in re.finditer(
                r'<form([^>]*)>(.*?)</form>', html, re.S | re.I):
            attrs, body = fm.group(1), fm.group(2)
            am = re.search(r'action=["\']([^"\']*)["\']', attrs)
            mm = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)
            action = am.group(1) if am else ""
            method = (mm.group(1) if mm else "GET").upper()
            if not action or action.startswith(("@", "$", "#", "javascript")):
                continue
            if not action.startswith("/"):
                action = "/" + action
            if "WebGoat" not in action and not action.startswith(("/IDOR", "/cia")):
                continue
            fields = sorted(set(
                re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', body, re.S)
                + re.findall(r'<select[^>]*name=["\']([^"\']+)["\']', body, re.S)
                + re.findall(r'<textarea[^>]*name=["\']([^"\']+)["\']', body, re.S)))
            # drop button-ish fields (value-only controls, no injection surface)
            fields = [f for f in fields if not re.match(
                r"(?i)^(submit|view profile|submit diffs|get account info|"
                r"check dave|steal the cheese|try this|login-submit|register-submit|"
                r"recover-submit|check question)$", f)]
            if not fields:
                continue
            key = (action, method if method in ("GET", "POST") else "GET")
            paths.setdefault(key, set()).update(fields)

# WebGoat is a STATEFUL SPA surface: an attack endpoint only answers after
# POST /WebGoat/{Lesson}.lesson has set the session's current-lesson (the
# LessonTrackerInterceptor NPEs with lesson=null otherwise — live-measured).
# The engine's passive-baseline loop processes endpoints IN ORDER, so seeding
# each lesson's .lesson endpoint right before its attack endpoints (natural
# string sort: '.' < '/') primes the context for the whole battery.
LESSON_NAMES = ["WebGoatIntroduction", "WebWolfIntroduction", "HttpBasics",
    "HttpProxies", "ChromeDevTools", "CIA", "Crypto", "SqlInjection",
    "SqlInjectionAdvanced", "SqlInjectionMitigations", "PathTraversal",
    "AuthBypass", "JWT", "PasswordReset", "SecurePasswords", "InsecureLogin",
    "XXE", "IDOR", "MissingFunctionAC", "CrossSiteScripting",
    "InsecureDeserialization", "VulnerableComponents", "CSRF", "SSRF",
    "BypassRestrictions", "ClientSideFiltering", "HtmlTampering",
    "Challenge1", "Challenge5", "Challenge7", "Challenge8"]
for ln in LESSON_NAMES:
    key = (f"/WebGoat/{ln}.lesson", "POST")
    paths.setdefault(key, set())   # no params: passive POST primes the context

spec = {"openapi": "3.0.0", "info": {"title": "WebGoat 8.2.2 lesson surface "
        "(operator spec from the app's own form templates)", "version": "1"},
        "servers": [{"url": BASE}], "paths": {}}
for (action, method), fields in sorted(paths.items()):
    p = spec["paths"].setdefault(action, {})
    params = [{"name": f, "in": "query" if method == "GET" else "query",
               "schema": {"type": "string", "example": ""}} for f in fields]
    p[method.lower()] = {"parameters": params,
                         "responses": {"200": {"description": "ok"}}}
json.dump(spec, open(OUT, "w"), indent=1)
n_ops = sum(len(v) for v in spec["paths"].values())
print(f"wrote {OUT}: {len(spec['paths'])} paths / {n_ops} operations")
for a, m in sorted(paths):
    print(f"  {m:4} {a}")

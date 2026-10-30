"""INDEPENDENT VERIFICATION — WebGoat 2026.4 (official release JAR).

Phase-1 campaign (2026-10-31). Everything runs in ONE call (processes do not
survive between calls):
  1. boot the official JAR on portable JDK 25 (system Java is 21; the jar
     needs class file 67+)
  2. register a scan account through the REAL flow discovered in-session:
     POST /WebGoat/register.mvc {username,password,matchingPassword,agree}
     — password policy 6..10 chars (a 12-char password is rejected with
     'size must be between 6 and 10')
  3. extract the LESSON CATALOG (the app's own rendered curriculum — the
     independent truth set) by rendering /WebGoat/start.mvc in playwright
     and harvesting the lesson links from the DOM
  4. engine scan: authenticated (guest-less app — registration is the only
     path), bounded (max_pages=30, max_requests=4500, timeout=10, local
     OAST, browser on), batteries off disclosed
  5. save everything under evidence/independent-verification/webgoat-2026.4/
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path("/home/z/my-project")
EXT = ROOT / "external"
EV = ROOT / "evidence" / "independent-verification" / "webgoat-2026.4"
EV.mkdir(parents=True, exist_ok=True)
PORT = 8080
BASE = f"http://127.0.0.1:{PORT}"

# ---- 1. boot ---------------------------------------------------------------
proc = None
try:
    urllib.request.urlopen(BASE + "/WebGoat/login", timeout=3)
    print("webgoat already up")
except Exception:
    proc = subprocess.Popen(
        [str(EXT / "jdk-25.0.5+8/bin/java"), "-Dfile.encoding=UTF-8",
         "-jar", str(EXT / "webgoat-2026.4.jar"),
         "--server.address=127.0.0.1"],
        cwd=str(EXT), stdout=open("/tmp/wg_scan_boot.log", "w"),
        stderr=subprocess.STDOUT)
    up = False
    for _ in range(36):
        try:
            urllib.request.urlopen(BASE + "/WebGoat/login", timeout=3)
            up = True
            break
        except Exception:
            time.sleep(5)
    assert up, "webgoat failed to boot"
    print(f"webgoat booted (pid {proc.pid})")


def post(path, data):
    req = urllib.request.Request(
        BASE + path, data=urllib.parse.urlencode(data).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    op = urllib.request.build_opener(NoRedirect)
    try:
        r = op.open(req, timeout=10)
        return r.status, r.headers.get("Location", "")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Location", "")


import urllib.parse
# ---- 2. register + login-shape verification --------------------------------
st, loc = post("/WebGoat/register.mvc",
               {"username": "scanbot9", "password": "Sc4nx9!q",
                "matchingPassword": "Sc4nx9!q", "agree": "agree"})
print(f"register: {st} -> {loc}")
assert st in (200, 302), f"registration failed: {st}"

# ---- 3. lesson catalog via playwright (the app's own rendered curriculum) ---
from playwright.sync_api import sync_playwright

import http.cookiejar
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cj),
    urllib.request.HTTPRedirectHandler())
# prime session + login through the REAL form flow
opener.open(BASE + "/WebGoat/login", timeout=10).read()
req = urllib.request.Request(
    BASE + "/WebGoat/login",
    data=b"username=scanbot9&password=Sc4nx9%21q",
    headers={"Content-Type": "application/x-www-form-urlencoded"})
r = opener.open(req, timeout=10)
welcome = r.url
print(f"login landed: {welcome}")
assert "login" not in welcome.lower(), f"login failed: {welcome}"
cookies = {c.name: c.value for c in cj}

lessons = []
with sync_playwright() as p:
    b = p.chromium.launch(args=["--no-sandbox"])
    ctx = b.new_context()
    ctx.add_cookies([{"name": k, "value": v, "url": BASE} for k, v in cookies.items()])
    page = ctx.new_page()
    page.goto(BASE + "/WebGoat/start.mvc", wait_until="networkidle", timeout=30000)
    page.wait_for_timeout(2500)
    hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
    lessons = sorted({h.split("#lesson/")[-1] for h in hrefs if "#lesson/" in h})
    # also harvest the visible menu labels for readability
    labels = page.eval_on_selector_all(
        "a[href*='#lesson/']", "els => els.map(e => e.textContent.trim())")
    b.close()
print(f"lesson catalog: {len(lessons)} lessons")
(EV / "lesson_catalog.json").write_text(
    json.dumps({"source": "rendered /WebGoat/start.mvc lesson menu "
                          "(the app's own curriculum, official JAR)",
                "lessons": lessons, "labels": labels}, indent=1,
               ensure_ascii=False), encoding="utf-8")

# ---- 4. engine scan --------------------------------------------------------
sys.path.insert(0, str(ROOT))
from sentinel.auth import AuthProfile
from sentinel.core import EventBus, ScopeRule
from sentinel.oast import OastServer
from sentinel.orchestrator import ScanConfig, SentinelScanner

auth = AuthProfile(login_url=BASE + "/WebGoat/login",
                   username="scanbot9", password="Sc4nx9!q",
                   user_field="username", pass_field="password")
oast = OastServer()
t0 = time.time()
cfg = ScanConfig(allow_private=True, max_pages=30, timeout=10.0,
                 seed="indep-webgoat-2026.4", oast=oast, auth=auth,
                 max_requests=4500, browser=True)
sc = SentinelScanner(BASE + "/WebGoat", cfg)
try:
    rep = sc.run()
finally:
    oast.stop()
wall = time.time() - t0

(EV / "scan.json").write_text(
    json.dumps(rep, indent=1, ensure_ascii=False), encoding="utf-8")
meta = {
    "target": "OWASP WebGoat 2026.4 (official GitHub release JAR, portable "
              "JDK 25 — the jar needs class-file 67+)",
    "base_url": BASE + "/WebGoat",
    "lesson_catalog": "rendered start.mvc lesson menu (in-app curriculum)",
    "auth": "in-session registered account (register.mvc, password policy "
            "6..10 chars), engine form-intelligent login",
    "bounds": {"max_pages": 30, "max_requests": 4500, "timeout": 10.0,
               "oast": "local",
               "batteries_off": ["race", "workflow", "logic_active",
                                 "symbolic", "authz"]},
    "scan_wall_seconds": round(wall, 1),
    "requests": rep["stats"]["requests"],
    "endpoints": rep["stats"]["endpoints"],
    "findings": len(rep["findings"]),
    "run_id": rep.get("run_id"),
}
(EV / "run_meta.json").write_text(
    json.dumps(meta, indent=1, ensure_ascii=False), encoding="utf-8")
print(json.dumps(meta, indent=1, ensure_ascii=False))

if proc is not None:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
print("WEBGOAT SCAN PHASE COMPLETE")

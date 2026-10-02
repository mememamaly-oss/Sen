#!/usr/bin/env python3
"""L1-R diagnosis: manual login trace against a temp instance (same pattern
as r3_e2e_orchestrator, verbose). Temporary — kept for the record."""
import http.cookiejar
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
import urllib.parse
import urllib.error

root = "/home/z/my-project"
port = 3010
tmp = f"/tmp/l1r-diag-{port}"
shutil.rmtree(tmp, ignore_errors=True)
os.makedirs(f"{tmp}/data", exist_ok=True)
base = f"http://localhost:{port}"

r = subprocess.run(["bun", "run", "db:push"], cwd=root,
                   env={**os.environ, "DATABASE_URL": f"file:{tmp}/data/test.db"},
                   capture_output=True, text=True)
print("db:push rc=", r.returncode)

env = {**os.environ,
       "DATABASE_URL": f"file:{tmp}/data/test.db",
       "NEXTAUTH_URL": base,
       "SENTINEL_DATA_DIR": f"{tmp}/data",
       "PORT": str(port), "HOSTNAME": "127.0.0.1", "NODE_ENV": "production"}
log = open(f"{tmp}/server.log", "wb")
srv = subprocess.Popen(["bun", "server.js"], cwd=f"{root}/.next/standalone",
                       env=env, stdout=log, stderr=log, preexec_fn=os.setsid)
print("server pid:", srv.pid)
try:
    for _ in range(60):
        try:
            with urllib.request.urlopen(base + "/api/bootstrap", timeout=3):
                break
        except Exception:
            time.sleep(1)
    print("server ready")

    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def show(tag, req):
        try:
            with op.open(req, timeout=30) as resp:
                body = resp.read().decode()[:400]
                print(f"{tag}: HTTP {resp.status} body={body}")
                return resp.status
        except urllib.error.HTTPError as e:
            print(f"{tag}: HTTP {e.code} body={e.read().decode()[:400]}")
            return e.code

    # bootstrap admin
    data = json.dumps({"email": "diag@sentinel.test", "name": "Diag",
                       "password": "Diag-Pass-123", "orgName": "Diag Org"}).encode()
    show("bootstrap", urllib.request.Request(
        base + "/api/bootstrap", data=data,
        headers={"Content-Type": "application/json"}, method="POST"))

    # csrf (capture errors so we can still read the server log)
    try:
        with op.open(base + "/api/auth/csrf", timeout=30) as r:
            csrf = json.loads(r.read())
        print("csrf ok:", "csrfToken" in csrf)
        got_csrf = True
    except urllib.error.HTTPError as e:
        print("csrf FAILED:", e.code, e.read().decode()[:300])
        got_csrf = False
        csrf = None

    if got_csrf:
        # login
        form = urllib.parse.urlencode({
            "csrfToken": csrf["csrfToken"],
            "email": "diag@sentinel.test",
            "password": "Diag-Pass-123",
            "json": "true"}).encode()
        code = show("login", urllib.request.Request(
            base + "/api/auth/callback/credentials", data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"))
        print("cookies:", [(c.name, c.value[:12]) for c in jar])

        # me
        show("me", urllib.request.Request(base + "/api/me"))

    print("--- server.log tail ---")
    print(open(f"{tmp}/server.log").read()[-1500:])
finally:
    try:
        os.killpg(os.getpgid(srv.pid), signal.SIGTERM)
    except Exception:
        pass
    log.close()
    if "--keep" not in sys.argv:
        shutil.rmtree(tmp, ignore_errors=True)

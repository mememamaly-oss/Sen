"""Differential determinism audit of the 7 Juice Shop path_traversal findings.

Method (per finding): 4 fresh requests — probe('..' as param/header NAME),
control(sentinel-random NAME), probe again, control again. Bodies are
echo-neutralized exactly like the detector does. Classification:

  STABLE-ORACLE   probe differs from control, AND control == control2
                  AND probe == probe2 (the differential is deterministic —
                  a genuine input-dependent oracle)
  NONDETERMINISTIC control != control2 (the endpoint's responses vary on
                  their own — the detector's differential measured noise:
                  FALSE POSITIVE, engine limitation recorded)

Juice Shop boot is included (processes do not survive between calls).
"""
import http.client
import json
import random
import urllib.parse
from pathlib import Path

EV = Path("/home/z/my-project/evidence/independent-verification/juice-shop-20.3.0")
rep = json.loads((EV / "scan.json").read_text(encoding="utf-8"))
targets = [f for f in rep["findings"] if f["type"] == "path_traversal"]
print(f"auditing {len(targets)} path_traversal findings for determinism")

import subprocess, os, time
PORT = 31000
BASE = f"http://127.0.0.1:{PORT}"
proc = None
try:
    import urllib.request
    urllib.request.urlopen(BASE + "/", timeout=3)
    print("juice-shop already up")
except Exception:
    log = open("/tmp/js_audit_boot.log", "w")
    proc = subprocess.Popen(
        ["node", "build/app.js"],
        cwd="/home/z/my-project/external/juice-shop_20.3.0",
        env={**os.environ, "PORT": str(PORT), "NODE_ENV": "production"},
        stdout=log, stderr=subprocess.STDOUT)
    for _ in range(60):
        try:
            urllib.request.urlopen(BASE + "/", timeout=3)
            break
        except Exception:
            time.sleep(1)
    print(f"juice-shop booted (pid {proc.pid})")


def send(url, header_name=None, param_name=None):
    u = urllib.parse.urlsplit(url)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
    path = u.path + ("?" + u.query if u.query else "")
    headers = {}
    if header_name:
        headers[header_name] = "1"
    if param_name:
        path += ("&" if "?" in path else "?") + urllib.parse.quote(param_name) + "=1"
    conn.request("GET", path, headers=headers)
    r = conn.getresponse()
    body = r.read().decode("utf-8", "replace")
    conn.close()
    return r.status, body


def neutralize(body, *tokens):
    for t in tokens:
        if t:
            body = body.replace(t, "")
    return body


results = []
for f in targets:
    url = f["url"]
    is_header = f.get("parameter", "").startswith("header:")
    ctrl = f"sentinel-audit-{random.randrange(10000, 99999)}"
    p1 = send(url, header_name=".." if is_header else None,
              param_name=None if is_header else "..")
    c1 = send(url, header_name=ctrl if is_header else None,
              param_name=None if is_header else ctrl)
    p2 = send(url, header_name=".." if is_header else None,
              param_name=None if is_header else "..")
    c2 = send(url, header_name=f"{ctrl}b" if is_header else None,
              param_name=None if is_header else f"{ctrl}b")
    pn1 = neutralize(p1[1], "..", "1")
    cn1 = neutralize(c1[1], ctrl)
    pn2 = neutralize(p2[1], "..", "1")
    cn2 = neutralize(c2[1], f"{ctrl}b")
    probe_stable = (p1[0] == p2[0]) and (pn1 == pn2)
    control_stable = (c1[0] == c2[0]) and (cn1 == cn2)
    differs = (p1[0] != c1[0]) or (pn1 != cn1)
    if not control_stable:
        verdict = "NONDETERMINISTIC (responses vary on their own — differential measured noise)"
    elif differs and probe_stable:
        verdict = "STABLE-ORACLE (input-dependent differential — needs semantic review)"
    elif not differs:
        verdict = "NO-DIFFERENTIAL on re-test (the scan-time differential did not recur)"
    else:
        verdict = "MIXED (probe unstable — inconclusive)"
    rec = {"finding_id": f["id"], "url": url,
           "channel": "header" if is_header else "param-name",
           "probe": [p1[0], len(p1[1])], "control": [c1[0], len(c1[1])],
           "probe2": [p2[0], len(p2[1])], "control2": [c2[0], len(c2[1])],
           "verdict": verdict}
    results.append(rec)
    print(f"  {f['id']} {url.split('31000')[1]:32s} {verdict[:70]}")

out = {"method": "4-request differential determinism audit (probe x2 + control x2)",
       "results": results}
(EV / "path_traversal_determinism_audit.json").write_text(
    json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
print("saved path_traversal_determinism_audit.json")

if proc is not None:
    proc.terminate()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()

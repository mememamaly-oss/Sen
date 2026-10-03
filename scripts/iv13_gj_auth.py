#!/usr/bin/env python3
"""IV-13 Phase 2: ginandjuice.shop — legitimate auth flow (carlos) + product/cart
mapping + INDEPENDENT SQLi/XSS probes on catalog params. stdlib only, no SENTINEL code."""
import json, os, re, time, ssl, urllib.request, urllib.parse, urllib.error, http.cookiejar
from html.parser import HTMLParser
from datetime import datetime, timezone, timedelta

BASE = 'https://ginandjuice.shop'
UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 IV13-IndependentVerifier/1.0'
CTX = ssl.create_default_context()
OUT = '/home/z/my-project/scripts/iv_out'
TZ = timezone(timedelta(hours=2))

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
            self.cur = {'action': a.get('action'), 'method': (a.get('method') or 'GET').upper(),
                        'class': a.get('class'), 'fields': []}
        elif self.cur is not None and tag in ('input', 'textarea', 'select', 'button'):
            self.cur['fields'].append({'tag': tag, 'type': a.get('type'), 'name': a.get('name'),
                                       'value': (a.get('value') or '')[:80]})
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

def req(opener, url, data=None, extra=None, timeout=25):
    hdrs = {'User-Agent': UA, 'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
            'Referer': BASE + '/', 'Origin': BASE}
    if extra:
        hdrs.update(extra)
    if data is not None and isinstance(data, dict):
        data = urllib.parse.urlencode(data).encode()
        hdrs['Content-Type'] = 'application/x-www-form-urlencoded'
    r = urllib.request.Request(url, data=data, headers=hdrs,
                               method='POST' if data is not None else 'GET')
    try:
        resp = opener.open(r, timeout=timeout)
        body = resp.read().decode('utf-8', 'replace')
        return {'status': resp.status, 'final': resp.geturl(), 'headers': [(k, v) for k, v in resp.headers.items()],
                'body': body, 'len': len(body)}
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', 'replace')
        return {'status': e.code, 'final': url, 'headers': [(k, v) for k, v in e.headers.items()],
                'body': body, 'len': len(body)}
    except Exception as e:
        return {'status': None, 'final': url, 'headers': [], 'body': '', 'len': 0, 'error': repr(e)[:150]}

def setcookies(res):
    return [v for k, v in res['headers'] if k.lower() == 'set-cookie']

def forms_of(html):
    fp = FormParser()
    fp.feed(html)
    return fp.forms

def cart_count(html):
    m = re.search(r'class="cart-icon[^"]*"[^>]*><span>(\d+)</span>', html)
    return int(m.group(1)) if m else None

def title_of(html):
    m = re.search(r'<title[^>]*>(.*?)</title>', html, re.S | re.I)
    return m.group(1).strip() if m else None

log = {'ts_start': datetime.now(TZ).isoformat(timespec='seconds'), 'steps': []}

def note(step, data):
    log['steps'].append({'step': step, 'data': data})
    print('## %s: %s' % (step, json.dumps(data, ensure_ascii=False)[:400]), flush=True)

# ---------- LEGIT FLOW (persistent jar) ----------
op, cj = build(follow=True)

r1 = req(op, BASE + '/login')
csrf = None
m = re.search(r'name="csrf" value="([^"]+)"', r1['body'])
if m:
    csrf = m.group(1)
note('get_login', {'status': r1['status'], 'len': r1['len'], 'csrf_found': bool(csrf),
                   'set_cookie': [c[:160] for c in setcookies(r1)]})

r2 = req(op, BASE + '/login', data={'csrf': csrf or '', 'username': 'carlos'},
         extra={'Referer': BASE + '/login'})
logged_in = ('Log out' in r2['body']) or ('logout' in r2['body'].lower()) or ('carlos' in r2['body'])
note('post_login', {'status': r2['status'], 'final': r2['final'], 'len': r2['len'],
                    'title': title_of(r2['body']), 'logged_in_marker': logged_in,
                    'cookies_now': [c.name for c in cj]})

r3 = req(op, BASE + '/my-account')
note('my_account', {'status': r3['status'], 'final': r3['final'], 'len': r3['len'],
                    'title': title_of(r3['body']),
                    'has_logout': 'log out' in r3['body'].lower(),
                    'forms': [{'m': f['method'], 'a': f['action'],
                               'fields': [x['name'] for x in f['fields']]} for f in forms_of(r3['body'])]})

# product page 1
r4 = req(op, BASE + '/catalog/product?productId=1')
pforms = forms_of(r4['body'])
note('product_1', {'status': r4['status'], 'len': r4['len'], 'title': title_of(r4['body']),
                   'cart_count': cart_count(r4['body']), 'forms': pforms,
                   'links_with_cart': sorted(set(re.findall(r'href="([^"]*cart[^"]*)"', r4['body'])))[:10]})

# try to add to cart per the first POST form found (exact replica)
added = None
for f in pforms:
    if f['method'] == 'POST' and f['action']:
        fields = {x['name']: x['value'] for x in f['fields'] if x.get('name') and x.get('type') != 'submit'}
        url = f['action'] if f['action'].startswith('http') else BASE + f['action']
        r5 = req(op, url, data=fields, extra={'Referer': BASE + '/catalog/product?productId=1'})
        note('add_to_cart_POST', {'action': f['action'], 'fields': fields, 'status': r5['status'],
                                  'final': r5['final'], 'len': r5['len'], 'title': title_of(r5['body']),
                                  'cart_count': cart_count(r5['body'])})
        added = f['action']
        break
if not added:
    # look for GET links like /catalog/cart?add
    m = re.search(r'href="([^"]*cart[^"]*(?:add|product)[^"]*)"', r4['body'])
    if m:
        url = m.group(1) if m.group(1).startswith('http') else BASE + m.group(1)
        r5 = req(op, url, extra={'Referer': BASE + '/catalog/product?productId=1'})
        note('add_to_cart_GET', {'url': m.group(1), 'status': r5['status'], 'final': r5['final'],
                                 'len': r5['len'], 'cart_count': cart_count(r5['body'])})
        added = m.group(1)

# cart state after add
r6 = req(op, BASE + '/catalog/cart')
cforms = forms_of(r6['body'])
note('cart_after_add', {'status': r6['status'], 'len': r6['len'], 'title': title_of(r6['body']),
                        'cart_count': cart_count(r6['body']), 'empty': 'currently empty' in r6['body'],
                        'forms': cforms,
                        'products': sorted(set(re.findall(r'(?:productId=)(\d+)', r6['body'])))[:20]})

log['legit_flow_end'] = datetime.now(TZ).isoformat(timespec='seconds')
log['cookies_final'] = [{'name': c.name, 'attrs': '%s|%s|%s' % (c.get_nonstandard_attr('SameSite', '-'),
                                                                'Secure' if c.secure else '-',
                                                                'HttpOnly' if c.has_nonstandard_attr('HttpOnly') else '-')} for c in cj]

# ---------- INDEPENDENT PROBES (fresh jar, unauthenticated where possible) ----------
op2, cj2 = build(follow=False)
MARK = 'zxK1mQ7v'
probes = []

# P1: searchTerm reflection
for payload, label in [('<b>%s</b>' % MARK, 'tag'), ('"><u>%s</u>' % MARK, 'attr-break')]:
    r = req(op2, BASE + '/catalog?' + urllib.parse.urlencode({'searchTerm': payload}))
    raw = payload in r['body']
    esc = payload.replace('<', '&lt;').replace('>', '&gt;') in r['body']
    i = r['body'].find(MARK)
    ctx = r['body'][max(0, i - 80):i + 100].replace('\n', ' ') if i >= 0 else ''
    probes.append({'probe': 'searchTerm', 'payload': payload, 'status': r['status'], 'len': r['len'],
                   'verdict': 'RAW-REFLECTED' if raw else ('escaped' if esc else 'not-reflected'),
                   'context': ctx[:200]})
    print('PROBE searchTerm %-16s %-14s %s' % (label, probes[-1]['verdict'], r['status']), flush=True)
    time.sleep(0.5)

# P2: productId SQLi oracle (unauth)
for q, label in [('productId=1', 'base'), ('productId=1\'', 'quote'),
                 ('productId=1 AND 1=1', 'true'), ('productId=1 AND 1=2', 'false'),
                 ('productId=1\'--', 'quote-comment'), ('productId=1 ORDER BY 1--', 'order1'),
                 ('productId=100000', 'nonexistent')]:
    r = req(op2, BASE + '/catalog/product?' + q)
    err = re.search(r'(error|exception|SQL|syntax|ODBC|OLE|sqlite|query)[^<]{0,100}', r['body'], re.I)
    probes.append({'probe': 'productId', 'query': q, 'label': label, 'status': r['status'],
                   'len': r['len'], 'err': err.group(0)[:120] if err else None,
                   'title': title_of(r['body'])})
    print('PROBE productId %-14s %s len=%d err=%s' % (label, r['status'], r['len'],
          (err.group(0)[:60] if err else '-')), flush=True)
    time.sleep(0.5)

log['probes'] = probes
log['ts_end'] = datetime.now(TZ).isoformat(timespec='seconds')
with open(os.path.join(OUT, 'gj_flow.json'), 'w') as f:
    json.dump(log, f, indent=1, ensure_ascii=False)
print('\nsaved -> scripts/iv_out/gj_flow.json')

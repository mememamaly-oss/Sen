#!/usr/bin/env python3
"""IV-13 Phase 3: ginandjuice.shop /catalog/cart — CSRF ADJUDICATION BATTERY.
The supervisor's question: real CSRF (no effective protection) vs protected
(SameSite or token makes the claim wrong)?
Evidence layers, each with a fresh isolated session:
  L1 cookie audit: session cookie attributes (SameSite?) on every response
  L2 token audit: does the add-to-cart form carry a csrf token? (already known: NO)
  L3 enforcement A: POST /catalog/cart withOUT token, SAME-SITE Origin/Referer  -> state change?
  L4 enforcement B: POST withOUT token, FOREIGN Origin+Referer (evil.example)   -> state change?
  L5 enforcement C: POST withOUT token, NO Origin/Referer at all                -> state change?
  L6 method test:   GET /catalog/cart?productId=1&quantity=1 (GET state change?) -> state change?
  L7 stock endpoint cross-site probe (secondary, read-only state)
stdlib only."""
import json, os, re, time, ssl, urllib.request, urllib.parse, urllib.error, http.cookiejar
from datetime import datetime, timezone, timedelta

BASE = 'https://ginandjuice.shop'
UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 IV13-IndependentVerifier/1.0'
CTX = ssl.create_default_context()
OUT = '/home/z/my-project/scripts/iv_out'
TZ = timezone(timedelta(hours=2))

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def build(jar=None, follow=False):
    cj = jar or http.cookiejar.CookieJar()
    handlers = [urllib.request.HTTPCookieProcessor(cj),
                urllib.request.HTTPSHandler(context=CTX)]
    if not follow:
        handlers.append(NoRedirect())
    return urllib.request.build_opener(*handlers), cj

def req(opener, url, data=None, headers=None, timeout=25):
    hdrs = {'User-Agent': UA, 'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8'}
    if headers:
        hdrs.update(headers)
    if data is not None:
        if isinstance(data, dict):
            data = urllib.parse.urlencode(data).encode()
            hdrs.setdefault('Content-Type', 'application/x-www-form-urlencoded')
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

def sess_cookie(res_list):
    """extract session cookie Set-Cookie lines"""
    return [v for k, v in res_list if k.lower() == 'set-cookie' and v.startswith('session=')]

def cart_state(opener):
    r = req(opener, BASE + '/catalog/cart')
    m = re.search(r'class="cart-icon[^"]*"[^>]*><span>(\d+)</span>', r['body'])
    empty = 'currently empty' in r['body']
    items = re.findall(r'productId=(\d+)', r['body'])
    return {'count': int(m.group(1)) if m else None, 'empty': empty,
            'len': r['len'], 'product_refs': sorted(set(items))[:10]}

def scenario(label, mode):
    """mode: legit | cross-origin | no-origin | get-based"""
    op, cj = build()
    # visit product page first (like a real user; establishes session + any cookies)
    r0 = req(op, BASE + '/catalog/product?productId=1')
    sc0 = sess_cookie(r0['headers'])
    before = cart_state(op)
    payload = {'productId': '1', 'redir': 'PRODUCT', 'quantity': '1'}
    if mode == 'legit':
        hdrs = {'Origin': BASE, 'Referer': BASE + '/catalog/product?productId=1'}
        r1 = req(op, BASE + '/catalog/cart', data=payload, headers=hdrs)
    elif mode == 'cross-origin':
        hdrs = {'Origin': 'https://evil-iv13.example',
                'Referer': 'https://evil-iv13.example/csrf-attack.html'}
        r1 = req(op, BASE + '/catalog/cart', data=payload, headers=hdrs)
    elif mode == 'no-origin':
        hdrs = {}
        op2, cj2 = build(jar=cj)
        # rebuild opener that does not send Referer: just don't set them
        r1 = req(op2, BASE + '/catalog/cart', data=payload, headers=hdrs)
    elif mode == 'get-based':
        r1 = req(op, BASE + '/catalog/cart?' + urllib.parse.urlencode(payload))
    time.sleep(0.4)
    after = cart_state(op)
    out = {'mode': mode, 'post_status': r1['status'], 'post_location': dict(r1['headers']).get('Location'),
           'post_len': r1['len'], 'cart_before': before, 'cart_after': after,
           'session_cookie_attrs': [c[c.find(';') + 1:].strip()[:120] for c in sc0] if sc0 else None}
    changed = (before['count'] != after['count']) or (before['empty'] and not after['empty']) or \
              (before['len'] != after['len'] and not after['empty'])
    out['state_changed'] = bool(changed)
    print('[%-12s] POST->%s loc=%s | before count=%s empty=%s | after count=%s empty=%s | CHANGED=%s' % (
        label, r1['status'], out['post_location'], before['count'], before['empty'],
        after['count'], after['empty'], out['state_changed']), flush=True)
    return out

def main():
    results = {'ts': datetime.now(TZ).isoformat(timespec='seconds'), 'scenarios': []}
    # L1/L2 context: session cookie attributes (from recon + fresh check)
    op, cj = build()
    r = req(op, BASE + '/catalog/product?productId=1')
    results['session_cookie_set'] = sess_cookie(r['headers'])
    results['session_cookie_attrs'] = [c[c.find(';') + 1:].strip() for c in sess_cookie(r['headers'])]
    print('L1 session cookie:', results['session_cookie_set'], flush=True)
    print('L1 attrs:', results['session_cookie_attrs'], flush=True)

    for label, mode in [('A legit', 'legit'), ('B cross-origin', 'cross-origin'),
                        ('C no-origin', 'no-origin'), ('D get-based', 'get-based')]:
        results['scenarios'].append(scenario(label, mode))
        time.sleep(0.6)

    # L7: stock endpoint cross-origin (read-only secondary)
    op2, cj2 = build()
    r0 = req(op2, BASE + '/catalog/product?productId=1')
    hdrs = {'Origin': 'https://evil-iv13.example', 'Referer': 'https://evil-iv13.example/x.html'}
    r1 = req(op2, BASE + '/catalog/product/stock',
             data={'productId': '1', 'storeId': '1'}, headers=hdrs)
    results['stock_cross_origin'] = {'status': r1['status'], 'len': r1['len'],
                                     'body_head': r1['body'][:150]}
    print('[stock x-origin] POST->%s len=%s body=%s' % (r1['status'], r1['len'], r1['body'][:100]), flush=True)

    with open(os.path.join(OUT, 'gj_csrf_battery.json'), 'w') as f:
        json.dump(results, f, indent=1, ensure_ascii=False)
    print('\nsaved -> scripts/iv_out/gj_csrf_battery.json')

if __name__ == '__main__':
    main()

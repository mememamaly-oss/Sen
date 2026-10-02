#!/usr/bin/env python3
"""Targeted live verification: the REAL CsrfDetector.run() on the endpoint as the
PATCHED discovery parser now builds it (ENG-15 + ENG-17 together), against the
authorized target, with an authenticated SENTINEL engine. This is the engine
firing the finding itself — not a manual claim."""
import sys
sys.path.insert(0, '/home/z/my-project/verify-live')

from sentinel.discovery import _LinkParser
from sentinel.core import Endpoint, Parameter, ParamLocation, ScopeRule
from sentinel.http_engine import RequestEngine, RequestMutation
from sentinel.detect import CsrfDetector

# 1. build the endpoint exactly as the scan now would: parse the live product page
import urllib.request
req = urllib.request.Request('https://ginandjuice.shop/catalog/product?productId=1',
                             headers={'User-Agent': 'SENTINEL-eng17-proof/3.0.1'})
html = urllib.request.urlopen(req, timeout=15).read().decode('utf-8', 'replace')
p = _LinkParser(); p.feed(html)
cart_form = next(f for f in p.forms if f['action'] == '/catalog/cart')
print('parsed add-to-cart params:', cart_form['params'])
assert ('quantity', '1') in cart_form['params'], 'ENG-17 failed live: quantity missing'

# 2. the endpoint the crawl registers from that form
params = [Parameter(n, ParamLocation.BODY, v).classify() for n, v in cart_form['params']]
ep = Endpoint(url='https://ginandjuice.shop/catalog/cart', method='POST', parameters=params)

# 3. classifier says state-changing now (ENG-15)
det = CsrfDetector.__new__(CsrfDetector)
assert det._state_changing(ep), 'ENG-15 failed live: /catalog/cart still demoted'
print('ENG-15: /catalog/cart classified state-changing: True')

# 4. run the REAL detector with a real engine + authenticated session
from sentinel.core import EventBus
engine = RequestEngine(scope=ScopeRule(allow_private=False), bus=EventBus('eng-proof-run'))
from sentinel.auth import AuthProfile, AuthEngine
ap = AuthProfile(login_url='https://ginandjuice.shop/login', username='carlos',
                 password='hunter2', user_field='username', pass_field='password')
ae = AuthEngine(ap, engine, EventBus('eng-proof-run'))
ok = ae.login()
print('auth login via SENTINEL engine:', ok)

det2 = CsrfDetector(engine, EventBus('eng-proof-run'))
f = det2.run(ep)
if f is None:
    print('DETECTOR: no finding (still failing)'); sys.exit(1)
print('DETECTOR FIRED:', f.vuln_type if hasattr(f,'vuln_type') else f.type, getattr(f,'severity',''), getattr(f,'endpoint',''), '| params:', getattr(f,'parameter',''))
for e in f.evidence:
    print('  EV:', e.kind, '-', e.detail[:220])

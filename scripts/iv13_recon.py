#!/usr/bin/env python3
"""IV-13 Phase 0: BLIND recon of the 5 sanctioned test targets.
Independent verifier round — stdlib only, NO SENTINEL code, NO SENTINEL findings data
consulted for target selection (only public knowledge + live recon).
Saves headers/forms/bodies to scripts/iv_out/recon/ for later phases."""
import ssl, json, os, re, urllib.request, urllib.error
from html.parser import HTMLParser

OUT = '/home/z/my-project/scripts/iv_out/recon'
os.makedirs(OUT, exist_ok=True)
UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 IV13-IndependentVerifier/1.0'

TARGETS = {
    'demo.testfire.net': ['/', '/robots.txt', '/login.jsp'],
    'ginandjuice.shop': ['/', '/robots.txt', '/login', '/catalog', '/catalog/cart'],
    'testasp.vulnweb.com': ['/', '/robots.txt', '/guestbook.asp'],
    'testaspnet.vulnweb.com': ['/', '/robots.txt', '/guestbook.aspx'],
    'google-gruyere.appspot.com': ['/', '/robots.txt', '/login'],
}

CTX = ssl.create_default_context()

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def fetch(url, timeout=20):
    req = urllib.request.Request(url, headers={'User-Agent': UA,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'})
    op = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=CTX))
    try:
        r = op.open(req, timeout=timeout)
        return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()
    except Exception as e:
        return None, None, repr(e).encode()

class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.cur = None
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'form':
            self.cur = {'action': a.get('action'), 'method': (a.get('method') or 'GET').upper(),
                        'fields': []}
        elif self.cur is not None and tag in ('input', 'textarea', 'select', 'button'):
            self.cur['fields'].append({'tag': tag, 'type': a.get('type'), 'name': a.get('name'),
                                       'value': (a.get('value') or '')[:60]})
    def handle_endtag(self, tag):
        if tag == 'form' and self.cur:
            self.forms.append(self.cur)
            self.cur = None

report = {}
for host, paths in TARGETS.items():
    report[host] = {}
    for p in paths:
        url = 'https://' + host + p
        status, hdrs, body = fetch(url)
        ent = {'url': url, 'status': status}
        if hdrs is not None:
            ent['headers'] = [(k, v) for k, v in hdrs.items()]
            ent['set_cookie'] = [v for k, v in hdrs.items() if k.lower() == 'set-cookie']
            interesting = ['content-security-policy', 'x-frame-options', 'x-content-type-options',
                           'server', 'strict-transport-security', 'referrer-policy',
                           'cache-control', 'location']
            ent['sec_headers'] = dict((k, v) for k, v in hdrs.items() if k.lower() in interesting)
        if isinstance(body, bytes) and body and status is not None and status < 400:
            txt = body.decode('utf-8', 'replace')
            safe = p.strip('/').replace('/', '_') or 'root'
            try:
                with open(os.path.join(OUT, host + '__' + safe + '.html'), 'w') as f:
                    f.write(txt)
            except OSError:
                pass
            fp = FormParser()
            fp.feed(txt)
            ent['len'] = len(body)
            m = re.search(r'<title[^>]*>(.*?)</title>', txt, re.S | re.I)
            ent['title'] = m.group(1).strip()[:120] if m else None
            ent['forms'] = fp.forms
            ent['links_sample'] = sorted(set(re.findall(r'href="(/[^"]{0,60})"', txt)))[:40]
        elif isinstance(body, bytes):
            ent['len'] = len(body)
            ent['err'] = body[:150].decode('utf-8', 'replace')
        else:
            ent['error'] = str(body)[:150]
        report[host][p] = ent
        print('%-28s %-16s %s len=%s | %s' % (host, p, status, ent.get('len'),
              (ent.get('error') or '')[:60] or (ent.get('title') or '')[:60]), flush=True)

with open('/home/z/my-project/scripts/iv_out/recon.json', 'w') as f:
    json.dump(report, f, indent=1, ensure_ascii=False)
print('\nsaved -> scripts/iv_out/recon.json')

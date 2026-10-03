#!/usr/bin/env python3
"""IV-13 Phase 4: testasp.vulnweb.com + testaspnet.vulnweb.com (HTTP — HTTPS certs invalid).
Independent probing: form extraction -> reflection test (HTML-injection marker),
SQLi error probes on same params. stdlib only."""
import json, os, re, ssl, time, urllib.request, urllib.parse, urllib.error
from html.parser import HTMLParser

OUT = '/home/z/my-project/scripts/iv_out'
os.makedirs(OUT, exist_ok=True)
UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 IV13-IndependentVerifier/1.0'
CTX = ssl._create_unverified_context()

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def fetch(url, data=None, headers=None, timeout=25):
    hdrs = {'User-Agent': UA, 'Accept': 'text/html,*/*;q=0.8'}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs,
                                 method='POST' if data is not None else 'GET')
    op = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=CTX))
    try:
        r = op.open(req, timeout=timeout)
        return r.status, dict(r.headers), r.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode('utf-8', 'replace')
    except Exception as e:
        return None, {}, repr(e)

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
            self.cur['fields'].append({'tag': tag, 'type': a.get('type'), 'name': a.get('name'), 'value': (a.get('value') or '')[:60]})
    def handle_endtag(self, tag):
        if tag == 'form' and self.cur:
            self.forms.append(self.cur)
            self.cur = None

def probe_host(base):
    print('=' * 70)
    print('TARGET', base)
    results = {'target': base, 'pages': {}, 'probes': []}
    # 1. entry pages
    pages = {'/': None, '/guestbook.asp' if 'testasp.' in base else '/guestbook.aspx': None}
    if 'aspnet' in base:
        pages = {'/': None, '/blog/': None}
    for p in list(pages):
        st, hd, body = fetch(base + p)
        fp = FormParser()
        if isinstance(body, str) and body:
            fp.feed(body)
        pages[p] = {'status': st, 'len': len(body) if isinstance(body, str) else 0,
                    'forms': fp.forms,
                    'set_cookie': hd.get('Set-Cookie', '')[:200] if isinstance(hd, dict) else '',
                    'error': body if isinstance(body, str) and not body.startswith('<') else None}
        print('%-16s %s len=%d forms=%d' % (p, st, pages[p]['len'], len(fp.forms)))
        for f in fp.forms:
            print('   FORM %s %s fields=%s' % (f['method'], f['action'],
                  [(x['name'], x['type']) for x in f['fields']]))
        time.sleep(0.4)
    results['pages'] = {k: v for k, v in pages.items() if v}

    # 2. reflection probes on every discovered GET form param
    MARK = 'zxK1mQ7v'
    MARKTAG = '<b>%s</b>' % MARK
    for p, info in results['pages'].items():
        if not isinstance(info, dict):
            continue
        for f in info.get('forms') or []:
            if f['method'] != 'GET' or not f['action']:
                continue
            for fld in f['fields']:
                nm = fld.get('name')
                if not nm or fld.get('type') in ('submit', 'button', 'hidden'):
                    continue
                # reflection test
                q = urllib.parse.urlencode({nm: MARKTAG})
                url = f['action'] if f['action'].startswith('http') else base + f['action']
                if '?' in url:
                    url += '&' + q
                else:
                    url += '?' + q
                st, hd, body = fetch(url)
                raw = isinstance(body, str)
                reflected_raw = raw and MARKTAG in body
                reflected_esc = raw and ('&lt;b&gt;%s&lt;/b&gt;' % MARK) in body
                ctx = ''
                if raw:
                    i = body.find(MARK)
                    if i >= 0:
                        ctx = body[max(0, i - 80):i + 100].replace('\n', ' ')
                verdict = 'XSS-CONFIRMED (raw tag reflected)' if reflected_raw else ('reflected-escaped' if reflected_esc else 'not-reflected')
                print('  PROBE %-14s %-10s %-28s %s' % (p, nm, verdict, st))
                if ctx:
                    print('    ctx: %s' % ctx[:160])
                results['probes'].append({'page': p, 'param': nm, 'verdict': verdict,
                                          'status': st, 'context': ctx[:200]})
                # SQLi error probe on same param
                q = urllib.parse.urlencode({nm: "'"})
                url2 = f['action'] if f['action'].startswith('http') else base + f['action']
                url2 += ('&' if '?' in url2 else '?') + q
                st2, hd2, body2 = fetch(url2)
                if isinstance(body2, str):
                    m = re.search(r'(OLE DB|SQL Server|Microsoft \[|ODBC|JET|Oracle|syntax error|unterminated|SQLException|ODBC\.NET)[^<]{0,120}', body2, re.I)
                    if m:
                        print('    SQLI-ERR: %s' % m.group(0)[:140])
                        results['probes'].append({'page': p, 'param': nm, 'verdict': 'SQL-error-string',
                                                  'status': st2, 'evidence': m.group(0)[:200]})
                time.sleep(0.4)
    return results

def main():
    allr = []
    for base in ['http://testasp.vulnweb.com', 'http://testaspnet.vulnweb.com']:
        allr.append(probe_host(base))
    with open(os.path.join(OUT, 'vulnweb_probes.json'), 'w') as f:
        json.dump(allr, f, indent=1, ensure_ascii=False)
    print('\nsaved -> scripts/iv_out/vulnweb_probes.json')

if __name__ == '__main__':
    main()

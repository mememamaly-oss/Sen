#!/usr/bin/env python3
"""Patch 2: exact pair-swap value replacement.

str.replace(old, new, 1) replaces the first occurrence of the value ANYWHERE
in the URL/body — on the live testaspnet report the tbComment payload landed
under __EVENTTARGET (its value was 'sentinel', the same string, appearing
earlier in the body). Every planner now swaps the value INSIDE ITS OWN PAIR,
preserving pair order and every other byte.
"""
import ast

P = "/home/z/my-project/build-v423/sentinel/impact.py"
src = open(P).read()

HELPERS = '''

def _swap_query_value(url, param, new_val):
    """Swap one param's value inside its OWN query pair (byte-exact elsewhere)."""
    try:
        u = urllib.parse.urlsplit(url)
    except Exception:
        return url
    pairs = (u.query or "").split("&")
    out, done = [], False
    for pair in pairs:
        if "=" in pair and not done:
            k, _v = pair.split("=", 1)
            if urllib.parse.unquote_plus(k) == param:
                out.append(k + "=" + new_val)
                done = True
                continue
        out.append(pair)
    if not done:
        out.append(urllib.parse.quote_plus(param) + "=" + new_val)
    return urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, "&".join(out), ""))


def _swap_body_value(body, param, new_val):
    """Swap one param's value inside its OWN body pair (byte-exact elsewhere)."""
    pairs = (body or "").split("&")
    out, done = [], False
    for pair in pairs:
        if "=" in pair and not done:
            k, _v = pair.split("=", 1)
            if urllib.parse.unquote_plus(k) == param:
                out.append(k + "=" + new_val)
                done = True
                continue
        out.append(pair)
    if not done:
        out.append(urllib.parse.quote_plus(param) + "=" + new_val)
    return "&".join(out)
'''

src = src.replace('''def _mk_req(label, method, url, headers=None, body="", **extra):''',
                  HELPERS + '''

def _mk_req(label, method, url, headers=None, body="", **extra):''')

# ---- _plan_sql: swap inside the param's own pair -----------------------------
src = src.replace('''    reqs = []
    for label, cond in conds:
        new_val = tpl["render"](cond)
        if tpl["kind"] == "query":
            nurl = tpl["raw_url"].replace(tpl["old_value"], new_val, 1)
            reqs.append(_mk_req(label, (ents[0][1].get("method") or "GET") if ents else "GET",
                                nurl, dict((ents[0][1].get("headers") or {})) if ents else {},
                                body="", condition=cond))
        else:
            nbody = (tpl["raw_body"] or "").replace(tpl["old_value"], new_val, 1)
            reqs.append(_mk_req(label, "POST", tpl["raw_url"],
                                dict((ents[0][1].get("headers") or {})) if ents else {},
                                body=nbody, condition=cond))
    return {"status": "PLANNED", "requests": reqs,''',
'''    reqs = []
    base_headers = dict((ents[0][1].get("headers") or {})) if ents else {}
    base_method = (ents[0][1].get("method") or "GET").upper() if ents else "GET"
    for label, cond in conds:
        new_val = tpl["render"](cond)
        if tpl["kind"] == "query":
            nurl = _swap_query_value(tpl["raw_url"], tpl["param"], new_val)
            reqs.append(_mk_req(label, base_method, nurl, dict(base_headers),
                                body=(tpl["raw_body"] or ""), condition=cond))
        else:
            nbody = _swap_body_value(tpl["raw_body"] or "", tpl["param"], new_val)
            reqs.append(_mk_req(label, base_method, tpl["raw_url"], dict(base_headers),
                                body=nbody, condition=cond))
    return {"status": "PLANNED", "requests": reqs,''')

# ---- _plan_crlf: swap inside the param's own pair ----------------------------
src = src.replace('''        new_val = rv[:cut] + sep + L3_HEADER_TAIL
        nurl = url.replace(rv, new_val, 1)''',
'''        new_val = rv[:cut] + sep + L3_HEADER_TAIL
        nurl = _swap_query_value(url, param, new_val)''')

# ---- _plan_stored: swap inside the param's own pair (body + query) -----------
src = src.replace('''        if carrier == "body":
            nbody, nurl = body.replace(rv, new_val, 1), url
            method = (req.get("method") or "POST").upper()
            hdrs = dict(req.get("headers") or {})
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            nurl, nbody = url.replace(rv, new_val, 1), ""
            method = (req.get("method") or "GET").upper()
            hdrs = dict(req.get("headers") or {})''',
'''        if carrier == "body":
            nbody = _swap_body_value(body, param, new_val)
            nurl = url
            method = (req.get("method") or "POST").upper()
            hdrs = dict(req.get("headers") or {})
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            nurl = _swap_query_value(url, param, new_val)
            nbody = ""
            method = (req.get("method") or "GET").upper()
            hdrs = dict(req.get("headers") or {})''')

open(P, "w").write(src)
ast.parse(src)
print("pair-swap patch applied; impact.py parses")

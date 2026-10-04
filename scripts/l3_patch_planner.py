#!/usr/bin/env python3
"""Patch impact.py planner fixes:
A. full surface pool (uncapped) — the capped proving pool cut the CRLF/stored
   vectors on the live ginjuice/gruyere reports;
B. CRLF: case-insensitive separator detection, original separator preserved,
   fixture-exact fresh-header tail;
C. stored XSS: query-param payloads (GET forms) in addition to body params;
D. traversal original-body lookup via the surface pool.
"""
import re

P = "/home/z/my-project/build-v423/sentinel/impact.py"
src = open(P).read()

# ---- A: replace the capped proving pool with a full surface pool -------------
src = src.replace('''def _finding_proving_entries(f, ctx):
    """Decoded proving-request haystacks for a finding, deterministic order."""
    out = []
    for rid in ctx.proving_entries(f):
        e = ctx.entry(rid)
        req = e.get("request") or {}
        hay = urllib.parse.unquote_plus(
            f"{req.get('url', '')} {req.get('body', '')}").lower()
        out.append((rid, req, hay))
    return out''',
'''def _surface_entries(f, ctx):
    """EVERY journal entry on the finding's own surface (method + path + any
    param name present), deterministic rid order. Uncapped on purpose: the
    proving pool (capped at 6) cut the CRLF/stored vectors on the live reports
    — L3 must always see the finding's whole surface."""
    ftype = f.get("type") or ""
    path = apath._path_of(f.get("url", ""))
    method = (f.get("method") or "GET").upper()
    params = [p.strip() for p in (f.get("parameter") or "").split(",") if p.strip()]
    out = []
    for rid in sorted((ctx.journal or {}).keys(), key=str):
        e = ctx.entry(rid)
        req = e.get("request") or {}
        rpath = apath._path_of(req.get("url", ""))
        rmethod = (req.get("method") or "").upper()
        hay = f"{req.get('url', '')} {req.get('body', '')}"
        if rmethod == method and rpath == path and any(p in hay for p in params):
            out.append((rid, req, hay))
    return out


def _finding_proving_entries(f, ctx):
    """Decoded proving-request haystacks for a finding, deterministic order."""
    out = []
    for rid, req, hay in _surface_entries(f, ctx):
        out.append((rid, req,
                    urllib.parse.unquote_plus(
                        f"{req.get('url', '')} {req.get('body', '')}").lower()))
    return out''')

src = src.replace("ents = _finding_proving_entries(f, ctx)",
                  "ents = _finding_proving_entries(f, ctx)", 1)

# every planner call site: _surface_entries -> decoded pool handled inside
src = src.replace("def _plan_xxe(f, ctx):\n    ents = _finding_proving_entries(f, ctx)",
                  "def _plan_xxe(f, ctx):\n    ents = _finding_proving_entries(f, ctx)")
src = src.replace("def _plan_csrf(f, ctx, origin_probe, cart_view=\"/cart\"):\n    url = f.get(\"url\") or \"\"\n    ents = _finding_proving_entries(f, ctx)",
                  "def _plan_csrf(f, ctx, origin_probe, cart_view=\"/cart\"):\n    url = f.get(\"url\") or \"\"\n    ents = _finding_proving_entries(f, ctx)")
src = src.replace("def _plan_trav(f, ctx):\n    ents = _finding_proving_entries(f, ctx)",
                  "def _plan_trav(f, ctx):\n    ents = _finding_proving_entries(f, ctx)")
src = src.replace("def _plan_crlf(f, ctx):\n    ents = _finding_proving_entries(f, ctx)",
                  "def _plan_crlf(f, ctx):\n    ents = _finding_proving_entries(f, ctx)")

# ---- B: CRLF — case-insensitive separator, original separator preserved,
#         fixture-exact fresh-header tail --------------------------------------
src = src.replace('''def _plan_crlf(f, ctx):
    ents = _finding_proving_entries(f, ctx)
    for _rid, req, _hay in ents:
        url = req.get("url") or ""
        try:
            q = urllib.parse.urlsplit(url).query or ""
        except Exception:
            continue
        param = (f.get("parameter") or "").split(",")[0].strip()
        rv = _raw_param(q, param)
        if rv is None or ("%0d%0a" not in rv.lower() and "\\r\\n" not in rv):
            continue
        low = rv.lower()
        cut = low.find("%0d%0a")
        if cut < 0:
            cut = rv.find("\\r\\n")
            prefix = rv[:cut]
            sep = "%0d%0a"
        else:
            prefix = rv[:cut]
            sep = "%0d%0a"
        fresh = urllib.parse.quote_plus(f"{L3_HEADER_NAME}: {L3_HEADER_VALUE}")
        new_val = prefix + sep + fresh
        nurl = url.replace(rv, new_val, 1)
        return {"status": "PLANNED", "requests": [
            _mk_req("header_injection", (req.get("method") or "GET").upper(), nurl,
                    dict(req.get("headers") or {}), req.get("body") or "",
                    expected_header=L3_HEADER_NAME, expected_value=L3_HEADER_VALUE)],
            "refusal_reason": ""}
    return _refuse("no CRLF-shaped proven vector on the finding's surface")''',
'''def _plan_crlf(f, ctx):
    ents = _finding_proving_entries(f, ctx)
    for _rid, req, _hay in ents:
        url = req.get("url") or ""
        try:
            q = urllib.parse.urlsplit(url).query or ""
        except Exception:
            continue
        param = (f.get("parameter") or "").split(",")[0].strip()
        rv = _raw_param(q, param)
        if rv is None:
            continue
        low = rv.lower()
        cut = low.find("%0d%0a")
        sep = ""
        if cut >= 0:
            sep = rv[cut:cut + 6]          # preserve the proven separator bytes
        else:
            cut = rv.find("\\r\\n")
            if cut >= 0:
                sep = "%0D%0A"
        if cut < 0:
            continue
        # the fresh header tail, byte-exact (lowercase %3a / %20 — the shape
        # the live targets accept after decoding and the fixture pins)
        new_val = rv[:cut] + sep + L3_HEADER_TAIL
        nurl = url.replace(rv, new_val, 1)
        return {"status": "PLANNED", "requests": [
            _mk_req("header_injection", (req.get("method") or "GET").upper(), nurl,
                    dict(req.get("headers") or {}), req.get("body") or "",
                    expected_header=L3_HEADER_NAME, expected_value=L3_HEADER_VALUE)],
            "refusal_reason": ""}
    return _refuse("no CRLF-shaped proven vector on the finding's surface")''')

src = src.replace('''L3_HEADER_NAME = "x-sentinel-l3-proof"
L3_HEADER_VALUE = "capability-proven"''',
'''L3_HEADER_NAME = "x-sentinel-l3-proof"
L3_HEADER_VALUE = "capability-proven"
L3_HEADER_TAIL = "x-sentinel-l3-proof%3a%20capability-proven"''')

# ---- C: stored XSS — query-param payloads in addition to body params --------
src = src.replace('''def _plan_stored(f, ctx):
    param = (f.get("parameter") or "").split(",")[0].strip()
    render_url = ""
    for e in f.get("evidence") or []:
        if e.get("kind") == "stored_xss_surfaces":
            m = re.search(r"https?://\\S+", e.get("detail") or "")
            if m:
                render_url = m.group(0)
                break
    if not render_url:
        return _refuse("no render surface recorded for the stored finding")
    ents = _finding_proving_entries(f, ctx)
    body = ""
    for _rid, req, _hay in ents:
        if (req.get("body") or "").strip():
            body = req.get("body")
            break
    if not body:
        return _refuse("no proven POST vector on the stored surface")
    rv = None
    for pair in body.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            if urllib.parse.unquote_plus(k) == param:
                rv = v
                break
    if rv is None:
        return _refuse("the stored parameter is not present in the proven vector")
    new_val = urllib.parse.quote_plus(_xss_payload("xss_stored"))
    nbody = body.replace(rv, new_val, 1)
    hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
    return {"status": "PLANNED", "requests": [
        _mk_req("stored_resubmit", "POST", f.get("url") or "", hdrs, nbody,
                expected_status=200),
        _mk_req("browser_exec_stored", "GET", render_url, {}, "",
                expected_flag=XSS_FLAG["xss_stored"], expected_variant=XSS_VARIANT["xss_stored"],
                render_url=render_url)],
        "refusal_reason": ""}''',
'''def _plan_stored(f, ctx):
    param = (f.get("parameter") or "").split(",")[0].strip()
    render_url = ""
    for e in f.get("evidence") or []:
        if e.get("kind") == "stored_xss_surfaces":
            m = re.search(r"https?://\\S+", e.get("detail") or "")
            if m:
                render_url = m.group(0)
                break
    if not render_url:
        return _refuse("no render surface recorded for the stored finding")
    ents = _finding_proving_entries(f, ctx)
    new_val = urllib.parse.quote_plus(_xss_payload("xss_stored"))
    for _rid, req, _hay in ents:
        url = req.get("url") or ""
        body = req.get("body") or ""
        try:
            q = urllib.parse.urlsplit(url).query or ""
        except Exception:
            continue
        # body-param shape (POST forms, e.g. testaspnet Comments.aspx)
        rv = None
        carrier = ""
        if body.strip():
            for pair in body.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    if urllib.parse.unquote_plus(k) == param:
                        rv = v
                        carrier = "body"
                        break
        # query-param shape (GET forms, e.g. gruyere saveprofile)
        if rv is None:
            rv = _raw_param(q, param)
            if rv is not None:
                carrier = "query"
        if rv is None:
            continue
        if carrier == "body":
            nbody, nurl = body.replace(rv, new_val, 1), url
            method = (req.get("method") or "POST").upper()
            hdrs = dict(req.get("headers") or {})
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            nurl, nbody = url.replace(rv, new_val, 1), ""
            method = (req.get("method") or "GET").upper()
            hdrs = dict(req.get("headers") or {})
        return {"status": "PLANNED", "requests": [
            _mk_req("stored_resubmit", method, nurl, hdrs, nbody, expected_status=200),
            _mk_req("browser_exec_stored", "GET", render_url, {}, "",
                    expected_flag=XSS_FLAG["xss_stored"],
                    expected_variant=XSS_VARIANT["xss_stored"], render_url=render_url)],
            "refusal_reason": ""}
    return _refuse("no proven vector carrying the stored parameter on its surface")''')

# ---- D: traversal original-body via the surface pool ------------------------
src = src.replace('''        for f in ctx.findings:
            if f.get("type") == "path_traversal":
                for rid in ctx.proving_entries(f):
                    e = ctx.entry(rid)
                    req = e.get("request") or {}
                    if ".." in urllib.parse.unquote_plus(f"{req.get('url', '')} {req.get('body', '')}"):
                        return _body(e)''',
'''        for f in ctx.findings:
            if f.get("type") == "path_traversal":
                for rid, req, _hay in _surface_entries(f, ctx):
                    if ".." in urllib.parse.unquote_plus(
                            f"{req.get('url', '')} {req.get('body', '')}"):
                        return _body(ctx.entry(rid))''')

open(P, "w").write(src)
print("impact.py planner fixes applied")
print("L3_HEADER_TAIL present:", "L3_HEADER_TAIL" in src)
print("_surface_entries present:", "_surface_entries" in src)

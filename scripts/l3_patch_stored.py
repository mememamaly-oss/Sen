#!/usr/bin/env python3
"""Patch 3: stored-XSS probe upgrade.

Live measurement on testaspnet taught:
 - the WebForms postback needs the SUBMIT BUTTON field (btnSend) — the
   verifier's real-form entries carry it, the engine's probe entries don't;
 - __VIEWSTATE/__EVENTVALIDATION must be FRESH — a stale body from the scan
   journal is rejected silently, so the executor refreshes the hidden fields
   from a live GET and merges them into the planned body;
 - the app filters the img-onerror comment TODAY (the <u> markup persists) —
   the probe stays honest: what fires is what gets recorded.

Assessor change: stored_resubmit matches by label+url (the hidden fields are
refreshed live by the executor — never part of the planned bytes); the
confirmation requires the planned PAYLOAD VALUE inside the sent body/url.
"""
import ast

P = "/home/z/my-project/build-v423/sentinel/impact.py"
src = open(P).read()

# ---- planner: pick the real-form entry; drop hidden pairs from the plan body
old = '''        if carrier == "body":
            nbody = _swap_body_value(body, param, new_val)
            nurl = url
            method = (req.get("method") or "POST").upper()
            hdrs = dict(req.get("headers") or {})
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            nurl = _swap_query_value(url, param, new_val)
            nbody = ""
            method = (req.get("method") or "GET").upper()
            hdrs = dict(req.get("headers") or {})'''
new = '''        if carrier == "body":
            nbody = _swap_body_value(body, param, new_val)
            # hidden fields (__VIEWSTATE & friends) are refreshed LIVE by the
            # executor — they never belong to the planned bytes
            nbody = "&".join(p for p in nbody.split("&")
                             if not p.split("=", 1)[0].startswith("__"))
            nurl = url
            method = (req.get("method") or "POST").upper()
            hdrs = dict(req.get("headers") or {})
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            nurl = _swap_query_value(url, param, new_val)
            nbody = ""
            method = (req.get("method") or "GET").upper()
            hdrs = dict(req.get("headers") or {})'''
assert old in src
src = src.replace(old, new)

# prefer an entry whose form carries a submit-button field (real form replay)
old = '''    ents = _finding_proving_entries(f, ctx)
    new_val = urllib.parse.quote_plus(_xss_payload("xss_stored"))
    for _rid, req, _hay in ents:'''
new = '''    ents = _finding_proving_entries(f, ctx)
    new_val = urllib.parse.quote_plus(_xss_payload("xss_stored"))
    # prefer a REAL-FORM entry (one that carries a submit-button field): the
    # WebForms postback only processes the comment when the button field rides
    # the body (live-measured: without it the POST is a silent no-op)
    def _has_submit(req):
        b = req.get("body") or ""
        return any(("btn" in k or "send" in k or "submit" in k)
                   for k, _v in [(p.split("=", 1) + [""])[:2][0], 0][:1]
                   for p in b.split("&") if "=" in p
                   for k in [p.split("=", 1)[0]])
    ents = sorted(ents, key=lambda t: (0 if _has_submit(t[1]) else 1, t[0]))
    for _rid, req, _hay in ents:'''
assert old in src
src = src.replace(old, new)

# ---- assessor: body-exempt matching + payload-value presence confirmation
old = '''    if probe_kind in ("xss_stored_persistence",):
        need = ("stored_resubmit", "browser_exec_stored")
        missing = [lb for lb in need if lb not in got]
        if missing:
            return _probe_failed("probe records incomplete — " + ", ".join(missing),
                                 {"missing_labels": missing})
        sr, be = got["stored_resubmit"][1], got["browser_exec_stored"][1]
        sr_status = int((sr.get("response") or {}).get("status") or 0)
        b = (be.get("response") or {}).get("browser") or {}
        want = _first_expected(requests, "expected_flag", XSS_FLAG["xss_stored"])'''
new = '''    if probe_kind in ("xss_stored_persistence",):
        need = ("stored_resubmit", "browser_exec_stored")
        missing = [lb for lb in need if lb not in got]
        if missing:
            return _probe_failed("probe records incomplete — " + ", ".join(missing),
                                 {"missing_labels": missing})
        sr, be = got["stored_resubmit"][1], got["browser_exec_stored"][1]
        sr_status = int((sr.get("response") or {}).get("status") or 0)
        b = (be.get("response") or {}).get("browser") or {}
        want = _first_expected(requests, "expected_flag", XSS_FLAG["xss_stored"])
        # the planned payload VALUE must ride the request the executor sent
        # (url for GET forms, body for POST forms); hidden fields never count
        payload_val = next((urllib.parse.quote_plus(_xss_payload("xss_stored"))
                            for r in requests or [] if r.get("label") == "stored_resubmit"
                            for _x in [1]), "")
        sent = ((sr.get("request") or {}).get("url", "") + " " +
                ((sr.get("request") or {}).get("body") or ""))
        payload_rides = bool(payload_val) and payload_val in sent'''
assert old in src
src = src.replace(old, new)

old = '''        if not (200 <= sr_status < 300) or not b.get("fired") or b.get("flag_value") != want:
            return _probe_failed("the stored canary did not persist AND execute "
                                 "(measured below) — honest failure",
                                 {"resubmit_status": sr_status, "fired": bool(b.get("fired")),
                                  "observed_flag": b.get("flag_value"), "expected_flag": want})'''
new = '''        if not (200 <= sr_status < 300) or not payload_rides or \\
                not b.get("fired") or b.get("flag_value") != want:
            return _probe_failed("the stored canary did not persist AND execute "
                                 "(measured below) — honest failure",
                                 {"resubmit_status": sr_status, "fired": bool(b.get("fired")),
                                  "payload_rides_the_request": payload_rides,
                                  "observed_flag": b.get("flag_value"), "expected_flag": want})'''
assert old in src
src = src.replace(old, new)

# matching: stored_resubmit is matched by label+url (hidden fields refreshed live)
old = '''def _match_entries(requests, journal):
    """Match journal entries to planned requests by (label, url, body) — the
    strictest identity that does not depend on how the executor records
    transport headers. First match by stable key order."""
    out = {}
    for r in requests or []:
        for k in sorted(journal.keys(), key=str):
            e = journal.get(k)
            if not isinstance(e, dict):
                continue
            if e.get("label") != r.get("label"):
                continue
            req = e.get("request") or {}
            if (req.get("method") or "").upper() != (r.get("method") or "GET").upper():
                continue
            if (req.get("url") or "") != (r.get("url") or ""):
                continue
            if (req.get("body") or "") != (r.get("body") or ""):
                continue
            out[r["label"]] = (k, e)
            break
    return out'''
new = '''def _match_entries(requests, journal):
    """Match journal entries to planned requests by (label, url[, body]).
    stored_resubmit is body-exempt on purpose: its hidden fields
    (__VIEWSTATE & friends) are refreshed LIVE by the executor and never
    belong to the planned bytes — the payload-pair presence is confirmed
    separately by the kind's own logic."""
    out = {}
    for r in requests or []:
        body_exempt = r.get("label") == "stored_resubmit"
        for k in sorted(journal.keys(), key=str):
            e = journal.get(k)
            if not isinstance(e, dict):
                continue
            if e.get("label") != r.get("label"):
                continue
            req = e.get("request") or {}
            if (req.get("method") or "").upper() != (r.get("method") or "GET").upper():
                continue
            if (req.get("url") or "") != (r.get("url") or ""):
                continue
            if not body_exempt and (req.get("body") or "") != (r.get("body") or ""):
                continue
            out[r["label"]] = (k, e)
            break
    return out'''
assert old in src
src = src.replace(old, new)

# ---- executor: refresh hidden fields for POST stored_resubmit
old = '''def _exec_http(r, engine, Endpoint, Parameter, ParamLocation, RequestMutation):
    u = urllib.parse.urlsplit(r["url"])
    q = urllib.parse.parse_qsl(u.query or "", keep_blank_values=True)
    ep = Endpoint(url=urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, "", "")),
                  method=(r.get("method") or "GET").upper(),
                  parameters=[Parameter(n, ParamLocation.QUERY, v) for n, v in q],
                  headers=dict(r.get("headers") or {}))
    m = RequestMutation(endpoint=ep, method=(r.get("method") or "GET").upper(),
                        body_override=r.get("body") or "",
                        extra_headers=dict(r.get("headers") or {}))
    resp = engine.send(m)
    body = resp.body or ""
    return {"request": {"method": (r.get("method") or "GET").upper(),
                        "url": r["url"], "headers": dict(r.get("headers") or {}),
                        "body": r.get("body") or ""},
            "response": {"status": int(resp.status or 0),
                         "headers": dict(resp.headers or {}),
                         "body": body[:4000], "size": len(body),
                         "redirect_chain": [list(h) for h in (resp.redirect_chain or [])]}}'''
new = '''def _exec_http(r, engine, Endpoint, Parameter, ParamLocation, RequestMutation):
    import re as _re
    u = urllib.parse.urlsplit(r["url"])
    q = urllib.parse.parse_qsl(u.query or "", keep_blank_values=True)
    body = r.get("body") or ""
    # WebForms real-form replay: hidden fields are refreshed from a LIVE GET
    # (a stale __VIEWSTATE is rejected silently — live-measured on testaspnet)
    if r.get("label") == "stored_resubmit" and (r.get("method") or "GET").upper() == "POST":
        page = engine.send(_mk_probe_mutation(r, Endpoint, Parameter, ParamLocation,
                                              RequestMutation, method="GET", body=""))
        html = (page.body or "") if page else ""
        fresh = []
        for m0 in _re.finditer(r"<input[^>]*type=[\\"']hidden[\\"'][^>]*>", html or "", _re.I):
            tag = m0.group(0)
            n = _re.search(r"name=[\\"']([^\\"]+)[\\"']", tag)
            v = _re.search(r"value=[\\"']([^\\"]*)[\\"']", tag)
            if n:
                name = n.group(1)
                val = (v.group(1) if v else "")
                fresh.append(f"{urllib.parse.quote_plus(name)}="
                             f"{urllib.parse.quote_plus(val)}")
        m0 = _re.search(r"<input[^>]*name=[\\"']([^\\"]*(?:btn|send|submit)[^\\"]*)[\\"'][^>]*value=[\\"']([^\\"]*)[\\"']", html or "", _re.I)
        if m0 and not any(m0.group(1) == p.split("=", 1)[0] for p in body.split("&") if "=" in p):
            fresh.append(f"{urllib.parse.quote_plus(m0.group(1))}="
                         f"{urllib.parse.quote_plus(m0.group(2))}")
        if fresh:
            body = "&".join(fresh + [body]) if body else "&".join(fresh)
    m = _mk_probe_mutation(r, Endpoint, Parameter, ParamLocation, RequestMutation,
                           body=body)
    resp = engine.send(m)
    rbody = resp.body or ""
    return {"request": {"method": (r.get("method") or "GET").upper(),
                        "url": r["url"], "headers": dict(r.get("headers") or {}),
                        "body": body},
            "response": {"status": int(resp.status or 0),
                         "headers": dict(resp.headers or {}),
                         "body": rbody[:4000], "size": len(rbody),
                         "redirect_chain": [list(h) for h in (resp.redirect_chain or [])]}


def _mk_probe_mutation(r, Endpoint, Parameter, ParamLocation, RequestMutation,
                       method=None, body=None):
    u = urllib.parse.urlsplit(r["url"])
    q = urllib.parse.parse_qsl(u.query or "", keep_blank_values=True)
    ep = Endpoint(url=urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, "", "")),
                  method=(method or r.get("method") or "GET").upper(),
                  parameters=[Parameter(n, ParamLocation.QUERY, v) for n, v in q],
                  headers=dict(r.get("headers") or {}))
    return RequestMutation(endpoint=ep, method=(method or r.get("method") or "GET").upper(),
                           body_override=(body if body is not None else (r.get("body") or "")),
                           extra_headers=dict(r.get("headers") or {}))'''
assert old in src
src = src.replace(old, new)

open(P, "w").write(src)
ast.parse(src)
print("patch 3 applied; impact.py parses")

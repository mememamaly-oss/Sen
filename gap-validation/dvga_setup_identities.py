#!/usr/bin/env python3
"""DVGA live campaign setup: register the second identity, mint fresh JWTs,
create PRIVATE marker pastes for both identities (the BOLA victim objects),
and write the authz accounts JSON (token mode — V411)."""
import json, urllib.request, urllib.error, sys

URL = "http://127.0.0.1:5013/graphql"
OUT = "/home/z/my-project/gap-validation/dvga_authz_accounts.json"

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

pa = private_paste(ta, "sentinel-private-a", "PRIVATE-MARKER-41A-CONTENT")
pb = private_paste(tb, "sentinel-private-b", "PRIVATE-MARKER-41B-CONTENT")
print("victim pastes: 41a id=%s, 41b id=%s" % (pa, pb))

# 4. own-object ids for field-authz probes (the users' own ids)
me_a = must(gql('{ me(token: "%s") { id username } }' % ta), "me-a")["me"]
me_b = must(gql('{ me(token: "%s") { id username } }' % tb), "me-b")["me"]
print("users:", me_a, me_b)

accounts = {
    "login_url": "http://127.0.0.1:5013/graphql",
    "token_validate_url": "http://127.0.0.1:5013/graphql",
    "accounts": [
        {"name": "sentinel41a", "role": "user", "username": "sentinel41a",
         "token": ta, "marker": "PRIVATE-MARKER-41A-CONTENT", "object_id": str(pa)},
        {"name": "sentinel41b", "role": "user", "username": "sentinel41b",
         "token": tb, "marker": "PRIVATE-MARKER-41B-CONTENT", "object_id": str(pb)},
    ],
}
json.dump(accounts, open(OUT, "w"), indent=1)
print("authz accounts written:", OUT)

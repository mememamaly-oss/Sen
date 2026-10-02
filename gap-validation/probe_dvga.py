#!/usr/bin/env python3
"""Manual feasibility probes against local DVGA (authorized training target).
Doctrine: manual verification BEFORE pointing the scanner. Every probe is
non-destructive (no shell metacharacters, no destructive mutations)."""
import json, urllib.request, sys

URL = "http://127.0.0.1:5013/graphql"

def gql(query, variables=None, token=None):
    body = {"query": query}
    if variables is not None:
        body["variables"] = variables
    req = urllib.request.Request(URL, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode()[:500]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:500]

print("=== 1. introspection (default mode) ===")
s, b = gql("{__schema{queryType{name} mutationType{name}}}")
print(s, b[:200])

print("\n=== 2. anonymous sensitive query: users ===")
s, b = gql("{ users { id username email password } }")
print(s, b[:300])

print("\n=== 3. SQLi probe: pastes(filter:) ===")
s, b = gql('{ pastes(filter: "\'") { id title } }')
print(s, b[:300])

print("\n=== 4. command exec probe: systemDebug (SAFE marker only) ===")
s, b = gql('{ systemDebug(arg: "sentinelprobe") }')
print(s, b[:300])

print("\n=== 5. BOLA: paste by id ===")
s, b = gql('{ paste(id: 1) { id title content } }')
print(s, b[:250])

print("\n=== 6. createUser + login (mutation feasibility) ===")
s, b = gql('mutation { createUser(userData: {username: "sentinel41a", email: "a@t.local", password: "test1234"}) { user { id username } } }')
print(s, b[:250])
s, b = gql('mutation { login(username: "sentinel41a", password: "test1234") { accessToken } }')
print(s, b[:300])
tok = ""
try:
    tok = json.loads(b if isinstance(b, str) else "{}").get("data", {}).get("login", {}).get("accessToken", "")
except Exception:
    pass
print("TOKEN:", (tok[:40] + "...") if tok else "NONE")

if tok:
    print("\n=== 7. authenticated users query (JWT) — field-level authz ===")
    s, b = gql("{ users { id username password email } }", token=tok)
    print(s, b[:300])
    print("\n=== 8. systemUpdate authenticated ===")
    s, b = gql("{ systemUpdate }", token=tok)
    print(s, b[:200])

print("\n=== 9. anonymous mutation: createPaste ===")
s, b = gql('mutation { createPaste(title: "sentinel-probe", content: "probe content", public: true) { paste { id title } } }')
print(s, b[:250])

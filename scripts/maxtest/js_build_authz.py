#!/usr/bin/env python3
"""maxtest — build Juice Shop authz_accounts.json (token-mode identities).

Reads live-targets/juice_tokens_v41.json ({email: {"token": ...}}), decodes
each JWT payload locally (no server round-trip: whoami is cookie-only in
Juice Shop 20.2.0 — MAX-01 finding), and emits a 3-account token-mode authz
config (admin + two regular users) for the cross-account matrix.
Authorized local target: OWASP Juice Shop 20.2.0 (localhost).
"""
import base64
import json
import sys

SRC = "/home/z/my-project/live-targets/juice_tokens_v41.json"
DST = "/home/z/my-project/live-targets/juice_authz_maxtest.json"


def jwt_payload(token: str) -> dict:
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def main() -> int:
    tokens = json.load(open(SRC))
    accounts = []
    plan = [
        ("admin@juice-sh.op", "js-admin", "admin"),
        ("sentinel41e@juice-sh.op", "js-user-e", "user"),
        ("sentinel41f@juice-sh.op", "js-user-f", "user"),
    ]
    for email, name, role in plan:
        if email not in tokens or not tokens[email].get("token"):
            print(f"[authz] MISSING token for {email}")
            return 1
        tok = tokens[email]["token"]
        try:
            data = jwt_payload(tok).get("data", {})
            uid = str(data.get("id", ""))
            marker = data.get("email", email)
            print(f"[authz] {name}: id={uid} email={marker} role={data.get('role')}")
            if not uid:
                print(f"[authz] {name}: no id in JWT — aborting, no fake config")
                return 1
        except Exception as e:
            print(f"[authz] {name}: JWT decode FAILED ({e}) — aborting, no fake config")
            return 1
        accounts.append({
            "name": name, "role": role, "username": email.split("@")[0],
            "token": tok, "auth_scheme": "Bearer",
            "marker": marker, "object_id": uid,
        })
    cfg = {
        "login_url": "/rest/user/login",
        "token_validate_url": "/rest/basket/1",
        "accounts": accounts,
    }
    json.dump(cfg, open(DST, "w"), indent=1)
    print(f"[authz] wrote {DST} ({len(accounts)} token-mode accounts)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

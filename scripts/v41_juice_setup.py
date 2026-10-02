#!/usr/bin/env python3
"""SENTINEL v4.1 — Juice Shop live campaign setup.
Registers authz test users, logs in all identities, saves JWT tokens,
and builds the operator OpenAPI spec (19 REST paths) for the deep scan.
Authorized local target: OWASP Juice Shop 20.2.0 (localhost:3000).
"""
import json
import urllib.request

BASE = "http://localhost:3000"
OUT_TOKENS = "/home/z/my-project/live-targets/juice_tokens_v41.json"
OUT_SPEC = "/home/z/my-project/live-targets/juice_surface_openapi_v41.json"


def req(method, path, body=None, token=None):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
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


def main():
    identities = {}

    # 1. Register two fresh regular users (authz matrix).
    for user in ("sentinel41e", "sentinel41f"):
        body = {
            "email": user + "@juice-sh.op",
            "password": "test1234",
            "passwordRepeat": "test1234",
            "securityQuestion": {
                "id": 2,
                "question": "Mother's maiden name?",
                "answer": "smith",
            },
        }
        code, resp = req("POST", "/api/Users", body)
        print(f"[register] {user}: HTTP {code} "
              f"{('OK id=' + str(resp.get('id'))) if code in (200, 201) else str(resp)[:120]}")

    # 2. Log in all three identities and capture JWTs (+ user ids).
    for user, pw in (("admin@juice-sh.op", "admin123"),
                     ("sentinel41e@juice-sh.op", "test1234"),
                     ("sentinel41f@juice-sh.op", "test1234")):
        code, resp = req("POST", "/rest/user/login",
                         {"email": user, "password": pw})
        tok = resp.get("authentication", {}).get("token", "")
        adata = resp.get("authentication", {}).get("data", {}) or {}
        email = adata.get("email", "")
        print(f"[login] {user}: HTTP {code} "
              f"{'JWT len=' + str(len(tok)) + ' as ' + email + ' id=' + str(adata.get('id')) if tok else 'FAILED'}")
        identities[user] = {"token": tok, "id": adata.get("id")}

    with open(OUT_TOKENS, "w") as f:
        json.dump(identities, f, indent=1)
    print(f"[tokens] saved -> {OUT_TOKENS}")

    # 3. Operator OpenAPI spec (19 REST paths, parameters declared — the
    #    operator surface the v4.0.0 campaign was authorized to scan; params
    #    feed param-intel: the q search param drives oracle-verified SQLi
    #    probes, id path params register data objects for BOLA probing).
    def _p(name, where="query", typ="string", required=False):
        return {"name": name, "in": where, "required": required,
                "schema": {"type": typ}}

    paths = {
        "/rest/products/search": {
            "get": {"parameters": [_p("q", required=True)],
                    "responses": {"200": {"description": "OK"}}}},
        "/rest/product/{id}": {
            "get": {"parameters": [_p("id", "path", "integer", True)],
                    "responses": {"200": {"description": "OK"}}}},
        "/rest/products/{id}/reviews": {
            "get": {"parameters": [_p("id", "path", "string", True)],
                    "responses": {"200": {"description": "OK"}}},
            "post": {"responses": {"200": {"description": "OK"}}}},
        "/api/Users": {"post": {"responses": {"200": {"description": "OK"}}}},
        "/rest/user/login": {"post": {"responses": {"200": {"description": "OK"}}}},
        "/rest/user/whoami": {"get": {"responses": {"200": {"description": "OK"}}}},
        "/rest/basket/{id}": {
            "get": {"parameters": [_p("id", "path", "integer", True)],
                    "responses": {"200": {"description": "OK"}}}},
        "/api/BasketItems": {"post": {"responses": {"200": {"description": "OK"}}}},
        "/api/BasketItems/{id}": {
            "delete": {"parameters": [_p("id", "path", "integer", True)],
                       "responses": {"200": {"description": "OK"}}}},
        "/rest/basket/{id}/checkout": {
            "post": {"parameters": [_p("id", "path", "integer", True)],
                     "responses": {"200": {"description": "OK"}}}},
        "/rest/user/change-password": {"post": {"responses": {"200": {"description": "OK"}}}},
        "/rest/user/reset-password": {"post": {"responses": {"200": {"description": "OK"}}}},
        "/api/SecurityQuestions": {"get": {"responses": {"200": {"description": "OK"}}}},
        "/api/SecurityQuestion/{id}": {
            "get": {"parameters": [_p("id", "path", "integer", True)],
                    "responses": {"200": {"description": "OK"}}}},
        "/api/SecurityAnswers": {"post": {"responses": {"200": {"description": "OK"}}}},
        "/rest/continue-code": {"get": {"responses": {"200": {"description": "OK"}}}},
        "/rest/repeat-captcha": {"get": {"responses": {"200": {"description": "OK"}}}},
        "/rest/saveLoginIp": {"get": {"responses": {"200": {"description": "OK"}}}},
        "/redirect": {
            "get": {"parameters": [_p("to", required=True)],
                    "responses": {"200": {"description": "OK"}}}},
    }
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Juice Shop operator surface (authorized scope)",
                 "version": "20.2.0-sentinel-v41"},
        "servers": [{"url": BASE}],
        "paths": paths,
    }
    with open(OUT_SPEC, "w") as f:
        json.dump(spec, f, indent=1)
    print(f"[spec] {len(paths)} paths (params declared) -> {OUT_SPEC}")

    # 4. Sanity: token-gated request as admin (whoami).
    code, resp = req("GET", "/rest/user/whoami",
                     token=identities["admin@juice-sh.op"]["token"])
    print(f"[whoami admin] HTTP {code} {str(resp)[:100]}")


if __name__ == "__main__":
    main()

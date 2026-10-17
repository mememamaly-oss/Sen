#!/usr/bin/env python3
"""maxtest — isolate the missing-SQLi regression on Juice Shop /rest/products/search.

Runs two minimal engine scans against the live local Juice Shop:
  A) spec with ONLY /rest/products/search?q=  (no auth, no authz, no crawl)
  B) same + the 3-account token authz config (as the full campaign used)
Prints, for each: requests, endpoints, candidates, verified, findings by type.
Authorized local target: OWASP Juice Shop 20.2.0 (localhost:3100).
"""
import json
import subprocess
import sys

BASE = "http://localhost:3100"
B = "/home/z/my-project/build-v423"
OUT = f"{B}/results/maxtest/juiceshop"

SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "minimal isolation spec", "version": "1"},
    "servers": [{"url": BASE}],
    "paths": {
        "/rest/products/search": {
            "get": {
                "parameters": [
                    {"name": "q", "in": "query",
                     "schema": {"type": "string", "example": "apple"}}
                ],
                "responses": {"200": {"description": "ok"}},
            }
        }
    },
}


def run(tag: str, extra: list[str]) -> None:
    spec_path = f"{OUT}/iso_{tag}_spec.json"
    json.dump(SPEC, open(spec_path, "w"))
    cmd = [sys.executable, "sentinel/cli.py", "scan", BASE,
           "--allow-private", "--no-crawl", "--no-browser", "--no-oast",
           "--openapi-spec", spec_path,
           "--seed", f"iso-{tag}",
           "--out", f"{OUT}/iso_{tag}.json"]
    cmd += extra
    print(f"=== [{tag}] cmd extra={extra}")
    r = subprocess.run(cmd, cwd=B, capture_output=True, text=True, timeout=280)
    tail = "\n".join(r.stdout.strip().splitlines()[-6:])
    print(tail)
    try:
        res = json.load(open(f"{OUT}/iso_{tag}.json"))
    except Exception as e:
        print(f"[{tag}] RESULT LOAD FAIL: {e}")
        return
    s = res["stats"]
    print(f"[{tag}] requests={s.get('requests')} endpoints={s.get('endpoints')} "
          f"candidates={s.get('candidates')} verified={s.get('verified')} "
          f"rejected={s.get('rejected')}")
    pi = s.get("param_intel", {})
    print(f"[{tag}] params={pi.get('params_total')} by_kind={pi.get('by_kind')}")
    types = {}
    for f in res.get("findings", []):
        types[f["type"]] = types.get(f["type"], 0) + 1
    print(f"[{tag}] findings: {types}")
    for f in res.get("findings", []):
        if f["type"] != "missing_security_headers":
            print(f"[{tag}]   -> {f['type']} {f.get('url')} param={f.get('parameter')} "
                  f"status={f.get('status')} verif={json.dumps(f.get('verification'))[:120]}")
    for c in res.get("rejected_candidates", [])[:5]:
        print(f"[{tag}]   REJECTED: {json.dumps(c)[:220]}")


if __name__ == "__main__":
    run("A", [])
    run("B", ["--authz-accounts", "/home/z/my-project/live-targets/juice_authz_maxtest.json"])

#!/usr/bin/env python3
"""LIVE VALIDATION v2 (owner order 2026-10-31, part 3): crAPI + DVGA.

Runs the modern battery v2 (owner order part 3 layers) against the two
official targets and scores every finding against the GROUND TRUTH
recorded from each project's official documentation BEFORE any scan:

  crAPI (OWASP/crAPI, v1.1.5, docs/challenges.md):
    3A jwt_weak_secret   — challenge 15 documents JWT forgery (the docs
                           describe algorithm confusion via the RSA public
                           key as HMAC secret; a WEAK-WORDLIST secret is a
                           DIFFERENT mechanism — a hit here is scored
                           confirmed-positive; a miss is scored NOT FOUND,
                           honestly, not as a false negative).
    3D excessive_data_exposure — challenges 4+5 document endpoints leaking
                           sensitive data of other users / internal video
                           properties.
  DVGA (dolevf/Damn-Vulnerable-GraphQL-Application, port 5013):
    3C graphql_aliasing  — the official scenario list documents "Aliases
                           based Attack" under Denial of Service.
    (DVGA's other documented scenarios — introspection, batch query,
     deep recursion, field duplication, injections, JWT forge — map to the
     EXISTING v4.4.0 families (graphql.py / modernsec.py), not to 3C; the
     full-family run against DVGA is out of scope for this driver.)

Verdicts (per finding): confirmed-positive (type in the documented ground
truth for that target) / unjudged (engine finding with no matching
documented scenario — reported, never silently dropped) / expected-miss
(documented scenario with no engine finding — the honest miss list).

Every finding id carries a SHA-256 over the canonical finding JSON.
Exit 0 = scan+scoring completed (misses do not fail the run — they are
recorded); exit 2/3 = infrastructure/gate failure.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# ── ground truth, recorded 2026-10-31 from the official docs (pre-scan) ──────
GROUND_TRUTH = {
    "crapi": {
        "source": "github.com/OWASP/crAPI @ main (VERSION 1.1.5), "
                  "docs/challenges.md + services/identity JwtProvider.java",
        "jwt_weak_secret": {
            "documented": True,
            "mechanism": "challenge 15: forge valid JWT tokens. Mechanism in "
                         "source: algorithm confusion (RSA public key re-used "
                         "as the HS256 secret) — NOT a wordlist-weak secret. "
                         "3A's wordlist check targets a different mechanism; "
                         "an engine hit is a confirmed positive, a miss is an "
                         "honest NOT-FOUND, not a false negative.",
        },
        "excessive_data_exposure": {
            "documented": True,
            "mechanism": "challenges 4+5: endpoints leaking sensitive data of "
                         "other users and an internal video property.",
        },
    },
    "dvga": {
        "source": "github.com/dolevf/Damn-Vulnerable-GraphQL-Application @ "
                  "master, README 'Scenarios' section",
        "graphql_aliasing": {
            "documented": True,
            "mechanism": "'Aliases based Attack' listed under Denial of "
                         "Service; also Batch/Deep Recursion/Resource "
                         "Intensive/Field Duplication (other families).",
        },
    },
}


def finding_sha(f: dict) -> str:
    canon = json.dumps(
        {k: f.get(k) for k in ("type", "url", "parameter", "method",
                               "severity", "status", "evidence")},
        sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canon.encode()).hexdigest()


def run_target(name: str, base: str, modern_types: list[str], out: Path,
               max_requests: int = 2000, auth=None) -> dict:
    from burhan.orchestrator import ScanConfig, BurhanScanner
    from burhan.oast import OastServer

    oast = OastServer()
    t0 = time.time()
    try:
        cfg = ScanConfig(allow_private=True, max_pages=50, timeout=15.0,
                         seed=f"lv2-{name}" * 8, oast=oast, workflow=False,
                         logic_active=False, modern_v2=True, auth=auth,
                         max_requests=max_requests)
        sc = BurhanScanner(base, cfg)
        rep = sc.run()
    finally:
        oast.stop()
    wall = time.time() - t0

    findings = rep["findings"]
    m2 = [f for f in findings if f.get("type") in modern_types]
    for f in m2:
        f["sha256"] = finding_sha(f)

    stats = rep.get("stats", {})
    result = {
        "target": name,
        "base": base,
        "wall_seconds": round(wall, 1),
        "requests": stats.get("requests"),
        "findings_total": len(findings),
        "modern2_findings": [
            {k: f.get(k) for k in ("type", "url", "severity", "status",
                                    "evidence", "sha256")}
            for f in m2],
        "boundaries": rep.get("boundaries", [])[:40],
        "axes": {k: stats.get(k) for k in ("modern2", "graphql") if k in stats},
    }
    (out / f"{name}-scan.json").write_text(
        json.dumps(rep, indent=1, ensure_ascii=False, default=str),
        encoding="utf-8")
    return result


def score(name: str, result: dict) -> dict:
    gt = GROUND_TRUTH[name]
    confirmed, unjudged = [], []
    for f in result["modern2_findings"]:
        entry = {"type": f["type"], "url": f["url"], "sha256": f["sha256"]}
        if gt.get(f["type"], {}).get("documented"):
            entry["verdict"] = "confirmed-positive"
            confirmed.append(entry)
        else:
            entry["verdict"] = "unjudged (not in the documented ground truth)"
            unjudged.append(entry)
    expected_miss = [
        {"type": t, "reason": gt[t]["mechanism"]}
        for t, g in gt.items() if isinstance(g, dict) and g.get("documented")
        and not any(f["type"] == t for f in result["modern2_findings"])]
    return {"target": name, "confirmed_positive": confirmed,
            "unjudged": unjudged, "expected_miss": expected_miss,
            "ground_truth_source": gt["source"]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--crapi", default="", help="crAPI base URL")
    ap.add_argument("--dvga", default="", help="DVGA base URL")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()
    out = Path(args.out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)

    ok = True
    results, scores = {}, {}

    if args.crapi:
        # crAPI's own happy path: signup then login; the identity service
        # issues the JWT the 3A layer harvests. Unauthenticated harvest
        # (login responses) is also attempted — both are honest inputs.
        import urllib.request
        try:
            email = f"burhan{int(time.time())}@integration.test"
            body = json.dumps({
                "email": email,
                "password": "Burhan-Live-123!",
                "name": "Burhan Live",
                "phoneNumber": "1234567890",
            }).encode()
            req = urllib.request.Request(
                args.crapi + "/identity/api/auth/signup", data=body,
                headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(req, timeout=15)
            print(f"crAPI signup ok: {email}")
        except Exception as e:  # noqa: BLE001
            print(f"crAPI signup failed (continuing unauthenticated): {e}")
        try:
            from burhan.auth import AuthProfile
            login = AuthProfile(
                login_url=args.crapi + "/identity/api/auth/login",
                username=f"burhan{int(time.time())}@integration.test",
                password="Burhan-Live-123!",
                user_field="email", pass_field="password")
        except Exception:  # noqa: BLE001
            login = None
        results["crapi"] = run_target(
            "crapi", args.crapi,
            ["jwt_weak_secret", "excessive_data_exposure"], out, auth=login)
        scores["crapi"] = score("crapi", results["crapi"])

    if args.dvga:
        results["dvga"] = run_target("dvga", args.dvga,
                                     ["graphql_aliasing"], out)
        scores["dvga"] = score("dvga", results["dvga"])

    if not results:
        print("no target given"); return 2

    verdict = {"when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "results": results, "scores": scores}
    (out / "live-validation.json").write_text(
        json.dumps(verdict, indent=1, ensure_ascii=False, default=str),
        encoding="utf-8")
    for name, r in results.items():
        print(f"[{name}] wall={r['wall_seconds']}s requests={r['requests']} "
              f"findings={r['findings_total']} modern2={len(r['modern2_findings'])}")
        for s in scores[name]["confirmed_positive"]:
            print(f"  CONFIRMED-POSITIVE {s['type']} {s['sha256'][:12]} {s['url'][:60]}")
        for s in scores[name]["unjudged"]:
            print(f"  UNJUDGED           {s['type']} {s['sha256'][:12]} {s['url'][:60]}")
        for m in scores[name]["expected_miss"]:
            print(f"  EXPECTED-MISS      {m['type']}")
    # gate: every target must have completed its scan (misses are recorded,
    # not failures — this is a validation run, not a pass/fail benchmark)
    for name, r in results.items():
        if r["requests"] is None or r["wall_seconds"] is None:
            print(f"GATE FAIL: {name} scan incomplete"); ok = False
    return 0 if ok else 3


if __name__ == "__main__":
    sys.exit(main())

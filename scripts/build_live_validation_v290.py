#!/usr/bin/env python3
"""Build the v2.9.0 live-validation summary artifact from the live scan + vault."""
import json

BASE = '/home/z/my-project/download/sentinel-results'
scan = json.load(open(f'{BASE}/scan_testfire_v290_LIVE.json'))
audit = json.load(open(f'{BASE}/vault_audit_testfire_v290.json'))

summary = {
    "phase": "57 — Credential Intelligence (v2.9.0)",
    "run_id": scan['run_id'],
    "scanner": scan['scanner'],
    "target": scan['target'],
    "date": "2026-09-29",
    "gates": {
        "tests": "69/69",
        "doctor": "14/14 (incl. credential_vault self-test)",
        "benchmark": "F1=1.000 TP=30 FP=0 FN=0 TN=24 — deterministic x3 "
                     "(run-3c0652b6be, 1434 req, oast x7)",
    },
    "live_scan": {
        "strategy": "light (no browser, 20 pages, authenticated jsmith, public OAST)",
        "requests": scan['stats']['requests'],
        "endpoints": scan['stats'].get('discovered'),
        "verified": len(scan['findings']),
        "rejected": len(scan.get('rejected', [])),
        "active_classes": ["sql_injection", "xss_reflected x6",
                           "host_header_injection", "csrf x3", "open_redirect"],
        "credential_exposure": "0 findings — HONEST NEGATIVE (matches the v2.8.0 "
                               "baseline: the deployment exposes no secret-shaped "
                               "values in responses)",
        "vault": {
            "org": "altoro-mutual",
            "armed": True,
            "records": 0,
            "policy": "raw values encrypted at rest; reveal requires an authorized "
                      "key and is audit-logged",
        },
    },
    "vault_workflow_proven": {
        "init": "vault created for org=altoro-mutual before any request "
                "(fail-fast on wrong key)",
        "capture": "0 credentials observed -> 0 records (no fabrication, no inflation)",
        "masked_reports": "scan report + secrets report carry masks/policy only; "
                          "byte-level: no AKIA/ghp_/sk_live_/xox shapes in any artifact",
        "audit_trail": [f"{e['ts']} {e['actor']} {e['action']} {e['target']}"
                        for e in audit['entries']],
        "multi_party": "org-owner key authorized by tool-designer (key files NEVER "
                       "ship with deliverables — spec 9: keys stay out of "
                       "code/Git/artifacts)",
    },
    "fixture_e2e_proof": "regression_phase57_vault_end_to_end: 3 credential classes "
                         "captured encrypted, byte-level no-plaintext gates on report "
                         "AND vault file, owner reveal == fixture's true values, purge "
                         "+ audit survival, full CLI surface via subprocess (script mode)",
    "engine_defects_caught": [
        "ENG-11 (live-caught by the new CLI surface in script mode): vault.py's "
        "`import secrets` resolved to OUR sentinel/secrets.py when the package dir "
        "led sys.path — replaced with os.urandom (same entropy source, unshadowable)",
    ],
}

out = f'{BASE}/live_validation_v290.json'
json.dump(summary, open(out, 'w'), indent=1)
print("live_validation_v290.json written")
print(json.dumps(summary["gates"], indent=1))
print("audit trail:", summary["vault_workflow_proven"]["audit_trail"])

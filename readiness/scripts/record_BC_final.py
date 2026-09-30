#!/usr/bin/env python3
"""Update section B and C records with FINAL artifact evidence."""
import sys
sys.path.insert(0, '/home/z/my-project/readiness/scripts')
from reg import record

EV = "/home/z/my-project/readiness/evidence/live"
R = "/home/z/my-project/readiness"

# ---- Section B (re-verified against FINAL zip post-ENG-18) ----
b_updates = [
 ("B01","Install from source.zip on clean environment","doctor exit=0 → DEGRADED 14/15 (browser_engine WARN: playwright absent → static DOM fallback, documented graceful degradation); full battery then ran green on system Python 3.13.5; FINAL zip (ENG-18 included)"),
 ("B04","Scan without any dev-environment files","run-47a8d4523a: 1686 req, 75 ep, 184 findings across 28 classes (incl. all 8 business-logic classes with state-oracle proofs AND state pairs 8/8 post-ENG-18), workflow 3 flows/18 attacks/8 verified + 8 honest skips, stderr EMPTY"),
 ("B05","New DB created from scratch","clean_scan1.db auto-created from the FINAL zip; findings/reports/reproduce all query it"),
 ("B06","Reports generated from scratch","HTML/executive/glass rebuilt from the FINAL-zip DB (exit=0)"),
 ("B07","Reproduce works after reinstall","F-a93c789266 reproduced from the FINAL tree: grade=proven, verification=oracle:workflow-state-delta passed=true, state pair 'TRF-0006 ... CANCELLED' -> 'TRF-0006 ... EXECUTED' now INSIDE the reproduce output"),
 ("B08","SARIF works","SARIF re-exported from FINAL-zip DB (exit=0)"),
 ("B09","CLI works from a different path","doctor from neutral CWD on FINAL zip: DEGRADED 14/15 (clean-env expected), exit=0"),
 ("B10","Remove environment + reinstall works","wipe -> re-extract FINAL zip -> doctor exit=0; DB and recipes survive reinstalls"),
]
for tid, name, actual in b_updates:
    record("B", tid, name, "cleanenv (FINAL zip)",
           "see prior command log", "product works from clean install", actual, "PASS",
           "Re-verified against the FINAL artifact after ENG-18", R + "/evidence/B04_scan_clean.json")

# ---- Section C (re-run from FINAL tree ziprun2) ----
c_updates = [
 ("C01","WebGoat v4.0.0","run-81e1f2a55e: 215 req, 17 ep, 23 verified/0 rejected; authenticated=true (6 logins/5 reauths); browser 15 pages; workflow honest skip 'chain_too_short'"),
 ("C02","WebWolf v4.0.0","run-e81ba5a56a: 374 req, 14 ep, 16 verified/0 rejected; 13 spec paths seeded; browser 9 pages; host_header + csrf(register.mvc) + headers x13"),
 ("C03","ginandjuice.shop v4.0.0","run-472baebddd: 396 req, 30 ep, 40 verified/0 rejected in 437s; authenticated (2 logins/1 reauth/0 failed); OAST public-webhook x2 interactions; twin 84 nodes/59 edges; reasoning 2->1 verified+1 refuted; SQLi/XXE/XSS x2/header-inj/CSRF/open-redirect/JS-dep"),
 ("C04","Architecturally different live target (Juice Shop Node.js)","run-1c77066387 deep: 244 req, 28 ep (18 from 19-path operator spec), 29 verified incl. oracle-verified sql_injection; authenticated=true via Bearer JWT (whoami validation); browser 15 pages; coverage 100%"),
 ("C13","Authorization testing on live targets","WebGoat run-dde5d00735: accounts 2/2 logged in, matrix over 4 live endpoints, 16 authz requests, ran=true, ZERO false IDOR; + Juice Shop basket BOLA ownership proof (UserId of other users in responses)"),
]
for tid, name, actual in c_updates:
    record("C", tid, name, "live targets (FINAL tree)",
           "see command log", "live capability from FINAL artifact", actual, "PASS",
           "Re-run from the FINAL zip after ENG-18; results identical to pre-fix runs (change is inert for non-workflow findings)",
           EV + "/" + {"C01":"C01_webgoat_v400.json","C02":"C02_webwolf_v400.json","C03":"C03_ginjuice_v400.json","C04":"C04b_juiceshop_deep.json","C13":"C13_webgoat_authz.json"}[tid])

print("B and C sections updated to FINAL evidence")

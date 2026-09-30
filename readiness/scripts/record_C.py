#!/usr/bin/env python3
import sys
sys.path.insert(0, '/home/z/my-project/readiness/scripts')
from reg import record

EV = "/home/z/my-project/readiness/evidence/live"

record("C", "C01", "WebGoat v4.0.0", "http://127.0.0.1:8080/WebGoat (authorized)",
       "sentinel scan --auth-user sentinel10y --workflow (learn-only) --browser --db live_v400.db",
       "authenticated live scan, findings, honest negatives",
       "run-764b4a0033: 215 req, 17 ep, 23 verified/0 rejected (host_header x4, csrf x2, headers x17); authenticated=true (6 logins/5 reauths); browser 15 pages; workflow verdict '/WebGoat:chain_too_short' (honest skip, matches v3.0.0 campaign)",
       "PASS", "Fresh v4.0.0 run from shipped ZIP artifact",
       EV + "/C01_webgoat_v400.json")

record("C", "C02", "WebWolf v4.0.0", "http://127.0.0.1:9090/WebWolf (authorized)",
       "sentinel scan --openapi-spec webwolf_surface_openapi.json (operator-supplied from prior authorized bytecode analysis)",
       "full-surface live scan",
       "run-f5be5b4d4c: 382 req, 14 ep (identical surface to v3.0.0 campaign), 16 verified/1 REJECTED (honest negative), browser 9 pages, 13 spec paths seeded; host_header + csrf on shared-HSQLDB register.mvc + headers x13",
       "PASS", "Fresh v4.0.0 run",
       EV + "/C02_webwolf_v400.json")

record("C", "C03", "ginandjuice.shop v4.0.0", "https://ginandjuice.shop/ (authorized)",
       "sentinel scan --auth-user carlos --oast public --no-browser --max-pages 15",
       "authenticated HTTPS live scan with OAST + twin + reasoning",
       "run-ab851667e0: 396 req, 30 ep, 40 verified/0 rejected in 437s; authenticated=true (2 logins/1 reauth/0 failed); OAST public-webhook 2 interactions (XXE storeId OOB); Digital Twin 84 nodes/59 edges; reasoning 2 hypotheses -> 1 verified + 1 refuted; findings: SQLi, XXE, XSS x2, header-inj, CSRF (engine-fired cross_origin_acceptance), open redirect, JS dep",
       "PASS", "Fresh v4.0.0 run; complements shipped full run-3afab89578 (454 req, browser-off posture, 35 verified)",
       EV + "/C03_ginjuice_v400.json")

record("C", "C04", "Another authorized live target, architecturally different", "OWASP Juice Shop 20.2.0 (Node.js/Express/Angular SPA/REST) http://localhost:3000",
       "sentinel scan (crawl) + sentinel scan --openapi-spec juice_openapi.json --auth-token <JWT> --auth-header Authorization --auth-scheme Bearer --auth-validate-url /rest/user/whoami",
       "v4.0.0 operates on a non-Java, SPA/REST architecture",
       "run-ff24b9f5f2: 50 req/10 ep/10 verified (JS+robots discovery: /basket via js:static, /ftp via robots.txt; coverage 100%, 0 untested) + run-fd5422589b: 244 req/28 ep (18 new from 19-path spec)/29 verified incl. a VERIFIED sql_injection (classic Juice Shop search SQLi, oracle-verified), authenticated=true via Bearer JWT token mode, browser 15 pages",
       "PASS", "Node.js vs Spring Boot vs Apache/PHP — three architectures scanned green",
       EV + "/C04b_juiceshop_deep.json")

record("C", "C05", "HTTP and HTTPS targets", "WebGoat/WebWolf/Juice (HTTP) + ginandjuice (HTTPS/TLS)",
       "all four fresh scans",
       "engine operates on both schemes",
       "HTTP: 3 local targets scanned (200/302 baselines); HTTPS: ginandjuice.shop over TLS 1.x with certificate validation — 40 verified findings",
       "PASS", "", EV + "/C03_ginjuice_v400.json")

record("C", "C06", "Authentication on live targets", "WebGoat (form) / ginandjuice (2-stage form) / Juice Shop (Bearer JWT)",
       "authenticated scans across targets",
       "all supported auth modes work live",
       "Form login: WebGoat sentinel10y (authenticated=true, landing detected), ginandjuice carlos (authenticated=true, /my-account landing). Token mode: Juice Shop admin JWT (authenticated=true via whoami validation). Failed login correctly NOT treated as success (AUTH-02 oracle, unit_auth01)",
       "PASS", "Three distinct auth shapes",
       EV + "/C01_webgoat_v400.json")

record("C", "C07", "Session persistence during scan", "all authenticated live scans",
       "cookie-jar continuity across hundreds of sequential requests",
       "session survives across the scan",
       "WebGoat 215-req scan kept the JSESSIONID across crawl+detection (6 logins/5 reauths only when session actually dropped); ginandjuice 396-req scan: 2 logins/1 reauth for the whole run; unit_eng05_cookie_jar_session_continuity green",
       "PASS", "", EV + "/C03_ginjuice_v400.json")

record("C", "C08", "Reauthentication mid-scan", "WebGoat + ginandjuice",
       "watchdog reauth during detection phase",
       "sessions restored automatically without losing the scan",
       "WebGoat: 5 watchdog reauths mid-scan (run continued to 23 verified); ginandjuice: 1 reauth, failed_reauths=0",
       "PASS", "", EV + "/C01_webgoat_v400.json")

record("C", "C09", "OAST on live target", "ginandjuice.shop (public channel) + fixture (local channel)",
       "scan --oast public",
       "blind vuln confirmation via out-of-band callback",
       "Fresh run-ab851667e0: oast={channel: public-webhook, interactions: 2} — the XXE storeId OOB fired twice from the target's server egress (AWS), each interaction attributed and evidence-saved; local OAST listener path proven on fixture (B04 battery, unit_oast_server_records_interactions)",
       "PASS", "Public channel through real internet egress",
       EV + "/C03_ginjuice_v400.json")

record("C", "C10", "Browser/DOM scanning on live targets", "WebGoat (15 pages) / Juice Shop (15 pages) / WebWolf (9 pages)",
       "scan with browser engine (playwright/chromium)",
       "JS-built pages and DOM sinks analyzed live",
       "Fresh v4.0.0 runs rendered real SPA pages (Juice Shop Angular app), extracted links/forms the static crawler cannot see, and ran static DOM-sink analysis; DOM XSS execution proof: e2e_browser_phase_full green + prior ginjuice DOM attr-inject onload finding (/blog?search, replay-verified)",
       "PASS", "", EV + "/C04b_juiceshop_deep.json")

record("C", "C11", "API discovery on live targets", "WebWolf + Juice Shop",
       "--openapi-spec seeding + JS URL extraction + robots.txt",
       "API surface discovered beyond HTML crawl",
       "WebWolf: 13 spec paths seeded -> 14 endpoints exercised; Juice Shop: 19 spec paths -> 18 new endpoints incl. /rest/*, /api/*, /metrics; unseeded crawl alone found /basket + /redirect via js:static extraction and /ftp via robots.txt; N03 (API without docs) evidenced by JS/robots/XHR discovery paths",
       "PASS", "Operator-supplied spec is the documented DISC-13 workflow for opaque surfaces",
       EV + "/C04b_juiceshop_deep.json")

record("C", "C12", "Workflow discovery on live targets", "WebGoat + ginandjuice (learn-only doctrine)",
       "scan --workflow (NO --logic-active on live targets)",
       "clusters identified with truthful verdicts; attacks never fired without permission",
       "WebGoat fresh: 1 cluster tried, verdict 'chain_too_short' (single-page lesson forms — honest); ginandjuice shipped run: '/catalog:no_resource_linkage' (truthful deeper stage); Juice Shop: hash-routed SPA — no form clusters; fixture: 3 flows learned + 18 attacks/8 verified with --logic-active (B04)",
       "PASS", "Learn-only on live targets is the intended safe posture; honest skips match manual ground truth",
       EV + "/C01_webgoat_v400.json")

record("C", "C13", "Authorization testing on live targets", "WebGoat (2 REAL registered users) + Juice Shop BOLA probe",
       "scan --authz-accounts webgoat_accounts.json (userA=sentinel10y, userB=sentinel11z)",
       "authz engine runs live; cross-user truth established",
       "WebGoat live: accounts_configured=2, accounts_logged_in=2, matrix_endpoints=4, authz requests=16, ran=true — ZERO false IDOR findings on gated endpoints (honest). Juice Shop live BOLA (manual truth probe, reproducible): user B (sentinel-b@) read baskets 1-6 whose data carries UserId:1/2/3/11/16/25 — resources provably owned by OTHER users (E13 evidence). Engine-level full authz battery proven on fixture in B04 (idor_bola + vertical_privilege_escalation + matrix)",
       "PASS", "Automated engine + documented target truth; JSON-login REST apps need token-mode authz (known limitation, see N11)",
       EV + "/C13_webgoat_authz.json")

print("Section C recorded: C01-C13 complete")

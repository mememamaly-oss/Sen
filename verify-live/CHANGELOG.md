# SENTINEL v2.7.0 — "Detector Expansion Release"

Deterministic DAST platform. Zero external dependencies (pure Python 3 stdlib).
Every finding is verification-gated: a candidate is NEVER a finding until an
independent replay confirms it.

## What v2.7.0 adds (Phase 55 — five new verified vulnerability classes)

1. **SSTI — Server-Side Template Injection (DETECT-15, CRITICAL)**
   Template-syntax arithmetic battery across the four dominant families
   ({{ }} Jinja2/Twig, ${ } FreeMarker/EL, <%= %> ERB, #{ } Ruby/Thymeleaf).
   Oracle: the COMPUTED result (49) appears in the response while the literal
   expression does NOT — raw echo is reflection, never evaluation. VR-12
   re-tests the winning syntax family with fresh operands ({{12*11}} -> 132):
   ambient page numbers cannot reproduce a fresh computation.

2. **CSRF — cross-origin acceptance (DETECT-16, MEDIUM)**
   State-changing POST forms carrying NO anti-CSRF token are replayed with a
   hostile Origin+Referer. The oracle is acceptance: the cross-origin request
   must succeed like the same-origin baseline (same status, similar body).
   Honesty gates: token-bearing forms skipped outright, read-only surfaces
   (stock/search/login) skipped, 401/403-gated baselines skipped (no honest
   anonymous oracle). VR-13 re-tests with a FRESH hostile origin.

3. **NoSQL operator injection (DETECT-17, CRITICAL)**
   JSON-body endpoints where a $-operator object ({"$ne": "x"}) flips a
   REJECTED baseline into an ACCEPTANCE — the Mongo auth-bypass shape. Full
   JSON bodies ride engine body_override. VR-14 re-tests with a DIFFERENT
   operator ($gt after $ne).

4. **JWT unsigned-issuance analysis (DETECT-18, MEDIUM)**
   Auth-shaped endpoints are replayed benignly; responses (body + Set-Cookie)
   are mined for JWTs. An issued token with alg=none and an EMPTY signature is
   a defect by RFC 8725 §3.1. Signed issuance (HS256/RS256) is normal and stays
   silent. VR-15 = fresh replay must issue another none-token.

5. **Host header injection (DETECT-19, MEDIUM)**
   A canary Host header on GET HTML endpoints; reflection into the response
   (Host-built absolute links — the reset-poisoning class) is the oracle.
   VR-16 re-tests with a FRESH canary host.

## Engine defect caught live by the new detectors

- **ENG-10** (found by the NoSQL detector during Phase 55 test development):
  requests using body_override went out with the WRONG Content-Type — a
  full-JSON probe on a JSON-location endpoint was sent as
  x-www-form-urlencoded and every JSON API rejected it with 400 before the
  payload was ever parsed. Fix in http_engine._render: a body_override that
  parses as JSON on a JSON-location endpoint now gets application/json.

## Ground truth v7 + quality gates

- Fixture v7: five new vulnerable/safe pairs (real mechanisms: template
  evaluation, operator-object matching, unsigned-token issuance, Host-derived
  link building) — /vuln/ssti, /vuln/csrf-action, /vuln/nosql-login,
  /vuln/jwt-login, /vuln/hostbuild + hardened twins.
- Ground truth v7: 27 TP / 21 TN (48 rows).
- Tests: 59 -> 61 (unit_phase55_detectors_and_gates,
  regression_phase55_five_classes_end_to_end). The browser E2E budget was
  recalibrated (fixture v7 grew the crawl surface; the old 30-page budget
  starved dom-write out of the crawl — caught by that very gate).
- Benchmark: F1 = 1.000, TP=27 FP=0 FN=0 TN=21, deterministic x3
  (run-3c0652b6be, 1253 requests, oast x7).
- Doctor: 12/12 — now 14 active detectors.

## Live validation (authorized targets)

- Manual feasibility probes FIRST (phase doctrine): ginandjuice.shop rejects
  canary Hosts with 421 Misdirected Request, reflects SSTI expressions
  literally with zero computation, its subscribe form requires a CSRF token,
  and it issues no JWTs — all five new classes are honest negatives on the
  real target, and the production scan proved it:
  **0 new-class findings, 0 false positives, 0 rejected** across 430 requests
  with every prior active intact (SQLi /catalog?category, XXE storeId
  OOB-verified again from 18.200.201.133 via the public webhook, XSS
  category+searchTerm, header injection, open redirect).
- Cross-target probes: demo.testfire.net (HTTP), testasp.vulnweb.com,
  testaspnet.vulnweb.com — honest negatives on all five classes, matching
  each platform's real posture.

## Field totals after v2.7.0

4 platforms | 22 verified actives | 0 false positives | **16 vulnerability classes**
(11 prior + ssti + csrf + nosql_injection + jwt_security + host_header_injection,
all five proven end-to-end on the fixture and honest-negative-proven live)

# SENTINEL v2.6.0 — "Stealth + Ops Release"

Deterministic DAST platform. Zero external dependencies (pure Python 3 stdlib).
Every finding is verification-gated: a candidate is NEVER a finding until an
independent replay confirms it.

## What v2.6.0 adds (stealth + ops + intelligence axes)

1. **Passive WAF + technology fingerprinting (`sentinel/fingerprint.py`)**
   Two observers that ride every response the scan already produces — zero
   extra requests. WafFingerprinter matches named WAF signatures (Cloudflare,
   AWS WAF, ModSecurity, F5, Imperva, Sucuri, Akamai, Fastly) from headers,
   cookies and block-page bodies, with the evidence line each conclusion came
   from. TechFingerprinter maps Server/X-Powered-By/X-AspNet-Version headers,
   session-cookie platforms (JSESSIONID->Java, PHPSESSID->PHP, ...), DOM markers
   (ng-app, __VIEWSTATE, wp-content) and meta generators. Honesty contract: no
   signature hits -> waf null ("no WAF seen" is NOT a claim the passive channel
   can make); x-amzn-requestid is deliberately NOT aws-waf (infra header —
   false-attribution guard). stats.fingerprint lands in every report.

2. **DETECT-14 context-adaptive XSS battery (`sentinel/detect.py`)**
   ONE benign known-tag probe per mutable param classifies the input context:
   tag-filtered (400/403 on a plain <b>) -> attribute-injection battery (no '<'
   at all); ng-app in the page -> + AngularJS {{expression}} vector; plain ->
   classic full-tag + slash-free battery. LIVE-PROVEN on ginandjuice.shop:
   the ng vector found a REAL Angular expression reflection on /catalog
   (param searchTerm) that every previous version missed — verified via
   re-test:fresh-ng-expression. (The /blog?search attr-inject vector that
   inspired the "filtered" arm was already live-proven in v2.2.0.)

3. **ENG-09 rate-limit resilience (`sentinel/http_engine.py`)**
   429/503 answers are a WAF/CDN saying "slow down", not an app response.
   Deterministic exponential backoff (0.4 * 2^n, cap 8s, max 3 retries),
   Retry-After honored when present, the request replayed IDENTICALLY
   (determinism preserved), and the final 429 returned HONESTLY if the limiter
   never relents (never a fabricated error). stats.rate_limit carries
   limited/retries/recovered for audit.

4. **AUTH-05 static-token authentication (`sentinel/auth.py`)**
   Bearer JWTs, API keys, custom headers (X-Auth-Token). "Login" = VALIDATION:
   fetch the validation URL WITH the header and require a door that is closed
   without it (401/403 rejected, login-gate bounce detected, optional success
   marker). The token rides engine.default_headers — every request carries it
   with zero per-phase wiring. No self-healing by design (a static token cannot
   be re-minted): mid-scan 401/403 are COUNTED honestly (stats.auth.rejections)
   instead of silently proceeding anonymous. CLI: --auth-token / --auth-header /
   --auth-scheme / --auth-validate-url. LIVE-PROVEN against ginandjuice.shop
   (header rides a real TLS target, scan completes, honest counters).

5. **DISC-13 OpenAPI/Swagger seeding (`sentinel/discovery.py`)**
   The target's own machine-readable surface map: auto-probe /openapi.json,
   /swagger.json, /swagger/v1/swagger.json, /v2/api-docs (or an explicit
   --openapi-spec file/URL) — unlinked admin/legacy/API paths invisible to any
   crawler are declared there with parameters (query, path, JSON body fields).
   Seeded endpoints ride the SAME dedup + scope gates as crawl results. Honest
   negative recorded (stats.openapi) when no document exists. LIVE on
   ginandjuice.shop: no document — honest null.

6. **OP-02 SARIF 2.1.0 export (`sentinel/report.py`)**
   The industry interchange format (GitHub code scanning, VS Code, DefectDojo).
   Stable rule registry (a finding type always maps to the same SEN-XXX ruleId
   so runs diff cleanly), severity->level mapping, verification-gated (rejected
   candidates NEVER become results), evidence chain + verification method as
   properties, partialFingerprints for result tracking. CLI: report --format
   sarif; REST: GET /api/runs/<id>/sarif. LIVE: the full ginandjuice.shop
   production run exports 34 results across 7 rules.

7. **Test-runner fast filter (ops)**
   SENTINEL_TEST_FILTER=prefix1,prefix2 executes only matching cases (cases run
   at import in this runner; a "filtered" CLI run used to pay the full suite
   runtime anyway). Release gate still runs the full suite.

## Live-caught defects fixed this phase

- **BrowserEngine API contract**: the orchestrator passed extra_headers
  (session transport headers for the browser context) before BrowserEngine
  learned to accept it — 9 tests red at session start. Fixed + the browser
  context UA is now version-derived (was stale hardcoded "Sentinel/2.2").
- **Set-Cookie attribute leak**: attribute names (Path=/, SameSite=Lax,
  Expires=...) leaked into the cookie-platform list as if they were cookie
  names (first live fingerprint run on ginandjuice.shop). Deterministic
  attribute filter + permanent regression assertion.
- **aws-waf false attribution**: x-amzn-requestid (API Gateway/ALB infra
  header) was a WAF signature — would claim "AWS WAF" for plain infrastructure.
  Removed; only x-amzn-waf-action counts.

## Gates (all green)

- Tests: **59/59** (52 -> 59: 6 unit + 1 composition regression)
- Doctor: **12/12** (9 detectors, live public OAST channel)
- Benchmark: local-fixture-v6 **F1=1.000** (TP=22 FP=0 FN=0 TN=16),
  run-3c0652b6be **x3 IDENTICAL** (deterministic)
- LIVE production scan ginandjuice.shop (--oast public --no-browser, 389 req,
  452s): **45 verified, 0 rejected, 0 false positives** — all 5 prior
  non-browser actives intact + **NEW ng-expression XSS on /catalog?searchTerm**
  (DETECT-14) + XXE storeId OOB-verified again from 54.170.155.72 via the
  public webhook channel. Real-target totals: **4 platforms, 22 verified
  actives, 0 false positives** across 11 vulnerability classes.

# SENTINEL v2.5.0 — "Hardening Release" Release

Deterministic DAST platform. Zero external dependencies (pure Python 3 stdlib).
Every finding is verification-gated: a candidate is NEVER a finding until an
independent replay confirms it.

## What v2.5.0 adds (detector hardening: SSRF / blind command injection / CORS)

1. **SsrfDetector — DETECT-11 (`sentinel/detect.py`)**
   Server-side request forgery on URL-carrier params (name- or value-gated),
   confirmed OUT-OF-BAND over the OAST channel (the evidence pattern proven for
   blind XXE in v2.4.0): the probe points the param at the listener; a callback
   is server-side fetch proof. Deterministic probe budget (12); inert without an
   armed channel (response-only SSRF oracles are ambient noise — live-observed).
   Verification **VR-09**: fresh interaction id replay.

2. **CommandInjectionDetector — DETECT-12**
   Blind OS command injection: a 2-variant shell-separator battery (`;` and `&&`
   chaining `curl` to the listener) across mutable params (deterministic budget,
   24 params). A callback proves code left the app's shell. Verification
   **VR-11**: fresh interaction id + DIFFERENT syntax (`|` chaining) — execution
   must reproduce through an independent separator.

3. **CorsDetector — DETECT-13**
   One header-only probe per GET endpoint: arbitrary-Origin reflection in
   Access-Control-Allow-Origin combined with Access-Control-Allow-Credentials:
   true (the dangerous pair; ACAO:* without credentials is NOT reportable).
   Verification **VR-10**: the reflection must repeat on a FRESH origin value.

4. **ENG-08 self-callback guard (live-caught during this build)**
   The v2.5.0 SSRF detector immediately exposed a real trap on fixture
   /vuln/redirect.php: the engine follows SAME-HOST redirects (required for auth
   landings), so an open-redirect target bounces the probe URL back at the
   listener and the SCANNER ITSELF performs the fetch — a would-be SSRF false
   positive (callback UA = engine UA; hop present in redirect_chain). Both
   OAST-channel detectors and the XXE path now reject scanner-initiated
   callbacks; the engine UA is version-derived (also fixes the stale hardcoded
   "Sentinel/2.2" fingerprint). Permanent regression:
   regression_eng08_self_callback_guard (true fetch found, redirect twin silent).

5. **Risk model + registry**: command_injection=9, ssrf=7, cors_misconfig=6 in
   RISK_WEIGHTS; 9 active detectors (doctor detector_registry updated).

## Fixture v6 + ground truth v6

New surfaces with hardened twins: /vuln/fetch + /safe/fetch (blind server-side
fetch vs allowlist), /vuln/ping + /safe/ping (REAL shell=True interpolation vs
argv list), /vuln/cors + /safe/cors (arbitrary reflection + credentials vs fixed
origin). Ground truth 22 TP / 16 TN (was 19/13).

## Live validation (real authorized targets)

- **ginandjuice.shop production scan (v2.5.0, public OAST channel, 369 req)**:
  zero-regression on verified actives; XXE storeId still confirmed out-of-band
  from the target's own AWS egress (src recorded in evidence + verification).
  New classes reported ZERO findings — honest negatives matching the target's
  published vuln list (no SSRF/cmdi/CORS planted): zero false positives on a
  real target, first scan out.
- **XXE productId independently re-confirmed live** (fresh public-channel probe,
  callback from 18.200.201.133 / UA ginandjuice.shop) — documents that its
  absence from the no-browser run is a scan-configuration artifact, not a
  detector regression.
- **CORS manual probes on all four authorized targets** (ginandjuice, testfire,
  testasp, testaspnet): no arbitrary-Origin reflection with credentials anywhere
  — consistent with the production scan's zero CORS findings.

## Quality gates (all live)

- Tests: 49 -> **52/52 PASS** (ENG-08 regression, CORS unit with fresh-origin
  verify, full v6 E2E asserting the three classes verified + twins silent +
  prior classes intact).
- Doctor: **12/12 PASS** (9 detectors; oast_providers against the live service).
- Benchmark: **F1 = 1.000** (TP=22 FP=0 FN=0 TN=16, authenticated, deterministic
  run-3c0652b6be x3 IDENTICAL findings sets; OAST local channel interactions=7).

---

# SENTINEL v2.4.0 — "Public OAST Channel" Release

Deterministic DAST platform. Zero external dependencies (pure Python 3 stdlib).
Every finding is verification-gated: a candidate is NEVER a finding until an
independent replay confirms it.

## What v2.4.0 adds (architecture continuation: Phase 52 — public OAST endpoint)

1. **PublicWebhookProvider — `sentinel/oast.py` (Phase 52)**
   A PUBLIC out-of-band channel via the webhook.site REST service — Burp-
   Collaborator-class semantics with ZERO owned infrastructure. One channel
   token per scan; the interaction id rides in the callback query string
   (`?i=<id>`); `poll()` reads the service request log over TLS and matches ids
   client-side. Source attribution (origin IP + User-Agent) lands in the
   evidence text and the verification notes, so every OOB confirmation is
   auditable from the report alone. Live-proven end-to-end: ginandjuice.shop's
   blind XXE fetched a webhook.site entity URL from 54.170.155.72 (the target's
   own AWS egress, UA "ginandjuice.shop; support@portswigger.net") while the
   HTTP response stayed a content-free 400.

2. **Channel selection policy — `make_oast()`**
   `local` (loopback listener for lab targets) | `public` (webhook channel for
   ANY target; fails loud when explicitly requested and unreachable) | `auto`
   (local for private hosts, public for remote hosts; degrades HONESTLY to
   None on outage — the scan proceeds exactly as in v2.0.x, never crashing for
   lack of a listener). CLI: `scan --oast auto|local|public` (default auto).

3. **Stats transparency — `stats.oast`**
   Every scan report now records which channel served OOB evidence and how
   many interactions it recorded (`{"channel": "public-webhook",
   "interactions": 4}`).

4. **Verification notes in serialization**
   `Finding.to_dict()` now includes verification `notes` (channel + source IP
   on OOB paths) — the full evidence chain persists to the SQLite store and
   exports to reports.

5. **Doctor check `oast_providers`** (12 checks total): local listener bind +
   record round-trip, public channel token creation + empty-log poll against
   the LIVE service; network outage = WARN (degraded), never a false FAIL.

## Live validation (real authorized targets)

- **ginandjuice.shop (PortSwigger scanme), v2.4.0 production scan** — 446
  requests, 467.9s, browser on, PUBLIC channel armed:
  * **NEW CRITICAL xxe /catalog/product/stock param=storeId** — blind XXE
    confirmed out-of-band from 54.170.155.72 (the target's own server),
    verified via VR-07 fresh-interaction-id replay (2nd independent callback).
  * **NEW CRITICAL xxe /catalog/product/stock param=productId** — same class,
    fully independent evidence chain (its own detect + verify interaction ids).
  * ZERO REGRESSION: all five v2.2.0 verified actives still present (SQLi
    /catalog?category, reflected XSS, header injection, DOM XSS /blog?search
    via attr-inject onload, open redirect, AngularJS 1.7.7 EOL dep).
  * The v2.0.3-documented coverage limit ("blind XXE undetectable without a
    public collaborator") is CLOSED on the real target.

## Quality gates (all live)

- Tests: 46 -> **49/49 PASS** (unit provider protocol vs hermetic protocol
  double, unit channel policy incl. loud/honest failure modes, E2E blind-XXE
  over the public-channel protocol with source-attribution assertions).
- Doctor: **12/12 PASS** (new oast_providers check against the live service).
- Benchmark: **F1 = 1.000** (TP=19 FP=0 FN=0 TN=13, authenticated,
  deterministic run-3c0652b6be x3 IDENTICAL findings sets, OAST local channel
  interactions=2 in every run).

---

# SENTINEL v2.1.0 — "Platform Services" Release

Deterministic DAST platform. Zero external dependencies (pure Python 3 stdlib).
Every finding is verification-gated: a candidate is NEVER a finding until an
independent replay confirms it.

## What v2.1.0 adds (architecture continuation: DB / REST-UI / OAST phases)

1. **Persistence Layer — `sentinel/store.py` (Phase 46)**
   SQLite store for runs + findings (verified AND rejected). Cross-run
   intelligence: `recurring()` (the same vuln came back), `delta()` between runs
   (new / fixed / recurring), filterable queries, aggregate stats. CLI: `--db`,
   `findings [--recurring|--delta|--type|--min-risk]`.

2. **Report Builder — `sentinel/report.py` (Phase 47)**
   Self-contained HTML report (inline CSS, zero external assets) + JSON export,
   per-run or cross-run overview. CLI: `report --format html|json`.

3. **REST API + Web UI — `sentinel/api.py` (Phase 48)**
   `GET /api/health|runs|runs/{id}|findings|stats|scans/{id}` and
   `POST /api/scans` (background scan threads, auto-persisted). Embedded dark-mode
   dashboard at `/` (launch scans, live polling, recurring/delta intel).
   Security posture: loopback bind by default; non-loopback bind REQUIRES a token.
   CLI: `serve --port 8022 --db results/sentinel.db`.

4. **OAST Engine — `sentinel/oast.py` (Phase 49)**
   Out-of-band interaction server (Burp-Collaborator-class semantics, local).
   Closes the documented v2.0.x gap: blind XXE with NO response oracle is now
   confirmed via the target's own callback. Detection: `oob_callback` evidence;
   verification: **VR-07** fresh-interaction-id replay. Auto-armed for
   local/private targets (remote targets need a public listener — documented).

## Quality gates (all executed live at release time)

| Gate | Result |
|------|--------|
| Test suite (unit + regression + chaos + E2E) | **36/36 PASS** |
| Doctor | **9/9 PASS** (new: persistence_layer check) |
| Benchmark (fixture v3, 23-entry ground truth) | **TP=13 FP=0 FN=0 TN=10, P=R=F1=1.000** |
| Determinism | same seed -> `run-3c0652b6be` -> identical findings set |
| Self-repair gate (repair-demo) | real failure F1=0.0 reproduced; rule-only repair ROLLED BACK; rule+policy ACCEPTED (F1=1.0) |
| Real remote target (ginandjuice.shop, PortSwigger scanme) | same 5 verified findings as v2.0.3 — zero regression; SQLi CRITICAL risk 85 conf .95 |

## Live defects caught & fixed during this release (each with a permanent regression case)

- **CLI gap**: docstring promised `findings`/`report` since v2.0.3 — never
  implemented; now real, with script-mode subprocess coverage
  (`regression_cli_script_mode_all_subcommands`).
- **Relative import in script mode** (`from .core import ...` crashed
  `python3 sentinel/cli.py scan`) — live-caught during the ginandjuice scan;
  fixed + permanent subprocess-mode test.
- **API access logs polluted stdout** — would have corrupted the test-suite JSON
  verdict consumed by the repair gate (`json.loads(stdout)`); moved to stderr.

## Fixture v3 (benchmarks/ground_truth.json)

New endpoints: `/vuln/oob-stock` (blind XXE, confirmable ONLY out-of-band —
cycling-noise responses) and `/safe/oob-stock` (DTD rejected). Ground truth:
23 entries (13 TP-able / 10 TN-able).

## Usage

```bash
python3 sentinel/cli.py scan https://target.example/ --max-pages 25 --db results/sentinel.db
python3 sentinel/cli.py benchmark            # F1 against ground truth, OAST armed
python3 sentinel/cli.py findings --db results/sentinel.db --recurring
python3 sentinel/cli.py report --db results/sentinel.db --out results/report.html
python3 sentinel/cli.py serve --port 8022    # REST API + dashboard at http://127.0.0.1:8022/
python3 sentinel/cli.py doctor               # 9 environment checks
python3 sentinel/cli.py repair-demo          # live self-repair gate loop
```

## Documented coverage limits (honesty contract)

- Remote-target OAST requires a publicly reachable listener (local loopback
  listener only proves lab targets; plug point: `OastServer.public_base`).
- Browser/DOM engine (DOM-XSS, JS-rendered forms) — next architecture phase.
- Authenticated crawling depth (session replay exists in the engine; scanner
  surface is anonymous-context by default).

## 2.2.0 — Phase 50: Browser/DOM Engine
- NEW sentinel/browser.py: static DomSinkScanner (source->sink flows, param extraction)
  + BrowserEngine (Playwright/Chromium, scope-gated) — render, runtime form/link
  discovery, network capture, DOM XSS execution proofs (window-flag canary), BR-01
  fresh-canary verification, BR-02 WAF-resistant 5-variant probe battery.
- DISC-10: div[data-action] pseudo-form parsing (ginandjuice #subscribe markup) +
  static JSON-serialization learning (JSON.stringify + application/json hints).
- DISC-11: static DOM source->sink scan on inline scripts + JS assets.
- DISC-12: GET-form action URLs queued as crawl pages with default params
  (live-caught: /blog?search= script is server-side conditional — the param-less
  index carries no script at all).
- DISC-09 fix (live-caught via traced crawl): per-path cap now counts FETCHES not
  queue insertions — duplicate menubar links used to burn the whole path budget
  and starve the DISC-12 form-target URL (every gate passed, surface unreachable).
- ENG-04: ParamLocation.JSON rendering (JSON body + Content-Type application/json;
  siblings like CSRF tokens ride along verbatim).
- ENG-05: session cookie jar (multi Set-Cookie harvest — dict comprehension kept
  only the last one — + same-host Cookie replay). Substrate for CSRF-protected
  flows and the future authenticated-scan phase.
- DETECT-10: XSS detector content-type gate — raw reflection inside an
  application/json response is data, not markup (subscribe email would have been
  an FP); the browser submit-flow owns that verdict.
- TOKEN param kind (csrf/token/nonce): never mutated, carried as sibling — all
  detectors skip it.
- Doctor: browser_engine check (10 checks now; WARN-with-degraded when playwright
  absent — static fallback stays active).
- CLI: scan --no-browser.
- Fixture v4 (ground truth 17 TP / 12 TN): /vuln/dom-write (conditional DOM-XSS
  script — reachable only via DISC-12) + /safe/dom-text (TN), /vuln/json-reflect
  + /safe/json-reflect (div-form JSON chain), /vuln/csrf-reflect (session+CSRF
  gated), /vuln/jsform + runtime-built form page (render-merge only).
- Tests 36 -> 41 (div-form parsing, sink scanner, JSON render, cookie jar E2E,
  full browser-phase E2E). Benchmark local-fixture-v4: F1=1.000 TP=17 FP=0 FN=0
  TN=12, deterministic run-3c0652b6be x3 identical — WITH a real browser in the loop.
- REAL TARGET (ginandjuice.shop, PortSwigger scanme): the documented browser-phase
  gap is CLOSED — xss_dom /blog/ param=search VERIFIED (execution proof +
  fresh-canary re-probe). Live WAF hunt on the target: tag-name + event-handler
  blacklist (400 on <img/<svg/<x onfocus=...); defeated by the BR-02
  attribute-injection vector (" onload="... — no '<' at all) after mapping the
  filter empirically. 5 verified actives total, 0 FP, 0 rejected.

# SENTINEL v2.3.0 — "Authenticated Depth" Release

Phase 51 of the 55-section architecture: authenticated scanning. The session
cookie (ENG-05 jar) becomes a first-class scan dimension — login before
discovery, authenticated crawl seed, mid-scan session self-healing.

## What v2.3.0 adds

1. **Authentication Engine — `sentinel/auth.py` (Phase 51)**
   - **AUTH-01 form-intelligent login**: GET the login page (primes the session),
     parse the REAL form (action + hidden fields — session-bound CSRF tokens ride
     verbatim as TOKEN params), POST credentials. Live-proven necessity: testfire's
     public demo account transmits nothing without ENG-06.
   - **AUTH-02 deterministic success oracle**: success = first-hop redirect
     (ENG-01 preserved) lands OFF the login path + landing body carries the
     marker. Landing URL becomes the authenticated crawl seed — /bank/* is
     linked ONLY from post-login pages.
   - **AUTH-03 session-loss watchdog**: transparent engine proxy inspects EVERY
     response; a non-login request redirected to a login-marked path = session
     died -> budget-capped re-login -> ONE replay of the same mutation. No
     silent degradation. Live-proven: testfire expired the session 3x mid-scan,
     all self-healed (reauths=3, failed=0); fixture AUTH_TTL proves it E2E.
   - **AUTH-04 browser session continuity**: the Playwright context receives the
     engine jar's cookies before every navigation — the DOM phase sees the
     authenticated surface too.

2. **Engine fixes (both live-caught on demo.testfire.net)**
   - **ENG-06**: requests with NO mutation target (login POSTs, passive baselines
     of POST endpoints) went out with an EMPTY body — credentials transmitted as
     nothing. Now BODY/JSON params serialize in the endpoint's declared shape.
   - **ENG-07**: redirect hops replayed the ORIGINAL Cookie header, so cookies
     issued ON a 302 (login session rotation) never reached the landing page —
     the hop arrived anonymous and bounced to the gate. Cookie header is now
     rebuilt from the jar for every hop.

3. **Discovery / orchestration / CLI**
   - Crawl accepts `extra_seeds` (the authenticated landing joins the BFS queue
     under the SAME deterministic gates — no privileged path) and `exclude_urls`
     (the login page is never page-fetched once authenticated: re-fetching it
     clobbers the session cookie with a fresh anonymous one — live-caught in the
     first v5 benchmark run: logins=2, healed but wasteful; now logins=1).
   - ScanConfig(auth=...); CLI `scan --auth-user --auth-pass --auth-url
     --auth-user-field --auth-pass-field --auth-success-marker`. Failed login =
     explicit ScanContinuesUnauthenticated event (scan still runs, honestly
     labeled). stats.auth = {authenticated, landing, logins, reauths,
     failed_reauths}. Budget: max_reauth=5 (anti-hammering). Auth crawl budget
     1.5x (deterministic constant).
   - Doctor: auth_engine check (11 checks now).

4. **Fixture v5 (ground truth 19 TP / 13 TN)**
   Altoro-style login: session-bound CSRF (changes every GET), session rotation
   on success (Set-Cookie on the 302 — the ENG-07 forcing function), auth-gated
   TPs reachable ONLY behind the session (/account?q raw reflection,
   /vault/transfer?acct boolean SQLi) + escaped twin (/account?tab, TN), plus a
   realistic session policy (live sessions are kept; failed logins never clobber).
   AUTH_TTL env = deterministic mid-scan expiry for the AUTH-03 test.

5. **Quality gates**
   - Tests 41 -> 46 (ENG-06 unit, ENG-07 unit, AUTH-01 unit incl. wrong-credential
     negative, authenticated-vs-anonymous E2E delta with negative control, AUTH-03
     mid-scan expiry E2E). 46/46 PASS.
   - Benchmark local-fixture-v5: **F1=1.000 TP=19 FP=0 FN=0 TN=13** as an
     AUTHENTICATED scan, deterministic run-3c0652b6be x3 identical (694 requests,
     logins=1, reauths=0).
   - Doctor 11/11.

6. **REAL TARGET (demo.testfire.net / AltoroJ, public demo account jsmith)**
   The authenticated scan reached 10 /bank/* endpoints invisible anonymously
   (695 requests vs 190 anonymous) and produced 4 NEW verified findings,
   independently re-confirmed with fresh vectors + fresh canaries:
   - CRITICAL sql_injection /bank/ccApply param=passwd (quote->500 / base->200 /
     doubled-quote->200 oracle, reproduced independently via POST)
   - HIGH xss_reflected /bank/customize.jsp param=lang (raw reflection, fresh
     canary)
   - HIGH xss_reflected /bank/queryxpath.jsp param=query (raw reflection, fresh
     canary)
   - MEDIUM open_redirect /bank/customize.jsp param=content (off-site Location)
   Anonymous negative control: the same probes bounce to login.jsp. Session
   expired 3x under scan load; AUTH-03 healed all three (failed_reauths=0).

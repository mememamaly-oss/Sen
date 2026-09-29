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

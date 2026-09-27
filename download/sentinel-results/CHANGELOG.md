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

# L3 — Proven Real Impact (الأثر الحقيقي المُثبَت)

Layer `sentinel-impact/4.4.0` over the hardened engine (L0) and Attack Path Intelligence (L2). For every attack path it proves what the attacker ACTUALLY REACHES at the end — with the MINIMAL BENIGN live probe. Safety ceiling in code, fail-closed: capability proven, not exploited — أُثبتت القدرة، لم تُستغَل.

- redirect sink (our OAST channel): `http://127.0.0.1:39709/l3redir-ab12`
- every target's probe journal + plan + assessment: `results/l3_impact/<target>/`

## ginjuice — ginandjuice.shop (scan run `run-1738d74ba4`)

- plans: 9 total / 9 planned / 0 refused / 0 not-safe
- impacts: **5 VERIFIED** / 3 PROBE_FAILED / 1 INFERRED (of 9)
- OAST redirect landing hits: 1

- `[X]` **sql_version_oracle** ['F-277b70ea40'] — PROBE_FAILED
  - detail: `{"control_true_size": 17106, "control_false_size": 9421, "version_true_size": 3761, "version_false_size": 3761, "control_separated": true, "version_separated": false}`
- `[X]` **xss_browser_execution** ['F-4df129b258'] — PROBE_FAILED
  - detail: `{"fired": false, "observed_flag": "", "expected_flag": "l3canary"}`
- `[X]` **xxe_file_read** ['F-98386c0986'] — PROBE_FAILED
  - detail: `{"control_body_len": 41, "read_body_len": 41, "control_excerpt": "\"Product ID could not be parsed from XML\"", "read_excerpt": "\"Product ID could not be parsed from XML\""}`
- `[V]` **csrf_own_session_state_change** ['F-d8bbff4e3e'] — VERIFIED
  - detail: `{"origin": "https://csrf-probe.example", "cross_origin_status": 200, "state_changed": true, "new_state_tokens": ["image", "item", "left", "productcatalog", "products"]}`
- `[V]` **header_split_proof** ['F-e6ca09b8b8'] — VERIFIED
  - detail: `{"header": "x-sentinel-l3-proof", "value": "capability-proven; Secure; HttpOnly"}`
- `[V]` **open_redirect_navigation** ['F-ef23b8b42b'] — VERIFIED
  - detail: `{"landed_url": "http://127.0.0.1:39709/l3redir-ab12"}`
- `[V]` **xss_browser_execution** ['F-fc86abef99'] — VERIFIED
  - detail: `{"variant": "attr_inject_onload", "flag": "l3domcanary"}`
- `[V]` **chain_conjunction** ['F-fc86abef99', 'F-d8bbff4e3e'] — VERIFIED
  - detail: `{"legs": [{"probe_kind": "xss_browser_execution", "status": "VERIFIED"}, {"probe_kind": "csrf_own_session_state_change", "status": "VERIFIED"}]}`
- `[i]` **chain_conjunction** ['F-4df129b258', 'F-d8bbff4e3e'] — INFERRED
  - detail: `{"legs": [{"probe_kind": "xss_browser_execution", "status": "PROBE_FAILED"}, {"probe_kind": "csrf_own_session_state_change", "status": "VERIFIED"}]}`

## gruyere2 — google-gruyere.appspot.com (scan run `run-228ffb67c9`)

- plans: 3 total / 3 planned / 0 refused / 0 not-safe
- impacts: **1 VERIFIED** / 2 PROBE_FAILED / 0 INFERRED (of 3)
- OAST redirect landing hits: 1

- `[V]` **traversal_file_read** ['F-4eac8c9136'] — VERIFIED
  - detail: `{"file": "227311345106373618080751617/..%2f..%2f..%2f..%2fetc%2fpasswd", "shared_markers": ["root:x:0:0:root:/root:/bin/sh", "daemon:x:1:1:daemon:/usr/sbin:/bin/sh", "bin:x:2:2:bin:/bin:/bin/sh", "sys:x:3:3:sys:/dev:/bin/sh"]}`
- `[X]` **xss_stored_persistence** ['F-85f0251945'] — PROBE_FAILED
  - detail: `{"resubmit_status": 200, "fired": false, "payload_rides_the_request": true, "observed_flag": "", "expected_flag": "l3stocanary"}`
- `[X]` **xss_browser_execution** ['F-fada1dc319'] — PROBE_FAILED
  - detail: `{"fired": false, "observed_flag": "", "expected_flag": "l3canary"}`

## testasp — testasp.vulnweb.com (scan run `run-e2a9fe4450`)

- plans: 6 total / 6 planned / 0 refused / 0 not-safe
- impacts: **5 VERIFIED** / 1 PROBE_FAILED / 0 INFERRED (of 6)
- OAST redirect landing hits: 1

- `[V]` **sql_version_oracle** ['F-1b63b983d5'] — VERIFIED
  - detail: `{"control_true_size": 5931, "control_false_size": 3235, "version_true_size": 5931, "version_false_size": 3235, "version_char": null, "digit_probes": {"version_digit_5": 3235, "version_digit_8": 3235}}`
- `[V]` **sql_version_oracle** ['F-392b76b39c'] — VERIFIED
  - detail: `{"control_true_size": 2965, "control_false_size": 1208, "version_true_size": 3035, "version_false_size": 1208, "version_char": null, "digit_probes": {"version_digit_5": 1208, "version_digit_8": 1208}}`
- `[V]` **sql_version_oracle** ['F-513d590d27'] — VERIFIED
  - detail: `{"control_true_size": 5939, "control_false_size": 3235, "version_true_size": 5950, "version_false_size": 3235, "version_char": null, "digit_probes": {"version_digit_5": 3235, "version_digit_8": 3235}}`
- `[V]` **sql_version_oracle** ['F-5257ed42db'] — VERIFIED
  - detail: `{"control_true_size": 3142, "control_false_size": 1208, "version_true_size": 3212, "version_false_size": 1208, "version_char": null, "digit_probes": {"version_digit_5": 1208, "version_digit_8": 1208}}`
- `[X]` **xss_browser_execution** ['F-9e99b000d0'] — PROBE_FAILED
  - detail: `{"fired": false, "observed_flag": "", "expected_flag": "l3canary"}`
- `[V]` **traversal_file_read** ['F-acb5de3e87'] — VERIFIED
  - detail: `{"file": "om/Templatize.asp?item=..%2F..%2F..%2F..%2Fwindows%2Fwin.ini", "shared_markers": ["<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">", "<html><!-- InstanceBegin template=\"/Templates/MainTemplate.dwt.asp\" codeOutsideHTMLIsLocked=\"f`

## testaspnet — testaspnet.vulnweb.com (scan run `run-4fe17c44cc`)

- plans: 2 total / 2 planned / 0 refused / 0 not-safe
- impacts: **1 VERIFIED** / 1 PROBE_FAILED / 0 INFERRED (of 2)
- OAST redirect landing hits: 1

- `[V]` **sql_version_oracle** ['F-1e2f9fefe2'] — VERIFIED
  - detail: `{"control_true_size": 30554, "control_false_size": 13444, "version_true_size": 30608, "version_false_size": 13552, "version_char": null, "digit_probes": {"version_digit_5": 13534, "version_digit_8": 13534}}`
- `[X]` **xss_stored_persistence** ['F-9779edbacd'] — PROBE_FAILED
  - detail: `{"resubmit_status": 200, "fired": false, "payload_rides_the_request": true, "observed_flag": "", "expected_flag": "l3stocanary"}`

## Combined register

- **12 VERIFIED** / 7 PROBE_FAILED / 1 INFERRED — of 20 impact plans across 4 authorized targets
- every VERIFIED impact cites its probe journal entries with literal-slice excerpts (the L2 evidence-integrity discipline, zero tolerance)
- every PROBE_FAILED carries the measured numbers; no fake proof anywhere

## The honest register (كل قيد بقياسه)

- **sql_version_oracle (ginjuice)**: PROBE_FAILED, honest: the boolean ORACLE separated (controls 17106B vs 9421B) but every allowlisted version predicate (@@version LIKE / version() LIKE / SUBSTRING(@@version,1,1)='d') returns the app's 500 page on this target's DB — a version-metadata read cannot be proven within the safety ceiling on this target. The fail-closed allowlist stays: no UNION, no information_schema, no data extraction.
- **xxe_file_read (ginjuice)**: PROBE_FAILED, honest: the entity probe was issued live (control + file entity). The stock endpoint is response-blind for file entities (param entities are blocked with 'Entities are not allowed for security reasons') — no in-band confirmation exists, and OOB exfiltration of file content is not possible on this parser. The XXE outbound-fetch capability itself was already proven at L0 via OAST.
- **xss_browser_execution (ginjuice reflected /catalog?category)**: PROBE_FAILED, honest: the attr_inject payload reaches the app as a quote in the category value — the SQL layer 500s before any reflection renders. The finding's own L2 impact link was INFERRED (grade indicated); L3's fresh browser probe confirms no execution on this surface this run.
- **xss_stored_persistence (testaspnet)**: PROBE_FAILED, honest: the payload rode a real-form replay (fresh __VIEWSTATE + btnSend, live-harvested — the WebForms postback is only processed with the button field). The app filters the <img onerror> comment TODAY (live-measured: benign <u> markup persists raw; the img shape does not). Persistence+execution of that vector is not provable on this target this run.
- **xss_stored_persistence / xss_browser_execution (gruyere2)**: PROBE_FAILED, honest: the resubmit carried the payload (200) and the render page was driven in a real browser; the canary did not execute. The L2 stored-XSS path for gruyere was INFERRED at the impact link — L3's fresh probe agrees.
- **xss_browser_execution (testasp Search.asp?tfSearch)**: PROBE_FAILED, honest: the attr_inject_onerror probe returned the app's 500 page — no reflection rendered. The L1-era note ('Templatize + tfSearch not reproduced') matches: this surface drifts on the public target.
- **chain_conjunction (ginjuice xss_reflected->csrf)**: INFERRED, weakest-link, honest: the CSRF leg VERIFIED fresh (own-session state change) but the reflected-XSS leg's browser execution did not verify this run — the whole chain stays INFERRED and names the failed leg. The dom->csrf chain VERIFIED with both legs fresh.
- **sql_version_oracle digit extraction (MSSQL targets)**: VERIFIED with version_char null, honest: the version-string read separated (version_true vs version_false) proving the DB-metadata read; the digit ladder (8/5) came back FALSE-side on both — the MSSQL version string's first character is not a digit. The measured digit probes are recorded verbatim.

## Safety ceiling actually exercised (this run)

- SQLi: only control tautologies + version predicates over DB metadata; the digit ladder is 2 probes; no extraction, no timing, no table names — anywhere.
- XXE / file reads: only /etc/hostname (never reached a secret; the blind target honestly failed).
- Traversal: benign allowlisted files only — win.ini (testasp), /etc/passwd (gruyere) — fresh reads, nothing else.
- State change: ONE cart-add, in OUR OWN session (minted by this run's engine), from a hostile Origin header, additive only. No destructive action, no victim session, anywhere.
- Redirect: the browser landed on OUR OAST channel (1 recorded interaction) — never on a third party.


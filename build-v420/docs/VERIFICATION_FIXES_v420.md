# v4.2.0 — Verification Honesty Fixes: Full Record

This document is the durable record of the v4.2.0 engine changes: what was
broken, how it was fixed, how it was gated, and how the fixed engine's
judgments compared against independently known truth on live authorized
targets.

## 1. Origin

An adversarial review of `intel.py verify()` (the `verification` generator)
concluded: Layer A (injection/OOB/DOM/SSTI/authz) performs real differential
replays; but three named break points plus one architectural weakness let the
engine write `passed=true` without proof:

1. the `else` catch-all (any unlisted type -> VERIFIED, conf 0.98 — the
   engine's highest, above every replayed class);
2. VR-13 csrf and VR-14 nosql oracles degenerated to `r.ok` (HTTP 2xx);
3. PATH A's body-diff half (no status agreement, no proportional threshold);
4. three factories (workflow / graphql / websocket) stamped `passed=True`
   by construction — the discipline was a calling convention, not a mechanism.

Additionally confirmed during fix design: ssrf / command_injection branches
were conditioned on `oob_callback` evidence — when unmet, findings fell into
the catch-all else and were stamped VERIFIED 0.98. (Today the detectors are
OAST-gated so such findings rarely exist; the fall-through was still a live
structural hazard and is now fail-closed: `unverified:blind-class-no-oob`,
CANDIDATE, never VERIFIED.)

## 2. The fixes (VF-01..04)

See CHANGELOG v4.2.0 for the specification of each fix. In short:

- VF-01 fail-closed defaults: explicit `_PRESENCE_VERIFIED_TYPES` allowlist
  (4 passive types, conf 0.70); blind classes without OOB -> CANDIDATE;
  unlisted types -> CANDIDATE; report carries `unverified_candidates`.
- VF-02 real oracles: csrf triple control (baseline / fresh hostile origin
  with same-status+similar-body / malformed-input control rejected);
  nosql reproduced flip (literal rejected -> fresh operator accepted).
- VF-03 PATH A guard mirrors PATH D (same-status + max(200, 25%)).
- VF-04 proof protocol: `passed` is DERIVED in the factory from raw
  observations (`proof={"rule", "obs"}`); missing proof / unknown rule raise;
  failed derivation -> REJECTED.

## 3. Gates

- tests 102/102 (new: `unit_v420_fail_closed_verification_defaults`;
  one assertion updated to the new method-string format, deliberate).
- doctor 15/15.
- benchmark x3: F1=1.000, deterministic (run-3c0652b6be identical x3),
  passive conf 0.70, csrf 0.85, nosql 0.9, unverified 0 on the fixture.
- engine v4.1.1 frozen baseline untouched (build-v411 diff vs tag = 0).

## 4. Live validation — v4.2.0 judgments vs independently known truth

All four authorized remote targets were live and scanned with v4.2.0.
Note: these are public test sites whose applications drift over time; where
the app changed, the NEW surface is reported and the drift is noted.

### testasp.vulnweb.com (http; app now "acuforum forums" — was Acuart store)
| known truth (prior live sessions) | v4.2.0 judgment |
|---|---|
| SQLi blind showforum.asp?id (conf .95) | RE-VERIFIED: conf .95, oracle:replay-2round (status differential) |
| path traversal Templatize.asp?item (win.ini) | RE-VERIFIED: conf .9, same-marker-alt-depth |
| XSS Search.asp?tfSearch | RE-VERIFIED: conf .9, variant-battery-6 |
| (new forum surface) | + SQLi showthread.asp?id (.95), SQLi error-based Search/Login/Register (.9, error:replay-2variants) |
Honesty layer: 3 xss candidates honestly REJECTED (reflections that do not
reproduce raw); 0 unverified; passives 0.70. FP: 0.

### testaspnet.vulnweb.com (http; routes drifted — /Search.aspx now 404)
| known truth | v4.2.0 judgment |
|---|---|
| SQLi (old: Comments.aspx?id; app drifted) | SQLi VERIFIED on the current surface: ReadNews.aspx?id, conf .95, oracle:replay-2round |
Bounded run (--max-pages 12 --no-oast): the grown ASP.NET surface exceeds the
single-call time budget in this environment with OAST polls enabled — recorded
as an operational limit, not a scanner defect. FP: 0.

### demo.testfire.net (http, AltoroJ2EE)
| known truth | v4.2.0 judgment |
|---|---|
| SQLi /doLogin auth bypass (manual: `uid="' OR '1'='1' --"` -> 302 /bank/main.jsp) | RE-VERIFIED: conf .95, oracle:or-redirect-2round (PATH C) |
| XSS search.jsp?query | RE-VERIFIED: conf .9 |
| XSS index.jsp?content — false NEGATIVE in the old era (WAF vetoed the single vector) | RE-VERIFIED: conf .9, variant-battery-6 (WAF-bypass battery) |
| (current surface) | + XSS sendFeedback name/email_addr (.9) |
FP: 0. Passives 0.70.

### ginandjuice.shop (https, PortSwigger VDP playground)
| known truth (v4.1 live-proven on this site) | v4.2.0 judgment |
|---|---|
| SQLi /catalog?category= (VR-04, PATH D) | RE-VERIFIED: conf .95, oracle:or-bodydiff-2round — PATH A's tightening did NOT cost the finding (chain falls to the correct oracle) |
| header injection /catalog?category= (VR-05) | RE-VERIFIED: conf .9, fresh-header-name |
| XXE /catalog/product/stock (VR-06) | RE-VERIFIED — now via the STRONGER OOB channel: fresh-interaction-id, live out-of-band callback from the real site |
| CSRF /catalog/cart (ENG-15: tokenless POST, hostile-origin acceptance, SameSite=None — manually verified) | RE-VERIFIED under the NEW triple control: conf .85, rounds=3, re-test:fresh-hostile-origin — the new oracle does not strangle a real CSRF; it strengthens the proof |
| (current surface) | + XSS ng-expression /catalog?searchTerm (.85, fresh Angular expression), XSS /catalog?category (.9), open_redirect /blog/?search (.85) |
FP: 0. Passives 0.70. vulnerable_js_dependency 0.70.

### Cross-target summary
- Every independently known truth was re-verified with a real oracle (zero
  regressions from the tightened guards).
- The tightened PATH A cost nothing (the OR-pair PATH D and redirect PATH C
  catch the string-context and auth-bypass cases, exactly as designed).
- The new csrf oracle verified a REAL csrf on a real target and demotes
  blanket-2xx endpoints to CANDIDATE (unit-proven; no such endpoint arose on
  these four targets — the only csrf candidate that arose passed the control).
- Zero unverified candidates arose on these targets (no csrf/nosql/ssrf/cmdi
  candidates without proof appeared); the honesty layer is visible in the
  report schema and exercised by the new unit test.
- Known limitation: this session could not re-run the workflow battery on a
  live remote target (ginandjuice learns 0 flows — honest skip
  `/catalog:no_resource_linkage`, same as the v4.1 run); the proof-protocol
  factories are validated by the phase-58 E2E fixture gate (all 8 classes,
  derived proofs) + the 102/102 suite.

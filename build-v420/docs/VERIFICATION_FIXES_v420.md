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

---

## Round 2026-10-03 — bench-adv: the bench now DISCRIMINATES the fix set

### The supervisor's finding, confirmed with data
The stock 73-case bench scored **F1=1.000 on BOTH engines** — the frozen v4.1.1
(broken oracles) and v4.2.0 (fixed) — with the *identical* run-id
(`run-3c0652b6be`) and confusion matrix (38/0/0/35). Two facts explain it:

1. `run_id = "run-" + sha1(seed)[:10]` (`core.py:new_run_id`) — derived from the
   seed only, never from engine code or fixture content. Same seed → same run-id
   by design. The identical id across engines was never evidence of anything.
2. The 73 cases DO include csrf×2 / nosql×2 / ssrf×2 / cmdi×2 — the cases touch
   the fixed branches, but only through scenarios where the weak and strong
   oracles AGREE (e.g. the safe csrf twin returns 403, so even `r.ok` rejects
   it). The bench contained ZERO cases in the disagreement zone — the failure
   modes the fixes address. Verdict-level F1 was therefore invariant to the
   fixes: the bench certified the broken engine as readily as the fixed one.

### The fix to the bench (fixture v11 + GT 75)
Two adversarial cases, each placed exactly in the disagreement zone, each with
ground truth `present:false` (neither endpoint is exploitable — no state ever
changes, no credentials are ever granted):

| case | endpoint shape | v4.1.1 (weak oracle) | v4.2.0 (strong oracle) |
|---|---|---|---|
| `csrf@/vuln/subscribe-echo:email` | blanket-200 echo: accepts ANY POST (any origin, malformed/empty input) with the same 200; no state change | VR-13 `r.ok` on one hostile replay → **VERIFIED 0.85 (FP)** — notes: "cross-origin replay … accepted: True (HTTP 200)", rounds=1 | triple control: malformed control ALSO 200 → no input discrimination → **CANDIDATE `unverified:no-input-discrimination` 0.30** (TN) |
| `nosql_injection@/api/nosql-lockout:user` | literal wrong creds → 401; any `$operator` body → soft-fail 200 (driver swallows the error); the FIRST operator body trips a permanent rate-limiter: everything → blanket 200 | VR-14 `r.ok` on the `$gt` probe alone (post-lockout blanket 200) → **VERIFIED 0.90 (FP)** — notes: "fresh operator {$gt} on param 'user' bypassed: True", rounds=1 | reproduced-flip re-runs the literal baseline FIRST: it now returns 200 → the 401→200 flip no longer reproduces → **REJECTED 0.15** (TN) |

### Results (deterministic ×3 each, identical every run)
| engine | fixture | GT | confusion | F1 |
|---|---|---|---|---|
| sentinel-core/4.2.0 | v11 (extended) | 75 cases | **38 TP / 0 FP / 0 FN / 37 TN** | **1.000** |
| sentinel-core/4.1.1 (frozen, imported read-only) | v11 (extended) | 75 cases | **38 TP / 2 FP / 0 FN / 35 TN** | **0.9744** |

Same fixture, same GT, same seed, same run-id — **different engines, different
F1.** The 2-FP delta is engine-level proof (not description-level) that the
fixed oracles do what the diffs claim. Artifacts:
`results/bench_v420_adv_{1,2,3}.json`, `results/bench_v411_adv_{1,2,3}.json`,
driver `scripts/bench_adv_v411_driver.py` (imports build-v411 without touching
a byte of the frozen baseline).

### Mechanism probes (the fixes the fixture cannot reach)
`scripts/probe_vf_mechanisms.py` — direct calls into both engines
(`results/probe_vf_mechanisms_v{411,420}.jsonl`):

| probe | v4.1.1 | v4.2.0 |
|---|---|---|
| VF-01a unlisted type `future_widget_scan` | **VERIFIED 0.98** (fail-open catch-all) | CANDIDATE 0.30 `unverified:no-branch` |
| VF-01b ssrf, no OOB evidence, no OAST | **VERIFIED 0.98** (same catch-all — the structural fall-through, live-proven) | CANDIDATE 0.30 `unverified:blind-class-no-oob` |
| VF-01c passive confidence | 0.98 | 0.70 |
| VF-03 PATH A stubbed replay 200/4500B vs 200/4000B (500B = 11% volatile content, same status) | **VERIFIED 0.95** (`>200B` rule) | REJECTED 0.15 (500B < max(200, 25%) → falls through to PATH B → no error) |
| VF-04 `WorkflowEngine._finding()` without proof | returns Finding with **stamped passed=True** | **ValueError** (proof required) |
| VF-04 proof with unknown rule | (no protocol to violate) | **ValueError** (unknown rule, fail-closed) |

### Honest limitation discovered BY building this bench
**VF-03 cannot be discriminated at bench level through the current detector
pipeline.** The SQLi *detector* already enforces the 25% body-diff guard
(DETECT-05, present in both builds — `detect.py` is byte-identical md5
fe73401a), so any candidate that reaches PATH A already passed a ≥25%
differential, which the new verifier also accepts. The old verifier was looser
than its own detector — VF-03 aligned them — so the disagreement zone (>200B
but ≤25%, or diff-without-status-agreement) is unreachable from detector-emitted
candidates unless the target CHANGES STATE between detection and verification
(a volatile target — not honestly emulable in a deterministic fixture without
keying the fixture to engine payload internals, which would be overfitting the
bench to the engine). VF-03 is therefore proven at mechanism level (stubbed
replay above) and by the live targets (PATH A tightening cost zero verified
findings on ginandjuice/testfire/testasp while the chain fell to the correct
oracles).

### What this does NOT prove
- v4.2.0's F1=1.000 on the extended bench proves the fix set changes verdicts
  on the disagreement cases. It does NOT prove the absence of OTHER failure
  modes outside these two adversarial shapes. The bench discriminates the four
  fixes; it is not a general correctness proof.
- The live-target results remain self-judged (see the record above): re-finding
  publicly documented truths on testfire/ginandjuice is reproduction, not
  independent discovery, and "zero FP" is an internal claim until a party
  outside the engine re-verifies the findings (manual review or a VDP
  confirmation).

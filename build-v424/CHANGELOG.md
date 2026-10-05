# SENTINEL v4.2.3 — stored XSS, URL-path traversal, and two precision fixes

Supervisor orders 2026-10-04 (round 4): fix the three confirmed IV13 gaps
(testaspnet stored XSS via tbComment, gruyere stored XSS via signup uid, gruyere
path traversal in the URL path), and resolve the three unreplicated claims
(ginandjuice searchTerm XSS — FALSE POSITIVE, engine-fixed; testasp tfSearch and
Templatize — REAL, target-drift during IV13, live-reconfirmed 2026-10-03 20:43
UTC by the IV14 raw re-probe).

## The changes

Order 2 — the three gaps:
- detect.py StoredXSSDetector (DETECT-16) + shared stored_xss_flow(): two-step
  flow — fresh form fetch (rotating __VIEWSTATE / CSRF tokens round-trip with
  FRESH values; the live testaspnet miss was exactly a stale-viewstate 500) ->
  canary submit via the real form (hidden fields ride verbatim, passwords never
  targeted) -> render-surface re-fetch (form action page + origin page + parent
  dir; the SUBMIT response is deliberately NOT a surface — echoes there are
  reflections, the reflected detector's class) -> persistence control (the raw
  canary must survive an INDEPENDENT second fetch). Content-submission forms
  only (comment/profile/signup/...): search/login/commerce forms never store.
  Per-param unique canaries (<sentinelst0>, <sentinelst1>) — a shared marker
  cross-attributes the first probe's hit to later params (caught by the unit
  test's tbName control).
- discovery.py: form_origin tag on CRAWL_FORM endpoints (where the form was
  discovered — the stored flow's fresh-fetch source and third render surface).
- detect.py PathTraversalDetector (DETECT-17) + orchestrator wiring: URL-path
  traversal battery, once per scan, from the target root + the crawled
  directory prefixes (gruyere serves /<inst>/..%2f..%2f..%2f..%2fetc%2fpasswd —
  the encoded shape survives front-line path normalization). Param-bound
  traversal (Templatize.asp?item=) is unchanged.
- intel.py xss_stored verification: full re-execution with a FRESH canary
  (re-test:fresh-canary-resubmit) — never a replay of the detection request.
  path_file_marker verification: fresh GET of the traversal URL
  (re-test:same-path-marker).
- detect.py _get_endpoint_for(): every flow request preserves the URL's query
  string (the request engine serializes queries from ep.parameters — a bare
  Endpoint(url=...) silently drops them; ASP.NET form actions carry ?id=...).
- detect.py _StoredFormParser + stored_xss_flow (second live lesson, caught on
  the testaspnet re-scan): ASP.NET WebForms routes the postback event through
  the CLICKED SUBMIT BUTTON's name=value pair (btnSend=Send comment). The
  first flow dropped buttons ("servers do not require them" — true for most
  stacks, FALSE for WebForms): POST accepted 200, comment silently discarded,
  render surface empty. Named submit buttons now ride along on submit (the
  FIRST one = the primary button, deterministic), <button> text content used
  when the value attr is absent, Referer = the form's page. The discriminating
  unit test's mini-app enforces both live-caught requirements (fresh viewstate
  AND button routing) and would fail the buttonless flow.
- discovery.py (live-caught on the gruyere re-scan): the DISC-12 page-fetch of
  a GET-form's target re-registered the form's endpoint as SEED — stripping
  the CRAWL_FORM source and form_origin tag the stored detector gates on, and
  the surface was silently skipped. Form registration is now canonical for
  same-id endpoints, and page-fetch registration no longer clobbers a
  CRAWL_FORM entry.

Order 3 — the two precision fixes (adjudicated false positives):
- detect.py in_script_or_style() + XSSDetector.analyze (DETECT-15): an
  {{expression}} canary that lands inside <script>/<style> content is NOT an
  Angular binding context — AngularJS never interpolates script content. The
  ginandjuice /catalog?searchTerm claim (GINJUICE F03) was exactly this: the
  marker reflected raw inside `var searchText = '...'` while every breakout
  probe (', ", </script>, \) was neutralized by the app's escaper (IV14 raw
  evidence, 2026-10-03 20:43 UTC). Attribute-context ng reflections
  (GINJUICE F04 category) still fire and still verify — positive control unit
  tested.
- intel.py VR-14: fresh-ng-expression verification requires the reflection to
  land OUTSIDE script/style (defense in depth — an old-run-style finding is
  refused too).
- intel.py PATH B (VF-04): a BARE 5xx on the quote replay no longer counts as
  error reproduction — verification requires an actual DB error STRING. The
  v4.2.2 logic verified testasp tfSearch/tfUName/tfUPass as CRITICAL SQLi on a
  generic IIS 500 alone (notes even claimed "reproduce DB error" while the
  evidence said "no DB string"). DETECT-04 status_oracle candidates are
  unchanged (still produced, still visible) — they just no longer VERIFY
  without an oracle. Endpoints carrying a real oracle still verify through
  PATH A/D/C/C' — the live tfSearch re-scan now verifies via PATH A (the
  AND-pair body differential exists on the recovered endpoint).

## What this does NOT prove
- The stored-XSS flow proves the canary class renders raw after a real submit
  on the tested surfaces. It does NOT prove other users see the payload
  (cross-user reachability depends on the app's sharing model — gruyere's
  cookie-carried uid render is session-scoped).
- The path battery proves arbitrary-file READ for the marker files on the
  probed depths (2/4/6 up, encoded + one plain shape) from the target root and
  the top crawled directories. Deeper bases or exotic encodings are unprobed.
- PATH B tightening trades recall for precision honestly: a real error-based
  SQLi whose errors are 500-pages-without-DB-text will now land REJECTED
  instead of wrongly VERIFIED. That is the intended direction (supervisor:
  "tighten precision") and the candidate signal remains visible.

## Proofs (not descriptions)
- Six discriminating unit tests in the 110/110 suite: stored comment form
  (rotating viewstate), stored GET-form cookie render, URL-path traversal +
  probe-base selection, PATH-B rejection on a bare 500, ng-in-script refusal
  (detect + verify), ng-in-attribute positive control.
- Mechanism probe scripts/probe_v423_gaps.py: the SAME five scenarios through
  the FROZEN v4.2.2 engine (read-only import) vs v4.2.3 — raw records
  results/probe_v423_gaps.jsonl:
  A comment form:    v422 reflected battery -> NO candidate (stale viewstate 500s, the live miss reproduced) / v423 -> VERIFIED xss_stored
  B cookie GET form: v422 -> NO candidate / v423 -> VERIFIED xss_stored
  C URL-path trav:   v422 param battery -> 0 candidates / v423 -> VERIFIED path_traversal
  D status oracle:   v422 -> VERIFIED sql_injection conf 0.9 (the over-claim) / v423 -> REJECTED
  E ng in script:    v422 -> VERIFIED xss_reflected (the F03 FP) / v423 -> no candidate, claim refused
- Gates: tests 110/110 (104 + 6), doctor 15/15, bench x3 DETERMINISTIC
  38/0/0/37 F1 1.000 run-3c0652b6be, 1959 requests (v422: 1944; +15 = the
  DETECT-17 path battery — the stored detector adds ZERO fixture requests by
  its content-word gate) and VERDICT-LEVEL DIFF vs frozen v422: NONE (every
  fixture finding bit-stable).
- Live re-scan of the five sanctioned targets (this round): the three fixed
  gaps now detected, the searchTerm claim gone, tfSearch verifying through a
  real oracle — see results/live_v423/ and the external comparison re-run.

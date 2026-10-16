# SENTINEL v4.2.6 — NodeGoat: nine live-caught defects, the JS/NoSQL + authz-matrix class unlocked

OWASP extended campaign app 5/6: **OWASP NodeGoat 1.3.0** — MongoDB 4.4.29
(ubuntu2004 bintar, userspace; OpenSSL 1.1 from a bullseye .deb because the
build links libcrypto.so.1.1 while the sandbox ships OpenSSL 3) + `node
server.js` on Node 24, deployed from source with `artifacts/db-reset.js`
seeding (admin/Admin_123, user1/User1_123, user2/User2_123 — plaintext
passwords by design) and the full 3-account authorization matrix armed.

## The target's verdict (final scan of record, final3: 874 requests, 30 endpoints, 34s)

**14 VERIFIED active findings, ZERO false positives, every marquee vulnerability class covered:**
`nosql_injection` (/allocations/1?threshold= — the $where JS-evaluation sink),
`vertical_privilege_escalation` (/benefits — the real A7 function-level break),
`idor_bola` (/allocations/:userId — path-segment object substitution),
`xss_reflected` ×9 (7 profile params + benefits date + **/memos via the marked
0.3.5 sanitizer-bypass markdown data:URI link**), `ssrf` (/research —
needle.get(url + symbol), OOB-callback verified), `open_redirect` (/learn — the
true one), csrf as an honest CANDIDATE (csurf is commented out in the app).

## Nine live-caught engine defects, each RED-proven then fixed (suite 170 → 179)

- **OWSP-27 redirect_diff payload self-echo**: an endpoint whose redirect
  Location ECHOES the submitted payload (express `res.redirect(req.query.url)`)
  "differs" between TRUE/FALSE OR-probes because the payloads differ — a
  behavioral ZERO misread as an auth-bypass oracle, VERIFIED as sql_injection
  on /learn (no DB anywhere in the handler). Guard at all three detector
  redirect_diff sites + verifier PATH C/C': a Location containing the very
  payload string that was submitted is not a differential.
- **OWSP-28 vertical-escalation tiered confirmation**: "dashboard" was in the
  strong admin-path set — every app gives ordinary users a dashboard; the name
  alone nominated NodeGoat's role-agnostic /dashboard and the access
  differential "verified" it, while the REAL break (/benefits — POST forms over
  other accounts' ids, open to every role) carried no admin-ish name and was
  never nominated. Fix: two-tier path vocabulary (strong names keep the
  name+differential oracle; ambiguous names require data-level corroboration —
  cross-account markers or cross-object state-change forms) + a NEW nomination
  source: cross-object-management surfaces collected from the privileged
  role-view replay.
- **OWSP-29 body-redirect proximity**: the open_redirect body oracle matched
  the off-site URL ANYWHERE and the sink regex ANYWHERE ELSE — on /research the
  URL rode inside an HTML comment of SERVER-SIDE-FETCHED Yahoo content while
  the only "sink" was an unrelated window.location.hostname beacon 3KB away.
  Fix: the sink must sit within a bounded window of the injected URL
  (detector + verifier), plus an honest attribution note on fetch-proxy
  endpoint shapes (a sibling param carrying an off-target URL base).
- **OWSP-30 MongoDB error family**: the $where sink answers a quote probe with
  HTTP 500 "MongoError: SyntaxError: unexpected token: string literal" — a
  clean DB-error oracle on the most common NoSQL server, invisible because
  SQL_ERR_PATTERNS carried no Mongo family. New MONGO_ERR_PATTERNS; matches
  route to `nosql_injection`, never `sql_injection` (a misattributed class is
  an FP of its own). The pair_quote control ('' is valid SQL but INVALID JS)
  yields to the JS-tautology differential.
- **OWSP-31 JS-tautology battery**: every SQL-shaped OR pair dies as an
  identical JS SyntaxError on a $where sink (no differential); the JS pair
  (1' || '1'=='1 matches all rows, 1' && '1'=='2 matches none) separates
  cleanly (live: 200/8251B vs 500). '==' is the JS discriminator — invalid SQL
  in every engine, so the family cannot fire on SQL backends.
- **OWSP-32 companion-gated SSRF**: the server-side fetch (needle.get(url +
  symbol)) sits behind `if (req.query.symbol)` while symbol's discovered base
  value is EMPTY — the OAST probe rode in `url` with symbol= (falsy) and the
  fetch code path never executed. Four-part fix: the detector emits a FILLER
  twin (empty sibling QUERY params render with a benign constant — the DISC-04
  body-field discipline applied to the query string), the local OAST listener
  matches interaction ids by PREFIX (oob-<12hex>) so URL-concatenated
  callbacks (/oob-<id><suffix>) still land, the render gained
  `fill_query_siblings` (default OFF — every other battery renders
  byte-identically), and the VR-09 verifier replay got the same twin (without
  it every candidate of this shape died at verification).
- **OWSP-33 path-segment object ids**: /allocations/:userId carries the object
  id as the FINAL PATH SEGMENT — no Parameter at all — so the IDOR engine
  (which iterates ep.parameters) never probed it: user1 could read admin's
  allocations live and the scanner said nothing. Synthesized URL-substitution
  probes under the same victim-marker oracle + VR-17 fresh-victim replay.
- **OWSP-34 markdown data:URI link family**: marked 0.3.5 with sanitize:true
  correctly escapes raw HTML (the classic battery honestly finds nothing) but
  passes data:text/html;base64 URIs through RAW — an executable-URI XSS with
  no battery family. The ORACLE is the RENDERED ANCHOR SHAPE (the payload text
  itself is inert; a markdown renderer transforms it away), so the family
  cannot fire on plain reflections.
- **OWSP-35 the authz gate-scope type error**: `_gate_scope` aliases
  `endpoint_gate_scope(ep)` (expects the ENDPOINT OBJECT) but both call sites
  passed `ep.url` (a STRING) — getattr(<str>, 'url', '') collapsed to '' and
  the whole probeable gate (logout/destructive/state-change/login filtering)
  silently passed EVERYTHING. Live: the role-view replay fetched /logout under
  every account, killed all sessions (auto-reauth rotated cookies, then died
  again), the IDOR probes landed on login pages (no victim markers), and the
  vertical differential compared login-page-to-login-page. Found by chasing
  the IDOR miss; the fix passes the Endpoint and adds a defensive probeable
  gate on every vertical-loop fetch.

Also fixed en route: `http_engine.py` did not import `ParamKind` (the filler
branch raised NameError inside the per-detector exception handler — the probe
silently never shipped; caught live on the final2 scan), and the OWSP-32 unit
fixture initially used a NON-EMPTY symbol base (the plain probe already
reached the sink — it passed vacuously; corrected to the real empty-base
shape).

## Gates (all green)

Suite **179/179** (170 + owsp27..35 discriminating cases, each RED-proven on
the unfixed engine first) + doctor 17/17 + bench ×3 IDENTICAL 38/0/0/37
F1=1.000 run-3c0652b6be @2515 requests (+166 vs the Mutillidae cycle = the
jsor/md/ssrf-filler battery families' bounded effect; ZERO verdict changes) +
verdict-diff vs frozen v4.2.2: NONE.

## Honest gaps

NodeGoat's /research SSRF verification rides the needle fetch of a
CONCATENATED URL (url + symbol) — the callback lands on /oob-<id><suffix>
(prefix-matched); an app that sanitizes the URL before fetching would need a
response-oracle family. The authz IDOR battery covers GET surfaces only —
POST object mutations (/benefits' updateBenefits with an arbitrary userId)
are a documented future surface. The vertical-escalation oracle still relies
on path-name vocabulary for the strong tier (admin|manage|console|...) —
name-less admin surfaces without cross-object forms remain invisible. DVWA's
logic modules, Mutillidae's two environment-blocked surfaces, and the
Benchmark's cmdi/pathtraver oracles remain open from their rounds.


# SENTINEL v4.2.5 — DVWA: eight live-caught defects, the PHP/MySQL class unlocked

OWASP extended campaign app 3/6: **DVWA 3.x (master 088256f)** — PHP 8.5.8
(static-php-cli bulk build, userspace) + MariaDB 11.4.5 (userspace bintar) +
PHP built-in server, deployed from source with DEFAULT_SECURITY_LEVEL=low and
authentication ON (the engine's own AUTH-01..03 flow performs the form login,
CSRF user_token riding verbatim).

## The target's verdict

Final scan (1814 requests, 76 endpoints, browser 15 pages / 24 probes):
**every injection-shaped vulnerability class at low security VERIFIED** —
SQLi ×3 (`/vulnerabilities/sqli/` id, `/vulnerabilities/brute/` username,
`/vulnerabilities/sqli_blind/` id via the NEW existence-flip oracle),
command_injection (OOB), path_traversal, SSRF (OOB), open_redirect,
XSS reflected ×4, XSS stored ×2, **XSS DOM** (`/vulnerabilities/xss_d/` — the
decodeURI href-slicing sink), **unrestricted_file_upload** (`/vulnerabilities/upload/`
— real multipart + serve-check, benign .txt canary only, never an executable
shape). CSRF surfaces as 11 honest CANDIDATES (unverified_candidates — the
blanket-200 discriminator of VR-13 refuses to certify without a destructive
commit, which the OWSP-15 guard now makes structurally impossible).
AND: the admin password hash is byte-identical before and after the scan —
the scanner no longer destroys the target it is testing.

## The eight defects (each red→green, suite 164/164)

- **OWSP-13** (db_error gated on `not r.ok`): PHP with display_errors=On
  prints fatal SQL errors INSIDE HTTP 200 responses — the MariaDB signature
  ("You have an error in your SQL syntax ... MariaDB server version",
  live-measured 637B) never reached the check on the world's most common web
  stack. Signature now evaluated regardless of status; OWSP-12 base control
  preserved + a new pair_quote control (valid SQL `1''` must not error).
  Fixture sqli_error.php made realistic to match the live DVWA measurement
  (unpaired-quote-only errors — the old any-quote-500 shape was itself the
  degenerate class OWSP-12 rejects).
- **OWSP-14** (`--` comment without trailing space): MySQL/MariaDB require
  whitespace after `--`; T-SQL/PostgreSQL do not. The ornum/par1/par2 families
  (calibrated on testfire's MS SQL) made both pair members die as identical
  MariaDB syntax errors — dead on the most common web DB. Trailing space fixes
  MySQL at zero T-SQL/pgsql cost (bench + verdict-diff prove it).
- **OWSP-15** (destructive equal-pair commit — SCANNER SAFETY): the BASE
  request on DVWA's csrf form (GET ?password_new=&password_conf=&Change=Change)
  COMMITTED a password change to md5('') — the DB proved it (admin hash
  d41d8cd9...). A render-time guard now makes password-ish confirm pairs
  deterministically unequal on every query/body/JSON request the engine issues.
  Live proof: hash identical after the full scan.
- **OWSP-16** (no-base OR pair): lookup-style endpoints answer the base-prefixed
  OR pair identically on both sides (user_id='1' exists under OR 1=1 AND OR
  1=2 — live-measured 200/4703B both). The no-base tautology pair turns the
  WHERE pure: TRUE → 200 'exists', FALSE → 404 'MISSING'. New detector family
  + verification PATH E (fresh comparison vectors '2'>'1' / '1'>'2').
- **OWSP-17** (CsrfDetector POST-only): DVWA's own password-change form is
  method=GET at low security; SameSite=Lax still attaches cookies to cross-site
  top-level GETs — GET-CSRF is the surviving live class on legacy apps.
- **OWSP-18** (multipart file upload structurally dead): forms with
  `<input type=file>` were probed as urlencoded text (56 ghost requests on a
  surface that reads $_FILES, never $_POST). New UploadDetector (DETECT-18):
  real multipart body, benign canary .txt, acceptance (filename echoed) +
  servability (the app's own reference fetched back, canary content intact),
  VR-20 verification with a fresh canary. Sub-fixes: 18b (static parser
  dropped `action="#"` forms — fragment-only action means submit-to-self;
  both upload and csrf surfaces vanished from the static map), 18c (serve-check
  urljoin against a double-slash base resolved one level too shallow),
  18d (DVWA echoes the stored path as PLAIN TEXT — quoted-context regex
  extended with a path-shaped fallback).
- **OWSP-19** (DOM param extraction blind to the href-slicing idiom):
  `location.href.substring(location.href.indexOf("default=")+8)` reads the
  param MANUALLY — no URLSearchParams, no .get(). Params list came back empty,
  browser_probes=0 with 4 sink candidates (the silent-zero failure mode).
  19b: the img battery is dead inside `<select>` (the HTML spec's in-select
  insertion mode drops `<img>`) — script-execution variants added (same
  canary-only flag). 19c: decodeURI does NOT decode %3D ('=') / %2F ('/') —
  fully-encoded payloads reached the sink as JS syntax errors; the probe URL
  now uses minimal encoding (JS-syntax characters raw).
- **OWSP-20** (post-verification CANDIDATE findings silently dropped):
  the findings rebuild kept only verified+rejected, betraying VF-01's
  visibility contract — VR-13's no-input-discrimination branch (blanket-200
  CSRF endpoints) is the producer; the DVWA csrf candidate vanished between
  detector and report. Candidates now survive into unverified_candidates.

## Gates

Suite 164/164 (153 + 11 discriminating, each RED-proven on frozen v4.2.4
surgical revert) · doctor 17/17 · bench ×3 IDENTICAL 38/0/0/37 F1=1.000
@2349 reqs (fingerprint d0dc663e — +146 reqs from the new families, ZERO
verdict changes) · verdict-diff vs frozen v4.2.2: NONE.

## What this does NOT prove

- The csrf CANDIDATES stay unproven by design: proving a state change on a
  password form requires committing it — the safety guard makes that
  impossible and the report says so honestly.
- DVWA's logic-level modules (insecure captcha, authbypass change_user_details,
  weak session IDs, the cryptography playground) have no detector classes —
  recorded as not-covered, not as clean.
- host_header_injection findings (16) are real for this deployment (the PHP
  built-in server reflects Host) but are deployment-specific, not app bugs.
- The 25%-relative body-diff threshold still hides result-set-size differentials
  on large-chrome pages when no error/status/flip oracle exists (the /brute/
  login-bypass body diff is ~60B on a 4.3KB page; it verified here via db_error
  instead). A template-diff oracle is future work.

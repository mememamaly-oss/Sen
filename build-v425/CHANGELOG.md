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

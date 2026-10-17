# trustbound Category Close — recall-push round (TB-1a/1b/1c/2/3a/3b/3c)

**Date:** 2026-10-14 (single session; the environment had been rebuilt from
scratch — JDK + Maven + BenchmarkJava re-cloned/rebuilt, benchmark.war 4,541
classes, cp.txt regenerated, CSV byte-identical to the campaign ground truth;
the Tomcat 9.0.85 core was verified structurally complete — stock 637 files,
32 lib jars, the 5 stock webapps, ServerInfo 9.0.85 — so NO re-download was
needed; stack smoke green: tomcat 200, LDAP 10389, HSQLDB 9001, sqli
header-vector 200, crypto probes writing passwordFile. Per the supervisor's
item-0 order the assembly scripts' overwrite flaw was fixed FIRST: a verified
artifact is never written over — `tomcat_guard.sh`).
**Baseline:** origin/main cc142b3 (TB-3c) — trustbound 32 TP / 51 FN / 0 FP =
38.55% recall (the cmdi-close eval `eval_cmdi_close_full.json` is the
regression baseline).
**Result:** **83 TP / 0 FN / 0 FP = 100.00% recall, precision 1.0000** (fresh
full 12-chunk re-run on the TB engine cc142b3, **447,834 requests**, 4,272
findings, 1,498 active ALL VERIFIED, zero rejected). The +51 = EXACTLY the
diagnosed 51-FN set; the trustbound TP set = the cmdi-close TP+FN union
exactly. Machine-checked ZERO regressions: every other category's TP/FP
counts AND test lists byte-identical, cross-class 54=54 identical, FP 0
across ALL. Overall covered: recall 90.33% -> 94.31%, F1 0.9492 -> 0.9707,
precision 1.0000.

## The 51 FNs — complete live root-cause taxonomy (diagnosed 986735e before any code; every channel hand-proven LIVE on the running stack)

| Family (read channel) | Count | Root cause (live-proven) | Fix |
|---|---|---|---|
| self-named VALUE (`?<TCID>=<marker>`) | 35 | the benchmark trust-boundary servlets read the request param NAMED AFTER THE ENDPOINT'S OWN URL SEGMENT (getParameter/getTheParameter/getParameterValues("<TCID>"), getQueryString substring, getParameterMap TCID scan) while the engine probed only the FIRST declared param's value; for the no-declared-params endpoints the old fallback sent the marker as a param NAME — exactly backwards. Live: 00031/02622 `?<TCID>=<marker>` reflects with the session phrase while the first-param probe answers a constant. Covers tcid-value 20 + raw-query-string 10 + map-read 5 | **TB-1a** (5f1bbe4) |
| header-NAME (first non-standard) | 4 | the servlet scans getHeaderNames(), skips the common list, and takes the FIRST non-standard header's NAME as the tainted string; no probe ever put the marker in a header NAME. Live-caught subtlety: the family's own openapi declares a NON-STANDARD header param that wins the race — the probe must be the only non-standard header on the wire (`_clone_ep_drop_header_params`) | **TB-1b** (89a2d48) |
| resolver name-channel | 7 | getParameterNames() + value==basename -> the param NAME is the tainted string (the SQ-1/XS-1/CM-2 resolver shape), but the name-channel probe existed ONLY as the no-param fallback — every resolver endpoint WITH declared params never saw the marker ride a NAME | **TB-3a** (07d0db6) |
| header-tcid-VALUE | 4 | the servlet reads the VALUE of the header NAMED AFTER THE ENDPOINT'S OWN BASENAME (request.getHeader("<TCID>"), URL-decoded); reclassified live from "header-name" (01206's source reads getHeaders("<TCID>") — the VALUE, not the name) | **TB-3b** (c6d80f7) |
| cookie-value | 1 | the servlet scans request.getCookies() for the cookie NAMED AFTER THE ENDPOINT'S OWN BASENAME, URL-decodes its VALUE, and crosses it into the trusted store — the battery had no cookie channel (01876, the last of the 51) | **TB-3c** (cc142b3) |
| last-char MANGLE (cross-cutting) | 17 | the sink destroys EXACTLY ONE TRAILING CHAR of the marker before the trusted-store save (substring(0,len-1) drop — live on 01617 the plain probe reflects 'sentineltb1marke' — or StringBuilder.replace(len-1,len,'Z')): the exact-marker differential is structurally dead on every plain probe. Fix: the sacrificial-tail marker+zz pair (pass 2, only on channels whose plain pass missed — request economy); the mangler eats the tail and the UNTAILED marker survives verbatim so the existing needle checks pass unchanged; VR-25 replays a FRESH tailed marker through the same channel+variant | **TB-1c** (25cc789) |
| wrong-param-pick (cross-cutting) | (01617 family) | the servlet reads the trust-boundary param that is NEITHER first NOR segment-named (01617: spec declares [password, email, BenchmarkTest01617], the servlet reads the TCID-named THIRD param) — live: the first-param probe echoed the TCID param's ORIGINAL value while `?<TCID>=<marker>` was LIVE. Fix: every OTHER mutable param's VALUE joins the battery | **TB-2** (b33f2b7) |
| unexplained | 0 | — | — |

Honest live nuances on record (from the fix commits): this corpus's specs
DECLARE the TCID-named param/header/cookie on the 3b/3c families, so those
verify via channel=param+tail (the declared shape fires first in battery
order) — the header_tcid and cookie channels are the GENERAL fixes for the
undeclared shapes, proven by the spec-driven unit fixtures (crawl-discovered,
no declared params, only that channel can fire). The battery now covers every
diagnosed read channel: param (first+all), selfnamed, resolver_name,
segment_name (fallback), header_tcid, header_name, cookie — each with plain +
conditional sacrificial-tail variants and a channel-aware VR-25.

## Gates (this session, fresh)

- suite **4313/4313** (19/19 chunks; c00 preserved cached PASS 227/227 per
  the supervisor's order, the remaining 18 re-run fresh — one environmental
  port-squat by an orphaned test runner killed and retried, all green)
- doctor **17/17**
- bench ×3 **STRUCTURALLY IDENTICAL 38/0/0/37 F1=1.0000 @7161 requests**
  (the cm2_bench_structural.py hash — same count as the TB-3c record)

## Full-benchmark verdict (fresh 12-chunk run on the final engine cc142b3, this session)

| category | tp | fp | fn | tn | recall | precision |
|---|---|---|---|---|---|---|
| **trustbound** | **83** | **0** | **0** | 43 | **1.0000** | **1.0000** |
| sqli | 272 | 0 | 0 | 232 | 1.0000 | 1.0000 |
| xss | 246 | 0 | 0 | 209 | 1.0000 | 1.0000 |
| cmdi | 126 | 0 | 0 | 125 | 1.0000 | 1.0000 |
| crypto | 124 | 0 | 6 | 116 | 0.9538 | 1.0000 |
| hash | 115 | 0 | 14 | 107 | 0.8915 | 1.0000 |
| weakrand | 202 | 0 | 16 | 275 | 0.9266 | 1.0000 |
| pathtraver* | 116 | 0 | 17 | 135 | 0.8722 | 1.0000 |
| securecookie | 22 | 0 | 14 | 31 | 0.6111 | 1.0000 |
| ldapi | 13 | 0 | 14 | 32 | 0.4815 | 1.0000 |
| xpathi | 6 | 0 | 9 | 20 | 0.4000 | 1.0000 |

*pathtraver is outside the strict COVERED_CATEGORIES set of the eval
(the round-18 STATE wording listed it loosely; both numbers recorded here).

**OVERALL (covered):** TP=1209 FP=0 FN=73 TN=1190 — recall 0.9431,
precision 1.0000, F1 0.9707 (from 90.33% / 0.9492 at the cmdi close).
Cross-class findings 54 = 54 IDENTICAL. 1,498 active findings ALL VERIFIED,
zero rejected, FP 0 across ALL categories.

Per-chunk request counts (the real cost of the channel battery: 447,834 vs
the cmdi close's 390,703 = +57,131 for 7 channels × plain + conditional tail
× the corpus):

00000_00228 24,974 | 00229_00457 32,427 | 00458_00686 42,506 |
00687_00915 47,279 | 00916_01144 23,894 | 01145_01373 35,901 |
01374_01602 42,674 | 01603_01831 47,193 | 01832_02060 21,471 |
02061_02289 39,759 | 02290_02518 42,730 | 02519_02739 47,026

## Machine check

`tb_close_eval.py` (the cm_close_eval.py/xs_close_eval.py campaign-honesty
logic): merges the 12 fresh chunk JSONs (real request counts), re-evaluates
against expectedresults-1.2.csv, and strictly diffs against
`eval_cmdi_close_full.json`: trustbound must gain EXACTLY its 51 FNs (the
cmdi-close TP+FN union) with FN 0 / FP 0, every other category's TP/FP
counts AND test lists byte-identical, cross-class identical. Verdict:
**REGRESSION CHECK: PASS — zero regressions, trustbound closed** (rc=0).
One display-level bug live-caught and fixed during the close: the
cross-class comparison stringified in-memory tuples vs JSON-loaded lists
(`('a','b')` vs `['a','b']`) and printed a spurious DIFFERS on identical
data — both sides proven identical after round-trip, the compare normalized,
re-run clean IDENTICAL.

## Artifacts

- `build-v430/results/owsp/benchmark/benchmark_scan_tb_close.json` — the
  merged 12-chunk scan (447,834 requests, the canonical close measurement)
- `build-v430/results/owsp/benchmark/eval_tb_close_full.json` — the eval
  (per-category TP/FP/FN/TN + full test lists + cross-class register)
- per-chunk raw JSONs under `tool-results/bm_full_chunks/` (gitignored,
  session-local; the merged scan is the committed record)
- this report: `build-v430/results/owasp/trustbound_category_close.md`

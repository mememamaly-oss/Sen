# sqli Category Close — recall-push round (SQ-1 + SQ-2)

**Date:** 2026-10-12/13 (single session, rollback #18 recovered at start)
**Baseline:** origin/main a456942 (crypto close) — sqli 207 TP / 65 FN / 0 FP = 76.10% recall
**Result:** **272 TP / 0 FN / 0 FP = 100.00% recall, precision 1.0000** (full 12-chunk re-run, 348,193 requests, primitive-seeded specs)

## The 65 FNs — complete live root-cause taxonomy (diagnosed before any code)

| Family | Count | Root cause (live-proven) | Fix |
|---|---|---|---|
| resolver, non-callable | 34 | getParameterNames() value-match → the param **NAME** is interpolated; the nminj family was QUERY-gated while the whole family is POST **form body**; openapi form fields imported value-blank (the schema `default` IS the resolver sentinel); the name-channel VR rejected every catch on empty-result pages (tautology TRUE/FALSE both 200/19B) | **SQ-1** (bcf0163) |
| callable sink, value/header/cookie/query channel | 27 | `{call <param>}` dies as SQLSyntaxErrorException on BOTH the quote (malformed string) AND the '' pair control (unexpected token) — both error oracles structurally dead family-wide (zero callable TPs existed) | **SQ-2** (febb619) |
| resolver + callable | 4 | both of the above, plus: the base probe is dirty through no fault of the attacker (`{call whatever}` = unknown procedure) | **SQ-1 + SQ-2b** |
| unexplained | 0 | — | — |

## Fixes (each RED → GREEN → full gate → immediate individual push, ls-remote verified)

- **SQ-1 (bcf0163):** nminj gate extended to BODY params; openapi form-body schema default imported as the param value; name-channel VR error-based fallback (quote-NAMED reproduces a DB-error string + at least one valid-SQL control name clean — PATH-B discipline through the NAME channel). Live minispec: 00037/00038/00039 verified 3/3, TN twins silent.
- **SQ-2 (febb619):** `call_ctrl` probe (base-1; live `{call 1-1}` → 200) as the callable-aware valid-SQL control; db_error pair control becomes EITHER '' pair OR call_ctrl clean; an ABSENT call_ctrl never counts as clean (OWSP-13 control-2 regression live-caught by the suite mid-round and fixed in-loop); `nminj_call_ctrl` + the SQ-2b name-channel oracle for the overlap (the attacker-controlled base-1-NAMED staying clean is the honest degenerate guard when the resolved original name is itself an invalid callable). Live minispec: 00008 (header) / 01302 (form) / 01712 (raw-qs + URLDecoder) / 00996 (cookie) / 00590 / 01460 verified 6/6, TN twins silent.

Full patch code for both fixes is pasted verbatim in worklog.md (tasks 42/43) as the text backup.

## Full-benchmark verdict (fresh 12-chunk run, this session)

| category | tp | fp | fn | tn | recall | precision |
|---|---|---|---|---|---|---|
| **sqli** | **272** | **0** | **0** | 232 | **1.0000** | **1.0000** |
| crypto | 124 | 0 | 6 | 116 | 0.9538 | 1.0000 |
| hash | 115 | 0 | 14 | 107 | 0.8915 | 1.0000 |
| pathtraver | 116 | 0 | 17 | 135 | 0.8722 | 1.0000 |
| xss | 186 | 0 | 60 | 209 | 0.7561 | 1.0000 |
| weakrand | 202 | 0 | 16 | 275 | 0.9266 | 1.0000 |
| securecookie | 22 | 0 | 14 | 31 | 0.6111 | 1.0000 |
| cmdi | 75 | 0 | 51 | 125 | 0.5952 | 1.0000 |
| trustbound | 32 | 0 | 51 | 43 | 0.3855 | 1.0000 |
| ldapi | 13 | 0 | 14 | 32 | 0.4815 | 1.0000 |
| xpathi | 6 | 0 | 9 | 20 | 0.4000 | 1.0000 |

**Overall (covered): recall 76.37% → 81.67%, F1 0.8660 → 0.8991, precision 1.0000, FP 0 across ALL categories.**

- sqli +65 TP (the entire FN set, exactly as the two-family diagnosis predicted).
- securecookie +3 TP side-benefit (the openapi form-default import feeds its battery too).
- ZERO regressions: every other category byte-identical TP/FP to the baseline.
- Gates at each fix: suite 18/18 chunks (3869/3869 then 3870/3870 — the SQ-2 run FRESH on final code after the in-loop OWSP-13 absence-semantics fix), doctor 17/17, bench x3 IDENTICAL 38/0/0/37 F1=1.0000.

## Honest ceiling

sqli has NO remaining FNs on the OWASP Benchmark v1.2 (master). The two families closed:
resolver-shaped NAME-channel injection through POST form bodies (with callable-aware controls), and the CallableStatement sink family across all four input channels.

Cross-class findings: 54 (unchanged from baseline — all on vulnerable tests; the attribution note for the coming rounds stands).

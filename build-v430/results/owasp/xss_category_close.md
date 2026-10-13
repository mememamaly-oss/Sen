# xss Category Close — recall-push round (XS-1 + XS-2 + XS-3)

**Date:** 2026-10-13 (single session; full environment rollback recovered at start — local main reset to origin/main 8b10ec6 byte-identical per the sq0 protocol, stack rebuilt from scratch: Temurin JDK 21.0.12.1 + Maven 3.9.9 + BenchmarkJava master 8b67a88 CSV byte-identical + mvn package 4541 classes + cp.txt + plain-Tomcat9 assembly, boot+smoke GREEN)
**Baseline:** origin/main e5beb7a (sqli close) — xss 186 TP / 60 FN / 0 FP = 75.61% recall
**Result:** **246 TP / 0 FN / 0 FP = 100.00% recall, precision 1.0000** (full 12-chunk re-run on the XS-3 engine, 376,878 requests, primitive-seeded specs, 4170 findings, 1396 active ALL VERIFIED, zero rejected)

## The 60 FNs — complete live root-cause taxonomy (diagnosed before any code)

| Family | Count | Root cause (live-proven) | Fix |
|---|---|---|---|
| resolver, POST-form name-channel | 33 | the payload rides the param **NAME** via the `value==basename` sentinel read from `getParameterNames()` on the **FORM BODY**; the xname battery was QUERY-gated (the exact SQ-1 mirror) AND the generic loop attributed unmatched-name probes to `ep.parameters[0]` — candidates carried `parameter=answer` with no input_channel evidence, so the VR replayed the answer VALUE channel 0/6 → REJECTED family-wide | **XS-1** (1a3a97a) |
| last-char-mangle reflection | 27 | every source destroys EXACTLY ONE trailing char of the input before the writer sink (`substring(0,len-1)` drops it; `StringBuilder.replace(len-1,len,'Z')` rewrites it) — the verbatim needle check was structurally dead family-wide AND the VR's plain variant battery checked every vector verbatim (0/6 → REJECTED even when a candidate existed) | **XS-2** (d8faa3e) |
| resolver × mangle crossover | 1 (BenchmarkTest02324 — counted inside the 33 at classification; surfaced as the last FN on the first close re-run at 245/246) | a resolver (XS-1 family) whose sink ALSO rewrites the final char (XS-2 family): the plain xname probe dies (the canary's own last char is eaten) and the plain fresh-name-canary VR replay dies the same way | **XS-3** (8b10ec6) |
| unexplained | 0 | — | — |

## Fixes (each RED → GREEN → full gate → immediate individual push, ls-remote verified)

- **XS-1 (1a3a97a):** xname gate admits (QUERY, BODY); name-channel probes keep their OWN name via `_pseudo_param` (orchestrator + evidence replay) so the VR replays the channel the app actually reads. Live minispec: 00036/00549/00542/00547/00541/01438 verified 6/6 across every sink variant via fresh-name-canary; safe twins 00544/00545/00546 structurally discard the name and stay silent.
- **XS-2 (d8faa3e):** sacrificial-tail discipline — detector probes `needle+'zz'` (tail_full/tail_slash; the mangler eats the tail, the UNTAILED needle survives verbatim in the reflection; analyze() checks unchanged); VR gains the plain+tail tier (plain first, VR-02 semantics untouched; the tail tier only fires when plain is 0/6, each vector replaying as alt+'zz' checked as the untailed substring). Live minispec: 00392/00291/01666/02134/02395/00146 verified 6/6 across every channel (param/Referer/raw-QS/self-named); safe twins 00275/00885/00894 silent.
- **XS-3 (8b10ec6):** tailed name-channel probes (xname_tail_full/xname_tail_slash — canary+TAIL rides the NAME on the renamed clone, sentinel value preserved) + the tailed VR fallback (fresh+'zz' as the name, check the UNTAILED fresh as substring; plain first, existing semantics intact). Live minispec: 02324 VERIFIED; safe twins 00544 (resolver discard) + 00275 (mangle+encode) silent.

Full patch code for all three fixes is pasted verbatim in worklog.md (tasks 45/46/47) as the text backup.

## Full-benchmark verdict (fresh 12-chunk run on the final XS-3 engine, this session)

| category | tp | fp | fn | tn | recall | precision |
|---|---|---|---|---|---|---|
| **xss** | **246** | **0** | **0** | 209 | **1.0000** | **1.0000** |
| sqli | 272 | 0 | 0 | 232 | 1.0000 | 1.0000 |
| crypto | 124 | 0 | 6 | 116 | 0.9538 | 1.0000 |
| hash | 115 | 0 | 14 | 107 | 0.8915 | 1.0000 |
| weakrand | 202 | 0 | 16 | 275 | 0.9266 | 1.0000 |
| pathtraver | 116 | 0 | 17 | 135 | 0.8722 | 1.0000 |
| securecookie | 22 | 0 | 14 | 31 | 0.6111 | 1.0000 |
| cmdi | 75 | 0 | 51 | 125 | 0.5952 | 1.0000 |
| trustbound | 32 | 0 | 51 | 43 | 0.3855 | 1.0000 |
| ldapi | 13 | 0 | 14 | 32 | 0.4815 | 1.0000 |
| xpathi | 6 | 0 | 9 | 20 | 0.4000 | 1.0000 |

**Overall (covered): recall 81.67% → 86.35%, F1 0.8991 → 0.9267, precision 1.0000, FP 0 across ALL categories.**

- xss +60 TP (the entire FN set, exactly as the three-family diagnosis predicted — the TP set equals the sqli-close TP∪FN union exactly; no surprise TPs, no near-misses).
- ZERO regressions: every other category byte-identical TP/FP **and test lists** to the sqli-close baseline (machine-checked by scripts/owsp/xss/xs_close_eval.py); cross-class findings 54 → 54, identical set.
- Gates fresh this session on the final code: suite 19/19 chunks ALL PASS 4142/4142 (218 registered × 19 chunk runs; the 1 documented env-stall exclusion), doctor 17/17, bench x3 IDENTICAL 38/0/0/37 F1=1.0000.

## Honest ceiling

xss has NO remaining FNs on the OWASP Benchmark v1.2 (master). The three families closed: resolver-shaped NAME-channel reflection through POST form bodies (with input_channel-evidenced VR replay), last-char-mangle reflection (sacrificial-tail discipline on both the detector and the VR), and their crossover (tailed name-channel probes + the tailed VR fallback).

## Program scoreboard (recall at precision 1.0000, full ground truth)

| round | closed category | recall | F1 |
|---|---|---|---|
| GTP-12 (start) | — | 68.90% | 0.8159 |
| pathtraver close | pathtraver 87.22% | 69.81% | — |
| crypto close | crypto 95.38% | 76.37% | 0.8660 |
| sqli close | sqli 100.00% | 81.67% | 0.8991 |
| **xss close (this)** | **xss 100.00%** | **86.35%** | **0.9267** |

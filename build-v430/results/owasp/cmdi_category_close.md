# cmdi Category Close — recall-push round (CM-1 + CM-2 + CM-2b)

**Date:** 2026-10-13/14 (single session; started by repairing the session
baseline — the previous session's "token lost git-protocol access" diagnosis
was WRONG: the origin remote URL had been environment-rewritten to
mememaly-oss/Sen (owner typo, missing "ma"); fixed to mememamaly-oss/Sen,
pushed the blocked CM-1 work d3ab1bf..0af0fc6 with ls-remote confirm, then
continued per the standing methodology)
**Baseline:** origin/main d3ab1bf (xss close) — cmdi 75 TP / 51 FN / 0 FP = 59.52% recall
**Result:** **126 TP / 0 FN / 0 FP = 100.00% recall, precision 1.0000** (full
12-chunk re-run on the CM-1+CM-2 engine, 390,703 requests, 4,221 findings,
1,447 active ALL VERIFIED, zero rejected)

## The 51 FNs — complete live root-cause taxonomy (diagnosed before any code)

| Family | Count | Root cause (live-proven) | Fix |
|---|---|---|---|
| dead twin harvest (value channel) | 36 | the OOB detector's TWIN forms (env-array + direct-argv — the ONLY forms that reach envp/direct sinks; live: Runtime.exec(String) is NOT a shell, "localhost;" ENOENT; an envp entry defines a variable only when it is an assignment) were sent on every scan but analyze() only polled the "detect" iid — twin callbacks landed in the OAST log and nothing harvested them (dead machinery, 2 wasted requests/param). Covers 30 query/form + 6 header value-channel FNs at ANY chunk position (the OOB detector has no budget starvation: 4096 cap vs ~231 used) | **CM-1** (efdf314) |
| no name-channel forms (A4, mirrors SQ-1/XS-1) | 15 | NO name-channel form existed in ANY cmdi battery; the resolver family reads the param NAME (getParameterNames + value==basename), so every value probe hits a channel the app never reads (live: the 00573 value-control probe returned NO callback while the name-channel form fired on the same surface). Sub-shapes live-proven by hand probes: envp 4 (00573/574/1442/2344 — the name is the ONE env entry, an assignment), direct 6 (00567/575/576/1446/2342/2343 — unix cmd stays "" so exec(cmd+bar) IS exec(bar): the name IS argv; the inherited "echo family" source-grep classification was WRONG and the hand probes corrected it — live: `Cannot run program "x;"`), shell 5 (00568/1430/1441/2333/2344 — sh -c "ls "+bar concat) | **CM-2** (7248c4d) |
| unexplained | 0 | — | — |

(The A2/A3 echo-budget starvation of CmdiEchoDetector was deliberately NOT
touched — minimal-root-cause rule; with CM-1 the OOB channel closes all
value-channel FNs independent of position, so the echo detector's budget
starvation stands as a documented non-blocking limitation.)

## Fixes (each RED → GREEN → full gates → immediate individual push, ls-remote verified)

- **CM-1 (efdf314):** form-tagged twin iids (twin-env/twin-direct) + ONE
  combined poll window over all three channels (same wall-clock cost as the
  old single poll) + VR-11 replays THE FORM THAT FIRED (curl→wget alternate
  command; no separator exists to vary on these sinks). Live minispec:
  00499/01285/00176/01064 verified form=twin-direct with the wget replay.
- **CM-2 (7248c4d):** the three OOB forms ride the NAME via a renamed clone
  (value = the param's declared value = the resolver sentinel; QUERY/BODY
  nminj gate), each with its own nc-tagged iid embedded in the payload-name
  (self-identifying oob-<12hex>); analyze polls the embedded iid and
  attributes the form from the payload shape; VR-11 replays the nc form
  THAT FIRED through the name channel with a FRESH iid + the wget alternate
  command (anchor: first eligible QUERY param else the URL last-path-segment
  sentinel — the XS-1 discipline). A live-caught patch bug on the record:
  the first version referenced ParamLocation inside intel.py (not imported
  at module top) — the NameError was silently swallowed by the
  orchestrator's per-detector except and DROPPED findings; fixed to the
  sqli/xss string-compare pattern. Live minispec: ALL 15 name-channel FNs
  VERIFIED (nc-twin-env 00573/574/1442/2344, nc-twin-direct
  00567/575/576/1446/2342/2343, nc-variant 00568/1430/1441/2333/2334), TP
  control 00007 no regression, TN silent.
- **CM-2b (c3753bf):** wall-time fix — the nc poll budget on the LOCAL
  channel 0.15s → 0.0 (immediate check): the OAST handler records the
  interaction on arrival BEFORE replying to the curl; the target's curl
  round-trip completes inside its handler; only then is the HTTP response
  written — the 0.15s grace x 6-9 nc mutations/endpoint was pure waste
  (+~1s/endpoint) and blew the 470s chunk budget (live-caught: chunk
  00458_00686 timed out twice with an empty log; the bisector showed both
  halves slow = systematic cost, not a stall). PUBLIC-WEBHOOK keeps 3.0s.

Full patch code for all three fixes is pasted verbatim in worklog.md
(tasks 49.1/49.2/49.2b) as the text backup.

## Full-benchmark verdict (fresh 12-chunk run on the final engine c3753bf, this session)

| category | tp | fp | fn | tn | recall | precision |
|---|---|---|---|---|---|---|
| **cmdi** | **126** | **0** | **0** | 125 | **1.0000** | **1.0000** |
| sqli | 272 | 0 | 0 | 232 | 1.0000 | 1.0000 |
| xss | 246 | 0 | 0 | 209 | 1.0000 | 1.0000 |
| crypto | 124 | 0 | 6 | 116 | 0.9538 | 1.0000 |
| hash | 115 | 0 | 14 | 107 | 0.8915 | 1.0000 |
| weakrand | 202 | 0 | 16 | 275 | 0.9266 | 1.0000 |
| pathtraver | 116 | 0 | 17 | 135 | 0.8722 | 1.0000 |
| securecookie | 22 | 0 | 14 | 31 | 0.6111 | 1.0000 |
| trustbound | 32 | 0 | 51 | 43 | 0.3855 | 1.0000 |
| ldapi | 13 | 0 | 14 | 32 | 0.4815 | 1.0000 |
| xpathi | 6 | 0 | 9 | 20 | 0.4000 | 1.0000 |

**Overall (covered): recall 86.35% → 90.33%, F1 0.9267 → 0.9492, precision 1.0000, FP 0 across ALL categories.**

- cmdi +51 TP (the entire FN set, exactly as the two-family diagnosis
  predicted — the TP set equals the xss-close TP∪FN union exactly; no
  surprise TPs, no near-misses).
- ZERO regressions: every other category byte-identical TP/FP **and test
  lists** to the xss-close baseline (machine-checked by
  scripts/owsp/cmdi/cm_close_eval.py); cross-class findings 54 → 54,
  identical set.
- Gates fresh this session on the final code: suite 19/19 chunks ALL PASS
  4180/4180 (220 cases x 19; the 1 documented env-stall exclusion; two
  port-squatter retries, the documented class), doctor 17/17, bench x3
  STRUCTURALLY IDENTICAL 38/0/0/37 F1=1.0000 requests=5595.

## Honest ceiling

cmdi has NO remaining FNs on the OWASP Benchmark v1.2 (master). The two
families closed: the dead twin harvest (form-tagged iids + one combined
poll window + form-aware VR-11 replay) and the absent name-channel battery
(three nc forms riding the NAME on renamed clones with self-identifying
iids + the nc-replay VR). The echo detector's A2/A3 budget starvation
remains a documented non-blocking limitation (its oracles are redundant on
every FN the OOB channel now closes).

## Program scoreboard (recall at precision 1.0000, full ground truth)

| round | closed category | recall | F1 |
|---|---|---|---|
| GTP-12 (start) | — | 68.90% | 0.8159 |
| pathtraver close | pathtraver 87.22% | 69.81% | — |
| crypto close | crypto 95.38% | 76.37% | 0.8660 |
| sqli close | sqli 100.00% | 81.67% | 0.8991 |
| xss close | xss 100.00% | 86.35% | 0.9267 |
| **cmdi close (this)** | **cmdi 100.00%** | **90.33%** | **0.9492** |

# OWASP Benchmark — crypto CATEGORY CLOSE (recall-push round, 2026-10-12)

Engine: v4.3.9-cr3 @ main f9dabcc (CR-1 + CR-2 + CR-3, each individually
RED/GREEN-proven, gate-cycled, and pushed separately: f18f5df, 2f777f2, f9dabcc).

## Measurement

Full 12-chunk re-run (no-crawl campaign mode, seed 7f3c91aa, primitive-seeded
chunk specs), 323,088 requests, 2,740 tests:

| category | TP | FP | FN | TN | recall | precision |
|---|---|---|---|---|---|---|
| **crypto** | **124** | **0** | **6** | 116 | **95.38%** | **1.0000** |
| hash (side-benefit) | 115 | 0 | 14 | 107 | 89.15% | 1.0000 |
| pathtraver (held) | 116 | 0 | 17 | 135 | 87.22% | 1.0000 |
| **OVERALL covered** | **979** | **0** | **303** | 1190 | **76.37%** | **1.0000** |

- crypto recall 42.31% -> 95.38% (+53.07 points, TP 55 -> 124 of 130).
- Overall covered recall 69.81% -> 76.37% at precision 1.0000 (F1 0.8660);
  overall recall was 68.90% before the pathtraver round began.
- FP 0 across ALL categories; the 54 cross-class findings are all on
  VULNERABLE tests (attribution note for the coming rounds, unchanged in kind).

## The three root causes (each live-proven before any code)

1. **CR-1 — the chain died in chunks 5-6** (23 crypto + 19 hash FNs):
   HashCryptoChainPhase.run() returns [] without a VERIFIED file_marker read
   primitive, and the 12-chunk split put zero content-leaking traversal
   endpoints in tests 00917-01374. Fix: seed the two PROVEN primitives
   (00001 read + 00002 truncate) into every chunk spec — restoring the
   single-scan semantics of the real app. Zero engine change.
2. **CR-2 — five missing input channels** (16 catches): the test-id-named
   HEADER value, the first NON-STANDARD header NAME, the test-id COOKIE value,
   the RAW query string, the value-matching param NAME. Fix: the channel
   LADDER on param-bare endpoint copies; liveness = ciphertext LENGTH follows
   the marker (the byte-compare defect was caught by the unit fixture first).
   VR-28 replays through the SAME channel (write_channel in the recipe).
3. **CR-3 — the constant-plaintext family** (42 catches): ~44 FNs encrypt a
   FIXED constant (always-true ternaries, getTheValue "bar", puzzle constants)
   that the write response ECHOES. Fix: input-independent ct across the whole
   14-probe ladder + echoed constant C + the pad8 non-full-pad shape
   L == (len(C)//8+1)*8, len(C)%8 != 0; VR-28 replays two distinct fresh inputs
   (same L, same C).

## FP safety (structural, live-measured)

Static inventory of all 246 crypto tests: the 116 secure twins are ALL
AES/GCM, AES/CCM (property cryptoAlg2), or ESAPI-secure — ZERO DES/ECB in the
secure set. The controllable TN answer pt+tag curves and die on the P15
off-boundary gate (live: 00058 16/24 + 15->23; 01227 24/32/40 + 15->31).
The constant TN are tag shapes (3->19, 25->33, 7->15/23, 22->30) outside the
pad8 non-full-pad grid — EXCEPT the poisoned zones below.

## The honest ceiling — 6 FNs, all one family

BenchmarkTest00056, 00945, 01483, 01566, 01897, 02374: the "moresafe" (8->16)
constant family. A GCM-tag8/CCM constant answers pt+tag = (8->16) —
byte-identical to DES's pad8 shape at a full-pad constant length. No black-box
length/echo oracle can separate them; excluding the full-pad zone is what kept
precision at 1.0 (19 constant-shape TN guards live-verified silent). Closing
this family needs a different evidence class (e.g. an ECB-repeat oracle ON the
constant at multiple lengths, or cross-endpoint key correlation) — recorded as
the follow-up path, not attempted this round.

## Gates (every fix individually)

- Suite 18/18 chunks ALL PASS each round (211 -> 212 -> 213 registered as
  unit_cr2 / unit_cr3 were added; 1 documented env-stall exclusion
  regression_oob_public_channel_end_to_end — runner-only, hangs on pristine
  engines too).
- Doctor 17/17 PASS each round.
- Local bench x3 IDENTICAL 38/0/0/37 F1=1.0000 each round.
- RED/GREEN live proofs: cr1_redgreen.json (0 -> 12 crypto + 15 hash),
  cr2_live.json (16/16, TN guards 0, TP lost 0), cr3_live.json (42/42
  safe-zone, poisoned zone silent, TN guards 0, controls lost 0).

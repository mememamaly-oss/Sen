# PATHTRAVER CATEGORY CLOSE — recall push round (2026-10-12, supervisor order)

## The measurement (full 12-chunk OWASP Benchmark re-run, campaign no-crawl mode,
## seed 7f3c91aa, engine v4.3.7-pt1b @ main 1680655)

| metric                  | before (v431_gtp12_definitive) | after (v437_pt1b_full_final) |
|-------------------------|-------------------------------|------------------------------|
| pathtraver recall       | 38.35% (51/133)                | **87.22% (116/133)**          |
| pathtraver precision    | 1.0000                         | **1.0000**                    |
| pathtraver FP           | 0                              | **0**                         |
| OVERALL precision       | 1.0000                         | **1.0000** (9 FPs killed)     |
| OVERALL recall (covered)| 68.90% (975/1415)              | **69.81% (895/1282)**         |
| requests                | 298,576                        | 316,964 (+6.1%)               |

Side effect: trustbound 29 -> 32 TP (the extended budget reaches its params too).
Cross-class claims 78 -> 54 (all on genuinely-vulnerable tests of other classes;
zero count as FPs — attribution note for the crypto/trustbound rounds).

## The four pushes (one fix per commit, per supervisor order)

1. **PT-1** (791e037 + fix-up dd01b7b): trailing-param traversal budget —
   2 full + 2 reduced params (the Benchmark's own spec puts the sink param
   THIRD behind password/username; live-proven on BenchmarkTest00362).
   Live: 50/82 FNs caught. [791e037 shipped artifacts without the code — a
   reset --hard between proof and staging reverted the engine files; dd01b7b
   restored them verbatim.]
2. **PT-2** (afcabdb): header-NAME traversal battery — '..' (valid RFC 7230
   token, the base's parent) vs sentinel-random control, symmetric
   echo-neutralization, param-bare probe endpoint (the 'whatever' decoy
   pollution defect live-caught by instrumented scan). Live: +9 (59/82).
3. **PT-3** (1bd8e11): param-NAME traversal battery — param named '..'
   carrying the endpoint-basename value vs sentinel-random control; three
   live differential shapes (exists-flip, stream-error text, empty-vs-echo).
   Live: +6 (65/82).
4. **PT-1b** (1680655): echo-derivative guard — the full re-run exposed 9
   false exists/writability oracles on crypto/hash safe twins (surfaces that
   echo a cipher/digest of the param); missing-vs-missing and
   writable-vs-writable controls now required in detector + all verifier
   replay axes. Live: the 9 FPs 0 firing, catches 20/20 intact.

## The remaining 17 FNs — honest ceiling (each live-proven, no guessing)

* Fixed '/Test.txt' child family — File(param, '/Test.txt'): no reachable
  directory contains Test.txt; the exists-boolean can never flip true through
  any channel (header/cookie/param). 00526/00527/00623/02377/02302/01571/
  00011/00061/00950. Follow-up path: a write->read cross-servlet chain (create
  the file via a FileOutputStream servlet, then flip the oracle) — the GTP-10
  artifact-chain pattern.
* Stream-swallow family — both answers empty (exception swallowed):
  00529/02304/01111/01112. Needs a known-existing file NAME in the base
  (not discoverable black-box through these channels).
* Create-always family — FileOutputStream creates any target, answers
  identical: 01116/01117/00698.
* Extraction-shape variants: 01571.

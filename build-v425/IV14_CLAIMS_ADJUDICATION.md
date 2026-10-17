# IV14 — Adjudication of the Three Unreplicated SENTINEL Claims (2026-10-04)

Supervisor order 3 (2026-10-04): the IV13 independent round probed three
SENTINEL claims and could not reproduce them. This document settles each one
with raw evidence, and records what changed in the engine as a result.

**Toolchain independence:** stdlib `http.client`/`urllib` ONLY
(`scripts/iv14_claims.py`, `scripts/iv14_claims_gj.py`), zero SENTINEL code —
same discipline as IV13. Raw outputs verbatim:
`build-v423/results/iv14_evidence/{iv14_claims.json, iv14_claims_gj.json}`
(also `scripts/iv_out/`). Sanctioned test targets only. All timestamps
2026-10-03 20:43 UTC (IV14 probe window).

---

## C1 — ginandjuice.shop `/catalog?searchTerm` xss_reflected (GINJUICE F03)

**SENTINEL's claim (v4.2.1):** VERIFIED `re-test:fresh-ng-expression`
(conf 0.85) — "{{91*7}} reflected raw inside an ng-app page."

**IV14 verdict: FALSE POSITIVE — engine-fixed in v4.2.3 (DETECT-15/VR-14).**

Raw evidence (https direct; the app answers the bare-markup probes):

| probe | result |
|---|---|
| `{{91*7}}iv14ngmark` | 200, reflected RAW — **but only inside `<script>var searchText = '…';</script>`** (both occurrences: the script string + URL-encoded JSON map) |
| `<u>iv14tag</u>` | 200 — **NOT reflected raw** (escaped) |
| `iv14attr" onmouseover="alert(1)" x="` | 200 — not reflected raw |
| `iv14q';alert(1)//` and `iv14q";alert(1)//` | 200 — not reflected raw (quotes backslash-escaped) |
| `iv14cs</script><u>iv14raw</u>` | 200 — `<` escaped to `&lt;` **even inside the script string** (`var searchText = 'iv14cs&lt;/script&gt;…'`) |
| `iv14bs\';alert(1)//` | 200 — not reflected raw |

Why the claim is wrong: **AngularJS never interpolates `{{ }}` inside
`<script>` or `<style>` element content** — the $compile service binds
rendered text-node/attribute contexts only. The canary landed raw inside a JS
string literal on an ng-app page, which is NOT a binding context, and the
app's escaper neutralizes every breakout vector (quotes backslash-escaped,
angle brackets HTML-escaped including inside the script string). No client-side
code execution path exists through this parameter.

Engine fix (v4.2.3): `in_script_or_style()` context check in the detector
(DETECT-15) and in the fresh-ng-expression verification (VR-14) — an
{{expression}} reflection inside script/style content no longer produces a
candidate and can no longer verify. The genuine attribute-context ng
reflection on the same page (`/catalog?category`, GINJUICE F04) still fires
and still verifies (positive-control unit test).

---

## C2 — testasp.vulnweb.com `/Search.asp?tfSearch` sql_injection (TESTASP F02)

**SENTINEL's claim (v4.2.1):** VERIFIED `error:replay-2variants` (conf 0.9) —
evidence `status_oracle`: quote → HTTP 500 (generic IIS page, no DB string),
base → 200, doubled-quote → 200.

**IV14 verdict: the ENDPOINT is REAL SQLi — but SENTINEL's verification
CHANNEL was over-claiming. Both halves now corrected.**

Raw evidence (http; target state 2026-10-03 20:43 UTC — the IV13 window's
500-everything outage had recovered):

| probe | result |
|---|---|
| `tfSearch=1` | 200 / 4563 B |
| `tfSearch=1'` | **500 / 1208 B (generic IIS page)** |
| `tfSearch=1''` | 200 / 4585 B, reflected raw ("You searched for '1'''") |
| `tfSearch=1 AND 1=1` | 200 / 4603 B |
| `tfSearch=1 AND 1=2` | 200 / **5846 B** — **boolean body-differential** |
| `tfSearch=1 OR 1=1` | 200 / 4600 B |
| `<u>iv14x</u>` (XSS) | 200 / 4636 B — **reflected RAW** ("You searched for '<u>iv14x</u>'") |

So the endpoint carries a real boolean SQLi oracle (AND 1=1 vs AND 1=2 differ
by 1243 B) AND a genuine reflected XSS. The IV13 round's 500s were a transient
target outage, not a refutation — recorded honestly.

The over-claim: v4.2.2's PATH B accepted a **bare 5xx** on the quote replay as
"error reproduction" and VERIFIED CRITICAL SQLi with notes claiming "reproduce
DB error" while the evidence itself said "no DB string". Engine fix (v4.2.3,
VF-04): PATH B now requires an actual DB error STRING; a status-only signal
(DETECT-04 candidate) stays a visible CANDIDATE but never VERIFIES.

**Re-scan outcome (2026-10-03 22:27 UTC, run-e2a9fe4450 — honesty correction to
this document's original prediction):** the live v4.2.3 re-scan did NOT
reproduce the boolean differential inside its window — PATH A did not fire for
tfSearch and PATH B correctly refused to verify without a DB error string, so
tfSearch lands as a visible REJECTED candidate (status_oracle evidence
preserved, confidence 0.15). Relative to the IV14 ground truth this is a live
FALSE NEGATIVE of the precision-first trade-off (section 2.5 of STATE.md): the
endpoint is real (raw stdlib evidence above), the engine no longer over-claims
it, and the honest verification channel did not reproduce at scan time — the
same target-drift phenomenon this document's methodological note describes.
Related correction on the same re-scan: Login.asp `tfUName` REJECTED as
predicted below, but `tfUPass` VERIFIED — through `oracle:or-bodydiff-2round`,
a REAL boolean body-differential oracle that fired live. So tfUPass was real
SQLi all along (the v4.2.1 VERIFIED verdict happened to be right, but through
the over-claiming PATH B channel; v4.2.3 re-verifies it through a genuine
oracle — the honest channel).

---

## C3 — testasp.vulnweb.com `/Templatize.asp?item` path_traversal (TESTASP F06)

**SENTINEL's claim (v4.2.1):** VERIFIED `re-test:same-marker-alt-depth`
(conf 0.9) — "content of win.ini leaked (marker '[fonts]' at offset 1905)".

**IV14 verdict: REAL — reconfirmed with byte-exact offsets.**

Raw evidence (http; 2026-10-03 20:43 UTC):

| probe | result |
|---|---|
| `item=html/about.html` (base page) | 200 / 4594 B — **no `[fonts]` marker anywhere** (marker-soundness control) |
| `item=..%2F..%2F..%2F..%2Fwindows%2Fwin.ini` | 200 / **2783 B, `[fonts]` at offset 1905** |
| `item=..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fwin.ini` | 200 / 2827 B, `[fonts]` at offset **1949** |
| `item=../../../../windows/win.ini` (plain ../) | 200 / 2763 B, `[fonts]` at offset 1885 — the PLAIN shape works too on this stack |
| `item=..%2F..%2F..%2F..%2Fetc%2Fpasswd` | 500 (generic IIS) — the /etc/passwd read fails on this Windows host (honest negative) |

The scan-time evidence chain said "[fonts] at offset 1905" (4-up) and "at
offset 1949" (6-up). The IV14 re-probe reproduces **offset 1905 at 4-up and
1949 at 6-up — byte-exact agreement with the frozen v4.2.1 journal**. The
IV13 round's 500s were the same transient outage window as C2. The claim
stands as VERIFIED; no engine change needed for the param-bound battery.

---

## Summary table

| claim | IV13 status | IV14 verdict | engine action (v4.2.3) |
|---|---|---|---|
| ginandjuice `/catalog?searchTerm` XSS (ng) | not reproduced | **false positive** (script-string context, no breakout) | DETECT-15 + VR-14: script/style context excluded from ng claims |
| testasp `/Search.asp?tfSearch` SQLi | not reproduced (target 500s) | **endpoint REAL** (boolean oracle + reflected XSS both reconfirmed); SENTINEL's verification channel was over-claiming | VF-04: PATH B requires a DB error string; live re-scan lands it as a visible REJECTED candidate (honest FN, trade-off section 2.5) |
| testasp `/Templatize.asp?item` traversal | not reproduced (target 500s) | **REAL** — byte-exact offset match with the frozen scan journal | none needed (marker-soundness control added to the probe record) |

Methodological note (honest): a probe round that cannot reproduce a claim has
NOT refuted it — targets drift (this one flapped inside a single day: the v4.2.2
addendum documents three windows for doLogin; IV13's 500-window vs IV14's
recovery is the same phenomenon on testasp). The correct response to a
non-reproduction is a re-probe in a different window plus a mechanism-level
check of the engine's evidence — exactly what this round did.

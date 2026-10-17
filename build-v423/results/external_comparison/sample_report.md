# External-Verifier vs SENTINEL — Comparison Report

External list: `examples/external_verifier_sample.json`
SENTINEL scans: `build-v421/results/live_v421/ginjuice.json`, `build-v421/results/live_v421/testasp.json`, `build-v421/results/live_v421/testaspnet.json`, `build-v421/results/live_v421/gruyere.json`, `build-v422/results/live_v422/testfire.json`

This tool MATCHES lists; it never adjudicates correctness.
CONFIRMED = the two lists agree (still engine-self-judged on SENTINEL's side).

## (a) GAPS — external found, SENTINEL did not [4]
- **sql_injection** @ ginandjuice.shop/login — external row: {"target": "https://ginandjuice.shop", "type": "SQL Injection", "url": "/login", "notes": "external found an injection we did NOT list — should land in GAPS"}
- **sql_injection** @ testasp.vulnweb.com/listagents.aspx param `a` — external row: {"target": "http://testasp.vulnweb.com", "type": "Blind SQLi", "url": "/listagents.aspx", "param": "a", "notes": "time-based, external-only — GAPS"}
- **path_traversal** @ testasp.vulnweb.com/showthread.asp — external row: {"target": "http://testasp.vulnweb.com", "type": "path traversal", "url": "/showthread.asp", "notes": "path-aware matching demo: same class as SENTINEL's testasp traversal but a DIFFERENT path (SENTINEL found Templatize.asp) — must land in GAPS, not false-confirm at class level"}
- **ssti** @ google-gruyere.appspot.com/snippets.gtl — external row: {"target": "google-gruyere.appspot.com", "type": "SSTI", "url": "/snippets.gtl", "notes": "external claims template injection (SENTINEL engine-REJECTED it; rejected candidates are not in the strong list — this lands in GAPS honestly, with the rejection visible in the frozen package)"}

## (b) UNCONFIRMED — SENTINEL found, external did not [18]
- **xss_reflected** @ ginandjuice.shop/catalog param `searchterm` [verified, run run-d2edb73a27, ginjuice.json]
- **xss_reflected** @ ginandjuice.shop/catalog param `category` [verified, run run-d2edb73a27, ginjuice.json]
- **xss_dom** @ ginandjuice.shop/blog param `search` [verified, run run-d2edb73a27, ginjuice.json]
- **http_response_header_injection** @ ginandjuice.shop/catalog param `category` [verified, run run-d2edb73a27, ginjuice.json]
- **open_redirect** @ ginandjuice.shop/blog param `search` [verified, run run-d2edb73a27, ginjuice.json]
- **sql_injection** @ testasp.vulnweb.com/showforum.asp param `id` [verified, run run-e2a9fe4450, testasp.json]
- **sql_injection** @ testasp.vulnweb.com/Search.asp param `tfsearch` [verified, run run-e2a9fe4450, testasp.json]
- **sql_injection** @ testasp.vulnweb.com/Login.asp param `tfuname` [verified, run run-e2a9fe4450, testasp.json]
- **sql_injection** @ testasp.vulnweb.com/Login.asp param `tfupass` [verified, run run-e2a9fe4450, testasp.json]
- **sql_injection** @ testasp.vulnweb.com/showthread.asp param `id` [verified, run run-e2a9fe4450, testasp.json]
- **path_traversal** @ testasp.vulnweb.com/Templatize.asp param `item` [verified, run run-e2a9fe4450, testasp.json]
- **xss_reflected** @ testasp.vulnweb.com/Search.asp param `tfsearch` [verified, run run-e2a9fe4450, testasp.json]
- **sql_injection** @ testaspnet.vulnweb.com/Comments.aspx param `id` [verified, run run-3d6cf53f93, testaspnet.json]
- **sql_injection** @ testaspnet.vulnweb.com/ReadNews.aspx param `id` [verified, run run-3d6cf53f93, testaspnet.json]
- **xss_reflected** @ demo.testfire.net/index.jsp param `content` [verified, run run-6a6418ab8d, testfire.json]
- **xss_reflected** @ demo.testfire.net/search.jsp param `query` [verified, run run-6a6418ab8d, testfire.json]
- **xss_reflected** @ demo.testfire.net/sendFeedback param `name` [verified, run run-6a6418ab8d, testfire.json]
- **xss_reflected** @ demo.testfire.net/sendFeedback param `email_addr` [verified, run run-6a6418ab8d, testfire.json]

## (c) CONFIRMED by both [5]
- **sql_injection** @ ginandjuice.shop/catalog param `category` — match level EXACT | SENTINEL: verified, run run-d2edb73a27
- **xxe** @ ginandjuice.shop/catalog/product/stock param `productid` — match level STRONG | SENTINEL: verified, run run-d2edb73a27
- **csrf** @ ginandjuice.shop/catalog/cart param `productid, redir, quantity` — match level STRONG | SENTINEL: verified, run run-d2edb73a27
- **sql_injection** @ demo.testfire.net/doLogin param `uid` — match level EXACT | SENTINEL: verified, run run-6a6418ab8d
- **xss_reflected** @ google-gruyere.appspot.com/530506698111053146050861906974275631884/snippets.gtl param `uid` — match level CLASS | SENTINEL: verified, run run-228ffb67c9

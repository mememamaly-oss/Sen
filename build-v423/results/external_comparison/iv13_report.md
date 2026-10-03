# External-Verifier vs SENTINEL — Comparison Report

External list: `build-v422/results/external_comparison/iv13_external_list.json`
SENTINEL scans: `build-v422/results/live_v421/ginjuice.json`, `build-v422/results/live_v421/testfire.json`, `build-v422/results/live_v421/testasp.json`, `build-v422/results/live_v421/testaspnet.json`, `build-v422/results/live_v421/gruyere.json`, `build-v422/results/live_v422/testfire.json`

This tool MATCHES lists; it never adjudicates correctness.
CONFIRMED = the two lists agree (still engine-self-judged on SENTINEL's side).

## (a) GAPS — external found, SENTINEL did not [4]
- **xss_reflected** @ testaspnet.vulnweb.com/Comments.aspx param `tbcomment` — external row: {"target": "testaspnet.vulnweb.com", "type": "Cross-Site Scripting", "url": "/Comments.aspx", "param": "tbComment", "notes": "IV13-CONFIRMED STORED XSS. Comment 'IV13 verification <u>zxK1mQ7v</u>' (benign marker) posted via the real form (session cookies + full untruncated __VIEWSTATE); page reload renders it RAW: <DIV class=\"CommentText\">IV13 verification <u>zxK1mQ7v</u></DIV>. Unescaped markup storage => arbitrary script injection. (Note: request validation does NOT cover this POST body path.)"}
- **path_traversal** @ google-gruyere.appspot.com/399537805906358592369366415027868878530/..%2f..%2f..%2f..%2fetc%2fpasswd param `url path` — external row: {"target": "google-gruyere.appspot.com", "type": "Path Traversal", "url": "/399537805906358592369366415027868878530/..%2f..%2f..%2f..%2fetc%2fpasswd", "param": "URL path", "notes": "IV13-CONFIRMED arbitrary file read. GET /<inst>/..%2f..%2f..%2f..%2fetc%2fpasswd -> 200, 246B, real /etc/passwd content ('root:x:0:0:root:/root:/bin/sh daemon:...'). Instance created via sanctioned /start launcher."}
- **xss_reflected** @ google-gruyere.appspot.com/399537805906358592369366415027868878530/saveprofile param `uid` — external row: {"target": "google-gruyere.appspot.com", "type": "Cross-Site Scripting", "url": "/399537805906358592369366415027868878530/saveprofile", "param": "uid", "notes": "IV13-CONFIRMED STORED XSS via signup. GET /<inst>/saveprofile?action=new&uid=iv13<u>m</u> -> account created; home page renders the uid RAW in the menu-user welcome ('iv13&lt;u&gt;m&lt;/u&gt; &lt;iv13<u>m</u>&gt;'). Cookie GRUYERE=67913603|iv13<u>m</u>||author carries the raw uid and an UNSIGNED role field (client-state manipulation surface observed, privilege escalation not fully exploited)."}
- **xss_reflected** @ google-gruyere.appspot.com/399537805906358592369366415027868878530/snippets.gtl param `uid` — external row: {"target": "google-gruyere.appspot.com", "type": "Reflected XSS", "url": "/399537805906358592369366415027868878530/snippets.gtl", "param": "uid", "notes": "IV13-CONFIRMED. GET /<inst>/snippets.gtl?uid=<u>iv13rm</u> -> value reflected RAW inside <h2 class='has-refresh' id=\"user_name\"><u>iv13rm</u></h2>. Unescaped reflection in HTML body context."}

## (b) UNCONFIRMED — SENTINEL found, external did not [17]
- **sql_injection** @ ginandjuice.shop/catalog param `category` [verified, run run-d2edb73a27, ginjuice.json]
- **xss_reflected** @ ginandjuice.shop/catalog param `searchterm` [verified, run run-d2edb73a27, ginjuice.json]
- **xss_reflected** @ ginandjuice.shop/catalog param `category` [verified, run run-d2edb73a27, ginjuice.json]
- **xss_dom** @ ginandjuice.shop/blog param `search` [verified, run run-d2edb73a27, ginjuice.json]
- **http_response_header_injection** @ ginandjuice.shop/catalog param `category` [verified, run run-d2edb73a27, ginjuice.json]
- **open_redirect** @ ginandjuice.shop/blog param `search` [verified, run run-d2edb73a27, ginjuice.json]
- **xss_reflected** @ demo.testfire.net/index.jsp param `content` [verified, run run-6a6418ab8d, testfire.json]
- **xss_reflected** @ demo.testfire.net/search.jsp param `query` [verified, run run-6a6418ab8d, testfire.json]
- **xss_reflected** @ demo.testfire.net/sendFeedback param `name` [verified, run run-6a6418ab8d, testfire.json]
- **xss_reflected** @ demo.testfire.net/sendFeedback param `email_addr` [verified, run run-6a6418ab8d, testfire.json]
- **sql_injection** @ testasp.vulnweb.com/Search.asp param `tfsearch` [verified, run run-e2a9fe4450, testasp.json]
- **sql_injection** @ testasp.vulnweb.com/Login.asp param `tfuname` [verified, run run-e2a9fe4450, testasp.json]
- **sql_injection** @ testasp.vulnweb.com/Login.asp param `tfupass` [verified, run run-e2a9fe4450, testasp.json]
- **sql_injection** @ testasp.vulnweb.com/showthread.asp param `id` [verified, run run-e2a9fe4450, testasp.json]
- **path_traversal** @ testasp.vulnweb.com/Templatize.asp param `item` [verified, run run-e2a9fe4450, testasp.json]
- **xss_reflected** @ testasp.vulnweb.com/Search.asp param `tfsearch` [verified, run run-e2a9fe4450, testasp.json]
- **xss_reflected** @ google-gruyere.appspot.com/530506698111053146050861906974275631884/snippets.gtl param `uid` [verified, run run-228ffb67c9, gruyere.json]

## (c) CONFIRMED by both [6]
- **sql_injection** @ demo.testfire.net/doLogin param `uid` — match level EXACT | SENTINEL: verified, run run-6a6418ab8d
- **csrf** @ ginandjuice.shop/catalog/cart param `productid, redir, quantity` — match level STRONG | SENTINEL: verified, run run-d2edb73a27
- **xxe** @ ginandjuice.shop/catalog/product/stock param `productid` — match level STRONG | SENTINEL: verified, run run-d2edb73a27
- **sql_injection** @ testasp.vulnweb.com/showforum.asp param `id` — match level EXACT | SENTINEL: verified, run run-e2a9fe4450
- **sql_injection** @ testaspnet.vulnweb.com/Comments.aspx param `id` — match level EXACT | SENTINEL: verified, run run-3d6cf53f93
- **sql_injection** @ testaspnet.vulnweb.com/ReadNews.aspx param `id` — match level EXACT | SENTINEL: verified, run run-3d6cf53f93

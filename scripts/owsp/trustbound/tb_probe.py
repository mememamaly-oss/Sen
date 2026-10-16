#!/usr/bin/env python3
"""TB diagnosis round — hand probes (stdlib-only, zero engine code): prove the
per-family channel design on the RUNNING stack BEFORE any engine patch.
Families: (a) self-named VALUE `?TCID=<marker>` (tcid-value + raw-query-string
reads), (b) header-NAME channel, (c) first-param-pick wrong (01617 reads the
TCID-named 3rd param), (d) last-char mangle (the exact-marker check dies)."""
import urllib.request, urllib.parse, re

BASE = "http://127.0.0.1:8080/benchmark"
M1, M2 = "sentineltb1marker", "sentineltb2marker"
TAIL = "zz"

def post(url, marker, shape, tcid):
    if shape == "selfnamed":        # ?TCID=<marker>  (query string on the POST)
        qs = urllib.parse.urlencode({tcid: marker})
        req = urllib.request.Request(f"{url}?{qs}", data=b"", method="POST")
    elif shape == "headername":     # a header NAMED <marker>
        req = urllib.request.Request(url, data=b"", method="POST")
        req.add_header(marker, "x")
    elif shape == "firstparam":     # the marker as the FIRST declared param value
        body = urllib.parse.urlencode({"password": marker, "email": "e", tcid: "orig"})
        req = urllib.request.Request(url, data=body.encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    elif shape == "selfnamed-tail": # ?TCID=<marker+zz> — the mangle eats the tail
        qs = urllib.parse.urlencode({tcid: marker + TAIL})
        req = urllib.request.Request(f"{url}?{qs}", data=b"", method="POST")
    elif shape == "resolvername":   # ?<marker>=<TCID> — the resolver takes the NAME
        qs = urllib.parse.urlencode({marker: tcid})
        req = urllib.request.Request(f"{url}?{qs}", data=b"", method="POST")
    elif shape == "resolvername-tail":  # ?<marker+zz>=<TCID>
        qs = urllib.parse.urlencode({marker + TAIL: tcid})
        req = urllib.request.Request(f"{url}?{qs}", data=b"", method="POST")
    elif shape == "headertcid":     # a header NAMED <TCID> carrying the marker
        req = urllib.request.Request(url, data=b"", method="POST")
        req.add_header(tcid, marker)
    elif shape == "headertcid-tail":
        req = urllib.request.Request(url, data=b"", method="POST")
        req.add_header(tcid, marker + TAIL)
    elif shape == "cookie":         # a cookie NAMED <TCID> carrying the marker
        req = urllib.request.Request(url, data=b"", method="POST")
        req.add_header("Cookie", f"{tcid}={urllib.parse.quote(marker)}")
    elif shape == "cookie-tail":
        req = urllib.request.Request(url, data=b"", method="POST")
        req.add_header("Cookie", f"{tcid}={urllib.parse.quote(marker + TAIL)}")
    try:
        r = urllib.request.urlopen(req, timeout=10)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")

CASES = [
    ("00031 map-read  ", "trustbound-00/BenchmarkTest00031", "BenchmarkTest00031", ["selfnamed"]),
    ("01617 3rd-param ", "trustbound-00/BenchmarkTest01617", "BenchmarkTest01617", ["firstparam", "selfnamed-tail"]),
    ("00251 headername", "trustbound-00/BenchmarkTest00251", "BenchmarkTest00251", ["headername"]),
    ("02622 raw-qs    ", "trustbound-01/BenchmarkTest02622", "BenchmarkTest02622", ["selfnamed"]),
    ("00427 tcid+mangle", "trustbound-00/BenchmarkTest00427", "BenchmarkTest00427", ["selfnamed", "selfnamed-tail"]),
    # the fix-round hand-probes (the worklog's planned session-start act):
    ("00587 resolver  ", "trustbound-00/BenchmarkTest00587", "BenchmarkTest00587", ["resolvername"]),
    ("00588 resol+mang", "trustbound-00/BenchmarkTest00588", "BenchmarkTest00588", ["resolvername", "resolvername-tail"]),
    ("01082 hdr-tcid  ", "trustbound-00/BenchmarkTest01082", "BenchmarkTest01082", ["headertcid", "headertcid-tail"]),
    ("01206 hdrtcid+m ", "trustbound-00/BenchmarkTest01206", "BenchmarkTest01206", ["headertcid", "headertcid-tail"]),
    ("01876 cookie+m  ", "trustbound-01/BenchmarkTest01876", "BenchmarkTest01876", ["cookie", "cookie-tail"]),
]
CTX = re.compile(r"saved in session|stored in session|put in session|session attribute", re.I)
print(f"{'case':<18} {'shape':<15} {'M1?':<5} {'M2?':<5} {'ctx?':<5} verdict")
for label, path, tcid, shapes in CASES:
    for shape in shapes:
        s1, b1 = post(f"{BASE}/{path}", M1, shape, tcid)
        s2, b2 = post(f"{BASE}/{path}", M2, shape, tcid)
        hit1 = M1 in b1
        hit2 = M2 in b2
        i = max(b1.find(M1), b1.find(M1[:-1]))
        ctx = bool(i >= 0 and CTX.search(b1, max(0, i-100), i+160))
        verdict = "CHANNEL LIVE" if (hit1 and hit2 and ctx) else (
            "reflect-no-ctx" if (hit1 and hit2) else "dead")
        print(f"{label:<18} {shape:<15} {str(hit1):<5} {str(hit2):<5} {str(ctx):<5} {verdict}"
              + (f"  core={M1[:-1] in b1} body[:60]={b1[:60]!r}" if verdict != "CHANNEL LIVE" else ""))

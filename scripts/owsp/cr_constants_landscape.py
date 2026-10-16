#!/usr/bin/env python3
"""Task 40 — CLEAN re-measurement of the constant-family landscape (CR-3 design data).

Robust artifact parser (the ESAPI line-wrap broke the old one) + full channel
battery per test. For every crypto test (TP/FN/TN all 246):
  - try channels: form-testid, header-testid, header-name, cookie, qs, valmatch
    with a 16B marker 'C'*16 (and 'D'*16 confirm)
  - verdict CONTROLLED if echo contains the marker (case-insensitive) or ct
    length follows the marker; else CONSTANT with (echo, ct_len)
Output: tool-results/cr_constants_landscape.json + disjointness table.
"""
import json, re, base64, urllib.request, urllib.parse
from collections import Counter

BASE = "http://localhost:8080/benchmark"
ART = "/home/z/tools/benchmark/testfiles/passwordFile.txt"
EVAL = "/home/z/my-project/build-v430/results/owsp/benchmark/eval_v437_pt1b_full_final.json"
INV = "/home/z/my-project/tool-results/cr_cipher_inventory.json"
OUT = "/home/z/my-project/tool-results/cr_constants_landscape.json"

ev = json.load(open(EVAL))
cc = ev["per_category"]["crypto"]
fn_ids = sorted(t.replace("BenchmarkTest", "") for t in cc["fn_tests"])
tp_ids = sorted(t.replace("BenchmarkTest", "") for t in cc["tp_tests"])
csv_rows = [l.split(",") for l in open(
    "/home/z/my-project/build-v430/results/owsp/benchmark/expectedresults-1.2.csv").read().splitlines() if l]
all_crypto = {r[0].replace("BenchmarkTest", "") for r in csv_rows if len(r) > 2 and r[1] == "crypto"}
tn_ids = sorted(all_crypto - set(fn_ids) - set(tp_ids))
inv = json.load(open(INV))

def url_for(num):
    src = f"/home/z/tools/benchmark/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest{num}.java"
    m = re.search(r'@WebServlet\(value\s*=\s*"([^"]+)"', open(src).read())
    return BASE + m.group(1)

def fresh_ct():
    """ROBUST: after truncate there is exactly ONE value in the file.
    Take everything after the last 'secret_value=' (or 'hash_value='), strip ALL
    whitespace (ESAPI wraps at 76 cols), decode."""
    try:
        txt = open(ART, "rb").read().decode("utf-8", "replace")
    except FileNotFoundError:
        return None
    for pref in ("secret_value=", "hash_value="):
        i = txt.rfind(pref)
        if i >= 0:
            seg = re.sub(r"\s+", "", txt[i + len(pref):])
            if seg:
                try:
                    return base64.b64decode(seg + "=" * (-len(seg) % 4))
                except Exception:
                    return None
    return None

def send(num, marker, channel):
    tid = f"BenchmarkTest{num}"
    url = url_for(num)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = None
    if channel == "form":
        data = urllib.parse.urlencode({tid: marker})
    elif channel == "header":
        headers[tid] = marker
    elif channel == "hdrname":
        headers[marker] = "x"
    elif channel == "cookie":
        headers["Cookie"] = f"{tid}={urllib.parse.quote(marker)}"
    elif channel == "qs":
        url += "?" + urllib.parse.urlencode({tid: marker})
        data = ""
    elif channel == "valmatch":
        data = urllib.parse.urlencode({marker: tid})
    req = urllib.request.Request(url, data=(data.encode() if data is not None else None),
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, f"{type(e).__name__}"

CHANNELS = ["form", "header", "hdrname", "cookie", "qs", "valmatch"]

def battery(num):
    tid = f"BenchmarkTest{num}"
    res = {"num": num}
    # 1) channel battery with C-marker (P16) — CONTROLLED?
    for ch in CHANNELS:
        open(ART, "w").close()
        code, body = send(num, "C" * 16, ch)
        ct = fresh_ct()
        echo = ""
        m = re.search(r"Sensitive value: '([^']*)'", body or "")
        if m:
            echo = m.group(1)
        controlled = ("cccccccccccccccc" in echo.lower()) or (
            ct is not None and len(ct) not in (8, 16, 24, 32, 40, 48, 64, 72)) or False
        res[ch] = {"echo": echo[:40], "ct": None if ct is None else len(ct)}
        if "cccccccccccccccc" in echo.lower():
            res["controlled_channel"] = ch
            break
    # 2) if not echo-controlled: length-follow check on the best channel (form)
    if "controlled_channel" not in res:
        lens = []
        for mk in ("C" * 8, "C" * 16, "C" * 24, "C" * 64):
            open(ART, "w").close()
            send(num, mk, "form")
            ct = fresh_ct()
            lens.append(None if ct is None else len(ct))
        res["form_lens"] = lens
        if len(set(l for l in lens if l is not None)) > 1:
            res["controlled_channel"] = "form-len"
    # 3) constant measurement (2 probes, same channel, different junk)
    if "controlled_channel" not in res:
        open(ART, "w").close()
        code, body = send(num, "qqqqqqqqqqqqqqqq", "form")
        ct1 = fresh_ct()
        echo1 = ""
        m = re.search(r"Sensitive value: '([^']*)'", body or "")
        if m: echo1 = m.group(1)
        open(ART, "w").close()
        code, body = send(num, "zzzzzzzzzzzzzzzz", "form")
        ct2 = fresh_ct()
        res["const"] = {"echo": echo1[:40], "ct1": None if ct1 is None else len(ct1),
                        "ct2": None if ct2 is None else len(ct2)}
    return res

rows = []
for grp, ids in (("FN", fn_ids), ("TN", tn_ids), ("TP", tp_ids)):
    for n in ids:
        r = battery(n)
        r["grp"] = grp
        r["cipher"] = inv[grp].get(n, ["?", "?"])[0]
        rows.append(r)
    print(f"--- {grp} done ({len(ids)}) ---")

print("\n=== CONSTANT LANDSCAPE (len(C), ct_len) by group ===")
for grp in ("FN", "TN", "TP"):
    consts = [r for r in rows if r["grp"] == grp and "const" in r and r["const"]["ct1"] is not None]
    pairs = Counter()
    for r in consts:
        C = r["const"]["echo"]
        pairs[(len(C), r["const"]["ct1"])] += 1
    print(f"\n{grp} constants: {len(consts)}")
    for (lc, L), n in sorted(pairs.items()):
        print(f"   len(C)={lc:3d} -> ct={L:3d}  (x{n})  [DES-pad8={'YES' if L == (lc//8+1)*8 else 'no'}]")

print("\n=== FN constants: full detail ===")
for r in rows:
    if r["grp"] == "FN" and "const" in r:
        print(f"  {r['num']} {r['cipher'][:22]:22s} echo={r['const']['echo'][:28]!r:30s} len={len(r['const']['echo']):2d} ct={r['const']['ct1']}")

print("\n=== CONTROLLED map (FN) ===")
for r in rows:
    if r["grp"] == "FN" and "controlled_channel" in r:
        print(f"  {r['num']} {r['cipher'][:22]:22s} via {r['controlled_channel']}")

json.dump(rows, open(OUT, "w"), indent=1)
print("\nwritten:", OUT)

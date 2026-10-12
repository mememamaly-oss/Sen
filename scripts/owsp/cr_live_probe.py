#!/usr/bin/env python3
"""Task 40 — LIVE manual probe battery for the crypto FN families (red-team,
zero engine code). Must run while the stack is UP (same call as cr_stack_boot).

For each of the 75 FN + TN constants + TP controls:
  - send the SHAPE-APPROPRIATE marker probe(s) (P8/P16 = 8/16 known bytes)
  - read the fresh secret_value line straight off the local artifact file
  - record: echoed plaintext, ciphertext byte length, control verdict

Verdicts:
  CONTROLLED  : ct length follows the marker length (8->16B, 16->24B on DES)
  CONSTANT    : ct length ignores input; echo reveals the constant
  DEAD        : no fresh artifact line (write leg never happened)
"""
import json, re, base64, urllib.request, urllib.parse, os, sys
from collections import Counter

BASE = "http://localhost:8080/benchmark"
ART = "/home/z/tools/benchmark/testfiles/passwordFile.txt"
EVAL = "/home/z/my-project/build-v430/results/owsp/benchmark/eval_v437_pt1b_full_final.json"
SHAPES = "/home/z/my-project/tool-results/cr_final_plaintext.json"
SPEC = "/home/z/tools/benchmark/data/openapi.yaml"
OUT = "/home/z/my-project/tool-results/cr_live_probes.json"

P8, P16 = "B" * 8, "A" * 16
ev = json.load(open(EVAL))
cc = ev["per_category"]["crypto"]
fn_ids = sorted(t.replace("BenchmarkTest", "") for t in cc["fn_tests"])
tp_ids = sorted(t.replace("BenchmarkTest", "") for t in cc["tp_tests"])[:15]
shapes = json.load(open(SHAPES))
shape_of = {r["num"]: r for r in shapes["fn"]}
csv_rows = [l.split(",") for l in open(
    "/home/z/my-project/build-v430/results/owsp/benchmark/expectedresults-1.2.csv").read().splitlines() if l]
all_crypto = {r[0].replace("BenchmarkTest", "") for r in csv_rows if len(r) > 2 and r[1] == "crypto"}
tn_ids = sorted(all_crypto - set(fn_ids) - set(tp_ids))

# spec param names per path (for named-param family)
spec_params = {}
try:
    import yaml
    spec = yaml.safe_load(open(SPEC))
    for p, pd in (spec.get("paths") or {}).items():
        for m in ("get", "post"):
            for prm in (pd.get(m) or {}).get("parameters", []) or []:
                spec_params[p] = spec_params.get(p, []) + [prm.get("name")]
except Exception as e:
    print("spec load fail:", e)

def url_for(num):
    """TRUE url from the servlet's own @WebServlet annotation (folders vary: crypto-00/01/...)."""
    src = f"/home/z/tools/benchmark/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest{num}.java"
    m = re.search(r'@WebServlet\(value\s*=\s*"([^"]+)"', open(src).read())
    return BASE + m.group(1) if m else f"{BASE}/crypto-00/BenchmarkTest{num}"

def read_artifact():
    try:
        return open(ART, "rb").read().decode("utf-8", "replace")
    except FileNotFoundError:
        return ""

B64_RE = re.compile(r"secret_value=([A-Za-z0-9+/=\s]+?)(?=\n\w+=|\Z)")

def fresh_ct(prev_lines_count):
    """Return (n_lines_now, last secret_value decoded bytes or None)."""
    txt = read_artifact()
    blocks = B64_RE.findall(txt)
    if not blocks:
        return txt.count("\n"), None
    b64 = re.sub(r"\s+", "", blocks[-1])
    try:
        return txt.count("\n"), base64.b64decode(b64 + "=" * (-len(b64) % 4))
    except Exception:
        return txt.count("\n"), None

def probe(num, marker, shape):
    tid = f"BenchmarkTest{num}"
    url = url_for(num)
    data = None
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if shape["final"].startswith("CONST"):
        data = "x=1"  # input ignored; anything goes
    elif shape["final"] == "CONTROLLED(form-field-testid)" or shape["final"] == "CONTROLLED(raw-body)":
        data = urllib.parse.urlencode({tid: marker})
    elif shape["final"] == "CONTROLLED(header-value)":
        headers[tid] = marker
    elif shape["final"] == "CONTROLLED(header-name)":
        headers[marker] = "1"  # header NAME is the plaintext
    elif shape["final"] == "CONTROLLED(param-name)":
        data = urllib.parse.urlencode({marker: tid})  # name=marker, value=testid
    elif shape["final"] == "CONTROLLED(cookie-value)":
        headers["Cookie"] = f"{tid}={urllib.parse.quote(marker)}"
    elif shape["final"] == "CONTROLLED(qs)":
        url = url + "?" + urllib.parse.urlencode({tid: marker})
        data = "" if data is None else data
    else:  # named-param: send EVERY source-declared param name + the testid, all = marker
        names = []
        s = open(f"/home/z/tools/benchmark/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest{num}.java").read()
        names += re.findall(r'getParameter\("([^"]+)"\)', s)
        for p, ns in spec_params.items():
            if p.endswith("/" + tid):
                names += [x for x in (ns or []) if x]
        names.append(tid)
        data = urllib.parse.urlencode({n: marker for n in dict.fromkeys(names)})  # dedup, all=marker
    body = data.encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            resp = r.read().decode("utf-8", "replace")
            code = r.status
    except urllib.error.HTTPError as e:
        resp = e.read().decode("utf-8", "replace"); code = e.code
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    echo = ""
    m = re.search(r"Sensitive value: '([^']*)'", resp)
    if m:
        echo = m.group(1)
    return {"code": code, "echo": echo[:60], "resp_head": resp[:120].replace("\n", " ")}

def run_case(num, is_fn=True):
    shape = shape_of.get(num)
    if shape is None:
        # TP/TN contrast: classify on the fly
        s = open(f"/home/z/tools/benchmark/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest{num}.java").read()
        tid = f"BenchmarkTest{num}"
        if "getTheValue(" in s: fin = 'CONST("bar",3B)'
        elif "This_should_always_happen" in s: fin = 'CONST("This_should_always_happen",26B)'
        elif "This should never happen" in s: fin = 'CONST("This should never happen",24B)'
        elif "getInputStream()" in s: fin = "CONTROLLED(raw-body)"
        elif re.search(rf'getHeader\("{tid}"\)', s): fin = "CONTROLLED(header-value)"
        elif "getHeaderNames()" in s: fin = "CONTROLLED(header-name)"
        elif "getCookies()" in s: fin = "CONTROLLED(cookie-value)"
        elif "getQueryString()" in s: fin = "CONTROLLED(qs)"
        elif re.search(rf'map\.get\("{tid}"\)|getParameter\("{tid}"\)', s): fin = "CONTROLLED(form-field-testid)"
        elif f'value.equals("{tid}")' in s: fin = "CONTROLLED(param-name)"
        else: fin = "CONTROLLED(named-param)"
        shape = {"num": num, "final": fin, "ext": "derived", "ovr": "-"}
    # truncate artifact for a clean window
    open(ART, "w").close()
    r1 = probe(num, P8, shape)
    _, ct1 = fresh_ct(0)
    open(ART, "w").close()
    r2 = probe(num, P16, shape)
    _, ct2 = fresh_ct(0)
    rec = {"num": num, "shape": shape["final"], "p8": {"echo": r1.get("echo"), "ct_len": None if ct1 is None else len(ct1), "code": r1.get("code"), "err": r1.get("error")},
           "p16": {"echo": r2.get("echo"), "ct_len": None if ct2 is None else len(ct2), "code": r2.get("code"), "err": r2.get("error")}}
    l8, l16 = rec["p8"]["ct_len"], rec["p16"]["ct_len"]
    if l8 is not None and l16 is not None and l8 != l16:
        rec["verdict"] = f"CONTROLLED({l8}->{l16})"
    elif l8 is not None and l16 is not None:
        rec["verdict"] = f"CONSTANT(ct={l8})"
        rec["const_echo"] = rec["p16"]["echo"]
    else:
        rec["verdict"] = f"DEAD(l8={l8},l16={l16})"
    return rec

results = {"fn": [], "tn_const": [], "tp": []}
for n in fn_ids:
    results["fn"].append(run_case(n))
    print(f"FN {n}: {results['fn'][-1]['verdict']:24s} echo16='{results['fn'][-1]['p16']['echo'][:30]}'")
json.dump(results, open("/tmp/cr_partial.json", "w"))
print("\n=== FN verdict rollup ===")
for k, v in Counter(r["verdict"].split("(")[0] for r in results["fn"]).most_common():
    print(f"{v:3d} {k}")

# TN constants (the FP danger) + all TN actually — cheap enough, run all 116
print("\n=== TN probes (FP danger landscape) ===")
for n in tn_ids:
    r = run_case(n)
    results["tn_const"].append(r)
for k, v in Counter((r["verdict"], r["shape"]) for r in results["tn_const"]).most_common(20):
    print(f"{v:3d} {k}")

print("\n=== TP controls (regression guard) ===")
for n in tp_ids:
    r = run_case(n)
    results["tp"].append(r)
    print(f"TP {n}: {r['verdict']:24s} shape={r['shape']}")

json.dump(results, open(OUT, "w"), indent=1)
print("\nwritten:", OUT)

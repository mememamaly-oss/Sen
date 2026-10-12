#!/usr/bin/env python3
"""Task 40 CR-1 RED/GREEN live proof — chunk-5/6 semantics with and without
the chain-primitive seeds.

RED  spec = the chunk-5/6 reality: crypto+hash FN tests + their OWN traversal
            endpoints (exists_oracle TPs that never leak content) — no seeds.
GREEN spec = the same + the 2 seeded primitives (00001 read / 00002 write).

Expected: RED -> 0 weak_crypto/weak_hash catches (chain dead: no read primitive);
          GREEN -> the catchable tests verify, TN stay silent.
Run with the stack UP. Zero engine changes — measurement-infrastructure fix."""
import json, sys
sys.path.insert(0, "/home/z/my-project/build-v430")
import yaml

from sentinel.orchestrator import SentinelScanner, ScanConfig

BM = "/home/z/tools/benchmark"

CRYPTO_FN_56 = ["01015", "01016", "01017", "01018", "01020", "01099", "01102", "01103",
                "01105", "01106", "01107", "01148", "01149", "01150", "01228", "01229",
                "01230", "01317", "01318", "01320", "01322", "01323", "01325"]
HASH_FN_56 = ["00961", "00963", "01038", "01041", "01042", "01043", "01044", "01123",
              "01124", "01165", "01166", "01167", "01168", "01244", "01246", "01247",
              "01248", "01333", "01334"]
TRAV_TP_56 = ["00949", "00952", "00953", "00956", "01025", "01029", "01032", "01033",
              "01034", "01155", "01156", "01157", "01161", "01231", "01232", "01234", "01235"]
TN_56 = ["01019", "01100", "01108", "01324", "01021", "01022"]  # must stay silent

ALL = ([f"BenchmarkTest{n}" for n in CRYPTO_FN_56] +
       [f"BenchmarkTest{n}" for n in HASH_FN_56] +
       [f"BenchmarkTest{n}" for n in TRAV_TP_56] +
       [f"BenchmarkTest{n}" for n in TN_56])
SEEDS = ["BenchmarkTest00001", "BenchmarkTest00002"]

spec = yaml.safe_load(open(f"{BM}/data/openapi.yaml"))
spec["servers"] = [{"url": "http://localhost:8080/benchmark"}]

def build(paths_tests):
    sub = {k: spec[k] for k in spec if k != "paths"}
    sub["paths"] = {}
    for p in spec["paths"]:
        if p.rsplit("/", 1)[-1] in paths_tests:
            sub["paths"][p] = spec["paths"][p]
    return sub

def run(label, sub):
    cfg = ScanConfig(active=True, passive=True, allow_private=True, crawl=False,
                     openapi=False, openapi_spec=sub, seed="7f3c91aa", max_pages=200)
    sc = SentinelScanner("http://localhost:8080/benchmark", cfg)
    out = sc.run()
    rows = []
    for f in out["findings"]:
        if f["type"] in ("weak_crypto", "weak_hash", "path_traversal"):
            tid = f["url"].rstrip("/").split("/")[-1]
            rows.append((f["type"], f["status"], tid))
    crypto_catch = [r for r in rows if r[0] == "weak_crypto" and r[1] == "verified"]
    hash_catch = [r for r in rows if r[0] == "weak_hash" and r[1] == "verified"]
    trav = [r for r in rows if r[0] == "path_traversal" and r[1] == "verified"]
    tn_fire = [r for r in rows if r[2] in [f"BenchmarkTest{n}" for n in TN_56]
               and r[1] == "verified" and r[0] in ("weak_crypto", "weak_hash")]
    print(f"\n=== {label}: paths={len(sub['paths'])} reqs={out['stats'].get('requests')} ===")
    print(f"  weak_crypto verified: {len(crypto_catch)}  {[r[2][-5:] for r in crypto_catch]}")
    print(f"  weak_hash   verified: {len(hash_catch)}    {[r[2][-5:] for r in hash_catch]}")
    print(f"  path_traversal verified: {len(trav)} ({[r[2][-5:] for r in trav][:8]}...)")
    print(f"  TN fired (MUST be 0): {tn_fire}")
    return {"label": label, "crypto": [r[2] for r in crypto_catch],
            "hash": [r[2] for r in hash_catch], "trav": len(trav),
            "tn_fire": tn_fire, "reqs": out["stats"].get("requests")}

red = run("RED (chunk-5/6 reality, no seeds)", build(set(ALL)))
green = run("GREEN (same + 2 primitive seeds)", build(set(ALL) | set(SEEDS)))

verdict = {
    "red": red, "green": green,
    "cr1_proven": (len(red["crypto"]) == 0 and len(red["hash"]) == 0
                   and len(green["crypto"]) > 0 and len(green["hash"]) > 0
                   and not green["tn_fire"] and not red["tn_fire"]),
}
print("\nCR-1 PROVEN:" if verdict["cr1_proven"] else "\nCR-1 NOT PROVEN — INVESTIGATE")
print(f"  RED : crypto {len(red['crypto'])}, hash {len(red['hash'])} (expected 0/0)")
print(f"  GREEN: crypto {len(green['crypto'])}, hash {len(green['hash'])} (expected >0/>0), TN fired: {len(green['tn_fire'])}")
json.dump(verdict, open("/home/z/my-project/tool-results/cr1_redgreen.json", "w"), indent=1)
print("written: tool-results/cr1_redgreen.json")

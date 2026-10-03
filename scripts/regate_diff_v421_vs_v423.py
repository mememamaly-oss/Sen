#!/usr/bin/env python3
"""regate_diff_v421_vs_v423.py — stop-line comparison for supervisor round 4.

Diffs VERIFIED findings between the frozen v4.2.1 campaign (live_v421/) and the
v4.2.3 re-gate runs (live_v423/) per target, so the stop-line questions get a
raw, checkable answer:

  (a) are the three fixed gaps now VERIFIED live?   (expect +3)
  (b) were the two over-claimed verdicts dropped?   (expect -2)
  (c) any NEW verified claims that were NOT in v4.2.1 and are NOT one of the
      fixed gaps?  (= new false positives / regressions — expect none)

testfire: demo.testfire.net is network-unreachable in this window (HTTP+HTTPS
timeout at the socket level, 2026-10-03 23:0x UTC) — recorded as
UNSCANNED(env), not as an engine result.
"""
import json, os
from urllib.parse import urlsplit, unquote

R = "/home/z/my-project/build-v423/results"
TARGETS = ["gruyere", "testaspnet", "testasp", "ginjuice"]  # testfire = env-down


def key(f):
    p = unquote(urlsplit(f.get("url", "")).path)
    return (f.get("type"), p, f.get("parameter") or "", f.get("method", ""))


def load(t, ver):
    path = f"{R}/live_{ver}/{t}.json"
    d = json.load(open(path))
    ver_set = {}
    for f in d.get("findings", []):
        if f.get("status") == "verified":
            ver_set.setdefault(key(f), f)
    return d, ver_set


def main():
    report = {"meta": {"v421": "frozen campaign", "v423": "re-gate after DETECT-15/16/17 + VF-04",
                       "testfire": "UNSCANNED — target network-unreachable (socket timeout) in this window"},
              "per_target": {}, "totals": {}}
    tot_new = tot_gone = tot_same = 0
    for t in TARGETS:
        d21, v21 = load(t, "v421")
        d23, v23 = load(t, "v423")
        new = sorted(set(v23) - set(v21))
        gone = sorted(set(v21) - set(v23))
        same = sorted(set(v21) & set(v23))
        # verification-channel drift on kept findings (over-claim -> real oracle)
        channel = {}
        for k in same:
            m21 = v21[k].get("verification", {}).get("method")
            m23 = v23[k].get("verification", {}).get("method")
            if m21 != m23:
                channel[" | ".join(map(str, k)) + f"  [{m21} -> {m23}]"] = True
        report["per_target"][t] = {
            "v421_verified": len(v21), "v423_verified": len(v23),
            "new_in_v423": [" | ".join(map(str, k)) for k in new],
            "dropped_from_v421": [" | ".join(map(str, k)) for k in gone],
            "verification_channel_changes": list(channel),
        }
        tot_new += len(new); tot_gone += len(gone); tot_same += len(same)
    report["totals"] = {"kept": tot_same, "new": tot_new, "dropped": tot_gone}
    out = f"{R}/regate_v421_vs_v423.json"
    json.dump(report, open(out, "w"), indent=1)
    print(json.dumps(report["totals"]))
    for t, r in report["per_target"].items():
        print(f"\n== {t}: v421={r['v421_verified']} -> v423={r['v423_verified']}")
        for k in r["new_in_v423"]:
            print(f"   +NEW      {k}")
        for k in r["dropped_from_v421"]:
            print(f"   -DROPPED  {k}")
        for k in r["verification_channel_changes"]:
            print(f"   ~CHANNEL  {k}")
    print(f"\nwritten: {out}")


if __name__ == "__main__":
    main()

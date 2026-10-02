#!/usr/bin/env python3
"""SENTINEL v4.1 — Juice Shop scan result analyzer (compact, no huge dumps)."""
import json
import sys

PATH = "/home/z/my-project/build-v410/results/live_v41/juiceshop.json"
d = json.load(open(PATH))
st = d.get("stats", {})

print("scanner  :", d.get("scanner"), "| run:", d.get("run_id"))
print("target   :", d.get("target"))
print("verified :", st.get("verified"), "| rejected:", st.get("rejected"),
      "| reqs:", st.get("requests"), "| dur:", round(st.get("duration", 0), 1), "s")

auth = st.get("auth", {})
print("auth     :", auth.get("mode"), "| authenticated:", auth.get("authenticated"),
      "| rejections:", auth.get("rejections"))

sev = {}
cls = {}
for f in d.get("findings", []):
    sev[f.get("severity", "?")] = sev.get(f.get("severity", "?"), 0) + 1
    cls[f.get("type", f.get("class", "?"))] = cls.get(f.get("type", f.get("class", "?")), 0) + 1
print("severity :", sev)
print("classes  :")
for k, v in sorted(cls.items(), key=lambda x: -x[1]):
    print(f"   {v:3d} x {k}")

b = st.get("boundary", {})
print("boundary :", b.get("records"), "records | by_state:", b.get("by_state"),
      "| unresolved:", b.get("unresolved"))

wf = st.get("workflow", {})
print("workflow :", json.dumps({k: wf[k] for k in list(wf)[:5]})[:200])

ai = st.get("api_inventory", {})
if isinstance(ai, dict):
    print("api_inv  :", {k: ai[k] for k in list(ai)[:6]})

am = st.get("action_matrix", {})
if isinstance(am, dict):
    print("act_mtx  :", {k: am[k] for k in list(am)[:6]})

tw = st.get("digital_twin", {})
if isinstance(tw, dict):
    print("twin     : nodes:", tw.get("nodes", "?"), "| edges:", tw.get("edges", "?"))

rs = st.get("reasoning", {})
if isinstance(rs, dict):
    print("reasoning:", {k: rs[k] for k in list(rs)[:6]})

pl = st.get("planner", {})
if isinstance(pl, dict):
    print("planner  :", {k: pl[k] for k in list(pl)[:6]})

pf = st.get("proofs", {})
if isinstance(pf, dict):
    print("proofs   :", {k: pf[k] for k in list(pf)[:6]})
elif isinstance(pf, list):
    print("proofs   :", len(pf), "proof bundles")

mm = st.get("memory", {})
if isinstance(mm, dict):
    print("memory   :", {k: mm[k] for k in list(mm)[:6]})

# Coverage 2.0 dimensions detail
cov = st.get("coverage", {})
if isinstance(cov, dict):
    print("coverage dims shown above; full keys:", list(cov)[:20])

# top findings list (id + class + severity + short target)
print("\nfindings (id | class | severity | target):")
for f in d.get("findings", [])[:40]:
    print(f"  {f.get('id','?'):14s} {f.get('type', f.get('class','?'))[:38]:38s} "
          f"{f.get('severity','?'):8s} {f.get('url', f.get('target',''))[:60]}")

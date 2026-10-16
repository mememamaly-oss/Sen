#!/usr/bin/env python3
"""Mutillidae campaign final evaluation: recon3 (OWSP-21..23) vs recon2 (OWSP-21/21b only).

Ground truth = the app's own source: 25 form-bearing pages under mutillidae-src/src/.
Honest questions:
  1. SCOPE: did any finding/endpoint/request leave 127.0.0.1:4290? (OWSP-22 paypal-class)
  2. COVERAGE: which form-bearing pages were fetched (fetched-with-params = surface reached)?
  3. FINDINGS: verdict/type breakdown, new vs recon2, esp. on the 20 previously-strangled pages.
  4. HONEST GAPS: pages not fetched, classes with no detector, unverified candidates.
"""
import json, sys, os
from collections import Counter

R = "/home/z/my-project/build-v425/results/owsp/mutillidae"
PAGES = """add-to-your-blog.php client-side-control-challenge.php conference-room-lookup.php
content-security-policy.php cors.php database-offline.php dns-lookup.php document-viewer.php
echo.php edit-account-profile.php html5-storage.php login.php password-generator.php
pen-test-tool-lookup-ajax.php pen-test-tool-lookup.php register.php repeater.php
set-background-color.php source-viewer.php test-connectivity.php text-file-viewer.php
upload-file.php user-info-xpath.php user-info.php user-poll.php view-someones-blog.php
xml-validator.php""".split()

def load(name):
    p = os.path.join(R, name)
    return json.load(open(p)) if os.path.exists(p) else None

def host_of(u):
    try:
        return u.split("/")[2]
    except Exception:
        return "?"

def main(run="recon3", prev="recon2"):
    d = load(f"{run}.json"); d0 = load(f"{prev}.json")
    if not d:
        print(f"NO {run}.json yet"); return 1
    s = d.get("stats", {})
    print(f"===== {run.upper()} (vs {prev}) =====")
    print(f"run_id={d.get('run_id')} requests={s.get('requests')} endpoints={s.get('endpoints')} "
          f"candidates={s.get('candidates')} verified={s.get('verified')} rejected={s.get('rejected')} "
          f"duration={s.get('duration')}s browser={s.get('browser_pages')}p/{s.get('browser_probes')}b "
          f"journal_dropped={s.get('request_journal_dropped')}")

    f = d.get("findings", [])
    print(f"\nfindings list: {len(f)}  statuses: {dict(Counter(str(x.get('status')) for x in f))}")

    # 1) SCOPE ESCAPE CHECK (OWSP-22)
    off = [x for x in f if host_of(x.get("url", "")) not in ("127.0.0.1:4290",)]
    print(f"\n[SCOPE] off-target findings: {len(off)}  {'<- ESCAPE STILL PRESENT' if off else '(clean)'}")
    for x in off[:10]:
        print(f"   ESCAPE: {x.get('type')} {x.get('url')[:80]}")
    eps = d.get("endpoints") or []
    if isinstance(eps, list):
        offe = [e.get("url", "") if isinstance(e, dict) else str(e) for e in eps]
        bad = [u for u in offe if host_of(u) not in ("127.0.0.1:4290",)]
        print(f"[SCOPE] off-target endpoints: {len(bad)}")
        for u in bad[:5]: print(f"   ESCAPE-EP: {u[:80]}")

    # 2) COVERAGE: form-bearing pages reached (endpoint with the page param)
    fetched = set()
    if isinstance(eps, list):
        for e in eps:
            u = e.get("url", "") if isinstance(e, dict) else str(e)
            if "index.php" in u and "page=" in u:
                for p in PAGES:
                    if f"page={p}" in u or f"page={p.replace('.php','')}" in u:
                        fetched.add(p)
    # journal fallback: stats only; endpoints are the honest proxy
    missed = [p for p in PAGES if p not in fetched]
    print(f"\n[COVERAGE] form-bearing pages reached: {len(fetched)}/{len(PAGES)}")
    print(f"  reached: {' '.join(sorted(fetched))}")
    print(f"  MISSED ({len(missed)}): {' '.join(missed)}")

    # 3) FINDINGS by type on index.php?page= surfaces
    act = [x for x in f if x.get("type") not in
           ("missing_security_headers", "tech_banner_disclosure", "host_header_injection")]
    print(f"\n[FINDINGS] active+content classes: {len(act)}")
    for (t, st), n in sorted(Counter((x.get("type"), str(x.get("status"))) for x in act).items()):
        print(f"  {t:24} {st:10} x{n}")
    page_findings = [x for x in act if "page=" in x.get("url", "")]
    pf = Counter()
    for x in page_findings:
        u = x.get("url", "")
        for p in PAGES:
            if f"page={p}" in u or f"page={p.replace('.php','')}" in u:
                pf[p] += 1
    print(f"\n[FINDINGS] per vuln-page (index.php?page=...):")
    for p, n in sorted(pf.items(), key=lambda kv: -kv[1]):
        print(f"  {p:38} {n}")
    nof = [p for p in PAGES if p not in pf and p in fetched]
    print(f"  fetched-but-zero-findings ({len(nof)}): {' '.join(nof)}")

    # 4) delta vs previous run
    if d0:
        f0 = d0.get("findings", [])
        k0 = Counter((x.get("type"), x.get("url"), x.get("parameter")) for x in f0)
        k1 = Counter((x.get("type"), x.get("url"), x.get("parameter")) for x in f)
        new = k1 - k0
        gone = k0 - k1
        print(f"\n[DELTA] new findings vs {prev}: {sum(new.values())}")
        for (t, u, prm), n in sorted(new.items()):
            if t not in ("missing_security_headers", "tech_banner_disclosure", "host_header_injection"):
                print(f"  + {t:22} {u[:64]} param={prm}")
        off_gone = [k for k in gone if host_of(k[1]) not in ("127.0.0.1:4290",)]
        print(f"[DELTA] off-target findings REMOVED: {len(off_gone)}")
        for k in off_gone[:10]: print(f"  - {k[0]} {k[1][:64]}")

    uc = d.get("unverified_candidates", [])
    print(f"\n[UNVERIFIED] candidates kept visible: {len(uc)}")
    for x in uc[:12]:
        print(f"  {x.get('type'):22} {x.get('url','')[:66]}")
    rj = d.get("rejected_candidates", [])
    print(f"[REJECTED] honest rejects: {len(rj)}")
    for x in rj[:8]:
        print(f"  {x.get('type', '?'):22} {str(x.get('url',''))[:66]} reason={str(x.get('reject_reason') or x.get('reason') or '')[:40]}")
    return 0

if __name__ == "__main__":
    sys.exit(main(*(sys.argv[1:2] or ["recon3"]), *(sys.argv[2:3] or ["recon2"])))

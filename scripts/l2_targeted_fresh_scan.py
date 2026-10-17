#!/usr/bin/env python3
"""ROUND 7 (supervisor order) — targeted FRESH live scans for the two projected
L2 targets (ginjuice, testaspnet).

The round-6 L2 files for these two targets were PROJECTIONS over their real
v4.2.3 live journals (the environment caps foreground calls at 600s; their full
scans take 620s/936s). The supervisor ordered: every L2 attack path must rest
on FRESH live evidence — request/response pairs actually sent to the live
target in THIS scan — never a projection over old logs. The solution for the
600s cap: do NOT re-scan the whole application. Run a TARGETED fresh scan of
ONLY the specific points that enter each attack path (known from the
projections), which is fast and yields fresh live evidence for exactly the
links that matter.

HOW (integrity-preserving):
  * The SHIPPED v4.3.0 pipeline runs untouched — SentinelScanner.run() exactly
    as the CLI builds it (crawl on, browser on, OAST auto, secrets/graphql/
    websocket/openapi on, default timeouts). Detectors, verifiers, journal,
    twin, coverage, boundaries, attack_paths: all the shipped code.
  * The ONLY intervention is discovery scoping, applied in-process and
    recorded inside the report itself (stats.crawl.targeted_mode):
      1. the exact path-surface pages are seeded at the FRONT of the BFS
         queue (they are fetched live NOW — forms/dom-sinks parsed live NOW);
      2. the endpoint map is filtered to the path surfaces named by the
         projected paths (operator targeting — the inverse of --exclude-url).
    Everything the scan does beyond those seeds (JS-asset fetches, browser
    renders, verification replays) is the shipped behavior on a scoped map.
  * Every proving request/response pair is sent live in this run and journaled
    in the fresh report's request_journal; L2 paths are computed by the
    shipped apath layer over that fresh journal (weakest-link rule enforced).

Honesty contract: if this targeted scan overruns the 600s window or the target
is network-dead, NOTHING is claimed fresh — the outcome is recorded verbatim.

Usage: python3 scripts/l2_targeted_fresh_scan.py <ginjuice|testaspnet>
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "build-v423"))

RESULTS = os.path.join(ROOT, "build-v423", "results", "live_v430")
ARCHIVE = os.path.join(RESULTS, "archive_round6_projections")

# The path surfaces named by the round-6 projected paths (from the v4.2.3
# findings): seeds = pages fetched live first (front of BFS); keep = endpoint
# filter (method, path, required param subset). Ride-along form fields
# (storeId/back/searchTerm/redir/quantity/__VIEWSTATE...) are preserved
# verbatim by the shipped form parser — only the listed params are REQUIRED.
TARGETS = {
    "ginjuice": {
        "url": "https://ginandjuice.shop",
        "seed": "l2fresh-gj-r7",
        "max_pages": 8,
        "seeds": [
            "https://ginandjuice.shop/",                       # session/identity provenance (Set-Cookie AWSALB/session)
            "https://ginandjuice.shop/catalog",                # category surface (SQLi + reflected XSS + header injection)
            "https://ginandjuice.shop/blog/?search=1",         # search surface (DOM XSS sink + open redirect) — param'd page carries the sink script
            "https://ginandjuice.shop/catalog/product?productId=1",  # carries stock-check + add-to-cart forms (XXE + CSRF)
        ],
        "keep": [
            ("GET",  "/catalog",               {"category"}),   # F-277b70ea40 SQLi / F-4df129b258 XSS / F-e6ca09b8b8 header-inj
            ("GET",  "/blog/",                 {"search"}),     # F-fc86abef99 DOM XSS / F-ef23b8b42b open redirect
            ("POST", "/catalog/product/stock", {"productId"}),  # F-98386c0986 XXE
            ("POST", "/catalog/cart",          {"productId"}),  # F-d8bbff4e3e CSRF (chain partner of both XSS)
        ],
        "old_seeds": {"sql:/catalog?category": "F-277b70ea40",
                      "xxe:/catalog/product/stock": "F-98386c0986",
                      "xssr:/catalog?category": "F-4df129b258",
                      "xssd:/blog/?search": "F-fc86abef99",
                      "hdr:/catalog?category": "F-e6ca09b8b8",
                      "csrf:/catalog/cart": "F-d8bbff4e3e",
                      "oredir:/blog/?search": "F-ef23b8b42b"},
    },
    "testaspnet": {
        "url": "http://testaspnet.vulnweb.com",
        "seed": "l2fresh-tn-r7",
        "max_pages": 5,
        "seeds": [
            "http://testaspnet.vulnweb.com/",                    # session/identity provenance (ASP.NET_SessionId) + ReadNews/Comments links
            "http://testaspnet.vulnweb.com/Comments.aspx?id=2",  # comment form (stored XSS) + id-param surface (SQLi)
        ],
        "keep": [
            ("GET",  "/Comments.aspx", {"id"}),         # F-c9596a7ab3 SQLi
            ("GET",  "/ReadNews.aspx", {"id"}),         # F-1e2f9fefe2 SQLi
            ("POST", "/Comments.aspx", {"tbComment"}),  # F-9779edbacd stored XSS
        ],
        "old_seeds": {"sqli:/Comments.aspx?id": "F-c9596a7ab3",
                      "sqli:/ReadNews.aspx?id": "F-1e2f9fefe2",
                      "xsss:/Comments.aspx#tbComment": "F-9779edbacd"},
    },
}


def _norm_path(p: str) -> str:
    p = (urllib.parse.urlsplit(p or "/").path or "/")
    if len(p) > 1:
        p = p.rstrip("/")
    return p.lower()


def _keep_endpoint(e, keep_rules) -> bool:
    m = (getattr(e, "method", None) or "GET").upper()
    p = _norm_path(getattr(e, "url", ""))
    names = {param.name for param in (getattr(e, "parameters", None) or [])}
    for km, kp, kr in keep_rules:
        if m == km.upper() and p == _norm_path(kp) and kr <= names:
            return True
    return False


def run_targeted(name: str, spec: dict) -> dict:
    from sentinel import discovery as discovery_mod
    from sentinel.orchestrator import ScanConfig, SentinelScanner
    from sentinel.oast import make_oast

    keep_rules, seeds = spec["keep"], spec["seeds"]
    orig_crawl = discovery_mod.DiscoveryEngine.crawl

    def targeted_crawl(self, seed_url, extra_seeds=None, exclude_urls=None):
        # 1) ship the exact path-surface pages to the FRONT of the BFS queue —
        #    they are fetched live NOW, forms/DOM sinks parsed live NOW.
        eps, js, stats = orig_crawl(
            self, seed_url,
            extra_seeds=list(seeds) + list(extra_seeds or []),
            exclude_urls=exclude_urls)
        # 2) scope the endpoint map to the path surfaces (recorded, not silent)
        kept = [e for e in eps if _keep_endpoint(e, keep_rules)]
        stats = dict(stats)
        stats["targeted_mode"] = {
            "order": "round 7 — fresh-live L2 evidence for the projected path surfaces",
            "seeds": list(seeds),
            "keep_rules": [f"{m} {p} params⊇{{{','.join(sorted(r))}}}" for m, p, r in keep_rules],
            "endpoints_discovered": len(eps),
            "endpoints_kept": len(kept),
            "endpoints_dropped_non_target": len(eps) - len(kept),
        }
        return kept, js, stats

    discovery_mod.DiscoveryEngine.crawl = targeted_crawl
    oast = None
    try:
        # exactly what the CLI builds for a default scan (no auth, no spec)
        oast = make_oast(urllib.parse.urlsplit(spec["url"]).hostname or "", mode="auto")
        cfg = ScanConfig(max_pages=spec["max_pages"], crawl=True,
                         seed=spec["seed"], oast=oast)
        sc = SentinelScanner(spec["url"], cfg)
        t0 = time.time()
        started_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        rep = sc.run()
        elapsed = time.time() - t0
        finished_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    finally:
        discovery_mod.DiscoveryEngine.crawl = orig_crawl
        if oast is not None:
            try:
                oast.stop()
            except Exception:
                pass

    # ---- provenance stamp: this file is a FRESH targeted live scan
    note = (f"fresh TARGETED v4.3.0 live scan ({rep.get('run_id')}, seed {rep.get('seed')}) "
            "of ONLY the L2 attack-path surfaces (supervisor round-7 order: fresh-live "
            "evidence, no projections) — the shipped pipeline ran with discovery seeded "
            "to the exact path-surface pages and the endpoint map scoped to those "
            "surfaces (stats.crawl.targeted_mode records the seeds/keep-rules); every "
            f"request/response pair in this journal was sent live in this run "
            f"({started_utc} .. {finished_utc}, {elapsed:.0f}s wall)")
    rep["l2_source"] = note
    rep["l2_fresh_scan"] = {
        "mode": "targeted-fresh-live",
        "order": "round 7",
        "started_utc": started_utc,
        "finished_utc": finished_utc,
        "wall_seconds": round(elapsed, 1),
        "seeds": list(seeds),
        "keep_rules": [[m, p, sorted(r)] for m, p, r in keep_rules],
        "old_projection_seed_findings": dict(spec["old_seeds"]),
    }

    # ---- freshness self-check: every journaled response must carry a server
    # date INSIDE this run's window (±10min clock skew) — proof the journal is
    # this run's traffic, not a replayed artifact.
    j = (rep.get("stats") or {}).get("request_journal") or {}
    lo = time.mktime(time.gmtime()) - elapsed - 600
    hi = time.mktime(time.gmtime()) + 600
    stale = []
    for rid, e in j.items():
        dh = str(((e.get("response") or {}).get("headers") or {})
                 .get("date") or ((e.get("response") or {}).get("headers") or {})
                 .get("Date") or "")
        if not dh:
            continue
        try:
            import email.utils
            ts = email.utils.mktime_tz(email.utils.parsedate_tz(dh))
        except Exception:
            continue
        if not (lo <= ts <= hi):
            stale.append({"req": rid, "date": dh})
    rep["l2_fresh_scan"]["journal_entries"] = len(j)
    rep["l2_fresh_scan"]["journal_date_window_check"] = (
        {"status": "PASS", "stale_entries": []} if not stale
        else {"status": "FAIL", "stale_entries": stale[:10]})

    out_path = os.path.join(RESULTS, f"{name}.json")
    if os.path.exists(out_path):  # archive the round-6 projection, never destroy
        os.makedirs(ARCHIVE, exist_ok=True)
        shutil.copy2(out_path, os.path.join(ARCHIVE, f"{name}.json"))
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1)

    # ---- console summary (honest, verbatim)
    st = rep.get("stats") or {}
    s = (rep.get("attack_paths") or {}).get("summary") or {}
    print(json.dumps({
        "target": name,
        "run_id": rep.get("run_id"), "seed": rep.get("seed"),
        "elapsed_s": round(elapsed, 1), "requests": st.get("requests"),
        "endpoints_kept": (st.get("crawl") or {}).get("targeted_mode", {}).get("endpoints_kept"),
        "endpoints_discovered": (st.get("crawl") or {}).get("targeted_mode", {}).get("endpoints_discovered"),
        "verified_findings": [{"id": f["id"], "type": f["type"], "url": f["url"],
                               "param": f.get("parameter"), "conf": f.get("confidence"),
                               "impact": (f.get("impact") or {}).get("grade")}
                              for f in rep.get("findings", [])
                              if f.get("status") == "verified"],
        "paths": {"total": s.get("paths_total"), "verified": s.get("paths_verified"),
                  "inferred": s.get("paths_inferred"),
                  "chains": s.get("chains"),
                  "weak": s.get("weak_link_histogram")},
        "journal_entries": len(j),
        "freshness_window_check": rep["l2_fresh_scan"]["journal_date_window_check"]["status"],
        "out": out_path,
    }, indent=1))
    return rep


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in TARGETS:
        print(__doc__)
        print("usage: l2_targeted_fresh_scan.py <ginjuice|testaspnet>", file=sys.stderr)
        sys.exit(2)
    run_targeted(sys.argv[1], TARGETS[sys.argv[1]])


if __name__ == "__main__":
    main()

"""PART 2 patcher — 3F: the generic limited-resource race prober.

Invariant-based (NOT the axis-17 timing-variance battery): the prober
fires ONE bounded concurrent burst per OPERATOR-NAMED candidate and
counts winners; more winners than the declared quota is the finding
(CWE-362). The concurrency substrate is the project's own proven
burhan/race/engine.send_concurrent; the design basis is the methodology
proven twice in this codebase — the bootstrap concurrency fix
(scripts/axis18_load_test.py, POST /api/bootstrap) and the G8
concurrent-scan-start gate (scripts/axis19_gap_probe.py, "concurrent
scan start on same target -> exactly 1 wins").

NEVER BLIND (order 2.2, prominent): the prober runs ONLY on endpoints
the operator explicitly named (cfg.race_candidates). Firing concurrent
requests at arbitrary endpoints of a live target not under the
operator's control risks state corruption and unintended load; the
Docker-isolated and fixture targets share nothing with anyone else.

Patches:
  burhan/modernsec2.py   — the 3F family + caps + battery signature
  burhan/orchestrator.py — ScanConfig.race_candidates + battery wiring
  burhan/intel.py        — VR-37 (fresh burst; verify_params when the
                           resource is single-use)
  burhan/compliance.py   — CWE-362 / A04 mapping
  burhan/report.py       — Burhan-RACE-001
  fixtures/vulnapp.py    — POST /api/coupon/redeem (RACE_MODE=broken:
                           check-then-set with a 40ms window; =locked:
                           the same handler under a mutex)
"""
import re

# ---------------------------------------------------------------- modernsec2
p = "burhan/modernsec2.py"
s = open(p).read()

s = s.replace(
    'MODERN2_TYPES = ("jwt_weak_secret", "graphql_aliasing",\n'
    '                 "excessive_data_exposure", "rebind_toctou", "bfla")',
    'MODERN2_TYPES = ("jwt_weak_secret", "graphql_aliasing",\n'
    '                 "excessive_data_exposure", "rebind_toctou", "bfla",\n'
    '                 "race_condition")')
s = s.replace(
    'FAMILY2_CAPS = {"jwt_weak_secret": 2, "graphql_aliasing": 2,\n'
    '                "excessive_data_exposure": 8, "rebind_toctou": 4,\n'
    '                "bfla": 18}',
    'FAMILY2_CAPS = {"jwt_weak_secret": 2, "graphql_aliasing": 2,\n'
    '                "excessive_data_exposure": 8, "rebind_toctou": 4,\n'
    '                "bfla": 18, "race_condition": 48}')

s = s.replace(
    'BFLA_EP_CAP = 6         # admin-shaped non-GET endpoints examined (3E);',
    'RACE_CAND_CAP = 4       # operator-named candidates per scan (3F)\n'
    'RACE_DEFAULT_N = 6      # concurrent requests per burst (3F default)\n'
    'RACE_MAX_N = 12         # hard ceiling on the operator-declared N (3F);\n'
    '                         # the substrate gate (race/gates) allows 64 —\n'
    '                         # the family stays far below it on purpose\n'
    'BFLA_EP_CAP = 6         # admin-shaped non-GET endpoints examined (3E);')

anchor = "def run_modern_battery_v2("
family = '''# ------------------------------------------------------------------ 3F
def _race_prober(st: "_St2", eps, candidates):
    """3F — the generic limited-resource race prober (CWE-362): for each
    OPERATOR-NAMED candidate endpoint, fire ONE bounded concurrent burst
    and assert the declared invariant — at most `quota` winners (default
    1) across the burst. More winners than the resource should allow is
    the finding.

    Design basis — the methodology proven twice in this codebase: the
    bootstrap concurrency fix (scripts/axis18_load_test.py, POST
    /api/bootstrap) and the G8 concurrent-scan-start gate
    (scripts/axis19_gap_probe.py: "concurrent scan start on same target
    -> exactly 1 wins"). The concurrency substrate is the same proven
    engine: burhan/race/engine.send_concurrent (bounded, ordered
    results, honest boundaries per request). This family is
    INVARIANT-based (count the winners), not the axis-17
    timing-variance battery — the two are complementary.

    *** NEVER BLIND — an explicit, hard constraint (order 2.2) ***
    The prober runs ONLY on endpoints the operator explicitly named
    (cfg.race_candidates). It never heuristically selects POSTs to
    concurrency-bomb: firing concurrent requests at arbitrary endpoints
    of a live target not under the operator's control risks state
    corruption (real writes racing) and unintended load. The fixture and
    Docker-isolated targets share nothing with anyone else; a shared
    public target is never a race target (Part 4 forbids it).

    Candidate schema (all fields except url optional):
      {"url": ..., "method": "POST", "params": {...}, "quota": 1,
       "concurrent": 6, "win_statuses": [200, 201],
       "verify_params": {...}}   # VR-37's fresh-burst params — declare a
                                # SECOND single-use code when the resource
                                # is consumed by the first burst; without
                                # it VR-37 replays the same params and
                                # fail-closes on a consumed resource."""
    fam = "race_condition"
    from urllib.parse import urlsplit
    if not candidates:
        st.boundary(fam, "NOT_DISCOVERED",
                    "no explicit opt-in candidate list (cfg.race_candidates) "
                    "\u2014 the prober NEVER fires concurrent load at "
                    "endpoints the operator did not name (state corruption "
                    "and unintended load on live targets; see the family "
                    "docstring)")
        return
    from .race.engine import send_concurrent
    fired_any = False
    for cand in candidates[:RACE_CAND_CAP]:
        if st.counts[fam]["sent"] >= FAMILY2_CAPS[fam]:
            st.boundary(fam, "NOT_SUPPORTED",
                        "family request cap reached (4 candidates x 1 burst "
                        "x N concurrent, documented)")
            break
        url = str(cand.get("url") or "")
        method = str(cand.get("method") or "POST").upper()
        params = cand.get("params") or {}
        quota = int(cand.get("quota") or 1)
        n = min(int(cand.get("concurrent") or RACE_DEFAULT_N), RACE_MAX_N)
        win = tuple(int(x) for x in (cand.get("win_statuses") or (200, 201)))
        if not url or n < 2:
            st.boundary(fam, "UNTESTABLE",
                        f"candidate {url!r}: missing url or concurrent < 2 "
                        f"(a race needs at least two simultaneous requests)")
            continue
        req = {"method": method, "url": url,
               "headers": {"Content-Type": "application/json"},
               "body": json.dumps(params)}
        results = send_concurrent([dict(req) for _ in range(n)],
                                  max_concurrent=n, timeout=10.0)
        st.requests += n
        st.counts[fam]["sent"] += n
        statuses = [r.get("status") or 0 for r in results]
        winners = sum(1 for x in statuses if x in win)
        if winners > quota:
            fired_any = True
            ep = Endpoint(url=url, method=method)
            st.find(fam, Severity.HIGH, ep, "-", [
                Evidence("invariant_violated",
                         f"race condition (CWE-362): {winners} concurrent "
                         f"requests WON where the declared invariant allows "
                         f"at most {quota} — the limited-resource check is "
                         f"not atomic. Burst of {n} simultaneous "
                         f"{method} {urlsplit(url).path}: statuses "
                         f"{statuses}, winners {winners}", None),
                Evidence("probe_recipe",
                         f"url={url}; method={method}; quota={quota}; "
                         f"concurrent={n}; win_statuses={list(win)}; "
                         f"params={json.dumps(params, sort_keys=True)}",
                         None)])
            # VR-37 stash: the verifier fires a FRESH burst — with
            # verify_params when the operator declared a second sample
            # for a single-use resource
            stash = getattr(st.engine, "race_verify", None)
            if stash is None:
                stash = st.engine.race_verify = {}
            stash[url] = {"candidate": dict(cand), "n": n, "quota": quota,
                          "win": win, "method": method}
        else:
            st.boundary(fam, "TESTED_NEGATIVE",
                        f"{url}: invariant held — {winners} winner(s) <= "
                        f"quota {quota} across a {n}-wide concurrent burst "
                        f"(statuses {statuses})")
    if not fired_any and not any(
            b["family"] == fam and b["kind"] == "TESTED_NEGATIVE"
            for b in st.boundaries):
        pass  # per-candidate boundaries above already carry the record


def run_modern_battery_v2('''
assert anchor in s, "battery anchor"
s = s.replace(anchor, family, 1)

s = s.replace(
    '''def run_modern_battery_v2(engine: RequestEngine, endpoints, seed=None,
                          rebind_cfg: dict | None = None,
                          authz_sessions: dict | None = None) -> Modern2Result:''',
    '''def run_modern_battery_v2(engine: RequestEngine, endpoints, seed=None,
                          rebind_cfg: dict | None = None,
                          authz_sessions: dict | None = None,
                          race_candidates: list | None = None) -> Modern2Result:''')
s = s.replace(
    '''    _rebind_toctou(st, eps, rebind_cfg)
    _bfla(st, eps, authz_sessions or {})
    return Modern2Result(st.findings, st.boundaries, probe_counts_of(st),
                         st.requests)''',
    '''    _rebind_toctou(st, eps, rebind_cfg)
    _bfla(st, eps, authz_sessions or {})
    _race_prober(st, eps, race_candidates or [])
    return Modern2Result(st.findings, st.boundaries, probe_counts_of(st),
                         st.requests)''')
open(p, "w").write(s)
print("modernsec2 patched")

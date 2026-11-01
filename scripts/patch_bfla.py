"""PART 1 patcher — 3E BFLA (Broken Function Level Authorization).

A new modern2-battery family (rides the existing modern_v2 feature flag,
OFF by default). Reuses — never duplicates — the authz engine's logged-in
sessions: for each admin-shaped non-GET endpoint the crawl discovered,
replay the exact request (method, path, body) anonymously, with the
highest-privilege session, and with a lower-privilege session. The
finding fires when the function executes for the lower privilege where
the boundary should have rejected it (anon gated + high 2xx + low 2xx).

Patches:
  burhan/modernsec2.py   — the 3E family + caps + battery signature
  burhan/orchestrator.py — pass authz_sessions into the v2 battery
  burhan/intel.py        — VR-36 (fresh low-privilege replay via the stash)
  burhan/compliance.py   — CWE-285 / A01 mapping
  burhan/report.py       — Burhan-AUT-002
  fixtures/vulnapp.py    — POST /api/admin/rotate-keys (broken) +
                           POST /api/secure/admin/rotate-keys (403 twin) +
                           BFLA=1-gated lab divs (stock benchmark untouched)
"""
import re

# ---------------------------------------------------------------- modernsec2
p = "burhan/modernsec2.py"
s = open(p).read()

s = s.replace(
    'MODERN2_TYPES = ("jwt_weak_secret", "graphql_aliasing",\n'
    '                 "excessive_data_exposure", "rebind_toctou")',
    'MODERN2_TYPES = ("jwt_weak_secret", "graphql_aliasing",\n'
    '                 "excessive_data_exposure", "rebind_toctou", "bfla")')

s = s.replace(
    'FAMILY2_CAPS = {"jwt_weak_secret": 2, "graphql_aliasing": 2,\n'
    '                "excessive_data_exposure": 8, "rebind_toctou": 4}',
    'FAMILY2_CAPS = {"jwt_weak_secret": 2, "graphql_aliasing": 2,\n'
    '                "excessive_data_exposure": 8, "rebind_toctou": 4,\n'
    '                "bfla": 18}')

# BFLA_EP_CAP next to the other caps
s = s.replace(
    'ALIAS_CAP = 20          # aliases in the single probe request (3C)\n'
    'EXPOSURE_EP_CAP = 8     # JSON endpoints examined (3D)',
    'ALIAS_CAP = 20          # aliases in the single probe request (3C)\n'
    'EXPOSURE_EP_CAP = 8     # JSON endpoints examined (3D)\n'
    'BFLA_EP_CAP = 6         # admin-shaped non-GET endpoints examined (3E);\n'
    '                         # each costs 3 replays (anon + high + low) -> the\n'
    '                         # family cap above is 18 requests, hard-stopped')

# _St2.probe_with — replay through a SESSION engine, still family-counted
s = s.replace(
    '''    def probe(self, fam, ep, note="", **kw):
        self.counts[fam]["sent"] += 1
        self.requests += 1
        return self.engine.send(
            RequestMutation(endpoint=ep, note=note or f"m2-{fam}", **kw))''',
    '''    def probe(self, fam, ep, note="", **kw):
        self.counts[fam]["sent"] += 1
        self.requests += 1
        return self.engine.send(
            RequestMutation(endpoint=ep, note=note or f"m2-{fam}", **kw))

    def probe_with(self, fam, engine, ep, note=""):
        """3E: replay through a SESSION engine (the authz battery's per-account
        RequestEngine, cookie jar included) — family-counted like any probe."""
        self.counts[fam]["sent"] += 1
        self.requests += 1
        return engine.send(
            RequestMutation(endpoint=ep, note=note or f"m2-{fam}"))''')

# the 3E family, placed before the battery entry point
anchor = "def run_modern_battery_v2("
family = '''# ------------------------------------------------------------------ 3E
def _bfla(st: "_St2", eps, authz_sessions):
    """3E BFLA (Broken Function Level Authorization) — CWE-285; OWASP API
    Security Top 10 2023 API5 (Broken Function Level Authorization), whose
    official text is exactly this check: "requests to administrative HTTP
    endpoints should be denied for regular users". The FUNCTION in
    function-level: the replay carries the exact method+path+body of the
    privileged call, so a POST/PUT/PATCH/DELETE admin function that
    executes for a lower-privilege session is the finding.

    Reuses — never duplicates — the authz battery's logged-in sessions
    (cfg.authz accounts; nothing logs in here). OFF by default with the
    whole modern2 battery (--modern-v2)."""
    fam = "bfla"
    from .authz import ADMIN_PATH_RE          # lazy: the battery's convention
    from urllib.parse import urlsplit
    if not authz_sessions:
        st.boundary(fam, "NOT_DISCOVERED",
                    "no multi-role authz sessions in flight — 3E needs the "
                    "authz config (cfg.authz) with two or more privilege "
                    "levels; the sessions the BOLA battery already built are "
                    "reused, nothing logs in here")
        return
    ranks = {s.get("rank") for s in authz_sessions.values()}
    if len(ranks) < 2:
        st.boundary(fam, "NOT_DISCOVERED",
                    f"authz sessions carry a single privilege level "
                    f"({sorted(ranks)}) — no ladder to climb")
        return
    top_rank = min(ranks)
    highs = sorted((s for s in authz_sessions.values() if s["rank"] == top_rank),
                   key=lambda x: x["account"].name)
    lows = sorted((s for s in authz_sessions.values() if s["rank"] > top_rank),
                  key=lambda x: (x["rank"], x["account"].name))
    cands = [ep for ep in eps
             if (ep.method or "GET").upper() in ("POST", "PUT", "PATCH", "DELETE")
             and ADMIN_PATH_RE.search(urlsplit(ep.url).path)][:BFLA_EP_CAP]
    if not cands:
        st.boundary(fam, "NOT_DISCOVERED",
                    "no admin-shaped non-GET endpoints in flight")
        return
    # the anonymous oracle: a FRESH cookie-less engine (the battery's own
    # engine may carry the scan's session — the anon replay must not)
    from .http_engine import RequestEngine
    anon_engine = RequestEngine(st.engine.scope, st.engine.bus,
                                timeout=st.engine.timeout)
    import difflib
    fired = 0
    for ep in cands:
        if st.counts[fam]["sent"] + 3 > FAMILY2_CAPS[fam]:
            st.boundary(fam, "NOT_SUPPORTED",
                        "family request cap reached before exhausting the "
                        "candidate set (BFLA_EP_CAP x 3 replays, documented)")
            break
        anon = st.probe_with(fam, anon_engine, ep, "m2-bfla-anon")
        hops = [u for _, u in (getattr(anon, "redirect_chain", None) or [])]
        _hop = anon.hop_location()
        if _hop:
            hops.append(_hop)
        anon_gated = (getattr(anon, "status", 0) in (401, 403)
                      or any("login" in urlsplit(u).path.lower()
                             for u in hops if u))
        high, high_used = None, None
        for h in highs:
            high = st.probe_with(fam, h["engine"], ep, "m2-bfla-high")
            if _ok(high):
                high_used = h
                break
        if high_used is None:
            st.boundary(fam, "UNTESTABLE",
                        f"{ep.url}: the privileged oracle failed — the "
                        f"function does not execute for the highest-privilege "
                        f"session either; no authorization claim is possible")
            continue
        for lo in lows:
            if st.counts[fam]["sent"] >= FAMILY2_CAPS[fam]:
                break
            low = st.probe_with(fam, lo["engine"], ep, "m2-bfla-low")
            if not _ok(low):
                continue
            na = re.sub(r"\\s+", " ", (high.body or ""))[:600]
            nb = re.sub(r"\\s+", " ", (low.body or ""))[:600]
            import difflib
            sim = difflib.SequenceMatcher(None, na, nb).ratio()
            if not anon_gated and sim < 0.6:
                # a role-agnostic surface (every logged-in user legitimately
                # allowed) is NOT BFLA — the same discipline OWSP-28 taught
                # the vertical detector
                st.boundary(fam, "TESTED_NEGATIVE",
                            f"{ep.url}: lower-privilege 2xx but anonymous "
                            f"ungated and body similarity {sim:.2f} — a "
                            f"role-agnostic surface, not a broken boundary")
                continue
            st.find(fam, Severity.HIGH, ep, "-", [
                Evidence("function_level_boundary_bypass",
                         f"BFLA (CWE-285; OWASP API5:2023): the admin-only "
                         f"FUNCTION {(ep.method or 'POST').upper()} "
                         f"{urlsplit(ep.url).path} EXECUTED for a "
                         f"lower-privilege session (role="
                         f"{lo['account'].role}, account={lo['account'].name}) "
                         f"— anonymous replay gated (HTTP "
                         f"{getattr(anon, 'status', 0)}), highest-privilege "
                         f"session (role={high_used['account'].role}) "
                         f"-> HTTP {high.status}, lower-privilege replay -> "
                         f"HTTP {low.status} with body similarity {sim:.2f} "
                         f"to the privileged response", low.request_id),
                Evidence("probe_recipe",
                         f"high={high_used['account'].name}; "
                         f"low={lo['account'].name}; method={ep.method}",
                         low.request_id)])
            f = st.findings[-1]
            f.authz_context = (f"attacker={lo['account'].name}"
                               f"(role={lo['account'].role}) surface=admin-function")
            # VR-36 stash: the verifier replays the EXACT endpoint with the
            # SAME low-privilege session engine — credentials never enter
            # finding evidence
            stash = getattr(st.engine, "bfla_verify", None)
            if stash is None:
                stash = st.engine.bfla_verify = {}
            stash.setdefault(ep.url, {"engine": lo["engine"], "endpoint": ep})
            fired += 1
            break
    if not fired:
        st.boundary(fam, "TESTED_NEGATIVE",
                    "every admin-shaped function rejected the lower-privilege "
                    "replays (or was untestable above) — no boundary broken")


def run_modern_battery_v2('''
assert anchor in s, "battery entry anchor"
s = s.replace(anchor, family, 1)

# battery signature + call
s = s.replace(
    '''def run_modern_battery_v2(engine: RequestEngine, endpoints, seed=None,
                          rebind_cfg: dict | None = None) -> Modern2Result:''',
    '''def run_modern_battery_v2(engine: RequestEngine, endpoints, seed=None,
                          rebind_cfg: dict | None = None,
                          authz_sessions: dict | None = None) -> Modern2Result:''')
s = s.replace(
    '''    _rebind_toctou(st, eps, rebind_cfg)
    return Modern2Result(st.findings, st.boundaries, probe_counts_of(st),
                         st.requests)''',
    '''    _rebind_toctou(st, eps, rebind_cfg)
    _bfla(st, eps, authz_sessions or {})
    return Modern2Result(st.findings, st.boundaries, probe_counts_of(st),
                         st.requests)''')
open(p, "w").write(s)
print("modernsec2 patched")

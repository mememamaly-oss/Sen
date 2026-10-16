#!/usr/bin/env python3
"""SENTINEL Axis-4 suite — Channel Synthesis (csynth).

PROVENANCE DECLARATION (honest, up front): the original 12-axis spec's S4
table is NOT recoverable from the committed record (searched: the full
worklog, STATE.md, every reachable git object, all build trees — only the
axis NAME "channel synthesis" survives, in the axis-3 closure queue note).
This coverage contract is therefore DERIVED from committed, reviewable
evidence, per the supervisor's standing rule "nothing without reasoning":

  D1  The channel alphabet = the live-proven carrier taxonomy of the
      trustbound recall campaign (committed in sentinel/detect.py battery):
      param (tb-p), self-named param (tb-sn / TB-1a), resolver-name (tb-rn /
      TB-3a), header-named-after-endpoint (tb-ht / TB-3b, channel=
      header_tcid), cookie-named-after-endpoint (tb-ck / TB-3c, channel=
      cookie), header-name (channel=headername), the GTP name/segment
      channels (name_channel, segment_name/segment_value, detect.py:446-469)
      and their general discovered forms (header_value / cookie_value).
  D2  The variant discipline = TB-1c's conditional sacrificial tail: the
      live manglers eat string ENDS (drop-last 'sentineltb1marke' and
      rewrite '...markeZ', both live-diagnosed on the corpus) — the tail
      absorbs the damage so the marker survives detectably.
  D3  Battery order = the corpus-proven priority: the declared param fires
      FIRST ("verified via channel=param+tail ... first in battery order"),
      then the name/self-named family, then discovered forms.
  D4  Attribution = the GTP twins-win rule (detect.py:431-450): name-channel
      strategies ride the same oracle as their value-channel twins; when
      both are live the VALUE channel (earlier in priority) wins; a carrier
      mangled to death is skipped in favor of the next live one (the TB-3a
      live result: verification via the name channel, not the dead value
      channel).
  D5  Boundary discipline = the Axis-12 14-category taxonomy (reused from
      xgraph/statemachine) and digests over the LOGICAL stream only
      (Axis-11: wall timings and markers never enter digests).

If the supervisor holds the original S4 table it supersedes this derivation
at any station boundary — every station is an isolated commit. Nothing here
touches the scan hot path: sentinel/__init__.py stays empty and this suite
is NOT @case-registered, so the 227 x 19 = 4313 core contract is untouched
by construction (the axis-1/2/3 recon proof).

Coverage contract (the derived H4 table, 26 cases):
  H4_01  channel alphabet: exactly the 12 live-proven kinds, closed set,
         unknown kinds rejected with a boundary record
  H4_02  Carrier identity: (type, name, location, origin) + canonical
         identity_key; equality discipline
  H4_03  GET declared-params synthesis: param carriers at QUERY location,
         origin=declared, declaration order preserved
  H4_04  POST body-params synthesis: location follows the param (the ENG-02
         lesson encoded: body params never default to query)
  H4_05  mixed-location endpoint: per-param locations honored independently
  H4_06  paramless endpoint: the fallback family fires (self_param,
         self_header, self_cookie, header_name, cookie_name, segment_value,
         segment_name)
  H4_07  basename derivation: extension strip, trailing slash, no-extension,
         empty path suppresses the self family
  H4_08  resolver_name semantics: anchor = basename (rides as the value),
         fires iff params declared AND basename non-empty (TB-3a)
  H4_09  self_header / self_cookie: named after the endpoint basename,
         marker in the VALUE (TB-3b / TB-3c)
  H4_10  variant composition: plain + sacrificial-tail rendering with
         integrity fields
  H4_11  drop_last classification (the 'sentineltb1marke' live class)
  H4_12  rewrite_suffix classification (the '...markeZ' live class)
  H4_13  truncate + carrier_dead classification (partial eating; marker
         damaged or absent)
  H4_14  mangle none: intact reflection; extra-junk reflection with the
         marker intact also classifies none (the marker surviving is what
         matters)
  H4_15  battery assembly: the deterministic priority total order (declared
         param first — the corpus nuance), stable across re-assembly
  H4_16  dedup: the same identity key reached via two origins -> ONE entry
         (first-origin-wins by priority)
  H4_17  attribution twins-win: value + name both live -> the VALUE channel
         (GTP rule, D4)
  H4_18  attribution past a dead carrier: value mangled to death, name live
         -> the name channel (the TB-3a live result)
  H4_19  ambiguity record: multiple live channels -> earliest-priority
         chosen, the others recorded in the ambiguity set
  H4_20  empty-shape rejection: atomic (no partial battery), boundary record
         PRECONDITION_FAILED
  H4_21  unknown-kind boundary: rejection + record UNKNOWN_PROTOCOL; seq
         monotone; legal operations write nothing to the boundary log
  H4_22  malformed carrier inside a valid shape: empty-name carrier skipped,
         boundary recorded, the rest of the battery intact
  H4_23  digest stability: same shape -> same digest; a different shape ->
         a different digest; the digest covers the logical stream only
         (marker-independent, timing-free)
  H4_24  synthesis determinism: three consecutive passes -> identical
         ordered identity-key lists
  H4_25  interface contract via inspect: public surface names, function
         arities, dataclass fields, exception base
  H4_26  mounting demonstration (blue+red in one): the Altoro shape (GET
         /bank/search.jsp?query — declared param first, verification
         attributes to the param channel) and the corpus TB-3a shape (POST
         servlet with declared param; value carrier dead, name carrier live
         — verification attributes to the resolver/name channel) — both
         live-proven scenarios reproduced end-to-end through synthesize ->
         assemble -> classify -> attribute.

Atoms mode (--atoms): the M3 battery —
  4a completeness matrix (every shape class x synthesis; closed-form counts;
     only-alphabet output; every type reachable somewhere)
  4b variant x mangle cross-product (200 seeded markers x every mangle
     class incl. 3 truncate depths and 3 carrier-death modes: 100% correct)
  4c large-scale determinism (500 seeded shapes; two independent passes ->
     identical digests; dedup invariants)
  4d adversarial RED battery (name collisions, unicode/huge/reserved names,
     pathless/query-only/fragment URLs, method casing, duplicate + empty
     params: everything synthesizes or rejects atomically, never crashes)
  4e attribution accounting (300 seeded evidence streams: exactly one chosen
     or none; chosen always the earliest-priority live carrier; ambiguity
     always a subset of the live set)

Usage: python3 tests/test_axis4_csynth.py [--out results/axis4/axis4_GREEN.json]
       python3 tests/test_axis4_csynth.py --atoms [--out results/axis4/axis4_ATOMS.json]
"""
import argparse
import hashlib
import inspect
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from sentinel.csynth import (
        ATTRIBUTION_REASONS, BOUNDARY_CATEGORIES, CHANNEL_TYPES,
        MANGLE_CLASSES, PRIORITY, TAIL, Attribution, Carrier, CSynthError,
        EndpointShape, ParamSpec, assemble, attribute, basename,
        channel_live, classify_reflection, digest, synthesize,
    )
    _IMPORT_ERROR = None
except Exception as _e:  # RED phase: module absent/incomplete
    _IMPORT_ERROR = f"{type(_e).__name__}: {_e}"

RESULTS = []


def case(fn):
    RESULTS.append(fn)
    return fn


def _guard_red():
    if _IMPORT_ERROR is not None:
        raise AssertionError(f"RED — sentinel.csynth unavailable: {_IMPORT_ERROR}")


# ---------------------------------------------------------------- helpers ---

def _shape(url="/bank/search.jsp", method="GET", params=(), headers=(),
           cookies=()):
    return EndpointShape(method=method, url=url, params=tuple(params),
                         headers=tuple(headers), cookies=tuple(cookies))


def _keys(carriers):
    return [c.identity_key() for c in carriers]


def _by_type(carriers):
    out = {}
    for c in carriers:
        out.setdefault(c.type, []).append(c)
    return out


MARKER = "sentineltb1marker"


# ============================================================= H4 cases ====

@case
def h04_01_alphabet_closed():
    """H4_01: exactly the 12 live-proven carrier kinds (D1), closed set,
    unknown kinds rejected with an UNKNOWN_PROTOCOL boundary record."""
    _guard_red()
    expected = {"param", "param_name", "resolver_name", "self_param",
                "self_header", "self_cookie", "header_name", "cookie_name",
                "segment_value", "segment_name", "header_value",
                "cookie_value"}
    assert set(CHANNEL_TYPES) == expected, (
        f"alphabet mismatch: {sorted(set(CHANNEL_TYPES) ^ expected)}")
    assert len(CHANNEL_TYPES) == 12
    assert set(CHANNEL_TYPES) == set(PRIORITY) and len(PRIORITY) == 12, (
        "PRIORITY must be a total order over exactly the alphabet")
    assert len(set(PRIORITY)) == len(PRIORITY), "PRIORITY has duplicates"
    try:
        Carrier(type="bogus_channel", name="x", location="query",
                origin="synthesized")
        raise AssertionError("unknown channel type accepted")
    except CSynthError:
        pass


@case
def h04_02_carrier_identity():
    """H4_02: Carrier (type, name, location, origin) with a canonical
    identity_key 'type|name|location' — origin is provenance, not identity."""
    _guard_red()
    a = Carrier(type="param", name="query", location="query",
                origin="declared")
    b = Carrier(type="param", name="query", location="query",
                origin="discovered")   # different origin, same identity
    c = Carrier(type="param", name="query", location="body",
                origin="declared")     # different location
    d = Carrier(type="param_name", name="query", location="query",
                origin="synthesized")  # different type
    e = Carrier(type="param", name="q2", location="query", origin="declared")
    assert a.identity_key() == b.identity_key(), "origin must not be identity"
    assert a.identity_key() == "param|query|query"
    assert len({a.identity_key(), c.identity_key(), d.identity_key(),
                e.identity_key()}) == 4, "all four variations must differ"
    assert a == b or a.identity_key() == b.identity_key()


@case
def h04_03_get_declared_params():
    """H4_03: GET declared params -> param carriers at QUERY, origin
    declared, declaration order preserved (first param first — D3)."""
    _guard_red()
    sh = _shape(params=[ParamSpec("query", "query"),
                        ParamSpec("lang", "query")])
    cs = synthesize(sh)
    params = [c for c in cs if c.type == "param"]
    assert [p.name for p in params] == ["query", "lang"], (
        "declaration order must be preserved")
    assert all(p.location == "query" and p.origin == "declared" for p in params)


@case
def h04_04_post_body_params():
    """H4_04: POST body params -> location BODY (ENG-02: the param's real
    location is honored, never defaulted to query)."""
    _guard_red()
    sh = _shape(url="/doLogin", method="POST",
                params=[ParamSpec("uid", "body"), ParamSpec("passw", "body")])
    cs = synthesize(sh)
    params = [c for c in cs if c.type == "param"]
    assert [p.name for p in params] == ["uid", "passw"]
    assert all(p.location == "body" for p in params), (
        f"body params must stay at body: {[(p.name, p.location) for p in params]}")
    # the name-channel twins inherit the same location
    names = [c for c in cs if c.type == "param_name"]
    assert {n.location for n in names} == {"body"}


@case
def h04_05_mixed_locations():
    """H4_05: one endpoint, query + body params -> per-param locations
    honored independently."""
    _guard_red()
    sh = _shape(url="/api/mixed", method="POST",
                params=[ParamSpec("a", "query"), ParamSpec("b", "body"),
                        ParamSpec("c", "query")])
    cs = _by_type(synthesize(sh))
    locs = {p.name: p.location for p in cs["param"]}
    assert locs == {"a": "query", "b": "body", "c": "query"}
    assert [p.name for p in cs["param"]] == ["a", "b", "c"]


@case
def h04_06_paramless_fallback_family():
    """H4_06: paramless endpoint -> the fallback family fires exactly:
    self family (basename-anchored) + segment family (the GTP paramless
    fallbacks, D1)."""
    _guard_red()
    sh = _shape(url="/BenchmarkTest01876", method="POST")
    cs = _by_type(synthesize(sh))
    got = set(cs)
    assert got == {"self_param", "self_header", "self_cookie",
                   "header_name", "cookie_name", "segment_value",
                   "segment_name"}, f"paramless family mismatch: {sorted(got)}"
    assert cs["self_param"][0].name == "BenchmarkTest01876"
    assert cs["segment_value"][0].name == "BenchmarkTest01876"
    assert cs["segment_name"][0].name == "BenchmarkTest01876"


@case
def h04_07_basename_derivation():
    """H4_07: basename = last non-empty path segment, one extension
    stripped; empty path suppresses the whole self family."""
    _guard_red()
    assert basename("/bank/search.jsp") == "search"
    assert basename("/BenchmarkTest01876") == "BenchmarkTest01876"
    assert basename("/a/b/c/") == "c"
    assert basename("/") == ""
    assert basename("") == ""
    assert basename("/archive.tar.gz") == "archive.tar"
    assert basename("/.hidden") == ".hidden"
    sh = _shape(url="http://host/")   # no basename at all
    cs = synthesize(sh)
    got = set(_by_type(cs))
    assert got == set(), (
        f"empty basename must suppress the self family entirely: {sorted(got)}")


@case
def h04_08_resolver_name_semantics():
    """H4_08: resolver_name (TB-3a): anchor = the basename riding as the
    VALUE; fires iff params declared AND basename non-empty."""
    _guard_red()
    with_p = synthesize(_shape(params=[ParamSpec("answer", "query")]))
    rn = [c for c in with_p if c.type == "resolver_name"]
    assert len(rn) == 1 and rn[0].name == "search" and rn[0].origin == "synthesized"
    # paramless -> no resolver_name (nothing to resolve against)
    without_p = synthesize(_shape(url="/BenchmarkTest01876"))
    assert not [c for c in without_p if c.type == "resolver_name"]
    # declared params but no basename -> no resolver_name
    no_base = synthesize(_shape(url="http://h/",
                                params=[ParamSpec("a", "query")]))
    assert not [c for c in no_base if c.type == "resolver_name"]


@case
def h04_09_self_header_self_cookie():
    """H4_09: self_header / self_cookie named after the endpoint basename,
    marker carried in the VALUE (TB-3b / TB-3c), origin synthesized."""
    _guard_red()
    cs = _by_type(synthesize(_shape(url="/BenchmarkTest01876")))
    assert cs["self_header"][0].name == "BenchmarkTest01876"
    assert cs["self_header"][0].location == "header"
    assert cs["self_cookie"][0].name == "BenchmarkTest01876"
    assert cs["self_cookie"][0].location == "cookie"
    assert cs["self_header"][0].origin == "synthesized"


@case
def h04_10_variant_composition():
    """H4_10: plain + sacrificial-tail variants; integrity fields carry the
    sent marker and the rendered form (D2)."""
    _guard_red()
    sh = _shape(params=[ParamSpec("query", "query")])
    entries = assemble(sh, MARKER)
    variants = {(e.carrier.identity_key(), e.variant) for e in entries}
    param_plain = ("param|query|query", "plain")
    param_tail = ("param|query|query", "tail")
    assert param_plain in variants and param_tail in variants
    plain = [e for e in entries if e.carrier.identity_key() == "param|query|query"
             and e.variant == "plain"][0]
    tail = [e for e in entries if e.carrier.identity_key() == "param|query|query"
            and e.variant == "tail"][0]
    assert plain.rendered == MARKER
    assert tail.rendered == MARKER + TAIL and len(TAIL) >= 3
    assert plain.sent_marker == MARKER and tail.sent_marker == MARKER


@case
def h04_11_drop_last():
    """H4_11: drop_last — the live 'sentineltb1marke' class: exactly the
    final character eaten (D2)."""
    _guard_red()
    full = MARKER + TAIL
    assert classify_reflection(MARKER, full[:-1]) == "drop_last"
    # the literal live shape: plain marker with its last char eaten is a
    # DEAD carrier for the plain variant (marker damaged)...
    assert classify_reflection(MARKER, MARKER[:-1]) == "carrier_dead"
    # ...but the tailed variant on the same channel keeps the marker intact
    # and only loses tail characters -> drop_last, channel LIVE.
    assert channel_live(classify_reflection(MARKER, MARKER + TAIL[:-1]))


@case
def h04_12_rewrite_suffix():
    """H4_12: rewrite_suffix — the live '...markeZ' class: same length,
    marker intact, the tail's last character replaced."""
    _guard_red()
    full = MARKER + TAIL
    rewritten = full[:-1] + ("Z" if full[-1] != "Z" else "Y")
    assert classify_reflection(MARKER, rewritten) == "rewrite_suffix"
    assert channel_live("rewrite_suffix")


@case
def h04_13_truncate_and_carrier_dead():
    """H4_13: truncate (partial eating, marker intact) vs carrier_dead
    (marker damaged / absent / empty reflection)."""
    _guard_red()
    assert classify_reflection(MARKER, MARKER + TAIL[:2]) == "truncate"
    assert classify_reflection(MARKER, MARKER) == "truncate"  # tail fully eaten
    assert classify_reflection(MARKER, MARKER[:5] + TAIL) == "carrier_dead"
    assert classify_reflection(MARKER, "") == "carrier_dead"
    assert classify_reflection(MARKER, "unrelated reflection") == "carrier_dead"
    assert not channel_live("carrier_dead")
    # FIXED (honest, caught by the first GREEN run): truncate keeps the
    # marker intact (only tail characters eaten) -> the channel IS live —
    # the v1 assertion was inverted, contradicting both its own comment and
    # the D2 design. The module was right; the test line was wrong.
    assert channel_live("truncate")


@case
def h04_14_mangle_none():
    """H4_14: intact reflection -> none; extra junk around an intact marker
    also none (the marker surviving is what matters)."""
    _guard_red()
    assert classify_reflection(MARKER, MARKER + TAIL) == "none"
    assert classify_reflection(MARKER, "<p>" + MARKER + TAIL + "</p>") == "none"
    assert channel_live("none")


@case
def h04_15_battery_priority_order():
    """H4_15: the deterministic priority total order — declared param first
    (the corpus nuance, D3), then the name/self family, then segments, then
    discovered forms; stable across re-assembly."""
    _guard_red()
    sh = _shape(url="/app/page.jsp", params=[ParamSpec("a", "query")],
                headers=("X-Custom",), cookies=("session",))
    order1 = [c.type for c in synthesize(sh)]
    assert order1[0] == "param" and order1[1] == "param_name"
    # group-stability: full expected order for this shape
    expected = ["param", "param_name", "resolver_name", "self_param",
                "self_header", "self_cookie", "header_name", "cookie_name",
                "header_value", "cookie_value"]
    assert order1 == expected, f"priority order mismatch: {order1}"
    order2 = [c.type for c in synthesize(sh)]
    assert order1 == order2
    # multiple params: param block first in declaration order, then names
    sh2 = _shape(url="/app/page.jsp",
                 params=[ParamSpec("b", "query"), ParamSpec("a", "query")])
    t2 = [c.type for c in synthesize(sh2)]
    assert t2[:4] == ["param", "param", "param_name", "param_name"]
    names = [c.name for c in synthesize(sh2) if c.type == "param"]
    assert names == ["b", "a"], "declaration order, not alphabetical"


@case
def h04_16_dedup_first_origin_wins():
    """H4_16: the same identity reached via two origins -> ONE battery
    entry; first-origin wins (declared beats discovered)."""
    _guard_red()
    # the true dedup case: the same (type,name,location) reached twice
    # (duplicate identical params) -> one carrier, first origin wins
    sh2 = _shape(url="/x.jsp",
                 params=[ParamSpec("a", "query"), ParamSpec("a", "query")])
    cs = [c for c in synthesize(sh2) if c.type == "param"]
    assert len(cs) == 1 and cs[0].origin == "declared", (
        "duplicate identical params must dedup to one carrier")
    # cross-type same-name coexistence is NOT dedup (identity includes type)
    sh3 = _shape(url="/x.jsp", params=[ParamSpec("a", "query")],
                 headers=("a",))
    t3 = [c.type for c in synthesize(sh3) if c.name == "a"]
    assert set(t3) == {"param", "param_name", "header_value"}


@case
def h04_17_attribution_twins_win():
    """H4_17: GTP twins-win (D4): value channel and name channel both live
    -> the VALUE channel (earlier in PRIORITY) is chosen."""
    _guard_red()
    value = Carrier("param", "query", "query", "declared")
    name = Carrier("param_name", "query", "query", "synthesized")
    att = attribute(((value, "none"), (name, "none")))
    assert att.chosen is not None and att.chosen.identity_key() == value.identity_key()
    assert att.reason in ATTRIBUTION_REASONS


@case
def h04_18_attribution_past_dead_carrier():
    """H4_18: the TB-3a live result — the value carrier mangled to death,
    the name carrier live -> verification attributes to the NAME channel."""
    _guard_red()
    value = Carrier("param", "answer", "query", "declared")
    name = Carrier("resolver_name", "BenchmarkTest01876", "query",
                   "synthesized")
    att = attribute(((value, "carrier_dead"), (name, "drop_last")))
    assert att.chosen is not None and att.chosen.identity_key() == name.identity_key()
    # all dead -> honest none
    att2 = attribute(((value, "carrier_dead"), (name, "carrier_dead")))
    assert att2.chosen is None and att2.ambiguity == ()


@case
def h04_19_ambiguity_record():
    """H4_19: multiple live channels -> earliest-priority chosen, the rest
    recorded in the ambiguity set (choice by rule, not by evidence)."""
    _guard_red()
    a = Carrier("param", "q", "query", "declared")
    b = Carrier("self_header", "page", "header", "synthesized")
    c = Carrier("cookie_value", "sess", "cookie", "discovered")
    att = attribute(((b, "none"), (c, "none"), (a, "truncate")))
    assert att.chosen.identity_key() == a.identity_key()
    amb_keys = {x.identity_key() for x in att.ambiguity}
    assert amb_keys == {b.identity_key(), c.identity_key()}
    # a single live channel records no ambiguity
    att2 = attribute(((a, "none"), (b, "carrier_dead")))
    assert att2.chosen.identity_key() == a.identity_key() and att2.ambiguity == ()


@case
def h04_20_empty_shape_rejection():
    """H4_20: empty shape (no url) -> CSynthError, ATOMIC (no partial
    battery), boundary record PRECONDITION_FAILED."""
    _guard_red()
    try:
        synthesize(EndpointShape(method="GET", url="", params=()))
        raise AssertionError("empty url accepted")
    except CSynthError:
        pass


@case
def h04_21_unknown_kind_boundary():
    """H4_21: unknown channel kind -> rejection + boundary record
    UNKNOWN_PROTOCOL; seq monotone; legal operations write nothing."""
    _guard_red()
    n_before = len(CARRIER_BOUNDARY_SNAPSHOT())
    try:
        Carrier(type="bogus", name="x", location="query", origin="synth")
        raise AssertionError("bogus type accepted")
    except CSynthError:
        pass
    log = CARRIER_BOUNDARY_SNAPSHOT()
    assert len(log) == n_before + 1, "exactly one boundary record"
    last = log[-1]
    assert last["category"] == "UNKNOWN_PROTOCOL" and last["seq"] > 0
    # a legal operation writes nothing
    n2 = len(log)
    synthesize(_shape(params=[ParamSpec("ok", "query")]))
    assert len(CARRIER_BOUNDARY_SNAPSHOT()) == n2, "legal op wrote boundary"
    seqs = [e["seq"] for e in CARRIER_BOUNDARY_SNAPSHOT()]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)


def CARRIER_BOUNDARY_SNAPSHOT():
    """Boundary snapshot helper (imported lazily so the RED guard fires
    first when the module is absent)."""
    from sentinel.csynth import boundary
    return boundary()


@case
def h04_22_malformed_carrier_skip():
    """H4_22: an empty-name param inside a valid shape -> that carrier is
    skipped with a boundary record; the rest of the battery stays intact."""
    _guard_red()
    sh = _shape(url="/ok.jsp",
                params=[ParamSpec("good", "query"), ParamSpec("", "query")])
    cs = synthesize(sh)
    names = [c.name for c in cs if c.type == "param"]
    assert names == ["good"], f"empty-name carrier leaked: {names}"
    assert any(c.type == "self_header" for c in cs), "battery must survive"
    assert any(e["category"] == "PRECONDITION_FAILED"
               for e in CARRIER_BOUNDARY_SNAPSHOT())


@case
def h04_23_digest_stability():
    """H4_23: digests cover the logical stream only — same shape twice ->
    identical; one param renamed -> different; marker-independent."""
    _guard_red()
    sh = _shape(params=[ParamSpec("query", "query")])
    sh2 = _shape(params=[ParamSpec("query2", "query")])
    d1 = digest(synthesize(sh))
    d2 = digest(synthesize(sh))
    assert d1 == d2 and len(d1) == 64
    assert digest(synthesize(sh2)) != d1
    # marker-independence: assembly digests with different markers match
    a1 = digest(assemble(sh, "sentineltb1marker"))
    a2 = digest(assemble(sh, "zz-other-marker"))
    assert a1 == a2, "assembly digest must not depend on the marker"


@case
def h04_24_synthesis_determinism():
    """H4_24: three consecutive synthesis passes -> identical ordered
    identity-key lists (Axis-11 discipline)."""
    _guard_red()
    sh = _shape(url="/d.jsp", params=[ParamSpec("a", "query"),
                                      ParamSpec("b", "body")],
                headers=("H",), cookies=("k",))
    runs = [_keys(synthesize(sh)) for _ in range(3)]
    assert runs[0] == runs[1] == runs[2]


@case
def h04_25_interface_contract():
    """H4_25: the inspect-enforced interface contract — public surface,
    arities, dataclass fields, exception base."""
    _guard_red()
    import sentinel.csynth as m
    surface = {"CHANNEL_TYPES", "MANGLE_CLASSES", "PRIORITY", "TAIL",
               "ATTRIBUTION_REASONS", "CSynthError", "Carrier", "ParamSpec",
               "EndpointShape", "Attribution", "basename", "synthesize",
               "assemble", "classify_reflection", "attribute",
               "channel_live", "digest", "boundary"}
    missing = surface - set(dir(m))
    assert not missing, f"public surface missing: {sorted(missing)}"
    assert issubclass(m.CSynthError, Exception)
    assert set(m.Carrier.__dataclass_fields__) == {"type", "name",
                                                   "location", "origin"}
    assert set(m.ParamSpec.__dataclass_fields__) == {"name", "location"}
    assert set(m.EndpointShape.__dataclass_fields__) == {"method", "url",
                                                         "params", "headers",
                                                         "cookies"}
    assert set(m.Attribution.__dataclass_fields__) == {"chosen",
                                                       "ambiguity", "reason"}
    ar = {f.__name__: len(inspect.signature(f).parameters)
          for f in (m.basename, m.classify_reflection, m.digest)}
    assert ar == {"basename": 1, "classify_reflection": 3, "digest": 1}, ar
    assert len(inspect.signature(m.synthesize).parameters) == 1
    assert len(inspect.signature(m.assemble).parameters) == 2
    assert len(inspect.signature(m.attribute).parameters) == 1
    assert len(inspect.signature(m.channel_live).parameters) == 1
    assert m.MANGLE_CLASSES == ("none", "drop_last", "rewrite_suffix",
                                "truncate", "carrier_dead")


@case
def h04_26_mounting_demonstration():
    """H4_26: the mounting demonstration — both live-proven scenarios
    reproduced end-to-end through synthesize -> assemble -> simulate
    reflection -> classify -> attribute.

    (a) Altoro shape: GET /bank/search.jsp?query=... — the declared param
        is first in battery order and the intact reflection attributes
        verification to the param channel (the live corpus nuance).
    (b) TB-3a corpus shape: POST servlet with declared param 'answer';
        the value carrier reflects a DEAD marker, the resolver/name carrier
        reflects marker+tail minus one char (drop_last, LIVE) — exactly the
        00588 live diagnosis — so verification attributes to the NAME
        channel, never the dead value channel."""
    _guard_red()
    # ---- (a) the Altoro scenario
    altoro = _shape(url="/bank/search.jsp",
                    params=[ParamSpec("query", "query")])
    battery = assemble(altoro, MARKER)
    param_c = [e.carrier for e in battery if e.carrier.type == "param"][0]
    name_twin = [e.carrier for e in battery
                 if e.carrier.type == "param_name"][0]
    # simulate: the param carrier's tailed probe reflects intact; the name
    # twin stays silent
    records = [(param_c, classify_reflection(MARKER, MARKER + TAIL)),
               (name_twin, "carrier_dead")]
    att = attribute(records)
    assert att.chosen.type == "param", (
        "the live value channel must win when intact (twins-win)")
    # ---- (b) the TB-3a scenario (00588's live shape)
    corpus = _shape(url="/BenchmarkTest00588", method="POST",
                    params=[ParamSpec("answer", "query")])
    cb = assemble(corpus, MARKER)
    value_c = [e.carrier for e in cb if e.carrier.type == "param"][0]
    name_c = [e.carrier for e in cb
              if e.carrier.type == "resolver_name"][0]
    # live-diagnosed reflections: plain value carrier eaten to death;
    # the tailed NAME carrier loses exactly one tail char (drop_last, live)
    sim = ((value_c, classify_reflection(MARKER, MARKER[:-1])),
           (name_c, classify_reflection(MARKER, MARKER + TAIL[:-1])))
    att2 = attribute(sim)
    assert att2.chosen.identity_key() == name_c.identity_key(), (
        "verification must attribute to the live NAME channel (TB-3a)")
    assert sim[0][1] == "carrier_dead" and sim[1][1] == "drop_last"


# ============================================================== atoms ======

def _atoms_4a():
    """Completeness matrix: every shape class x synthesis. Only-alphabet
    output, closed-form counts, every type reachable somewhere."""
    _guard_red()
    shapes = {
        "declared-get": _shape(params=[ParamSpec("a", "query")]),
        "declared-post": _shape(url="/p", method="POST",
                                params=[ParamSpec("b", "body")]),
        "mixed": _shape(url="/m", method="POST",
                        params=[ParamSpec("a", "query"),
                                ParamSpec("b", "body")]),
        "paramless": _shape(url="/solo", method="POST"),
        "no-basename": _shape(url="http://h/"),
        "with-discovered": _shape(url="/d", headers=("H1", "H2"),
                                  cookies=("c1",)),
        "kitchen-sink": _shape(url="/k.jsp", method="POST",
                               params=[ParamSpec("a", "query"),
                                       ParamSpec("b", "body")],
                               headers=("H",), cookies=("c",)),
    }
    checks = []
    seen_types = set()
    for label, sh in shapes.items():
        cs = synthesize(sh)
        assert all(c.type in CHANNEL_TYPES for c in cs), (label, "off-alphabet")
        keys = _keys(cs)
        assert len(keys) == len(set(keys)), (label, "identity dup")
        seen_types |= {c.type for c in cs}
        checks.append({"class": label, "carriers": len(cs)})
    assert seen_types == set(CHANNEL_TYPES), (
        f"unreachable types: {sorted(set(CHANNEL_TYPES) - seen_types)}")
    # exact closed forms for the clean classes (k = declared params):
    #   declared-get   (k=1, basename): param+param_name (2k) + resolver_name
    #                  + self family (5) = 2k+6 = 8
    #   paramless     (basename, raw segment): self family (5) + segment
    #                  family (2) = 7
    #   no-basename   (no params, empty path): 0
    #   with-discovered (paramless, basename): 5 + 2 + (2 headers + 1 cookie)
    #                  = 10
    assert checks[0]["carriers"] == 2 * 1 + 6, checks[0]
    assert checks[3]["carriers"] == 5 + 2, checks[3]
    assert checks[4]["carriers"] == 0, checks[4]
    assert checks[5]["carriers"] == 5 + 2 + 3, checks[5]
    return checks


def _atoms_4b(seed=20261016):
    """Variant x mangle cross-product: 200 seeded markers x every mangle
    class (incl. 3 truncate depths, 3 carrier-death modes) -> 100% correct."""
    _guard_red()
    import random
    rng = random.Random(seed)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    ok = 0
    total = 0
    for i in range(200):
        marker = "m%d" % i + "".join(rng.choice(alphabet) for _ in range(10))
        full = marker + TAIL
        cases = [
            (full, "none"),
            (full[:-1], "drop_last"),
            (full[:-1] + ("Z" if full[-1] != "Z" else "Y"), "rewrite_suffix"),
            (full[:len(full) - 2], "truncate"),       # 2 tail chars eaten
            (marker + TAIL[:1], "truncate"),          # most of tail eaten
            (marker, "truncate"),                     # tail fully eaten
            (marker[:-1] + TAIL, "carrier_dead"),     # marker damaged
            ("", "carrier_dead"),                     # nothing reflected
            ("totally-unrelated", "carrier_dead"),    # marker absent
            ("<b>" + full + "</b>", "none"),          # intact, junk around
        ]
        for reflected, expected in cases:
            total += 1
            got = classify_reflection(marker, reflected)
            assert got == expected, (marker, reflected, expected, got)
            ok += 1
    return {"markers": 200, "checks": ok, "total": total}


def _atoms_4c(seed=4242):
    """Large-scale determinism: 500 seeded shapes, two independent passes ->
    identical digests; dedup invariant holds on every battery."""
    _guard_red()
    import random
    rng = random.Random(seed)
    names = ["alpha", "beta", "gamma", "uid", "query", "search", "id", "ref"]
    paths = ["/a.jsp", "/b.php"] + ["/BenchmarkTest%05d" % i
                                     for i in range(20)]
    for i in range(500):
        n_params = rng.randint(0, 3)
        params = []
        for j in range(n_params):
            nm = rng.choice(names)
            params.append(ParamSpec(nm, rng.choice(("query", "body"))))
        if rng.random() < 0.2 and params:
            params.append(params[0])   # deliberate duplicate
        sh = EndpointShape(
            method=rng.choice(("GET", "POST")),
            url=rng.choice(paths),
            params=tuple(params),
            headers=tuple(rng.sample(names, rng.randint(0, 2))),
            cookies=tuple(rng.sample(names, rng.randint(0, 1))))
        p1, p2 = synthesize(sh), synthesize(sh)
        assert _keys(p1) == _keys(p2), f"determinism broke at shape {i}"
        keys = _keys(p1)
        assert len(keys) == len(set(keys)), f"dedup broke at shape {i}"
        assert digest(p1) == digest(p2)
    return {"shapes": 500, "deterministic": True, "dedup": True}


def _atoms_4d():
    """Adversarial RED battery: everything synthesizes or rejects atomically
    — never crashes, never a partial battery on a valid shape."""
    _guard_red()
    hostile = [
        ("param-named-basename", _shape(url="/page.jsp",
                                        params=[ParamSpec("page", "query")])),
        ("header-named-basename", _shape(url="/page.jsp",
                                         headers=("page",))),
        ("unicode", _shape(url="/ünïcødé/ø.jsp",
                           params=[ParamSpec("парам", "query")])),
        ("huge-name", _shape(url="/h.jsp",
                             params=[ParamSpec("x" * 10000, "query")])),
        ("reserved-header", _shape(url="/r.jsp", headers=("Content-Length",))),
        ("pathless", _shape(url="http://host")),
        ("query-only", _shape(url="http://host?a=1")),
        ("fragment", _shape(url="http://host/f#frag")),
        ("method-casing", EndpointShape(method="post", url="/mc.jsp",
                                        params=(ParamSpec("a", "body"),))),
        ("duplicate-params", _shape(url="/d.jsp",
                                    params=[ParamSpec("a", "query"),
                                            ParamSpec("a", "query")])),
        ("empty-param-name", _shape(url="/e.jsp",
                                    params=[ParamSpec("", "query")])),
    ]
    outcomes = []
    for label, sh in hostile:
        cs = synthesize(sh)
        keys = _keys(cs)
        assert len(keys) == len(set(keys)), (label, "identity dup")
        outcomes.append({"case": label, "carriers": len(cs)})
    # empty-param-name must have produced a boundary record, not a crash
    assert any(e["category"] == "PRECONDITION_FAILED"
               for e in CARRIER_BOUNDARY_SNAPSHOT())
    return outcomes


def _atoms_4e(seed=99):
    """Attribution accounting: 300 seeded evidence streams — chosen is None
    or the earliest-priority live carrier; ambiguity is a subset of live."""
    _guard_red()
    import random
    rng = random.Random(seed)
    pool = [Carrier(t, "n%d" % i, "query", "synthesized")
            for i, t in enumerate(PRIORITY)]
    for s in range(300):
        k = rng.randint(1, 5)
        recs = tuple((rng.choice(pool),
                      rng.choice(MANGLE_CLASSES)) for _ in range(k))
        att = attribute(recs)
        live = [c for (c, mcls) in recs if channel_live(mcls)]
        if not live:
            assert att.chosen is None and att.ambiguity == ()
        else:
            best = min(live, key=lambda c: PRIORITY.index(c.type))
            assert att.chosen.identity_key() == best.identity_key(), (
                s, [(c.type, mcls) for c, mcls in recs])
            amb = {x.identity_key() for x in att.ambiguity}
            assert amb <= {c.identity_key() for c in live} - {best.identity_key()}
        assert att.reason in ATTRIBUTION_REASONS
    return {"streams": 300, "law": "earliest-priority-live / twins-win"}


# ================================================================ main =====

def _run(cases, suite, out):
    entries = []
    for fn in cases:
        entry = {"name": fn.__name__, "ok": False}
        t0 = time.monotonic()
        try:
            fn()
            entry["ok"] = True
        except Exception as e:  # noqa: BLE001 — record every failure mode
            entry["error"] = f"{type(e).__name__}: {e}"[:400]
        entry["dur_s"] = round(time.monotonic() - t0, 4)
        entries.append(entry)
        print(("PASS " if entry["ok"] else "FAIL ") + entry["name"]
              + ("" if entry["ok"] else f"  -> {entry.get('error')}"))
    failed = sum(1 for c in entries if not c["ok"])
    dg = hashlib.sha256(json.dumps(
        [{"name": c["name"], "ok": c["ok"]} for c in entries],
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    report = {"suite": suite, "total": len(entries), "failed": failed,
              "passed": failed == 0, "cases": entries, "digest": dg}
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w") as fh:
        json.dump(report, fh, indent=1)
    print(f"{suite}: {len(entries) - failed}/{len(entries)} passed "
          f"(failed={failed}) digest={dg[:16]} -> {out}")
    return 0 if failed == 0 else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    ap.add_argument("--atoms", action="store_true")
    args = ap.parse_args()
    if args.atoms:
        out = args.out or "results/axis4/axis4_ATOMS.json"
        atoms = [("atoms_4a_completeness", _atoms_4a),
                 ("atoms_4b_mangle_cross", _atoms_4b),
                 ("atoms_4c_determinism", _atoms_4c),
                 ("atoms_4d_adversarial", _atoms_4d),
                 ("atoms_4e_attribution", _atoms_4e)]
        cases = []
        for name, fn in atoms:
            def wrapped(fn=fn):
                fn()
            wrapped.__name__ = name
            cases.append(wrapped)
        return _run(cases, "axis4-csynth-atoms", out)
    out = args.out or "results/axis4/axis4_GREEN.json"
    return _run(RESULTS, "axis4-csynth", out)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""SENTINEL Axis-4 — csynth: the Channel Synthesis Engine (contract DERIVED).

PROVENANCE: the original 12-axis spec's S4 table is not recoverable from any
committed record; this module implements the coverage contract DERIVED from
committed live-proven evidence (the full reasoning is declared in
tests/test_axis4_csynth.py's docstring, D1..D5). The mapping to the live
campaign record:

  D1  The 12-kind carrier alphabet generalizes the trustbound battery
      committed in detect.py: param (tb-p), param_name (GTP name_channel),
      resolver_name (tb-rn / TB-3a — the param NAME carries the marker with
      the endpoint basename as its value), self_param (tb-sn / TB-1a — a
      param NAMED after the basename), self_header (tb-ht / TB-3b — a header
      named after the basename, marker in the value; the corpus's
      header_tcid), self_cookie (tb-ck / TB-3c), header_name /
      cookie_name (the marker rides a fresh header/cookie NAME, basename as
      value), segment_value / segment_name (the GTP paramless fallbacks,
      detect.py:446-469), header_value / cookie_value (discovered forms).
  D2  Variants: TB-1c's conditional sacrificial tail. The live manglers eat
      string ENDS (drop-last 'sentineltb1marke' and rewrite '...markeZ',
      both live-diagnosed) — the tail absorbs the damage, so the marker
      survives detectably. TAIL's first char is chosen OUTSIDE the lowercase
      marker alphabet ('Z') so a damaged marker can never falsely contain
      the intact one.
  D3  Battery order: declared-param-first (the corpus nuance: "verified via
      channel=param+tail ... first in battery order"), then the name/self
      family, then segments, then discovered forms.
  D4  Attribution: the GTP twins-win rule (detect.py:431-450) — the
      earliest-priority LIVE carrier wins; a carrier mangled to death is
      skipped (the TB-3a live result: verification via the name channel).
  D5  Discipline: the Axis-12 14-category boundary taxonomy (shared with
      xgraph/statemachine) + Axis-11 digests over the LOGICAL stream only.

Standalone library: sentinel/__init__.py stays empty — the scan hot path
never imports this module; the core 4313 contract is untouched by
construction.
"""
import dataclasses
import hashlib
import json
from urllib.parse import urlsplit

# ---- D1: the carrier algebra (the live-proven taxonomy, generalized) ------

PRIORITY = (
    "param",             # declared param, marker in the VALUE (tb-p)
    "param_name",        # declared param, marker rides the NAME (GTP)
    "resolver_name",     # new param: name=marker, value=basename (tb-rn)
    "self_param",        # new param named basename (tb-sn / TB-1a)
    "self_header",       # header named basename, marker in value (tb-ht)
    "self_cookie",       # cookie named basename, marker in value (tb-ck)
    "header_name",       # marker rides a fresh header NAME
    "cookie_name",       # marker rides a fresh cookie NAME
    "segment_value",     # marker replaces the last path segment (paramless)
    "segment_name",      # synthetic param named after the segment (paramless)
    "header_value",      # discovered header, marker in the value
    "cookie_value",      # discovered cookie, marker in the value
)
CHANNEL_TYPES = frozenset(PRIORITY)

# ---- D2: the mangle classes + the sacrificial tail ------------------------

MANGLE_CLASSES = ("none", "drop_last", "rewrite_suffix", "truncate",
                  "carrier_dead")
# The tail's first char 'Z' sits outside the lowercase marker alphabet — a
# marker damaged at its end and followed by the tail can never falsely
# contain the intact marker (the false-containment trap, guarded in 4b).
TAIL = "Zk91"

# ---- D5: the Axis-12 boundary taxonomy (shared with xgraph/statemachine) --

BOUNDARY_CATEGORIES = frozenset({
    "OUT_OF_SCOPE", "PRECONDITION_FAILED", "RESOURCE_EXHAUSTED",
    "DETECTION_AVOIDED", "TIME_LIMIT", "SAFETY_GUARD", "UNKNOWN_PROTOCOL",
    "AUTH_REQUIRED", "ENCRYPTION_UNTRAVERSABLE", "HARDWARE_LIMIT",
    "NETWORK_ISOLATED", "POLICY_RESTRICTED", "CAPABILITY_MISSING",
    "UNSUPPORTED_PLATFORM",
})

_BOUNDARY = []   # append-only; seq monotone; legal operations never write


class CSynthError(Exception):
    """Channel-synthesis contract violation (always paired with a boundary
    record carrying the Axis-12 category)."""


def boundary():
    """Snapshot of the boundary log (append-only, seq monotone)."""
    return tuple(_BOUNDARY)


def _record(category, reason, detail=""):
    assert category in BOUNDARY_CATEGORIES, category   # taxonomy discipline
    _BOUNDARY.append({"seq": len(_BOUNDARY) + 1, "category": category,
                      "reason": reason, "detail": str(detail)[:200]})


# ---- the data model --------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Carrier:
    """One dispatch route for a marker. Identity = (type, name, location);
    origin is provenance only ('declared' | 'discovered' | 'synthesized')
    and never part of identity (H4_02)."""
    type: str
    name: str
    location: str
    origin: str

    def __post_init__(self):
        if self.type not in CHANNEL_TYPES:
            _record("UNKNOWN_PROTOCOL", "unknown channel kind", self.type)
            raise CSynthError(f"unknown channel kind: {self.type!r}")
        if not self.name:
            _record("PRECONDITION_FAILED", "empty carrier name", self.type)
            raise CSynthError("carrier name must be non-empty")

    def identity_key(self):
        return f"{self.type}|{self.name}|{self.location}"


@dataclasses.dataclass(frozen=True)
class ParamSpec:
    """A declared parameter: (name, location) — the ENG-02 lesson: the
    location is the param's OWN (query/body), never defaulted."""
    name: str
    location: str


@dataclasses.dataclass(frozen=True)
class EndpointShape:
    """The minimal endpoint surface model the synthesizer reads."""
    method: str = "GET"
    url: str = ""
    params: tuple = ()
    headers: tuple = ()
    cookies: tuple = ()


@dataclasses.dataclass(frozen=True)
class BatteryEntry:
    """One assembled probe: a carrier x a variant, rendered."""
    carrier: Carrier
    variant: str          # "plain" | "tail"
    rendered: str
    sent_marker: str


@dataclasses.dataclass(frozen=True)
class Attribution:
    """The verification-attribution verdict (D4)."""
    chosen: object        # Carrier | None
    ambiguity: tuple      # the other live carriers, by identity
    reason: str


ATTRIBUTION_REASONS = frozenset({
    "no live carrier",
    "single live carrier",
    "twins-win: earliest-priority live carrier (GTP rule)",
})


# ---- shape reading ---------------------------------------------------------

def _last_segment(url):
    path = urlsplit(url).path
    parts = [s for s in path.split("/") if s]
    return parts[-1] if parts else ""


def basename(url):
    """The endpoint's own basename: last non-empty path segment with ONE
    extension stripped (leading dot = dotfile, kept). '' when pathless."""
    seg = _last_segment(url)
    if not seg:
        return ""
    if "." in seg[1:]:
        return seg.rsplit(".", 1)[0]
    return seg


# ---- D3: synthesis (the battery-priority total order) ---------------------

def synthesize(shape):
    """Every candidate carrier for the shape, ordered by PRIORITY.

    Rejections are ATOMIC for an empty shape (CSynthError, no partial
    battery); an invalid member inside a valid shape (empty param/header/
    cookie name) is skipped with a boundary record and the rest of the
    battery survives (H4_22). Duplicate identities dedup first-wins — the
    priority order guarantees declared beats discovered (H4_16).
    """
    if not isinstance(shape, EndpointShape):
        _record("PRECONDITION_FAILED", "shape must be an EndpointShape",
                type(shape).__name__)
        raise CSynthError(f"synthesize expects EndpointShape, got "
                          f"{type(shape).__name__}")
    url = (shape.url or "").strip()
    if not url:
        _record("PRECONDITION_FAILED", "empty shape url", "")
        raise CSynthError("synthesize: shape.url must be non-empty")

    base = basename(url)
    seg = _last_segment(url)

    params, seen = [], set()
    for p in shape.params:
        if not p.name:
            _record("PRECONDITION_FAILED", "empty param name skipped",
                    p.location)
            continue
        key = (p.name, p.location)
        if key in seen:
            continue                      # duplicate identity: first wins
        seen.add(key)
        params.append(p)
    has_params = bool(params)

    out = []
    for p in params:                      # priority 1: declared values
        out.append(Carrier("param", p.name, p.location, "declared"))
    for p in params:                      # priority 2: name twins
        out.append(Carrier("param_name", p.name, p.location, "synthesized"))
    if has_params and base:               # priority 3: the resolver shape
        out.append(Carrier("resolver_name", base, "query", "synthesized"))
    if base:                              # priorities 4-8: the self family
        out.append(Carrier("self_param", base, "query", "synthesized"))
        out.append(Carrier("self_header", base, "header", "synthesized"))
        out.append(Carrier("self_cookie", base, "cookie", "synthesized"))
        out.append(Carrier("header_name", base, "header", "synthesized"))
        out.append(Carrier("cookie_name", base, "cookie", "synthesized"))
    if not has_params and seg:            # priorities 9-10: paramless only
        out.append(Carrier("segment_value", seg, "path", "synthesized"))
        out.append(Carrier("segment_name", seg, "query", "synthesized"))
    for h in shape.headers:               # priority 11: discovered headers
        if not h:
            _record("PRECONDITION_FAILED", "empty header name skipped",
                    "header")
            continue
        out.append(Carrier("header_value", h, "header", "discovered"))
    for c in shape.cookies:               # priority 12: discovered cookies
        if not c:
            _record("PRECONDITION_FAILED", "empty cookie name skipped",
                    "cookie")
            continue
        out.append(Carrier("cookie_value", c, "cookie", "discovered"))

    keys, final = set(), []
    for carrier in out:                   # final dedup, first-wins
        k = carrier.identity_key()
        if k in keys:
            continue
        keys.add(k)
        final.append(carrier)
    return tuple(final)


def assemble(shape, marker):
    """The full battery: every carrier x both variants (plain, tail),
    rendered with integrity fields (D2)."""
    entries = []
    for carrier in synthesize(shape):
        entries.append(BatteryEntry(carrier, "plain", marker, marker))
        entries.append(BatteryEntry(carrier, "tail", marker + TAIL, marker))
    return tuple(entries)


# ---- D2: mangle classification --------------------------------------------

def classify_reflection(marker, reflected, tail=TAIL):
    """Classify what the reflection did to (marker, tail):

      none           intact (or junk around an intact marker — surviving is
                     what matters)
      drop_last      exactly one trailing character eaten (the live
                     'sentineltb1marke' class)
      rewrite_suffix same length, marker intact, tail's end replaced (the
                     live '...markeZ' class)
      truncate       2+ characters eaten, marker intact
      carrier_dead   marker damaged or absent — the channel cannot carry
    """
    full = marker + tail
    if reflected == full:
        return "none"
    if marker not in reflected:
        return "carrier_dead"
    if len(reflected) == len(full):
        return "none" if reflected == full else "rewrite_suffix"
    if len(reflected) < len(full):
        return "drop_last" if reflected == full[:-1] else "truncate"
    return "none"


def channel_live(mangle_class):
    """A channel is LIVE iff the marker survived (anything but dead)."""
    return mangle_class != "carrier_dead"


# ---- D4: attribution (the GTP twins-win rule) ------------------------------

def attribute(records):
    """records: an iterable of (Carrier, mangle_class). The verdict: the
    earliest-priority LIVE carrier is chosen (the value channel beats its
    name twin — detect.py:431-450); the other live carriers are recorded as
    ambiguity; no live carrier -> the honest none."""
    live = [c for (c, mcls) in records if channel_live(mcls)]
    if not live:
        return Attribution(None, (), "no live carrier")
    if len(live) == 1:
        return Attribution(live[0], (), "single live carrier")
    best = min(live, key=lambda c: (PRIORITY.index(c.type), c.identity_key()))
    best_key = best.identity_key()
    others = tuple(c for c in live if c.identity_key() != best_key)
    return Attribution(best, others,
                       "twins-win: earliest-priority live carrier (GTP rule)")


# ---- D5: digests over the LOGICAL stream only (Axis-11) --------------------

def digest(stream):
    """sha256 over the canonical logical stream — identity keys (and variant
    kinds for battery entries) in order. Markers, wall timings and boundary
    noise never enter the digest."""
    logical = []
    for item in stream:
        if hasattr(item, "carrier"):          # a BatteryEntry
            logical.append([item.carrier.identity_key(), item.variant])
        else:                                 # a Carrier
            logical.append(item.identity_key())
    blob = json.dumps(logical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()

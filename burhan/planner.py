"""Burhan v4.0.0 — Safe Attack Planner (Phase 61).

Every operation the platform is about to perform is classified by the state
impact it can have on the target BEFORE it runs — and the classification
carries a human-readable rationale. This is the enterprise-safety layer:

    READ_ONLY       pure observation — no state can change        -> automatic
    LOW_IMPACT      marker-shaped writes with bounded, canary     -> automatic
                    values (workflow learning walks, CSRF
                    baselines on fresh sessions)
    STATE_CHANGING  creates/moves real objects in the             -> explicit
                    application's model (attack battery)             permission
                                                               (--logic-active)
    DESTRUCTIVE     deletes, resets, wipes or otherwise           -> blocked
                    destroys application data                       by default

The planner NEVER blocks what an authorized operator explicitly enabled —
it makes the safety contract machine-readable and auditable: every decision
is recorded (decision log in stats['planner']) with the WHY, so a report
reader can answer "what did this scan do to my application?".

Deterministic by construction: the classification is word/shape based, no
network calls, no randomness.
"""
from __future__ import annotations

import re
import urllib.parse

# ------------------------------------------------------------------ vocabulary
# words that make a surface DESTRUCTIVE wherever they appear in the path
DESTRUCTIVE_WORDS = ("delete", "drop", "purge", "wipe", "truncate", "destroy",
                     "uninstall", "erase", "reset-all", "kill-session",
                     "remove-all", "clear-all", "factory",
                     # V411-DISC-SAFE (live-caught on DVGA): state-changing
                     # GETs — /start_over re-seeds the whole database on a
                     # plain GET; /setup (DVWS) re-initializes it. The words
                     # below cover the global-reset class; _has() splits
                     # path separators so multi-word entries match segments.
                     "start over", "start_over", "reseed", "reinitialize",
                     "setup", "install", "migrate", "seed db", "seed all",
                     "flush all", "flush db", "clear data", "drop all",
                     "drop db", "drop table", "restore default", "reset world",
                     # OWSP-21 (OWASP campaign, live-caught on Mutillidae II
                     # 2.12.7): application-configuration toggles. The app
                     # routes commands through the query string
                     # (index.php?do=toggle-security); the crawler followed
                     # that header-menu link at journal index 11 and the scan
                     # session's security level oscillated 0->1->5->0 across
                     # 95 hits — 4661/4672 requests under an uncontrolled app
                     # posture while the scan looked healthy. A config toggle
                     # is blocked-always for the same reason as /start_over:
                     # it changes the conditions every later request is
                     # tested under.
                     "toggle", "switch", "enable", "disable",
                     "turn on", "turn off")

# words that make a surface STATE_CHANGING (creation/mutation of app objects)
STATE_WORDS = ("create", "add", "new", "submit", "update", "edit", "modify",
               "change", "delete", "remove", "cancel", "approve", "reject",
               "confirm", "execute", "send", "upload", "register", "transfer",
               "pay", "checkout", "place", "book", "subscribe", "publish",
               "post", "comment", "reply", "vote", "buy", "order", "ship",
               "reset", "rollback", "revert", "replay", "close", "open")

# canary/bounded markers: the write is provably burhan-shaped
CANARY_MARKERS = ("1111", "2222", "99001", "burhan", "canary", "csrf-probe",
                  "csrf-vr13", "oast", "probe", "marker")

READ_METHODS = ("GET", "HEAD", "OPTIONS")

POLICY = {
    # class        : (runs automatically?, needs --logic-active?, blocked always?)
    "READ_ONLY":      (True,  False, False),
    "LOW_IMPACT":     (True,  False, False),
    "STATE_CHANGING": (False, True,  False),
    "DESTRUCTIVE":    (False, True,  True),
}


def _path_of(url: str) -> str:
    return (urllib.parse.urlsplit(url or "").path or "").lower()


def _segments(url: str) -> list[str]:
    return [s for s in _path_of(url).split("/") if s]


def classify_operation(url: str, method: str = "GET", fields: list | None = None,
                       note: str = "") -> dict:
    """Classify one planned operation. Returns the impact class + WHY (the
    rationale is shown in reports and the planner's decision log)."""
    method = (method or "GET").upper()
    path = _path_of(url)
    segs = _segments(url)
    fields = fields or []
    note = (note or "").lower()

    def _has(wordlist) -> bool:
        hay = " ".join(segs) + " " + path.replace("-", " ").replace("_", " ")
        # OWSP-21: the vocabulary must see the QUERY STRING too — query-routed
        # apps (index.php?do=toggle-security) carry their commands in it.
        q = urllib.parse.urlsplit(url or "").query or ""
        if q:
            qh = urllib.parse.unquote_plus(q)
            for sep in ("=", "&", "+", "%", "|", ";"):
                qh = qh.replace(sep, " ")
            hay += " " + qh.replace("-", " ").replace("_", " ")
        return any(re.search(rf"(?<!\w){re.escape(w)}(?!\w)", hay) for w in wordlist)

    # 0) v4.1.0 safety fix: DESTRUCTIVE vocabulary wins over EVERYTHING —
    # an engine note can never whitelist a destructive path (live-caught by
    # the planner unit test: a 'wf-atk' note on a /purge-all path used to
    # classify as STATE_CHANGING instead of DESTRUCTIVE)
    if _has(DESTRUCTIVE_WORDS):
        return {"impact": "DESTRUCTIVE",
                "rationale": f"path vocabulary ('{path}') names a destructive "
                             "operation — data loss is reachable if the request "
                             "succeeds; no engine note can whitelist this"}

    # 1) notes the engine itself marks as learning/bounded are LOW_IMPACT writes
    if note.startswith(("wf-walk", "wf-anchor", "wf-oracle", "wf-marker",
                        "wf-base", "wf-atk-entry")):
        return {"impact": "LOW_IMPACT",
                "rationale": "workflow learning walk: canary-valued submissions "
                             "on a bounded chain (fresh session, marker values)"}
    if note.startswith(("wf-atk", "wf-atk-bypass", "wf-atk-order", "wf-atk-tamper",
                        "wf-atk-dup", "wf-atk-priv")):
        return {"impact": "STATE_CHANGING",
                "rationale": "business-logic attack manipulation: deliberately "
                             "submits out-of-sequence/tampered/replayed state to "
                             "prove (or refute) a process invariant"}

    # 2) pure reads can never change state
    if method in READ_METHODS:
        return {"impact": "READ_ONLY",
                "rationale": f"{method} fetch — observation only, no server state "
                             "can change"}

    # 4) state-changing vocabulary or any body-bearing write
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        if _has(STATE_WORDS) or fields or method == "DELETE":
            canary = any(str(v) in CANARY_MARKERS or any(m in str(v).lower()
                        for m in ("canary", "burhan", "probe", "oast"))
                        for _, v in fields)
            if canary:
                return {"impact": "LOW_IMPACT",
                        "rationale": "write with burhan canary values only "
                                     "(bounded, non-production data shape)"}
            return {"impact": "STATE_CHANGING",
                    "rationale": f"{method} with application-shaped body — the "
                                 "server may create or mutate a real object"}
        return {"impact": "STATE_CHANGING",
                "rationale": f"{method} — write-shaped method without a "
                             "read-shaped path"}

    return {"impact": "READ_ONLY", "rationale": "no state-changing signal found"}


class SafeAttackPlanner:
    """Gate + decision log. Every planned operation passes through gate()
    before the engine sends it; every decision is recorded with its rationale."""

    def __init__(self, logic_active: bool = False):
        self.logic_active = logic_active
        self.decisions: list[dict] = []
        self.blocked = 0

    def gate(self, url: str, method: str = "GET", fields: list | None = None,
             note: str = "") -> dict:
        """The safety verdict for one planned operation.

        Returns {allowed, impact, rationale, policy} — never raises, never
        performs I/O. Blocked operations are logged exactly like allowed ones
        (the audit trail is the product)."""
        verdict = classify_operation(url, method, fields, note)
        impact = verdict["impact"]
        auto, needs_flag, always_blocked = POLICY[impact]
        allowed = (auto or (needs_flag and self.logic_active)) and not always_blocked
        policy = ("automatic" if auto else
                  "requires --logic-active" if needs_flag else "blocked-by-default")
        if always_blocked:
            policy = "blocked-by-default (destructive)"
        entry = {"url": url.split("?")[0], "method": (method or "GET").upper(),
                 "impact": impact, "allowed": allowed, "policy": policy,
                 "rationale": verdict["rationale"]}
        if note:
            entry["note"] = note[:60]
        self.decisions.append(entry)
        if not allowed:
            self.blocked += 1
        return entry

    def summary(self) -> dict:
        by_impact: dict[str, int] = {}
        for d in self.decisions:
            by_impact[d["impact"]] = by_impact.get(d["impact"], 0) + 1
        return {"operations_evaluated": len(self.decisions),
                "by_impact": dict(sorted(by_impact.items())),
                "blocked": self.blocked,
                "logic_active": self.logic_active,
                "policy": "READ_ONLY/LOW_IMPACT automatic; STATE_CHANGING needs "
                          "--logic-active; DESTRUCTIVE blocked"}

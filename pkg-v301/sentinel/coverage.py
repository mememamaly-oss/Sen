"""SENTINEL v2.8.0 — Coverage Engine (Phase 56).

Audit-grade endpoint accounting: a scan is no longer just a list of findings —
it is a REVIEWABLE record of what was discovered, what was actually tested,
and WHY anything untested was left out. Every verdict a security tool ships
must answer the auditor's first question: "how do you know you looked?"

Design (all deterministic, zero extra requests by the tracker itself):
  * discover(ep)      — the endpoint entered the map (crawl / robots / OpenAPI /
                        browser / seed).
  * baseline(ep, st)  — the passive baseline fetch result (status or error).
  * activity(ep, kind, note) — a real request was attributed to this endpoint:
                        kinds: passive | secrets | active | authz. Attribution
                        rides the _CoverageProxy on the request engine, so every
                        detector probe, run-style flow and verification replay
                        lands on its endpoint's record automatically.
  * skipped(ep, why)  — an explicit, machine-readable reason the endpoint did
                        NOT get some class of testing (requires_authentication,
                        param_intel:json_object, transport_error, ...).

The summary reports discovered / passive / active / authz / secrets coverage,
per-reason skip counts and an honest coverage percentage — "tested" means at
least ONE security-relevant activity (passive audit, secrets scan, active
probe or authz probe) touched the endpoint. The per-endpoint detail (capped,
deterministically ordered) makes the full account auditable from the report
alone, without re-running the scan.
"""
from __future__ import annotations


class CoverageTracker:
    """One record per discovered endpoint; all operations O(1) dict/sets."""

    def __init__(self):
        self.records: dict[str, dict] = {}

    # ---------------------------------------------------------------- write
    def discover(self, ep) -> None:
        if ep.id in self.records:
            return
        self.records[ep.id] = {
            "id": ep.id,
            "method": (ep.method or "GET").upper(),
            "url": ep.url,
            "source": getattr(getattr(ep, "source", None), "value", "seed"),
            "params": sorted(p.name for p in ep.parameters),
            "activity": [],            # ordered unique kinds: passive/secrets/active/authz
            "notes": [],               # ordered unique request notes (capped below)
            "skips": [],               # ordered unique reasons
            "baseline_status": None,   # int status, "error" or None (never fetched)
        }

    def _rec(self, ep) -> dict | None:
        r = self.records.get(getattr(ep, "id", ""))
        if r is None:
            # a probe against an endpoint the tracker never saw (shouldn't
            # happen — discovery registers everything) still deserves a record
            self.discover(ep)
            r = self.records.get(ep.id)
        return r

    def baseline(self, ep, status) -> None:
        r = self._rec(ep)
        if r is None:
            return
        r["baseline_status"] = "error" if status in (None, 0) else int(status)

    def activity(self, ep, kind: str, note: str = "") -> None:
        r = self._rec(ep)
        if r is None:
            return
        if kind not in r["activity"]:
            r["activity"].append(kind)
        if note and note not in r["notes"] and len(r["notes"]) < 12:
            r["notes"].append(note)

    def skipped(self, ep, reason: str) -> None:
        r = self._rec(ep)
        if r is None:
            return
        if reason not in r["skips"]:
            r["skips"].append(reason)

    # ---------------------------------------------------------------- read
    TEST_KINDS = ("passive", "secrets", "active", "authz")

    def summarize(self, cap_detail: int = 200) -> dict:
        recs = list(self.records.values())
        discovered = len(recs)
        by_kind = {k: 0 for k in self.TEST_KINDS}
        for r in recs:
            for k in r["activity"]:
                if k in by_kind:
                    by_kind[k] += 1
        tested = sum(1 for r in recs if any(k in r["activity"] for k in self.TEST_KINDS))
        active_or_authz = sum(1 for r in recs
                              if "active" in r["activity"] or "authz" in r["activity"])
        reasons: dict[str, int] = {}
        for r in recs:
            for s in r["skips"]:
                reasons[s] = reasons.get(s, 0) + 1
        detail = sorted(
            ({"method": r["method"], "url": r["url"], "source": r["source"],
              "activity": list(r["activity"]), "skips": list(r["skips"]),
              "baseline": r["baseline_status"]} for r in recs),
            key=lambda d: (d["url"], d["method"]))[:cap_detail]
        return {
            "discovered": discovered,
            "tested": tested,
            "passive": by_kind["passive"],
            "secrets_scanned": by_kind["secrets"],
            "active": by_kind["active"],
            "authz_probed": by_kind["authz"],
            "active_or_authz": active_or_authz,
            "untested": discovered - tested,
            "skip_reasons": dict(sorted(reasons.items())),
            "coverage_pct": round(100.0 * tested / discovered, 1) if discovered else 0.0,
            "endpoints": detail,
            "detail_truncated": max(0, discovered - cap_detail),
        }


class _CoverageProxy:
    """Transparent outermost engine proxy (Phase 56): every RequestMutation the
    scan sends is attributed to its endpoint — passive baselines, detector
    probes, run-style flows and verification replays alike. Auth-flow requests
    (note prefix 'auth-') are intentionally NOT endpoint testing and are not
    recorded. Zero behavior change on the wire; pure observation."""

    def __init__(self, inner, coverage: CoverageTracker):
        self._inner, self._cov = inner, coverage

    # navigation/crawl fetches and auth-flow requests are NOT endpoint testing
    NAVIGATION_NOTES = ("discovery",)

    def send(self, m):
        r = self._inner.send(m)
        note = (getattr(m, "note", "") or "")
        ep = getattr(m, "endpoint", None)
        if ep is None or note.startswith("auth-") or note in self.NAVIGATION_NOTES:
            return r
        if note == "passive-baseline":
            self._cov.baseline(ep, getattr(r, "status", 0) or 0)
            self._cov.activity(ep, "passive", note)
        elif note.startswith("secrets-"):
            self._cov.activity(ep, "secrets", note)
        elif note:
            self._cov.activity(ep, "active", note)
        elif getattr(m, "param_name", "") or getattr(m, "body_override", ""):
            # a MUTATION with no note is a detector probe (the param-bound
            # detectors emit bare mutations) — that IS testing activity
            self._cov.activity(ep, "active", "")
        # a bare no-note, no-mutation fetch is navigation — not testing
        return r

    def __getattr__(self, name):
        return getattr(self._inner, name)

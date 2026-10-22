"""SENTINEL Coverage Engine — v2.8.0 endpoint ledger + v4.1.0 multi-dimensional
Coverage 2.0 (Phase V41-06).

Audit-grade accounting: a scan is no longer just a list of findings —
it is a REVIEWABLE record of what was discovered, what was actually tested,
and WHY anything untested was left out. Every verdict a security tool ships
must answer the auditor's first question: "how do you know you looked?"

v4.1.0 adds the DIMENSION layer on top of the endpoint ledger. Coverage is no
longer a single percentage: it is 17 auditable dimensions —

    endpoint, parameter, authentication, identity, authorization, entity,
    object, workflow, workflow_branch, state, api_protocol, graphql,
    websocket, browser, oast, detector, evidence

— each with its own discovered/tested/untested counts, per-reason untested
accounting, and an HONEST percentage produced together with the Boundary
Intelligence Engine (boundary.honest_pct): a dimension may claim 100% only
when no unresolved boundary record argues against it. Dimensions that never
discovered anything are reported as NOT_DISCOVERED ("no GraphQL endpoint
observed"), never as tested — the no-hallucination property.

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
  * dim_* methods     — dimension-ledger writes (discovered/tested/untested)
                        fed by every engine; dimensions() builds the full
                        multi-dimensional account.
"""
from __future__ import annotations


# The 17 Coverage 2.0 dimensions (single vocabulary, consumed by reports,
# the boundary engine, the capability matrix and the no-hallucination gate).
DIMENSIONS = (
    "endpoint", "parameter", "authentication", "identity", "authorization",
    "entity", "object", "workflow", "workflow_branch", "state",
    "api_protocol", "graphql", "websocket", "browser", "oast",
    "detector", "evidence",
)


class CoverageTracker:
    """One record per discovered endpoint + the dimension ledgers.
    All operations O(1) dict/sets."""

    def __init__(self):
        self.records: dict[str, dict] = {}
        # ---- Coverage 2.0 dimension ledgers (v4.1.0)
        self._dim_discovered: dict[str, dict[str, dict]] = {d: {} for d in DIMENSIONS}
        self._dim_tested: dict[str, set[str]] = {d: set() for d in DIMENSIONS}
        self._dim_untested: dict[str, dict[str, str]] = {d: {} for d in DIMENSIONS}

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

    # ------------------------------------------------------------ dimensions
    def dim_discover(self, dim: str, key: str, meta: dict | None = None) -> None:
        """An item of dimension `dim` entered the map (endpoint ids, param ids,
        identities, flows, branches, channels, detector classes, ...)."""
        if dim not in self._dim_discovered:
            return
        if key not in self._dim_discovered[dim]:
            self._dim_discovered[dim][key] = dict(meta or {})

    def dim_tested(self, dim: str, key: str) -> None:
        """A security-relevant activity actually exercised this item."""
        if dim in self._dim_tested:
            self._dim_tested[dim].add(key)
            self._dim_untested[dim].pop(key, None)

    def dim_untested(self, dim: str, key: str, reason: str) -> None:
        """Explicit machine-readable reason this item stayed untested."""
        if dim in self._dim_untested and key not in self._dim_tested[dim]:
            self._dim_untested[dim][key] = reason

    def dim_items(self, dim: str) -> dict[str, dict]:
        return dict(self._dim_discovered.get(dim, {}))

    def _dimension_account(self, dim: str, boundary) -> dict:
        """One dimension's auditable account. `boundary` may be None (tests);
        honest_pct degrades gracefully without it."""
        discovered = self._dim_discovered.get(dim, {})
        tested = self._dim_tested.get(dim, set())
        untested = {k: r for k, r in self._dim_untested.get(dim, {}).items()
                    if k not in tested}
        reasons: dict[str, int] = {}
        for r in untested.values():
            reasons[r] = reasons.get(r, 0) + 1
        n_disc = len(discovered)
        n_tested = len(tested & set(discovered)) if discovered else len(tested)
        acct = {"dimension": dim, "discovered": n_disc, "tested": n_tested,
                "untested": n_disc - min(n_tested, n_disc) if discovered else 0,
                "untested_reasons": dict(sorted(reasons.items()))}
        if n_disc == 0:
            # an ABSENCE statement, never a tested claim (no-hallucination)
            acct["status"] = "NOT_DISCOVERED"
            acct["pct"] = 0.0
            acct["note"] = f"no {dim.replace('_', ' ')} surface was observed on this target"
        else:
            pct = (100.0 * acct["tested"] / n_disc)
            if boundary is not None:
                pct = boundary.honest_pct(n_disc, acct["tested"], category=dim + "/")
                if pct >= 100.0 and acct["untested"]:
                    pct = 99.9   # 100%-guard: unexplained untested items forbid it
            acct["pct"] = round(pct, 1)
            acct["status"] = "TESTED" if acct["tested"] else "UNTESTED"
        return acct

    def dimensions(self, boundary=None, cap_detail: int = 12) -> dict:
        """The Coverage 2.0 multi-dimensional account. Deterministic order.
        `boundary` is the BoundaryEngine (100%-guard + honest percentages)."""
        out: dict[str, dict] = {}
        for dim in DIMENSIONS:
            acct = self._dimension_account(dim, boundary)
            items = self._dim_discovered.get(dim, {})
            untested = self._dim_untested.get(dim, {})
            acct["items"] = [
                {"key": k, "meta": (items[k] if isinstance(items[k], dict) else {}),
                 "tested": k in self._dim_tested.get(dim, set()),
                 "untested_reason": untested.get(k, "")}
                for k in sorted(items)[:cap_detail]]
            acct["items_truncated"] = max(0, len(items) - cap_detail)
            out[dim] = acct
        return out

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
        # ---- Coverage 2.0: parameter-dimension attribution — every mutation
        # that targets a named parameter marks that parameter TESTED (the
        # probe really exercised it). Navigation/auth requests excluded.
        pname = getattr(m, "param_name", "")
        if pname and ep is not None and not note.startswith("auth-"):
            self._cov.dim_discover("parameter", f"{ep.id}|{pname}",
                                   {"endpoint": ep.url, "name": pname})
            self._cov.dim_tested("parameter", f"{ep.id}|{pname}")
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

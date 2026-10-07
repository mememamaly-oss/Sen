"""SENTINEL v4.1.0 — Boundary Intelligence Engine (Phase V41-05).

The single registry of WHAT SENTINEL KNOWS IT DOES NOT KNOW.

v4.0.0 was honest at the endpoint level (coverage skip reasons) and at the
hypothesis level (untestable:* statuses) — but those honesty signals were
scattered across engines, each with its own vocabulary, and nothing could
answer the auditor's question in one place:

    "show me everything you did NOT test, and why, and what to do about it."

This engine is that place. Every engine in the platform records its limits
here, in ONE state vocabulary, with ONE record shape:

    BoundaryRecord(
        category,     'graphql/mutation', 'websocket/authorization',
                      'workflow/branch', 'endpoint/active', ...
        target,       'POST /api/updateUser', 'wss://host/chat',
                      'branch=express of flow /wf/transfer'
        state,        one of the 14 unified states below
        reason,       the explicit WHY (machine-parseable prefix where stable)
        evidence,     reference to the observation that JUSTIFIES the record
                      (never invented — empty evidence is legal only for
                      NOT_DISCOVERED, which is an absence statement)
        provenance,   the module + code path that produced the record
        remediation)  what an operator can DO about it (when actionable)

THE 14 UNIFIED STATES
    outcome states      TESTED, VERIFIED, REFUTED, TIMEOUT, TOOL_FAILURE
    absence states      NOT_DISCOVERED, NOT_SUPPORTED, NOT_APPLICABLE
    blocked states      BLOCKED_BY_PERMISSION, BLOCKED_BY_AUTH,
                        BLOCKED_BY_SAFETY, BLOCKED_BY_ENVIRONMENT,
                        DEPENDENCY_MISSING, UNTESTABLE

Design rules (enforced by tests):
  * determinism — records are ordered by insertion, ids are content hashes,
    wall time lives ONLY in the volatile `ts` field (excluded from the
    determinism proof, like request ids); `seq` is the stable ordinal.
  * no invention — a record whose state claims an observation (TESTED,
    VERIFIED, REFUTED, TIMEOUT, TOOL_FAILURE) MUST carry evidence; the
    no-hallucination gate fails the suite otherwise.
  * memory is not evidence — records rebuilt from previous runs are marked
    provenance=memory:* and are NEVER used to satisfy coverage claims for
    the current run.
"""
from __future__ import annotations

import hashlib
import time

# ------------------------------------------------------------------ states
TESTED = "TESTED"
VERIFIED = "VERIFIED"
REFUTED = "REFUTED"
SUPERSEDED = "SUPERSEDED"
UNTESTABLE = "UNTESTABLE"
NOT_DISCOVERED = "NOT_DISCOVERED"
NOT_SUPPORTED = "NOT_SUPPORTED"
BLOCKED_BY_PERMISSION = "BLOCKED_BY_PERMISSION"
BLOCKED_BY_AUTH = "BLOCKED_BY_AUTH"
BLOCKED_BY_SAFETY = "BLOCKED_BY_SAFETY"
BLOCKED_BY_ENVIRONMENT = "BLOCKED_BY_ENVIRONMENT"
TIMEOUT = "TIMEOUT"
TOOL_FAILURE = "TOOL_FAILURE"
DEPENDENCY_MISSING = "DEPENDENCY_MISSING"
NOT_APPLICABLE = "NOT_APPLICABLE"

ALL_STATES = (TESTED, VERIFIED, REFUTED, SUPERSEDED, UNTESTABLE, NOT_DISCOVERED,
              NOT_SUPPORTED, BLOCKED_BY_PERMISSION, BLOCKED_BY_AUTH,
              BLOCKED_BY_SAFETY, BLOCKED_BY_ENVIRONMENT, TIMEOUT,
              TOOL_FAILURE, DEPENDENCY_MISSING, NOT_APPLICABLE)

# states that assert an observation happened -> evidence is MANDATORY
EVIDENCE_MANDATORY = {TESTED, VERIFIED, REFUTED, TIMEOUT, TOOL_FAILURE}
# states that justify an item being outside this scan's testing reach
UNRESOLVED_STATES = {UNTESTABLE, NOT_DISCOVERED, NOT_SUPPORTED,
                     BLOCKED_BY_PERMISSION, BLOCKED_BY_AUTH, BLOCKED_BY_SAFETY,
                     BLOCKED_BY_ENVIRONMENT, TIMEOUT, TOOL_FAILURE,
                     DEPENDENCY_MISSING}
# volatile fields excluded from determinism comparisons (documented, tested)
VOLATILE_FIELDS = ("ts",)

STATE_MEANINGS = {
    TESTED: "an attempt was made against this item (see evidence)",
    VERIFIED: "a defect on this item was proven with reproducible evidence",
    REFUTED: "the attack theory for this item was tested and the target held",
    UNTESTABLE: "the item exists but a precondition for testing it never materialized",
    NOT_DISCOVERED: "no such item was ever observed (an absence statement)",
    NOT_SUPPORTED: "SENTINEL does not implement testing for this item class",
    BLOCKED_BY_PERMISSION: "policy/flags required for this test were not granted",
    BLOCKED_BY_AUTH: "the item sits behind authentication SENTINEL does not hold",
    BLOCKED_BY_SAFETY: "the Safe Attack Planner refused the operation (destructive/unsafe)",
    BLOCKED_BY_ENVIRONMENT: "the runtime environment cannot reach/exercise the item",
    TIMEOUT: "the item was probed but never answered within the deadline",
    TOOL_FAILURE: "SENTINEL itself failed while testing the item (bug/transport)",
    DEPENDENCY_MISSING: "a required external dependency (browser, second account, token) is absent",
    NOT_APPLICABLE: "the item class does not apply to this target/protocol",
}


def _bid(category: str, target: str, state: str, reason: str) -> str:
    return "B-" + hashlib.sha1(
        f"{category}|{target}|{state}|{reason}".encode()).hexdigest()[:10]


class BoundaryRecord:
    """One limit of knowledge. Plain data, JSON-safe, hash-stable."""

    __slots__ = ("category", "target", "state", "reason", "evidence",
                 "provenance", "remediation", "seq", "ts", "id")

    def __init__(self, category: str, target: str, state: str, reason: str,
                 evidence: str = "", provenance: str = "",
                 remediation: str = "", seq: int = 0, ts: float = 0.0):
        if state not in ALL_STATES:
            raise ValueError(f"unknown boundary state '{state}' "
                             f"(valid: {', '.join(ALL_STATES)})")
        self.category = category
        self.target = target
        self.state = state
        self.reason = reason
        self.evidence = evidence
        self.provenance = provenance
        self.remediation = remediation
        self.seq = seq
        self.ts = ts
        self.id = _bid(category, target, state, reason)

    def to_dict(self) -> dict:
        return {"id": self.id, "seq": self.seq, "category": self.category,
                "target": self.target, "state": self.state, "reason": self.reason,
                "evidence": self.evidence, "provenance": self.provenance,
                "remediation": self.remediation, "ts": round(self.ts, 3)}

    @classmethod
    def from_dict(cls, d: dict) -> "BoundaryRecord":
        return cls(d["category"], d["target"], d["state"], d["reason"],
                   d.get("evidence", ""), d.get("provenance", ""),
                   d.get("remediation", ""), d.get("seq", 0), d.get("ts", 0.0))

    def key(self) -> tuple:
        return (self.category, self.target, self.state, self.reason)


class BoundaryEngine:
    """Insertion-ordered registry. One instance per scan (+ restored memory)."""

    def __init__(self):
        self.records: list[BoundaryRecord] = []
        self._index: dict[tuple, BoundaryRecord] = {}

    # ------------------------------------------------------------ write
    def record(self, category: str, target: str, state: str, reason: str,
               evidence: str = "", provenance: str = "",
               remediation: str = "") -> BoundaryRecord:
        """Register one boundary. Deduplicated by (category,target,state,reason);
        the FIRST registration wins (first observation is the provenance)."""
        key = (category, target, state, reason)
        hit = self._index.get(key)
        if hit is not None:
            return hit
        rec = BoundaryRecord(category, target, state, reason, evidence,
                             provenance, remediation,
                             seq=len(self.records), ts=time.time())
        self.records.append(rec)
        self._index[key] = rec
        return rec

    # convenience shorthands used across engines (single vocabulary entry point)
    def tested(self, category, target, reason, evidence, provenance=""):
        return self.record(category, target, TESTED, reason, evidence, provenance)

    def refuted(self, category, target, reason, evidence, provenance=""):
        return self.record(category, target, REFUTED, reason, evidence, provenance)

    def untestable(self, category, target, reason, remediation="",
                   provenance="", evidence=""):
        return self.record(category, target, UNTESTABLE, reason, evidence,
                           provenance, remediation)

    def not_discovered(self, category, target, reason, provenance=""):
        return self.record(category, target, NOT_DISCOVERED, reason, "", provenance)

    def not_supported(self, category, target, reason, remediation="",
                      provenance=""):
        return self.record(category, target, NOT_SUPPORTED, reason, "",
                           provenance, remediation)

    def blocked(self, category, target, blocker: str, reason,
                remediation: str = "", provenance: str = "") -> BoundaryRecord:
        """blocker in {permission, auth, safety, environment}."""
        state = {"permission": BLOCKED_BY_PERMISSION, "auth": BLOCKED_BY_AUTH,
                 "safety": BLOCKED_BY_SAFETY,
                 "environment": BLOCKED_BY_ENVIRONMENT}[blocker]
        return self.record(category, target, state, reason, "", provenance,
                           remediation)

    def timeout(self, category, target, reason, evidence, remediation="",
                provenance=""):
        return self.record(category, target, TIMEOUT, reason, evidence,
                           provenance, remediation)

    def tool_failure(self, category, target, reason, evidence,
                     remediation="", provenance=""):
        return self.record(category, target, TOOL_FAILURE, reason, evidence,
                           provenance, remediation)

    def dependency_missing(self, category, target, reason, remediation="",
                           provenance=""):
        return self.record(category, target, DEPENDENCY_MISSING, reason, "",
                           provenance, remediation)

    def not_applicable(self, category, target, reason, provenance=""):
        return self.record(category, target, NOT_APPLICABLE, reason, "", provenance)

    # ------------------------------------------------------------ read
    def by_state(self, state: str) -> list[BoundaryRecord]:
        return [r for r in self.records if r.state == state]

    def by_category(self, category: str) -> list[BoundaryRecord]:
        return [r for r in self.records if r.category == category]

    def unresolved(self) -> list[BoundaryRecord]:
        """Everything that honestly blocks a 'fully tested' claim."""
        return [r for r in self.records if r.state in UNRESOLVED_STATES]

    def find(self, category: str, target: str) -> list[BoundaryRecord]:
        return [r for r in self.records
                if r.category == category and r.target == target]

    def summary(self, cap: int = 400) -> dict:
        by_state: dict[str, int] = {}
        by_category: dict[str, int] = {}
        for r in self.records:
            by_state[r.state] = by_state.get(r.state, 0) + 1
            by_category[r.category] = by_category.get(r.category, 0) + 1
        unres = self.unresolved()
        return {"records": len(self.records),
                "by_state": dict(sorted(by_state.items())),
                "by_category": dict(sorted(by_category.items())),
                "unresolved": len(unres),
                "unresolved_detail": [
                    {"category": r.category, "target": r.target, "state": r.state,
                     "reason": r.reason, "remediation": r.remediation}
                    for r in sorted(unres, key=lambda r: (r.category, r.target))[:cap]],
                "states_vocabulary": list(ALL_STATES)}

    def to_dict(self) -> list[dict]:
        return [r.to_dict() for r in self.records]

    @classmethod
    def from_dict(cls, items: list[dict]) -> "BoundaryEngine":
        eng = cls()
        for d in items or []:
            rec = BoundaryRecord.from_dict(d)
            eng.records.append(rec)
            eng._index[rec.key()] = rec
        return eng

    # ------------------------------------------------------------ honesty
    def validate(self) -> list[str]:
        """Structural invariants — consumed by the no-hallucination gate.
        Returns a list of violations (empty = clean)."""
        problems: list[str] = []
        seen_ids: set[str] = set()
        for r in self.records:
            where = f"{r.id} ({r.category}/{r.target})"
            if r.id in seen_ids:
                problems.append(f"duplicate id {where}")
            seen_ids.add(r.id)
            if r.state in EVIDENCE_MANDATORY and not r.evidence:
                problems.append(
                    f"{where}: state {r.state} asserts an observation but "
                    f"carries no evidence")
            if r.state == NOT_DISCOVERED and r.evidence:
                problems.append(
                    f"{where}: NOT_DISCOVERED is an absence statement and "
                    f"must not carry evidence")
            if not r.provenance:
                problems.append(f"{where}: no provenance")
            if not r.reason:
                problems.append(f"{where}: no reason")
        return problems

    def honest_pct(self, discovered: int, tested: int,
                   category: str = "") -> float:
        """The 100%-guard: a dimension may claim 100% ONLY when no unresolved
        boundary record argues against it. Otherwise the claim is capped at
        99.9 — the report shows the boundary instead of the round number."""
        if discovered <= 0:
            return 0.0
        pct = 100.0 * tested / discovered
        contested = any(r.category.startswith(category) for r in self.unresolved()) \
            if category else bool(self.unresolved())
        if contested and pct >= 100.0:
            return 99.9
        return round(pct, 1)


# module-level vocabulary export for the gate + tests
def boundary_states_documented() -> dict[str, str]:
    return dict(STATE_MEANINGS)

"""SENTINEL v2.8.0 — Smart Testing Engine (Phase 56).

Parameter intelligence: instead of running every battery on every parameter,
the engine reasons about WHAT a parameter observably IS (value shape, name
semantics, declared location) and selects the vulnerability classes that can
physically apply. This is the planner's kind->classes contract (Phase 7)
extended with VALUE-SHAPE inference, made observable in every report.

Conservative by construction — the priority is ZERO false negatives:
  * infer() only ever UPGRADES a param to a more specific kind when the
    observed value proves it (a value that parses as a JSON object is a JSON
    object); it never downgrades or clears an existing classification.
  * TOKEN params (CSRF/anti-forgery) are never touched.
  * Kinds WITHOUT a planner rule simply produce no plan entries — exactly the
    same mechanism that already existed for unknown kinds. The skip reason is
    recorded in the Coverage Engine so the decision is auditable, not silent.

The fixture proof: /api/filter?filter={"status":"active"} — a JSON-object
valued param — historically fell through to the GENERIC battery (sqli/xss/
header string probes, none of which can apply to a structured JSON value);
with value-shape inference it is classified json_object, the string batteries
are skipped with a recorded reason, and every detection outcome is unchanged
while the request budget shrinks.
"""
from __future__ import annotations
import json

from .core import ParamKind, ParamLocation


class ParamIntel:
    """Stateless parameter intelligence — pure functions, deterministic."""

    # names that semantically denote an object identifier (IDOR/authz surface)
    ID_NAMES = {
        "id", "uid", "userid", "user_id", "account", "account_id", "acct",
        "doc", "doc_id", "pid", "oid", "cid", "ref", "num", "order", "order_id",
        "order_num", "invoice", "invoice_id", "profile", "profile_id", "object",
        "object_id", "customer", "customer_id", "record", "record_id",
    }

    # what each inferred kind means for detector selection. The COVERAGE reason
    # is the compact key; the full rationale stays here in the module contract.
    SKIP_REASONS = {
        ParamKind.JSON_OBJECT:
            "param_intel:json_object",
    }
    RATIONALE = {
        ParamKind.JSON_OBJECT:
            "value is a structured JSON object — string batteries (sqli/xss/"
            "traversal/redirect) cannot apply to a structured value; JSON-body "
            "classes (nosql operator injection) remain eligible via their own "
            "location-based flow",
    }

    # ---------------------------------------------------------------- infer
    @staticmethod
    def infer(name: str, value: str, location=None) -> ParamKind | None:
        """Return a MORE SPECIFIC kind proven by the observed value, or None.

        Only value shapes that logically exclude the string batteries ever
        produce a result — everything else keeps its existing classification
        (the conservative default: unknown => run everything applicable).
        """
        v = (value or "").strip()
        if not v:
            return None
        # JSON object value: parses as a dict (arrays stay generic — a list of
        # strings can still be a reflection surface)
        if v.startswith("{") and v.endswith("}"):
            try:
                if isinstance(json.loads(v), dict):
                    return ParamKind.JSON_OBJECT
            except Exception:
                return None
        return None

    # ---------------------------------------------------------------- enrich
    @classmethod
    def enrich(cls, endpoints) -> dict:
        """Upgrade param kinds across the discovered surface; return the profile
        (kind distribution + upgrade count) for the scan report."""
        profile: dict[str, int] = {}
        upgraded = 0
        id_params: dict[str, set[str]] = {}
        for ep in endpoints:
            for p in ep.parameters:
                # TOKEN params are flow control — never re-classified
                if p.kind == ParamKind.TOKEN:
                    profile["token"] = profile.get("token", 0) + 1
                    continue
                new_kind = cls.infer(p.name, p.value, p.location)
                if new_kind is not None and p.kind != new_kind:
                    p.kind = new_kind
                    upgraded += 1
                key = p.kind.value
                profile[key] = profile.get(key, 0) + 1
                # data-object inventory for the application map
                n = (p.name or "").lower()
                if n in cls.ID_NAMES or n.endswith(("_id", "_num")):
                    id_params.setdefault(n, set()).add(ep.url.split("?")[0])
        return {
            "params_total": sum(profile.values()),
            "by_kind": dict(sorted(profile.items())),
            "value_shape_upgrades": upgraded,
            "data_objects": {k: sorted(v) for k, v in sorted(id_params.items())},
        }

    # ---------------------------------------------------------------- select
    @staticmethod
    def skip_reason(param) -> str | None:
        """Auditable, COMPACT reason a planned battery does not apply to this
        param (None = no skip — run everything the planner selected). The full
        rationale per kind lives in RATIONALE (surfaced via profile reports)."""
        return ParamIntel.SKIP_REASONS.get(param.kind)

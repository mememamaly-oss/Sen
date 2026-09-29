"""SENTINEL v2.8.0 — Application Map (Phase 56).

Post-scan application intelligence: the surfaces, roles, data objects and
access relations of the target, synthesized from what the scan ALREADY knows
(discovered endpoints, param intelligence, the authz engine's access matrix
and the coverage account). No extra requests — this is the "application
understanding" layer that turns a list of endpoints into a model an auditor
can reason about:

  Surfaces   pages / APIs / forms / statics
  Auth       session mode, roles actually tested, gated endpoints
  Access     role x endpoint status matrix (when the authz engine ran)
  Data       object-typed parameters and the endpoints that carry them
  Coverage   the audit account itself (what was tested and why not the rest)
  Workflows  form inventory grouped by target action (input surfaces)
"""
from __future__ import annotations

STATIC_EXTS = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
               ".woff", ".woff2", ".ttf", ".map")
API_MARKERS = ("/api/", "/api.", "/graphql", "/rest/", "/v1/", "/v2/", "/rpc/")


def _classify(ep) -> str:
    path = (ep.url.split("?")[0]).lower()
    if any(path.endswith(ext) for ext in STATIC_EXTS):
        return "static"
    if (ep.method or "GET").upper() in ("POST", "PUT", "PATCH", "DELETE"):
        return "form_or_action"
    if any(m in path for m in API_MARKERS) or path.endswith((".json", ".xml")):
        return "api"
    if "json" in {str(getattr(p, "location", "")).lower() for p in ep.parameters}:
        return "api"
    return "page"


def build_appmap(endpoints: list, param_profile: dict | None = None,
                 authz_result: dict | None = None,
                 coverage_summary: dict | None = None,
                 auth_mode: str = "anonymous") -> dict:
    """Assemble the application map. All inputs are already-computed scan
    artifacts; ordering is deterministic everywhere."""
    surfaces: dict[str, list[str]] = {"page": [], "api": [], "form_or_action": [], "static": []}
    for ep in endpoints:
        surfaces[_classify(ep)].append(ep.url.split("?")[0])
    for k in surfaces:
        surfaces[k] = sorted(set(surfaces[k]))

    data_objects = dict((param_profile or {}).get("data_objects") or {})

    _az_stats = (authz_result or {}).get("stats", {}) or {}
    auth = {
        "mode": auth_mode,
        "roles_tested": sorted(_az_stats.get("roles", [])),
        "accounts_logged_in": _az_stats.get("accounts_logged_in", 0),
    }

    access_matrix = None
    if authz_result and authz_result.get("matrix"):
        access_matrix = {u: dict(sorted(roles.items()))
                         for u, roles in sorted(authz_result["matrix"].items())}

    workflows = None
    actions = surfaces["form_or_action"]
    if actions:
        workflows = {"form_inventory": actions,
                     "note": ("state-changing surfaces grouped by target; "
                              "multi-step workflow learning is the Phase 57 "
                              "business-logic engine")}

    return {
        "surfaces": {k: {"count": len(v), "endpoints": v[:60]} for k, v in surfaces.items()},
        "authentication": auth,
        "access_matrix": access_matrix,
        "data_objects": {k: {"carried_by": v[:10]} for k, v in list(data_objects.items())[:25]},
        "workflows": workflows,
        "coverage": ({k: coverage_summary[k] for k in
                      ("discovered", "tested", "untested", "coverage_pct", "skip_reasons")
                      if k in (coverage_summary or {})} if coverage_summary else None),
    }

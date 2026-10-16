"""SENTINEL v4.1.0 — API Intelligence Layer (Phase V41-12).

One inventory for EVERY protocol the scan speaks:

    REST (crawled HTML forms/links) · OpenAPI/Swagger-declared · JS-extracted
    fetch/axios/XHR · GraphQL · WebSocket

Each API surface enters the inventory with its protocol, method/path, source,
authentication observation, parameters, per-surface findings, coverage status
and boundary status — the single place a report reader answers "what APIs
does this application have, and what do we know about each?"

Everything here is a PROJECTION of scan artifacts (zero requests). A surface
the scan never tested is shown with its honest status, never silently
omitted, and never counted as covered.
"""
from __future__ import annotations

import urllib.parse

# action classes from path/method vocabulary (authz matrix + twin op_class)
ACTION_CLASSES = ("read", "create", "update", "delete", "approve",
                  "execute", "export", "admin")

_ACTION_RE = {
    "create": ("create", "add", "new", "register", "submit", "upload", "post"),
    "update": ("update", "edit", "modify", "change", "patch", "reset"),
    "delete": ("delete", "remove", "drop", "purge", "destroy", "wipe"),
    "approve": ("approve", "authoriz", "sanction", "signoff", "sign-off"),
    "execute": ("execute", "run", "confirm", "transfer", "pay", "checkout",
                "ship", "send", "deploy"),
    "export": ("export", "download", "report", "dump", "backup", "csv", "pdf"),
    "admin": ("admin", "manage", "config", "user-manage", "role", "permission"),
}


def classify_action(method: str, path: str) -> str:
    """The action class of one surface (READ when nothing matches)."""
    p = (path or "").lower().replace("-", "/").replace("_", "/")
    m = (method or "GET").upper()
    if m in ("GET", "HEAD", "OPTIONS"):
        for cls, words in _ACTION_RE.items():
            if any(w in p for w in words):
                return cls if cls in ("export", "admin", "read") else "read"
        return "read"
    for cls in ("delete", "approve", "create", "update", "execute", "export", "admin"):
        words = _ACTION_RE.get(cls, ())
        if any(w in p for w in words):
            return cls
    if m == "DELETE":
        return "delete"
    if m == "POST":
        return "create"
    return "update"


def build_api_inventory(endpoints: list, openapi_info: dict | None = None,
                        graphql_stats: dict | None = None,
                        websocket_stats: dict | None = None,
                        coverage_summary: dict | None = None,
                        findings: list | None = None,
                        boundary=None) -> dict:
    """The unified API inventory (deterministic, zero requests)."""
    findings = findings or []
    by_url: dict[str, dict] = {}

    def _note(key: str, **fields):
        rec = by_url.setdefault(key, {"protocol": fields.get("protocol", "http"),
                                      "method": fields.get("method", ""),
                                      "path": fields.get("path", key),
                                      "channel": fields.get("channel", ""),
                                      "sources": [], "parameters": [],
                                      "findings": 0, "finding_types": [],
                                      "authentication": "unknown",
                                      "coverage_status": "unknown"})
        for k, v in fields.items():
            if k in ("protocol", "method", "path", "channel"):
                continue
            if k == "source":
                if v not in rec["sources"]:
                    rec["sources"].append(v)
            elif k == "parameters":
                for p in v:
                    if p not in rec["parameters"]:
                        rec["parameters"].append(p)
            elif isinstance(v, (int, float)):
                rec[k] = rec.get(k, 0) + v if k == "findings" else v
            elif isinstance(v, list):
                for x in v:
                    if x not in rec[k]:
                        rec[k].append(x)
            else:
                rec[k] = v
        return rec

    cov_by_url: dict[str, dict] = {}
    for r in (coverage_summary or {}).get("endpoints") or []:
        cov_by_url[(r.get("url", "").split("?")[0], r.get("method", "GET"))] = r

    for ep in endpoints:
        u = urllib.parse.urlsplit(ep.url)
        path = u.path or "/"
        method = (ep.method or "GET").upper()
        src = getattr(getattr(ep, "source", None), "value", "seed")
        auth_obs = "unknown"
        cr = cov_by_url.get((ep.url.split("?")[0], method)) or \
            cov_by_url.get((ep.url.split("?")[0], "GET"))
        skips = (cr or {}).get("skips") or []
        if "requires_authentication" in skips:
            auth_obs = "gated (authentication required)"
        elif any("auth" in s for s in skips):
            auth_obs = "gated"
        rec = _note(ep.url.split("?")[0], protocol="http", method=method,
                    path=path, source=src,
                    parameters=sorted(p.name for p in ep.parameters)[:12],
                    authentication=auth_obs)
        if cr:
            rec["coverage_status"] = "tested" if any(
                k in (cr.get("activity") or []) for k in
                ("passive", "secrets", "active", "authz")) else "untested"
            if cr.get("skips"):
                rec["coverage_skips"] = list(cr["skips"])[:4]
    for f in findings:
        url = (f.get("url") or f.get("endpoint_url") or "").split("?")[0]
        rec = by_url.get(url)
        if rec is not None:
            rec["findings"] += 1
            if f.get("type") not in rec["finding_types"]:
                rec["finding_types"].append(f.get("type"))
    # OpenAPI-sourced surfaces (already merged as endpoints by the
    # orchestrator — the spec source is recorded for provenance)
    if openapi_info and openapi_info.get("source"):
        for key, rec in by_url.items():
            if any(s.startswith("openapi") for s in rec["sources"]):
                rec["spec_declared"] = openapi_info.get("source")
    # GraphQL
    for cand in (graphql_stats or {}).get("endpoints") or []:
        _note(cand["url"], protocol="graphql", method="POST",
              path=urllib.parse.urlsplit(cand["url"]).path,
              source="graphql:" + cand["source"],
              authentication="see graphql stats",
              coverage_status="tested")
    # WebSocket
    for ch in (websocket_stats or {}).get("channels") or []:
        proto = ((websocket_stats or {}).get("protocols") or {}).get(ch["url"], "")
        _note(ch["url"], protocol="websocket", method="WS",
              path=urllib.parse.urlsplit(ch["url"]).path,
              channel=ch["url"], source="websocket:" + ch["source"],
              authentication="handshake " + (
                  "refused (401)" if ch["url"] not in
                  ((websocket_stats or {}).get("protocols") or {}) else "open"),
              coverage_status="tested" if proto else "handshake refused")
    # boundary statuses for API surfaces
    if boundary is not None:
        for rec in by_url.values():
            recs = [r for r in boundary.records
                    if r.target == rec["path"] or r.target == rec["channel"]]
            if recs:
                rec["boundary"] = {r.category: r.state for r in recs[:4]}
    inventory = sorted(by_url.values(),
                       key=lambda r: (r["protocol"], r["path"], r["method"]))
    by_protocol: dict[str, int] = {}
    for r in inventory:
        by_protocol[r["protocol"]] = by_protocol.get(r["protocol"], 0) + 1
    return {"total": len(inventory),
            "by_protocol": dict(sorted(by_protocol.items())),
            "apis": inventory}


def build_action_matrix(twin, authz_result: dict | None = None,
                        coverage_summary: dict | None = None) -> dict:
    """Phase V41-11: the Identity x Action boundary matrix.

    Rows: DISCOVERED identities only (anonymous + accounts that actually
    logged in + the primary session — never an assumed 'admin' role that was
    not observed). Columns: action classes derived from the twin's surface
    vocabulary. Cells carry the HONEST verdict:

        tested:reachable / tested:blocked   the authz engine probed a surface
                                           of this action class under this
                                           identity
        observed                            a workflow/attack exercised it
        untested:<reason>                  no data — never guessed
    """
    identities: list[dict] = [{"name": "anonymous", "role": "anonymous"}]
    for a in (authz_result or {}).get("accounts") or []:
        identities.append({"name": a["name"], "role": a["role"]})
    matrix: dict[str, dict[str, str]] = {}
    for ident in identities:
        row: dict[str, str] = {}
        for act in ACTION_CLASSES:
            row[act] = "untested:no surface of this action class was probed " \
                       "under this identity"
        matrix[ident["name"]] = row
    # surfaces by action class
    surfaces_by_action: dict[str, list] = {}
    for s in twin.by_kind("surface"):
        path = s.attrs.get("path", s.key.split(" ", 1)[-1] if " " in s.key else s.key)
        method = "GET" if s.key.startswith("GET") else "POST"
        act = classify_action(method, path)
        surfaces_by_action.setdefault(act, []).append(s)
    # authz matrix verdicts (role -> surface -> status)
    gates: dict[str, dict[str, str]] = {}
    for e in twin.edges:
        if e.rel != "gates":
            continue
        src = twin.nodes.get(e.src)
        dst = twin.nodes.get(e.dst)
        if src is None or dst is None:
            continue
        gates.setdefault(src.key, {})[dst.key] = e.attrs.get("verdict", "")
    for ident in identities:
        for act, surfaces in surfaces_by_action.items():
            probed = reachable = 0
            for s in surfaces:
                v = (gates.get(ident["role"], {})
                     .get(s.key)
                     or gates.get(ident["name"], {}).get(s.key))
                if v is not None:
                    probed += 1
                    if v in ("reachable", "partial", "redirect"):
                        reachable += 1
            if probed:
                matrix[ident["name"]][act] = \
                    f"tested:{reachable}/{probed} surfaces reachable"
            elif surfaces and ident["name"] == "anonymous":
                matrix[ident["name"]][act] = \
                    "untested:anonymous probes cover GET surfaces only" \
                    if act != "read" else \
                    "untested:no anonymous baseline for these surfaces"
    return {"identities": identities, "actions": list(ACTION_CLASSES),
            "matrix": matrix,
            "discovered_surface_actions":
                {a: len(s) for a, s in sorted(surfaces_by_action.items())}}

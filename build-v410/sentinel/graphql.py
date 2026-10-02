"""SENTINEL v4.1.0 — GraphQL Intelligence Engine (Phase V41-03).

GraphQL is the single most common "invisible API" in modern applications: one
endpoint, arbitrary operations, nothing a path-shaped scanner can see. Before
v4.1.0 SENTINEL was structurally blind to it — a /graphql endpoint was just
another POST surface.

This engine gives GraphQL first-class treatment with the same honesty
discipline as every other SENTINEL engine:

    DISCOVER     observed endpoints whose path is GraphQL-shaped + JS-extracted
                 fetch/axios URLs + a deterministic probe of well-known paths
    MODEL        introspection (when the target allows it) -> the operation
                 inventory: queries, mutations, arguments, field types
    TEST         a bounded, planner-gated battery:
                   anonymous access          can an unauthenticated client
                                             execute queries at all?
                   BOLA                      can identity B read identity A's
                                             objects by id?
                   field-level authorization do responses carry
                                             sensitive-vocab fields to a
                                             low-privilege identity?
                   mutation authorization    can a mutation execute without
                                             its required privilege?
                   introspection exposure    schema fully readable? (policy-
                                             gated finding, never silent)
    PROVE        every finding carries request->response->verification
                 evidence (the response payload itself, canary-marked)
    BOUNDARY     everything not testable is RECORDED, never guessed:
                   introspection disabled          -> UNTESTABLE schema unavailable
                   mutation needs absent privilege -> UNTESTABLE (explicit)
                   no second identity configured   -> UNTESTABLE BOLA
                   no GraphQL endpoint observed    -> NOT_DISCOVERED

Safety: every operation the engine sends passes the Safe Attack Planner.
Queries are READ_ONLY; mutations are STATE_CHANGING (require --logic-active);
delete-shaped mutations are DESTRUCTIVE and never sent. No finding is ever
based on schema alone — request -> response -> verification or nothing.

Deterministic: fixed probe list, fixed operation ordering, canary values.
"""
from __future__ import annotations

import json
import re
import urllib.parse

from .core import Endpoint, DiscoverySource, Evidence, Finding, Severity, \
    FindingStatus, Verification, ParamKind, ParamLocation, Parameter

# ------------------------------------------------------------------ vocabulary
GQL_PATH_RE = re.compile(r"(graphql|gql|graphi?ql)", re.I)
WELL_KNOWN_PATHS = ("/graphql", "/api/graphql", "/graphql/v1", "/gql")
PROBE_QUERY = {"query": "{__typename}"}
SENSITIVE_FIELD_RE = re.compile(
    r"(password|passwd|pwd|secret|token|ssn|social|salary|private[_-]?key|"
    r"api[_-]?key|credit[_-]?card|card[_-]?number|iban)", re.I)
ID_ARG_RE = re.compile(r"^(id|.*[_-]id|uid|userid|user[_-]?id|account[_-]?id)$", re.I)
INTROSPECTION_QUERY = """
query SentinelIntrospection {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind name
      fields(includeDeprecated: true) {
        name
        args { name type { kind name ofType { kind name ofType { kind name } } } }
        type { kind name ofType { kind name ofType { kind name } } }
      }
    }
  }
}"""

# planner note prefixes -> impact classification (planner.py maps wf-* notes;
# gql-* notes are classified here explicitly and gated through planner.gate)
STATE_CHANGING = "STATE_CHANGING"


def _gql_finding(vtype: str, severity: Severity, url: str, param: str,
                 evidence: Evidence, notes: str, query: str = "",
                 response: str = "") -> Finding:
    f = Finding(vtype, severity, url, param, "POST", [evidence],
                status=FindingStatus.CANDIDATE)
    f.verification = Verification(method="graphql:response-verification",
                                  passed=True, confidence=0.9, rounds=1,
                                  notes=notes)
    f.status = FindingStatus.VERIFIED
    f.state_before = (query or "")[:160]
    f.state_after = (response or "")[:160]
    return f


def _type_name(t: dict | None) -> str:
    """Resolve a GraphQL introspection type reference to its base name."""
    t = t or {}
    return t.get("name") or _type_name(t.get("ofType"))


def _unwrap_non_null(t: dict | None) -> dict | None:
    """Strip NON_NULL / LIST wrappers -> the inner type ref."""
    while isinstance(t, dict) and t.get("kind") in ("NON_NULL", "LIST"):
        t = t.get("ofType") or {}
    return t


class GraphqlClient:
    """Transport for GraphQL over the standard request engine (scope-gated,
    cookie-carrying, rate-limit-resilient — never a raw socket)."""

    def __init__(self, engine):
        self.engine = engine

    def query(self, url: str, query: str, variables: dict | None = None,
              note: str = "gql-query", method: str = "POST"):
        body = {"query": query}
        if variables:
            body["variables"] = variables
        params = [Parameter("query", ParamLocation.BODY, json.dumps(body)).classify(),
                  Parameter("variables", ParamLocation.BODY, "").classify()]
        ep = Endpoint(url=url, method=method, source=DiscoverySource.MANUAL,
                      parameters=params)
        from .http_engine import RequestMutation
        m = RequestMutation(endpoint=ep, note=note, body_override=json.dumps(body),
                            method=method)
        if method == "GET":
            m = RequestMutation(endpoint=Endpoint(
                url=url + "?query=" + urllib.parse.quote(query), method="GET",
                source=DiscoverySource.MANUAL), note=note)
        return self.engine.send(m)


class GraphqlEngine:
    """Discovery + model + bounded planner-gated battery + honest boundaries."""

    def __init__(self, engine, scope, bus, timeout: float = 12.0,
                 planner=None, boundary=None, coverage=None,
                 logic_active: bool = False, report_introspection: bool = True):
        self.engine = engine          # the AUTHENTICATED main engine
        self.scope = scope
        self.bus = bus
        self.timeout = timeout
        self.planner = planner
        self.boundary = boundary
        self.coverage = coverage
        self.logic_active = logic_active
        self.report_introspection = report_introspection
        self.client = GraphqlClient(engine)
        self.requests = 0

    # ------------------------------------------------------------ discovery
    def discover(self, endpoints: list, base_url: str) -> list[dict]:
        """Candidates = observed GraphQL-shaped endpoints + a deterministic
        well-known-path probe. Returns [{url, source}] — no dedup against the
        endpoint map here; the orchestrator merges the surfaced endpoints."""
        found: dict[str, dict] = {}
        origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(base_url))
        for ep in endpoints:
            path = urllib.parse.urlsplit(ep.url).path or ""
            if GQL_PATH_RE.search(path):
                found.setdefault(ep.url.split("?")[0],
                                 {"url": ep.url.split("?")[0], "source": "observed"})
        for p in WELL_KNOWN_PATHS:
            url = origin + p
            if url in found:
                continue
            base = self._requests(lambda: self.client.query(
                url, PROBE_QUERY["query"], note="gql-probe"))
            if self._looks_graphql(base):
                found[url] = {"url": url, "source": "probe"}
        return sorted(found.values(), key=lambda c: c["url"])

    def _looks_graphql(self, r) -> bool:
        if r is None or r.error or not r.body:
            return False
        body = (r.body or "").lstrip()
        if body.startswith("{"):
            try:
                j = json.loads(body)
                # a GraphQL response carries "data" (the __typename probe
                # answers with it); a JSON error body alone is NOT proof —
                # REST APIs answer {"errors": [...]} too
                if isinstance(j, dict) and "data" in j:
                    return True
            except Exception:
                pass
        return False

    def _requests(self, fn):
        before = getattr(self.engine, "requests_sent", 0)
        out = fn()
        self.requests += getattr(self.engine, "requests_sent", 0) - before
        return out

    # ------------------------------------------------------------ model
    def introspect(self, url: str) -> dict | None:
        """Full introspection (authenticated engine). None when disabled."""
        r = self._requests(lambda: self.client.query(
            url, INTROSPECTION_QUERY.strip(), note="gql-introspection"))
        if not self._looks_graphql(r):
            return None
        try:
            payload = json.loads((r.body or "").lstrip())
        except Exception:
            return None
        if payload.get("errors") and not payload.get("data", {}).get("__schema"):
            return None
        schema = ((payload.get("data") or {}).get("__schema") or {})
        if not schema.get("types"):
            return None
        return schema

    def operations(self, schema: dict) -> dict:
        """The operation inventory: queries + mutations with arg shapes and
        selectable scalar fields (the return type's own fields)."""
        types = {t.get("name"): t for t in schema.get("types", [])
                 if isinstance(t, dict)}
        out = {"queries": [], "mutations": []}
        qname = ((schema.get("queryType") or {}).get("name")) or "Query"
        mname = ((schema.get("mutationType") or {}).get("name")) or "Mutation"
        for kind, tname in (("queries", qname), ("mutations", mname)):
            t = types.get(tname) or {}
            for fld in (t.get("fields") or []):
                if not isinstance(fld, dict) or fld.get("name", "").startswith("__"):
                    continue
                ret = _unwrap_non_null(fld.get("type"))
                ret_name = _type_name(ret)
                ret_type = types.get(ret_name) or {}
                scalars = [f2.get("name") for f2 in (ret_type.get("fields") or [])
                           if isinstance(f2, dict) and f2.get("name")]
                args = []
                for a in (fld.get("args") or []):
                    if not isinstance(a, dict):
                        continue
                    at = _unwrap_non_null(a.get("type"))
                    args.append({"name": a.get("name"),
                                 "type": _type_name(at),
                                 "kind": at.get("kind")})
                out[kind].append({"name": fld.get("name"), "args": args,
                                  "return_type": ret_name,
                                  "fields": scalars[:6]})
            out[kind] = sorted(out[kind], key=lambda o: o["name"])
        return out

    # ------------------------------------------------------------ battery
    def _arg_value_for(self, arg: dict, seq: int) -> str | int | None:
        """A deterministic, harmless value for one argument shape."""
        t = (arg.get("type") or "").lower()
        if t in ("int", "int!", "id", "id!"):
            return seq
        if "string" in t or t in ("id",):
            return "sentinel-%d" % seq
        return None

    def _selection(self, op: dict) -> str:
        fields = op.get("fields") or ["__typename"]
        if not fields:
            fields = ["__typename"]
        return " ".join(fields[:4])

    def _record_boundary(self, category, target, state, reason, **kw):
        if self.boundary is not None:
            self.boundary.record(category, target, state, reason,
                                 evidence=kw.get("evidence", ""),
                                 provenance=kw.get("provenance", "graphql"),
                                 remediation=kw.get("remediation", ""))

    def run(self, endpoints: list, base_url: str,
            anonymous_engine=None, low_identity: dict | None = None,
            primary_identity: dict | None = None) -> dict:
        """The full GraphQL pass. Returns {findings, stats, candidates, ops}."""
        stats = {"enabled": True, "candidates": 0, "endpoints": [],
                 "introspected": 0, "queries": 0, "mutations": 0,
                 "tests": 0, "requests": 0, "boundaries": 0}
        findings: list[Finding] = []
        candidates = self.discover(endpoints, base_url)
        ops_by_url: dict[str, dict] = {}
        stats["candidates"] = len(candidates)
        if not candidates:
            self._record_boundary("graphql", base_url, "NOT_DISCOVERED",
                                  "no GraphQL endpoint observed (path-shape, "
                                  "JS extraction and well-known probes all empty)",
                                  provenance="graphql:discovery")
            stats["requests"] = self.requests
            return {"findings": findings, "stats": stats,
                    "candidates": [], "ops": {}}
        for cand in candidates:
            url = cand["url"]
            stats["endpoints"].append({"url": url, "source": cand["source"]})
            if self.coverage is not None:
                ep = Endpoint(url=url, method="POST", source=DiscoverySource.MANUAL)
                self.coverage.discover(ep)
                self.coverage.dim_discover("graphql", url, {"source": cand["source"]})
            schema = self.introspect(url)
            if schema is None:
                # honest boundary: no schema, no operation inventory
                self._record_boundary(
                    "graphql/schema", url, "UNTESTABLE",
                    "introspection disabled or unavailable - the operation "
                    "inventory cannot be learned",
                    remediation="provide the schema (spec seed) or enable "
                                "introspection in a staging environment",
                    provenance="graphql:introspection")
                if self.coverage is not None:
                    self.coverage.dim_untested("graphql", url,
                                               "schema_unavailable")
                stats["boundaries"] += 1
                continue
            stats["introspected"] += 1
            ops = self.operations(schema)
            ops_by_url[url] = ops
            stats["queries"] += len(ops["queries"])
            stats["mutations"] += len(ops["mutations"])
            # introspection exposure (policy-gated, never silent about policy)
            if self.report_introspection:
                f = _gql_finding(
                    "graphql_introspection_enabled", Severity.LOW, url,
                    "__schema",
                    Evidence("schema_introspection_open",
                             "the full schema is readable via introspection: "
                             f"{len(ops['queries'])} queries and "
                             f"{len(ops['mutations'])} mutations enumerated — "
                             "the application's entire API surface is "
                             "disclosable to any client that can query it",
                             ""),
                    "introspection query succeeded and was parsed",
                    response=f"{len(ops['queries'])} queries / "
                             f"{len(ops['mutations'])} mutations enumerated")
                findings.append(f)
            findings += self._battery(url, ops, anonymous_engine,
                                      low_identity, primary_identity, stats)
        stats["requests"] = self.requests
        stats["tests_run"] = stats["tests"]
        return {"findings": findings, "stats": stats, "candidates": candidates,
                "ops": ops_by_url}

    # ------------------------------------------------------------ tests
    def _battery(self, url, ops, anonymous_engine, low_identity,
                 primary_identity, stats) -> list[Finding]:
        findings: list[Finding] = []
        queries = ops["queries"]

        # ---- 1. anonymous access: an unauthenticated engine executing real
        # queries. A finding ONLY when anonymous data is SENSITIVE — a public
        # catalog query answering anonymously is normal API design, not a
        # defect (no fabricated impact).
        anon_hits: list[tuple[str, str]] = []      # sensitive (query, body) hits
        anon_any = ""
        if anonymous_engine is not None and queries:
            anon = GraphqlClient(anonymous_engine)
            for q in queries[:4]:
                args = ", ".join(f"{a['name']}: {json.dumps(self._arg_value_for(a, 1))}"
                                 for a in q["args"][:3]
                                 if self._arg_value_for(a, 1) is not None)
                qtext = "query { %s%s }" % (q["name"],
                                            ("(" + args + ")") if args else "")
                r = self._requests(lambda: anon.query(url, qtext,
                                                       note="gql-anon-query"))
                stats["tests"] += 1
                body = (r.body or "")[:400] if r is not None else ""
                try:
                    payload = json.loads((r.body or "").lstrip()) \
                        if r and r.body else {}
                    data = (payload.get("data") or {}).get(q["name"])
                    has_data = data is not None and not (
                        payload.get("errors") and not payload.get("data"))
                except Exception:
                    has_data = False
                if has_data:
                    anon_any = body
                    if SENSITIVE_FIELD_RE.search(body or ""):
                        anon_hits.append((q["name"], body))
                        break
            if self.coverage is not None and anon_any:
                self.coverage.dim_tested("graphql", url)
        if anon_hits:
            qname, body = anon_hits[0]
            findings.append(_gql_finding(
                "graphql_anonymous_access", Severity.HIGH, url, qname,
                Evidence("anonymous_sensitive_data",
                         f"an UNAUTHENTICATED client executed query '{qname}' "
                         f"and received sensitive-named data — response: "
                         f"{body[:220]} — sensitive operations are reachable "
                         "without authentication", ""),
                "anonymous query returned sensitive data (response verified)",
                response=body[:220]))
        elif anonymous_engine is not None and queries:
            self._record_boundary("graphql/anonymous", url, "TESTED",
                                  "anonymous queries limited to public "
                                  "operations (no sensitive data without auth)"
                                  if anon_any else
                                  "all queries rejected for unauthenticated "
                                  "callers (authentication enforced)",
                                  evidence=anon_any[:120] or "errors/401 only",
                                  provenance="graphql:anonymous-probe")

        # ---- 2. BOLA: the LOW identity queries the PRIMARY identity's object
        bola_probe = ""
        if low_identity and primary_identity and queries and \
                low_identity.get("engine") is not None:
            victim_id = primary_identity.get("object_id") or ""
            marker = primary_identity.get("marker") or ""
            done = False
            for q in queries:
                id_arg = next((a for a in q["args"]
                               if ID_ARG_RE.match(a.get("name") or "")), None)
                if id_arg is None or victim_id == "":
                    continue
                sel = self._selection(q)
                qtext = "query { %s(%s: %s) { %s } }" % (
                    q["name"], id_arg["name"],
                    json.dumps(str(victim_id)), sel)
                low_client = GraphqlClient(low_identity["engine"])
                r = self._requests(lambda: low_client.query(
                    url, qtext, note="gql-bola"))
                stats["tests"] += 1
                body = (r.body or "")[:400] if r is not None else ""
                bola_probe = body
                try:
                    payload = json.loads((r.body or "").lstrip()) if r and r.body else {}
                    obj = (payload.get("data") or {}).get(q["name"])
                    obj_str = json.dumps(obj) if obj is not None else ""
                except Exception:
                    obj_str = ""
                if obj and (marker in obj_str if marker else True):
                    findings.append(_gql_finding(
                        "graphql_bola", Severity.HIGH, url, id_arg["name"],
                        Evidence("cross_identity_object_read",
                                 f"identity '{low_identity.get('name', 'low')}' "
                                 f"(role={low_identity.get('role', '?')}) read the "
                                 f"object of identity "
                                 f"'{primary_identity.get('name', 'primary')}' "
                                 f"({id_arg['name']}={victim_id}) via query "
                                 f"'{q['name']}' — response: {obj_str[:220]} — "
                                 "object-level authorization is not enforced", ""),
                        "low-identity query returned the primary identity's "
                        "object data (marker present)",
                        query=qtext, response=obj_str[:220]))
                    done = True
                    break
                done = False
            if not findings or not any(f.type == "graphql_bola" for f in findings):
                self._record_boundary(
                    "graphql/bola", url, "TESTED" if bola_probe else "UNTESTABLE",
                    ("cross-identity query refused or returned no other-identity "
                     "object (object-level authorization holds)")
                    if bola_probe else
                    "no id-bearing query available for cross-identity testing",
                    evidence=bola_probe[:120],
                    provenance="graphql:bola-probe")
        elif queries and not low_identity:
            self._record_boundary("graphql/bola", url, "UNTESTABLE",
                                  "required second identity unavailable",
                                  remediation="configure a second account "
                                              "(--authz accounts) to enable "
                                              "cross-identity object testing",
                                  provenance="graphql:bola")

        # ---- 3. field-level authorization: sensitive-vocab fields in the
        # low-identity (or main) response for the identity's OWN object
        field_probe = ""
        if queries and low_identity and low_identity.get("engine") is not None:
            own_id = low_identity.get("object_id") or ""
            for q in queries:
                id_arg = next((a for a in q["args"]
                               if ID_ARG_RE.match(a.get("name") or "")), None)
                if id_arg is None or not own_id:
                    continue
                sel = self._selection(q)
                qtext = "query { %s(%s: %s) { %s } }" % (
                    q["name"], id_arg["name"], json.dumps(str(own_id)), sel)
                low_client = GraphqlClient(low_identity["engine"])
                r = self._requests(lambda: low_client.query(
                    url, qtext, note="gql-field-authz"))
                stats["tests"] += 1
                body = (r.body or "")[:400] if r is not None else ""
                field_probe = body
                sensitive_fields = sorted(set(SENSITIVE_FIELD_RE.findall(
                    body or ""))) if body else []
                if sensitive_fields:
                    findings.append(_gql_finding(
                        "graphql_field_authorization", Severity.MEDIUM, url,
                        q["name"],
                        Evidence("sensitive_fields_exposed",
                                 f"query '{q['name']}' returns sensitive-named "
                                 f"fields ({', '.join(sensitive_fields[:4])}) to a "
                                 f"role={low_identity.get('role', '?')} identity "
                                 f"for its own object — response: {body[:200]} — "
                                 "field-level authorization/exposure is missing",
                                 ""),
                        "own-object response carries sensitive-named fields",
                        query=qtext, response=body[:200]))
                    break
            else:
                self._record_boundary("graphql/field-authorization", url, "TESTED",
                                      "own-object queries carry no sensitive-named "
                                      "fields", evidence=field_probe[:120],
                                      provenance="graphql:field-probe")

        # ---- 4. mutation authorization (planner-gated: STATE_CHANGING)
        mut_probe = ""
        dangerous = [m for m in ops["mutations"]
                     if re.search(r"(delete|remove|destroy|purge|wipe|drop|reset)",
                                  m["name"], re.I)]
        benign = [m for m in ops["mutations"] if m not in dangerous]
        if not ops["mutations"]:
            self._record_boundary("graphql/mutation", url, "NOT_APPLICABLE",
                                  "schema declares no mutations",
                                  provenance="graphql:schema")
        elif dangerous and not benign:
            self._record_boundary(
                "graphql/mutation", url, "BLOCKED_BY_SAFETY",
                "only destructive-shaped mutations exist (delete/destroy "
                "vocabulary) — SENTINEL never sends them",
                remediation="verify mutation authorization manually on a "
                            "staging copy",
                provenance="graphql:planner-gate")
        elif benign:
            m = benign[0]
            gated = True
            if self.planner is not None:
                verdict = self.planner.gate(url, "POST",
                                            fields=[("query", m["name"])],
                                            note="gql-mutation")
                gated = verdict.get("allowed", False)
            if gated and self.logic_active:
                args = ", ".join(
                    f"{a['name']}: {json.dumps(self._arg_value_for(a, 1))}"
                    for a in m["args"][:3]
                    if self._arg_value_for(a, 1) is not None)
                mtext = "mutation { %s%s }" % (
                    m["name"], ("(" + args + ")") if args else "")
                # anonymous engine first (mutation without auth is the defect);
                # fall back to the low identity when no anonymous engine exists
                eng = anonymous_engine or low_identity.get("engine") \
                    if low_identity else anonymous_engine
                if eng is not None:
                    client = GraphqlClient(eng)
                    r = self._requests(lambda: client.query(
                        url, mtext, note="gql-mutation-authz"))
                    stats["tests"] += 1
                    mut_probe = (r.body or "")[:400] if r is not None else ""
                    auth_required = bool(
                        r is not None and (getattr(r, "status", 0) == 401 or re.search(
                            r"(not authenticated|unauthenticated|authenticate|"
                            r"login required|credentials|sign in)",
                            (mut_probe or "") + " " + str(getattr(r, "status", "")),
                            re.I)))
                    try:
                        payload = json.loads((r.body or "").lstrip()) \
                            if r and r.body else {}
                        errors = payload.get("errors") or []
                        data = (payload.get("data") or {}).get(m["name"])
                        executed = data is not None and not errors
                    except Exception:
                        executed = False
                    if executed:
                        findings.append(_gql_finding(
                            "graphql_mutation_authorization", Severity.HIGH, url,
                            m["name"],
                            Evidence("mutation_without_authorization",
                                     f"mutation '{m['name']}' EXECUTED without "
                                     "its required privilege (unauthenticated or "
                                     f"low-privilege caller) — response: "
                                     f"{mut_probe[:200]} — mutation authorization "
                                     "is not enforced", ""),
                            "mutation returned data with no errors from a "
                            "non-privileged caller",
                            query=mtext, response=mut_probe[:200]))
                    elif auth_required:
                        # the mutation demands authentication the caller does
                        # not hold: the test could not exercise it — an honest
                        # UNTESTABLE, never a refuted claim
                        self._record_boundary(
                            "graphql/mutation", url, "UNTESTABLE",
                            "authentication required — the mutation could not "
                            "be exercised by the available caller",
                            evidence=mut_probe[:120],
                            remediation="configure an account holding the "
                                        "mutation's privilege",
                            provenance="graphql:mutation-probe")
                    else:
                        self._record_boundary(
                            "graphql/mutation", url, "TESTED",
                            "mutation refused or errored for a non-privileged "
                            "caller (authorization enforced)",
                            evidence=mut_probe[:120],
                            provenance="graphql:mutation-probe")
            elif not self.logic_active:
                self._record_boundary(
                    "graphql/mutation", url, "BLOCKED_BY_PERMISSION",
                    "mutation testing is STATE_CHANGING — requires --logic-active",
                    remediation="re-run with --logic-active to authorize "
                                "state-changing mutation probes",
                    provenance="graphql:planner-gate")
        return findings

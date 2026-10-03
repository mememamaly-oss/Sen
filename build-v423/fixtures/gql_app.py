#!/usr/bin/env python3
"""SENTINEL v4.1.0 fixture — GraphQL Intelligence (three twins).

One server, three GraphQL endpoints with identical wire shape and a fixed
operation inventory:

    Query     me: User | user(id: Int!): User | products: [Product]
    Mutation  createUser(name: String!, email: String!): User
              updateUser(id: Int!, email: String!): User   (V411-GL-07: blocked
              vocabulary — update-shaped mutations are NEVER exercised; the
              engine must record BLOCKED_BY_SAFETY and probe the additive
              createUser instead)
    Types     User {id name email passwordHash ssn} · Product {id name price}

Auth: Bearer tokens (Authorization: Bearer <token>):
    alice-token (role user,  id 1) · bob-token (role user, id 2) ·
    admin-token (role admin, id 0)

GROUND TRUTH:

  defect                              | /api/graphql (vuln)   | /gql/safe       | /gql/partial
  ------------------------------------+-----------------------+-----------------+--------------
  introspection readable              | YES  (finding, LOW)   | YES (finding)   | NO  (disabled)
  anonymous sensitive query           | user(id) answers      | rejected        | n/a (no schema)
    graphql_anonymous_access          |   anonymously with    |                 |
                                      |   passwordHash+ssn   |                 |
  cross-identity object read (BOLA)   | bob reads alice by   | ownership       | n/a
    graphql_bola                      |   id                  | enforced        |
  sensitive fields to user role       | passwordHash+ssn in  | never exposed   | n/a
    graphql_field_authorization       |   own-object answer  |   to user role  |
  mutation without authorization      | anonymous createUser| 401 not         | n/a
    graphql_mutation_authorization    |   EXECUTES           |   authenticated |

  /gql/partial: introspection disabled but the endpoint is ALIVE (products
  answers) — the honest outcome is a UNTESTABLE schema boundary, NEVER a
  "tested" or "vulnerable" claim, and never a silent skip.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote

GQL_GROUND_TRUTH = {
    "/api/graphql": [
        "graphql_introspection_enabled",
        "graphql_anonymous_access",
        "graphql_bola",
        "graphql_field_authorization",
        "graphql_mutation_authorization",
        "graphql_sql_injection",          # V411-GL-01 (search.filter)
        "graphql_command_execution",      # V411-GL-02 (systemDebug.arg)
    ],
    "/gql/safe": [
        "graphql_introspection_enabled",     # schema readable — the ONE exposure
    ],
    "/gql/partial": [],
}

USERS = {
    1: {"id": 1, "name": "Alice", "email": "alice@sentinel-fixture.local",
        "passwordHash": "$2a$10$alicehash", "ssn": "111-22-3333"},
    2: {"id": 2, "name": "Bob", "email": "bob@sentinel-fixture.local",
        "passwordHash": "$2a$10$bobhash", "ssn": "999-88-7777"},
}
TOKENS = {"alice-token": (1, "user"), "bob-token": (2, "user"),
          "admin-token": (0, "admin")}
PRODUCTS = [{"id": p, "name": f"product-{p}", "price": p * 10} for p in range(1, 4)]

_INT = {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "Int"}}
_STR = {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String"}}
_USER = {"kind": "OBJECT", "name": "User", "ofType": None}
_PLIST = {"kind": "LIST", "name": None, "ofType": {"kind": "OBJECT", "name": "Product"}}


def _scalar(name):
    return {"kind": "SCALAR", "name": name, "ofType": None}


def _field(name, args, type_):
    return {"name": name, "args": [{"name": a, "type": t} for a, t in args],
            "type": type_}


def _schema_json():
    """The canned introspection response (identical for vuln + safe twins)."""
    return {"data": {"__schema": {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {"kind": "OBJECT", "name": "Query", "fields": [
                _field("me", [], _USER),
                _field("user", [("id", _INT)], _USER),
                _field("products", [], _PLIST),
                _field("search", [("filter", _STR)], _PLIST),
                _field("systemDebug", [("arg", _STR)], _STR)]},
            {"kind": "OBJECT", "name": "Mutation", "fields": [
                _field("createUser", [("name", _STR), ("email", _STR)], _USER),
                _field("updateUser", [("id", _INT), ("email", _STR)], _USER)]},
            {"kind": "OBJECT", "name": "User", "fields": [
                _field("id", [], _scalar("Int")),
                _field("name", [], _scalar("String")),
                _field("email", [], _scalar("String")),
                _field("passwordHash", [], _scalar("String")),
                _field("ssn", [], _scalar("String"))]},
            {"kind": "OBJECT", "name": "Product", "fields": [
                _field("id", [], _scalar("Int")),
                _field("name", [], _scalar("String")),
                _field("price", [], _scalar("Float"))]},
            {"kind": "SCALAR", "name": "Int", "fields": None},
            {"kind": "SCALAR", "name": "String", "fields": None},
            {"kind": "SCALAR", "name": "Float", "fields": None},
            {"kind": "SCALAR", "name": "Boolean", "fields": None},
            {"kind": "SCALAR", "name": "ID", "fields": None},
        ]}}}


def _err(msg, status=200):
    return {"errors": [{"message": msg}]}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj, raw=None):
        b = (raw if raw is not None else json.dumps(obj)).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _not_found(self):
        b = b"<html><body>404 not found</body></html>"
        self.send_response(404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _caller(self):
        h = self.headers.get("Authorization", "")
        for tok, (uid, role) in TOKENS.items():
            if h.endswith(tok):
                return uid, role
        return None, "anonymous"

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/" or path == "/index":
            html = ("<h1>GraphQL fixture</h1><p>APIs:</p>"
                    '<a href="/gql/safe">safe api</a> '
                    '<a href="/gql/partial">partial api</a>'
                    "<script>fetch('/api/graphql', {method:'POST',"
                    "headers:{'Content-Type':'application/json'},"
                    "body:JSON.stringify({query:'{products{name}}}'})});</script>")
            b = html.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            return self.wfile.write(b)
        if path in ("/api/graphql", "/gql/safe", "/gql/partial"):
            q = parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            return self._graphql(path, unquote(q.get("query", [""])[0]))
        return self._not_found()

    def do_POST(self):
        path = self.path.split("?")[0]
        if path not in ("/api/graphql", "/gql/safe", "/gql/partial"):
            return self._not_found()
        length = int(self.headers.get("Content-Length", 0) or 0)
        try:
            body = json.loads(self.rfile.read(length).decode() or "{}")
        except Exception:
            return self._send(400, _err("invalid json"))
        return self._graphql(path, body.get("query", ""))

    # ------------------------------------------------------------- resolver
    def _graphql(self, path, query):
        uid, role = self._caller()
        safe = path == "/gql/safe"
        partial = path == "/gql/partial"
        q = (query or "").strip()

        # V411-GL-11 (live-caught on DVGA, emulated here): GraphQL validation —
        # an OBJECT/LIST return REQUIRES a selection set; a SCALAR return must
        # NOT carry one. A real graphene server answers violations with HTTP
        # 400; so does this fixture, making any selection regression (the
        # engine's pre-GL-11 probes were all 400-invisible) fail loudly here.
        _OBJECT_FIELDS = ("me", "user", "products", "search", "createUser",
                          "updateUser")
        for m in re.finditer(
                r"(?<![\w:])(me|user|products|search|systemDebug|createUser|"
                r"updateUser)\s*(\([^)]*\))?\s*(\{)?", q):
            field, has_sel = m.group(1), m.group(3) is not None
            if field == "systemDebug" and has_sel:
                return self._send(400, _err(
                    "Field 'systemDebug' of type 'String!' must not have a "
                    "selection of subfields"))
            if field in _OBJECT_FIELDS and not has_sel:
                return self._send(400, _err(
                    "Field '%s' of type must have a selection of subfields"
                    % field))

        if "__schema" in q or "__typename" in q:
            if "__typename" in q and "__schema" not in q:
                return self._send(200, {"data": {"__typename": "Query"}})
            if partial:
                return self._send(200, _err("introspection disabled"))
            return self._send(200, _schema_json())

        if "createUser" in q:
            # V411-GL-07 ground truth: the ADDITIVE mutation executes without
            # authentication on the vuln twin (the authorization defect); the
            # safe twin demands authentication. updateUser stays in the schema
            # as blocked vocabulary — if it ever arrives here the engine broke
            # its safety gate (the regression test asserts the boundary).
            if safe and uid is None:
                return self._send(401, _err("not authenticated"))
            return self._send(200, {"data": {"createUser": {
                "id": 99, "name": "sentinel-1", "email": "sentinel-1",
                "passwordHash": "******", "ssn": "[REDACTED]"}}})

        if "updateUser" in q:
            import re as _re
            mid = _re.search(r"updateUser\s*\(\s*id:\s*(\d+)", q)
            if mid is None:
                return self._send(200, _err("updateUser requires id"))
            if safe:
                if uid is None:
                    return self._send(401, _err("not authenticated"))
                if role != "admin":
                    return self._send(200, _err("forbidden: admin only"))
            u = USERS.get(int(mid.group(1)))
            if u is None:
                return self._send(200, _err("unknown user"))
            email = "sentinel-probe@fixture.local"     # canary-shaped, benign
            u2 = dict(u, email=email)
            return self._send(200, {"data": {"updateUser": u2}})

        if "systemDebug" in q:
            # V411-GL-02 ground truth: the VULN twin executes an OS command
            # with the argument (ps aux); the SAFE twin answers with a fixed
            # diagnostic string — no command output, ever.
            marg = re.search(r"systemDebug\s*\(\s*arg:\s*\"([^\"]*)\"", q)
            if safe:
                return self._send(200, {"data": {
                    "systemDebug": "debug subsystem: logging enabled"}})
            arg = marg.group(1) if marg else ""
            if arg == "aux":
                return self._send(200, {"data": {"systemDebug":
                    "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                    "root         1  0.0  0.0   2564  1100 pts/0    Ss   20:31   0:00 /usr/bin/tini\n"
                    "root        88  0.0  0.8 222328 35360 pts/0    Sl+  20:32   0:00 uv run main.py"}})
            return self._send(200, {"data": {"systemDebug": ""}})

        msearch = re.search(r"\bsearch\s*\(\s*filter:\s*\"((?:[^\"\\]|\\.)*)\"", q)
        if msearch:
            # V411-GL-01 ground truth: the VULN twin concatenates the filter
            # into a SQL predicate (quote-break -> engine error + SQL echo;
            # OR-tautology -> full result set). The SAFE twin parameterizes.
            flt = msearch.group(1)
            if safe:
                sel = [p for p in PRODUCTS if p["name"] == flt]
                return self._send(200, {"data": {"search": sel}})
            if "'''" in flt or flt.endswith("'"):
                return self._send(200, _err(
                    "(sqlite3.OperationalError) near \"%s\": syntax error\n"
                    "[SQL: SELECT id, name, price FROM products "
                    "WHERE (name = '%s' OR descr = '%s')]" % (flt[:8], flt, flt)))
            if "' or '1'='1" in flt:
                return self._send(200, {"data": {"search": PRODUCTS}})
            sel = [p for p in PRODUCTS if p["name"] == flt]
            return self._send(200, {"data": {"search": sel}})

        if re.search(r"\buser\s*\(", q or ""):
            # V411-GL-08: the id argument is Int! — a QUOTED literal
            # (user(id: "1")) is invalid GraphQL and MUST not resolve. The
            # engine's type-aware literal rendering is regression-tested here
            # (a string-into-Int regression goes unanswered, exactly like a
            # real graphene server).
            mid = re.search(r"user\s*\(\s*id:\s*(\d+)", q)
            if mid is None:
                return self._send(200, _err("user requires id"))
            target = int(mid.group(1))
            if safe:
                if uid is None:
                    return self._send(401, _err("not authenticated"))
                if target != uid:
                    return self._send(200, _err("forbidden: not your record"))
                u = dict(USERS[uid])
                u["passwordHash"] = "******"              # masked, not exposed
                u["ssn"] = "[REDACTED]"
                return self._send(200, {"data": {"user": u}})
            return self._send(200, {"data": {"user": USERS.get(target)}})

        if re.search(r"\bme\b", q or ""):
            if uid is None:
                return self._send(200, _err("not authenticated"))
            u = dict(USERS[uid])
            if safe:
                # V411-GL-03 precision ground truth: the SAFE twin returns
                # MASKED sensitive fields — the value-aware engine must record
                # a masking boundary, never a field-authorization finding
                u["passwordHash"] = "******"
                u["ssn"] = "[REDACTED]"
            return self._send(200, {"data": {"me": u}})

        if "products" in q:
            return self._send(200, {"data": {"products": PRODUCTS}})
        return self._send(200, _err("unknown operation"))


import re  # noqa: E402  (used by _graphql)


def serve(port: int = 0) -> tuple[str, ThreadingHTTPServer]:
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_address[1]}", srv

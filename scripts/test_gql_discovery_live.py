#!/usr/bin/env python3
"""Quick live validation: does the v4.1.1 GraphQL engine discover & introspect
DVGA's real /graphql endpoint now (post ENG-11 Content-Type fix)?"""
import sys, json
sys.path.insert(0, "/home/z/my-project/build-v411")

from sentinel.core import ScopeRule, EventBus
from sentinel.http_engine import RequestEngine
from sentinel.graphql import GraphqlEngine, GraphqlClient, GQL_PATH_RE

BASE = "http://127.0.0.1:5013/"
scope = ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True)
bus = EventBus("test-gql-live")
engine = RequestEngine(scope, bus, timeout=12)

# --- 1. manual sanity: POST /graphql {__typename} with the fixed client
client = GraphqlClient(engine)
r = client.query(BASE + "graphql", "{__typename}", note="sanity")
print("SANITY /graphql:", r.status if r else None, "err:", r.error if r else None,
      "body:", (r.body or "")[:120])

# --- 2. discovery pass (observed candidates simulated from the endpoint map
#     the crawler produced in the failed scan: the static JS file is there)
class FakeEP:
    def __init__(self, url):
        self.url = url
endpoints = [FakeEP(BASE + "static/jquery/graphql.js"),
             FakeEP(BASE + "static/all.css"),
             FakeEP(BASE + "my_pastes"),
             FakeEP(BASE + "public_pastes")]

g = GraphqlEngine(engine, scope, bus, timeout=12)
cands = g.discover(endpoints, BASE)
print("\nDISCOVERY candidates:")
for c in cands:
    print("  ", c)

# --- 3. introspect the real endpoint
schema = g.introspect(BASE + "graphql")
if schema:
    ops = g.operations(schema)
    print("\nINTROSPECTION OK: %d queries, %d mutations" %
          (len(ops["queries"]), len(ops["mutations"])))
    for q in ops["queries"]:
        print("   Q:", q["name"], "args:", [(a["name"], a["type"]) for a in q["args"]])
    for m in ops["mutations"]:
        print("   M:", m["name"], "args:", [(a["name"], a["type"]) for a in m["args"]])
else:
    print("\nINTROSPECTION FAILED on /graphql")

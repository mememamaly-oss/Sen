#!/usr/bin/env python3
"""LIVE engine validation against running authorized targets:
1. GraphQL engine (v4.1.1, post GL-06..GL-10 fixes) vs DVGA on :5013
   - with primary identity (sentinel41a) + low identity (sentinel41b)
   - logic_active=True (planner gates state-changing probes)
2. WebSocket engine vs DVGA (/subscriptions expected via new probe path)
3. WebSocket channel sanity vs DVWS :8080 (rewritten pages)
Prints findings + boundary records so every capability claim is visible."""
import sys, json
sys.path.insert(0, "/home/z/my-project/build-v411")

from sentinel.core import ScopeRule, EventBus
from sentinel.http_engine import RequestEngine
from sentinel.boundary import BoundaryEngine as BoundaryRegistry
from sentinel.coverage import CoverageTracker
from sentinel.planner import SafeAttackPlanner
from sentinel.graphql import GraphqlEngine
from sentinel.websocket import WebSocketEngine, WsClient

ACC = json.load(open("/home/z/my-project/gap-validation/dvga_authz_accounts.json"))
A, B = ACC["accounts"][0], ACC["accounts"][1]     # a=primary, b=low

DVGA = "http://127.0.0.1:5013/"

def mk_engine(token=None):
    scope = ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True)
    eng = RequestEngine(scope, EventBus("live-val"), timeout=12)
    if token:
        eng.default_headers = dict(getattr(eng, "default_headers", {}) or {})
        eng.default_headers["Authorization"] = "Bearer " + token
    return eng

# token check first: me(token) — DVGA passes the token as a query argument
sanity = mk_engine(A["token"])
from sentinel.graphql import GraphqlClient
r = GraphqlClient(sanity).query(DVGA + "graphql",
                                'query { me(token: "%s") { id username } }'
                                % A["token"], note="token-sanity")
print("TOKEN SANITY (me):", (r.body or "")[:100])
if '"sentinel41a"' not in (r.body or ""):
    print("!! token expired or invalid — re-run dvga_setup_identities.py")
    sys.exit(1)

# ---------------- GraphQL engine full battery ----------------
print("\n" + "=" * 70)
print("GraphQL ENGINE vs DVGA (primary=sentinel41a, low=sentinel41b)")
print("=" * 70)
boundary = BoundaryRegistry()
coverage = CoverageTracker()
planner = SafeAttackPlanner(logic_active=True)
main_eng = mk_engine(A["token"])
anon_eng = mk_engine()
low_eng = mk_engine(B["token"])

g = GraphqlEngine(main_eng, main_eng.scope, main_eng.bus, timeout=12,
                  planner=planner, boundary=boundary, coverage=coverage,
                  logic_active=True)
res = g.run(
    [], DVGA,
    anonymous_engine=anon_eng,
    low_identity={"name": B["name"], "role": B["role"], "engine": low_eng,
                  "object_id": B["object_id"], "marker": B["marker"]},
    primary_identity={"name": A["name"], "role": A["role"],
                      "object_id": A["object_id"], "marker": A["marker"]})
print("\nSTATS:", json.dumps({k: v for k, v in res["stats"].items()
                              if k != "endpoints"}, indent=1)[:900])
print("\nFINDINGS:")
for f in res["findings"]:
    print(f"  [{f.severity.value}] {f.type} @ {f.parameter}")
    print(f"      evidence: {f.evidence[0].detail[:180]}")
print("\nBOUNDARY RECORDS:")
for rec in boundary.records:
    print(f"  [{rec.state}] {rec.category} :: {rec.reason[:130]}")

# ---------------- WebSocket engine vs DVGA ----------------
print("\n" + "=" * 70)
print("WebSocket ENGINE vs DVGA (expect /subscriptions via new probe path)")
print("=" * 70)
ws_boundary = BoundaryRegistry()
ws_cov = CoverageTracker()
w = WebSocketEngine(ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True),
                    EventBus("live-ws"), timeout=6, planner=SafeAttackPlanner(logic_active=True),
                    boundary=ws_boundary, coverage=ws_cov, logic_active=True)
wres = w.run([], DVGA,
             low_identity={"name": B["name"], "role": B["role"],
                           "engine": low_eng, "object_id": B["object_id"],
                           "marker": B["marker"]},
             primary_identity={"name": A["name"], "role": A["role"],
                               "object_id": A["object_id"],
                               "marker": A["marker"]})
print("\nWS STATS:", json.dumps(wres["stats"], indent=1)[:700])
print("\nWS FINDINGS:")
for f in wres["findings"]:
    print(f"  [{f.severity.value}] {f.type}")
    print(f"      evidence: {f.evidence[0].detail[:180]}")
print("\nWS BOUNDARY RECORDS:")
for rec in ws_boundary.records:
    print(f"  [{rec.state}] {rec.category} :: {rec.reason[:130]}")

# ---------------- DVWS channel sanity ----------------
print("\n" + "=" * 70)
print("DVWS WS channels sanity (:8080)")
print("=" * 70)
for path, msg in [("/reflected-xss", "sentinel-hello"),
                  ("/show-comments", "{}"),
                  ("/ssti", "{}"),
                  ("/command-execution", "{}")]:
    c = WsClient("ws://127.0.0.1:8080" + path, timeout=5)
    ok = c.connect()
    if not ok:
        print(f"  {path}: connect FAILED ({c.handshake_status})")
        continue
    c.send_text(msg)
    reply = c.listen(seconds=2.5, max_messages=3)
    c.close()
    texts = [m.get("text", "")[:120] for m in reply if m.get("opcode") == "text"]
    print(f"  {path}: send={msg!r} -> {texts if texts else '(no reply)'}")

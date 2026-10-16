#!/usr/bin/env python3
"""Surgical diagnosis: run the battery against the fixture and print each
family's raw observations per channel."""
import sys, os, json
sys.path.insert(0, "/home/z/my-project/build-v430")
import importlib.util as iu
spec = iu.spec_from_file_location("ws_app", "/home/z/my-project/build-v430/fixtures/ws_app.py")
mod = iu.module_from_spec(spec); spec.loader.exec_module(mod)
base, t, srv = mod.serve(port=8951)

from sentinel.core import ScopeRule, EventBus, Endpoint, DiscoverySource
from sentinel.websocket import (WebSocketEngine, WS_MESSAGE_SHAPES,
                                WS_CHANNEL_BINDINGS, harvest_ws_bindings, WsClient)
from sentinel.planner import SafeAttackPlanner
from sentinel.boundary import BoundaryEngine
from sentinel.coverage import CoverageTracker

WS_MESSAGE_SHAPES.clear()
WS_MESSAGE_SHAPES.extend([{"name": "", "comment": ""},
                          {"auth_user": "", "auth_pass": ""}])
WS_CHANNEL_BINDINGS.clear()
for page_js in mod.WS_BATTERY_PAGES_JS.values():
    harvest_ws_bindings(page_js.replace("HOST", base.split("//")[1]))

wsbase = base.replace("http", "ws", 1)

# --- direct manual battery probes: what do the channels answer? ---
print("=== RAW CHANNEL REPLIES (manual, same payloads the battery sends) ===")
for chan in ("/ws/sqli-prepared", "/ws/cmdi", "/ws/xss"):
    c = WsClient(wsbase + chan, timeout=6)
    ok = c.connect()
    print(f"\n{chan}: connected={ok}")
    for label, msg in [("pair-TRUE", "' OR '1'='1"), ("pair-FALSE", "' OR '1'='2"),
                       ("quote", "'")]:
        if chan == "/ws/sqli-prepared":
            import base64
            payload = json.dumps({"auth_user": base64.b64encode(msg.encode()).decode(),
                                  "auth_pass": base64.b64encode(b"sentinel").decode()})
        else:
            payload = msg
        r = None
        if ok:
            c.send_text(payload)
            r = c.wait_text(seconds=2.0)
        print(f"  {label}: sent={payload[:60]!r} -> reply={r!r}")
    c.close()

# --- now run the engine and dump battery evidence details ---
bus = EventBus("diag")
scope = ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True)
boundary = BoundaryEngine()
wse = WebSocketEngine(scope, bus, timeout=6,
                      planner=SafeAttackPlanner(logic_active=True),
                      boundary=boundary, coverage=CoverageTracker(),
                      logic_active=True, listen_seconds=2.0)
eps = [Endpoint(url=wsbase + p, source=DiscoverySource.JS_STATIC)
       for p in mod.WS_BATTERY_GROUND_TRUTH]
res = wse.run(eps, base)
print("\n=== BATTERY FINDINGS (details) ===")
for f in res["findings"]:
    if f.type in ("sql_injection", "command_injection", "ssti", "code_injection",
                  "path_traversal", "xss_reflected", "xss_stored"):
        print(f"\n{f.type} @ {f.endpoint_url} [{f.status.value}] param={f.parameter}")
        for e in f.evidence:
            print(f"   EV {e.kind}: {e.detail[:220]}")
srv.close()

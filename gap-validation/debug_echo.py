#!/usr/bin/env python3
"""Direct debug of the echo-channel battery flow."""
import sys
sys.path.insert(0, '/home/z/my-project/build-v411')
import importlib.util as iu
import os

spec = iu.spec_from_file_location("ws_app", "/home/z/my-project/build-v411/fixtures/ws_app.py")
mod = iu.module_from_spec(spec)
spec.loader.exec_module(mod)
base, t, srv = mod.serve(port=8955)

from sentinel.core import ScopeRule, EventBus, Endpoint, DiscoverySource
from sentinel.websocket import WebSocketEngine, WS_MESSAGE_SHAPES
from sentinel.planner import SafeAttackPlanner
from sentinel.boundary import BoundaryEngine
from sentinel.coverage import CoverageTracker

WS_MESSAGE_SHAPES.clear()
WS_MESSAGE_SHAPES.extend([{"name": "", "comment": ""}, {"auth_user": "", "auth_pass": ""}])

bus = EventBus("dbg")
scope = ScopeRule(allowed_domains=["127.0.0.1"], allow_private=True)
boundary = BoundaryEngine()
wse = WebSocketEngine(scope, bus, timeout=6,
                      planner=SafeAttackPlanner(logic_active=True),
                      boundary=boundary, coverage=CoverageTracker(),
                      logic_active=True, listen_seconds=1.5)
wsbase = base.replace("http", "ws", 1)
eps = [Endpoint(url=wsbase + "/ws/echo", source=DiscoverySource.JS_STATIC)]
res = wse.run(eps, base,
              low_identity=None, primary_identity=None)
print("FINDINGS:", [(f.type, f.endpoint_url) for f in res["findings"]])
print("STATS protocols:", res["stats"]["protocols"])
print("BOUNDARIES:")
for r in boundary.records:
    print("  ", r.category, "|", r.target.rsplit("/", 1)[-1], "|", r.state, "|", r.reason[:90])
srv.close()

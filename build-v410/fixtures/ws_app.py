#!/usr/bin/env python3
"""SENTINEL v4.1.0 fixture — WebSocket Intelligence (three channels).

A raw-socket WebSocket server (RFC 6455 server side, stdlib only) exposing:

    /ws/chat      VULNERABLE  no authentication; on connect the channel pushes
                             another user's session data (marker + token) and
                             chat traffic to EVERY listener
    /ws/safe      HARDENED    handshake requires Authorization: Bearer <token>;
                             a valid token hears only its own identity's data
    /ws/partial   TEXT        connection open, but the channel speaks a pipe-
                             separated TEXT protocol (no JSON) — the honest
                             outcome is protocol_not_understood, never a claim

GROUND TRUTH:

  defect                                | /ws/chat   | /ws/safe | /ws/partial
  --------------------------------------+------------+----------+-------------
  unauthenticated + sensitive data      | YES        | no (401) | no (nothing
    websocket_sensitive_data_exposure   |  (token +  |          |  readable)
                                        |   markers) |          |
  cross-user channel data (marker)      | YES        | no       | n/a
    websocket_cross_user_access         |            |          |
  protocol understood                   | json       | json     | text ->
                                        |            |          |  UNTESTABLE
                                        |            |          |  boundary

Auth: Authorization: Bearer alice-token (id 1) / bob-token (id 2).
"""
import base64
import hashlib
import json
import re
import socket
import struct
import threading

WS_GROUND_TRUTH = {
    "/ws/chat": ["websocket_sensitive_data_exposure",
                 "websocket_cross_user_access"],
    "/ws/safe": [],
    "/ws/partial": [],
}
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
TOKENS = {"alice-token": "alice", "bob-token": "bob"}


def _accept_key(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()


def _encode_frame(opcode: int, payload: bytes) -> bytes:
    n = len(payload)
    if n < 126:
        hdr = struct.pack("!BB", 0x80 | opcode, n)
    elif n < (1 << 16):
        hdr = struct.pack("!BBH", 0x80 | opcode, 126, n)
    else:
        hdr = struct.pack("!BBQ", 0x80 | opcode, 127, n)
    return hdr + payload


def _read_frame(conn) -> tuple[int, bytes] | None:
    try:
        hdr = conn.recv(2)
        if len(hdr) < 2:
            return None
        opcode = hdr[0] & 0x0F
        length = hdr[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", conn.recv(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", conn.recv(8))[0]
        if length > (1 << 20):
            return None
        payload = b""
        while len(payload) < length:
            chunk = conn.recv(length - len(payload))
            if not chunk:
                return None
            payload += chunk
        return opcode, payload
    except OSError:
        return None


def _handle(conn: socket.socket, addr):
    try:
        conn.settimeout(10)
        req = b""
        while b"\r\n\r\n" not in req and len(req) < 8192:
            chunk = conn.recv(4096)
            if not chunk:
                return
            req += chunk
        head = req.decode("latin-1", "replace")
        mpath = re.match(r"GET\s+(\S+)", head)
        path = mpath.group(1).split("?")[0] if mpath else "/"
        mkey = re.search(r"Sec-WebSocket-Key:\s*(\S+)", head, re.I)
        auth = re.search(r"Authorization:\s*Bearer\s+(\S+)", head, re.I)

        if path not in ("/ws/chat", "/ws/safe", "/ws/partial"):
            conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            return
        if path == "/ws/safe":
            user = TOKENS.get(auth.group(1) if auth else "", "")
            if not user:
                conn.sendall(b"HTTP/1.1 401 Unauthorized\r\n"
                             b"Content-Length: 0\r\n"
                             b"WWW-Authenticate: Bearer\r\n\r\n")
                return
        else:
            user = "anonymous"

        if not mkey:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        conn.sendall(("HTTP/1.1 101 Switching Protocols\r\n"
                      "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                      f"Sec-WebSocket-Accept: {_accept_key(mkey.group(1))}\r\n"
                      "\r\n").encode())

        # ---- channel behavior
        if path == "/ws/chat":
            # the defect: EVERY listener (unauthenticated) receives another
            # user's session token + identity-marked chat traffic
            conn.sendall(_encode_frame(0x1, json.dumps({
                "type": "system", "event": "user-joined", "user": "alice",
                "email": "alice@sentinel-fixture.local",
                "sessionToken": "tok-alice-9f3ab2"}).encode()))
            conn.sendall(_encode_frame(0x1, json.dumps({
                "type": "chat", "user": "alice",
                "email": "alice@sentinel-fixture.local",
                "message": "transfer confirmed"}).encode()))
            conn.sendall(_encode_frame(0x1, json.dumps({
                "type": "system", "event": "tick"}).encode()))
        elif path == "/ws/safe":
            # authenticated: own identity's data only, nothing sensitive
            conn.sendall(_encode_frame(0x1, json.dumps({
                "type": "system", "event": "connected", "user": user,
                "status": "ok"}).encode()))
        else:  # /ws/partial — pipe-separated TEXT protocol
            conn.sendall(_encode_frame(0x1, b"welcome|anonymous|sess-77x"))
            conn.sendall(_encode_frame(0x1, b"tick|1"))

        # ---- serve until the client closes (answer pings, ignore text)
        while True:
            fr = _read_frame(conn)
            if fr is None:
                return
            opcode, payload = fr
            if opcode == 0x8:                       # close
                return
            if opcode == 0x9:                       # ping -> pong
                conn.sendall(_encode_frame(0xA, payload))
            # client text frames are accepted and ignored (the replay probe)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve(port: int = 0) -> tuple[str, threading.Thread, socket.socket]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    actual_port = srv.getsockname()[1]

    def loop():
        while True:
            try:
                conn, addr = srv.accept()
            except OSError:
                return
            threading.Thread(target=_handle, args=(conn, addr),
                             daemon=True).start()

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return f"http://127.0.0.1:{actual_port}", t, srv

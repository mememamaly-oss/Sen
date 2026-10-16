#!/usr/bin/env python3
"""SENTINEL v4.1.1 fixture — WebSocket Intelligence (five channels).

A raw-socket WebSocket server (RFC 6455 server side, stdlib only) exposing:

    /ws/chat      VULNERABLE  no authentication; on connect the channel pushes
                             another user's session data (marker + token) and
                             chat traffic to EVERY listener
    /ws/safe      HARDENED    handshake requires Authorization: Bearer <token>;
                             a valid token hears only its own identity's data
    /ws/partial   TEXT        connection open, but the channel speaks a pipe-
                             separated TEXT protocol (no JSON) — the honest
                             outcome is protocol_not_understood, never a claim
    /ws/echo      REQ/RESP    V411: SILENT on connect (a request/response
    (vulnerable)              channel — nothing is pushed until a message
                             arrives). A JSON message {name, comment} is
                             answered with an HTML reply that REFLECTS the
                             field values (DVWS-style) — the elicitation
                             probe must discover the protocol, the canary
                             reflection probe must prove the content
                             injection, and the handshake accepts any Origin
    /ws/origin    HARDENED    V411: pushes a welcome JSON on connect but the
    (origin-gate)             handshake REFUSES a foreign Origin (403) — the
                             origin probe must record origin-enforced, never
                             a finding

GROUND TRUTH:

  defect                                | /ws/chat | /ws/safe | /ws/partial | /ws/echo | /ws/origin
  --------------------------------------+----------+----------+-------------+----------+------------
  unauthenticated + sensitive data      | YES      | no (401) | no (nothing | no (silent |
    websocket_sensitive_data_exposure   |  (token +|          |  readable)  |  channel)  |
                                        |   markers)|         |             |            |
  cross-user channel data (marker)      | YES      | no       | n/a         | no         | no
    websocket_cross_user_access         |          |          |             |            |
  message-field reflection (V411)       | n/a      | n/a      | n/a         | YES        | n/a
    websocket_message_reflection        |          |          |             |            |
  origin policy absent (V411)           | yes*     | n/a (401)| n/a         | YES        | no (403)
    websocket_origin_not_enforced       |          |          |             |            |
  protocol understood                   | json     | json     | text ->     | request/   | json
                                        |          |          |  UNTESTABLE | response  |
                                        |          |          |  boundary   | (elicit)  |

  * /ws/chat also accepts any origin, but its findings are already exhaustive;
    the origin assertion targets /ws/echo (accept) vs /ws/origin (refuse).

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
    "/ws/echo": ["websocket_message_reflection",
                 "websocket_origin_not_enforced"],   # V411 request/response twin
    "/ws/origin": [],                             # V411 origin-enforcing twin
}

# ---- V4.3.2 (DVWS campaign): ACTIVE-BATTERY ground truth ---------------------
# Channels mirroring DVWS's message-borne vulnerability classes. The battery
# must verify each vulnerable class and stay silent on the controls:
#   /ws/sqli            pair-differential blind SQLi (base64 JSON keys)
#   /ws/sqli-error      DB-error-signature SQLi
#   /ws/sqli-prepared   CONTROL: parameterized — pair replies IDENTICAL
#   /ws/cmdi            raw ; echo CAN -> canary only (stderr not captured)
#   /ws/ssti            raw {{40+2}} -> 42 (+ literal echo for other inputs)
#   /ws/eval            raw 20+22 -> 42 (code evaluation)
#   /ws/lfi             raw /etc/passwd -> passwd content
#   /ws/xss             raw verbatim echo
#   /ws/store+/ws/read  write->read stored roundtrip
#   /ws/change-password DESTRUCTIVE vocabulary — BLOCKED_BY_SAFETY, zero sends
WS_BATTERY_GROUND_TRUTH = {
    "/ws/sqli": ["sql_injection"],
    "/ws/sqli-error": ["sql_injection"],
    "/ws/sqli-prepared": [],
    "/ws/cmdi": ["command_injection"],
    "/ws/ssti": ["ssti", "xss_reflected"],   # literal text IS reflected too
    "/ws/eval": ["code_injection"],
    "/ws/lfi": ["path_traversal"],
    "/ws/xss": ["xss_reflected"],
    "/ws/store": ["xss_stored"],
    "/ws/read": [],
    "/ws/change-password": [],          # blocked, never probed
}
WS_BATTERY_PAGES_JS = {
    # DVWS-shaped inline JS: the harvest must bind each channel to the
    # builder on its own page, INCLUDING the base64 transforms and the
    # two-template same-var csrf pattern.
    "/ws/sqli": ("var wsUri = \"ws://HOST/ws/sqli\"; websocket = new WebSocket(wsUri);"
                  "var v1 = Base64.encode(document.getElementById('auth_user').value);"
                  "var v2 = Base64.encode(document.getElementById('auth_pass').value);"
                  "var field_value = '{\"auth_user\":\"'+v1+'\",\"auth_pass\":\"'+v2+'\"}';"
                  "websocket.send(field_value);"),
    "/ws/sqli-error": ("var wsUri = \"ws://HOST/ws/sqli-error\"; websocket = new WebSocket(wsUri);"
                        "var v1 = Base64.encode(document.getElementById('auth_user').value);"
                        "var v2 = Base64.encode(document.getElementById('auth_pass').value);"
                        "var field_value = '{\"auth_user\":\"'+v1+'\",\"auth_pass\":\"'+v2+'\"}';"
                        "websocket.send(field_value);"),
    "/ws/sqli-prepared": ("var wsUri = \"ws://HOST/ws/sqli-prepared\"; websocket = new WebSocket(wsUri);"
                          "var v1 = Base64.encode(document.getElementById('auth_user').value);"
                          "var v2 = Base64.encode(document.getElementById('auth_pass').value);"
                          "var field_value = '{\"auth_user\":\"'+v1+'\",\"auth_pass\":\"'+v2+'\"}';"
                          "websocket.send(field_value);"),
    "/ws/cmdi": ("var wsUri = \"ws://HOST/ws/cmdi\"; websocket = new WebSocket(wsUri);"
                  "var field_value = document.getElementById('ipaddr').value;"
                  "websocket.send(field_value);"),
    "/ws/ssti": ("var wsUri = \"ws://HOST/ws/ssti\"; websocket = new WebSocket(wsUri);"
                  "var field_value = document.getElementById('name').value;"
                  "websocket.send(field_value);"),
    "/ws/eval": ("var wsUri = \"ws://HOST/ws/eval\"; websocket = new WebSocket(wsUri);"
                  "var field_value = document.getElementById('op').value;"
                  "websocket.send(field_value);"),
    "/ws/lfi": ("var wsUri = \"ws://HOST/ws/lfi\"; websocket = new WebSocket(wsUri);"
                  "var field_value = document.getElementById('file').value;"
                  "websocket.send(field_value);"),
    "/ws/xss": ("var wsUri = \"ws://HOST/ws/xss\"; websocket = new WebSocket(wsUri);"
                  "var field_value = document.getElementById('name').value;"
                  "websocket.send(field_value);"),
    "/ws/store": ("var wsUri = \"ws://HOST/ws/store\"; websocket = new WebSocket(wsUri);"
                   "var field_value = '{\"name\":\"'+n1+'\",\"comment\":\"'+n2+'\"}';"
                   "websocket.send(field_value);"),
    "/ws/read": ("var wsUri = \"ws://HOST/ws/read\"; websocket = new WebSocket(wsUri);"
                   "setTimeout(function() { websocket.send(\"showComments\"); }, 2000);"),
    "/ws/change-password": ("var wsUri = \"ws://HOST/ws/change-password\"; websocket = new WebSocket(wsUri);"
                             "var npass_field_value = document.getElementById('npass').value;"
                             "var cpass_field_value = document.getElementById('cpass').value;"
                             "var field_value = '{\"npass\":\"'+npass_field_value+'\",\"cpass\":\"'+cpass_field_value+'\"}';"
                             "websocket.send(field_value);"),
}

# shared battery-channel state (the fixture's own honest probes)
WS_STORE_LOCK = threading.Lock()
WS_STORE: list[tuple[str, str]] = []
WS_CHANGE_PASSWORD_MESSAGES: list[str] = []     # MUST stay empty (safety)

PASSWD_FAKE = ("root:x:0:0:root:/root:/bin/bash\n"
               "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
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
        masked = bool(hdr[1] & 0x80)
        length = hdr[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", conn.recv(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", conn.recv(8))[0]
        if length > (1 << 20):
            return None
        mask = b""
        if masked:                              # RFC 6455: client frames are masked
            mask = conn.recv(4)
        payload = b""
        while len(payload) < length:
            chunk = conn.recv(length - len(payload))
            if not chunk:
                return None
            payload += chunk
        if masked:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
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
        origin = re.search(r"Origin:\s*(\S+)", head, re.I)

        if path not in ("/ws/chat", "/ws/safe", "/ws/partial",
                        "/ws/echo", "/ws/origin",
                        "/ws/sqli", "/ws/sqli-error", "/ws/sqli-prepared",
                        "/ws/cmdi", "/ws/ssti", "/ws/eval", "/ws/lfi",
                        "/ws/xss", "/ws/store", "/ws/read",
                        "/ws/change-password"):
            conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            return
        if path == "/ws/origin" and origin and \
                "sentinel-fixture.local" not in origin.group(1):
            # V411: an origin-GATED channel — foreign origins refused outright
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
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
        elif path == "/ws/origin":
            # V411: same-origin welcome only; foreign Origin never reaches here
            conn.sendall(_encode_frame(0x1, json.dumps({
                "type": "system", "event": "connected",
                "origin_policy": "strict"}).encode()))
        elif path == "/ws/echo":
            # V411: SILENT on connect — a request/response channel. Nothing
            # is pushed until the client speaks (the elicitation case).
            pass
        elif path == "/ws/partial":  # pipe-separated TEXT protocol
            # (the V4.3.2 battery channels stay SILENT on connect — the
            # DVWS request/response pattern: nothing is pushed until the
            # client speaks; the old bare `else` made every new channel a
            # partial twin and offset the battery's replies by the two
            # welcome/tick frames — caught by the discriminating test)
            conn.sendall(_encode_frame(0x1, b"welcome|anonymous|sess-77x"))
            conn.sendall(_encode_frame(0x1, b"tick|1"))

        # ---- serve until the client closes (answer pings; /ws/echo answers
        # JSON messages with an HTML reply that REFLECTS the fields)
        while True:
            fr = _read_frame(conn)
            if fr is None:
                return
            opcode, payload = fr
            if opcode == 0x8:                       # close
                return
            if opcode == 0x9:                       # ping -> pong
                conn.sendall(_encode_frame(0xA, payload))
            if opcode == 0x1 and path == "/ws/echo":
                try:
                    msg = json.loads(payload.decode() or "{}")
                except Exception:
                    msg = {}
                reply = ("<pre>Name: {}<br>Comment: {}</pre>".format(
                    msg.get("name", ""), msg.get("comment", "")))
                conn.sendall(_encode_frame(0x1, reply.encode()))
            # ---- V4.3.2 battery channels (DVWS-mirroring semantics)
            if opcode == 0x1 and path in ("/ws/sqli", "/ws/sqli-error",
                                          "/ws/sqli-prepared"):
                import base64 as _b64
                try:
                    msg = json.loads(payload.decode() or "{}")
                except Exception:
                    msg = {}
                u = msg.get("auth_user", "") or ""
                p = msg.get("auth_pass", "") or ""
                try:
                    u = _b64.b64decode(u).decode("latin-1", "replace")
                except Exception:
                    u = ""
                try:
                    p = _b64.b64decode(p).decode("latin-1", "replace")
                except Exception:
                    p = ""
                both = u + "\n" + p
                if path == "/ws/sqli-prepared":
                    # CONTROL: parameterized — the tautology NEVER changes
                    # the reply (identical replies, no differential)
                    reply = ("<pre>Welcome to your account.</pre>"
                             if (u, p) == ("admin", "admin")
                             else "<pre>Incorrect username/password</pre>")
                elif path == "/ws/sqli-error":
                    # DB-error-signature family: a bare quote breaks the query
                    reply = ("db error: You have an error in your SQL syntax; "
                             "check the manual for MariaDB server version"
                             if u.count("'") == 1 or p.count("'") == 1
                             else "<pre>Invalid username/password</pre>")
                else:
                    # /ws/sqli: boolean pair differential (tautology vs
                    # contradiction) — deterministic replies, no echo
                    if "'1'='1" in both:
                        reply = "<pre>Welcome to your account.</pre>"
                    elif "'1'='2" in both:
                        reply = "<pre>Invalid username/password</pre>"
                    else:
                        reply = "<pre>Invalid username/password</pre>"
                conn.sendall(_encode_frame(0x1, reply.encode()))
            if opcode == 0x1 and path == "/ws/cmdi":
                # shell_exec semantics: stdout only — unknown hosts error to
                # stderr (never echoed); `; echo CAN` prints the canary
                m = re.search(r"[;|]\s*echo\s+(\S+)", payload.decode("latin-1"))
                conn.sendall(_encode_frame(0x1, (m.group(1) if m else "").encode()))
            if opcode == 0x1 and path == "/ws/ssti":
                text = payload.decode("latin-1")
                if "{{40+2}}" in text:
                    conn.sendall(_encode_frame(0x1, b"Hello 42"))
                else:
                    conn.sendall(_encode_frame(
                        0x1, f"Hello {text}".encode()))
            if opcode == 0x1 and path == "/ws/eval":
                text = payload.decode("latin-1").strip()
                if text.startswith(";"):
                    # V4.3.2b (live-caught on the REAL DVWS): a cmdi-shaped
                    # payload on an eval sink returns NULL (return ; exits
                    # before the echo) — Ratchet's send(null) raises and the
                    # server CLOSES the connection. Simulated here so the
                    # per-family fresh-connection fix is discriminated: a
                    # single-connection battery goes deaf after this family.
                    return
                conn.sendall(_encode_frame(
                    0x1, (b"42" if text == "20+22"
                          else b"Error evaluating code.")))
            if opcode == 0x1 and path == "/ws/lfi":
                text = payload.decode("latin-1").strip()
                if text == "/etc/passwd":
                    conn.sendall(_encode_frame(0x1, PASSWD_FAKE.encode()))
                elif text.lower().endswith("win.ini"):
                    conn.sendall(_encode_frame(0x1, b"[fonts]\n[files]"))
                else:
                    conn.sendall(_encode_frame(0x1, b""))
            if opcode == 0x1 and path == "/ws/xss":
                conn.sendall(_encode_frame(
                    0x1, f"Hello {payload.decode('latin-1')}!".encode()))
            if opcode == 0x1 and path == "/ws/store":
                try:
                    msg = json.loads(payload.decode() or "{}")
                except Exception:
                    msg = {}
                with WS_STORE_LOCK:
                    WS_STORE.append((str(msg.get("name", "")),
                                     str(msg.get("comment", ""))))
                # no echo — the stored roundtrip is the only oracle
                conn.sendall(_encode_frame(0x1, b"ok: comment added"))
            if opcode == 0x1 and path == "/ws/read":
                with WS_STORE_LOCK:
                    dump = "".join(f"<pre>Name: {n}<br>Comment: {c}</pre>"
                                   for n, c in WS_STORE)
                conn.sendall(_encode_frame(
                    0x1, (dump or "no comments").encode()))
            if opcode == 0x1 and path == "/ws/change-password":
                # the SAFETY probe: the battery must NEVER send here
                WS_CHANGE_PASSWORD_MESSAGES.append(payload.decode("latin-1"))
                conn.sendall(_encode_frame(0x1, b"password changed"))
            # other channels: client text frames accepted and ignored
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

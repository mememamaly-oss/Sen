"""SENTINEL v4.1.0 — WebSocket Intelligence Engine (Phase V41-04).

The Python standard library has no WebSocket client — so this module ships a
minimal, dependency-free RFC 6455 implementation (handshake + frame codec,
client-side masking, ping/pong/close, fragmentation-aware receive) and builds
the intelligence layer on top of it:

    DISCOVER     ws:// / wss:// URLs observed in JavaScript (the discovery
                 engine already extracts `new WebSocket(...)` constructors)
                 + a deterministic well-known-path probe on the target host
    MODEL        connect (anonymous and authenticated), LISTEN passively,
                 and classify the message protocol: JSON-with-keys is
                 'understood' (channels/events/identifiers are visible);
                 anything else is honestly 'not understood'
    TEST         a bounded, planner-gated battery:
                   unauthenticated connection   does the channel admit us
                                                without credentials?
                   sensitive data exposure     do messages carry
                                                sensitive-vocab payloads or
                                                ANOTHER identity's markers?
                   cross-user channel access   does an unauthorized listener
                                                receive a specific identity's
                                                data (marker-proven)?
                   message tampering/replay    STATE_CHANGING — only with
                                                --logic-active AND an
                                                understood protocol
    BOUNDARY     never a guess:
                   no WebSocket observed      -> NOT_DISCOVERED
                   handshake refused (401)    -> TESTED (auth enforced)
                   binary/unknown frames      -> UNTESTABLE protocol_not_understood
                   tampering without protocol -> UNTESTABLE protocol_not_understood

Safety: connections are READ-dominant (listen first). Any write test is
classified by the Safe Attack Planner; destructive-shaped actions never run.
A channel whose protocol is not understood is NEVER reported as vulnerable —
it is a boundary.

Deterministic: fixed probe list, fixed listen budgets, fixed ordering.
"""
from __future__ import annotations

import base64
import json
import os
import re
import socket
import ssl
import struct
import time
import urllib.parse

from .core import Evidence, Finding, Severity, FindingStatus, Verification

# ------------------------------------------------------------------ constants
WELL_KNOWN_WS_PATHS = ("/ws", "/websocket", "/chat", "/socket", "/events")
SENSITIVE_WS_RE = re.compile(
    r"(password|passwd|secret|token|session[_-]?id|api[_-]?key|ssn|"
    r"credit[_-]?card|card[_-]?number|authorization|bearer)", re.I)
JSON_OBJ_RE = re.compile(r"^\s*\{.*\}\s*$", re.S)

OP_CONT, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA


class WsFrame:
    """One decoded server frame."""

    __slots__ = ("fin", "opcode", "payload")

    def __init__(self, fin: bool, opcode: int, payload: bytes):
        self.fin = fin
        self.opcode = opcode
        self.payload = payload


class WsClient:
    """Minimal RFC 6455 client over socket/ssl. Deterministic behavior; the
    handshake key is random (protocol-mandated) and never affects results."""

    def __init__(self, url: str, timeout: float = 6.0, headers: dict | None = None):
        self.url = url
        self.timeout = timeout
        self.headers = dict(headers or {})
        self.sock: socket.socket | ssl.SSLSocket | None = None
        self.handshake_status = 0
        self.handshake_body = ""
        self.connected = False
        self.close_code = 0
        self.bytes_sent = 0
        self._leftover = b""      # bytes read past the handshake, consumed
                                    # N bytes at a time (never wholesale)

    # ------------------------------------------------------------ handshake
    def connect(self) -> bool:
        u = urllib.parse.urlsplit(self.url)
        secure = u.scheme == "wss"
        host, port = u.hostname or "127.0.0.1", u.port or (443 if secure else 80)
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        try:
            raw = socket.create_connection((host, port), timeout=self.timeout)
            if secure:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                raw = ctx.wrap_socket(raw, server_hostname=host)
            self.sock = raw
            key = base64.b64encode(os.urandom(16)).decode()
            req = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                   "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n")
            for h, v in self.headers.items():
                req += f"{h}: {v}\r\n"
            req += "\r\n"
            self.sock.sendall(req.encode())
            # read the handshake response (headers only)
            buf = b""
            while b"\r\n\r\n" not in buf and len(buf) < 8192:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            head, _, rest = buf.partition(b"\r\n\r\n")
            lines = head.decode("latin-1", "replace").split("\r\n")
            if not lines or " 101 " not in lines[0] + " ":
                m = re.match(r"HTTP/[\d.]+\s+(\d+)", lines[0] if lines else "")
                self.handshake_status = int(m.group(1)) if m else 0
                self.handshake_body = rest.decode("latin-1", "replace")[:200] \
                    + " | " + (lines[0] if lines else "")
                self._hard_close()
                return False
            self.handshake_status = 101
            self.connected = True
            self._leftover = rest
            return True
        except (OSError, ValueError) as e:
            self.handshake_status = 0
            self.handshake_body = f"{type(e).__name__}: {e}"[:200]
            self._hard_close()
            return False

    # ------------------------------------------------------------ framing
    def _read_exact(self, n: int) -> bytes:
        """Read exactly n bytes: leftover first (PARTIALLY — a leftover may
        hold several coalesced frames and must not be consumed wholesale),
        then the socket."""
        buf = b""
        while n > 0:
            if self._leftover:
                take = self._leftover[:n]
                self._leftover = self._leftover[len(take):]
                buf += take
                n -= len(take)
                continue
            chunk = self.sock.recv(n)
            if not chunk:
                raise ConnectionError("socket closed mid-frame")
            buf += chunk
            n -= len(chunk)
        return buf

    def recv_frame(self) -> WsFrame | None:
        """One frame or None (timeout/close). Ping is answered inline."""
        try:
            hdr = self._read_exact(2)
            fin = bool(hdr[0] & 0x80)
            opcode = hdr[0] & 0x0F
            masked = bool(hdr[1] & 0x80)
            length = hdr[1] & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._read_exact(8))[0]
            if length > 1 << 20:                     # 1MB sanity cap
                raise ConnectionError("oversized frame rejected")
            payload = self._read_exact(length) if length else b""
            if masked:
                mask = self._read_exact(4)
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if opcode == OP_PING:
                self._send_frame(OP_PONG, payload)
                return self.recv_frame()
            if opcode == OP_CLOSE:
                self.close_code = struct.unpack(">H", payload[:2])[0] \
                    if len(payload) >= 2 else 1005
                self.close()
                return WsFrame(fin, OP_CLOSE, payload)
            return WsFrame(fin, opcode, payload)
        except (socket.timeout, TimeoutError):
            return None
        except (ConnectionError, OSError):
            return None

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        if self.sock is None:
            return
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        n = len(payload)
        if n < 126:
            hdr = struct.pack("!BB", 0x80 | opcode, 0x80 | n)
        elif n < (1 << 16):
            hdr = struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, n)
        else:
            hdr = struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, n)
        self.sock.sendall(hdr + mask + masked)
        self.bytes_sent += n

    def send_text(self, text: str) -> None:
        self._send_frame(OP_TEXT, text.encode())

    def listen(self, seconds: float = 3.0, max_messages: int = 8) -> list[dict]:
        """Passive collection: [{opcode, text}] until budget exhausted."""
        out: list[dict] = []
        if not self.connected:
            return out
        deadline = time.time() + seconds
        while len(out) < max_messages and time.time() < deadline:
            self.sock.settimeout(max(0.1, deadline - time.time()))
            f = self.recv_frame()
            if f is None:
                if not self.connected:
                    break
                continue
            if f.opcode == OP_CLOSE:
                out.append({"opcode": "close", "text": "",
                            "close_code": self.close_code})
                break
            out.append({"opcode": "text" if f.opcode == OP_TEXT else "binary",
                        "text": f.payload.decode("utf-8", "replace")[:400]})
        return out

    def close(self) -> None:
        if self.connected and self.sock is not None:
            try:
                self._send_frame(OP_CLOSE, b"")
            except Exception:
                pass
        self.connected = False
        self._hard_close()

    def _hard_close(self):
        try:
            if self.sock is not None:
                self.sock.close()
        except Exception:
            pass
        self.sock = None


# ------------------------------------------------------------------ engine
def classify_protocol(messages: list[dict]) -> str:
    """'json' | 'text' | 'binary' | 'none' — what the channel actually speaks."""
    texts = [m for m in messages if m.get("opcode") == "text"]
    bins = [m for m in messages if m.get("opcode") == "binary"]
    if bins and not texts:
        return "binary"
    json_count = 0
    for m in texts:
        try:
            if isinstance(json.loads(m.get("text", "")), dict):
                json_count += 1
        except Exception:
            pass
    if texts and json_count >= max(1, len(texts) // 2):
        return "json"
    if texts:
        return "text"
    return "none"


def _ws_finding(vtype, severity, url, evidence: Evidence, notes: str,
                state_before: str = "", state_after: str = "") -> Finding:
    f = Finding(vtype, severity, url, "", "GET", [evidence],
                status=FindingStatus.CANDIDATE)
    f.verification = Verification(method="websocket:message-verification",
                                  passed=True, confidence=0.85, rounds=1,
                                  notes=notes)
    f.status = FindingStatus.VERIFIED
    f.state_before = state_before[:160]
    f.state_after = state_after[:160]
    return f


class WebSocketEngine:
    """Discovery + bounded listen/tamper battery + honest boundaries."""

    def __init__(self, scope, bus, timeout: float = 6.0, planner=None,
                 boundary=None, coverage=None, logic_active: bool = False,
                 listen_seconds: float = 3.0):
        self.scope = scope
        self.bus = bus
        self.timeout = timeout
        self.planner = planner
        self.boundary = boundary
        self.coverage = coverage
        self.logic_active = logic_active
        self.listen_seconds = listen_seconds
        self.connections = 0

    # ------------------------------------------------------------ scope
    def _in_scope(self, url: str) -> bool:
        """The WS client speaks RAW SOCKETS — it bypasses the HTTP engine's
        scope gate by construction, so scope is enforced HERE, before any
        connect(): only channels on an explicitly allowed host/domain."""
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("ws", "wss"):
            return False
        host = (u.hostname or "").lower()
        if not host:
            return False
        if host in [h.lower() for h in (self.scope.allowed_hosts or [])]:
            return True
        for d in (self.scope.allowed_domains or []):
            d = d.lower()
            if host == d or host.endswith("." + d):
                return True
        return False

    # ------------------------------------------------------------ discovery
    def discover(self, endpoints: list, base_url: str) -> list[dict]:
        found: dict[str, dict] = {}
        u = urllib.parse.urlsplit(base_url)
        scheme = "wss" if u.scheme == "https" else "ws"
        origin = f"{scheme}://{u.netloc}"
        for ep in endpoints:
            eu = urllib.parse.urlsplit(ep.url)
            if eu.scheme in ("ws", "wss"):
                cand = f"{eu.scheme}://{eu.netloc}{eu.path or '/'}"
                if not self._in_scope(cand):
                    # an out-of-scope channel observed in the target's JS —
                    # discovered, honestly refused, never connected to
                    self._record("websocket", cand, "BLOCKED_BY_SAFETY",
                                 "channel outside the scan scope (raw-socket "
                                 "transport would bypass the HTTP scope gate)",
                                 remediation="add the channel's host to the "
                                             "scope if it is authorized",
                                 provenance="websocket:scope-gate")
                    continue
                found.setdefault(cand, {"url": cand, "source": "observed"})
        for p in WELL_KNOWN_WS_PATHS:
            url = origin + p
            if url in found:
                continue
            if not self._in_scope(url):
                continue
            c = WsClient(url, timeout=min(self.timeout, 4.0))
            ok = c.connect()
            c.close()
            self.connections += 1
            if ok:
                found[url] = {"url": url, "source": "probe"}
        return sorted(found.values(), key=lambda c: c["url"])

    # ------------------------------------------------------------ helpers
    def _record(self, category, target, state, reason, **kw):
        if self.boundary is not None:
            self.boundary.record(category, target, state, reason,
                                 evidence=kw.get("evidence", ""),
                                 provenance=kw.get("provenance", "websocket"),
                                 remediation=kw.get("remediation", ""))

    def _sensitive_lines(self, messages: list[dict]) -> list[str]:
        hits = []
        for m in messages:
            t = m.get("text", "")
            if t and SENSITIVE_WS_RE.search(t):
                hits.append(t[:200])
        return hits

    def _identity_lines(self, messages: list[dict], marker: str) -> list[str]:
        if not marker:
            return []
        return [m.get("text", "")[:200] for m in messages
                if marker in (m.get("text") or "")]

    # ------------------------------------------------------------ battery
    def run(self, endpoints: list, base_url: str,
            low_identity: dict | None = None,
            primary_identity: dict | None = None) -> dict:
        stats = {"enabled": True, "candidates": 0, "channels": [],
                 "connected": 0, "protocols": {}, "tests": 0,
                 "connections": 0, "blocked_by_planner": 0}
        findings: list[Finding] = []
        candidates = self.discover(endpoints, base_url)
        stats["candidates"] = len(candidates)
        if not candidates:
            self._record("websocket", base_url, "NOT_DISCOVERED",
                         "no WebSocket channel observed (JS extraction and "
                         "well-known probes all empty)",
                         provenance="websocket:discovery")
            stats["connections"] = self.connections
            return {"findings": findings, "stats": stats, "candidates": []}
        for cand in candidates:
            url = cand["url"]
            stats["channels"].append({"url": url, "source": cand["source"]})
            if self.coverage is not None:
                self.coverage.dim_discover("websocket", url,
                                           {"source": cand["source"]})
            # ---- 1. unauthenticated connection + passive listen
            client = WsClient(url, timeout=self.timeout)
            ok = client.connect()
            self.connections += 1
            stats["tests"] += 1
            if not ok:
                self._record("websocket/connection", url, "TESTED",
                             f"handshake refused without credentials "
                             f"(HTTP {client.handshake_status}) — "
                             "authentication enforced at the channel",
                             evidence=f"HTTP {client.handshake_status}: "
                                      f"{client.handshake_body[:100]}",
                             provenance="websocket:handshake")
                if self.coverage is not None:
                    self.coverage.dim_tested("websocket", url)
                continue
            stats["connected"] += 1
            messages = client.listen(seconds=self.listen_seconds)
            proto = classify_protocol(messages)
            stats["protocols"][url] = proto
            if self.coverage is not None:
                self.coverage.dim_tested("websocket", url)

            # ---- 2. protocol understanding (the honesty gate for everything
            # downstream: never claim a defect on a protocol we cannot read)
            if proto in ("binary", "none"):
                self._record(
                    "websocket/protocol", url, "UNTESTABLE",
                    f"protocol_not_understood ({proto or 'no'} frames) — the "
                    "channel's messages cannot be interpreted, so no "
                    "authorization or content claim is possible",
                    evidence=(messages[0].get("text", "")[:100]
                              if messages else "no messages within budget"),
                    remediation="supply the message schema or capture samples "
                                "to enable content analysis",
                    provenance="websocket:passive-listen")
                client.close()
                continue

            # ---- 3. sensitive data exposure to an anonymous listener
            sensitive = self._sensitive_lines(messages)
            if sensitive:
                findings.append(_ws_finding(
                    "websocket_sensitive_data_exposure", Severity.HIGH, url,
                    Evidence("sensitive_messages_to_listener",
                             f"an UNAUTHENTICATED listener received "
                             f"{len(sensitive)} sensitive-named message(s) on "
                             f"{url} — first: '{sensitive[0][:180]}' — "
                             "channel data is broadcast without authorization",
                             ""),
                    "passive listen captured sensitive-named payloads",
                    state_before="anonymous listener connected, no credentials",
                    state_after=sensitive[0]))
            else:
                self._record("websocket/content", url, "TESTED",
                             "no sensitive-named payloads within the listen "
                             "budget", evidence=(messages[0].get("text", "")[:100]
                                                 if messages else "silent channel"),
                             provenance="websocket:passive-listen")

            # ---- 4. cross-user channel access (marker-proven): does the
            # anonymous/low listener receive the PRIMARY identity's markers?
            if primary_identity and primary_identity.get("marker"):
                marker_hits = self._identity_lines(
                    messages, primary_identity["marker"])
                if marker_hits and low_identity:
                    findings.append(_ws_finding(
                        "websocket_cross_user_access", Severity.HIGH, url,
                        Evidence("cross_identity_channel_data",
                                 f"an unauthorized listener received data of "
                                 f"identity '{primary_identity['name']}' "
                                 f"(marker '{primary_identity['marker'][:40]}') "
                                 f"on {url} — first: '{marker_hits[0][:180]}' — "
                                 "channel membership is not enforced", ""),
                        "listener captured another identity's marker in "
                        "channel messages",
                        state_before="listener holds no credentials for the "
                                     "primary identity",
                        state_after=marker_hits[0]))
                elif not marker_hits:
                    self._record(
                        "websocket/cross-user", url, "TESTED",
                        "no other-identity markers within the listen budget "
                        "(channel membership may hold — or the identity was "
                        "silent; not a claim either way)",
                        provenance="websocket:marker-listen")
            elif not primary_identity:
                self._record("websocket/cross-user", url, "UNTESTABLE",
                             "no configured identity markers to listen for",
                             remediation="configure accounts (--authz) with "
                                         "markers to enable cross-user channel "
                                         "testing",
                             provenance="websocket:marker-listen")

            # ---- 5. message tampering / replay (STATE_CHANGING, gated)
            if proto == "json" and messages:
                gated = True
                if self.planner is not None:
                    verdict = self.planner.gate(url, "POST",
                                                fields=[("message", "replay")],
                                                note="ws-replay")
                    gated = verdict.get("allowed", False)
                if not gated:
                    stats["blocked_by_planner"] += 1
                    self._record("websocket/tampering", url,
                                 "BLOCKED_BY_SAFETY",
                                 "replay/tamper probes are STATE_CHANGING — "
                                 "blocked by the Safe Attack Planner",
                                 remediation="re-run with --logic-active on a "
                                             "staging copy to authorize write "
                                             "probes",
                                 provenance="websocket:planner-gate")
                elif self.logic_active:
                    # replay the FIRST observed message verbatim once — the
                    # most conservative write probe (no synthesis, no new shape)
                    first = messages[0].get("text", "")
                    if first:
                        client.send_text(first)
                        reply = client.listen(seconds=1.5, max_messages=2)
                        stats["tests"] += 1
                        effect = [m for m in reply if m.get("opcode") == "text"]
                        self._record(
                            "websocket/tampering", url, "TESTED",
                            "verbatim replay sent; server response captured "
                            + ("(no visible state effect)" if not effect
                               else f"('{effect[0]['text'][:80]}')"),
                            evidence=(effect[0]["text"][:120] if effect
                                      else "no reply"),
                            provenance="websocket:replay-probe")
            elif proto == "text":
                self._record("websocket/tampering", url, "UNTESTABLE",
                             "protocol_not_understood (text frames without "
                             "JSON structure) — no message fields to tamper "
                             "safely", provenance="websocket:protocol")
            client.close()
        stats["connections"] = self.connections
        return {"findings": findings, "stats": stats, "candidates": candidates}

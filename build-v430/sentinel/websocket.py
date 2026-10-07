"""SENTINEL v4.1.1 — WebSocket Intelligence Engine (Phase V41-04 + V411-WS).

The Python standard library has no WebSocket client — so this module ships a
minimal, dependency-free RFC 6455 implementation (handshake + frame codec,
client-side masking, ping/pong/close, fragmentation-aware receive) and builds
the intelligence layer on top of it:

    DISCOVER     ws:// / wss:// URLs observed in JavaScript (the discovery
                 engine already extracts `new WebSocket(...)` constructors)
                 + a deterministic well-known-path probe on the target host
    MODEL        connect (anonymous and authenticated), LISTEN passively,
                 and — v4.1.1 — ELICIT: many real channels are request/
                 response (a chat API, a GraphQL subscription server, a WS
                 RPC bridge) and say NOTHING until spoken to. The elicitation
                 probe sends ONE benign JSON hello ({} then graphql-ws
                 connection_init on a fresh connection), planner-gated as
                 STATE_CHANGING (an unknown channel may write on any message)
                 and only under --logic-active. The message protocol is then
                 classified per direction: request shape (what the channel
                 accepts) + reply shape (what it answers).
    TEST         a bounded, planner-gated battery:
                   unauthenticated connection   does the channel admit us
                                                without credentials?
                   sensitive data exposure     do messages carry
                                                sensitive-vocab data with
                                                REAL values (v4.1.1: value-
                                                shaped matching — an error
                                                string containing the word
                                                'password' is NOT exposure)
                                                to an anonymous listener?
                   cross-user channel access   does an unauthorized listener
                                                receive a specific identity's
                                                data (marker-proven)?
                   message reflection (V411-WS-03) a canary placed in every
                                                string field of the request
                                                message, proven in the reply
                                                (content injection through
                                                the WS transport)
                   verbatim replay (V411-WS-04)  the elicitation message
                                                resent verbatim once; the
                                                reply differential is
                                                recorded (state effect)
                   origin policy (V411-WS-05)    a foreign-Origin handshake:
                                                accepted -> CSWSH precondition
                                                recorded as a finding;
                                                refused -> origin enforced
                   message tampering/replay    STATE_CHANGING — only with
                                                --logic-active AND an
                                                understood protocol
    BOUNDARY     never a guess:
                   no WebSocket observed      -> NOT_DISCOVERED
                   handshake refused (401)    -> TESTED (auth enforced)
                   binary/unknown frames      -> UNTESTABLE protocol_not_understood
                   silent channel, elicitation
                   not authorized             -> UNTESTABLE elicitation_blocked
                   tampering without protocol -> UNTESTABLE protocol_not_understood

Safety: connections are READ-dominant (listen first). The elicitation hello
and every reflection/replay probe is classified by the Safe Attack Planner;
destructive-shaped actions never run. A channel whose protocol is not
understood is NEVER reported as vulnerable — it is a boundary.

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
# V411-WS-06 (live-caught on DVGA): GraphQL subscription transports are the
# most common production WebSocket surface after /ws — DVGA exposes
# /subscriptions (graphql-ws over gevent). Added /graphql-ws, /stomp, /mqtt
# (broker transports); all remain bounded, deterministic, one probe each.
WELL_KNOWN_WS_PATHS = ("/ws", "/websocket", "/chat", "/socket", "/events",
                       "/subscriptions", "/graphql-ws", "/stomp", "/mqtt")
SENSITIVE_WS_RE = re.compile(
    r"(password|passwd|secret|token|session[_-]?id|api[_-]?key|ssn|"
    r"credit[_-]?card|card[_-]?number|authorization|bearer)", re.I)
# V411-WS-02: value-shaped sensitive data — a sensitive KEY carrying a real
# VALUE ("password": "hunter2", password=hunter2). A bare keyword inside an
# error string ("Invalid username/password") is NOT exposure.
SENSITIVE_WS_VALUE_RE = re.compile(
    r"[\"']?(password|passwd|secret|token|session[_-]?id|api[_-]?key|ssn|"
    r"credit[_-]?card|card[_-]?number)[\"']?\s*[:=]\s*[\"']?"
    r"[^\s\"',}]{3,}", re.I)
JSON_OBJ_RE = re.compile(r"^\s*\{.*\}\s*$", re.S)
# V411-WS-01: deterministic elicitation hellos (in order, one per fresh
# connection). {} speaks to generic JSON request/response channels;
# connection_init speaks the graphql-ws subscription handshake. Between them:
# the message SHAPES harvested from the application's own JavaScript (the
# honest source of the schema — never guessed).
ELICIT_MESSAGES = ("{}", '{"type":"connection_init","payload":{}}')
FOREIGN_ORIGIN = "http://sentinel-origin-probe.example"

# ---- V411-WS-SHAPES: message shapes harvested from the target's JavaScript.
# The application's own client code (websocket.send(JSON.stringify({a:..})) or
# string-concatenated JSON templates like '{"name":"'+v+'"}') is the only
# OBSERVED source of the channel's message schema. Discovery feeds every
# fetched HTML/JS body through harvest_ws_shapes(); the WebSocket engine uses
# the registry for elicitation and canary-reflection probes. Provenance is
# always observable: no shape is invented.
_WS_JSONIFY_RE = re.compile(
    r"JSON\.stringify\(\s*\{(\s*[\w$\"']{1,40}\s*:[\s\S]{0,300}?)\}\s*\)")
_WS_TEMPLATE_RE = re.compile(
    r"\{\s*\"(\w+)\"\s*:\s*\"?\s*(?:\'\s*\+)?[^{}]{0,120}?"
    r"(?:,\s*\"(\w+)\"\s*:\s*\"?\s*(?:\'\s*\+)?[^{}]{0,120}?){0,6}\}")
_WS_KEY_RE = re.compile(r"[\"']?(\w+)[\"']?\s*:")
WS_MESSAGE_SHAPES: list[dict] = []
_WS_SHAPE_CAP = 6            # bounded registry; deterministic sorted order

# ---- V411-WS-DISC-2 (live-caught on DVWS): real applications rarely inline
# the channel URL in the constructor — DVWS's own pages say
#     var wsUri = "ws://127.0.0.1:8080/command-execution";
#     websocket = new WebSocket(wsUri);
# The constructor receives a VARIABLE, so the old literal-only pattern
# (`new WebSocket("ws://...")`) saw nothing, and the well-known-path probe
# probed the HTTP origin's port (8888) while the WS server listens on 8080 —
# the whole channel surface was invisible. The honest observed source is any
# QUOTED ws:// / wss:// URL in the application's own JavaScript (browsers use
# these schemes for WebSockets exclusively) — which covers the variable
# assignment AND the literal constructor AND config objects in one rule.
# The registry is what discovery feeds and the engine consumes; every entry
# still passes the raw-socket scope gate before any connect.
_WS_URL_RE = re.compile(r"""["'`](ws[s]?://[^"'`\s()<>]{3,300})["'`]""", re.I)
WS_OBSERVED_URLS: list[str] = []
_WS_URL_CAP = 16             # bounded registry; deterministic sorted order


def observe_ws_urls(js_text: str) -> list[str]:
    """Harvest quoted ws:// / wss:// URLs from JavaScript (observed channels).
    Returns the NEW urls added. Idempotent; bounded; sorted."""
    if not js_text:
        return []
    added = []
    for m in _WS_URL_RE.finditer(js_text):
        u = m.group(1).rstrip("/") or m.group(1)
        if u in WS_OBSERVED_URLS or u in added:
            continue
        if len(WS_OBSERVED_URLS) + len(added) >= _WS_URL_CAP:
            break
        added.append(u)
    WS_OBSERVED_URLS.extend(sorted(added))
    WS_OBSERVED_URLS.sort()
    return sorted(added)


def reset_ws_intel() -> None:
    """Per-scan reset of the JS-harvested registries (shapes + observed
    channels). Called by the orchestrator before discovery so a second scan
    in the same process never inherits the previous target's JS intel."""
    WS_MESSAGE_SHAPES.clear()
    WS_OBSERVED_URLS.clear()


def _safe_canary() -> str:
    """V411-WS-CANARY: the reflection canary is [a-z0-9] ONLY. Live-caught on
    DVWS: /command-execution appends the raw message to `shell_exec('ping -c
    3 ' . $msg)` — base64 canaries could carry '+' or '/' and file-inclusion
    channels pass the message to file_get_contents(). An alphanumeric-only
    canary carries NO shell metacharacter, NO path separator, NO wrapper
    prefix, NO template syntax — the probe is inert by construction in every
    injection context while remaining provably reflectable."""
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    raw = os.urandom(8)
    return "zk" + "".join(alphabet[b % 36] for b in raw) + "ws"


def harvest_ws_shapes(js_text: str) -> int:
    """Extract JSON message shapes from JS (client-side message builders).
    Returns the number of NEW shapes added. Idempotent; bounded; sorted."""
    if not js_text:
        return 0
    added = 0
    candidates = []
    for m in _WS_JSONIFY_RE.finditer(js_text):
        keys = _WS_KEY_RE.findall(m.group(1))
        if 1 <= len(keys) <= 8:
            candidates.append({k: "" for k in keys})
    for m in _WS_TEMPLATE_RE.finditer(js_text):
        keys = [k for k in m.groups() if k]
        if 1 <= len(keys) <= 8:
            candidates.append({k: "" for k in keys})
    for shape in candidates:
        sig = tuple(sorted(shape))
        if sig in [tuple(sorted(s)) for s in WS_MESSAGE_SHAPES]:
            continue
        if len(WS_MESSAGE_SHAPES) >= _WS_SHAPE_CAP:
            break
        WS_MESSAGE_SHAPES.append(shape)
        WS_MESSAGE_SHAPES.sort(key=lambda s: tuple(sorted(s)))
        added += 1
    return added


def elicitation_ladder() -> list[str]:
    """The full deterministic hello ladder: {} -> harvested shapes -> graphql-ws."""
    msgs = [ELICIT_MESSAGES[0]]
    for shape in WS_MESSAGE_SHAPES[:3]:
        msgs.append(json.dumps({k: "sentinel-hello" for k in shape}))
    msgs.append(ELICIT_MESSAGES[1])
    return msgs

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


# ------------------ v4.2.0 VF-04: websocket proof protocol ------------------
# A WebSocket finding's `passed` flag is DERIVED from raw observations by
# _derive_ws(), NEVER stamped by the caller. Every call site MUST pass
# proof={"rule": <closed-set name>, "obs": {...raw...}}; a missing proof,
# an unknown rule, or a failed derivation raises / yields REJECTED —
# mechanism, not convention.
def _derive_ws(proof: dict) -> bool:
    rule, obs = proof["rule"], proof.get("obs") or {}
    if rule == "canary-in-reply":
        return obs.get("opcode") == "text" \
            and str(obs.get("canary", "")) in str(obs.get("text", ""))
    if rule == "handshake-accepted":
        return bool(obs.get("upgraded"))
    if rule == "sensitive-present":
        return (obs.get("count", 0)) > 0
    if rule == "marker-in-messages":
        return (obs.get("hits", 0)) > 0 and bool(obs.get("low_identity"))
    raise ValueError(f"unknown websocket proof rule {rule!r} — add an explicit "
                     "derivation branch in _derive_ws (fail-closed)")


def _ws_finding(vtype, severity, url, evidence: Evidence, notes: str,
                state_before: str = "", state_after: str = "",
                proof: dict | None = None) -> Finding:
    if not isinstance(proof, dict) or "rule" not in proof or "obs" not in proof:
        raise ValueError(
            "websocket findings REQUIRE an explicit proof: "
            "proof={'rule': ..., 'obs': {...}} — the passed flag is DERIVED "
            "from raw observations by _derive_ws (v4.2.0 VF-04); stamped "
            "passed=True is forbidden")
    delta = _derive_ws(proof)
    f = Finding(vtype, severity, url, "", "GET", [evidence],
                status=FindingStatus.CANDIDATE)
    f.verification = Verification(
        method=f"websocket:message-verification:{proof['rule']}",
        passed=delta, confidence=0.85 if delta else 0.15, rounds=1,
        notes=notes + f" | derived={proof['rule']}")
    f.status = FindingStatus.VERIFIED if delta else FindingStatus.REJECTED
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
    def discover(self, endpoints: list, base_url: str,
                 observed_urls: list | None = None) -> list[dict]:
        """V411-WS-DISC-2: channels arrive from THREE observed sources —
        (a) ws:// endpoints in the discovery map, (b) ws:// URLs harvested
        from the target's own JavaScript (`var wsUri = "ws://host:port/path"`
        + `new WebSocket(wsUri)` — the DVWS pattern, where the WS server
        listens on a DIFFERENT PORT than the HTTP origin the well-known
        probes would scan), and (c) the deterministic well-known-path probe.
        Sources (a)/(b) are OBSERVED; (c) is a probe. Every channel —
        observed or probed — passes the raw-socket scope gate below; a
        same-host different-port channel is in scope (the HOST is what the
        operator authorized) and its provenance records the port delta."""
        found: dict[str, dict] = {}
        u = urllib.parse.urlsplit(base_url)
        scheme = "wss" if u.scheme == "https" else "ws"
        origin = f"{scheme}://{u.netloc}"

        def _admit(cand: str, source: str, seen_on: str = ""):
            """Scope-gate one candidate channel; record honest boundaries."""
            if not self._in_scope(cand):
                # an out-of-scope channel observed in the target's JS —
                # discovered, honestly refused, never connected to
                self._record("websocket", cand, "BLOCKED_BY_SAFETY",
                             "channel outside the scan scope (raw-socket "
                             "transport would bypass the HTTP scope gate)",
                             remediation="add the channel's host to the "
                                         "scope if it is authorized",
                             provenance="websocket:scope-gate")
                return
            entry = {"url": cand, "source": source}
            cu = urllib.parse.urlsplit(cand)
            if cu.netloc and cu.netloc != u.netloc and seen_on:
                entry["note"] = ("observed on %s; WS transport port %s "
                                 "differs from the HTTP origin port %s "
                                 "(same authorized host)" % (
                                     seen_on, cu.netloc, u.netloc))
            found.setdefault(cand, entry)

        for ep in endpoints:
            eu = urllib.parse.urlsplit(ep.url)
            if eu.scheme in ("ws", "wss"):
                cand = f"{eu.scheme}://{eu.netloc}{eu.path or '/'}"
                _admit(cand, "observed")
        for cand in (observed_urls or []):
            cu = urllib.parse.urlsplit(cand)
            if cu.scheme in ("ws", "wss"):
                _admit(f"{cu.scheme}://{cu.netloc}{cu.path or '/'}",
                       "observed-js", seen_on=u.netloc)
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
        """V411-WS-02: value-shaped sensitive data only."""
        hits = []
        for m in messages:
            t = m.get("text", "")
            if t and SENSITIVE_WS_VALUE_RE.search(t):
                hits.append(t[:200])
        return hits

    def _identity_lines(self, messages: list[dict], marker: str) -> list[str]:
        if not marker:
            return []
        return [m.get("text", "")[:200] for m in messages
                if marker in (m.get("text") or "")]

    def _gate(self, url: str, note: str, fields=None) -> bool:
        """Planner gate for WS write-shaped probes."""
        if self.planner is None:
            return True
        verdict = self.planner.gate(url, "POST", fields=fields or [],
                                    note=note)
        return bool(verdict.get("allowed", False))

    # V411-WS-01: elicitation — speak ONE benign hello to a silent channel.
    # The ladder: {} -> the app's OWN JS-harvested message shapes -> graphql-ws
    # connection_init. Returns (request_shape, hello_that_answered, messages);
    # ("", "", []) when not authorized or no hello produced a reply.
    def _elicit(self, url: str, stats: dict) -> tuple[str, str, list[dict]]:
        for hello in elicitation_ladder():
            if not self._gate(url, "ws-elicit",
                              fields=[("message", "hello")]):
                self._record("websocket/elicitation", url,
                             "BLOCKED_BY_SAFETY",
                             "elicitation probes are STATE_CHANGING (an "
                             "unknown channel may write on any message) — "
                             "blocked by the Safe Attack Planner",
                             remediation="re-run with --logic-active on an "
                                         "authorized staging copy",
                             provenance="websocket:planner-gate")
                return "", "", []
            if not self.logic_active:
                self._record("websocket/elicitation", url,
                             "BLOCKED_BY_PERMISSION",
                             "the channel is silent and elicitation is "
                             "STATE_CHANGING — requires --logic-active",
                             remediation="re-run with --logic-active to "
                                         "authorize the elicitation hello",
                             provenance="websocket:permission-gate")
                return "", "", []
            client = WsClient(url, timeout=self.timeout)
            if not client.connect():
                client.close()
                return "", "", []
            self.connections += 1
            stats["connections"] = self.connections
            client.send_text(hello)
            stats["tests"] += 1
            reply = client.listen(seconds=max(1.5, self.listen_seconds * 0.75),
                                  max_messages=4)
            client.close()
            texts = [m for m in reply if m.get("opcode") == "text"]
            if texts:
                try:
                    json.loads(hello)
                    req_shape = "json"
                except Exception:
                    req_shape = "text"
                return req_shape, hello, reply
        return "", "", []

    # V411-WS-03: canary reflection — every string field of each KNOWN message
    # shape (the elicited hello + the JS-harvested shapes) carries a fresh
    # canary; a reflection in the reply is proven content injection through
    # the WS transport. Bounded to 3 shapes, deterministic order.
    def _reflection_probe(self, url: str, hello: str, stats: dict) -> list[Finding]:
        findings: list[Finding] = []
        shapes: list[dict] = []
        try:
            first = json.loads(hello)
            if isinstance(first, dict) and first:
                shapes.append(first)
        except Exception:
            pass
        for shape in WS_MESSAGE_SHAPES[:3]:
            if tuple(sorted(shape)) not in [tuple(sorted(s)) for s in shapes]:
                shapes.append(shape)
        shapes = shapes[:3]
        if not shapes:
            self._record("websocket/reflection", url, "UNTESTABLE",
                         "no message shape known for the channel (the empty "
                         "hello has no fields) — nothing to place a canary in",
                         remediation="supply the message schema or run with "
                                     "JavaScript discovery so client-side "
                                     "message builders can be harvested",
                         provenance="websocket:reflection-probe")
            return findings
        for shape in shapes:
            canary = _safe_canary()
            probe = {k: canary for k in shape}
            n = len(probe)
            client = WsClient(url, timeout=self.timeout)
            if not client.connect():
                client.close()
                return findings
            self.connections += 1
            client.send_text(json.dumps(probe))
            stats["tests"] += 1
            reply = client.listen(seconds=2.0, max_messages=3)
            client.close()
            for m in reply:
                t = m.get("text", "")
                if m.get("opcode") == "text" and canary in t:
                    pos = t.find(canary)
                    around = t[max(0, pos - 60):pos + len(canary) + 60]
                    html_ctx = bool(re.search(
                        r"<[a-z][^>]*>[^<]*$|<br|</pre|<div|<b\b", around, re.I))
                    findings.append(_ws_finding(
                        "websocket_message_reflection", Severity.MEDIUM, url,
                        Evidence("message_field_reflection",
                                 "a canary placed in the request message's "
                                 "field(s) (%s) was REFLECTED in the server's "
                                 "reply%s — reply: '%s' — message field values "
                                 "reach the client response unsanitized (content "
                                 "injection through the WebSocket transport; the "
                                 "message shape was harvested from the "
                                 "application's own JavaScript)" % (
                                     ", ".join(sorted(shape)),
                                     " inside an HTML markup context" if html_ctx
                                     else "", t[:220]), ""),
                        "canary reflection proven in the WS reply",
                        state_before="request message carried canary in %d "
                                     "field(s)" % n,
                        state_after=t[:160],
                        proof={"rule": "canary-in-reply",
                               "obs": {"opcode": m.get("opcode"), "canary": canary,
                                       "text": t}}))
                    return findings
        self._record("websocket/reflection", url, "TESTED",
                     "canaries in every known message-shape field were not "
                     "reflected in the server replies",
                     provenance="websocket:reflection-probe")
        return findings

    # V411-WS-04: verbatim replay of the elicitation message — the reply
    # differential is recorded honestly (a state effect is evidence, not a
    # vulnerability claim by itself).
    def _replay_probe(self, url: str, hello: str, first_reply: list[dict],
                      stats: dict) -> None:
        client = WsClient(url, timeout=self.timeout)
        if not client.connect():
            client.close()
            return
        self.connections += 1
        client.send_text(hello)
        stats["tests"] += 1
        reply = client.listen(seconds=1.5, max_messages=3)
        client.close()
        first_text = next((m.get("text", "") for m in first_reply
                           if m.get("opcode") == "text"), "")
        second_text = next((m.get("text", "") for m in reply
                            if m.get("opcode") == "text"), "")
        if not reply:
            state, reason = "TESTED", "verbatim replay sent; no reply within " \
                                     "the budget (the message is not " \
                                     "idempotently answerable or the channel " \
                                     "closed)"
            evidence = "no reply"
        elif second_text == first_text:
            state, reason = "TESTED", "verbatim replay accepted with an " \
                                     "IDENTICAL reply — the operation is " \
                                     "replayable (idempotent or duplicate-write " \
                                     "shaped; a write effect cannot be " \
                                     "distinguished from here and is NOT " \
                                     "claimed)"
            evidence = second_text[:120]
        else:
            state, reason = "TESTED", "verbatim replay accepted with a " \
                                     "DIFFERENT reply (state or sequencing " \
                                     "sensitivity observed — recorded, not " \
                                     "claimed as a violation)"
            evidence = "first='%s' second='%s'" % (first_text[:60],
                                                   second_text[:60])
        self._record("websocket/replay", url, state, reason,
                     evidence=evidence, provenance="websocket:replay-probe")

    # V411-WS-05: foreign-Origin handshake — the CSWSH precondition.
    # unauth_ok: whether the SAME channel admitted a plain unauthenticated
    # handshake earlier in the battery — the honest attribution baseline
    # (a refusal is only attributable to the ORIGIN when the channel
    # otherwise admits anonymous handshakes).
    def _origin_probe(self, url: str, stats: dict,
                      unauth_ok: bool = False) -> list[Finding]:
        findings: list[Finding] = []
        client = WsClient(url, timeout=min(self.timeout, 5.0),
                          headers={"Origin": FOREIGN_ORIGIN})
        ok = client.connect()
        self.connections += 1
        stats["tests"] += 1
        if ok:
            findings.append(_ws_finding(
                "websocket_origin_not_enforced", Severity.LOW, url,
                Evidence("foreign_origin_handshake_accepted",
                         "the WebSocket handshake was accepted with the "
                         "foreign Origin '%s' (HTTP 101 upgraded) — the "
                         "channel does not enforce an origin policy; combined "
                         "with ambient cookie authentication this is the "
                         "cross-site WebSocket hijacking (CSWSH) precondition" %
                         FOREIGN_ORIGIN, ""),
                "handshake upgraded with a foreign Origin header",
                state_before="Origin: " + FOREIGN_ORIGIN,
                state_after="HTTP 101 Switching Protocols",
                proof={"rule": "handshake-accepted", "obs": {"upgraded": ok}}))
            client.close()
        else:
            if unauth_ok:
                self._record(
                    "websocket/origin", url, "TESTED",
                    "handshake with a foreign Origin refused (HTTP %s) while "
                    "the SAME channel admits plain unauthenticated "
                    "handshakes — an origin policy is actively enforced" %
                    client.handshake_status,
                    evidence="HTTP %d" % client.handshake_status,
                    provenance="websocket:origin-probe")
            else:
                self._record(
                    "websocket/origin", url, "UNTESTABLE",
                    "handshake with a foreign Origin refused (HTTP %s), but "
                    "the channel also refuses plain unauthenticated "
                    "handshakes — the refusal cannot be attributed to an "
                    "origin policy rather than authentication" %
                    client.handshake_status,
                    evidence="HTTP %d" % client.handshake_status,
                    provenance="websocket:origin-probe")
        return findings

    # ------------------------------------------------------------ battery
    def run(self, endpoints: list, base_url: str,
            low_identity: dict | None = None,
            primary_identity: dict | None = None,
            observed_urls: list | None = None) -> dict:
        stats = {"enabled": True, "candidates": 0, "channels": [],
                 "connected": 0, "protocols": {}, "tests": 0,
                 "connections": 0, "blocked_by_planner": 0}
        findings: list[Finding] = []
        candidates = self.discover(endpoints, base_url,
                                   observed_urls=observed_urls)
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
            request_shape = ""            # set when elicitation speaks JSON
            elicited_hello = ""
            elicited_reply: list[dict] = []

            # ---- V411-WS-01: elicitation — silent request/response channels
            # say nothing until spoken to; one benign JSON hello (planner-
            # gated STATE_CHANGING, --logic-active only)
            if proto == "none":
                client.close()
                req_shape, hello_used, elicited = self._elicit(url, stats)
                if elicited:
                    request_shape = req_shape
                    elicited_reply = elicited
                    elicited_hello = hello_used
                    messages = elicited
                    proto = classify_protocol(
                        [m for m in elicited if m.get("opcode") == "text"])
                    stats["protocols"][url] = "%s/request-%s" % (
                        proto, request_shape) if request_shape else proto
                    self._record(
                        "websocket/elicitation", url, "TESTED",
                        "the silent channel answered a benign JSON hello — "
                        "request/response protocol confirmed (request shape: "
                        "%s, reply shape: %s)" % (request_shape, proto),
                        evidence=(elicited[0].get("text", "")[:120]
                                  if elicited else ""),
                        provenance="websocket:elicitation-probe")
                else:
                    stats["protocols"][url] = "none"
                    self._record(
                        "websocket/protocol", url, "UNTESTABLE",
                        "channel is silent to passive listening and "
                        "elicitation did not produce a readable reply (not "
                        "authorized, or the channel speaks a protocol the "
                        "hello does not match) — no content claim is "
                        "possible",
                        remediation="supply the message schema or capture "
                                    "samples to enable content analysis",
                        provenance="websocket:elicitation")
                    if self.coverage is not None:
                        self.coverage.dim_tested("websocket", url)
                    continue
            else:
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
            # (V411-WS-02: value-shaped — a real value, not a keyword in an
            # error string)
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
                    state_after=sensitive[0],
                    proof={"rule": "sensitive-present",
                           "obs": {"count": len(sensitive)}}))
            else:
                self._record("websocket/content", url, "TESTED",
                             "no value-shaped sensitive data within the listen "
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
                        state_after=marker_hits[0],
                        proof={"rule": "marker-in-messages",
                               "obs": {"hits": len(marker_hits),
                                       "low_identity": bool(low_identity)}}))
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

            # ---- 5. V411-WS-03: canary reflection (message-field content
            # injection through the WS transport) — requires an elicited JSON
            # request shape (the engine knows the fields it spoke)
            if request_shape == "json" and elicited_hello:
                findings += self._reflection_probe(url, elicited_hello, stats)

            # ---- 6. V411-WS-04: verbatim replay of the elicitation message
            if request_shape == "json" and elicited_hello:
                self._replay_probe(url, elicited_hello, elicited_reply, stats)

            # ---- 7. V411-WS-05: foreign-Origin handshake (CSWSH precondition)
            findings += self._origin_probe(url, stats, unauth_ok=True)

            # ---- 8. message tampering / replay (STATE_CHANGING, gated)
            if proto == "json" and messages and not elicited_hello:
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
            elif proto == "text" and not elicited_hello:
                self._record("websocket/tampering", url, "UNTESTABLE",
                             "protocol_not_understood (text frames without "
                             "JSON structure) — no message fields to tamper "
                             "safely (elicited channels are covered by the "
                             "reflection and replay probes)",
                             provenance="websocket:protocol")
            client.close()
        stats["connections"] = self.connections
        return {"findings": findings, "stats": stats, "candidates": candidates}

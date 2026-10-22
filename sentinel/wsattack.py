"""V4.3.2 WS-ACTIVE — active WebSocket message batteries (DVWS campaign).

THE LIVE-CAUGHT DEFECT (owasp-campaign app 6/6, DVWS 2026-10-08): the engine
connected to every observed channel, listened, elicited shapes, probed
reflection and Origin — but NEVER sent an attack payload through the message
channel. Every message-borne vulnerability class was structurally invisible:
the baseline v4.3.1 scan of DVWS returned 58 passive-only findings and ZERO
strong-class findings while the target carries NINE message-borne
vulnerabilities (red-team-proven the same day with raw-socket probes, zero
engine code, scripts/owsp/dvws_manual_probes.py):

    /authenticate-user        auth_user="admin' -- "      -> <pre>Welcome...  (SQLi)
    /authenticate-user-blind  TRUE/FALSE pair             -> Welcome/Invalid (blind SQLi)
    /command-execution        "127.0.0.1; echo CAN"       -> CAN in reply    (OS cmdi)
    /file-inclusion           "/etc/passwd"               -> root:x:0:0:     (LFI read)
    /php-code-injection       "40+2"                      -> "42"            (eval RCE)
    /reflected-xss            "<img ...>"                 -> echoed verbatim (XSS)
    /ssti                     "{{7*7}}"                   -> "Hello 49"      (Twig SSTI)
    /post-comments            marker post + show read     -> stored marker   (stored XSS)
    /authenticate-user-prepared  (CONTROL) tautology pair -> identical reply — the
                               prepared statement kills the differential; the battery
                               must stay silent there (its discriminating control).

DESIGN (blue-team):
  * Message shapes are OBSERVED, never guessed: harvested from the target's
    own page JavaScript (JSON templates with per-key transforms — btoa /
    Base64.encode / encodeURIComponent — plus raw-value sends and literal
    triggers). A channel with no observed builder is honestly skipped
    (boundary-recorded), not probed blind.
  * Every family verdict requires a VERIFICATION ROUND on a FRESH connection
    (re-execution contract): the winning payload is re-sent and the oracle
    must reproduce. Two-round byte-stable pair differentials, canary
    reproduction, or signature reproduction. A single-round observation can
    never mark a finding VERIFIED.
  * Echo exclusion: a reply that contains the payload itself is REFLECTION,
    not execution — the sql/cmdi/ssti/code/lfi families all exclude it (the
    xss_reflected family owns reflection).
  * Safety (fail-closed): channels whose path carries destructive vocabulary
    (password/change/edit/delete/update/drop/import/reset/remove/kill/logout/
    truncate/erase/burn) are BLOCKED_BY_SAFETY with a boundary record and
    zero sends; JSON keys with destructive vocabulary (password/passwd/
    current/new/delete/drop/update/edit/reset/remove) are skipped per-key.
    The battery is STATE_CHANGING-class: it only runs under --logic-active.
  * Budgets: <= 9 sends per slot, <= 14 per channel, <= 150 per scan.
"""
from __future__ import annotations

import base64
import json
import random
import re

from .core import Evidence, Finding, FindingStatus, Severity, Verification

# Reuse the engine's DB-error signature families (the same oracle the HTTP
# sql detector trusts — one signature list, one truth).
from .detect import SQL_ERR_PATTERNS

# ---- vocabulary gates -------------------------------------------------------
# (the destructive PATH gate lives in websocket.ws_destructive_path — one
# shared truth for every message-sending phase; see its docstring)
DESTRUCTIVE_KEY_VOCAB = (
    "password", "passwd", "current", "new", "delete", "drop", "update",
    "edit", "reset", "remove", "logout",
)
# additive write semantics (the stored-XSS flow posts a marker here)
WRITE_CHANNEL_RE_WORDS = ("post", "create", "add", "insert", "comment", "new",
                          "store", "save", "publish", "submit")
READ_CHANNEL_RE_WORDS = ("show", "read", "list", "get", "view", "comment", "all")

import re

_RE_PASSWD_LINE = re.compile(r"root:[x*!]:0:0:")           # /etc/passwd proof
_RE_WIN_INI = re.compile(r"\[fonts\]|\[files\]", re.I)     # win.ini proof

# ---- budgets ----------------------------------------------------------------
MAX_SENDS_PER_SLOT = 9
MAX_SENDS_PER_CHANNEL = 14
MAX_SENDS_PER_SCAN = 150


def _canary(rand: random.Random) -> str:
    return "SWS" + "".join(rand.choice("0123456789abcdef") for _ in range(10))


def _destructive_keys(keys) -> list:
    return [k for k in keys
            if any(w in k.lower() for w in DESTRUCTIVE_KEY_VOCAB)]


def _family_payloads(can: str) -> list:
    """(family, [payloads]) — deterministic order, highest-value first.
    The cmdi payloads are HOST-SAFE (a valid host, then the separator +
    canary): live-proven on DVWS /command-execution — `127.0.0.1; echo CAN`
    answers the canary in ~2s, while a bare `; echo CAN` leaves ping without
    an operand and some stacks stall; the host-first shape is also what the
    red-team manual probes proved."""
    return [
        ("sql_pair", ["' OR '1'='1", "' OR '1'='2"]),
        ("sql_error", ["'"]),
        ("cmdi", [f"127.0.0.1; echo {can}", f"| echo {can}",
                  f"; echo {can}"]),
        ("ssti", ["{{40+2}}"]),
        ("code_injection", ["20+22"]),
        ("lfi", ["/etc/passwd", "C:/windows/win.ini"]),
        ("xss_reflected", [f'<img src=x onerror="{can}">']),
    ]


def _render_json_message(shape: dict, slot: str, payload: str) -> str:
    """Render the observed JSON template with the payload in ONE slot."""
    vals = {}
    for k in shape["keys"]:
        v = payload if k == slot else "sentinel"
        if shape["keys"][k] == "base64":
            v = base64.b64encode(v.encode()).decode()
        elif shape["keys"][k] == "percent":
            from urllib.parse import quote
            v = quote(v, safe="")
        vals[k] = v
    return json.dumps(vals)


def _send_and_recv(client, message: str, seconds: float = 2.5):
    """One send + first-reply wait (request/response channels answer once;
    wait_text returns the moment the reply frame arrives)."""
    client.send_text(message)
    return client.wait_text(seconds=seconds)


class _Budget:
    def __init__(self):
        self.scan_sends = 0

    def allow(self, channel_sends: int, slot_sends: int) -> bool:
        return (self.scan_sends < MAX_SENDS_PER_SCAN
                and channel_sends < MAX_SENDS_PER_CHANNEL
                and slot_sends < MAX_SENDS_PER_SLOT)


# ------------------------------------------------------------------ oracles
def _sql_sig(reply: str | None):
    """DB-error signature oracle (same family list as the HTTP detector)."""
    if not reply:
        return None
    for pat in SQL_ERR_PATTERNS:
        m = pat.search(reply)
        if m:
            return m.group(0)[:80]
    return None


def _pair_differential(r_true, r_false, p_true, p_false):
    """The blind/boolean oracle: byte-stable TRUE/FALSE differential with
    echo exclusion. Returns (ok, detail)."""
    if r_true is None or r_false is None:
        return False, "no reply on one side of the pair"
    if r_true == r_false:
        return False, "pair replies identical (no differential — likely parameterized)"
    if p_true in r_true or p_false in r_false:
        return False, "reply echoes its own payload (reflection, not SQL execution)"
    return True, (f"TRUE reply {len(r_true)}B vs FALSE reply {len(r_false)}B "
                  f"(deterministic differential)")


def run_ws_battery(engine, candidates: list, stats: dict,
                   bindings: dict | None = None) -> list:
    """The active message battery. Returns findings (VERIFIED/REJECTED with
    two-round evidence). Mutates stats with the battery account."""
    from .websocket import (WsClient, WS_CHANNEL_BINDINGS, ws_destructive_path)

    bindings = bindings if bindings is not None else WS_CHANNEL_BINDINGS
    rand = random.Random(20261008)          # deterministic canaries per scan
    battery_stats = {"sends": 0, "channels": [], "blocked": [],
                     "fired": {}, "skipped": []}
    stats["battery"] = battery_stats
    findings: list[Finding] = []
    budget = _Budget()
    canary = _canary(rand)
    families = _family_payloads(canary)

    def _record(category, target, state, reason, **kw):
        if engine.boundary is not None:
            engine.boundary.record(category, target, state, reason,
                                   evidence=kw.get("evidence", ""),
                                   provenance=kw.get("provenance",
                                                     "websocket:battery"),
                                   remediation=kw.get("remediation", ""))

    def _emit(f: Finding):
        if engine.coverage is not None:
            engine.coverage.dim_tested("websocket", f.endpoint_url)
        findings.append(f)

    def _verified(family: str, vtype: str, severity: Severity, url: str,
                  param: str, evidence: list, notes: str,
                  passed: bool, conf: float, method: str,
                  state_before: str = "", state_after: str = "") -> Finding:
        f = Finding(vtype, severity, url, param, "WS", evidence,
                    status=FindingStatus.CANDIDATE)
        f.verification = Verification(method=method, passed=passed,
                                      confidence=conf if passed else 0.15,
                                      rounds=2, notes=notes)
        f.status = FindingStatus.VERIFIED if passed else FindingStatus.REJECTED
        f.confidence = conf if passed else 0.15
        f.state_before = state_before[:160]
        f.state_after = state_after[:160]
        if passed:
            battery_stats["fired"][family] = battery_stats["fired"].get(family, 0) + 1
        return f

    for cand in candidates:
        url = cand["url"]
        path = url.split("/", 3)[-1].split("?")[0] if "://" in url else url
        channel_sends = 0

        # ---- safety gate 1: destructive channel vocabulary (the SHARED
        # gate — run() already refused the pre-battery message phases for
        # these channels; the battery double-checks, fail-closed)
        if ws_destructive_path(url):
            battery_stats["blocked"].append(url)
            continue

        builders = bindings.get(url) or []
        if not builders:
            battery_stats["skipped"].append(url)
            _record("websocket/battery", url, "UNTESTABLE",
                    "no observed message builder for this channel (no JSON "
                    "template / raw send in the target's own JavaScript) — "
                    "the battery does not guess message shapes",
                    remediation="supply the message schema to enable message "
                                "batteries",
                    provenance="websocket:battery-shape-gate")
            continue

        battery_stats["channels"].append(url)
        shapes = [b for b in builders if b.get("kind") == "json"]
        raws = [b for b in builders if b.get("kind") == "raw"]

        # ---- slots: every observed JSON key (destructive keys skipped) + raw
        slots: list[tuple[str, str, dict]] = []   # (slot_kind, name, shape)
        for shape in shapes[:2]:
            bad = _destructive_keys(shape["keys"])
            for k in shape["keys"]:
                if k in bad:
                    _record("websocket/battery-key", f"{url}#{k}",
                            "BLOCKED_BY_SAFETY",
                            "message field carries destructive vocabulary — "
                            "probing it could mutate state (e.g. a password "
                            "field); skipped per-key",
                            provenance="websocket:battery-key-gate")
                    continue
                slots.append(("json", k, shape))
        if raws:
            slots.append(("raw", "(message)", raws[0]))

        client = WsClient(url, timeout=min(engine.timeout, 6.0))
        if not client.connect():
            client.close()
            _record("websocket/battery", url, "UNTESTABLE",
                    "channel refused the battery handshake",
                    provenance="websocket:battery-connect")
            continue
        engine.connections += 1

        # baseline: the empty/benign observed shape
        baseline = None
        if shapes:
            baseline = _send_and_recv(
                client, _render_json_message(shapes[0], list(shapes[0]["keys"])[0],
                                             "sentinel-baseline"))
            budget.scan_sends += 1
            channel_sends += 1

        for slot_kind, slot, shape in slots:
            slot_sends = 0
            for family, payloads in families:
                if not budget.allow(channel_sends, slot_sends):
                    break
                if family == "xss_reflected" and slot_kind != "raw" \
                        and slot not in ("name", "comment", "message", "text"):
                    # reflection proof needs an HTML-rendering field; other
                    # fields keep the budget for the stronger families
                    continue
                p_t = p_f = None
                if family == "sql_pair":
                    p_t, p_f = payloads
                else:
                    p_t = payloads[0]

                def _mk(p):
                    if slot_kind == "json":
                        return _render_json_message(shape, slot, p)
                    return p

                if not budget.allow(channel_sends, slot_sends):
                    break
                # V4.3.2b (live-caught on DVWS): ONE CONNECTION PER FAMILY.
                # The Ratchet server CLOSES the connection when a payload
                # yields a null reply (eval('return ; echo X;') returns null
                # -> send(null) -> onError -> close) and single-threaded
                # shell_exec stalls (ping on an unresolvable host) queue
                # every later reply behind the stall — a per-channel client
                # went permanently deaf after the first such family. A
                # fresh connection per family isolates both failure modes.
                client.close()
                client = WsClient(url, timeout=min(engine.timeout, 6.0))
                if not client.connect():
                    engine.connections += 1
                    _record("websocket/battery", url, "UNTESTABLE",
                            "channel refused a battery-family handshake "
                            "mid-sweep (server may rate-limit new "
                            "connections)",
                            provenance="websocket:battery-connect")
                    break
                engine.connections += 1
                r_t = _send_and_recv(client, _mk(p_t),
                                     8.0 if family == "cmdi" else 3.0)
                budget.scan_sends += 1; channel_sends += 1; slot_sends += 1
                r_f = None
                if p_f is not None:
                    if not budget.allow(channel_sends, slot_sends):
                        break
                    r_f = _send_and_recv(client, _mk(p_f))
                    budget.scan_sends += 1; channel_sends += 1; slot_sends += 1

                ev_prefix = f"slot={slot} family={family}"
                # ---- family oracles
                if family == "sql_pair":
                    ok, detail = _pair_differential(r_t, r_f, p_t, p_f)
                    if ok:
                        # verification round on a FRESH connection
                        v2 = WsClient(url, timeout=min(engine.timeout, 6.0))
                        if v2.connect():
                            engine.connections += 1
                            r2_t = _send_and_recv(v2, _mk(p_t))
                            r2_f = _send_and_recv(v2, _mk(p_f))
                            v2.close()
                            stable = (r2_t is not None and r2_f is not None
                                      and r2_t == r_t and r2_f == r_f)
                            ev = [Evidence(
                                "ws_pair_differential",
                                f"{ev_prefix}: TRUE({p_t[:40]!r}) -> "
                                f"{(r_t or '')[:90]!r} | FALSE({p_f[:40]!r}) -> "
                                f"{(r_f or '')[:90]!r}", ""),
                                Evidence(
                                "ws_pair_replay",
                                f"fresh-connection replay: TRUE -> "
                                f"{(r2_t or '')[:90]!r} | FALSE -> "
                                f"{(r2_f or '')[:90]!r} (byte-stable: {stable})",
                                "")]
                            f_ = _verified(
                                family, "sql_injection", Severity.CRITICAL,
                                url, slot, ev,
                                "boolean pair differential reproduced on a "
                                "fresh connection (2-round, echo-excluded)",
                                stable, 0.95, "ws:battery-pair-2round",
                                state_before=f"message slot '{slot}' with "
                                             f"benign value",
                                state_after=f"TRUE payload altered the reply "
                                            f"({len(r_t or '')}B vs "
                                            f"{len(r_f or '')}B)")
                            _emit(f_)
                        else:
                            v2.close()
                    continue

                if family == "sql_error":
                    sig = _sql_sig(r_t)
                    if sig:
                        v2 = WsClient(url, timeout=min(engine.timeout, 6.0))
                        sig2 = None
                        if v2.connect():
                            engine.connections += 1
                            r2 = _send_and_recv(v2, _mk(p_t))
                            v2.close()
                            sig2 = _sql_sig(r2)
                        ev = [Evidence(
                            "ws_db_error_signature",
                            f"{ev_prefix}: quote probe -> DB-error signature "
                            f"'{sig}' in reply {(r_t or '')[:110]!r}", ""),
                            Evidence(
                            "ws_db_error_replay",
                            f"fresh-connection replay signature: '{sig2}'",
                            "")]
                        f_ = _verified(
                            family, "sql_injection", Severity.CRITICAL,
                            url, slot, ev,
                            "DB-error signature reproduced on a fresh "
                            "connection (2-round)",
                            bool(sig2), 0.95, "ws:battery-dberr-2round",
                            state_before="quote probe in message slot",
                            state_after=f"DB error disclosed: {sig}")
                        _emit(f_)
                    continue

                if family == "cmdi":
                    if r_t and canary in r_t and p_t not in r_t:
                        v2 = WsClient(url, timeout=min(engine.timeout, 8.0))
                        r2 = None
                        if v2.connect():
                            engine.connections += 1
                            r2 = _send_and_recv(v2, _mk(p_t), 8.0)
                            v2.close()
                        ok2 = bool(r2 and canary in r2 and p_t not in r2)
                        ev = [Evidence(
                            "ws_cmdi_canary",
                            f"{ev_prefix}: '{p_t}' -> command output contains "
                            f"fresh canary: {(r_t or '')[:110]!r}", ""),
                            Evidence(
                            "ws_cmdi_replay",
                            f"fresh-connection replay: canary "
                            f"{'reproduced' if ok2 else 'NOT reproduced'}: "
                            f"{(r2 or '')[:110]!r}", "")]
                        f_ = _verified(
                            family, "command_injection", Severity.CRITICAL,
                            url, slot, ev,
                            "OS-command canary reproduced on a fresh "
                            "connection (2-round, echo-excluded)",
                            ok2, 0.95, "ws:battery-cmdi-2round",
                            state_before="message slot carried a shell "
                                         "metacharacter payload",
                            state_after=f"canary {canary} printed by the "
                                        f"executed command")
                        _emit(f_)
                    continue

                if family in ("ssti", "code_injection"):
                    want = "42"
                    if r_t and want in r_t and p_t not in r_t:
                        v2 = WsClient(url, timeout=min(engine.timeout, 6.0))
                        r2 = None
                        if v2.connect():
                            engine.connections += 1
                            r2 = _send_and_recv(v2, _mk(p_t))
                            v2.close()
                        ok2 = bool(r2 and want in r2 and p_t not in r2)
                        vtype = ("ssti" if family == "ssti"
                                 else "code_injection")
                        label = ("template expression {{40+2}} evaluated to 42"
                                 if family == "ssti"
                                 else "code expression 20+22 evaluated to 42")
                        ev = [Evidence(
                            "ws_eval_oracle",
                            f"{ev_prefix}: '{p_t}' -> {label}: "
                            f"{(r_t or '')[:110]!r}", ""),
                            Evidence(
                            "ws_eval_replay",
                            f"fresh-connection replay: "
                            f"{'reproduced' if ok2 else 'NOT reproduced'}: "
                            f"{(r2 or '')[:110]!r}", "")]
                        f_ = _verified(
                            family, vtype, Severity.CRITICAL, url, slot, ev,
                            f"expression-evaluation oracle reproduced on a "
                            f"fresh connection (2-round, echo-excluded)",
                            ok2, 0.95, f"ws:battery-{family}-2round",
                            state_before="message slot carried an arithmetic "
                                         "expression",
                            state_after="expression evaluated server-side")
                        _emit(f_)
                    continue

                if family == "lfi":
                    sig = None
                    if r_t:
                        if _RE_PASSWD_LINE.search(r_t):
                            sig = "/etc/passwd content (root:x:0:0:)"
                        elif _RE_WIN_INI.search(r_t):
                            sig = "win.ini content ([fonts]/[files])"
                    if sig and p_t not in r_t:
                        v2 = WsClient(url, timeout=min(engine.timeout, 6.0))
                        sig2 = None
                        if v2.connect():
                            engine.connections += 1
                            r2 = _send_and_recv(v2, _mk(p_t))
                            v2.close()
                            if r2:
                                if _RE_PASSWD_LINE.search(r2):
                                    sig2 = "passwd"
                                elif _RE_WIN_INI.search(r2):
                                    sig2 = "win.ini"
                        ok2 = bool(sig2)
                        ev = [Evidence(
                            "ws_file_read",
                            f"{ev_prefix}: '{p_t}' -> local file content in "
                            f"reply ({sig}): {(r_t or '')[:130]!r}", ""),
                            Evidence(
                            "ws_file_read_replay",
                            f"fresh-connection replay: "
                            f"{'signature reproduced' if ok2 else 'NOT reproduced'}",
                            "")]
                        f_ = _verified(
                            family, "path_traversal", Severity.HIGH,
                            url, slot, ev,
                            "arbitrary local file read reproduced on a fresh "
                            "connection (2-round, echo-excluded)",
                            ok2, 0.95, "ws:battery-lfi-2round",
                            state_before="message slot carried a file path",
                            state_after=f"server read {sig}")
                        _emit(f_)
                    continue

                if family == "xss_reflected":
                    if r_t and p_t in r_t:
                        v2 = WsClient(url, timeout=min(engine.timeout, 6.0))
                        r2 = None
                        if v2.connect():
                            engine.connections += 1
                            r2 = _send_and_recv(v2, _mk(p_t))
                            v2.close()
                        ok2 = bool(r2 and p_t in r2)
                        ev = [Evidence(
                            "ws_xss_reflection",
                            f"{ev_prefix}: attack-shaped payload reflected "
                            f"verbatim (tag+event handler intact): "
                            f"{(r_t or '')[:130]!r}", ""),
                            Evidence(
                            "ws_xss_reflection_replay",
                            f"fresh-connection replay: "
                            f"{'reflected again' if ok2 else 'NOT reflected'}",
                            "")]
                        f_ = _verified(
                            family, "xss_reflected", Severity.HIGH,
                            url, slot, ev,
                            "attack-shaped reflection reproduced on a fresh "
                            "connection (2-round) — the page renders WS "
                            "replies into the DOM (innerHTML sink pattern)",
                            ok2, 0.9, "ws:battery-xss-2round",
                            state_before="benign message",
                            state_after=f"HTML injected into the reply: "
                                        f"{p_t[:60]}")
                        _emit(f_)
                    continue

        # ---- stored-XSS flow: additive write channel + read channel.
        # (Reserved-budget section: the family sweep may consume the whole
        # per-channel allowance on multi-slot channels — post-comments has
        # name+comment — so the write->read roundtrip draws from the SCAN
        # budget with a tail reserve instead of the channel allowance.)
        path_l = path.lower()
        is_write = any(w in path_l for w in WRITE_CHANNEL_RE_WORDS)
        if is_write and shapes \
                and budget.scan_sends < MAX_SENDS_PER_SCAN - 12:
            read_urls = [c["url"] for c in candidates
                         if any(w in c["url"].split("/", 3)[-1].lower()
                                for w in READ_CHANNEL_RE_WORDS)
                         and not ws_destructive_path(c["url"])]
            read_triggers = []
            for ru in read_urls[:2]:
                trig = next((b.get("value") for b in (bindings.get(ru) or [])
                             if b.get("kind") == "literal"), "{}")
                read_triggers.append((ru, trig))
            if read_triggers:
                mk = _canary(rand)
                marker = f"<b id={mk}>s</b>"
                wshape = shapes[0]
                ckey = next((k for k in wshape["keys"]
                             if k in ("comment", "message", "text", "body",
                                      "content")),
                            list(wshape["keys"])[-1])
                # fresh connection for the write->read roundtrip (the family
                # sweep's last connection may be dead — same V4.3.2b cause)
                client.close()
                client = WsClient(url, timeout=min(engine.timeout, 6.0))
                post = None
                if client.connect():
                    engine.connections += 1
                    post = _send_and_recv(
                        client, _render_json_message(wshape, ckey, marker))
                budget.scan_sends += 1; channel_sends += 1
                for ru, trig in read_triggers:
                    rc = WsClient(ru, timeout=min(engine.timeout, 6.0))
                    if not rc.connect():
                        rc.close()
                        continue
                    engine.connections += 1
                    rd = _send_and_recv(rc, trig)
                    rc.close()
                    budget.scan_sends += 1
                    if rd and mk in rd:
                        # verification: FRESH marker + fresh round
                        mk2 = _canary(rand)
                        marker2 = f"<b id={mk2}>s</b>"
                        w2 = WsClient(url, timeout=min(engine.timeout, 6.0))
                        r2v = None
                        if w2.connect():
                            engine.connections += 1
                            _send_and_recv(w2, _render_json_message(
                                wshape, ckey, marker2))
                            rc2 = WsClient(ru, timeout=min(engine.timeout, 6.0))
                            if rc2.connect():
                                engine.connections += 1
                                r2v = _send_and_recv(rc2, trig)
                                rc2.close()
                            w2.close()
                        ok2 = bool(r2v and mk2 in r2v)
                        ev = [Evidence(
                            "ws_stored_roundtrip",
                            f"marker {mk} posted on {url} (slot '{ckey}') "
                            f"then read back on {ru}: "
                            f"{(rd or '')[:130]!r}", ""),
                            Evidence(
                            "ws_stored_replay",
                            f"fresh marker {mk2} roundtrip: "
                            f"{'reproduced' if ok2 else 'NOT reproduced'}",
                            "")]
                        f_ = _verified(
                            "xss_stored", "xss_stored", Severity.HIGH,
                            url, ckey, ev,
                            "stored payload survives the write->read cycle "
                            "and is served back (2-round, fresh markers)",
                            ok2, 0.9, "ws:battery-stored-2round",
                            state_before="no marker in storage",
                            state_after=f"marker persisted and served on {ru}")
                        _emit(f_)
                        break

        client.close()

    battery_stats["sends"] = budget.scan_sends
    stats["tests"] = stats.get("tests", 0) + budget.scan_sends
    return findings

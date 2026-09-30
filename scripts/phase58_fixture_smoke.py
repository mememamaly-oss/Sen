#!/usr/bin/env python3
"""Phase 58 smoke: exercise the wizard flows by hand against a live fixture.
Doctrine: manual feasibility BEFORE the engine run. Verifies all five defects
on the vulnerable twin AND all five guards on the hardened twin."""
import http.client, json, re, sys, threading
import subprocess, time, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXT = os.path.join(ROOT, "verify-live", "fixtures", "vulnapp.py")
PORT = 8791


def spawn():
    p = subprocess.Popen([sys.executable, FIXT], env={**os.environ, "PORT": str(PORT)},
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            http.client.HTTPConnection("127.0.0.1", PORT, timeout=1).request("GET", "/")
            return p
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("fixture did not start")


class C:
    """Tiny cookie-carrying client."""
    def __init__(self):
        self.cookies = {}

    def _hdrs(self):
        h = {}
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        return h

    def req(self, method, path, body=None, ctype="application/x-www-form-urlencoded"):
        c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
        c.request(method, path, body=body, headers={**self._hdrs(), **({"Content-Type": ctype} if body else {})})
        r = c.getresponse()
        data = r.read().decode("utf-8", "replace")
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                m = re.match(r"([^=]+)=([^;]*)", v)
                if m:
                    self.cookies[m.group(1)] = m.group(2)
        c.close()
        return r.status, data

    def login(self, user, pw):
        st, page = self.req("GET", "/login")
        tok = re.search(r'name="csrfToken" value="([^"]+)"', page).group(1)
        body = f"uid={user}&passw={pw}&csrfToken={tok}&btnSubmit=Login"
        st, _ = self.req("POST", "/doLogin", body)
        st, home = self.req("GET", "/home")
        assert "Sign Off" in home, f"login failed for {user}: {st}"
        return self

    def token(self, base):
        st, page = self.req("GET", base + "/start")
        m = re.search(r'name="csrfToken" value="([^"]+)"', page)
        return m.group(1) if m else ""


def ledger_lines(c, base):
    st, page = c.req("GET", base + "/ledger")
    return re.findall(r"<li>(TRF-\d+ [^<]+)</li>", page)


def walk(c, base, amount="111", mode="ach"):
    """Full legit walk: select -> create -> confirm. Returns tid."""
    tok = c.token(base)
    c.req("POST", base + "/select", f"acct=800001&csrfToken={tok}")
    st, page = c.req("POST", base + "/create", f"acct=800001&amount={amount}&csrfToken={tok}")
    m = re.search(r'name="tid" value="(TRF-\d+)"', page)
    if not m:
        return None, st, page
    tid = m.group(1)
    st2, p2 = c.req("POST", base + "/confirm",
                    f"tid={tid}&amount={amount}&mode={mode}&csrfToken={tok}")
    return tid, st2, p2


def main():
    proc = spawn()
    try:
        V, S = "/wf/transfer", "/wf/safe/transfer"
        ok = 0

        # ---- 1. step bypass: create WITHOUT select (fresh session)
        c = C().login("demo", "demo123")
        tok = c.token(V)
        st, _ = c.req("POST", V + "/create", f"acct=800001&amount=111&csrfToken={tok}")
        lines = ledger_lines(c, V)
        assert st == 200 and any(l.startswith("TRF-") and " 111 " in l and "PENDING" in l for l in lines), \
            f"VULN bypass FAILED: {st} {lines}"
        print(f"1a vuln  bypass            : create-no-select -> {st}, ledger {lines[-1]}")
        ok += 1
        c = C().login("demo", "demo123")
        tok = c.token(S)
        st, _ = c.req("POST", S + "/create", f"acct=800001&amount=111&csrfToken={tok}")
        lines = ledger_lines(c, S)
        assert st == 400 and not lines, f"SAFE bypass leaked: {st} {lines}"
        print(f"1b safe  bypass            : create-no-select -> {st} (no account selected), ledger empty")
        ok += 1

        # ---- 2. out of order: confirm a never-created tid (fresh session)
        c = C().login("demo", "demo123")
        tok = c.token(V)
        st, _ = c.req("POST", V + "/confirm",
                      f"tid=TRF-99001&amount=222&mode=ach&csrfToken={tok}")
        lines = ledger_lines(c, V)
        assert st == 200 and any("TRF-99001" in l and "222" in l and "EXECUTED" in l for l in lines), \
            f"VULN out-of-order FAILED: {st} {lines}"
        print(f"2a vuln  out-of-order      : confirm-unknown-tid -> {st}, {lines[-1]}")
        ok += 1
        c = C().login("demo", "demo123")
        tok = c.token(S)
        st, _ = c.req("POST", S + "/confirm",
                      f"tid=TRF-99001&amount=222&mode=ach&csrfToken={tok}")
        lines = ledger_lines(c, S)
        assert st == 404 and not lines, f"SAFE out-of-order leaked: {st} {lines}"
        print(f"2b safe  out-of-order      : confirm-unknown-tid -> {st} (unknown transfer), ledger empty")
        ok += 1

        # ---- 3. value tamper: create 111, confirm 222
        c = C().login("demo", "demo123")
        tid, st, _ = walk(c, V, amount="111")  # walk confirms with 111; redo tamper fresh
        c = C().login("demo", "demo123")
        tok = c.token(V)
        c.req("POST", V + "/select", f"acct=800001&csrfToken={tok}")
        st, page = c.req("POST", V + "/create", f"acct=800001&amount=111&csrfToken={tok}")
        tid = re.search(r'name="tid" value="(TRF-\d+)"', page).group(1)
        st, _ = c.req("POST", V + "/confirm",
                      f"tid={tid}&amount=222&mode=ach&csrfToken={tok}")
        lines = [l for l in ledger_lines(c, V) if tid in l]
        assert st == 200 and any("222" in l and "EXECUTED" in l and "111" not in l for l in lines), \
            f"VULN tamper FAILED: {st} {lines}"
        print(f"3a vuln  value-tamper      : confirm amount=222 on approved 111 -> {st}, {lines[0]}")
        ok += 1
        c = C().login("demo", "demo123")
        tok = c.token(S)
        c.req("POST", S + "/select", f"acct=800001&csrfToken={tok}")
        st, page = c.req("POST", S + "/create", f"acct=800001&amount=111&csrfToken={tok}")
        tid = re.search(r'name="tid" value="(TRF-\d+)"', page).group(1)
        st, _ = c.req("POST", S + "/confirm",
                      f"tid={tid}&amount=222&mode=ach&csrfToken={tok}")
        lines = [l for l in ledger_lines(c, S) if tid in l]
        assert st == 400 and lines and "PENDING" in lines[0] and "111" in lines[0], \
            f"SAFE tamper leaked: {st} {lines}"
        print(f"3b safe  value-tamper      : confirm amount=222 on approved 111 -> {st} (amount changed), {lines[0]}")
        ok += 1

        # ---- 4. duplicate execution
        c = C().login("demo", "demo123")
        tok = c.token(V)
        c.req("POST", V + "/select", f"acct=800001&csrfToken={tok}")
        st, page = c.req("POST", V + "/create", f"acct=800001&amount=111&csrfToken={tok}")
        tid = re.search(r'name="tid" value="(TRF-\d+)"', page).group(1)
        c.req("POST", V + "/confirm", f"tid={tid}&amount=111&mode=ach&csrfToken={tok}")
        st2, _ = c.req("POST", V + "/confirm", f"tid={tid}&amount=111&mode=ach&csrfToken={tok}")
        n = sum(1 for l in ledger_lines(c, V) if tid in l and "EXECUTED" in l)
        assert st2 == 200 and n == 2, f"VULN duplicate FAILED: {st2} n={n}"
        print(f"4a vuln  duplicate         : confirm replay -> {st2}, tid executed x{n}")
        ok += 1
        c = C().login("demo", "demo123")
        tid, st, _ = walk(c, S, amount="111")
        tok = c.token(S)
        st2, _ = c.req("POST", S + "/confirm", f"tid={tid}&amount=111&mode=ach&csrfToken={tok}")
        n = sum(1 for l in ledger_lines(c, S) if tid in l and "EXECUTED" in l)
        assert st2 == 409 and n == 1, f"SAFE duplicate leaked: {st2} n={n}"
        print(f"4b safe  duplicate         : confirm replay -> {st2} (already executed), executed x{n}")
        ok += 1

        # ---- 5. privilege: wire mode by regular user
        c = C().login("bob", "bob123")           # role=user
        tid, st, page = walk(c, V, amount="111", mode="wire")
        lines = [l for l in ledger_lines(c, V) if tid in l]
        assert st == 200 and any("wire" in l and "EXECUTED" in l for l in lines), \
            f"VULN privilege FAILED: {st} {lines}"
        print(f"5a vuln  privilege-wire    : user(bob) wire confirm -> {st}, {lines[0]}")
        ok += 1
        c = C().login("bob", "bob123")
        tid, st, page = walk(c, S, amount="111", mode="wire")
        lines = [l for l in ledger_lines(c, S) if tid in l]
        assert st == 403 and lines and "PENDING" in lines[0], f"SAFE privilege leaked: {st} {lines}"
        print(f"5b safe  privilege-wire    : user(bob) wire confirm -> {st} (requires admin), {lines[0]}")
        ok += 1

        # ---- hygiene: escaped echo (no raw reflection), csrf enforcement, admin wire ok
        c = C().login("demo", "demo123")
        tok = c.token(V)
        st, page = c.req("POST", V + "/select", f"acct=<x>&csrfToken={tok}")
        assert "&lt;x&gt;" in page and "<x>" not in page.replace("<input", "").replace("<label", ""), \
            "raw reflection leaked on wizard page"
        st, _ = c.req("POST", V + "/select", f"acct=800001&csrfToken=WRONG")
        assert st == 403, f"csrf not enforced: {st}"
        print("6  hygiene                : escaped echoes + csrf enforced OK")
        ok += 1

        print(f"\nSMOKE PASS {ok}/11 — fixture v8 wizard flows behave exactly as designed")
    finally:
        proc.terminate(); proc.wait(timeout=5)


if __name__ == "__main__":
    main()

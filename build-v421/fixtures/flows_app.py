#!/usr/bin/env python3
"""SENTINEL v4.1.0 fixture — Workflow Branching & State Intelligence (flows app).

The dedicated ground truth for the four v4.1.0 workflow attacks that vulnapp
(v10) structurally cannot carry (its only select option beyond the default is
privilege-labeled, it has no approve-vocabulary step and no rollback-vocabulary
path — which is exactly why the benchmark stays F1=1.000 while this fixture
proves the new battery):

    flow shape (both twins, identical wire shape):
      GET  {base}/start       -> eligibility form: select plan
      POST {base}/eligibility -> sets the session plan draft -> create form
      POST {base}/create      -> mints APP-nnnn {plan, amount, state=draft}
                                 (hidden plan field carries the branch choice)
                                 landing: approve form + rollback form
      POST {base}/approve     -> state=approved              (in-chain step)
      POST {base}/execute     -> state=executed (vulnerable) / guards (safe)
      POST {base}/rollback    -> state=draft again (reopens the object)
      GET  {base}/status      -> the STATE ORACLE: one line per application

    branch vocabulary:
      plan=standard  default, open branch (the walked chain)
      plan=premium   label 'Premium express (premium members only)' —
                     RESTRICTION vocabulary (not privilege vocabulary: the
                     unauthorized-branch attack, distinct from privilege)

GROUND TRUTH (per defect class):

  defect                        | /flows/loan (vulnerable)          | /flows/safe/loan
  ------------------------------+-----------------------------------+--------------------------
  9  create with forged branch  | POSTed plan trusted (no draft     | 400 "complete eligibility
     business_logic_            | check) — premium object minted    | first"; plan from draft
     branch_bypass              | without the eligibility step      |
  10 premium branch by basic    | no membership check on premium    | 403 "premium plans require
     business_logic_            | role — basic member executes      | premium membership"
     unauthorized_branch        | premium applications              |
  11 execute without approval   | no approved-state check on        | 409 "application not
     business_logic_            | execute — never-approved object   | approved"
     approval_bypass            | executes                          |
  12 rollback reopens values    | rollback returns the object to    | 409 "rolled-back
     business_logic_            | draft and execute re-trusts the   | application must be
     rollback_abuse             | POSTed amount (tamper canary      | re-approved"
                                 | executes)                         |
  1  create without eligibility | (same missing draft check as #9)  | 400 (same guard)
     business_logic_step_bypass |                                   |
  3  amount tamper at execute   | POSTed amount overrides the       | 400 "amount changed
     business_logic_value_tamper| approved one                      | since approval"
  4  duplicate execute          | executed apps execute again       | 409 "already executed"
     business_logic_duplicate_  | (no one-shot consumption)         |
     execution                  |                                   |
  2  execute synthetic id       | 404 "unknown application" (both   | 404
     business_logic_out_of_     | twins — object must exist)        |
     order                      |                                   |
  5/6/7/8 privilege / cross-*   | structurally absent (no           | -
     (vulnapp's domain)         | privilege option, no shared       |
                                 | store, no cancel path, no         |
                                 | foreign objects)                  |

Honest-negative discipline: the safe twin is the SAME wizard with four
server-side guards; every attack that fires on the vulnerable flow must
produce a no_proof verdict on the safe one.
"""
import http.cookies
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

FLOWS_GROUND_TRUTH = {
    "/flows/loan": [
        "business_logic_branch_bypass",
        "business_logic_unauthorized_branch",
        "business_logic_approval_bypass",
        "business_logic_rollback_abuse",
        "business_logic_step_bypass",
        "business_logic_value_tamper",
        "business_logic_duplicate_execution",
        # the rollback path doubles as a state-machine defect: a rolled-back
        # (draft) object executes anyway — CANCEL_RE matches /rollback, so the
        # cross-state attack legitimately fires on this flow too
        "business_logic_cross_state_execution",
    ],
    "/flows/safe/loan": [],          # hardened twin: every attack a no_proof
}

ACCOUNTS = {                          # username -> (password, role, premium)
    "alice": ("alice123", "user", False),
    "bob": ("bob123", "user", False),
    "root": ("root123", "admin", True),
}

_APPS: dict[tuple, dict] = {}         # (base, sid) -> {"seq": n, "items": {}}
_SESSIONS: dict[str, dict] = {}
_seq_lock = threading.Lock()


def _state(base: str, sid: str) -> dict:
    with _seq_lock:
        return _APPS.setdefault((base, sid), {"seq": 0, "items": {}})


def _esc(v) -> str:
    return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, headers=None):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        for h, v in (headers or []):
            self.send_header(h, v)
        self.end_headers()
        self.wfile.write(b)

    # ------------------------------------------------------------ session
    def _sid(self) -> str:
        c = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        if "sid" in c:
            return c["sid"].value
        return ""

    def _sess(self) -> dict:
        sid = self._sid()
        return _SESSIONS.get(sid, {"user": "", "role": "anonymous", "csrf": ""})

    def _authed(self) -> bool:
        return bool(self._sess().get("user"))

    # ------------------------------------------------------------ GET
    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/" or path == "/login":
            body = ('<form action="/login" method="POST">'
                    '<input type="text" name="username">'
                    '<input type="password" name="password">'
                    '<button type="submit">Sign in</button></form>')
            return self._send(200, body)
        if path == "/home":
            s = self._sess()
            if not s.get("user"):
                return self._send(401, "<html><body>login required</body></html>")
            return self._send(200, f"<h1>Welcome {s['user']}</h1>"
                              '<p><a href="/flows/loan/start">loan application</a> - '
                              '<a href="/flows/loan/status">loan status</a> - '
                              '<a href="/flows/safe/loan/start">safe loan</a> - '
                              '<a href="/flows/safe/loan/status">safe status</a></p>')
        if path.endswith("/start"):
            base = path.rsplit("/", 1)[0]
            s = self._sess()
            if not s.get("user"):
                return self._send(401, "<html><body>login required</body></html>")
            body = (f'<form action="{base}/eligibility" method="POST">'
                    f'<input type="hidden" name="csrfToken" value="{s["csrf"]}">'
                    '<label>Plan</label>'
                    '<select name="plan">'
                    '<option value="standard">Standard processing</option>'
                    '<option value="premium">Premium express (premium members only)</option>'
                    '</select>'
                    '<button type="submit">Check eligibility</button></form>')
            return self._send(200, f"<h2>Loan application - step 1 of 4: eligibility</h2>{body}"
                              f'<p><a href="{base}/status">application status</a></p>')
        if path.endswith("/status"):
            base = path.rsplit("/", 1)[0]
            s = self._sess()
            if not s.get("user"):
                return self._send(401, "<html><body>login required</body></html>")
            st = _state(base, self._sid())
            lines = []
            for app in sorted(st["items"]):
                it = st["items"][app]
                for _ in range(it["executions"]):
                    lines.append(f"<li>{app} {it['plan']} {it['amount']} EXECUTED</li>")
                if it["executions"] == 0:
                    lines.append(f"<li>{app} {it['plan']} {it['amount']} "
                                 f"{it['state'].upper()}</li>")
            listing = "<ul>" + ("\n".join(lines) if lines else
                                "<li>No applications yet.</li>") + "</ul>"
            return self._send(200, f"<h2>Application status</h2>{listing}"
                              f'<p><a href="{base}/start">new application</a></p>')
        return self._send(404, "<html><body>not found</body></html>")

    # ------------------------------------------------------------ POST
    def do_POST(self):
        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length", 0) or 0)
        form = parse_qs(self.rfile.read(length).decode() if length else "")
        if path == "/login":
            user = form.get("username", [""])[0]
            pw = form.get("password", [""])[0]
            if ACCOUNTS.get(user, ("",))[0] == pw and user:
                import secrets as _secrets
                sid = _secrets.token_hex(12)
                _SESSIONS[sid] = {"user": user, "role": ACCOUNTS[user][1],
                                  "premium": ACCOUNTS[user][2],
                                  "csrf": _secrets.token_hex(8)}
                return self._send(302, "", [("Location", "/home"),
                                            ("Set-Cookie", f"sid={sid}; Path=/")])
            return self._send(401, "<html><body>bad credentials</body></html>")
        s = self._sess()
        if not s.get("user"):
            return self._send(401, "<html><body>login required</body></html>")
        base = path.rsplit("/", 1)[0]
        step = path.rsplit("/", 1)[1]
        safe = "/safe/" in base
        st = _state(base, self._sid())
        csrf = form.get("csrfToken", [""])[0]
        if csrf != s["csrf"]:
            return self._send(403, "<html><body>bad csrf token</body></html>")

        def _amount(raw):
            try:
                n = int(str(raw).strip())
            except (TypeError, ValueError):
                return None
            return n if 1 <= n <= 999999 else None

        if step == "eligibility":
            plan = form.get("plan", ["standard"])[0]
            if plan not in ("standard", "premium"):
                return self._send(400, "<html><body>unknown plan</body></html>")
            if safe and plan == "premium" and not s.get("premium"):
                return self._send(403, "<html><body>premium plans require "
                                       "premium membership</body></html>")
            s["draft" + base] = plan
            body = (f'<form action="{base}/create" method="POST">'
                    f'<input type="hidden" name="csrfToken" value="{s["csrf"]}">'
                    f'<input type="hidden" name="plan" value="{_esc(plan)}">'
                    '<label>Amount</label><input type="text" name="amount" value="">'
                    '<button type="submit">Create application</button></form>')
            return self._send(200, f"<h2>Loan - step 2 of 4: amount (plan {plan})</h2>{body}")

        if step == "create":
            amount = _amount(form.get("amount", [""])[0])
            if amount is None:
                return self._send(400, "<html><body>invalid amount</body></html>")
            plan = form.get("plan", ["standard"])[0]
            draft = s.get("draft" + base)
            if safe:
                if not draft:
                    return self._send(400, "<html><body>no plan selected - "
                                           "complete eligibility first</body></html>")
                plan = draft                       # server-side draft wins
            with _seq_lock:
                st["seq"] += 1
                app = "APP-%04d" % st["seq"]
            st["items"][app] = {"plan": plan, "amount": amount,
                                "state": "draft", "executions": 0}
            body = (f'<form action="{base}/approve" method="POST">'
                    f'<input type="hidden" name="csrfToken" value="{s["csrf"]}">'
                    f'<input type="hidden" name="appid" value="{app}">'
                    f'<input type="hidden" name="amount" value="{amount}">'
                    '<button type="submit">Approve application</button></form>'
                    f'<form action="{base}/rollback" method="POST">'
                    f'<input type="hidden" name="csrfToken" value="{s["csrf"]}">'
                    f'<input type="hidden" name="appid" value="{app}">'
                    '<button type="submit">Rollback to draft</button></form>')
            return self._send(200, f"<h2>Loan - step 3 of 4: approve {app}</h2>{body}")

        if step in ("approve", "rollback"):
            app = form.get("appid", [""])[0]
            it = st["items"].get(app)
            if it is None:
                return self._send(404, "<html><body>unknown application</body></html>")
            if step == "approve":
                if safe and it["state"] != "draft":
                    return self._send(409, "<html><body>application not in "
                                           "draft state</body></html>")
                it["state"] = "approved"
            else:
                it["state"] = "draft"              # rollback reopens the object
            nxt = "execute" if step == "approve" else "approve"
            body = (f'<form action="{base}/{nxt}" method="POST">'
                    f'<input type="hidden" name="csrfToken" value="{s["csrf"]}">'
                    f'<input type="hidden" name="appid" value="{app}">'
                    f'<input type="hidden" name="amount" value="{it["amount"]}">'
                    f'<button type="submit">{"Execute" if step == "approve" else "Re-approve"}'
                    '</button></form>')
            title = "approved" if step == "approve" else "rolled back to draft"
            return self._send(200, f"<h2>Loan: {app} {title}</h2>{body}")

        if step == "execute":
            app = form.get("appid", [""])[0]
            it = st["items"].get(app)
            if it is None:
                return self._send(404, "<html><body>unknown application</body></html>")
            amount = _amount(form.get("amount", [""])[0])
            if safe:
                if it["state"] != "approved":
                    return self._send(409, "<html><body>application not approved"
                                           + ("; rolled-back application must be"
                                              " re-approved" if it["state"] == "draft"
                                              else "") + "</body></html>")
                if amount is not None and amount != it["amount"]:
                    return self._send(400, "<html><body>amount changed since "
                                           "approval</body></html>")
                if it["executions"]:
                    return self._send(409, "<html><body>already executed</body></html>")
            if amount is not None:
                it["amount"] = amount              # vulnerable: re-trusts POSTed value
            it["executions"] += 1
            it["state"] = "executed"
            return self._send(200, f"<h2>Loan: {app} executed for {it['amount']}</h2>"
                              f'<p><a href="{base}/status">status</a></p>')
        return self._send(404, "<html><body>not found</body></html>")


def serve(port: int = 0) -> tuple[str, ThreadingHTTPServer]:
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return f"http://127.0.0.1:{srv.server_address[1]}", srv

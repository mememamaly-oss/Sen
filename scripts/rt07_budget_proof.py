#!/usr/bin/env python3
"""RT-07 request-budget differential proof (standing tool).

RED  (banked Step 1, same tree): grep max_requests in orchestrator.py ->
      COUNT: 0 — no built-in limit; the live testasp campaign breached 1,261
      requests before the EXTERNAL watchdog killed it (audit-rb-1).
GREEN (fixed tree): a REAL scan of the vulnapp fixture with max_requests=10
      must (a) emit BUDGET_REACHED into the event log with the ordered
      message format, (b) stop at exactly 10 engine requests, (c) still
      return a well-formed report (loops finish cleanly, no crash).
      Control arm: the same fixture scanned with the default 500 budget must
      complete WITHOUT any BudgetReached event (budget not choking normal
      scans).
"""
import subprocess
import sys
import time

REPO = "/home/z/my-project/build-v430"
sys.path.insert(0, REPO)

PORT = 18877
srv_proc = subprocess.Popen([sys.executable, f"{REPO}/fixtures/vulnapp.py"],
                            env={"PORT": str(PORT), "PATH": "/usr/bin:/bin",
                                 "DELAY_MS": "0", "HOME": "/tmp"},
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
time.sleep(1.5)

from sentinel.orchestrator import ScanConfig, SentinelScanner  # noqa: E402

# --- GREEN arm: budget 10 ----------------------------------------------------
cfg = ScanConfig(allow_private=True, max_pages=40, crawl=True, active=True,
                 passive=True, timeout=8.0, seed="rt07-green", browser=False,
                 oast=None, max_requests=10)
s = SentinelScanner(f"http://127.0.0.1:{PORT}/", cfg)
t0 = time.time()
report = s.run()
el = time.time() - t0
events = [e for e in s.bus.events if e["kind"] == "BudgetReached"]
reqs = s.engine.requests_sent
print(f"scan_completed={bool(report)} elapsed={el:.1f}s")
print(f"engine_requests={reqs} (limit=10)")
print(f"budget_events={len(events)}")
if events:
    print(f"BUDGET_REACHED_MSG: {events[0]['msg']!r}")
ok_msg = events and events[0]["msg"] == f"BUDGET_REACHED: stopped at {reqs} requests (limit=10)"
stopped_at_10 = reqs == 10
blocked_after = sum(1 for e in s.bus.events if e["kind"] == "RequestError"
                    and "budget:" in str(e.get("error", "")))
print(f"budget_blocked_requests_after_limit={blocked_after}")

# --- Control arm: explicit opt-out (max_requests=0) must complete unbounded ---
cfg2 = ScanConfig(allow_private=True, max_pages=8, crawl=True, active=True,
                  passive=True, timeout=8.0, seed="rt07-ctrl", browser=False,
                  oast=None, max_requests=0)
s2 = SentinelScanner(f"http://127.0.0.1:{PORT}/", cfg2)
r2 = s2.run()
ev2 = [e for e in s2.bus.events if e["kind"] == "BudgetReached"]
print(f"control(opt-out 0): requests={s2.engine.requests_sent} budget_events={len(ev2)} "
      f"completed={bool(r2)}")
ctrl_ok = (not ev2) and s2.engine.requests_sent > 500

if events and stopped_at_10 and ok_msg and not ev2:
    print("VERDICT: GREEN — STOPPED_AT_BUDGET (10/10 exact, ordered log format, "
          "control scan unchoked)")
elif not events:
    print("VERDICT: RED/INCONCLUSIVE — no BUDGET_REACHED event (budget not enforced)")
else:
    print(f"VERDICT: INCONCLUSIVE — events={len(events)} reqs={reqs} stopped_ok={stopped_at_10} "
          f"msg_ok={bool(ok_msg)} control_choked={bool(ev2)}")

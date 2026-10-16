#!/usr/bin/env python3
"""Diagnose the hang in regression_oob_public_channel_end_to_end:
run the test body with faulthandler dumping all thread stacks every 45s."""
import faulthandler, signal, sys, os, re
sys.path.insert(0, "/home/z/my-project/build-v430")
os.chdir("/home/z/my-project/build-v430")
faulthandler.register(signal.SIGALRM, all_threads=True)

# import the test module without running the suite: read the function source
src = open("tests/run_tests.py").read()
m = re.search(r"def regression_oob_public_channel_end_to_end\(\):(.*?)\n(?=@case|\ndef )", src, re.S)
body = m.group(0)
ns = {"__name__": "diag", "__file__": "/home/z/my-project/build-v430/tests/run_tests.py"}
# provide the suite's common imports the test relies on
prelude = src.split("# ================================================================ UNIT SUITE")[0]
exec(prelude, ns)

def alarm_ring(*a):
    pass

signal.signal(signal.SIGALRM, alarm_ring)
for t in (45, 90, 135):
    signal.alarm(t)          # dumps stacks at +45s, +90s, +135s
import threading
print(f"[diag] running test body; main thread stack dumps follow...", flush=True)
try:
    exec(compile(body, "regression_oob_public_channel_end_to_end", "exec"), ns)
    print("[diag] TEST BODY COMPLETED")
except BaseException as e:
    print(f"[diag] test body raised: {type(e).__name__}: {e}")

#!/usr/bin/env python3
"""Diagnose the two live channels the battery missed: command-execution and
php-code-injection. Replays the EXACT battery family sequence on ONE
connection (as the battery does) and prints what arrives when."""
import sys, time
sys.path.insert(0, "/home/z/my-project/build-v430")
from sentinel.websocket import WsClient

def seq(chan):
    c = WsClient(f"ws://127.0.0.1:8080/{chan}", timeout=6)
    ok = c.connect()
    print(f"\n=== {chan} connected={ok} ===")
    families = [
        ("sql_pair-T", "' OR '1'='1", 2.5),
        ("sql_pair-F", "' OR '1'='2", 2.5),
        ("sql_error", "'", 2.5),
        ("cmdi-1", "; echo DIAGCAN1", 8.0),
        ("cmdi-2", "| echo DIAGCAN2", 8.0),
        ("ssti", "{{40+2}}", 2.5),
        ("code_injection", "20+22", 2.5),
        ("lfi-1", "/etc/passwd", 2.5),
        ("lfi-2", "C:/windows/win.ini", 2.5),
        ("xss", '<img src=x onerror="DIAGXSS">', 2.5),
    ]
    for name, payload, secs in families:
        t0 = time.time()
        c.send_text(payload)
        r = c.wait_text(seconds=secs)
        dt = time.time() - t0
        print(f"  {name:15s} sent={payload[:30]!r:34s} -> {r!r}  ({dt:.1f}s)")
    c.close()

# also: fresh connection per family (the candidate fix)
def seq_fresh(chan):
    print(f"\n=== {chan} FRESH-CONNECTION PER FAMILY ===")
    families = [
        ("sql_pair-T", "' OR '1'='1", 2.5),
        ("cmdi-1", "127.0.0.1; echo DIAGCAN3", 8.0),
        ("code_injection", "20+22", 2.5),
    ]
    for name, payload, secs in families:
        c = WsClient(f"ws://127.0.0.1:8080/{chan}", timeout=6)
        c.connect()
        t0 = time.time()
        c.send_text(payload)
        r = c.wait_text(seconds=secs)
        dt = time.time() - t0
        print(f"  {name:15s} sent={payload[:30]!r:34s} -> {r!r}  ({dt:.1f}s)")
        c.close()

seq("command-execution")
seq("php-code-injection")
seq_fresh("command-execution")
seq_fresh("php-code-injection")

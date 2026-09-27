#!/usr/bin/env python3
"""
PHASE 2: WEB APPLICATION RECON & CONFIG ANALYSIS — REAL TESTS
Targets: Acunetix vulnweb.com intentionally-vulnerable test sites (authorized)
"""
import urllib.request, urllib.error, ssl, socket, json

GREEN="\033[92m"; RED="\033[91m"; YELLOW="\033[93m"; CYAN="\033[96m"; END="\033[0m"; BOLD="\033[1m"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

SITES = ["http://testphp.vulnweb.com", "http://testasp.vulnweb.com", "http://testaspnet.vulnweb.com"]

SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
    "X-Content-Type-Options", "X-XSS-Protection", "Referrer-Policy",
    "Permissions-Policy", "Cross-Origin-Opener-Policy", "X-Powered-By", "Server",
]

def fetch(url, method="GET", timeout=15):
    req = urllib.request.Request(url, method=method, headers={"User-Agent": "SecurityTestSuite/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read() if e.fp else b""
    except Exception as e:
        return None, {}, str(e).encode()

print(f"""{BOLD}{CYAN}
=====================================================================
  PHASE 2: WEB APP RECON & SECURITY CONFIGURATION ANALYSIS
====================================================================={END}""")

for site in SITES:
    print(f"\n{BOLD}{CYAN}──────── TARGET: {site} ────────{END}")
    status, headers, body = fetch(site)
    if status is None:
        print(f"  {RED}UNREACHABLE: {body.decode()[:80]}{END}")
        continue

    print(f"\n{BOLD}[T6] HTTP RESPONSE & SERVER FINGERPRINT{END}")
    print(f"  Status: {status} | Content-Length: {len(body)} bytes")
    server = headers.get("Server", ""); powered = headers.get("X-Powered-By", "")
    print(f"  {RED}Server banner disclosed: '{server}'{END}" if server else f"  Server banner: hidden")
    if powered: print(f"  {RED}X-Powered-By disclosed: '{powered}'{END}")

    print(f"\n{BOLD}[T7] SECURITY HEADERS AUDIT{END}")
    score = 0
    for h in SECURITY_HEADERS:
        val = headers.get(h) or headers.get(h.lower())
        if h in ("Server", "X-Powered-By"):
            continue
        if val:
            print(f"  {GREEN}PRESENT {h}: {val[:60]}{END}"); score += 1
        else:
            print(f"  {RED}MISSING  {h}{END}")
    print(f"  → Security header score: {score}/8")

    print(f"\n{BOLD}[T8] ROBOTS.TXT INFO DISCLOSURE{END}")
    s, h, b = fetch(site + "/robots.txt")
    if s == 200 and b:
        lines = [l.decode().strip() for l in b.split(b"\n") if l.strip()][:10]
        for l in lines: print(f"    {l}")
    else:
        print(f"    robots.txt: {s or 'N/A'}")

    print(f"\n{BOLD}[T9] HTTP METHODS ENUMERATION{END}")
    s, h, b = fetch(site, method="OPTIONS")
    allow = h.get("Allow") or h.get("allow") or "(none)"
    dangerous = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"] if m in allow.upper()]
    print(f"  Allow: {allow}")
    print(f"  {RED}DANGEROUS METHODS ENABLED: {dangerous}{END}" if dangerous else f"  {GREEN}No dangerous methods{END}")

    print(f"\n{BOLD}[T10] TRACE METHOD (XST) CHECK{END}")
    s, h, b = fetch(site, method="TRACE")
    if s == 200 and b"SecurityTestSuite" in b:
        print(f"  {RED}VULNERABLE: TRACE enabled → Cross-Site Tracing possible{END}")
    else:
        print(f"  {GREEN}Not vulnerable (status {s}){END}")

print(f"\n{GREEN}{BOLD}===== PHASE 2 COMPLETE ====={END}")

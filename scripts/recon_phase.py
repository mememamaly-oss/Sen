#!/usr/bin/env python3
"""
PHASE 1: RECONNAISSANCE — REAL TESTS against AUTHORIZED targets only:
  - scanme.nmap.org (45.33.32.156)  → Nmap's officially authorized scan target
  - testphp.vulnweb.com    (Acunetix intentionally-vulnerable test site)
  - testasp.vulnweb.com    (Acunetix test site)
"""
import socket, concurrent.futures, time, subprocess

GREEN  = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"; CYAN = "\033[96m"; END = "\033[0m"; BOLD = "\033[1m"

print(f"""{BOLD}{CYAN}
=====================================================================
  REAL-ENVIRONMENT SECURITY TEST SUITE — PHASE 1: RECONNAISSANCE
  Targets: explicitly-authorized public testing platforms
====================================================================={END}""")

# ---------- TEST 1: TCP PORT SCAN ----------
print(f"\n{BOLD}[TEST 1] TCP PORT SCAN — scanme.nmap.org (authorized by Nmap Inc.){END}")
PORTS = [20,21,22,23,25,53,80,110,111,135,139,143,443,445,587,993,995,1433,1521,
         2049,2222,3000,3306,3389,4444,5000,5432,5900,5985,6379,6443,7000,8000,
         8008,8009,8080,8081,8443,8888,9000,9090,9200,9300,9999,11211,27017,31337]

def scan_port(ip, port, timeout=3.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((ip, port))
        s.close()
        return port if r == 0 else None
    except Exception:
        return None

t0 = time.time()
open_ports = []
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
    for res in ex.map(lambda p: scan_port("45.33.32.156", p), PORTS):
        if res: open_ports.append(res)

print(f"  Scanned {len(PORTS)} common ports in {time.time()-t0:.1f}s")
for p in sorted(open_ports):
    try:
        svc = socket.getservbyport(p)
    except Exception:
        svc = "unknown"
    print(f"  {GREEN}>> OPEN  {p}/tcp  ({svc}){END}")
if not open_ports:
    print(f"  {YELLOW}No open ports in top list{END}")

# ---------- TEST 2: BANNER GRABBING ----------
print(f"\n{BOLD}[TEST 2] SERVICE BANNER GRABBING{END}")
for port in sorted(open_ports):
    try:
        s = socket.socket(); s.settimeout(5)
        s.connect(("45.33.32.156", port))
        if port in (80, 8000, 8080, 443):
            s.send(b"HEAD / HTTP/1.0\r\nHost: scanme.nmap.org\r\n\r\n")
        else:
            s.send(b"\r\n")
        data = s.recv(256)
        s.close()
        banner = data.decode(errors="replace").strip().split("\r\n")[0][:90]
        print(f"  {CYAN}port {port}:{END} {banner}")
    except Exception as e:
        print(f"  {YELLOW}port {port}:{END} no banner ({type(e).__name__})")

# ---------- TEST 3: FULL 65535-port sweep ----------
print(f"\n{BOLD}[TEST 3] FULL TCP SWEEP (all 65535 ports) — scanme.nmap.org{END}")
t0 = time.time()
all_open = []
with concurrent.futures.ThreadPoolExecutor(max_workers=500) as ex:
    futs = {ex.submit(scan_port, "45.33.32.156", p, 1.5): p for p in range(1, 65536)}
    for f in concurrent.futures.as_completed(futs):
        r = f.result()
        if r: all_open.append(r)
print(f"  Completed 65535 ports in {time.time()-t0:.1f}s")
print(f"  {GREEN}ALL OPEN PORTS: {sorted(all_open)}{END}" if all_open else f"  {YELLOW}none{END}")

# ---------- TEST 4: DNS ----------
print(f"\n{BOLD}[TEST 4] DNS RECORD ENUMERATION{END}")
for host in ["scanme.nmap.org", "vulnweb.com", "testphp.vulnweb.com"]:
    try:
        out = subprocess.run(["dig", "+short", host], capture_output=True, text=True, timeout=10).stdout.strip()
        print(f"  {host}: {out.splitlines()[:3]}")
    except Exception as e:
        print(f"  {host}: {type(e).__name__}")

# ---------- TEST 5: Reverse DNS ----------
print(f"\n{BOLD}[TEST 5] REVERSE DNS (PTR){END}")
for ip in ["45.33.32.156", "44.228.249.3", "44.238.29.244"]:
    try:
        out = subprocess.run(["dig", "+short", "-x", ip], capture_output=True, text=True, timeout=10).stdout.strip()
        print(f"  {ip} -> {out or 'no PTR'}")
    except Exception as e:
        print(f"  {ip}: error {type(e).__name__}")

print(f"\n{GREEN}{BOLD}===== PHASE 1 COMPLETE ====={END}")

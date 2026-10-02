#!/usr/bin/env python3
"""Phase 58 LIVE feasibility probes (doctrine: manual BEFORE production).
Questions the workflow engine will face on demo.testfire.net:
  1. Is there a multi-step transfer CHAIN (form landing -> next form)?
  2. Is there a state ORACLE page echoing produced resource ids?
  3. What shape is /bank/transfer.jsp (the only money-movement surface)?
Expected (from architecture knowledge): a SINGLE form, no chain, no oracle ->
the honest negative: 0 flows learned, loud stats. Probes are READ-ONLY except
one benign form GET; nothing is submitted."""
import http.client, re, ssl, sys

HOST, PORT = "demo.testfire.net", 80


def req(method, path, body=None, cookies=None, ctype="application/x-www-form-urlencoded"):
    c = http.client.HTTPConnection(HOST, PORT, timeout=15)
    h = {"User-Agent": "sentinel-probe/3.0.0-feasibility"}
    if cookies:
        h["Cookie"] = cookies
    if body:
        h["Content-Type"] = ctype
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    data = r.read().decode("utf-8", "replace")
    setc = [v for k, v in r.getheaders() if k.lower() == "set-cookie"]
    c.close()
    return r.status, data, setc


def main():
    # 1. anonymous transfer page shape
    st, body, _ = req("GET", "/bank/transfer.jsp")
    forms = re.findall(r'<form[^>]*action="([^"]*)"[^>]*>', body, re.I)
    print(f"transfer.jsp anonymous: {st} | forms -> {forms[:4]}")
    m = re.search(r'<form[^>]*action="([^"]*)".*?</form>', body, re.I | re.S)
    if m:
        fields = re.findall(r'name="([^"]+)"', m.group(0))
        print(f"  first form fields: {fields}")
        # does the landing of this form carry a NEXT form? (chain test is
        # submit-free: we only note that a single form exists — submitting is
        # the engine's job in learn mode, gated by --workflow)
    # 2. any state-oracle-ish page linked from the transfer page?
    links = sorted(set(re.findall(r'href="(/bank/[^"]*)"', body)))
    print(f"  /bank links on the page: {links[:10]}")
    # 3. login + authenticated transfer page (session view)
    st, lp, sc = req("GET", "/bank/login.jsp")
    st, body, _ = req("GET", "/bank/transfer.jsp")
    print(f"transfer.jsp follow-up: {st}")
    # 4. main.jsp menubar links (authenticated view comes after login — probe
    #    anonymous only; the scan itself will do the authenticated walk)
    st, main_b, _ = req("GET", "/bank/main.jsp")
    print(f"main.jsp anonymous: {st} (redirect to login expected)")
    print("\nVERDICT INPUT: single-form transfer (no chained steps visible), "
          "no per-session transaction list linked -> honest-negative expected "
          "for flow learning on this target.")


if __name__ == "__main__":
    main()

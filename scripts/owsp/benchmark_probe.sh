#!/bin/bash
# Functional verification of the deployed Benchmark: SQLi (DB-backed) + LDAPi (LDAP-backed)
# flows + a rate measurement. Runs in ONE call with the stack.
set -u
/home/z/my-project/scripts/owsp/benchmark_stack.sh > /tmp/stack_out.txt 2>&1 || { cat /tmp/stack_out.txt | tail -5; exit 1; }
grep -E "STACK READY|STACK:" /tmp/stack_out.txt

B=http://localhost:8080/benchmark

echo "=== SQLi test 00008 (header vector per openapi: doheader_8) ==="
# read the servlet to see its actual vector
SRC=/home/z/my-project/tools/benchmark-src
grep -m3 -E "getHeader|getParameter|theCookies|getQueryString" $SRC/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00008.java | head -3

echo "=== Probe: GET the page (cookie-vector flow like 00001) ==="
curl -s -c /tmp/jar.txt -o /dev/null -w "GET %{http_code}\n" $B/sqli-00/BenchmarkTest00008
echo "=== Probe: POST with cookie payload ' OR 1=1-- ==="
# mutate the cookie value like a DAST would
sed -i "s/BenchmarkTest00008=[^;]*/BenchmarkTest00008=' OR 1=1--/" /tmp/jar.txt 2>/dev/null
curl -s -b /tmp/jar.txt -o /tmp/sqli_resp.html -w "POST %{http_code} size=%{size_download}\n" -X POST $B/sqli-00/BenchmarkTest00008
grep -oE "Problem with[^<]*|results[^<]*" /tmp/sqli_resp.html | head -3

echo "=== LDAPi test 00012 ==="
grep -m3 -E "getHeader|getParameter|theCookies|getQueryString" $SRC/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00012.java | head -3
echo "=== Probe: ldapi flow ==="
curl -s -c /tmp/jar2.txt -o /dev/null -w "GET %{http_code}\n" $B/ldapi-00/BenchmarkTest00012
sed -i "s/BenchmarkTest00012=[^;]*/BenchmarkTest00012=*/" /tmp/jar2.txt 2>/dev/null
curl -s -b /tmp/jar2.txt -o /tmp/ldapi_resp.html -w "POST %{http_code} size=%{size_download}\n" -X POST $B/ldapi-00/BenchmarkTest00012

echo "=== RATE: 100 sequential GETs ==="
START=$(date +%s.%N)
for i in $(seq 1 100); do curl -s -o /dev/null $B/sqli-00/BenchmarkTest0000$((8 + i % 3)); done
END=$(date +%s.%N)
echo "100 reqs in $(echo "$END - $START" | bc)s"

echo "=== DONE ==="

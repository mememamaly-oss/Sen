#!/bin/bash
# Task 40 — benchmark stack boot + smoke (all-in-one single call; stack dies with the call).
# Mirrors bm_full_chunk.sh boot params exactly (Task-39 contract).
set -u
TOOLS=/home/z/tools
BM=$TOOLS/benchmark
export JAVA_HOME=$TOOLS/jdk-21.0.12.1+1
export PATH=$JAVA_HOME/bin:$TOOLS/apache-maven-3.9.9/bin:$PATH
cd "$BM" || exit 1

pkill -9 -f "catalina" 2>/dev/null; pkill -9 -f "hsqldb" 2>/dev/null
pkill -9 -f LDAPServer 2>/dev/null; pkill -9 -f DataBaseServer 2>/dev/null
pkill -9 -f "cargo-maven3-plugin" 2>/dev/null
sleep 2
: > "$BM/testfiles/passwordFile.txt" 2>/dev/null || true

MVNLOG=$TOOLS/cr_stack_smoke.log
nohup mvn -B -Dmaven.repo.local=$TOOLS/m2 package cargo:run -Pdeploy -Dcargo.servlet.port=8080 \
  -Dcargo.protocol=http -Dcargo.tomcat.httpSecure=false -Drunenv=local -Dmaven.test.skip=true \
  > "$MVNLOG" 2>&1 &
MVPID=$!
trap 'kill $MVPID 2>/dev/null; pkill -9 -f "catalina" 2>/dev/null; pkill -9 -f hsqldb 2>/dev/null; pkill -9 -f LDAPServer 2>/dev/null; pkill -9 -f DataBaseServer 2>/dev/null; pkill -9 -f cargo-maven3 2>/dev/null' EXIT

up=0
for i in $(seq 1 280); do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "http://localhost:8080/benchmark/" 2>/dev/null)
  [ "$code" = "200" ] && { up=1; break; }
  kill -0 $MVPID 2>/dev/null || { echo "MVN DIED"; tail -20 "$MVNLOG"; exit 1; }
  sleep 2
done
[ "$up" = "1" ] || { echo "STACK TIMEOUT code=$code"; tail -20 "$MVNLOG"; exit 1; }
echo "=== STACK UP (${i} polls) ==="

echo "--- LDAP 10389 ---"
ss -tln | grep -q ":10389 " && echo "LDAP LISTENING" || echo "LDAP NOT LISTENING"

echo "--- sqli smoke (header vector) ---"
SQLI_CODE=$(curl -s -H "BenchmarkTest00008: verifyUserPassword('foo','bar')" -o /dev/null -w "%{http_code}" --max-time 10 http://localhost:8080/benchmark/sqli-00/BenchmarkTest00008)
echo "sqli flow = $SQLI_CODE (expect 200)"

echo "--- crypto smoke: TP case 00019 (known DES) + FN case 00035 ---"
for T in 00019 00035 00050 02290; do
  URL=$(grep -h "BenchmarkTest${T}," $BM/expectedresults-1.2.csv | head -1)
  echo "GT $T: $URL"
done
echo "--- direct probes (POST vector=default) ---"
for T in 00019 00035 00050; do
  RESP=$(curl -s -X POST --max-time 10 "http://localhost:8080/benchmark/crypto-00/BenchmarkTest${T}" 2>&1 | head -c 200)
  echo "[$T] ${RESP:0:180}"
done
echo "--- passwordFile after probes ---"
wc -c "$BM/testfiles/passwordFile.txt" 2>/dev/null
head -c 200 "$BM/testfiles/passwordFile.txt" 2>/dev/null
echo ""
echo "SMOKE DONE"

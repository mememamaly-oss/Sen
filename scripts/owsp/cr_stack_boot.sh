#!/bin/bash
# Task 40 — benchmark stack BOOT + smoke (all-in-one single call; stack dies with the call).
# Plain-Tomcat pattern (GTP-12 proven): HSQLDB + LDAPServer + Tomcat9, CWD=$SRC for all.
# Usage: cr_stack_boot.sh [extra: "keep-passwordfile" to NOT truncate the artifact]
set -u
TOOLS=/home/z/tools
SRC=$TOOLS/benchmark
JDK=$TOOLS/jdk-21.0.12.1+1
export JAVA_HOME=$JDK
export PATH=$JDK/bin:$PATH
CATALINA=$TOOLS/tomcat9
CPFILE=$SRC/target/cp.txt
LOGD=$SRC/target/logs
mkdir -p "$LOGD" "$SRC/target/db"

cd "$SRC" || exit 1

# artifact hygiene: truncate passwordFile (fresh appends visible to the 1000B read window)
if [ "${1:-}" != "keep-passwordfile" ]; then
  : > "$SRC/testfiles/passwordFile.txt" 2>/dev/null || true
fi
# stale locks/dbs from previous killed runs
rm -f "$SRC/benchmarkDataBase.lck" "$SRC/benchmarkDataBase.data" "$SRC/benchmarkDataBase.script" \
      "$SRC/benchmarkDataBase.properties" "$SRC/benchmarkDataBase.tmp" \
      "$SRC/target/db/benchmark.db"* 2>/dev/null

# 0) kill leftovers HARD, wait for ports to free
pkill -9 -f "catalina" 2>/dev/null; pkill -9 -f "hsqldb" 2>/dev/null
pkill -9 -f "LDAPServer" 2>/dev/null; pkill -9 -f "DataBaseServer" 2>/dev/null
for i in $(seq 1 30); do
  if ss -tln 2>/dev/null | grep -qE ":(8080|10389|9001) "; then sleep 2; else break; fi
done
ss -tln | grep -E ":(8080|10389|9001) " && { echo "PORTS STILL BUSY"; exit 1; }

# 1) HSQLDB Server (port 9001) — the jdbc/BenchmarkDB JNDI target
CP="$SRC/target/classes:$(cat $CPFILE)"
"$JDK/bin/java" -Xmx256m -cp "$CP" org.hsqldb.Server \
  --database.0 file:$SRC/target/db/benchmark.db --dbname.0 benchmarkDataBase \
  > "$LOGD/hsqldb.log" 2>&1 &
HSQL_PID=$!
sleep 3

# 2) LDAPServer (ApacheDS on 10389)
"$JDK/bin/java" -Xmx512m -cp "$CP" org.owasp.benchmark.helpers.LDAPServer \
  > "$LOGD/ldap.log" 2>&1 &
LDAP_PID=$!
sleep 4

# 3) Tomcat with the exploded benchmark app on http://localhost:8080
export CATALINA_HOME=$CATALINA
export CATALINA_BASE=$CATALINA
"$CATALINA/bin/catalina.sh" run > "$LOGD/tomcat.log" 2>&1 &
TC_PID=$!

# 4) readiness
UP=000
for i in $(seq 1 240); do
  UP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 http://localhost:8080/benchmark/Index.html)
  [ "$UP" = "200" ] && break
  sleep 2
done
echo "STACK: tomcat=$UP ldap=$(ss -tln | grep -c ':10389 ') hsqldb=$(ss -tln | grep -c ':9001 ')"
[ "$UP" = "200" ] || { echo "TOMCAT FAILED"; tail -20 "$LOGD/tomcat.log"; exit 1; }

# 5) smoke: sqli header-vector flow (DB-backed, 200 = JNDI+HSQLDB OK)
SQLI_CODE=$(curl -s -H "BenchmarkTest00008: verifyUserPassword('foo','bar')" -o /tmp/sqli_smoke.html -w "%{http_code}" --max-time 10 http://localhost:8080/benchmark/sqli-00/BenchmarkTest00008)
echo "sqli flow = $SQLI_CODE (expect 200)"

# 6) crypto probes: 00019 (TP, DES) + 00035/00050 (FN cases) with a known 16B value
for T in 00019 00035 00050; do
  BODY=$(curl -s --max-time 10 -X POST "http://localhost:8080/benchmark/crypto-00/BenchmarkTest${T}" \
    --data-urlencode "vector=AAAAAAAAAAAAAAAA" 2>&1)
  echo "[${T}] $(echo "$BODY" | head -c 160)"
done
echo "--- passwordFile after crypto probes ---"
wc -c "$SRC/testfiles/passwordFile.txt" 2>/dev/null
grep -c "secret_value" "$SRC/testfiles/passwordFile.txt" 2>/dev/null
echo "STACK READY (pid tomcat=$TC_PID)"

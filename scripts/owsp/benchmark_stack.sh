#!/bin/bash
# OWASP Benchmark — userspace stack launcher (plain Tomcat, no maven in hot path).
# Starts: HSQLDB -> DataBaseServer(init) -> LDAPServer -> Tomcat9 (http://localhost:8080)
# All-in-one single-call pattern: caller must scan in the SAME call; stack dies with it.
set -u
TOOLS=/home/z/my-project/tools
SRC=$TOOLS/benchmark-src
JDK=$TOOLS/jdk-21.0.12.1+1
export JAVA_HOME=$JDK
export PATH=$JDK/bin:$PATH
CATALINA=$TOOLS/tomcat9
CPFILE=$SRC/target/cp.txt
LOGD=$SRC/target/logs
mkdir -p "$LOGD" "$SRC/target/db"
# FIXED CWD: the app's hibernate uses a CWD-RELATIVE file db (jdbc:hsqldb:benchmarkDataBase)
# so all java processes must share the same working directory ($SRC).
cd "$SRC" || exit 1
# stale locks/dbs from previous killed runs (hsqldb refuses future-timestamped stale locks)
rm -f "$SRC/benchmarkDataBase.lck" "$SRC/benchmarkDataBase.data" "$SRC/benchmarkDataBase.script" \
      "$SRC/benchmarkDataBase.properties" "$SRC/benchmarkDataBase.tmp" \
      /home/z/my-project/benchmarkDataBase.* "$SRC/target/db/benchmark.db"* 2>/dev/null

# 0) Kill leftovers HARD and WAIT for ports to actually free (processes sometimes
#    survive between calls; a dying Tomcat holds 8005 and kills the new instance)
pkill -9 -f "catalina" 2>/dev/null; pkill -9 -f "hsqldb" 2>/dev/null
pkill -9 -f "LDAPServer" 2>/dev/null; pkill -9 -f "DataBaseServer" 2>/dev/null
for i in $(seq 1 30); do
  if ss -tln 2>/dev/null | grep -qE ":(8080|8005|10389) "; then sleep 2; else break; fi
done
ss -tln | grep -E ":(8080|8005|10389) " && { echo "PORTS STILL BUSY"; exit 1; }

# 1) HSQLDB Server (database.0) — the jdbc/BenchmarkDB JNDI target (default port 9001)
CP="$SRC/target/classes:$(cat $CPFILE)"
"$JDK/bin/java" -Xmx256m -cp "$CP" org.hsqldb.Server \
  --database.0 file:$SRC/target/db/benchmark.db --dbname.0 benchmarkDataBase \
  > "$LOGD/hsqldb.log" 2>&1 &
HSQL_PID=$!
sleep 3

# 2) LDAPServer (ApacheDS on 10389) — REQUIRES target/classes on the classpath
#    (DataBaseServer's main() is empty by design — the app seeds the DB itself at boot)
"$JDK/bin/java" -Xmx512m -cp "$CP" org.owasp.benchmark.helpers.LDAPServer \
  > "$LOGD/ldap.log" 2>&1 &
LDAP_PID=$!

sleep 4

# 4) Tomcat with benchmark.war on http://localhost:8080
# 4a) Deploy UNPACKED with a DIRECT app-context Resource (the war's ResourceLink
#     -> global-name indirection fails to resolve; direct definition is standard)
[ -f "$CATALINA/webapps/benchmark.war" ] || cp "$SRC/target/benchmark.war" "$CATALINA/webapps/benchmark.war"
rm -rf "$CATALINA/webapps/benchmark" "$CATALINA/webapps/ROOT"
mkdir -p "$CATALINA/webapps/benchmark"
unzip -q -o "$CATALINA/webapps/benchmark.war" -d "$CATALINA/webapps/benchmark"
rm -f "$CATALINA/webapps/benchmark.war" "$CATALINA/webapps/benchmark/META-INF/context.xml"
cat > "$CATALINA/webapps/benchmark/META-INF/context.xml" <<'CTXEOF'
<?xml version="1.0" encoding="UTF-8"?>
<Context>
    <Resource name="jdbc/BenchmarkDB" auth="Container" type="javax.sql.DataSource"
              username="sa" password=""
              driverClassName="org.hsqldb.jdbc.JDBCDriver"
              url="jdbc:hsqldb:hsql://localhost/benchmarkDataBase;sql.enforce_size=false;shutdown=false;"
              maxTotal="12" maxIdle="2" maxWaitMillis="5000" removeAbandonedOnBorrow="true"/>
    <CookieProcessor sameSiteCookies="strict" />
</Context>
CTXEOF
# 4b) Disable the shutdown port (8005) — repeated runs must never die on a stale holder
sed -i 's|<Server port="8005"|<Server port="-1"|' "$CATALINA/conf/server.xml"
grep -q '<Server port="-1"' "$CATALINA/conf/server.xml" || { echo "server.xml Server port patch failed"; exit 1; }
export CATALINA_HOME=$CATALINA
export CATALINA_BASE=$CATALINA
"$CATALINA/bin/catalina.sh" run > "$LOGD/tomcat.log" 2>&1 &
TC_PID=$!

# 5) Wait for readiness (war unpack + servlet init)
UP=000
for i in $(seq 1 90); do
  UP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 http://localhost:8080/benchmark/Index.html)
  [ "$UP" = "200" ] && break
  sleep 2
done
echo "STACK: tomcat=$UP ldap_pid=$LDAP_PID hsqldb_pid=$HSQL_PID"
[ "$UP" = "200" ] || { echo "TOMCAT FAILED"; tail -15 "$LOGD/tomcat.log"; exit 1; }
# smoke: LDAP must listen + the DB-backed sqli flow must answer 200 WITH its
# header vector (bare GET 500s BY DESIGN: {call + empty} is malformed SQL)
ss -tln | grep -q ":10389 " || { echo "LDAP NOT LISTENING"; tail -10 "$LOGD/ldap.log"; exit 1; }
SQLI_CODE=$(curl -s -H "BenchmarkTest00008: verifyUserPassword('foo','bar')" -o /tmp/sqli_smoke.html -w "%{http_code}" --max-time 10 http://localhost:8080/benchmark/sqli-00/BenchmarkTest00008)
[ "$SQLI_CODE" = "200" ] || { echo "SQLI FLOW = $SQLI_CODE (app-side DB broken)"; head -c 300 /tmp/sqli_smoke.html; exit 1; }
curl -s -D - -o /dev/null http://localhost:8080/benchmark/pathtraver-00/BenchmarkTest00001 | grep -iE "^HTTP|set-cookie" | head -4
echo "STACK READY"

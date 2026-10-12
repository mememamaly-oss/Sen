#!/bin/bash
# Task 42 (sqli recall round) — Tomcat assembly for /home/z/tools (cr_stack_build.sh
# contract: exploded webapp + direct DataSource + shutdown -1 + jarsToSkip), but WITHOUT
# the cargo dependency: direct archive.apache.org Tomcat download + unzip of the war
# (the GTP-12 benchmark_stack.sh pattern, adapted to the Task-40 /home/z/tools layout).
# Resume-safe. One-time setup; boots happen in cr_stack_boot.sh.
set -u
TOOLS=/home/z/tools
SRC=$TOOLS/benchmark
CATALINA=$TOOLS/tomcat9
WAR=$SRC/target/benchmark.war

[ -f "$WAR" ] || { echo "war missing: $WAR"; exit 1; }

echo "=== [1/5] Tomcat 9 download (GTP-12 version pin) ==="
if [ ! -x "$CATALINA/bin/catalina.sh" ]; then
  curl -sSL -o /home/z/tools/tomcat.tgz https://archive.apache.org/dist/tomcat/tomcat-9/v9.0.85/bin/apache-tomcat-9.0.85.tar.gz || { echo "TOMCAT DOWNLOAD FAILED"; exit 1; }
  mkdir -p "$CATALINA"
  tar xzf /home/z/tools/tomcat.tgz -C "$CATALINA" --strip-components=1 && rm /home/z/tools/tomcat.tgz
fi
ls "$CATALINA/bin/catalina.sh" >/dev/null && echo "tomcat9 OK"

echo "=== [2/5] exploded webapp deploy (unzip the war directly) ==="
if [ ! -d "$CATALINA/webapps/benchmark/WEB-INF" ]; then
  mkdir -p "$CATALINA/webapps/benchmark"
  unzip -q -o "$WAR" -d "$CATALINA/webapps/benchmark" || { echo "UNZIP FAILED"; exit 1; }
fi
echo "exploded app: $(find "$CATALINA/webapps/benchmark/WEB-INF/classes" -name '*.class' | wc -l) classes"

echo "=== [3/5] context.xml: direct DataSource (same as cr_stack_build) ==="
rm -f "$CATALINA/webapps/benchmark/META-INF/context.xml"
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
grep -q "jdbc/BenchmarkDB" "$CATALINA/webapps/benchmark/META-INF/context.xml" && echo "context.xml OK"

echo "=== [4/5] server.xml: shutdown port -1 ==="
sed -i 's|<Server port="8005"|<Server port="-1"|' "$CATALINA/conf/server.xml"
grep -q '<Server port="-1"' "$CATALINA/conf/server.xml" && echo "server.xml OK"

echo "=== [5/5] catalina.properties: skip jar scanning (CR-JARSKIP) ==="
CPROP=$CATALINA/conf/catalina.properties
if ! grep -q "CR-JARSKIP" "$CPROP"; then
  printf '\n# CR-JARSKIP: skip dependency-jar annotation scanning (deploy was timing out)\ntomcat.util.scan.StandardJarScanFilter.jarsToSkip=*.jar\n' >> "$CPROP"
fi
grep -q "CR-JARSKIP" "$CPROP" && echo "jarsToSkip OK"

mkdir -p "$SRC/target/logs" "$SRC/target/db" "$SRC/testfiles"
echo "=== sq_stack_tomcat done ==="

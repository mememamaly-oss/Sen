#!/bin/bash
# Task 40 — plain-Tomcat stack build (GTP-12 benchmark_stack.sh pattern, no cargo).
# One-time setup: copies the cargo-installed Tomcat + the ALREADY-EXTRACTED exploded
# webapp into $TOOLS/tomcat9, patches context.xml (direct DataSource Resource),
# server.xml (shutdown port -1) and catalina.properties (jar-scan skip for fast boot).
# Resume-safe. Run once; boots happen in cr_stack_boot.sh.
set -u
TOOLS=/home/z/tools
SRC=$TOOLS/benchmark
CATALINA=$TOOLS/tomcat9
CARGO_TC=$SRC/target/cargo/installs/apache-tomcat-9.0.122/apache-tomcat-9.0.122

[ -d "$CARGO_TC" ] || { echo "cargo tomcat install missing: $CARGO_TC"; exit 1; }

echo "=== [1/5] Tomcat copy ==="
if [ ! -x "$CATALINA/bin/catalina.sh" ]; then
  mkdir -p "$CATALINA"
  cp -r "$CARGO_TC/." "$CATALINA/"
  rm -rf "$CATALINA/webapps/"*
fi
ls "$CATALINA/bin/catalina.sh" >/dev/null && echo "tomcat9 OK"

echo "=== [2/5] exploded webapp deploy ==="
if [ ! -d "$CATALINA/webapps/benchmark/WEB-INF" ]; then
  [ -d "$SRC/target/tomcat9x/webapps/benchmark/WEB-INF" ] || { echo "extracted webapp missing"; exit 1; }
  mkdir -p "$CATALINA/webapps/benchmark"
  cp -r "$SRC/target/tomcat9x/webapps/benchmark/." "$CATALINA/webapps/benchmark/"
fi
echo "exploded app: $(find "$CATALINA/webapps/benchmark/WEB-INF/classes" -name '*.class' | wc -l) classes"

echo "=== [3/5] context.xml: direct DataSource (ResourceLink indirection fails) ==="
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

echo "=== [4/5] server.xml: shutdown port -1 (repeated boots never die on a stale holder) ==="
sed -i 's|<Server port="8005"|<Server port="-1"|' "$CATALINA/conf/server.xml"
grep -q '<Server port="-1"' "$CATALINA/conf/server.xml" && echo "server.xml OK"

echo "=== [5/5] catalina.properties: skip jar scanning (fast boot; classes/ still scanned) ==="
CPROP=$CATALINA/conf/catalina.properties
if ! grep -q "CR-JARSKIP" "$CPROP"; then
  printf '\n# CR-JARSKIP: skip dependency-jar annotation scanning (deploy was timing out)\ntomcat.util.scan.StandardJarScanFilter.jarsToSkip=*.jar\n' >> "$CPROP"
fi
grep -q "CR-JARSKIP" "$CPROP" && echo "jarsToSkip OK"

mkdir -p "$SRC/target/logs" "$SRC/target/db" "$SRC/testfiles"
echo "=== stack build done ==="

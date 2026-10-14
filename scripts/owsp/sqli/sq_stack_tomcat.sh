#!/bin/bash
# Task 42 (sqli recall round) — Tomcat assembly for /home/z/tools (cr_stack_build.sh
# contract: exploded webapp + direct DataSource + shutdown -1 + jarsToSkip), but WITHOUT
# the cargo dependency: direct archive.apache.org Tomcat download + unzip of the war
# (the GTP-12 benchmark_stack.sh pattern, adapted to the Task-40 /home/z/tools layout).
# Resume-safe. One-time setup; boots happen in cr_stack_boot.sh.
#
# 2026-10-14 NO-CLOBBER FIX (supervisor order, item 0): the old step [1/5] did
# `curl -o tomcat.tgz` (unconditional overwrite — replaced a COMPLETE tarball
# with a partial one whenever a session died mid-download) and `tar xzf` straight
# into the live tree (a truncated tarball left a PARTIAL tomcat9 whose bare
# catalina.sh then satisfied the re-entry guard). Step [1/5] now sources
# tomcat_guard.sh: verified artifacts are never written over; only incomplete
# tarballs are resumed; the official SHA-512 is required before extraction;
# extraction happens in a temp dir, is structurally verified (key files, 32
# lib jars, the 5 stock webapps, the jar's own ServerInfo=9.0.85), and only
# then swapped in; a marker file records the verification.
set -u
TOOLS=/home/z/tools
SRC=$TOOLS/benchmark
CATALINA=$TOOLS/tomcat9
WAR=$SRC/target/benchmark.war
TGZ=$TOOLS/tomcat.tgz
GUARD=/home/z/my-project/scripts/owsp/tomcat_guard.sh

# shellcheck source=tomcat_guard.sh
source "$GUARD" || { echo "cannot source $GUARD"; exit 1; }
[ -f "$WAR" ] || { echo "war missing: $WAR"; exit 1; }

echo "=== [1/5] Tomcat 9.0.85 core (no-clobber: verify first, fetch only if needed) ==="
if tomcat_core_verified "$CATALINA"; then
  echo "tomcat9 core already structurally VERIFIED — not touching it"
  [ -f "$CATALINA/$TC_MARKER_NAME" ] || write_core_marker "$CATALINA" "pre-existing tree, structurally verified (tarball absent: size/file-inventory/ServerInfo checks)"
else
  echo "tomcat9 core NOT verified — guarded fetch + verified extraction"
  fetch_tarball "$TGZ" || { echo "TOMCAT FETCH FAILED"; exit 1; }
  extract_core "$TGZ" "$CATALINA" || { echo "TOMCAT EXTRACT FAILED (no clobber happened)"; exit 1; }
fi
tomcat_core_verified "$CATALINA" && echo "tomcat9 OK (verified)" || { echo "tomcat9 FAILED verification after assembly"; exit 1; }

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

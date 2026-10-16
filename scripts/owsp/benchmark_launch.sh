#!/bin/bash
# OWASP campaign — Benchmark 1.2 (2,740 labeled test cases): launch Tomcat 9 with
# benchmark.war, verify readiness, smoke-test test cases. All-in-one single call.
set -u
LT=/home/z/my-project/live-targets
TC=$LT/tools/apache-tomcat-9.0.106
PORT=8180

echo "=== [1/3] prepare + launch Tomcat $(date -u +%H:%M:%S) ==="
pkill -f "catalina.startup.Bootstrap" 2>/dev/null; sleep 1
mkdir -p $TC/webapps
rm -rf $TC/webapps/benchmark $TC/webapps/benchmark.war
rm -rf $TC/logs/* 2>/dev/null
cp $LT/benchmark/target/benchmark.war $TC/webapps/benchmark.war
# strip the default apps to save memory/startup
rm -rf $TC/webapps/ROOT $TC/webapps/docs $TC/webapps/examples $TC/webapps/host-manager $TC/webapps/manager 2>/dev/null
export JAVA_HOME=$LT/tools/jdk-21.0.12.1+1
export CATALINA_OPTS="-Xmx1200m -Djava.awt.headless=true"
setsid nohup $TC/bin/catalina.sh run > $LT/logs/tomcat.log 2>&1 < /dev/null &

UP=000
for i in $(seq 1 240); do
  UP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "http://localhost:$PORT/benchmark/" 2>/dev/null)
  [ "$UP" = "200" ] && break; sleep 1
done
echo "benchmark app http=$UP after ~${i}s"
[ "$UP" != "200" ] && { echo "LAUNCH FAILED"; tail -15 $LT/logs/tomcat.log; exit 1; }

echo "=== [2/3] smoke tests $(date -u +%H:%M:%S) ==="
curl -s -o /dev/null -w "t00001 (pathtraver vuln): %{http_code}\n" "http://localhost:$PORT/benchmark/BenchmarkTest00001"
curl -s -o /dev/null -w "t00027 (sqli?): %{http_code}\n" "http://localhost:$PORT/benchmark/BenchmarkTest00027"
curl -s "http://localhost:$PORT/benchmark/BenchmarkTest00001" | head -c 400; echo

echo "=== [3/3] index/link discovery check $(date -u +%H:%M:%S) ==="
curl -s "http://localhost:$PORT/benchmark/" | head -c 600; echo
echo "---- total servlet mappings in web.xml:"
grep -c "<servlet-mapping>" $LT/benchmark/src/main/webapp/WEB-INF/web.xml 2>/dev/null || echo "web.xml not found (annotations?)"
pkill -f "catalina.startup.Bootstrap" 2>/dev/null
echo "DONE $(date -u +%H:%M:%S)"

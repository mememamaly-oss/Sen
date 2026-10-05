#!/bin/bash
# OWASP campaign app 2/6: OWASP Benchmark (BenchmarkJava) — build script.
# Userspace toolchain (survives pod death under /home/z/my-project/tools).
# Usage: benchmark_build.sh [phase]   phase in: init | package | both
set -u
TOOLS=/home/z/my-project/tools
SRC=$TOOLS/benchmark-src
export JAVA_HOME=$TOOLS/jdk-21.0.12.1+1
export PATH=$JAVA_HOME/bin:$TOOLS/apache-maven-3.9.16/bin:$PATH
MVN="mvn -Dmaven.repo.local=$TOOLS/m2 -q"
cd "$SRC" || exit 1
PHASE="${1:-both}"

if [ "$PHASE" = "init" ] || [ "$PHASE" = "both" ]; then
  echo "=== mvn initialize ==="
  $MVN initialize 2>&1 | tail -5
fi
if [ "$PHASE" = "package" ] || [ "$PHASE" = "both" ]; then
  echo "=== mvn package -DskipTests (resume-safe) ==="
  $MVN package -DskipTests 2>&1 | tail -15
fi
echo "=== artifacts ==="
ls -la target/*.war 2>/dev/null || echo "no war yet"

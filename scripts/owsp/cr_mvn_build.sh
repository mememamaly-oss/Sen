#!/bin/bash
# Task 40 — mvn build of the benchmark war (resume-safe; repo cache persists in /home/z/tools/m2).
# Usage: cr_mvn_build.sh [initialize|package|both]
set -u
TOOLS=/home/z/tools
SRC=$TOOLS/benchmark
export JAVA_HOME=$TOOLS/jdk-21.0.12.1+1
export PATH=$JAVA_HOME/bin:$TOOLS/apache-maven-3.9.9/bin:$PATH
MVN="mvn -Dmaven.repo.local=$TOOLS/m2 -B"
cd "$SRC" || exit 1
PHASE="${1:-both}"

if [ "$PHASE" = "initialize" ] || [ "$PHASE" = "both" ]; then
  echo "=== mvn initialize ==="
  $MVN initialize 2>&1 | tail -4
fi
if [ "$PHASE" = "package" ] || [ "$PHASE" = "both" ]; then
  echo "=== mvn package -DskipTests ==="
  $MVN package -DskipTests 2>&1 | grep -E "BUILD|ERROR|error:" | head -10
fi
echo "=== artifacts ==="
ls -la "$SRC"/target/*.war 2>/dev/null || echo "no war yet"
ls "$SRC"/target/classes >/dev/null 2>&1 && echo "classes OK: $(find "$SRC/target/classes" -name '*.class' | wc -l) classes"

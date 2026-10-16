#!/bin/bash
# Task 40 (crypto recall round) — benchmark stack rebuild at /home/z/tools,
# mirroring the Task-39 layout exactly (bm_full_chunk.sh contract):
#   /home/z/tools/jdk-21.0.12.1+1        (symlink to system JDK 21.0.12.1)
#   /home/z/tools/apache-maven-3.9.9/
#   /home/z/tools/benchmark/             (BenchmarkJava master = v1.2 layout)
# Resume-safe: every step checks for its own output before redoing work.
set -u
TOOLS=/home/z/tools
mkdir -p "$TOOLS"
cd "$TOOLS"

echo "=== [1/4] JDK 21 symlink ==="
if [ ! -e "$TOOLS/jdk-21.0.12.1+1" ]; then
  ln -s /usr/lib/jvm/java-21-openjdk-amd64 "$TOOLS/jdk-21.0.12.1+1"
fi
"$TOOLS/jdk-21.0.12.1+1/bin/java" -version 2>&1 | head -1 || { echo "JDK FAILED"; exit 1; }

echo "=== [2/4] Maven 3.9.9 ==="
if [ ! -x "$TOOLS/apache-maven-3.9.9/bin/mvn" ]; then
  curl -sSL -o maven.tgz https://archive.apache.org/dist/maven/maven-3/3.9.9/binaries/apache-maven-3.9.9-bin.tar.gz || { echo "MVN DOWNLOAD FAILED"; exit 1; }
  tar xzf maven.tgz && rm maven.tgz
fi
export JAVA_HOME=$TOOLS/jdk-21.0.12.1+1
"$TOOLS/apache-maven-3.9.9/bin/mvn" -version 2>&1 | head -1

echo "=== [3/4] BenchmarkJava master clone ==="
if [ ! -d "$TOOLS/benchmark/.git" ]; then
  git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git benchmark 2>&1 | tail -2 || { echo "CLONE FAILED"; exit 1; }
fi
ls "$TOOLS/benchmark/pom.xml" >/dev/null && echo "benchmark clone OK"

echo "=== [4/4] Ground-truth CSV comparison ==="
LOCAL_CSV=/home/z/my-project/build-v430/results/owsp/benchmark/expectedresults-1.2.csv
CLONED_CSV="$TOOLS/benchmark/expectedresults-1.2.csv"
if [ -f "$CLONED_CSV" ]; then
  if diff -q "$LOCAL_CSV" "$CLONED_CSV" >/dev/null 2>&1; then
    echo "CSV IDENTICAL — cloned master matches the campaign ground truth (2740 tests)"
  else
    echo "CSV DIFFERS — INVESTIGATE BEFORE ANY MEASUREMENT"
    diff "$LOCAL_CSV" "$CLONED_CSV" | head -5
    echo "local lines: $(wc -l < "$LOCAL_CSV")  cloned lines: $(wc -l < "$CLONED_CSV")"
  fi
else
  echo "cloned CSV missing — searching:"
  find "$TOOLS/benchmark" -maxdepth 2 -name "expectedresults*" | head -5
fi
echo "=== stack_rebuild done ==="

#!/bin/bash
# Stack rebuild after container rollback wiped tools/ (gitignored, never committed).
# Rebuilds: apache-maven-3.9.16 + OWASP BenchmarkJava source + Tomcat 9 + JDK symlink.
# Resume-safe: every step checks for its own output before redoing work.
set -u
TOOLS=/home/z/my-project/tools
mkdir -p "$TOOLS"
cd "$TOOLS"

echo "=== [1/5] JDK symlink (system JDK 21.0.12.1 = the version the scripts expect) ==="
if [ ! -e "$TOOLS/jdk-21.0.12.1+1" ]; then
  ln -s /usr/lib/jvm/java-21-openjdk-amd64 "$TOOLS/jdk-21.0.12.1+1"
fi
"$TOOLS/jdk-21.0.12.1+1/bin/java" -version 2>&1 | head -1

echo "=== [2/5] Maven 3.9.16 ==="
if [ ! -x "$TOOLS/apache-maven-3.9.16/bin/mvn" ]; then
  curl -sSL -o maven.tgz https://archive.apache.org/dist/maven/maven-3/3.9.16/binaries/apache-maven-3.9.16-bin.tar.gz || exit 1
  tar xzf maven.tgz && rm maven.tgz
fi
"$TOOLS/apache-maven-3.9.16/bin/mvn" -version 2>&1 | head -1

echo "=== [3/5] Tomcat 9.0.85 (no-clobber: verify first, fetch only if needed) ==="
# 2026-10-14 NO-CLOBBER FIX: the old step did `curl -o tomcat.tgz` (unconditional
# overwrite — could replace a COMPLETE tarball with a partial one) and `tar xzf`
# straight into the live tree. Now: verified artifacts are never written over
# (tomcat_guard.sh); the official SHA-512 is required before extraction; the
# extracted core is structurally verified before it is swapped in.
GUARD=/home/z/my-project/scripts/owsp/tomcat_guard.sh
# shellcheck source=tomcat_guard.sh
source "$GUARD" || { echo "cannot source $GUARD"; exit 1; }
if tomcat_core_verified "$TOOLS/tomcat9"; then
  echo "tomcat9 core already structurally VERIFIED — not touching it"
  [ -f "$TOOLS/tomcat9/$TC_MARKER_NAME" ] || write_core_marker "$TOOLS/tomcat9" "pre-existing tree, structurally verified"
else
  fetch_tarball "$TOOLS/tomcat.tgz" || exit 1
  extract_core "$TOOLS/tomcat.tgz" "$TOOLS/tomcat9" || exit 1
fi
tomcat_core_verified "$TOOLS/tomcat9" && echo "tomcat9 OK (verified)"

echo "=== [4/5] OWASP BenchmarkJava source (tag 1.2beta) ==="
if [ ! -d "$TOOLS/benchmark-src/.git" ]; then
  git clone --depth 1 --branch 1.2beta https://github.com/OWASP-Benchmark/BenchmarkJava.git benchmark-src 2>&1 | tail -2
fi
ls "$TOOLS/benchmark-src/pom.xml" >/dev/null && echo "benchmark-src OK"

echo "=== [5/5] Ground-truth CSV comparison ==="
LOCAL_CSV=/home/z/my-project/build-v430/results/owsp/benchmark/expectedresults-1.2.csv
CLONED_CSV="$TOOLS/benchmark-src/expectedresults-1.2.csv"
if [ -f "$CLONED_CSV" ]; then
  if diff -q "$LOCAL_CSV" "$CLONED_CSV" >/dev/null 2>&1; then
    echo "CSV IDENTICAL — the cloned source matches the campaign ground truth"
  else
    echo "CSV DIFFERS:"
    diff "$LOCAL_CSV" "$CLONED_CSV" | head -5
    echo "local lines: $(wc -l < "$LOCAL_CSV")  cloned lines: $(wc -l < "$CLONED_CSV")"
  fi
else
  echo "cloned CSV not at root — searching:"
  find "$TOOLS/benchmark-src" -name "expectedresults*" | head -5
fi
echo "=== done ==="

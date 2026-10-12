#!/bin/bash
# Task 40 — Temurin JDK 21 as a REAL directory named jdk-21.0.12.1+1 (no symlinks:
# the sandbox blocks/converts them). Replaces the headless-JRE copy.
set -u
TOOLS=/home/z/tools
cd "$TOOLS"

if [ -x "$TOOLS/jdk-21.0.12.1+1/bin/javac" ]; then
  echo "javac already present:"; "$TOOLS/jdk-21.0.12.1+1/bin/javac" -version; exit 0
fi

# fresh Temurin tarball (skip if already extracted somewhere)
JDKDIR=$(find "$TOOLS" -maxdepth 1 -type d -name "jdk-21*" ! -name "jdk-21.0.12.1+1" | head -1)
if [ -z "$JDKDIR" ] && [ ! -f temurin21.tar.gz ]; then
  echo "downloading Temurin 21 JDK..."
  curl -sSL -o temurin21.tar.gz "https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse" || { echo "DOWNLOAD FAILED"; exit 1; }
fi
if [ -z "$JDKDIR" ]; then
  ls -la temurin21.tar.gz
  tar xzf temurin21.tar.gz || { echo "EXTRACT FAILED"; exit 1; }
  JDKDIR=$(find "$TOOLS" -maxdepth 1 -type d -name "jdk-21*" ! -name "jdk-21.0.12.1+1" | head -1)
fi
echo "temurin dir: $JDKDIR"
[ -n "$JDKDIR" ] || { echo "NO TEMURIN DIR"; exit 1; }

# replace the broken dir with the real JDK under the expected name
rm -rf "$TOOLS/jdk-21.0.12.1+1"
mv "$JDKDIR" "$TOOLS/jdk-21.0.12.1+1"
rm -f temurin21.tar.gz

"$TOOLS/jdk-21.0.12.1+1/bin/javac" -version || { echo "JAVAC FAILED"; exit 1; }
"$TOOLS/jdk-21.0.12.1+1/bin/java" -version 2>&1 | head -1
echo "JDK READY (real directory, no symlink)"

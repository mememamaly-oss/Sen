#!/bin/bash
# cmdi round (task 49) — full stack rebuild chain at /home/z/tools, mirroring the
# task-48 (rollback #19) live recovery exactly:
#   1. cr_jdk.sh                 (real Temurin JDK 21.0.12.1+1, javac required)
#   2. cr_stack_rebuild.sh       (maven 3.9.9 + BenchmarkJava master clone + CSV check)
#   3. clone pinned to 8b67a88   (the campaign-record commit; CSV binding check)
#   4. cr_mvn_build.sh both      (mvn initialize + package -> benchmark.war)
#   5. cp.txt                    (mvn dependency:build-classpath)
#   6. sq_stack_tomcat.sh        (tomcat9 9.0.85 + exploded webapp + DataSource + jarsToSkip)
#   7. cr_stack_boot.sh smoke    (HSQLDB + LDAP + tomcat + sqli/crypto smoke)
# Resume-safe: every step checks for its own output before redoing work.
set -u
OWSP=/home/z/my-project/scripts/owsp
BMARK=/home/z/tools/benchmark
LOCAL_CSV=/home/z/my-project/build-v430/results/owsp/benchmark/expectedresults-1.2.csv

step() { echo; echo "########## [chain] $* ##########"; date -u +"%Y-%m-%dT%H:%M:%SZ"; }

step "1/7 cr_jdk.sh (real Temurin JDK)"
bash "$OWSP/cr_jdk.sh" || { echo "CHAIN FAIL at cr_jdk"; exit 1; }

step "2/7 cr_stack_rebuild.sh (maven + clone + CSV)"
bash "$OWSP/cr_stack_rebuild.sh" || { echo "CHAIN FAIL at cr_stack_rebuild"; exit 1; }

step "3/7 clone pin 8b67a88"
if [ -d "$BMARK/.git" ]; then
  HEAD_SHA=$(git -C "$BMARK" rev-parse HEAD 2>/dev/null || echo none)
  CSV_OK=no
  [ -f "$BMARK/expectedresults-1.2.csv" ] && diff -q "$LOCAL_CSV" "$BMARK/expectedresults-1.2.csv" >/dev/null 2>&1 && CSV_OK=yes
  echo "clone HEAD=$HEAD_SHA csv_identical=$CSV_OK"
  case "$HEAD_SHA" in
    8b67a88*) echo "clone already at the campaign commit 8b67a88";;
    *)
      if [ "$CSV_OK" = "yes" ]; then
        echo "HEAD moved but CSV byte-identical — pinning to 8b67a88 anyway for exactness"
      else
        echo "CSV DIFFERS — must pin to 8b67a88"
      fi
      git -C "$BMARK" fetch --depth 1 origin 8b67a88 2>&1 | tail -1 || true
      git -C "$BMARK" checkout -q 8b67a88 2>&1 | tail -1 || { echo "PIN FAILED"; exit 1; }
      HEAD_SHA=$(git -C "$BMARK" rev-parse HEAD 2>/dev/null || echo none)
      diff -q "$LOCAL_CSV" "$BMARK/expectedresults-1.2.csv" >/dev/null 2>&1 \
        || { echo "CSV STILL DIFFERS AFTER PIN — ABORT (no measurement on a drifted corpus)"; exit 1; }
      echo "pinned OK: HEAD=$HEAD_SHA csv identical";;
  esac
else
  echo "no clone present after step 2 — ABORT"; exit 1
fi

step "4/7 cr_mvn_build.sh both (initialize + package)"
bash "$OWSP/cr_mvn_build.sh" both || { echo "CHAIN FAIL at cr_mvn_build"; exit 1; }
[ -f "$BMARK/target/benchmark.war" ] || { echo "war missing after build"; exit 1; }

step "5/7 cp.txt (dependency:build-classpath)"
if [ ! -s "$BMARK/target/cp.txt" ]; then
  cd "$BMARK" || exit 1
  mvn -B -Dmaven.repo.local=/home/z/tools/m2 dependency:build-classpath \
      -Dmdep.outputFile=target/cp.txt 2>&1 | grep -E "BUILD|ERROR" | head -5
fi
[ -s "$BMARK/target/cp.txt" ] || { echo "cp.txt missing"; exit 1; }
echo "cp.txt OK: $(wc -c < "$BMARK/target/cp.txt") bytes"

step "6/7 sq_stack_tomcat.sh (tomcat9 9.0.85 assembly)"
bash "$OWSP/sqli/sq_stack_tomcat.sh" || { echo "CHAIN FAIL at sq_stack_tomcat"; exit 1; }

step "7/7 cr_stack_boot.sh (boot + smoke)"
bash "$OWSP/cr_stack_boot.sh" || { echo "CHAIN FAIL at cr_stack_boot (boot+smoke)"; exit 1; }

step "CHAIN COMPLETE"

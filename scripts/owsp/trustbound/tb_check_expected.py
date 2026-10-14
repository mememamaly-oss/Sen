#!/usr/bin/env python3
"""Check the minispec tests' expected categories (TB live proof helper)."""
import csv
import os

P = "/home/z/my-project/build-v430/results/owasp/benchmark/expectedresults-1.2.csv"
print("exists:", os.path.exists(P))
want = {"BenchmarkTest00034", "BenchmarkTest00031", "BenchmarkTest00424",
        "BenchmarkTest00427", "BenchmarkTest02622"}
for row in csv.DictReader(open(P)):
    if row["# test name"] in want:
        print(row["# test name"], row["category"], "vuln=" + row["vulnerable"])

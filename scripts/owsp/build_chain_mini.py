#!/usr/bin/env python3
"""GTP-12c/d live gate: a mini spec (read primitive + write sink + one hash
servlet + two crypto servlets) -> the full chain must fire AND verify."""
import json
from pathlib import Path
import yaml

SRC = Path("/home/z/my-project/tools/benchmark-src")
OUT = SRC / "target" / "campaign" / "spec_chain_mini.json"
BASE = "http://localhost:8080/benchmark"

spec = yaml.safe_load((SRC / "data" / "openapi.yaml").read_text())
spec["servers"] = [{"url": BASE}]
KEEP = ("BenchmarkTest00001",   # content-read primitive (file_marker)
        "BenchmarkTest00002",   # write sink (writability_oracle)
        "BenchmarkTest00003",   # hash vuln (properties MD5)
        "BenchmarkTest00005",   # crypto vuln (literal DES/CBC direct-param)
        "BenchmarkTest00019",   # crypto vuln (properties DES/ECB raw-stream)
        "BenchmarkTest00010")   # weakrand secure (negative control)
spec["paths"] = {p: ops for p, ops in spec["paths"].items()
                 if any(p.endswith("/" + k) for k in KEEP)}
OUT.write_text(json.dumps(spec))
print(f"mini spec: {len(spec['paths'])} paths -> {OUT}")

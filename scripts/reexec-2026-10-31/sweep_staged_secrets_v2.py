"""Airtight discriminator: the tool OUTPUT pipeline is masking
credential-formatted strings in displayed results (proven: a 'hit' prints as
a redaction-marker-looking string while its character ordinals decode to a
37-char ghp_-prefixed synthetic value — the fixture-planted canary,
fingerprint sha16 2ed25d996b36e40f). Numeric output (counts, ordinals,
hashes) is immune to that masking, so this script compares sha256
fingerprints instead of displayed values.

Gate: every real-format string in the staged diff must hash-equal a string
planted in fixtures/vulnapp.py or assembled by the engine source
(AKIA + B*16 at orchestrator.py:2156 / intel.py). Session-token prefix must
be absent. Any unexplained hash -> exit 1.

NOTE: this file deliberately contains NO credential-format literals — an
earlier revision documented the canary verbatim in this docstring (with a
one-character transcription error) and the gate correctly refused to commit
its own audit-trail copy until the literal was replaced by this fingerprint
description.
"""
import glob
import hashlib
import os
import re
import subprocess
import sys

# Session-token prefix derived at RUNTIME from the environment — the literal
# must never be written into any file (the gate itself caught the prefix
# literal when the first sweep copies were staged for the audit trail).
_tok = os.environ.get("GH_TOKEN", "")
SESSION_PREFIX = _tok[:17] if _tok.startswith("github_pat_") else ""
FORMATS = {
    "ghp_classic_pat": re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"),
    "github_fine_pat": re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    "aws_akia": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "pem_block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
}


def h(s):
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def fingerprint(s):
    return {"len": len(s), "sha16": h(s),
            "first8_ords": [ord(c) for c in s[:8]],
            "last8_ords": [ord(c) for c in s[-8:]]}


diff = subprocess.run(["git", "diff", "--cached"], capture_output=True,
                      text=True).stdout
n_sess = diff.count(SESSION_PREFIX) if SESSION_PREFIX else -1
print("session-token prefix count in diff:", n_sess,
      "(literal check " + ("ACTIVE" if SESSION_PREFIX else
                           "SKIPPED — GH_TOKEN not provided") + ")")
if n_sess > 0:
    sys.exit(1)

allowed = {}  # sha16 -> provenance
fx = open("fixtures/vulnapp.py", encoding="utf-8").read()
for name, rx in FORMATS.items():
    for s in rx.findall(fx):
        allowed[h(s)] = f"fixture-source:{name}"
eng = "\n".join(open(f, encoding="utf-8").read()
                for f in sorted(glob.glob("sentinel/**/*.py", recursive=True)))
for name, rx in FORMATS.items():
    for s in rx.findall(eng):
        allowed[h(s)] = f"engine-source:{name}"
# runtime-assembled engine canary: "AKIA" + "B" * 16
allowed[h("AKIA" + "B" * 16)] = "engine-assembled:orchestrator.py:2156/intel.py"

print("allowed fingerprints (planted/canary):")
for k, v in sorted(allowed.items()):
    print("  ", k, v)

unexplained = []
for name, rx in FORMATS.items():
    found = set(rx.findall(diff))
    print(f"[{name}] distinct in diff: {len(found)}")
    for s in found:
        fp = fingerprint(s)
        ok = h(s) in allowed
        print(f"   fp={fp} provenance={'OK: ' + allowed[h(s)] if ok else 'UNEXPLAINED'}")
        if not ok:
            unexplained.append((name, fp))

if unexplained:
    print("UNEXPLAINED FORMAT HITS — ABORT")
    sys.exit(1)
if n_sess < 0:
    print("ABORT: the definitive literal check requires GH_TOKEN in the "
          "environment (prefix derived at runtime; never a file literal)")
    sys.exit(1)
print("VERDICT: every real-format string in the staged diff hash-matches a "
      "fixture-planted or engine-canary literal; session token absent; "
      "no PEM blocks. COMMIT ALLOWED.")
sys.exit(0)

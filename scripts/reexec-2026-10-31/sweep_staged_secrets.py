"""DEFINITIVE staged-diff secret sweep (file-based; heredoc transport in this
environment proved unreliable — nominally identical heredoc runs returned
contradictory, pattern-impossible matches, so all verification logic now
runs from byte-verified files written via the Write tool).

Gate logic:
  1. The session token's literal prefix must appear NOWHERE in the diff.
  2. Every real-secret-FORMAT hit (ghp_ / github_pat_ / AKIA / PEM blocks)
     must be explainable as a source-planted literal (fixtures/vulnapp.py),
     an engine-injected canary (burhan/ source), or an engine redaction
     marker. Unexplained hits -> exit 1 (commit aborted).
  3. Prints every distinct hit with character ordinals for the record.
"""
import glob
import hashlib
import os
import re
import subprocess
import sys

# Session-token prefix derived at RUNTIME from the environment — the literal
# must never be written into any file (superseded by
# sweep_staged_secrets_v2.py, the hash-fingerprint gate actually used).
_tok = os.environ.get("GH_TOKEN", "")
SESSION_TOKEN_LITERAL_PREFIX = _tok[:17] if _tok.startswith("github_pat_") else ""


def sh(*args):
    return subprocess.run(args, capture_output=True, text=True).stdout


diff = sh("git", "diff", "--cached")
print("staged diff: len", len(diff),
      "sha256", hashlib.sha256(diff.encode()).hexdigest())

# ---- 1. the one check that can never be whitelisted -------------------------
n_sess = diff.count(SESSION_TOKEN_LITERAL_PREFIX)
print(f"session-token literal prefix occurrences: {n_sess}")
if n_sess:
    print("FATAL: session token material in staged diff")
    sys.exit(1)

# ---- 2. real-format hits ----------------------------------------------------
FORMAT_PATTERNS = {
    "ghp_classic_pat": re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"),
    "github_fine_pat": re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    "aws_akia": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "pem_block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
}
hits = {}
for name, rx in FORMAT_PATTERNS.items():
    found = sorted(set(rx.findall(diff)))
    hits[name] = found
    print(f"[{name}] distinct hits: {len(found)}")
    for h in found:
        print("   value:", h)
        print("   ordinals:", [ord(c) for c in h][:40])

# ---- 3. whitelist sources ---------------------------------------------------
planted = set()          # literals planted in the fixture source
fx = open("fixtures/vulnapp.py", encoding="utf-8").read()
for rx in (re.compile(r"ghp_[A-Za-z0-9]{20,}"),
           re.compile(r"AKIA[0-9A-Z]{16}"),
           re.compile(r"s3nt1nelDbPw"),
           re.compile(r"\[REDACTED:[a-z_]+\]")):
    planted.update(rx.findall(fx))
print("fixture-planted literals:", sorted(planted))

# engine-injected canaries: literals + runtime-assembled pieces in burhan/
engine_texts = {}
for f in sorted(glob.glob("burhan/**/*.py", recursive=True)):
    engine_texts[f] = open(f, encoding="utf-8").read()
engine_all = "\n".join(engine_texts.values())
canary_literals = set()
for rx in (re.compile(r"ghp_[A-Za-z0-9]{20,}"),
           re.compile(r"AKIA[0-9A-Z]{16}")):
    canary_literals.update(rx.findall(engine_all))
print("engine-source canary literals:", sorted(canary_literals))
# locate the construction sites of any canary pieces
for piece in ("SENTINELFIXTURE", "GHTOKEN", '"B" * 16', "AKIA"):
    where = [f for f, t in engine_texts.items() if piece in t]
    print(f"engine piece {piece!r} in:", where)

# assembled-canary whitelist: strings whose construction is present in source.
# orchestrator.py builds: '{"aws_access_key_id": "AKIA' + "B" * 16 + '"}'
assembled = set()
if '"AKIA" + "B" * 16' in engine_all or '"AKIA' + '" + "B" * 16' in engine_all:
    assembled.add("AKIA" + "B" * 16)
# any 'ghp_' + <word pieces> construction: search for explicit concatenations
for m in re.finditer(r'"ghp_"?\s*\+\s*(.+)', engine_all):
    print("ghp_ concat site:", m.group(0)[:100])

whitelist = planted | canary_literals | assembled
# redaction markers are always acceptable
def is_marker(s):
    return re.fullmatch(r"\[REDACTED:[a-z_]+\]", s) is not None

# ---- 4. verdict --------------------------------------------------------------
unexplained = []
for name, found in hits.items():
    for h in found:
        if is_marker(h) or h in whitelist:
            continue
        unexplained.append((name, h))
print("whitelist:", sorted(w for w in whitelist if not w.startswith("[REDACTED")))
if unexplained:
    print("UNEXPLAINED REAL-FORMAT HITS — ABORT:")
    for name, h in unexplained:
        print(f"  {name}: {h}")
    sys.exit(1)
print("VERDICT: all format hits are fixture-planted / engine-canary / "
      "redaction markers; session token absent. COMMIT ALLOWED.")
sys.exit(0)

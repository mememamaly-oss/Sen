#!/usr/bin/env python3
"""Env secrets/user-data inventory (follow-up Q1, 2026-10-23).

Enumerates every SQLite DB on the machine (excl. node_modules):
- all tables + row counts
- any table holding emails/passwords/user-ish data -> full dump with
  password hashes truncated (they are bcrypt fixtures, not real secrets)
- PII scan of saas-data/ report files (email pattern classification)
"""
import os, re, sqlite3, glob

DBS = [
    "/home/z/my-project/qa-results/cli/store.db",
    "/home/z/my-project/qa-results/cli/store2.db",
    "/home/z/my-project/qa-results/qa-prod.db",
    "/home/z/my-project/tests/integration.db",
    "/home/z/my-project/db/custom.db",
]

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")

def redact(v):
    if isinstance(v, str) and len(v) >= 20 and (v.startswith("$2") or v.startswith("pbkdf2")):
        return f"{v[:12]}...<{len(v)}-char-hash>"
    return v

print("=" * 72)
print("A) SQLITE DATABASES — tables, counts, user data")
print("=" * 72)
for db in DBS:
    print(f"\n--- {db} ---")
    if not os.path.exists(db):
        print("  (missing)"); continue
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        cur = con.cursor()
        tables = [r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_prisma%' ORDER BY 1")]
        for t in tables:
            n = cur.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
            print(f"  table {t:24} rows={n}")
        # dump user-ish tables (any table with email/password column)
        for t in tables:
            cols = [r[1] for r in cur.execute(f'PRAGMA table_info("{t}")')]
            if any(c.lower() in ("email", "password", "passwordhash", "hashedpassword") for c in cols):
                print(f"  >> user data in '{t}' (cols: {', '.join(cols)}):")
                for row in cur.execute(f'SELECT * FROM "{t}" LIMIT 30'):
                    vals = [redact(v) for v in row]
                    print("     " + " | ".join(str(v) for v in vals))
        con.close()
    except Exception as e:
        print(f"  ERROR: {e}")

print()
print("=" * 72)
print("B) saas-data/ + fixtures — PII email scan (classification)")
print("=" * 72)
roots = ["/home/z/my-project/saas-data", "/home/z/my-project/fixtures"]
hits = {}
for root in roots:
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            p = os.path.join(dirpath, f)
            try:
                with open(p, "r", errors="ignore") as fh:
                    found = set(EMAIL_RE.findall(fh.read()))
                if found:
                    hits[p] = sorted(found)[:6]
            except Exception:
                pass
if not hits:
    print("  (no email-like strings found)")
for p, emails in hits.items():
    print(f"  {p}")
    for e in emails:
        print(f"      {e}")

print()
print("=" * 72)
print("C) NEXTAUTH_SECRET / real-looking secrets in tracked .env files")
print("=" * 72)
for p in ["/home/z/my-project/.env", "/home/z/my-project/.env.local", "/home/z/my-project/.env.production"]:
    if os.path.exists(p):
        print(f"  {p}:")
        for line in open(p):
            line = line.strip()
            if line and not line.startswith("#"):
                print(f"      {line}")
    else:
        print(f"  {p}: (does not exist)")

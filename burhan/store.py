"""Phase 46 (architecture continuation): Persistence Layer — SQLite store for runs
and findings. Pure stdlib (sqlite3). 

Why: until v2.0.x every scan was a stateless JSON file — the platform had no memory
ACROSS runs. The architecture's intelligence phases (trend analysis, recurring
findings, fix-regression detection "the same vuln came back after a deploy") require
a queryable store. This module is that store, wired behind the same determinism
contract as everything else (run_id is the join key; finding fingerprints are the
identity of a vulnerability across runs).

Schema (v1):
  runs     (run_id PK, seed, scanner, target, started, finished, stats_json)
  findings (id PK, run_id FK, type, severity, status, url, parameter, method,
            confidence, risk, fingerprint, evidence_json, verification_json,
            first_seen)

Queries:
  save_run()      — persist a scan report (idempotent per run_id+finding id)
  list_runs()     — newest first
  get_run()       — one run + its findings
  list_findings() — cross-run filterable query
  recurring()     — fingerprints seen in >1 run (the vuln came back)
  delta()         — new / fixed / recurring between two runs (or latest two)
"""
from __future__ import annotations
import json, os, sqlite3, time, hashlib


SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id     TEXT PRIMARY KEY,
    seed       TEXT,
    scanner    TEXT,
    target     TEXT,
    started    REAL,
    finished   REAL,
    stats_json TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id                TEXT,
    run_id            TEXT NOT NULL REFERENCES runs(run_id),
    type              TEXT,
    severity          TEXT,
    status            TEXT,
    url               TEXT,
    parameter         TEXT,
    method            TEXT,
    confidence        REAL,
    risk              INTEGER,
    fingerprint       TEXT,
    evidence_json     TEXT,
    verification_json TEXT,
    first_seen        REAL,
    PRIMARY KEY (id, run_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_run   ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_fp    ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_type  ON findings(type);
"""


def finding_fingerprint(type_: str, method: str, url: str, parameter: str) -> str:
    """Stable cross-run identity of ONE vulnerability at ONE injection point
    (same contract as Finding.fingerprint(), minus per-instance evidence kinds)."""
    base = f"{type_}|{method}|{url.split('?')[0]}|{parameter}"
    return hashlib.sha256(base.encode()).hexdigest()[:16]


class Store:
    """SQLite persistence. One file, WAL mode, thread-safe via per-call connections
    (the REST API serves scans from worker threads while readers poll)."""

    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with self._conn() as c:
            c.executescript(SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=5000")
        return c

    # ---------------------------------------------------------------- write
    def save_run(self, report: dict) -> int:
        """Persist one scan report dict (as produced by BurhanScanner.report())."""
        stats = dict(report.get("stats") or {})
        now = time.time()
        rows = 0
        with self._conn() as c:
            c.execute("INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?,?,?)",
                      (report["run_id"], report.get("seed", ""), report.get("scanner", ""),
                       report.get("target", ""), now, now, json.dumps(stats)))
            for f in report.get("findings", []):
                fp = finding_fingerprint(f["type"], f.get("method", "GET"),
                                         f.get("url", ""), f.get("parameter", ""))
                c.execute("INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                          (f["id"], report["run_id"], f["type"], f.get("severity", ""),
                           f.get("status", "verified"), f.get("url", ""), f.get("parameter", ""),
                           f.get("method", "GET"), f.get("confidence", 0.0), f.get("risk", 0), fp,
                           json.dumps(f.get("evidence", []))[:4000],
                           json.dumps(f.get("verification", {}))[:2000], now))
                rows += 1
            # rejected candidates stored too (status='rejected') — audit trail of the
            # verification gate's decisions, queryable for FN forensics
            for f in report.get("rejected_candidates", []):
                fp = finding_fingerprint(f["type"], f.get("method", "GET"),
                                         f.get("url", ""), f.get("parameter", ""))
                c.execute("INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                          (f["id"], report["run_id"], f["type"], f.get("severity", ""),
                           "rejected", f.get("url", ""), f.get("parameter", ""),
                           f.get("method", "GET"), f.get("confidence", 0.0), 0, fp,
                           json.dumps(f.get("evidence", []))[:4000],
                           json.dumps(f.get("verification", {}))[:2000], now))
                rows += 1
        return rows

    # ---------------------------------------------------------------- read
    def list_runs(self, limit: int = 50) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT run_id, seed, scanner, target, started, stats_json FROM runs "
                "ORDER BY started DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            out.append({"run_id": r["run_id"], "seed": r["seed"], "scanner": r["scanner"],
                        "target": r["target"], "started": r["started"],
                        **({"stats": json.loads(r["stats_json"])} if r["stats_json"] else {})})
        return out

    def get_run(self, run_id: str) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if not r:
                return None
            fs = c.execute(
                "SELECT * FROM findings WHERE run_id=? AND status='verified' "
                "ORDER BY risk DESC, type", (run_id,)).fetchall()
            rec = c.execute(
                "SELECT * FROM findings WHERE run_id=? AND status='rejected'", (run_id,)).fetchall()
        return {"run_id": r["run_id"], "seed": r["seed"], "scanner": r["scanner"],
                "target": r["target"], "started": r["started"],
                "stats": json.loads(r["stats_json"] or "{}"),
                "findings": [self._finding_row(f) for f in fs],
                "rejected_candidates": [self._finding_row(f) for f in rec]}

    @staticmethod
    def _finding_row(f) -> dict:
        return {"id": f["id"], "type": f["type"], "severity": f["severity"],
                "status": f["status"], "url": f["url"], "parameter": f["parameter"],
                "method": f["method"], "confidence": f["confidence"], "risk": f["risk"],
                "fingerprint": f["fingerprint"],
                "evidence": json.loads(f["evidence_json"] or "[]"),
                "verification": json.loads(f["verification_json"] or "{}")}

    def list_findings(self, run_id: str = "", type_: str = "", min_risk: int = 0,
                      status: str = "verified", limit: int = 200) -> list[dict]:
        q = "SELECT * FROM findings WHERE status=?"
        args: list = [status]
        if run_id:
            q += " AND run_id=?"; args.append(run_id)
        if type_:
            q += " AND type=?"; args.append(type_)
        if min_risk:
            q += " AND risk>=?"; args.append(min_risk)
        q += " ORDER BY risk DESC, first_seen DESC LIMIT ?"; args.append(limit)
        with self._conn() as c:
            return [self._finding_row(f) for f in c.execute(q, args).fetchall()]

    # ---------------------------------------------------------------- intelligence
    def recurring(self, status: str = "verified") -> list[dict]:
        """Fingerprints confirmed in MORE THAN ONE run — the same vulnerability came
        back after (supposedly) being fixed, or persists across releases."""
        with self._conn() as c:
            rows = c.execute(
                "SELECT fingerprint, type, url, parameter, COUNT(DISTINCT run_id) AS n_runs, "
                "       MIN(first_seen) AS first_seen, MAX(first_seen) AS last_seen "
                "FROM findings WHERE status=? GROUP BY fingerprint HAVING n_runs > 1 "
                "ORDER BY n_runs DESC, last_seen DESC", (status,)).fetchall()
        return [dict(r) for r in rows]

    def delta(self, run_a: str = "", run_b: str = "", status: str = "verified") -> dict:
        """Diff two runs (default: the two most recent). new = in B not A (fresh vuln
        or fix-regression of something previously remediated elsewhere), fixed = in A
        not B, recurring = in both."""
        with self._conn() as c:
            def _pick(rid, order):
                if rid:
                    return rid
                r = c.execute(f"SELECT run_id FROM runs ORDER BY started {order} LIMIT 1").fetchone()
                return r["run_id"] if r else ""
            a, b = _pick(run_a, "ASC" if run_a else "DESC"), _pick(run_b, "ASC" if run_b else "DESC")
            # default: A = previous (2nd newest), B = newest
            if not run_a and not run_b:
                runs = c.execute("SELECT run_id FROM runs ORDER BY started DESC LIMIT 2").fetchall()
                b = runs[0]["run_id"] if runs else ""
                a = runs[1]["run_id"] if len(runs) > 1 else b
            if not a or not b:
                return {"run_a": a, "run_b": b, "new": [], "fixed": [], "recurring": []}

            def fps(rid):
                return {r["fingerprint"]: r["type"] for r in
                        c.execute("SELECT fingerprint, type FROM findings WHERE run_id=? AND status=?",
                                  (rid, status)).fetchall()}
            fa, fb = fps(a), fps(b)
        return {"run_a": a, "run_b": b,
                "new": sorted(set(fb) - set(fa)), "fixed": sorted(set(fa) - set(fb)),
                "recurring": sorted(set(fa) & set(fb))}

    def stats_summary(self) -> dict:
        with self._conn() as c:
            runs = c.execute("SELECT COUNT(*) AS n FROM runs").fetchone()["n"]
            by_type = {r["type"]: r["n"] for r in c.execute(
                "SELECT type, COUNT(*) AS n FROM findings WHERE status='verified' "
                "GROUP BY type ORDER BY n DESC").fetchall()}
            by_sev = {r["severity"]: r["n"] for r in c.execute(
                "SELECT severity, COUNT(*) AS n FROM findings WHERE status='verified' "
                "GROUP BY severity").fetchall()}
            targets = c.execute("SELECT COUNT(DISTINCT target) AS n FROM runs").fetchone()["n"]
        return {"runs": runs, "targets_scanned": targets,
                "verified_findings": sum(by_type.values()),
                "by_type": by_type, "by_severity": by_sev,
                "recurring_fingerprints": len(self.recurring())}

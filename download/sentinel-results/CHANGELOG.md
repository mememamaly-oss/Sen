# SENTINEL v2.1.0 — "Platform Services" Release

Deterministic DAST platform. Zero external dependencies (pure Python 3 stdlib).
Every finding is verification-gated: a candidate is NEVER a finding until an
independent replay confirms it.

## What v2.1.0 adds (architecture continuation: DB / REST-UI / OAST phases)

1. **Persistence Layer — `sentinel/store.py` (Phase 46)**
   SQLite store for runs + findings (verified AND rejected). Cross-run
   intelligence: `recurring()` (the same vuln came back), `delta()` between runs
   (new / fixed / recurring), filterable queries, aggregate stats. CLI: `--db`,
   `findings [--recurring|--delta|--type|--min-risk]`.

2. **Report Builder — `sentinel/report.py` (Phase 47)**
   Self-contained HTML report (inline CSS, zero external assets) + JSON export,
   per-run or cross-run overview. CLI: `report --format html|json`.

3. **REST API + Web UI — `sentinel/api.py` (Phase 48)**
   `GET /api/health|runs|runs/{id}|findings|stats|scans/{id}` and
   `POST /api/scans` (background scan threads, auto-persisted). Embedded dark-mode
   dashboard at `/` (launch scans, live polling, recurring/delta intel).
   Security posture: loopback bind by default; non-loopback bind REQUIRES a token.
   CLI: `serve --port 8022 --db results/sentinel.db`.

4. **OAST Engine — `sentinel/oast.py` (Phase 49)**
   Out-of-band interaction server (Burp-Collaborator-class semantics, local).
   Closes the documented v2.0.x gap: blind XXE with NO response oracle is now
   confirmed via the target's own callback. Detection: `oob_callback` evidence;
   verification: **VR-07** fresh-interaction-id replay. Auto-armed for
   local/private targets (remote targets need a public listener — documented).

## Quality gates (all executed live at release time)

| Gate | Result |
|------|--------|
| Test suite (unit + regression + chaos + E2E) | **36/36 PASS** |
| Doctor | **9/9 PASS** (new: persistence_layer check) |
| Benchmark (fixture v3, 23-entry ground truth) | **TP=13 FP=0 FN=0 TN=10, P=R=F1=1.000** |
| Determinism | same seed -> `run-3c0652b6be` -> identical findings set |
| Self-repair gate (repair-demo) | real failure F1=0.0 reproduced; rule-only repair ROLLED BACK; rule+policy ACCEPTED (F1=1.0) |
| Real remote target (ginandjuice.shop, PortSwigger scanme) | same 5 verified findings as v2.0.3 — zero regression; SQLi CRITICAL risk 85 conf .95 |

## Live defects caught & fixed during this release (each with a permanent regression case)

- **CLI gap**: docstring promised `findings`/`report` since v2.0.3 — never
  implemented; now real, with script-mode subprocess coverage
  (`regression_cli_script_mode_all_subcommands`).
- **Relative import in script mode** (`from .core import ...` crashed
  `python3 sentinel/cli.py scan`) — live-caught during the ginandjuice scan;
  fixed + permanent subprocess-mode test.
- **API access logs polluted stdout** — would have corrupted the test-suite JSON
  verdict consumed by the repair gate (`json.loads(stdout)`); moved to stderr.

## Fixture v3 (benchmarks/ground_truth.json)

New endpoints: `/vuln/oob-stock` (blind XXE, confirmable ONLY out-of-band —
cycling-noise responses) and `/safe/oob-stock` (DTD rejected). Ground truth:
23 entries (13 TP-able / 10 TN-able).

## Usage

```bash
python3 sentinel/cli.py scan https://target.example/ --max-pages 25 --db results/sentinel.db
python3 sentinel/cli.py benchmark            # F1 against ground truth, OAST armed
python3 sentinel/cli.py findings --db results/sentinel.db --recurring
python3 sentinel/cli.py report --db results/sentinel.db --out results/report.html
python3 sentinel/cli.py serve --port 8022    # REST API + dashboard at http://127.0.0.1:8022/
python3 sentinel/cli.py doctor               # 9 environment checks
python3 sentinel/cli.py repair-demo          # live self-repair gate loop
```

## Documented coverage limits (honesty contract)

- Remote-target OAST requires a publicly reachable listener (local loopback
  listener only proves lab targets; plug point: `OastServer.public_base`).
- Browser/DOM engine (DOM-XSS, JS-rendered forms) — next architecture phase.
- Authenticated crawling depth (session replay exists in the engine; scanner
  surface is anonymous-context by default).

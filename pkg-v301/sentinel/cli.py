#!/usr/bin/env python3
"""SENTINEL CLI — scan / benchmark / doctor / findings / report / serve / repair-demo.
Phase 16/29: Benchmark Registry with ground-truth comparison, TP/FP/FN/TN + P/R/F1.
Phase 46+: persistence (--db), findings query, report export, REST API server.
Phase 57 (v2.9.0): `vault` command group — keygen / init / status / list / export /
report / audit / authorize / revoke / purge for the encrypted Credential Vault,
plus scan-time arming via --vault/--vault-key-file (raw credentials captured
during a scan land encrypted at rest, never in reports, logs or findings).
"""
from __future__ import annotations
import argparse, json, os, signal, socket, subprocess, sys, time, hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sentinel.orchestrator import SentinelScanner, ScanConfig, doctor
from sentinel.intel import (StrategyStore, FailureMemory, RepairClassifier, RepairGate,
                            VerificationEngine, FindingPipeline)


# ============================================================ benchmark
def _port_open(host, port, timeout=0.3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def ensure_fixture(base_url="http://127.0.0.1:8777"):
    """Self-repair ops rule OP-01 (fixture_not_running): if the benchmark target is the
    local fixture port and nothing is listening, auto-spawn fixtures/vulnapp.py and
    wait for readiness. Returns the spawned process (or None if already running /
    not applicable). Prevents the F1=0.0 silent-failure mode caught by live re-test."""
    from urllib.parse import urlparse
    u = urlparse(base_url)
    host, port = u.hostname or "127.0.0.1", u.port or 80
    if host not in ("127.0.0.1", "localhost"):
        return None                                   # remote target: nothing to spawn
    if _port_open(host, port):
        return None                                   # fixture already up
    fixture = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures", "vulnapp.py")
    if not os.path.exists(fixture):
        return None
    proc = subprocess.Popen([sys.executable, fixture],
                            env={**os.environ, "PORT": str(port)},
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):                               # wait up to ~6s for readiness
        if _port_open(host, port):
            return proc
        if proc.poll() is not None:
            return None
        time.sleep(0.1)
    proc.terminate()
    return None


def run_benchmark(base_url="http://127.0.0.1:8777", out="results/benchmark.json",
                  strategy_path=None, timeout=12.0, label=""):
    """Scan the fixture and score against ground truth (spec 29/30).
    OP-01: auto-starts the local fixture if it is not running (self-repair ops rule)."""
    spawned = ensure_fixture(base_url)                 # OP-01 auto-start (self-repair)
    try:
        return _run_benchmark_inner(base_url, out, strategy_path, timeout, label, spawned)
    finally:
        if spawned is not None:
            spawned.terminate()                        # we started it -> we stop it
            try:                                       # SYNCHRONOUS cleanup (OP-01b):
                spawned.wait(timeout=5)                # wait for port release, escalate if needed
            except subprocess.TimeoutExpired:
                spawned.kill(); spawned.wait(timeout=5)


def _run_benchmark_inner(base_url, out, strategy_path, timeout, label, spawned):
    gt = json.load(open(os.path.join(os.path.dirname(__file__), "..", "benchmarks", "ground_truth.json")))
    # Phase 49: the benchmark exercises the FULL platform — OAST armed, so the blind
    # XXE ground-truth entry (/vuln/oob-stock) is confirmable out-of-band.
    from sentinel.oast import OastServer
    oast = OastServer()
    try:
        # Phase 51: the benchmark is now an AUTHENTICATED scan — /account and
        # /vault/transfer (ground truth v5) are 302-gated for anonymous clients,
        # so the login flow (AUTH-01/02) is exercised by the benchmark itself.
        from sentinel.auth import AuthProfile
        auth = AuthProfile(login_url=base_url.rstrip("/") + "/login",
                           username="demo", password="demo123",
                           user_field="uid", pass_field="passw",
                           success_marker="Sign Off")
        # Phase 56: the benchmark exercises the FULL platform including the
        # multi-user Authorization Engine — benchmarks/authz_accounts.json is
        # the fixture's three-account matrix (admin + two users).
        authz_cfg = None
        _azp = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "authz_accounts.json")
        if os.path.exists(_azp):
            authz_cfg = json.load(open(_azp))
        # Phase 56: fixture v8 grew the crawl surface (7 new linked pages:
        # leak-config x2, api/filter, api/data, api/secure/data, admin stats x2)
        # — the old 30-page budget (x1.5 auth = 45) capped the BFS exactly at the
        # edge and starved the late-queued DOM pages out of the crawl (live-caught
        # by this very benchmark going FN on xss_dom). Budget recalibrated to track
        # the fixture, same doctrine as the Phase 55 browser-budget recalibration.
        cfg = ScanConfig(allow_private=True, max_pages=36, timeout=timeout,
                         strategy_path=strategy_path, seed="benchmark-fixed-seed",
                         oast=oast, auth=auth, authz=authz_cfg,
                         # Phase 58 (v3.0.0): the benchmark exercises the FULL
                         # platform including the Workflow Intelligence engine —
                         # learning AND the attack battery (fixture v8's wizard
                         # twins are the ground truth for the five logic classes).
                         workflow=True, logic_active=True)
        sc = SentinelScanner(base_url, cfg)
        result = sc.run()
    finally:
        oast.stop()
    findings = result["findings"]

    # ---- score
    def exists(gt_entry):
        return gt_entry["present"]

    def detected(gt_entry):
        for f in findings:
            if f["type"] != gt_entry["type"]:
                continue
            ep_gt = gt_entry["endpoint"]
            if ep_gt == "*" or f["url"].split("?")[0].endswith(ep_gt):
                if not gt_entry["parameter"] or f["parameter"] == gt_entry["parameter"]:
                    return True
        return False

    tp = fn = tn = fp = 0
    details = []
    for g in gt["ground_truth"]:
        d, e = detected(g), exists(g)
        cell = ("TP" if d and e else "FP" if d and not e else "FN" if e and not d else "TN")
        tp += cell == "TP"; fp += cell == "FP"; fn += cell == "FN"; tn += cell == "TN"
        details.append({"case": f"{g['type']}@{g['endpoint']}:{g['parameter']}", "cell": cell})
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    report = {
        "benchmark": gt["benchmark"], "label": label or "adhoc",
        "scanner": result["scanner"], "run_id": result["run_id"], "seed": result["seed"],
        "confusion": {"TP": tp, "FP": fp, "FN": fn, "TN": tn},
        "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
        "stats": result["stats"], "details": details,
        "findings": findings,
        "ground_truth_sha256": hashlib.sha256(json.dumps(gt, sort_keys=True).encode()).hexdigest()[:16],
    }
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    json.dump(report, open(out, "w"), indent=1)
    return report


# ============================================================ repair demo (spec 22/23/38)
def repair_demo():
    """Live full-loop self-repair with a REAL, reproducible failure:
    slow fixture (150ms/request) + degenerate timeout (5ms) -> every request times out.
    Rule-only repair (x3 = 15ms) still fails -> gate ROLLS BACK.
    Rule + policy floor (12s) passes regression + benchmark -> ACCEPTED."""
    import subprocess, signal as _sig
    print("=" * 70)
    print(" SELF-REPAIR GATE — LIVE EXECUTION (no AI, deterministic rules)")
    print("=" * 70)

    # 0) spawn SLOW fixture (real failure substrate)
    slow = subprocess.Popen([sys.executable, "fixtures/vulnapp.py"],
                            env={**os.environ, "PORT": "8778", "DELAY_MS": "150"},
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.2)
    import urllib.request
    slow_alive = False
    try:
        urllib.request.urlopen("http://127.0.0.1:8778/", timeout=5); slow_alive = True
    except Exception:
        pass
    print(f"\n[0] SLOW fixture (150ms/req) spawned on :8778 -> alive={slow_alive}")

    try:
        # 1) healthy baseline on normal fixture
        base = run_benchmark(out="results/benchmark_baseline.json", label="pre-repair baseline", timeout=12.0)
        print(f"\n[1] BASELINE benchmark (normal env): F1={base['f1']:.3f} P={base['precision']:.3f} "
              f"R={base['recall']:.3f} (TP={base['confusion']['TP']} FP={base['confusion']['FP']} FN={base['confusion']['FN']})")

        # 2) REAL failure: slow env + degenerate timeout -> reproducible scanner failure
        print("\n[2] INDUCING REAL FAILURE: slow env (150ms/req) + timeout=5ms ...")
        broken = run_benchmark(base_url="http://127.0.0.1:8778",
                               out="results/benchmark_broken.json", label="broken-transport", timeout=0.005)
        print(f"    broken run: F1={broken['f1']:.3f} verified={broken['stats']['verified']} "
              f"requests={broken['stats']['requests']} -> {'REAL FAILURE REPRODUCED' if broken['f1'] < 0.5 else 'unstable — demo invalid'}")
        assert broken["f1"] < 0.5, "failure was not reproduced; refusing to fake results"

        # 3) deterministic classification
        err = "timeout:TimeoutError"
        cls = RepairClassifier().classify(err, {"scanner": "sqli"})
        print(f"\n[3] FAILURE CLASSIFICATION: error='{err}' -> rule='{cls[0]}' action={cls[1]['action']}")
        assert cls and cls[0] == "timeout_spike"

        # 4) gate: candidate A (rule-only) vs candidate B (rule + policy floor)
        def regression_suite():
            r = subprocess.run([sys.executable, "tests/run_tests.py", "regression"],
                               capture_output=True, text=True,
                               cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            try:
                j = json.loads(r.stdout)          # run_tests prints a single pretty JSON object
                return {"passed": j["passed"], "total": j["total"], "failed": j["failed"]}
            except Exception:
                return {"passed": False, "raw": (r.stdout or r.stderr)[-200:]}

        print("\n[4] REPAIR GATE EXECUTION (against the SAME broken environment):")
        cand_a = run_benchmark(base_url="http://127.0.0.1:8778",
                               out="results/benchmark_repair_candidateA.json",
                               label="repair-A-rule-only", timeout=0.005 * cls[1]["action"]["multiply_timeout"])
        a_ok = cand_a["f1"] >= base["f1"] - 0.02
        print(f"    candidate A (timeout=15ms, rule-only): F1={cand_a['f1']:.3f} acceptable={a_ok} "
              f"-> {'ACCEPT' if a_ok else 'ROLLBACK + RULE QUARANTINED'}")
        reg = regression_suite()
        print(f"    regression suite: passed={reg.get('passed')} ({reg.get('total')} cases)")
        cand_b = run_benchmark(base_url="http://127.0.0.1:8778",
                               out="results/benchmark_repair_candidateB.json",
                               label="repair-B-with-floor", timeout=12.0)
        b_ok = cand_b["f1"] >= base["f1"] - 0.02 and cand_b["confusion"]["FP"] <= base["confusion"]["FP"]
        print(f"    candidate B (timeout=12s, rule + policy floor): F1={cand_b['f1']:.3f} "
              f"FP={cand_b['confusion']['FP']} acceptable={b_ok}")
        verdict = "ACCEPTED" if (b_ok and reg.get("passed") and not a_ok) else \
                  ("ACCEPTED" if (b_ok and reg.get("passed")) else "REJECTED")
        print(f"\n    FINAL GATE VERDICT: {verdict}")
        if verdict == "ACCEPTED":
            print("    -> repair B activated; failure class has permanent regression case "
                  "(tests/run_tests.py::regression_timeout_repair_rule)")
        else:
            print("    -> repair quarantined; failure kept in FailureMemory for rule revision")
        return {"baseline_f1": base["f1"], "broken_f1": broken["f1"],
                "candidate_a_f1": cand_a["f1"], "candidate_a_accepted": a_ok,
                "candidate_b_f1": cand_b["f1"], "candidate_b_accepted": b_ok,
                "regression": reg, "verdict": verdict}
    finally:
        slow.terminate()


# ============================================================ main
def main():
    ap = argparse.ArgumentParser(prog="sentinel")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan"); s.add_argument("target"); s.add_argument("--allow-private", action="store_true")
    s.add_argument("--max-pages", type=int, default=25); s.add_argument("--timeout", type=float, default=12.0)
    s.add_argument("--no-crawl", action="store_true"); s.add_argument("--seed")
    s.add_argument("--out", default="results/scan.json"); s.add_argument("--strategy-path")
    s.add_argument("--db", default="", help="persist run+findings to this SQLite store")
    s.add_argument("--no-oast", action="store_true",
                   help="disable the OAST engine entirely (OOB blind-vuln confirmation)")
    s.add_argument("--oast", choices=["auto", "local", "public"], default="auto",
                   help="Phase 52 OAST channel: auto = local listener for lab targets, "
                        "public webhook channel for remote targets (default); "
                        "public = force the public channel (fails loud if unreachable)")
    s.add_argument("--no-browser", action="store_true",
                   help="disable the browser/DOM engine (Phase 50: JS-built forms + DOM XSS)")
    s.add_argument("--auth-user", default="", help="Phase 51: enable authenticated scanning — username")
    s.add_argument("--auth-pass", default="", help="Phase 51: password")
    s.add_argument("--auth-url", default="", help="login page carrying the form (default: <target>/login.jsp)")
    s.add_argument("--auth-user-field", default="uid")
    s.add_argument("--auth-pass-field", default="passw")
    s.add_argument("--auth-success-marker", default="",
                   help="substring expected on the landing page after login (optional hard gate)")
    # ---- AUTH-05 (Phase 54): static-token authentication (Bearer JWT / API key / custom header)
    s.add_argument("--auth-token", default="",
                   help="Phase 54: static token (Bearer JWT, API key) — enables token mode")
    s.add_argument("--auth-header", default="Authorization",
                   help="header name carrying the token (default: Authorization)")
    s.add_argument("--auth-scheme", default="Bearer",
                   help="scheme prefix ('Bearer x' / 'Token x' / '' = raw value)")
    s.add_argument("--auth-validate-url", default="",
                   help="page fetched WITH the header to prove the token opens a closed door")
    # ---- DISC-13 (Phase 54): OpenAPI seeding
    s.add_argument("--no-openapi", action="store_true",
                   help="disable OpenAPI/Swagger document auto-probing")
    s.add_argument("--openapi-spec", default="",
                   help="path/URL of an explicit OpenAPI/Swagger JSON document to seed endpoints")
    # ---- Phase 56 (v2.8.0): the Intelligence Layer
    s.add_argument("--authz-accounts", default="",
                   help="Phase 56: multi-user authorization testing — JSON file with "
                        "accounts (name/role/username/password/marker/object_id) + "
                        "login flow; enables IDOR/BOLA + vertical-escalation "
                        "detection and the role x endpoint access matrix")
    s.add_argument("--no-secrets", action="store_true",
                   help="disable the credential-exposure scan of passive baselines")
    s.add_argument("--secrets-report", default="",
                   help="also write a standalone credential-exposure report (masked "
                        "values only) to this path")
    # ---- Phase 57 (v2.9.0): Credential Vault — encrypted retention of captured
    # credentials. Requires BOTH the vault file and an authorized key file.
    s.add_argument("--vault", default="",
                   help="Phase 57: path of the credential vault file — arms encrypted "
                        "capture of credentials found during the scan")
    s.add_argument("--vault-key-file", default="",
                   help="an authorized vault key file (see: sentinel vault keygen)")
    # ---- Phase 58 (v3.0.0): Workflow / Business-Logic Intelligence. Learning
    # is safe (guided walks); the attack battery changes application state and
    # is therefore behind its own explicit flag.
    s.add_argument("--workflow", action="store_true",
                   help="Phase 58: learn multi-step business flows (guided walks: "
                        "chain, resource linkage, state oracle) and add them to "
                        "the application map")
    s.add_argument("--logic-active", action="store_true",
                   help="Phase 58: ALSO run the five business-logic attack "
                        "manipulations (step bypass / out-of-order / value tamper / "
                        "duplicate execution / privilege bound) on fresh sessions — "
                        "THESE PROBES CHANGE APPLICATION STATE (canary values, "
                        "bounded budgets); every finding requires state-oracle proof")
    b = sub.add_parser("benchmark"); b.add_argument("--url", default="http://127.0.0.1:8777")
    b.add_argument("--out", default="results/benchmark.json"); b.add_argument("--strategy-path"); b.add_argument("--timeout", type=float, default=12.0)
    sub.add_parser("doctor")
    sub.add_parser("repair-demo")
    # ---- Phase 46+: findings / report / serve
    fnd = sub.add_parser("findings", help="query persisted findings across runs")
    fnd.add_argument("--db", default="results/sentinel.db")
    fnd.add_argument("--run-id", default=""); fnd.add_argument("--type", default="")
    fnd.add_argument("--min-risk", type=int, default=0); fnd.add_argument("--status", default="verified")
    fnd.add_argument("--recurring", action="store_true", help="only fingerprints seen in >1 run")
    fnd.add_argument("--delta", action="store_true", help="diff the two most recent runs")
    rep = sub.add_parser("report", help="export an HTML/JSON/SARIF report from the store")
    rep.add_argument("--db", default="results/sentinel.db"); rep.add_argument("--run-id", default="")
    rep.add_argument("--out", default="results/report.html"); rep.add_argument("--format", choices=["html", "json", "sarif"], default="html")
    srv = sub.add_parser("serve", help="REST API + web UI (Phase: REST/UI)")
    srv.add_argument("--host", default="127.0.0.1"); srv.add_argument("--port", type=int, default=8022)
    srv.add_argument("--db", default="results/sentinel.db")
    srv.add_argument("--token", default="", help="required when binding non-loopback")
    # ---- Phase 57 (v2.9.0): the Credential Vault command group -----------------
    # Access model: key FILES, not passwords. keygen hands a 0600 key file to an
    # authorized party (tool designer / organization owner); the vault refuses
    # every operation without a key authorized for THAT vault file.
    vlt = sub.add_parser("vault", help="Phase 57: encrypted Credential Vault")
    vsub = vlt.add_subparsers(dest="vcmd", required=True)
    vg = vsub.add_parser("keygen", help="create a new authorized key file (hand it "
                                       "to the organization owner — never commit it)")
    vg.add_argument("--out", required=True); vg.add_argument("--label", default="")
    vi = vsub.add_parser("init", help="create a new vault for an organization")
    vi.add_argument("--vault", required=True); vi.add_argument("--key-file", required=True)
    vi.add_argument("--org", required=True); vi.add_argument("--label", default="designer")
    for name, help_ in (
            ("status", "masked overview: org, revision, record count, authorized keys"),
            ("list", "masked record listing — raw values NEVER leave the vault"),
            ("audit", "who opened what, when — the encrypted audit trail")):
        vp = vsub.add_parser(name, help=help_)
        vp.add_argument("--vault", required=True); vp.add_argument("--key-file", required=True)
    vr = vsub.add_parser("report", help="OWNER-ONLY full-reveal report "
                                         "(CONFIDENTIAL, audited)")
    vr.add_argument("--vault", required=True)
    vr.add_argument("--key-file", required=True); vr.add_argument("--out", default="")
    ve = vsub.add_parser("export", help="authenticated reveal of ONE record (audited)")
    ve.add_argument("--vault", required=True); ve.add_argument("--key-file", required=True)
    ve.add_argument("--record", required=True)
    va = vsub.add_parser("authorize", help="add another authorized key (e.g. the "
                                           "organization owner's)")
    va.add_argument("--vault", required=True); va.add_argument("--key-file", required=True)
    va.add_argument("--new-key", required=True); va.add_argument("--label", default="")
    vv = vsub.add_parser("revoke", help="remove a key AND rotate the blob key — a "
                                        "revoked key cannot open any copy of the file")
    vv.add_argument("--vault", required=True); vv.add_argument("--key-file", required=True)
    vv.add_argument("--key-id", required=True)
    vp = vsub.add_parser("purge", help="shred records after report delivery "
                                       "(the audit entry survives by design)")
    vp.add_argument("--vault", required=True); vp.add_argument("--key-file", required=True)
    vp.add_argument("--record", default="")
    vp.add_argument("--all", action="store_true")
    a = ap.parse_args()

    if a.cmd == "doctor":
        print(json.dumps(doctor(), indent=1))
    elif a.cmd == "scan":
        auth = None
        if a.auth_token:
            # AUTH-05 token mode: Bearer JWT / API key / custom header.
            from sentinel.auth import AuthProfile
            if a.auth_user:
                print("[AUTH-05] --auth-token overrides --auth-user (token mode)", file=sys.stderr)
            auth = AuthProfile(login_url=a.auth_validate_url or a.target.rstrip("/"),
                               token=a.auth_token, auth_header=a.auth_header,
                               auth_scheme=a.auth_scheme)
        elif a.auth_user:
            from sentinel.auth import AuthProfile
            login_url = a.auth_url or (a.target.rstrip("/") + "/login.jsp")
            auth = AuthProfile(login_url=login_url, username=a.auth_user, password=a.auth_pass,
                               user_field=a.auth_user_field, pass_field=a.auth_pass_field,
                               success_marker=a.auth_success_marker)
        # DISC-13: explicit OpenAPI/Swagger seed (local path or URL) — parsed to
        # endpoints BEFORE the crawl so unlinked API surface is scanned too.
        openapi_spec = None
        if a.openapi_spec:
            if a.openapi_spec.startswith(("http://", "https://")):
                import urllib.request as _ur
                openapi_spec = json.loads(_ur.urlopen(a.openapi_spec, timeout=a.timeout).read().decode("utf-8", "replace"))
            else:
                openapi_spec = json.load(open(a.openapi_spec))
        # Phase 56: multi-user authorization config (accounts + login flow)
        authz_cfg = None
        if a.authz_accounts:
            authz_cfg = json.load(open(a.authz_accounts))
        cfg = ScanConfig(allow_private=a.allow_private, max_pages=a.max_pages,
                         crawl=not a.no_crawl, timeout=a.timeout, seed=a.seed,
                         strategy_path=a.strategy_path, browser=not a.no_browser,
                         auth=auth, openapi=not a.no_openapi, openapi_spec=openapi_spec,
                         authz=authz_cfg, secrets=not a.no_secrets,
                         vault=a.vault or None, vault_key_file=a.vault_key_file or None,
                         workflow=a.workflow, logic_active=a.logic_active)
        # Phase 58: the attack battery changes application state — a loud,
        # explicit warning before a single probe leaves the engine.
        if a.logic_active:
            print("[!] --logic-active: business-logic attack probes are ENABLED — "
                  "state-changing manipulations (step bypass / out-of-order / value "
                  "tamper / duplicate execution / privilege bound) WILL be executed "
                  "against the target with canary values and bounded budgets.", flush=True)
        # Phase 52: channel-aware OAST arming. auto = local listener for targets
        # that can reach loopback (lab fixtures), PUBLIC webhook channel for remote
        # targets (live-proven: ginandjuice.shop blind XXE confirmed via webhook.site
        # callback from the target's own AWS egress). Degrades honestly to None when
        # the public service is unreachable — the scan proceeds exactly as in v2.0.x.
        oast = None
        from urllib.parse import urlparse as _up
        if not a.no_oast:
            from sentinel.oast import make_oast
            oast = make_oast(_up(a.target).hostname or "", mode=a.oast)
            cfg.oast = oast
        try:
            sc = SentinelScanner(a.target, cfg)
            rep = sc.run()
        except Exception as e:
            # Phase 57: a refused vault (wrong key / tampered file / unauthorized
            # key) is a CONFIGURATION error that must fail fast and clean —
            # never a mid-scan traceback, never a partial vault write.
            from sentinel.vault import VaultError
            if isinstance(e, VaultError):
                print(json.dumps({"scan_aborted": "vault refused",
                                  "vault_error": str(e),
                                  "hint": "the scan made ZERO requests; unlock "
                                          "with an authorized key file "
                                          "(sentinel vault keygen / authorize)"}),
                      file=sys.stderr)
                sys.exit(2)
            raise
        finally:
            if oast is not None:
                oast.stop()
        os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
        json.dump(rep, open(a.out, "w"), indent=1)
        # Phase 56: standalone credential-exposure report (masked values only —
        # the data-minimization discipline: secrets get their own channel and
        # never appear unmasked in ANY artifact).
        if a.secrets_report:
            cred = [f for f in rep["findings"] if f["type"] == "credential_exposure"]
            os.makedirs(os.path.dirname(a.secrets_report) or ".", exist_ok=True)
            vault_armed = bool(rep.get("stats", {}).get("vault"))
            json.dump({"run_id": rep["run_id"], "target": rep["target"],
                       "generated_by": rep["scanner"],
                       "policy": ("raw values are retained ENCRYPTED in the "
                                  "credential vault (see: sentinel vault report) — "
                                  "this report stays masked"
                                  if vault_armed else
                                  "masked evidence only — raw secret values are "
                                  "never stored or transmitted by SENTINEL"),
                       "summary": rep.get("stats", {}).get("secrets", {}),
                       "vault": rep.get("stats", {}).get("vault"),
                       "findings": cred},
                      open(a.secrets_report, "w"), indent=1)
        if a.db:
            from sentinel.store import Store
            n = Store(a.db).save_run(rep)
            print(json.dumps({"target": rep["target"], "stats": rep["stats"],
                              "verified_findings": len(rep["findings"]),
                              "persisted": n, "db": a.db}, indent=1))
        else:
            print(json.dumps({"target": rep["target"], "stats": rep["stats"],
                              "verified_findings": len(rep["findings"])}, indent=1))
        for f in sorted(rep["findings"], key=lambda x: -x["risk"]):
            print(f"  [{f['severity'].upper():8s}] {f['type']:26s} {f['url'][:60]:60s} param={f['parameter']:6s} risk={f['risk']}")
    elif a.cmd == "benchmark":
        rep = run_benchmark(a.url, a.out, a.strategy_path, a.timeout, label="cli")
        c = rep["confusion"]
        if rep["stats"]["requests"] <= 5:
            print("[OP-01] WARNING: benchmark target unreachable (requests<=5); "
                  "check --url", file=sys.stderr)
        print(json.dumps({"benchmark": rep["benchmark"], "confusion": c,
                          "precision": rep["precision"], "recall": rep["recall"], "f1": rep["f1"],
                          "stats": rep["stats"]}, indent=1))
        for d in rep["details"]:
            print(f"  {d['cell']}: {d['case']}")
    elif a.cmd == "repair-demo":
        repair_demo()
    elif a.cmd == "findings":
        from sentinel.store import Store
        st = Store(a.db)
        if a.delta:
            print(json.dumps(st.delta(), indent=1))
        elif a.recurring:
            print(json.dumps(st.recurring(), indent=1))
        else:
            rows = st.list_findings(run_id=a.run_id, type_=a.type,
                                    min_risk=a.min_risk, status=a.status)
            print(json.dumps({"count": len(rows), "findings": rows}, indent=1))
            for f in rows:
                print(f"  [{f['severity'].upper():8s}] {f['type']:30s} {f['url'][:58]:58s} "
                      f"param={f['parameter']:8s} risk={f['risk']:3d} run={f.get('run_id', '')}")
    elif a.cmd == "report":
        from sentinel.store import Store
        from sentinel.report import build_report, build_html, build_sarif
        st = Store(a.db)
        os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
        if a.format == "sarif":
            # OP-02: SARIF 2.1.0 — the industry interchange format (GitHub code
            # scanning / VS Code / DefectDojo). Verification-gated like everything
            # else: only VERIFIED findings become results.
            sarif = build_sarif(st, a.run_id)
            json.dump(sarif, open(a.out, "w"), indent=1)
            n = len(sarif.get("runs", [{}])[0].get("results", [])) if "runs" in sarif else 0
            print(json.dumps({"report": a.out, "format": "sarif", "run_id": a.run_id or "all-verified",
                              "results": n, "sarif_version": sarif.get("version", "")}))
        elif a.format == "json":
            json.dump(build_report(st, a.run_id), open(a.out, "w"), indent=1)
            print(json.dumps({"report": a.out, "format": a.format, "run_id": a.run_id or "overview"}))
        else:
            open(a.out, "w").write(build_html(st, a.run_id))
            print(json.dumps({"report": a.out, "format": a.format, "run_id": a.run_id or "overview"}))
    elif a.cmd == "serve":
        from sentinel.api import run_server
        run_server(a.host, a.port, a.db, token=a.token)
    elif a.cmd == "vault":
        from sentinel.vault import Vault, VaultError, keygen
        try:
            if a.vcmd == "keygen":
                kf = keygen(a.out, label=a.label)
                print(json.dumps({"key_file": a.out, "key_id": kf["key_id"],
                                  "label": a.label,
                                  "note": "0600 key file — hand to an authorized "
                                          "party only; never commit it to Git"}))
            elif a.vcmd == "init":
                v = Vault.init(a.vault, a.key_file, a.org, label=a.label)
                print(json.dumps(v.status()))
            else:
                v = Vault.open(a.vault, a.key_file)
                if a.vcmd == "status":
                    print(json.dumps(v.status()))
                elif a.vcmd == "list":
                    print(json.dumps({"org": v.org, "records": v.list()}, indent=1))
                elif a.vcmd == "export":
                    rec = v.export(a.record)
                    print(json.dumps(rec, indent=1))
                elif a.vcmd == "report":
                    rep_v = v.report()
                    if a.out:
                        os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
                        json.dump(rep_v, open(a.out, "w"), indent=1)
                        print(json.dumps({"report": a.out, "org": rep_v["org"],
                                          "records": len(rep_v["records"]),
                                          "classification": rep_v["classification"]}))
                    else:
                        print(json.dumps(rep_v, indent=1))
                elif a.vcmd == "audit":
                    print(json.dumps({"org": v.org, "entries": v.audit()}, indent=1))
                elif a.vcmd == "authorize":
                    kid = v.authorize(a.new_key, label=a.label)
                    print(json.dumps({"authorized": kid, "label": a.label,
                                      "actor": v.key_id}))
                elif a.vcmd == "revoke":
                    v.revoke(a.key_id)
                    print(json.dumps({"revoked": a.key_id,
                                      "note": "blob key rotated — the revoked key "
                                              "cannot open any copy of this file"}))
                elif a.vcmd == "purge":
                    if not a.record and not a.all:
                        print(json.dumps({"error": "--record ID or --all required"}),
                              file=sys.stderr)
                        sys.exit(2)
                    n = v.purge(record_id=a.record or None, all_records=a.all)
                    print(json.dumps({"shredded": n,
                                      "note": "values removed from the encrypted "
                                              "blob; the audit entry survives"}))
        except VaultError as e:
            print(json.dumps({"vault_error": str(e)}), file=sys.stderr)
            sys.exit(2)


if __name__ == "__main__":
    main()

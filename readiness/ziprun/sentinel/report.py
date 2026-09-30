"""Phase 47 (architecture continuation): Report builder — export findings from the
persistence store as a self-contained HTML page or a JSON document.

Design notes:
- Self-contained: one HTML file, inline CSS, zero external assets (portable evidence
  artifact — can be attached to a ticket, stored in a repo, opened offline).
- Scope: single run (run-id) or cross-run overview (no run-id) with recurring /
  delta intelligence from the store.
- Same honesty contract as the scanner: rejected candidates are exported too
  (verification decisions are auditable), each finding carries its evidence chain
  and verification method.
"""
from __future__ import annotations
import html as _html
import json

from .store import Store
from .core import VERSION

SEV_COLORS = {"critical": "#c0392b", "high": "#e67e22", "medium": "#f1c40f",
              "low": "#3498db", "info": "#95a5a6"}


def build_report(store: Store, run_id: str = ""):
    """Returns a JSON dict, or a self-contained HTML string when as_html=True."""
    return _build_json(store, run_id)


def build_html(store: Store, run_id: str = "") -> str:
    return _build_html(store, run_id)


# ============================================================ Phase 64 (v4.0.0): Executive layer
RISK_LANGUAGE = {
    "critical": ("Immediate compromise potential — an attacker can take over "
                 "sessions, data or hosts without further preconditions."),
    "high": ("Serious impact demonstrated — full or partial control of data, "
             "business actions or other users' sessions is reachable."),
    "medium": ("Meaningful exposure — attackers can read or influence data in "
               "ways the application does not intend."),
    "low": "Defense-in-depth gap — useful to attackers as part of a chain.",
    "info": "Reconnaissance-grade information disclosure.",
}


def build_executive(store: Store, run_id: str = "") -> dict:
    """The executive view of one run (or the newest): risk posture, business
    impact, affected assets, verification and coverage proof — derived from the
    SAME data as the technical report, phrased for decision makers.
    Every number is auditable: it traces to the run's stored findings/stats."""
    if run_id:
        run = store.get_run(run_id)
    else:
        runs = store.list_runs(limit=1)
        run = store.get_run(runs[0]["run_id"]) if runs else None
    if not run:
        return {"error": "run not found"}
    findings = run.get("findings", [])
    stats = run.get("stats", {}) or {}
    by_sev: dict[str, int] = {}
    by_type: dict[str, int] = {}
    assets: dict[str, set] = {}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        by_sev[sev] = by_sev.get(sev, 0) + 1
        by_type[f.get("type", "")] = by_type.get(f.get("type", ""), 0) + 1
        asset = (f.get("url") or "").split("?")[0]
        assets.setdefault(asset, set()).add(sev)
    top_risk = sorted(findings, key=lambda f: -int(f.get("risk") or 0))[:8]
    cov = stats.get("coverage") or {}
    twin = stats.get("digital_twin") or {}
    reasoning = stats.get("reasoning") or {}
    planner = stats.get("planner") or {}
    # posture: worst severity with at least one VERIFIED finding
    posture = next((s for s in ("critical", "high", "medium", "low", "info")
                    if by_sev.get(s)), "clean")
    return {
        "kind": "executive",
        "run_id": run["run_id"], "target": run.get("target", ""),
        "scanner": run.get("scanner", ""),
        "risk_posture": posture,
        "risk_language": RISK_LANGUAGE.get(posture, "No verified weaknesses."),
        "verified_findings": len(findings),
        "by_severity": dict(sorted(by_sev.items())),
        "by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        "affected_assets": {a: sorted(sevs) for a, sevs in sorted(assets.items())},
        "top_risks": [{"type": f.get("type"), "severity": f.get("severity"),
                        "risk": f.get("risk", 0), "asset": (f.get("url") or "").split("?")[0],
                        "parameter": f.get("parameter", ""),
                        "verified_by": (f.get("verification") or {}).get("method", "")}
                       for f in top_risk],
        "business_impact": {
            "data_exposure": any(t in by_type for t in
                                  ("sql_injection", "path_traversal", "xxe", "idor_bola",
                                   "credential_exposure", "cors_misconfig")),
            "session_takeover": any(t in by_type for t in
                                     ("xss_reflected", "xss_dom", "csrf", "jwt_security")),
            "unauthorized_actions": any(t.startswith("business_logic_") or
                                        t in ("vertical_privilege_escalation",
                                              "nosql_injection") for t in by_type),
            "infrastructure": any(t in by_type for t in
                                   ("ssrf", "command_injection", "ssti")),
        },
        "coverage_proof": {"discovered": cov.get("discovered", 0),
                            "tested": cov.get("tested", 0),
                            "coverage_pct": cov.get("coverage_pct", 0),
                            "untested_reasons": cov.get("skip_reasons", {})},
        "application_model": {"surfaces": twin.get("surfaces_total", 0),
                               "identities": twin.get("identities", 0),
                               "entities": twin.get("entities", 0),
                               "workflows": len(twin.get("flows", [])),
                               "graph_nodes": twin.get("nodes", 0)},
        "reasoning_coverage": {k: reasoning.get(k, 0) for k in
                                ("generated", "verified", "refuted", "untestable")},
        "safety_contract": planner.get("policy", ""),
        "ci_gate": {"fail_on_high": sum(1 for s in ("critical", "high")
                                         if by_sev.get(s)),
                    "exit_code_rule": "exit 1 when verified critical/high findings > 0"},
    }


# ============================================================ OP-02: SARIF 2.1.0
# Stable rule registry — a finding type always maps to the SAME ruleId so results
# from different runs diff cleanly in SARIF consumers (GitHub code scanning,
# VS Code SARIF viewer, DefectDojo importers).
SARIF_RULES = {
    "sql_injection":                    "SEN-SQL-001",
    "xss_reflected":                    "SEN-XSS-001",
    "xss_dom":                          "SEN-XSS-002",
    "path_traversal":                   "SEN-TRA-001",
    "open_redirect":                    "SEN-RED-001",
    "ssrf":                             "SEN-SSRF-001",
    "command_injection":                "SEN-CMD-001",
    "xxe":                              "SEN-XXE-001",
    "cors_misconfig":                   "SEN-COR-001",
    "http_response_header_injection":   "SEN-HDR-001",
    "missing_security_headers":         "SEN-HDR-002",
    "vulnerable_js_dependency":         "SEN-DEP-001",
    "idor":                             "SEN-IDOR-001",
    # Phase 56 (v2.8.0): the Intelligence Layer classes
    "idor_bola":                        "SEN-IDOR-001",
    "vertical_privilege_escalation":    "SEN-AUT-001",
    "credential_exposure":              "SEN-SEC-001",
    # v3.0.0/v4.0.0: workflow/business-logic + detector classes with stable rule ids
    "csrf":                             "SEN-CSRF-001",
    "ssti":                             "SEN-SSTI-001",
    "nosql_injection":                  "SEN-NOSQL-001",
    "jwt_security":                     "SEN-JWT-001",
    "host_header_injection":            "SEN-HDR-003",
    "header_injection":                 "SEN-HDR-004",
    "server_banner_disclosure":         "SEN-INF-001",
    "tech_banner_disclosure":           "SEN-INF-002",
    "business_logic_step_bypass":             "SEN-BL-001",
    "business_logic_out_of_order":            "SEN-BL-002",
    "business_logic_value_tamper":            "SEN-BL-003",
    "business_logic_duplicate_execution":     "SEN-BL-004",
    "business_logic_privilege_escalation":    "SEN-BL-005",
    "business_logic_cross_user_execution":    "SEN-BL-006",
    "business_logic_cross_object_execution":  "SEN-BL-007",
    "business_logic_cross_state_execution":   "SEN-BL-008",
}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
               "low": "note", "info": "note"}


def build_sarif(store: Store, run_id: str = "") -> dict:
    """OP-02 (Phase 54): export verified findings as a SARIF 2.1.0 log — the
    industry interchange format for static-analysis results. Same honesty contract
    as the scanner: only VERIFIED findings become results (rejected candidates are
    already excluded from the store's verified set); each result carries the
    evidence chain and the verification method as properties so the SARIF log is
    a standalone audit artifact, not just a count."""
    if run_id:
        run = store.get_run(run_id)
        if not run:
            return {"error": f"run {run_id} not found"}
        findings = run["findings"]
        scan_target = run.get("target", "")
    else:
        findings = store.list_findings(status="verified", limit=500)
        scan_target = ""
    rules, seen = [], set()
    results = []
    for f in findings:
        ftype = f.get("type", "unknown")
        rid = SARIF_RULES.get(ftype, "SEN-GEN-001")
        if rid not in seen:
            seen.add(rid)
            rules.append({"id": rid, "name": ftype,
                          "shortDescription": {"text": f"SENTINEL verified finding class: {ftype}"}})
        ver = f.get("verification") or {}
        evs = "; ".join(f"{e.get('kind', '')}: {str(e.get('detail', ''))[:140]}"
                        for e in (f.get("evidence") or [])[:3])
        results.append({
            "ruleId": rid,
            "ruleIndex": [r["id"] for r in rules].index(rid),
            "level": SARIF_LEVEL.get((f.get("severity") or "info").lower(), "note"),
            "message": {"text": f"{ftype} at {f.get('url', '')}"
                                + (f" (param={f.get('parameter')})" if f.get("parameter") else "")
                                + f" — verified via {ver.get('method', 'n/a')}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.get("url", "")},
                "region": {"snippet": {"text": f.get("parameter") or ""}}}}],
            "properties": {"severity": f.get("severity", ""), "risk": f.get("risk", 0),
                           "confidence": f.get("confidence", 0), "parameter": f.get("parameter", ""),
                           "verification": {"method": ver.get("method", ""), "passed": ver.get("passed", False),
                                            "notes": str(ver.get("notes", ""))[:200]},
                           "evidence": evs[:400]},
            "partialFingerprints": {"sentinelFindingId": f.get("id", "")},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "SENTINEL", "version": VERSION,
                                "informationUri": "https://sentinel.invalid/",
                                "rules": rules}},
            "properties": {"scanTarget": scan_target, "resultCount": len(results),
                           "honesty": "verification-gated: every result passed an independent replay"},
            "results": results,
        }],
    }


def _build_json(store: Store, run_id: str) -> dict:
    if run_id:
        run = store.get_run(run_id)
        if not run:
            return {"error": f"run {run_id} not found"}
        return {"kind": "single-run", "scanner": run["scanner"], "run": run}
    runs = store.list_runs(limit=100)
    return {"kind": "overview", "scanner": f"sentinel-core/{VERSION}",
            "summary": store.stats_summary(),
            "recurring": store.recurring(),
            "latest_delta": store.delta(),
            "runs": runs}


def _build_html(store: Store, run_id: str) -> str:
    e = _html.escape
    if run_id:
        run = store.get_run(run_id)
        if not run:
            return f"<html><body><h1>run {e(run_id)} not found</h1></body></html>"
        findings, rejected = run["findings"], run["rejected_candidates"]
        head = (f"SENTINEL — Run {e(run_id)}", run["target"], run.get("stats", {}))
    else:
        runs = store.list_runs(limit=100)
        findings = store.list_findings(limit=500)
        rejected = []
        head = ("SENTINEL — Cross-run overview",
                f"{len(runs)} runs · {len(findings)} verified findings",
                store.stats_summary())
    rows = []
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        color = SEV_COLORS.get(sev, "#95a5a6")
        evs = "<br>".join(f"{e(ev.get('kind', ''))}: {e(str(ev.get('detail', ''))[:160])}"
                          for ev in (f.get("evidence") or [])[:3])
        ver = f.get("verification") or {}
        rows.append(
            f"<tr><td><span class='pill' style='background:{color}'>{e(sev)}</span></td>"
            f"<td><code>{e(f['type'])}</code></td>"
            f"<td class='u'>{e(f['url'])}</td>"
            f"<td><code>{e(f.get('parameter') or '')}</code></td>"
            f"<td>{f.get('risk', 0)}</td><td>{f.get('confidence', 0)}</td>"
            f"<td class='ev'>{evs}</td>"
            f"<td class='ev'>{e(ver.get('method', ''))}</td></tr>")
    rej_rows = "".join(
        f"<li><code>{e(f['type'])}</code> — {e(f['url'])} param=<code>{e(f.get('parameter') or '')}</code> "
        f"({e((f.get('verification') or {}).get('method', ''))})</li>" for f in rejected)
    rec_rows = "".join(
        f"<li><code>{e(r['type'])}</code> {e(r['url'])} param=<code>{e(r['parameter'] or '')}</code> "
        f"— seen in <b>{r['n_runs']}</b> runs</li>" for r in store.recurring())
    delta = store.delta()
    title, subtitle, stats = head
    # Phase 56: Coverage & Application Map section (present when the run carried
    # the Intelligence Layer stats — older runs degrade gracefully to absent).
    cov = stats.get("coverage") if isinstance(stats, dict) else None
    amap = stats.get("appmap") if isinstance(stats, dict) else None
    intel_html = ""
    if cov or amap:
        cov_box = ""
        if cov:
            reasons = ", ".join(f"{e(str(k))}: {v}" for k, v in (cov.get("skip_reasons") or {}).items())
            cov_box = (f"<div class='box'>Discovered <b>{cov.get('discovered', 0)}</b> · "
                       f"tested <b>{cov.get('tested', 0)}</b> "
                       f"({cov.get('coverage_pct', 0)}%) · passive {cov.get('passive', 0)} · "
                       f"active {cov.get('active', 0)} · authz {cov.get('authz_probed', 0)} · "
                       f"untested <b>{cov.get('untested', 0)}</b>"
                       + (f"<br>Skip reasons — {reasons}" if reasons else "") + "</div>")
        amap_box = ""
        if amap:
            surf = amap.get("surfaces") or {}
            roles = ", ".join((amap.get("authentication") or {}).get("roles_tested", [])) or "—"
            dobj = ", ".join(sorted((amap.get("data_objects") or {}).keys())) or "—"
            amap_box = (f"<div class='box' style='margin-top:10px'>"
                        f"Surfaces — pages {surf.get('page', {}).get('count', 0)}, "
                        f"APIs {surf.get('api', {}).get('count', 0)}, "
                        f"actions {surf.get('form_or_action', {}).get('count', 0)}, "
                        f"statics {surf.get('static', {}).get('count', 0)}"
                        f"<br>Auth mode: {e(str((amap.get('authentication') or {}).get('mode', '—')))} · "
                        f"roles tested: {e(roles)}"
                        f"<br>Data objects: {e(dobj)}</div>")
        intel_html = (f"<section><h2>Coverage & Application Map (Phase 56)</h2>"
                      f"{cov_box}{amap_box}</section>")
    stat_items = "".join(f"<div class='stat'><b>{e(str(v))}</b><span>{e(str(k))}</span></div>"
                         for k, v in (stats.items() if isinstance(stats, dict)
                                      else zip(["requests", "endpoints", "verified", "rejected"],
                                               [stats.get("requests", 0) if isinstance(stats, dict) else 0,
                                                stats.get("endpoints", 0) if isinstance(stats, dict) else 0,
                                                len(findings), len(rejected)])))
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{e(title)}</title>
<style>
 body{{font-family:'Segoe UI',system-ui,sans-serif;margin:0;background:#0f1216;color:#e8e8e8}}
 header{{padding:28px 36px;background:linear-gradient(135deg,#161c24,#1c2733);border-bottom:3px solid #e74c3c}}
 h1{{margin:0;font-size:22px;letter-spacing:.5px}} .sub{{color:#9ab;margin-top:6px;font-size:13px}}
 section{{padding:20px 36px}} h2{{font-size:15px;color:#d5dde5;border-left:3px solid #e74c3c;padding-left:10px}}
 .stats{{display:flex;gap:14px;flex-wrap:wrap;margin:14px 0}}
 .stat{{background:#1a2028;border:1px solid #2a3440;border-radius:8px;padding:12px 20px;min-width:110px;text-align:center}}
 .stat b{{display:block;font-size:24px;color:#fff}} .stat span{{font-size:11px;color:#8fa;text-transform:uppercase}}
 table{{width:100%;border-collapse:collapse;font-size:12.5px}}
 th{{text-align:left;padding:8px;background:#1a2028;color:#9ab;text-transform:uppercase;font-size:10.5px;letter-spacing:.5px}}
 td{{padding:8px;border-bottom:1px solid #222b34;vertical-align:top}}
 .u{{font-family:monospace;color:#7fd;font-size:11.5px;word-break:break-all}}
 .ev{{font-size:10.5px;color:#9aa8b5}} code{{color:#ffd479}}
 .pill{{color:#fff;border-radius:10px;padding:2px 9px;font-size:10.5px;font-weight:600;text-transform:uppercase}}
 .box{{background:#1a2028;border:1px solid #2a3440;border-radius:8px;padding:14px 18px;font-size:12.5px}}
 ul{{margin:6px 0;padding-left:18px}} li{{margin:4px 0}}
 footer{{padding:16px 36px;color:#566;font-size:11px;border-top:1px solid #1c242e}}
</style></head><body>
<header><h1>{e(title)}</h1><div class="sub">{e(str(subtitle))}</div></header>
<section><h2>Statistics</h2><div class="stats">{stat_items}</div></section>
{intel_html}
<section><h2>Verified findings ({len(findings)})</h2>
<table><tr><th>Sev</th><th>Type</th><th>URL</th><th>Param</th><th>Risk</th><th>Conf</th><th>Evidence</th><th>Verification</th></tr>
{''.join(rows) or '<tr><td colspan="8">None</td></tr>'}</table></section>
<section><h2>Recurring across runs</h2><div class="box"><ul>{rec_rows or '<li>None</li>'}</ul></div>
<div class="box" style="margin-top:10px">Latest delta — new: <b>{len(delta.get('new', []))}</b>,
fixed: <b>{len(delta.get('fixed', []))}</b>, recurring: <b>{len(delta.get('recurring', []))}</b></div></section>
<section><h2>Rejected candidates (verification-gate audit trail, {len(rejected)})</h2>
<div class="box"><ul>{rej_rows or '<li>None</li>'}</ul></div></section>
<footer>sentinel-core/{VERSION} — deterministic DAST · verification-gated: every finding above passed an independent replay</footer>
</body></html>"""


# ============================================================ Phase 64 (v4.0.0): Glass dashboard
# The iOS-style frosted-glass view of the Security Digital Twin — one
# self-contained HTML artifact (inline CSS, zero external assets) that an
# executive or an engineer can open anywhere. Arabic-first RTL: SENTINEL's
# operator language, with technical class names kept in English on purpose.

def build_glass_html(store: Store, run_id: str = "") -> str:
    e = _html.escape
    if run_id:
        run = store.get_run(run_id)
    else:
        runs = store.list_runs(limit=1)
        run = store.get_run(runs[0]["run_id"]) if runs else None
    if not run:
        return "<html><body dir='rtl'><h1>لا يوجد فحص محفوظ</h1></body></html>"
    findings = run.get("findings", [])
    stats = run.get("stats", {}) or {}
    twin = stats.get("digital_twin") or {}
    cov = stats.get("coverage") or {}
    reasoning = stats.get("reasoning") or {}
    planner = stats.get("planner") or {}
    proofs = stats.get("proofs") or []
    azm = twin.get("authorization_matrix") or {}
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[(f.get("severity") or "info").lower()] = by_sev.get((f.get("severity") or "info").lower(), 0) + 1
    posture = next((s for s in ("critical", "high", "medium", "low", "info") if by_sev.get(s)), "clean")
    POSTURE_AR = {"critical": "خطر حرج", "high": "خطر مرتفع", "medium": "خطر متوسط",
                  "low": "خطر منخفض", "info": "معلومات", "clean": "سليم"}
    POSTURE_GRAD = {"critical": "linear-gradient(135deg,#ff2d55,#ff6b6b)",
                    "high": "linear-gradient(135deg,#ff9500,#ff6b3d)",
                    "medium": "linear-gradient(135deg,#ffd60a,#ff9f0a)",
                    "low": "linear-gradient(135deg,#0a84ff,#64d2ff)",
                    "info": "linear-gradient(135deg,#8e8e93,#aeaeb2)",
                    "clean": "linear-gradient(135deg,#30d158,#66d4cf)"}
    top = sorted(findings, key=lambda f: -int(f.get("risk") or 0))[:10]

    def chip(sev: str, n) -> str:
        return (f"<div class='chip'><span class='dot' style='background:{SEV_COLORS.get(sev, '#95a5a6')}'></span>"
                f"{POSTURE_AR.get(sev, sev)} <b>{n}</b></div>")

    sev_chips = "".join(chip(s, by_sev[s]) for s in ("critical", "high", "medium", "low", "info")
                        if by_sev.get(s)) or "<div class='chip'>لا نتائج موجبة</div>"

    def stat_card(icon: str, value, label_ar: str, sub: str = "") -> str:
        return (f"<div class='card'><div class='ic'>{icon}</div>"
                f"<div class='val'>{e(str(value))}</div><div class='lbl'>{e(label_ar)}</div>"
                + (f"<div class='sub'>{e(sub)}</div>" if sub else "") + "</div>")

    cards = "".join([
        stat_card("🧠", twin.get("nodes", 0), "عقد التوأم الرقمي",
                  f"{twin.get('edges', 0)} حافة · {twin.get('entities', 0)} كيان"),
        stat_card("👥", twin.get("identities", 0), "هويات مُختبرة",
                  f"{twin.get('roles', 0)} أدوار"),
        stat_card("🔀", len(twin.get("flows", [])), "سير عمل مُتعلَّم",
                  f"{twin.get('workflow_steps', 0)} خطوات · {twin.get('states_observed', 0)} حالات"),
        stat_card("🎯", f"{cov.get('coverage_pct', 0)}%", "إثبات التغطية",
                  f"{cov.get('tested', 0)}/{cov.get('discovered', 0)} سطح مُختبر"),
        stat_card("🧪", reasoning.get("verified", 0), "فرضيات مُثبتة",
                  f"من {reasoning.get('generated', 0)} فرضية · {reasoning.get('refuted', 0)} مُنفية"),
        stat_card("🛡️", planner.get("operations_evaluated", 0), "عمليات قُيّمت أمانًا",
                  f"محجوبة: {planner.get('blocked', 0)}"),
    ])

    def top_row(f) -> str:
        sev = (f.get("severity") or "info").lower()
        return (f"<div class='risk'><div class='rhead'><span class='pill' "
                f"style='background:{SEV_COLORS.get(sev, '#95a5a6')}'>{e(sev)}</span>"
                f"<code>{e(f.get('type', ''))}</code>"
                f"<span class='riskn'>{f.get('risk', 0)}</span></div>"
                f"<div class='rurl'>{e((f.get('url') or '').split('?')[0])}"
                + (f" · <code>{e(f.get('parameter'))}</code>" if f.get("parameter") else "") + "</div>"
                f"<div class='rver'>إثبات: {e((f.get('verification') or {}).get('method', '—'))}</div></div>")
    top_html = "".join(top_row(f) for f in top) or "<div class='risk'>لا نتائج موجبة</div>"

    az_rows = ""
    for role, verdicts in sorted(azm.items()):
        cells = "".join(f"<div class='azcell'><span>{e(v)}</span><b>{len(s)}</b></div>"
                        for v, s in sorted(verdicts.items()))
        az_rows += f"<div class='azrow'><div class='azrole'>{e(role)}</div>{cells}</div>"
    az_html = az_rows or "<div class='sub'>لم يُشغَّل محرك التفويض متعدد المستخدمين</div>"

    flow_rows = ""
    for fl in twin.get("flows", []):
        flow_rows += (f"<div class='flow'><div class='fcluster'>{e(fl['cluster'])}</div>"
                      f"<div class='fsteps'>{fl.get('steps', 0)} خطوات · أوراكل: "
                      f"<code>{e(fl.get('oracle', '—'))}</code></div></div>")
    flows_html = flow_rows or "<div class='sub'>لا سير عمل مُتعلَّم في هذا الفحص</div>"

    proof_rows = "".join(
        f"<div class='proof'><code>{e(p.get('type', ''))}</code>"
        f"<div class='pstep'>{' ⟶ '.join(e(s.get('request', '')[:70]) for s in p.get('reproduction', [])[:3])}</div></div>"
        for p in proofs[:8]) or "<div class='sub'>لا ملفات إثبات</div>"

    return f"""<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SENTINEL — التوأم الرقمي الأمني</title>
<style>
 *{{box-sizing:border-box;margin:0;padding:0}}
 body{{font-family:-apple-system,'SF Pro Display','Segoe UI',system-ui,sans-serif;
   background:#050507;color:#f5f5f7;min-height:100vh;overflow-x:hidden;
   -webkit-font-smoothing:antialiased}}
 .bg{{position:fixed;inset:0;z-index:-1;background:
   radial-gradient(60% 50% at 85% 10%,rgba(10,132,255,.28),transparent 60%),
   radial-gradient(50% 40% at 10% 25%,rgba(191,90,242,.22),transparent 60%),
   radial-gradient(45% 45% at 70% 90%,rgba(255,45,85,.16),transparent 60%),
   radial-gradient(40% 40% at 20% 80%,rgba(48,209,88,.14),transparent 60%),#050507}}
 .wrap{{max-width:1180px;margin:0 auto;padding:34px 22px 60px}}
 header{{display:flex;align-items:center;gap:18px;margin-bottom:30px}}
 .logo{{width:52px;height:52px;border-radius:15px;display:flex;align-items:center;justify-content:center;
   font-size:26px;background:linear-gradient(135deg,#0a84ff,#bf5af2);box-shadow:0 8px 30px rgba(10,132,255,.45)}}
 h1{{font-size:26px;font-weight:800;letter-spacing:-.3px}}
 .meta{{color:rgba(245,245,247,.55);font-size:12.5px;margin-top:3px}}
 .posture{{margin-inline-start:auto;text-align:center;padding:14px 26px;border-radius:22px;
   background:{POSTURE_GRAD.get(posture, '#8e8e93')};box-shadow:0 10px 40px rgba(0,0,0,.45);
   border:1px solid rgba(255,255,255,.25)}}
 .posture b{{display:block;font-size:20px;font-weight:800}}
 .posture span{{font-size:11px;opacity:.85}}
 .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:22px}}
 .card{{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.13);border-radius:22px;
   padding:18px 16px;backdrop-filter:blur(28px) saturate(160%);-webkit-backdrop-filter:blur(28px) saturate(160%);
   box-shadow:0 14px 40px rgba(0,0,0,.35);transition:transform .25s ease,background .25s ease;cursor:default}}
 .card:hover{{transform:translateY(-4px);background:rgba(255,255,255,.10)}}
 .ic{{font-size:22px;margin-bottom:8px}}
 .val{{font-size:30px;font-weight:800;letter-spacing:-.5px}}
 .lbl{{font-size:12.5px;color:rgba(245,245,247,.65);margin-top:3px}}
 .sub{{font-size:10.5px;color:rgba(245,245,247,.42);margin-top:6px}}
 .panel{{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);border-radius:26px;
   padding:22px;backdrop-filter:blur(30px) saturate(160%);-webkit-backdrop-filter:blur(30px) saturate(160%);
   box-shadow:0 16px 50px rgba(0,0,0,.38);margin-bottom:20px}}
 .panel h2{{font-size:15px;font-weight:700;margin-bottom:14px;display:flex;align-items:center;gap:8px}}
 .panel h2::before{{content:'';width:4px;height:18px;border-radius:2px;
   background:linear-gradient(#0a84ff,#bf5af2)}}
 .chips{{display:flex;gap:10px;flex-wrap:wrap}}
 .chip{{display:flex;align-items:center;gap:7px;background:rgba(255,255,255,.08);
   border:1px solid rgba(255,255,255,.14);border-radius:999px;padding:7px 15px;font-size:12.5px}}
 .dot{{width:9px;height:9px;border-radius:50%}}
 .risk{{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.10);border-radius:17px;
   padding:13px 16px;margin-bottom:9px}}
 .rhead{{display:flex;align-items:center;gap:10px;font-size:13px}}
 .pill{{color:#fff;border-radius:999px;padding:2.5px 11px;font-size:10px;font-weight:700;text-transform:uppercase}}
 .riskn{{margin-inline-start:auto;font-weight:800;color:rgba(245,245,247,.75);font-size:15px}}
 .rurl{{font-family:ui-monospace,monospace;font-size:11px;color:#64d2ff;margin-top:6px;
   direction:ltr;text-align:right;word-break:break-all}}
 .rver{{font-size:10.5px;color:rgba(245,245,247,.45);margin-top:3px}}
 code{{font-family:ui-monospace,monospace;color:#ffd60a;font-size:12px}}
 .azrow{{display:flex;align-items:center;gap:10px;margin-bottom:9px;flex-wrap:wrap}}
 .azrole{{background:linear-gradient(135deg,#0a84ff,#64d2ff);border-radius:13px;padding:7px 15px;
   font-size:12px;font-weight:700;min-width:86px;text-align:center}}
 .azcell{{display:flex;align-items:center;gap:6px;background:rgba(255,255,255,.07);
   border:1px solid rgba(255,255,255,.13);border-radius:12px;padding:6px 13px;font-size:11.5px}}
 .azcell span{{color:rgba(245,245,247,.55)}} .azcell b{{font-size:13px}}
 .flow{{display:flex;align-items:center;gap:14px;background:rgba(255,255,255,.05);
   border:1px solid rgba(255,255,255,.10);border-radius:16px;padding:12px 16px;margin-bottom:8px}}
 .fcluster{{font-family:ui-monospace,monospace;color:#bf5af2;font-size:12.5px;direction:ltr}}
 .fsteps{{font-size:11.5px;color:rgba(245,245,247,.6)}}
 .proof{{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.10);border-radius:16px;
   padding:11px 15px;margin-bottom:8px}}
 .pstep{{font-size:10.5px;color:rgba(245,245,247,.55);margin-top:5px;direction:ltr;text-align:left}}
 footer{{text-align:center;color:rgba(245,245,247,.35);font-size:11px;margin-top:8px}}
 @media (max-width:760px){{.posture{{margin:0}} header{{flex-wrap:wrap}} .wrap{{padding:22px 14px 40px}}}}
</style></head><body><div class="bg"></div><div class="wrap">
<header><div class="logo">🛡️</div>
 <div><h1>SENTINEL — التوأم الرقمي الأمني</h1>
 <div class="meta">{e(run.get("target", ""))} · فحص {e(run["run_id"])} · {e(run.get("scanner", ""))}</div></div>
 <div class="posture"><b>{POSTURE_AR.get(posture, posture)}</b><span>{len(findings)} نتيجة مؤكدة قابلة للإثبات</span></div>
</header>
<div class="grid">{cards}</div>
<div class="panel"><h2>توزيع الخطر</h2><div class="chips">{sev_chips}</div></div>
<div class="panel"><h2>أعلى المخاطر المثبتة</h2>{top_html}</div>
<div class="panel"><h2>مصفوفة التفويض القابلة للإثبات (دور × حكم وصول)</h2>{az_html}</div>
<div class="panel"><h2>سير العمل المُتعلَّم (سلاسل متعددة الخطوات)</h2>{flows_html}</div>
<div class="panel"><h2>ملفات الإثبات — إعادة الإنتاج خطوة بخطوة</h2>{proof_rows}</div>
<footer>sentinel-core/{VERSION} · كل نتيجة أعلاه اجتازت إعادة تشغيل مستقلة · عقد التوأم: {twin.get('nodes', 0)} · حواف: {twin.get('edges', 0)}</footer>
</div></body></html>"""

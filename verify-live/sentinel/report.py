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

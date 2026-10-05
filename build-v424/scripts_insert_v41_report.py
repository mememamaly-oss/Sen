#!/usr/bin/env python3
"""Insert the v4.1 HTML report sections into report.py (build tool)."""
import re

V41_BLOCK = '''
        # ================= v4.1.0 sections (Phase V41-15) =================
        # The unified boundary-honest report: what SENTINEL knows / verified /
        # refuted / could not test / why / what is unsupported / what safety
        # blocked — plus multi-dimensional coverage, the API inventory,
        # workflow graphs, the identity x action matrix, memory and the
        # twin's why() answers.
        def _v41_sections(istats: dict) -> str:
            out = []
            bnd = istats.get("boundary") or {}
            if bnd.get("records"):
                by_state = "".join(
                    f"<tr><td><code>{e(k)}</code></td><td>{v}</td></tr>"
                    for k, v in (bnd.get("by_state") or {}).items())
                limits = "".join(
                    f"<tr><td><code>{e(b.get('category',''))}</code></td>"
                    f"<td>{e(b.get('state',''))}</td>"
                    f"<td>{e((b.get('reason') or '')[:110])}</td>"
                    f"<td>{e((b.get('remediation') or '')[:80])}</td></tr>"
                    for b in (bnd.get("unresolved_detail") or [])[:25])
                out.append(
                    "<section><h2>Boundary Intelligence — ما لم يُختبر ولماذا (v4.1.0)</h2>"
                    f"<div class='box'>سجلات حدود المعرفة: <b>{bnd.get('records', 0)}</b> · "
                    f"غير محلولة: <b>{bnd.get('unresolved', 0)}</b> — كل عنصر غير مختبر "
                    "مُدرج بسببه؛ لا شيء يُدّعى مختبرًا دون دليل.</div>"
                    "<table style='margin-top:10px'><tr><th>State</th><th>Count</th></tr>"
                    f"{by_state}</table>"
                    "<table style='margin-top:10px'><tr><th>Category</th><th>State</th>"
                    f"<th>Reason</th><th>Remediation</th></tr>{limits}</table></section>")
            dims = (istats.get("coverage") or {}).get("dimensions") or {}
            if dims:
                drows = "".join(
                    f"<tr><td><code>{e(d.get('dimension',''))}</code></td>"
                    f"<td>{d.get('discovered', 0)}</td><td>{d.get('tested', 0)}</td>"
                    f"<td>{d.get('untested', 0)}</td><td>{d.get('pct', 0)}%</td>"
                    f"<td>{e(d.get('status',''))}"
                    + (f" <span style='color:#e67e22'>({e((d.get('note') or '')[:60])})</span>"
                       if d.get("status") == "NOT_DISCOVERED" else "")
                    + "</td></tr>"
                    for d in dims.values())
                out.append(
                    "<section><h2>Coverage 2.0 — التغطية متعددة الأبعاد (v4.1.0)</h2>"
                    "<div class='box'>كل بُعد قابل للتدقيق؛ الأبعاد غير المكتشفة "
                    "تُعرض كـ NOT_DISCOVERED — ولا تُعرض 100% مع بنود جوهرية غير مختبرة.</div>"
                    "<table style='margin-top:10px'><tr><th>Dimension</th><th>Discovered</th>"
                    f"<th>Tested</th><th>Untested</th><th>%</th><th>Status</th></tr>{drows}</table></section>")
            api = istats.get("api_inventory") or {}
            if api.get("total"):
                arows = "".join(
                    f"<tr><td><code>{e(a.get('protocol',''))}</code></td>"
                    f"<td>{e(a.get('method',''))}</td>"
                    f"<td><code>{e((a.get('path') or '/')[:60])}</code></td>"
                    f"<td>{e(', '.join((a.get('sources') or [])[:3]))}</td>"
                    f"<td>{a.get('findings', 0)}</td>"
                    f"<td>{e(str(a.get('coverage_status','')))}</td></tr>"
                    for a in (api.get("apis") or [])[:60])
                out.append(
                    "<section><h2>API Inventory — الجرد الموحد (v4.1.0)</h2>"
                    f"<div class='box'>إجمالي: <b>{api.get('total', 0)}</b> · حسب البروتوكول: "
                    f"<code>{e(json.dumps(api.get('by_protocol', {}), ensure_ascii=False))}</code>"
                    " — REST · OpenAPI · GraphQL · WebSocket في جرد واحد.</div>"
                    "<table style='margin-top:10px'><tr><th>Protocol</th><th>Method</th>"
                    f"<th>Path/Channel</th><th>Sources</th><th>Findings</th>"
                    f"<th>Coverage</th></tr>{arows}</table></section>")
            flows = (istats.get("workflow") or {}).get("flows") or []
            if flows:
                frows = []
                for fl in flows:
                    graph = fl.get("graph") or {}
                    counts = graph.get("counts") or {}
                    branches = fl.get("branches") or []
                    br_txt = ", ".join(
                        f"{e(b.get('field',''))}={e(b.get('value',''))} ({e(b.get('class',''))}"
                        + (", functional" if b.get("functional") else "") + ")"
                        for b in branches[:3]) or "none"
                    frows.append(
                        f"<li><code>{e(fl.get('cluster',''))}</code>: "
                        f"{len(fl.get('steps') or [])} steps · {counts.get('branches', 0)} branches · "
                        f"approval={e(str(fl.get('approval_step') or 'none'))} · "
                        f"rollback_paths={len(fl.get('rollback_only_paths') or [])} · "
                        f"branches: {br_txt}</li>")
                out.append(
                    "<section><h2>Workflow Graphs 2.0 — الفروع والحالات (v4.1.0)</h2>"
                    f"<div class='box'><ul>{''.join(frows)}</ul></div></section>")
            am = istats.get("action_matrix") or {}
            if am.get("matrix"):
                mrows = "".join(
                    f"<tr><td><b>{e(i.get('name',''))}</b> <small>({e(i.get('role',''))})</small></td>"
                    + "".join(
                        f"<td title='{e(str((am['matrix'].get(i['name'], {}).get(act, ''))[:120])}'>"
                        f"{e(str((am['matrix'].get(i['name'], {}).get(act, ''))[:34])}</td>"
                        for act in (am.get("actions") or []))
                    + "</tr>"
                    for i in (am.get("identities") or []))
                out.append(
                    "<section><h2>Identity × Action Matrix — مصفوفة التفويض (v4.1.0)</h2>"
                    "<div class='box'>الأدوار مُكتشفة من التطبيق (لا أدوار مفترضة)؛ "
                    "كل خلية تحمل حكمها الصادق بما في ذلك untested بسببها.</div>"
                    "<table style='margin-top:10px'><tr><th>Identity</th>"
                    + "".join(f"<th>{e(a)}</th>" for a in (am.get("actions") or []))
                    + f"</tr>{mrows}</table></section>")
            mem = istats.get("memory") or {}
            if mem:
                out.append(
                    "<section><h2>Security Memory — سياق عبر الجلسات (v4.1.0)</h2>"
                    "<div class='box'>"
                    + (f"تطبيق معروف: <b>{mem.get('prior_runs', 0)}</b> فحص سابق · "
                       f"نتائج مثبتة سابقًا: <b>{mem.get('previously_verified', 0)}</b> · "
                       + ("<b style='color:#e74c3c'>تغيّر التطبيق — التحققات السابقة "
                          "قديمة وتحتاج إعادة تثبيت</b>" if mem.get("app_changed")
                          else "بصمة التطبيق دون تغيير")
                       if mem.get("known_app") else
                       "لا معرفة سابقة بهذا التطبيق (ذاكرة معزولة لكل مضيف)")
                    + f"<br><small>{e(mem.get('policy', ''))}</small></div></section>")
            why = (istats.get("digital_twin") or {}).get("why_examples") or []
            if why:
                wrows = "".join(
                    f"<li><code>{e(w.get('kind',''))}: {e(str(w.get('key',''))[:50])}</code> "
                    f"→ belief=<b>{e(w.get('belief',''))}</b> · "
                    f"provenance=<i>{e((w.get('provenance') or '')[:80])}</i></li>"
                    for w in why if w.get("found"))
                if wrows:
                    out.append(
                        "<section><h2>Why does SENTINEL believe this? — أساس كل اعتقاد "
                        f"(v4.1.0)</h2><div class='box'><ul>{wrows}</ul></div></section>")
            return "".join(out)

        v41_html = _v41_sections(intel_stats)
'''

src = open("sentinel/report.py").read()
anchor = '''        intel_html = (f"<section><h2>Coverage & Application Map (Phase 56)</h2>"
                      f"{cov_box}{amap_box}</section>")'''
assert src.count(anchor) == 1, f"anchor count = {src.count(anchor)}"
src = src.replace(anchor, anchor + "\n" + V41_BLOCK)

# insert the v41_html into the template after {intel_html}
old_tpl = "{intel_html}\n<section><h2>Verified findings ({len(findings)})</h2>"
assert src.count(old_tpl) == 1, f"tpl count = {src.count(old_tpl)}"
src = src.replace(old_tpl, "{intel_html}\n{v41_html}\n<section><h2>Verified findings ({len(findings)})</h2>")
open("sentinel/report.py", "w").write(src)
print("v4.1 sections inserted into _build_html")

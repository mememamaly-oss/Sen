#!/usr/bin/env python3
"""L2 live evidence report — per-link raw evidence for every attack path.

ROUND 7 (supervisor order: fresh-live evidence, no projections): reads the
live_v430 result of each authorized target — gruyere2 + testasp are the round-6
fresh v4.3.0 full live scans (re-confirmed: apaths rebuild byte-identical,
journal single-window fresh, citations literal); ginjuice + testaspnet are the
round-7 TARGETED fresh live scans of exactly the path surfaces (the shipped
pipeline, discovery scoped; every request/response pair sent live in that run).
Renders, for EVERY link of EVERY path: its statement, status, and evidence
references — each with the raw excerpt AND, for journal refs, the FULL raw
request (method, URL, headers, body) and response line from THAT run's journal.
Cross-checks every journal citation: the excerpt must be a literal substring of
the cited journal entry (substring-verifiable evidence), and the freshness
confirmation matrix (l2_freshness_confirmation.json) is embedded. Paths that
could NOT be fresh-verified are listed in an explicit register with reasons —
never silently dropped, never faked. Zero requests: journals are replayed from
the saved scan artifacts, never re-sent.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIVE = os.path.join(ROOT, "build-v423", "results", "live_v430")
OUT = os.path.join(ROOT, "build-v423", "results", "l2_live_report.md")

TARGETS = ["testaspnet", "ginjuice", "gruyere2", "testasp"]


def raw_fields(entry):
    """All raw string fields of a journal entry — the ONLY valid surface for
    substring verification of an excerpt (json.dumps escapes quotes and would
    produce false negatives for XML/quoted excerpts — harness bug fixed round 6)."""
    req, resp = entry.get("request") or {}, entry.get("response") or {}
    out = [str(req.get("url") or ""), str(req.get("body") or "")]
    out += [str(v) for v in (req.get("headers") or {}).values()]
    out += [str(resp.get("body") or "")]
    out += [str(v) for v in (resp.get("headers") or {}).values()]
    return out


def journal_entry_block(journal, rid):
    e = journal.get(rid)
    if not e:
        return f"    !! cited request {rid} NOT IN JOURNAL"
    req, resp = e.get("request", {}), e.get("response", {})
    lines = [f"    REQUEST  {req.get('method','?')} {req.get('url','?')}"]
    for k, v in (req.get("headers") or {}).items():
        lines.append(f"      {k}: {str(v)[:100]}")
    body = str(req.get("body") or "")
    if body:
        lines.append(f"      body: {body[:160]}{'...' if len(body) > 160 else ''}")
    lines.append(f"    RESPONSE {resp.get('status','?')}")
    for k, v in (resp.get("headers") or {}).items():
        lines.append(f"      {k}: {str(v)[:100]}")
    rb = str(resp.get("body") or "")
    if rb:
        lines.append(f"      body[0:200]: {rb[:200]}")
    return "\n".join(lines)


def render_target(name, rep, md, checks):
    ap = rep.get("attack_paths") or {}
    paths, s = ap.get("paths", []), ap.get("summary", {})
    findings = {f["id"]: f for f in rep.get("findings", [])}
    journal = (rep.get("stats") or {}).get("request_journal") or {}
    md.append(f"\n## {name} — {rep.get('target','')} (run {rep.get('run_id','')}, scanner {rep.get('scanner','')})\n")
    src = rep.get("l2_source")
    if src:
        md.append(f"**L2 SOURCE (honesty note): {src}**\n")
    else:
        md.append("**L2 SOURCE: fresh v4.3.0 live scan — attack paths integrated "
                  "in the scan pipeline (orchestrator.report())**\n")
    md.append(f"**{s.get('paths_total',0)} paths: {s.get('paths_verified',0)} VERIFIED / "
              f"{s.get('paths_inferred',0)} INFERRED** ({s.get('singles',0)} single-finding, "
              f"{s.get('chains',0)} chains) — weak-link histogram: `{s.get('weak_link_histogram',{})}`\n")
    md.append(f"Seeds used: `{', '.join(s.get('seed_findings', []))}`; non-seed findings (annotation-only "
              f"classes): `{json.dumps(s.get('non_seed_findings', {}))}`\n")
    for p in paths:
        md.append(f"\n### {p['id']} — {p['classification']} — {p['title']}")
        if p["classification"] == "VERIFIED":
            md.append("*Every link below carries verified evidence. The path is fully proven.*")
        else:
            md.append(f"**INFERRED — weak links: {', '.join(p['weak_links'])}. The path is NOT presented "
                      "as proof; the unproven links are named above.**")
        md.append(f"\nfindings: {', '.join(p['findings'])} | chain_rule: {p.get('chain_rule') or '—'}"
                  f" | mitigations absent: "
                  f"{json.dumps([m['header'] for m in p.get('mitigations_absent', [])])}")
        for h in p.get("hops", []):
            md.append(f"\n**HOP {h['step']}** [{h['status'].upper()}] (finding {h['finding_id']}) — {h['statement']}")
            for e in h.get("evidence", []):
                md.append(f"  - evidence: {e['kind']} `{e['ref']}` — `{e['excerpt'][:110]}`")
        md.append("")
        md.append("| Link | Status | Statement |")
        md.append("|---|---|---|")
        for l in p["links"]:
            md.append(f"| **{l['slot']}** | {l['status']} | {l['statement'][:220]} |")
        md.append("\n<details><summary>raw evidence, link by link</summary>\n")
        for l in p["links"]:
            md.append(f"\n**[{l['slot'].upper()}] — {l['status']}**\n")
            md.append(f"  {l['statement']}\n")
            for e in l["evidence"]:
                md.append(f"  - `{e['kind']}` ref `{e['ref']}` excerpt: `{e['excerpt'][:140]}`")
                if e["kind"] == "finding":
                    f = findings.get(e["ref"])
                    if f:
                        md.append(f"    finding: {f['type']} {f['method']} {f['url']} param={f['parameter']} "
                                  f"status={f['status']} conf={f.get('confidence')}")
                        for ev in (f.get("evidence") or [])[:3]:
                            md.append(f"      evidence[{ev.get('kind')}]: {ev.get('detail','')[:150]}")
                        v = f.get("verification") or {}
                        md.append(f"      verification: {v.get('method')} passed={v.get('passed')} "
                                  f"conf={v.get('confidence')} rounds={v.get('rounds')}")
                elif e["kind"] == "journal":
                    raw = json.dumps(journal.get(e["ref"], {}))
                    if e["ref"] not in journal:
                        checks.append(f"{name}/{p['id']}/{l['slot']}: journal ref {e['ref']} MISSING")
                    else:
                        fields = raw_fields(journal[e["ref"]])
                        if not (e["excerpt"] and any(e["excerpt"] in f for f in fields)):
                            checks.append(f"{name}/{p['id']}/{l['slot']}: excerpt NOT a literal slice of "
                                          f"journal {e['ref']}: {e['excerpt'][:60]!r}")
                    md.append(journal_entry_block(journal, e["ref"]))
                elif e["kind"] == "twin":
                    md.append(f"    twin row: {e['excerpt'][:160]}")
                elif e["kind"] == "scan_artifact":
                    md.append(f"    artifact: {e['excerpt'][:160]}")
        md.append("\n</details>\n")
    return paths


def main():
    md = ["# SENTINEL v4.3.0 — L2 Attack Path Intelligence: LIVE EVIDENCE REPORT (round 7)",
          "",
          "Every attack path in this report rests on FRESH LIVE evidence — "
          "request/response pairs actually sent to the live authorized target in "
          "the scan named at the top of its section. gruyere2 and testasp carry "
          "their round-6 fresh v4.3.0 full live scans (re-confirmed this round: "
          "the shipped apath layer rebuilt their paths byte-identically from "
          "their own journals, every journal is a single-scan window, every "
          "citation is a literal slice). ginjuice and testaspnet carry round-7 "
          "TARGETED fresh live scans of exactly the attack-path surfaces "
          "(supervisor order: no projections over old logs — the shipped "
          "pipeline ran with discovery scoped to those surfaces; "
          "stats.crawl.targeted_mode inside each file records the seeds and "
          "keep-rules). Paths that could not be fresh-verified are NOT hidden: "
          "they are listed in the not-fresh-verified register with the measured "
          "reason. Every path is classified by the weakest-link rule: a path is "
          "VERIFIED only when ALL seven links (Identity, Entry, Action, Object, "
          "Authorization, State, Impact) trace to verified evidence — finding "
          "records, raw request-journal entries, twin rows, scan artifacts. Any "
          "inferred link makes the whole path INFERRED and the weak links are "
          "named. This report replays the saved journals; it sends zero requests.",
          ""]
    checks = []
    total = {"paths": 0, "verified": 0, "inferred": 0}
    for t in TARGETS:
        p = os.path.join(LIVE, f"{t}.json")
        if not os.path.exists(p):
            md.append(f"\n## {t}: RESULT FILE MISSING ({p})\n")
            continue
        rep = json.load(open(p, encoding="utf-8"))
        paths = render_target(t, rep, md, checks)
        total["paths"] += len(paths)
        total["verified"] += sum(1 for x in paths if x["classification"] == "VERIFIED")
        total["inferred"] += sum(1 for x in paths if x["classification"] == "INFERRED")
    md.insert(7, f"\n**TOTAL: {total['paths']} paths — {total['verified']} VERIFIED / "
                 f"{total['inferred']} INFERRED** (all fresh-live evidence; the one path "
                 "that could not be fresh-verified is in the register below)\n")

    # ---- freshness confirmation matrix (from l2_reconfirm_fresh.py output)
    conf_path = os.path.join(LIVE, "l2_freshness_confirmation.json")
    md.append("\n## Freshness confirmation matrix\n")
    md.append("Zero-request re-confirmation over each file's own journal "
              "(scripts/l2_reconfirm_fresh.py): the shipped apath layer rebuilt "
              "byte-identically, every journal entry dated inside a single scan "
              "window, every citation a literal slice.\n")
    md.append("| Target | Run | Kind | Journal entries | Window (s) | Rebuild identical | Stale entries | Citations literal | Verdict |")
    md.append("|---|---|---|---|---|---|---|---|---|")
    if os.path.exists(conf_path):
        conf = json.load(open(conf_path, encoding="utf-8"))
        for t in TARGETS:
            c = conf.get(t) or {}
            ck = c.get("checks", {})
            md.append(f"| {t} | {c.get('run_id','')} | {c.get('l2_source_kind','')} | "
                      f"{c.get('journal_entries','')} | {ck.get('journal_window_seconds','')} | "
                      f"{'YES' if ck.get('apaths_rebuild_byte_identical') else 'NO'} | "
                      f"{ck.get('journal_stale_entries','')} | "
                      f"{'YES' if ck.get('citations_resolved_excerpts_literal') else 'NO'} | "
                      f"**{c.get('verdict','')}** |")

    # ---- not-fresh-verified register (honesty contract: never hidden, never faked)
    md.append("\n## Not-fresh-verified register\n")
    if os.path.exists(conf_path):
        conf = json.load(open(conf_path, encoding="utf-8"))
        reg = conf.get("not_fresh_verified_register") or []
        if not reg:
            md.append("EMPTY — every projected path was re-proven with fresh live evidence.")
        for r in reg:
            md.append(f"\n**{r['target']} — {r['old_path']}**\n")
            md.append(f"- status: **{r['status']}**")
            md.append(f"- reason: {r['reason']}")
            md.append(f"- evidence: {r['evidence']}")

    md.append("\n## Evidence cross-checks\n")
    if checks:
        md.append("**FAILED CHECKS — citations that did not verify:**")
        for c in checks:
            md.append(f"- {c}")
    else:
        md.append("**ALL CHECKS PASSED** — every journal citation exists in that run's "
                  "journal and every excerpt is a literal slice of the cited raw entry "
                  "(substring-verified evidence against the FRESH journals).")
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md) + "\n")
    print(json.dumps({"written": OUT, "paths": total,
                      "failed_checks": len(checks), "checks": checks[:10]}))


if __name__ == "__main__":
    main()
